//! Kubernetes Secret destination for `sync`.
//!
//! Every destination naming one `(context, namespace, secret)` is one member
//! of one Secret; all members are decrypted first and applied as one
//! server-side apply, so a failure applies nothing and the object holds
//! exactly the declared keys.
//!
//! Decrypted and live values exist only in zeroized buffers and in the
//! manifest piped to `kubectl` on stdin. They are never placed in argv or the
//! child environment, and `-v` is never used. `-o json` is passed only to
//! `get` and to the `--adopt` apply, whose captured stdout is parsed in memory
//! and never surfaced. Child diagnostics are bounded and redacted before any of
//! them is reported; reports name keys and states only.
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::process::Command;
use zeroize::Zeroizing;

use crate::credential_process::{Captured, capture_with_diagnostics};
use crate::encryption::StreamEncryptor;
use crate::sync_state::{KubernetesMember, ManagedKind, ManagedRecord};
use crate::sync_targets::{
    DEFAULT_DOCKER_REGISTRY, DEFAULT_FIELD_MANAGER, KubernetesDestination, KubernetesFormat,
    KubernetesObject, KubernetesRender, SyncDocument,
};

/// Longest child diagnostic reported, after redaction.
const MAX_REPORTED_BYTES: usize = 400;
const REDACTED: &str = "[redacted]";

/// Strings derived from plaintext that must never appear in surfaced output.
type Needles = Vec<Zeroizing<String>>;

/// The bytes one member writes under its `data` key.
struct Rendered {
    key: String,
    bytes: Zeroizing<Vec<u8>>,
}

/// Every member of one Secret, rendered, plus its redaction needles.
struct Object {
    rendered: Vec<Rendered>,
    needles: Needles,
}

/// `--target` selects whole Secrets: a target sharing a Secret with a selected
/// target is selected too, transitively, so no apply drops a sibling's key.
pub(crate) fn expand_selection(
    doc: &SyncDocument,
    requested: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut selected = requested.clone();
    loop {
        let objects: BTreeSet<KubernetesObject> = doc
            .iter_targets()
            .filter(|(_, name, _)| selected.contains(*name))
            .flat_map(|(_, _, target)| target.kubernetes.iter().map(KubernetesDestination::object))
            .collect();
        let mut next = selected.clone();
        next.extend(
            doc.iter_targets()
                .filter(|(_, _, target)| {
                    target
                        .kubernetes
                        .iter()
                        .any(|destination| objects.contains(&destination.object()))
                })
                .map(|(_, name, _)| name.to_string()),
        );
        if next == selected {
            return selected;
        }
        selected = next;
    }
}

/// Every encrypted source a record reads: one per member for Kubernetes.
pub(crate) fn record_sources(record: &ManagedRecord) -> Vec<&str> {
    if record.members.is_empty() {
        vec![record.source.as_str()]
    } else {
        record
            .members
            .iter()
            .map(|member| member.source.as_str())
            .collect()
    }
}

/// Apply the whole Secret: every member's key, in one manifest.
pub(crate) fn push(record: &ManagedRecord, values: &[Zeroizing<String>]) -> Result<()> {
    let object = render(record, values)?;
    let manifest = manifest(record, &object, None)?;
    apply(record, &manifest, &object.needles, false)?;
    println!("{}: applied", label(record));
    Ok(())
}

pub(crate) fn delete(record: &ManagedRecord) -> Result<()> {
    let destination = destination(record)?;
    let label = label(record);
    let captured = capture_with_diagnostics(
        &mut kubectl(
            destination,
            [
                "delete",
                "secret",
                record.name.as_str(),
                "--ignore-not-found",
            ],
        ),
        None,
    )?;
    check(&captured, &label, "delete", &[], true)?;
    println!("{label}: deleted");
    Ok(())
}

/// Compare declared and live values; print one state per key. Returns whether
/// every declared key is `equal` and the live object has no undeclared key.
pub(crate) fn verify(record: &ManagedRecord, values: &[Zeroizing<String>]) -> Result<bool> {
    let object = render(record, values)?;
    let live = read_live(record, &object.needles)?;
    let report = compare(record, &object, live.as_ref())?;
    report.print(&label(record));
    Ok(report.clean())
}

/// Adopt a live Secret written by another manager: re-verify, apply under the
/// read `resourceVersion`, then hand data ownership to this field manager.
pub(crate) fn adopt(record: &ManagedRecord, values: &[Zeroizing<String>]) -> Result<()> {
    let label = label(record);
    let object = render(record, values)?;
    let live = read_live(record, &object.needles)?.with_context(|| {
        format!("{label}: not found; adopt takes a live Secret, sync creates one")
    })?;
    let report = compare(record, &object, Some(&live))?;
    report.print(&label);
    if !report.clean() {
        bail!(
            "{label}: not adopted; every declared key must be `equal` and no live key undeclared \
             (import or declare it, then verify again)"
        );
    }
    let manifest = manifest(record, &object, Some(&live.metadata.resource_version))?;
    let captured = apply(record, &manifest, &object.needles, true)?;
    let applied: LiveSecret = serde_json::from_slice(&captured.stdout)
        .map_err(|_| anyhow!("{label}: kubectl apply returned no readable Secret"))?;
    let manager = field_manager(record)?;
    let Some(patch) = ownership_handoff(&applied, manager) else {
        println!("{label}: adopted; `{manager}` is the only data owner");
        return Ok(());
    };
    let destination = destination(record)?;
    let captured = capture_with_diagnostics(
        &mut kubectl(
            destination,
            [
                "patch",
                "secret",
                record.name.as_str(),
                "--type",
                "json",
                "--field-manager",
                manager,
                "-p",
                patch.as_str(),
            ],
        ),
        None,
    )?;
    if !captured.status.success() && conflict(&captured) {
        bail!(
            "{label}: values applied, but the Secret changed before the ownership handoff; \
             rerun --adopt"
        );
    }
    check(&captured, &label, "patch", &object.needles, true)?;
    println!("{label}: adopted; `{manager}` is the only data owner");
    Ok(())
}

/// For each declared `raw` opaque member whose source file is missing, read the
/// live key and encrypt it to the master recipients at the declared path.
/// Never overwrites, never prints a value. Returns whether every missing
/// source was imported.
pub(crate) fn import(
    record: &ManagedRecord,
    root: &Path,
    encryptor: &StreamEncryptor,
) -> Result<bool> {
    let label = label(record);
    let missing: Vec<&KubernetesMember> = record
        .members
        .iter()
        .filter(|member| {
            root.join(&member.source)
                .symlink_metadata()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        })
        .collect();
    for member in record.members.iter().filter(|m| !missing.contains(m)) {
        println!("{label} key {}: source present, not imported", member.key);
    }
    if missing.is_empty() {
        return Ok(true);
    }
    if destination(record)?.format == KubernetesFormat::Dockerconfigjson {
        bail!(
            "{label}: a dockerconfigjson password cannot be recovered from the live Secret; \
             enroll its source instead"
        );
    }
    if let Some(member) = missing.iter().find(|m| m.render() != KubernetesRender::Raw) {
        bail!(
            "{label} key {}: a `render` member stores a derived value; import its source as \
             a raw member",
            member.key
        );
    }
    let Some(live) = read_live(record, &Vec::new())? else {
        for member in &missing {
            println!("{label} key {}: missing-live, not imported", member.key);
        }
        return Ok(false);
    };
    let mut complete = true;
    for member in missing {
        let Some(encoded) = live.data.get(&member.key) else {
            println!("{label} key {}: missing-live, not imported", member.key);
            complete = false;
            continue;
        };
        let value = decode(&encoded.0)
            .with_context(|| format!("{label} key {}: live data is not base64", member.key))?;
        import_member(root, member, &value, encryptor)
            .with_context(|| format!("{label} key {}", member.key))?;
        println!(
            "{label} key {}: imported into {}",
            member.key, member.source
        );
    }
    Ok(complete)
}

/// Encrypt one live value into a new source file, creating its directory.
fn import_member(
    root: &Path,
    member: &KubernetesMember,
    value: &[u8],
    encryptor: &StreamEncryptor,
) -> Result<()> {
    let relative = Path::new(&member.source);
    if relative.extension().and_then(|ext| ext.to_str()) != Some("age")
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        bail!(
            "source {} must be a relative `.age` path inside the store",
            member.source
        );
    }
    if value.is_empty() {
        bail!("the live value is empty; empty keys cannot be imported");
    }
    let path = root.join(relative);
    let parent = path.parent().context("source has no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    // Decryption strips one trailing newline, so store one: every value,
    // including one that itself ends in a newline, then round-trips exactly.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    plaintext.extend_from_slice(value);
    plaintext.push(b'\n');
    encryptor.encrypt_new(&path, &plaintext)
}

fn destination(record: &ManagedRecord) -> Result<&KubernetesDestination> {
    if record.kind != ManagedKind::Secret {
        bail!("Kubernetes sync takes encrypted secret sources only");
    }
    record
        .kubernetes
        .as_ref()
        .context("Kubernetes sync record has no destination")
}

fn field_manager(record: &ManagedRecord) -> Result<&str> {
    Ok(destination(record)?
        .field_manager
        .as_deref()
        .unwrap_or(DEFAULT_FIELD_MANAGER))
}

fn kubectl<const N: usize>(destination: &KubernetesDestination, tail: [&str; N]) -> Command {
    let mut command = Command::new("kubectl");
    command
        .args(["--context", &destination.context])
        .args(["--namespace", &destination.namespace])
        .args(tail);
    command
}

fn apply(
    record: &ManagedRecord,
    manifest: &Zeroizing<String>,
    needles: &[Zeroizing<String>],
    output: bool,
) -> Result<Captured> {
    let label = label(record);
    let manager = field_manager(record)?;
    let mut command = kubectl(
        destination(record)?,
        [
            "apply",
            "--server-side",
            "--force-conflicts",
            "--field-manager",
            manager,
        ],
    );
    if output {
        // kubectl strips managedFields from -o output unless asked.
        command.args(["-o", "json", "--show-managed-fields"]);
    }
    command.args(["-f", "-"]);
    let captured =
        capture_with_diagnostics(&mut command, Some(manifest.as_bytes())).map_err(|error| {
            anyhow!(
                "kubectl apply for {label}: {}",
                redact_text(format!("{error:#}").as_bytes(), needles)
            )
        })?;
    if !captured.status.success() && output && conflict(&captured) {
        bail!("{label}: the Secret changed since it was read; nothing was applied; rerun --adopt");
    }
    // With `-o json` stdout is the applied Secret; only stderr may be reported.
    check(&captured, &label, "apply", needles, !output)?;
    Ok(captured)
}

/// Optimistic-concurrency failures: a stale `resourceVersion` on apply, or a
/// failed JSON patch `test` on the handoff.
fn conflict(captured: &Captured) -> bool {
    let stderr = String::from_utf8_lossy(&captured.stderr);
    stderr.contains("the object has been modified")
        || stderr.contains("Conflict")
        || stderr.contains("testing value")
        || stderr.contains("test operation")
}

fn label(record: &ManagedRecord) -> String {
    format!(
        "kubernetes {}/{}/secret/{}",
        record.host,
        record.owner.as_deref().unwrap_or("?"),
        record.repo.as_deref().unwrap_or("?")
    )
}

fn check(
    captured: &Captured,
    label: &str,
    verb: &str,
    needles: &[Zeroizing<String>],
    with_stdout: bool,
) -> Result<()> {
    if captured.status.success() {
        return Ok(());
    }
    // stdout and stderr both pass through redaction before being truncated, so
    // a secret straddling the report boundary cannot leave a partial prefix.
    let mut combined = Zeroizing::new(Vec::new());
    combined.extend_from_slice(&captured.stderr);
    if with_stdout {
        combined.push(b'\n');
        combined.extend_from_slice(&captured.stdout);
    }
    bail!(
        "kubectl {verb} for {label} failed with {}: {}",
        captured.status,
        redact_text(&combined, needles)
    )
}

/// Replace every needle, then flatten to one short line.
fn redact_text(text: &[u8], needles: &[Zeroizing<String>]) -> String {
    let mut needles: Vec<&[u8]> = needles
        .iter()
        .map(|needle| needle.as_bytes())
        .filter(|needle| !needle.is_empty())
        .collect();
    needles.sort_by_key(|needle| std::cmp::Reverse(needle.len()));
    let mut redacted = Zeroizing::new(Vec::with_capacity(text.len()));
    let mut at = 0;
    while at < text.len() {
        match needles.iter().find(|needle| text[at..].starts_with(needle)) {
            Some(needle) => {
                redacted.extend_from_slice(REDACTED.as_bytes());
                at += needle.len();
            }
            None => {
                redacted.push(text[at]);
                at += 1;
            }
        }
    }
    let line = String::from_utf8_lossy(&redacted)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if line.len() <= MAX_REPORTED_BYTES {
        return line;
    }
    let end = (0..=MAX_REPORTED_BYTES)
        .rev()
        .find(|&end| line.is_char_boundary(end))
        .unwrap_or(0);
    format!("{}…", &line[..end])
}

/// Render every member of the record, refusing empty values and unclean
/// dockerconfigjson passwords. Values are in member order.
fn render(record: &ManagedRecord, values: &[Zeroizing<String>]) -> Result<Object> {
    let destination = destination(record)?;
    if record.members.is_empty() || values.len() != record.members.len() {
        bail!("Kubernetes sync record has no members or a value per member is missing");
    }
    let mut rendered = Vec::with_capacity(values.len());
    let mut needles = Vec::new();
    match destination.format {
        KubernetesFormat::Opaque => {
            for (member, value) in record.members.iter().zip(values) {
                if value.is_empty() {
                    bail!(
                        "refusing to sync kubernetes {}/{}/secret/{} key {}: the decrypted value is empty",
                        destination.context,
                        destination.namespace,
                        destination.secret,
                        member.key
                    );
                }
                needles.push(Zeroizing::new(value.to_string()));
                needles.push(json_escaped(value));
                needles.push(base64(value.as_bytes()));
                let bytes = match member.render() {
                    KubernetesRender::Raw => Zeroizing::new(value.as_bytes().to_vec()),
                    KubernetesRender::Sha256Hex => {
                        let hex = sha256_hex(value.as_bytes());
                        needles.push(Zeroizing::new(String::from_utf8_lossy(&hex).into_owned()));
                        needles.push(base64(&hex));
                        hex
                    }
                };
                rendered.push(Rendered {
                    key: member.key.clone(),
                    bytes,
                });
            }
        }
        KubernetesFormat::Dockerconfigjson => {
            let [member] = record.members.as_slice() else {
                bail!("a Kubernetes dockerconfigjson Secret has exactly one member");
            };
            let value = values[0].as_str();
            let (config, mut derived) = dockerconfig(destination, value)?;
            needles.append(&mut derived);
            rendered.push(Rendered {
                key: member.key.clone(),
                bytes: Zeroizing::new(config.as_bytes().to_vec()),
            });
        }
    }
    for item in &rendered {
        needles.push(base64(&item.bytes));
    }
    Ok(Object { rendered, needles })
}

fn dockerconfig(
    destination: &KubernetesDestination,
    value: &str,
) -> Result<(Zeroizing<String>, Needles)> {
    // Fail closed: an editor-added newline or a mis-encrypted value must
    // not be applied over a working pull secret. The value is never named.
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_ascii_whitespace() || c.is_control())
    {
        bail!(
            "refusing to sync kubernetes {}/{}/secret/{}: the dockerconfigjson value is empty or contains whitespace or control characters; re-enroll it with `canix secret dockerhub-pat --replace`",
            destination.context,
            destination.namespace,
            destination.secret
        );
    }
    let user = destination
        .username
        .as_deref()
        .context("Kubernetes dockerconfigjson record has no username")?;
    let registry = destination
        .registry
        .as_deref()
        .unwrap_or(DEFAULT_DOCKER_REGISTRY);
    let mut credentials = Zeroizing::new(String::with_capacity(user.len() + value.len() + 1));
    credentials.push_str(user);
    credentials.push(':');
    credentials.push_str(value);
    let auth = base64(credentials.as_bytes());
    let mut config = Zeroizing::new(String::with_capacity(
        128 + 6 * (registry.len() + user.len() + value.len()) + auth.len(),
    ));
    config.push_str(r#"{"auths":{"#);
    json_string(&mut config, registry);
    config.push_str(r#":{"username":"#);
    json_string(&mut config, user);
    config.push_str(r#","password":"#);
    json_string(&mut config, value);
    config.push_str(r#","auth":""#);
    config.push_str(&auth);
    config.push_str(r#""}}}"#);
    let needles = vec![
        Zeroizing::new(value.to_owned()),
        json_escaped(value),
        credentials,
        auth,
        config.clone(),
    ];
    Ok((config, needles))
}

/// The Secret manifest; `resource_version` makes the apply conditional.
fn manifest(
    record: &ManagedRecord,
    object: &Object,
    resource_version: Option<&str>,
) -> Result<Zeroizing<String>> {
    let destination = destination(record)?;
    let kind = match destination.format {
        KubernetesFormat::Opaque => "Opaque",
        KubernetesFormat::Dockerconfigjson => "kubernetes.io/dockerconfigjson",
    };
    let data_len: usize = object
        .rendered
        .iter()
        .map(|item| 6 * item.key.len() + item.bytes.len().div_ceil(3) * 4 + 8)
        .sum();
    let mut body = Zeroizing::new(String::with_capacity(
        256 + 6 * (record.name.len() + destination.namespace.len()) + data_len,
    ));
    body.push_str(r#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"#);
    json_string(&mut body, &record.name);
    body.push_str(r#","namespace":"#);
    json_string(&mut body, &destination.namespace);
    if let Some(version) = resource_version {
        body.push_str(r#","resourceVersion":"#);
        json_string(&mut body, version);
    }
    body.push_str(r#"},"type":"#);
    json_string(&mut body, kind);
    body.push_str(r#","data":{"#);
    for (index, item) in object.rendered.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        json_string(&mut body, &item.key);
        body.push_str(r#":""#);
        STANDARD.encode_string(&item.bytes[..], &mut body);
        body.push('"');
    }
    body.push_str("}}");
    Ok(body)
}

/// A live Secret as `kubectl get -o json` returns it. Data values stay in
/// zeroized buffers.
#[derive(Deserialize)]
struct LiveSecret {
    metadata: LiveMetadata,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    data: BTreeMap<String, Hidden>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveMetadata {
    resource_version: String,
    #[serde(default)]
    managed_fields: Vec<serde_json::Value>,
}

struct Hidden(Zeroizing<String>);

impl<'de> Deserialize<'de> for Hidden {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Hidden(Zeroizing::new(value)))
    }
}

fn read_live(record: &ManagedRecord, needles: &Needles) -> Result<Option<LiveSecret>> {
    let label = label(record);
    let captured = capture_with_diagnostics(
        &mut kubectl(
            destination(record)?,
            [
                "get",
                "secret",
                record.name.as_str(),
                "-o",
                "json",
                "--show-managed-fields",
            ],
        ),
        None,
    )?;
    if !captured.status.success() && String::from_utf8_lossy(&captured.stderr).contains("NotFound")
    {
        return Ok(None);
    }
    // stdout carries live values: never part of a report.
    check(&captured, &label, "get", needles, false)?;
    let live = serde_json::from_slice(&captured.stdout)
        .map_err(|_| anyhow!("{label}: kubectl get returned no readable Secret"))?;
    Ok(Some(live))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    Equal,
    Different,
    MissingLive,
    UndeclaredLive,
}

impl KeyState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "equal",
            Self::Different => "different",
            Self::MissingLive => "missing-live",
            Self::UndeclaredLive => "undeclared-live",
        }
    }
}

#[derive(Debug)]
struct Report {
    exists: bool,
    keys: Vec<(String, KeyState)>,
    /// `(live, declared)` when the live `type` differs; it is immutable.
    type_mismatch: Option<(String, String)>,
    foreign_managers: BTreeSet<String>,
}

impl Report {
    fn clean(&self) -> bool {
        self.exists
            && self.type_mismatch.is_none()
            && self.keys.iter().all(|(_, state)| *state == KeyState::Equal)
    }

    fn print(&self, label: &str) {
        if !self.exists {
            println!("{label}: missing-live");
        }
        if let Some((live, declared)) = &self.type_mismatch {
            println!("{label}: type {live} live, {declared} declared");
        }
        for (key, state) in &self.keys {
            println!("{label} key {key}: {}", state.as_str());
        }
        for manager in &self.foreign_managers {
            println!("{label}: foreign-manager {manager}");
        }
    }
}

fn compare(record: &ManagedRecord, object: &Object, live: Option<&LiveSecret>) -> Result<Report> {
    let destination = destination(record)?;
    let Some(live) = live else {
        return Ok(Report {
            exists: false,
            keys: object
                .rendered
                .iter()
                .map(|item| (item.key.clone(), KeyState::MissingLive))
                .collect(),
            type_mismatch: None,
            foreign_managers: BTreeSet::new(),
        });
    };
    let declared_type = match destination.format {
        KubernetesFormat::Opaque => "Opaque",
        KubernetesFormat::Dockerconfigjson => "kubernetes.io/dockerconfigjson",
    };
    let live_type = live.kind.as_deref().unwrap_or("Opaque");
    let mut keys = Vec::new();
    for item in &object.rendered {
        let state = match live.data.get(&item.key) {
            None => KeyState::MissingLive,
            Some(encoded) => {
                let live_bytes = decode(&encoded.0).unwrap_or_default();
                let equal = if destination.format == KubernetesFormat::Dockerconfigjson {
                    dockerconfig_equal(&item.bytes, &live_bytes)
                } else {
                    item.bytes[..] == live_bytes[..]
                };
                if equal {
                    KeyState::Equal
                } else {
                    KeyState::Different
                }
            }
        };
        keys.push((item.key.clone(), state));
    }
    let declared: BTreeSet<&str> = object
        .rendered
        .iter()
        .map(|item| item.key.as_str())
        .collect();
    for key in live
        .data
        .keys()
        .filter(|key| !declared.contains(key.as_str()))
    {
        keys.push((key.clone(), KeyState::UndeclaredLive));
    }
    let manager = field_manager(record)?;
    Ok(Report {
        exists: true,
        keys,
        type_mismatch: (live_type != declared_type)
            .then(|| (live_type.to_string(), declared_type.to_string())),
        foreign_managers: live
            .metadata
            .managed_fields
            .iter()
            .filter(|entry| owns_data(entry) && entry_manager(entry) != manager)
            .map(|entry| entry_manager(entry).to_string())
            .collect(),
    })
}

fn entry_manager(entry: &serde_json::Value) -> &str {
    entry
        .get("manager")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unnamed>")
}

fn owns_data(entry: &serde_json::Value) -> bool {
    entry
        .get("fieldsV1")
        .and_then(|fields| fields.get("f:data"))
        .is_some()
}

/// The JSON patch that leaves `manager` the only data owner, guarded by the
/// applied `resourceVersion`; `None` when it already is. Kubernetes accepts a
/// request that rewrites `metadata.managedFields`; entries hold field names,
/// never values.
fn ownership_handoff(applied: &LiveSecret, manager: &str) -> Option<String> {
    let kept: Vec<&serde_json::Value> = applied
        .metadata
        .managed_fields
        .iter()
        .filter(|entry| !owns_data(entry) || entry_manager(entry) == manager)
        .collect();
    (kept.len() != applied.metadata.managed_fields.len()).then(|| {
        serde_json::json!([
            {"op": "test", "path": "/metadata/resourceVersion",
             "value": applied.metadata.resource_version},
            {"op": "replace", "path": "/metadata/managedFields", "value": kept},
        ])
        .to_string()
    })
}

/// A dockerconfigjson document, normalized: registry to field to value.
type Auths<'a> = BTreeMap<&'a str, BTreeMap<&'a str, &'a str>>;

/// Equal as documents, ignoring key order and whitespace. Parsing borrows every
/// string from the zeroized inputs, so no value is copied, and its errors never
/// carry one. serde_json unescapes through a scratch buffer it never wipes, so
/// a document with any escape is compared byte for byte instead; Docker PATs,
/// user names and base64 `auth` values need none.
fn dockerconfig_equal(declared: &[u8], live: &[u8]) -> bool {
    if declared.contains(&b'\\') || live.contains(&b'\\') {
        return declared == live;
    }
    match (parse_dockerconfig(declared), parse_dockerconfig(live)) {
        (Some(declared), Some(live)) => declared == live,
        _ => false,
    }
}

/// `{"auths": {registry: {field: string}}}` and nothing else.
fn parse_dockerconfig(bytes: &[u8]) -> Option<Auths<'_>> {
    let Borrowed(mut top) =
        serde_json::from_slice::<Borrowed<Borrowed<Borrowed<Str>>>>(bytes).ok()?;
    let auths = top.remove("auths").filter(|_| top.is_empty())?;
    Some(
        auths
            .0
            .into_iter()
            .map(|(registry, Borrowed(fields))| {
                (
                    registry,
                    fields
                        .into_iter()
                        .map(|(field, Str(value))| (field, value))
                        .collect(),
                )
            })
            .collect(),
    )
}

/// A JSON string borrowed from the input. A string serde_json would have to
/// unescape, and any error, carries no value.
struct Str<'a>(&'a str);

impl<'de> Deserialize<'de> for Str<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Str<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                value: &'de str,
            ) -> Result<Self::Value, E> {
                Ok(Str(value))
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Err(E::custom("unborrowable string"))
            }
        }
        // `deserialize_any`: serde_json then hands every token to this visitor
        // instead of building a type error that quotes the value.
        deserializer.deserialize_any(Visitor)
    }
}

/// A JSON object with borrowed keys. A string in its place is refused without
/// naming it (serde's default error would quote the value).
struct Borrowed<'a, V>(BTreeMap<&'a str, V>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Borrowed<'de, V> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<V> {
            type Value = Borrowed<'de, V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut entries = BTreeMap::new();
                while let Some((Str(key), value)) = map.next_entry::<Str<'de>, V>()? {
                    entries.insert(key, value);
                }
                Ok(Borrowed(entries))
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Err(E::custom("a string where an object belongs"))
            }
        }
        deserializer.deserialize_any(Visitor(std::marker::PhantomData))
    }
}

fn decode(encoded: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(encoded.len() / 4 * 3 + 3));
    STANDARD.decode_vec(encoded, &mut out)?;
    Ok(out)
}

fn sha256_hex(value: &[u8]) -> Zeroizing<Vec<u8>> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = ring::digest::digest(&ring::digest::SHA256, value);
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    for byte in digest.as_ref() {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0xf)]);
    }
    out
}

fn base64(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(3) * 4));
    STANDARD.encode_string(bytes, &mut out);
    out
}

fn json_escaped(value: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(6 * value.len() + 2));
    json_string(&mut out, value);
    // Strip the surrounding quotes: the escaped body is what kubectl would echo.
    Zeroizing::new(out[1..out.len() - 1].to_owned())
}

/// Append `value` as a JSON string literal without intermediate heap copies.
/// Callers reserve `6 * len + 2` bytes, the worst case, so nothing reallocates.
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < ' ' => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_state::{SyncState, desired_records, stale_records};

    fn doc(targets: serde_json::Value) -> SyncDocument {
        SyncDocument::from_json(&serde_json::json!({"hosts":[{"targets":targets}]}).to_string())
            .unwrap()
    }

    fn member(secret: &str, key: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut destination = serde_json::json!({
            "context":"nrp","namespace":"syndb","secret":secret,"format":"opaque","key":key
        });
        destination
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        destination
    }

    fn values(values: &[&str]) -> Vec<Zeroizing<String>> {
        values
            .iter()
            .map(|v| Zeroizing::new(v.to_string()))
            .collect()
    }

    fn data_keys(manifest: &str) -> Vec<String> {
        let manifest: serde_json::Value = serde_json::from_str(manifest).unwrap();
        manifest["data"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    fn live(data: &[(&str, &str)], managers: &[(&str, bool)]) -> LiveSecret {
        serde_json::from_value(serde_json::json!({
            "metadata": {
                "resourceVersion": "41",
                "managedFields": managers.iter().map(|(manager, data)| if *data {
                    serde_json::json!({"manager": manager, "fieldsV1": {"f:data": {"f:a": {}}}})
                } else {
                    serde_json::json!({"manager": manager, "fieldsV1": {"f:metadata": {}}})
                }).collect::<Vec<_>>(),
            },
            "type": "Opaque",
            "data": data.iter().map(|(k, v)| (k.to_string(), STANDARD.encode(v))).collect::<BTreeMap<_, _>>(),
        }))
        .unwrap()
    }

    #[test]
    fn removing_one_member_keeps_secret() {
        let both = doc(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","a",serde_json::json!({}))]},
            "b": {"secret":"age/b.age","name":"B","kubernetes":[member("api","b",serde_json::json!({}))]},
        }));
        let one = doc(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","a",serde_json::json!({}))]},
        }));
        let previous = desired_records(&both).unwrap();
        assert_eq!(
            previous.len(),
            1,
            "two members of one Secret are one record"
        );
        assert_eq!(previous[0].members.len(), 2);
        let desired = desired_records(&one).unwrap();
        assert!(
            stale_records(&previous, &desired).is_empty(),
            "Secret scheduled for deletion"
        );
        // The next apply carries only the remaining key, so server-side apply
        // drops the removed one while the Secret stays.
        let object = render(&desired[0], &values(&["va"])).unwrap();
        let manifest = manifest(&desired[0], &object, None).unwrap();
        assert_eq!(data_keys(&manifest), ["a"]);
    }

    #[test]
    fn target_selection_expands_to_whole_object() {
        let doc = doc(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","a",serde_json::json!({}))]},
            "b": {"secret":"age/b.age","name":"B","kubernetes":[
                member("api","b",serde_json::json!({})), member("auth","b",serde_json::json!({}))]},
            "c": {"secret":"age/c.age","name":"C","kubernetes":[member("auth","c",serde_json::json!({}))]},
            "d": {"secret":"age/d.age","name":"D","kubernetes":[member("other","d",serde_json::json!({}))]},
        }));
        let requested = BTreeSet::from(["a".to_string(), "missing".to_string()]);
        let selected = expand_selection(&doc, &requested);
        // a shares `api` with b, and b shares `auth` with c: transitive.
        assert_eq!(
            selected,
            BTreeSet::from(["a", "b", "c", "missing"].map(String::from))
        );
    }

    #[test]
    fn duplicate_key_in_group_rejected() {
        let error = |targets| desired_records(&doc(targets)).unwrap_err().to_string();
        let message = error(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","k",serde_json::json!({}))]},
            "b": {"secret":"age/b.age","name":"B","kubernetes":[member("api","k",serde_json::json!({}))]},
        }));
        assert!(message.contains("key `k`"), "{message}");
        let message = error(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","a",serde_json::json!({}))]},
            "b": {"secret":"age/b.age","name":"B","kubernetes":[member("api","b",serde_json::json!({"fieldManager":"other"}))]},
        }));
        assert!(message.contains("fieldManager"), "{message}");
        let docker = serde_json::json!({"context":"nrp","namespace":"syndb","secret":"pull",
            "format":"dockerconfigjson","username":"robot"});
        let message = error(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[docker]},
            "b": {"secret":"age/b.age","name":"B","kubernetes":[docker]},
        }));
        assert!(message.contains("exactly one member"), "{message}");
    }

    #[test]
    fn v1_state_upgrades_to_single_member() {
        let dir = crate::io::TempDir::new().unwrap();
        let path = dir.path.join("sync-state.toml");
        std::fs::write(
            &path,
            r#"version = 1

[[managed]]
provider = "kubernetes"
host = "nrp"
scope = "namespace"
owner = "syndb"
repo = "api"
kind = "secret"
name = "api"
target = "a"
source = "age/a.age"

[managed.kubernetes]
context = "nrp"
namespace = "syndb"
secret = "api"
format = "opaque"
key = "a"

[[managed]]
provider = "kubernetes"
host = "nrp"
scope = "namespace"
owner = "syndb"
repo = "pull"
kind = "secret"
name = "pull"
target = "pull"
source = "age/pull.age"

[managed.kubernetes]
context = "nrp"
namespace = "syndb"
secret = "pull"
format = "dockerconfigjson"
username = "robot"
"#,
        )
        .unwrap();
        let upgraded = SyncState::load(&path).unwrap().unwrap();
        assert_eq!(upgraded.version, crate::sync_state::STATE_VERSION);
        let desired = desired_records(&doc(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","a",serde_json::json!({}))]},
            "pull": {"secret":"age/pull.age","name":"PULL","kubernetes":[{"context":"nrp",
                "namespace":"syndb","secret":"pull","format":"dockerconfigjson","username":"robot"}]},
        })))
        .unwrap();
        // Identical to what version 2 declares: one member each, key from
        // `data_key()`, so nothing is stale and a rewrite is stable.
        assert_eq!(upgraded.managed, desired);
        let pull = upgraded.managed.iter().find(|r| r.name == "pull").unwrap();
        assert_eq!(pull.members[0].key, ".dockerconfigjson");
        assert!(stale_records(&upgraded.managed, &desired).is_empty());
        upgraded.write_atomic(&path).unwrap();
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(rewritten.starts_with("version = 2"), "{rewritten}");
        assert_eq!(SyncState::load(&path).unwrap().unwrap(), upgraded);
    }

    #[test]
    fn adopt_rejects_changed_object() {
        let records = desired_records(&doc(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","a",serde_json::json!({}))]},
            "h": {"secret":"age/h.age","name":"H","kubernetes":[
                member("api","h",serde_json::json!({"render":"sha256-hex"}))]},
        })))
        .unwrap();
        let record = &records[0];
        let object = render(record, &values(&["va", "vh"])).unwrap();
        let hash = String::from_utf8(sha256_hex(b"vh").to_vec()).unwrap();
        let clean = live(&[("a", "va"), ("h", &hash)], &[("legacy", true)]);
        let report = compare(record, &object, Some(&clean)).unwrap();
        assert!(report.clean(), "{report:?}");
        assert_eq!(
            report.foreign_managers,
            BTreeSet::from(["legacy".to_string()])
        );
        // A changed value, an undeclared key or a missing key each refuse.
        for changed in [
            live(&[("a", "other"), ("h", &hash)], &[]),
            live(&[("a", "va"), ("h", &hash), ("extra", "x")], &[]),
            live(&[("a", "va")], &[]),
        ] {
            assert!(!compare(record, &object, Some(&changed)).unwrap().clean());
        }
        // The adopting apply is conditional on the read resourceVersion.
        let body = manifest(record, &object, Some(&clean.metadata.resource_version)).unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["metadata"]["resourceVersion"], "41");
        // The handoff drops every foreign data owner and tests the version.
        let patch = ownership_handoff(
            &live(
                &[],
                &[
                    ("secret-manager", true),
                    ("legacy", true),
                    ("labels", false),
                ],
            ),
            "secret-manager",
        )
        .unwrap();
        let patch: serde_json::Value = serde_json::from_str(&patch).unwrap();
        assert_eq!(patch[0]["op"], "test");
        assert_eq!(patch[0]["value"], "41");
        let kept: Vec<&str> = patch[1]["value"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["manager"].as_str().unwrap())
            .collect();
        assert_eq!(kept, ["secret-manager", "labels"]);
        assert!(
            ownership_handoff(&live(&[], &[("secret-manager", true)]), "secret-manager").is_none()
        );
    }

    #[test]
    fn import_into_new_category_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // A stand-in for lib.mkAgenixStreamEncryptor: emits a fixed age header
        // and records the synthetic plaintext it was handed.
        let script = dir.path().join("encryptor");
        std::fs::write(
            &script,
            "#!/bin/sh\n[ \"$1\" = encrypt ] || exit 2\ncat > \"$0.plain\"\n\
             printf 'age-encryption.org/v1\\n-> X25519 fixture\\n%064d\\n--- end\\n' 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let encryptor = StreamEncryptor::new(script.clone()).unwrap();
        let root = dir.path().join("store");
        std::fs::create_dir(&root).unwrap();
        let mut member = KubernetesMember {
            key: "clickhouse_password".into(),
            target: "clickhouse".into(),
            source: "age/secrets/home/can/app/syndb_clickhouse_password.age".into(),
            render: None,
        };
        import_member(&root, &member, b"live-value", &encryptor).unwrap();
        let written = std::fs::read(root.join(&member.source)).unwrap();
        assert!(written.starts_with(b"age-encryption.org/v1\n"));
        // Decryption strips exactly one trailing newline, so the stored
        // plaintext carries one more than the live value, even when the value
        // itself ends in a newline.
        let plain = || std::fs::read(script.with_extension("plain")).unwrap();
        assert_eq!(plain(), b"live-value\n");
        member.source = "age/secrets/home/can/app/syndb_with_newline.age".into();
        import_member(&root, &member, b"pem\n", &encryptor).unwrap();
        assert_eq!(plain(), b"pem\n\n");
        // Never overwrites an existing source.
        assert!(import_member(&root, &member, b"other", &encryptor).is_err());
        // Empty values are refused; paths stay inside the store.
        member.source = "age/secrets/home/can/oauth/syndb_oa_gitlab_secret.age".into();
        assert!(import_member(&root, &member, b"", &encryptor).is_err());
        member.source = "../escape.age".into();
        assert!(import_member(&root, &member, b"x", &encryptor).is_err());
    }

    #[test]
    fn dockerconfig_compares_as_documents_and_default_manager_groups() {
        let declared = br#"{"auths":{"r":{"username":"u","password":"p","auth":"dTpw"}}}"#;
        let reordered =
            br#"{ "auths": { "r": { "auth": "dTpw", "password": "p", "username": "u" } } }"#;
        assert!(dockerconfig_equal(declared, reordered));
        for different in [
            &br#"{"auths":{"r":{"username":"u","password":"q","auth":"dTpx"}}}"#[..],
            br#"{"auths":{"r":{"auth":"dTpw"}}}"#,
            br#"{"auths":{"r":{"username":"u","password":"p","auth":"dTpw"}},"credsStore":"x"}"#,
            b"not json",
        ] {
            assert!(!dockerconfig_equal(declared, different));
        }
        // Escaped values never reach serde_json: byte equality only.
        let escaped = br#"{"auths":{"r":{"username":"u","password":"p\"q"}}}"#;
        assert!(dockerconfig_equal(escaped, escaped));
        let reordered = br#"{"auths":{"r":{"password":"p\"q","username":"u"}}}"#;
        assert!(!dockerconfig_equal(escaped, reordered));
        // A string where an object belongs is refused without quoting it.
        let error = serde_json::from_slice::<Borrowed<Str>>(br#""hunter2-value""#)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("hunter2"), "{error}");
        let error = serde_json::from_slice::<Borrowed<Str>>(br#"{"k":"hunter2\u0041"}"#)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("hunter2"), "{error}");
        // An explicit `fieldManager = "secret-manager"` is the implicit default.
        let records = desired_records(&doc(serde_json::json!({
            "a": {"secret":"age/a.age","name":"A","kubernetes":[member("api","a",serde_json::json!({}))]},
            "b": {"secret":"age/b.age","name":"B","kubernetes":[
                member("api","b",serde_json::json!({"fieldManager":"secret-manager"}))]},
        })))
        .unwrap();
        assert_eq!(records[0].members.len(), 2);
    }

    #[test]
    fn empty_and_unclean_values_are_refused_without_echoing_them() {
        let records = desired_records(&doc(serde_json::json!({
            "pull": {"secret":"age/pull.age","name":"PULL","kubernetes":[{"context":"nrp",
                "namespace":"syndb","secret":"pull","format":"dockerconfigjson","username":"robot"}]},
            "gitlab": {"secret":"age/g.age","name":"G","kubernetes":[member("api","g",serde_json::json!({}))]},
        })))
        .unwrap();
        let (api, pull) = (&records[0], &records[1]);
        assert!(render(pull, &values(&["dckr_pat_Abc-123_xyz"])).is_ok());
        for bad in [
            "dckr_pat_secret\n",
            "",
            " dckr_pat_x",
            "dckr\tpat",
            "dckr\u{7f}pat",
        ] {
            let error = format!("{:#}", render(pull, &values(&[bad])).err().unwrap());
            assert!(error.contains("nrp/syndb/secret/pull"), "{error}");
            assert!(error.contains("dockerhub-pat --replace"), "{error}");
            assert!(bad.is_empty() || !error.contains(bad.trim()), "{error}");
        }
        assert!(
            render(api, &values(&[""])).is_err(),
            "empty opaque value accepted"
        );
        assert!(render(api, &values(&["line\n"])).is_ok());
    }
}
