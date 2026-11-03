//! Kubernetes Secret destination for `sync`.
//!
//! The decrypted value reaches `kubectl` only on its stdin, as a Secret
//! manifest built in zeroized buffers. It is never placed in argv or the child
//! environment, and neither `-o` nor `-v` is used. Child output is captured,
//! bounded and redacted before any of it is surfaced.
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::process::Command;
use zeroize::Zeroizing;

use crate::credential_process::{Captured, capture_with_diagnostics};
use crate::sync_state::{ManagedKind, ManagedRecord};
use crate::sync_targets::{
    DEFAULT_DOCKER_REGISTRY, DEFAULT_FIELD_MANAGER, KubernetesDestination, KubernetesFormat,
};

/// Longest child diagnostic reported, after redaction.
const MAX_REPORTED_BYTES: usize = 400;
const REDACTED: &str = "[redacted]";

/// A Secret manifest plus every string derived from the plaintext that must
/// never appear in surfaced output.
struct Manifest {
    body: Zeroizing<String>,
    needles: Vec<Zeroizing<String>>,
}

pub(crate) fn push(record: &ManagedRecord, value: &str) -> Result<()> {
    if record.kind != ManagedKind::Secret {
        bail!("Kubernetes sync takes encrypted secret sources only");
    }
    let destination = record
        .kubernetes
        .as_ref()
        .context("Kubernetes sync record has no destination")?;
    let manifest = manifest(destination, value, record.name.as_str())?;
    let label = label(record);
    let result = capture_with_diagnostics(
        &mut kubectl(
            destination,
            [
                "apply",
                "--server-side",
                "--force-conflicts",
                "--field-manager",
                destination
                    .field_manager
                    .as_deref()
                    .unwrap_or(DEFAULT_FIELD_MANAGER),
                "-f",
                "-",
            ],
        ),
        Some(manifest.body.as_bytes()),
    );
    let captured = result.map_err(|error| {
        anyhow!(
            "kubectl apply for {label}: {}",
            redact_text(format!("{error:#}").as_bytes(), &manifest.needles)
        )
    })?;
    check(&captured, &label, "apply", &manifest.needles)?;
    println!("{label}: applied");
    Ok(())
}

pub(crate) fn delete(record: &ManagedRecord) -> Result<()> {
    let destination = record
        .kubernetes
        .as_ref()
        .context("Kubernetes sync record has no destination")?;
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
    check(&captured, &label, "delete", &[])?;
    println!("{label}: deleted");
    Ok(())
}

fn kubectl<const N: usize>(destination: &KubernetesDestination, tail: [&str; N]) -> Command {
    let mut command = Command::new("kubectl");
    command
        .args(["--context", &destination.context])
        .args(["--namespace", &destination.namespace])
        .args(tail);
    command
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
) -> Result<()> {
    if captured.status.success() {
        return Ok(());
    }
    // stdout and stderr both pass through redaction before being truncated, so
    // a secret straddling the report boundary cannot leave a partial prefix.
    let mut combined = Zeroizing::new(Vec::new());
    combined.extend_from_slice(&captured.stderr);
    combined.push(b'\n');
    combined.extend_from_slice(&captured.stdout);
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

fn manifest(destination: &KubernetesDestination, value: &str, secret: &str) -> Result<Manifest> {
    let (data_key, data, needles) = match destination.format {
        KubernetesFormat::Opaque => {
            let key = destination
                .key
                .as_deref()
                .context("Kubernetes opaque record has no data key")?;
            let encoded = base64(value.as_bytes());
            let needles = vec![
                Zeroizing::new(value.to_owned()),
                json_escaped(value),
                encoded.clone(),
            ];
            (key, encoded, needles)
        }
        KubernetesFormat::Dockerconfigjson => {
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
            let mut credentials =
                Zeroizing::new(String::with_capacity(user.len() + value.len() + 1));
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
            let encoded = base64(config.as_bytes());
            let needles = vec![
                Zeroizing::new(value.to_owned()),
                json_escaped(value),
                credentials.clone(),
                auth,
                config.clone(),
                encoded.clone(),
            ];
            (crate::sync_targets::DOCKERCONFIGJSON_KEY, encoded, needles)
        }
    };
    let kind = match destination.format {
        KubernetesFormat::Opaque => "Opaque",
        KubernetesFormat::Dockerconfigjson => "kubernetes.io/dockerconfigjson",
    };
    let mut body = Zeroizing::new(String::with_capacity(
        256 + 6 * (secret.len() + destination.namespace.len() + data_key.len()) + data.len(),
    ));
    body.push_str(r#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"#);
    json_string(&mut body, secret);
    body.push_str(r#","namespace":"#);
    json_string(&mut body, &destination.namespace);
    body.push_str(r#"},"type":"#);
    json_string(&mut body, kind);
    body.push_str(r#","data":{"#);
    json_string(&mut body, data_key);
    body.push_str(r#":""#);
    body.push_str(&data);
    body.push_str(r#""}}"#);
    Ok(Manifest { body, needles })
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

    fn destination(format: &str) -> KubernetesDestination {
        serde_json::from_value(serde_json::json!({
            "context": "nrp", "namespace": "syndb", "secret": "pull",
            "format": format, "key": "k", "username": "robot",
        }))
        .unwrap()
    }

    #[test]
    fn dockerconfigjson_rejects_unclean_values_without_echoing_them() {
        let docker = destination("dockerconfigjson");
        assert!(manifest(&docker, "dckr_pat_Abc-123_xyz", "pull").is_ok());
        for bad in [
            "dckr_pat_secret\n",
            "",
            " dckr_pat_x",
            "dckr\tpat",
            "dckr\u{7f}pat",
        ] {
            let error = format!("{:#}", manifest(&docker, bad, "pull").err().unwrap());
            assert!(error.contains("nrp/syndb/secret/pull"), "{error}");
            assert!(error.contains("dockerhub-pat --replace"), "{error}");
            assert!(bad.is_empty() || !error.contains(bad.trim()), "{error}");
        }
        // Opaque values are passed through unchanged.
        assert!(manifest(&destination("opaque"), "line\n", "pull").is_ok());
    }
}
