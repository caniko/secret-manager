use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::io::{validate_ident, validate_slug};
use crate::pkl;
use crate::render::nix_string;

#[derive(Subcommand, Debug)]
pub enum RegistryCmd {
    /// Validate and summarize a Pkl secret registry.
    Check(CheckArgs),
    /// Export a Pkl secret registry to JSON or Nix.
    Export(ExportArgs),
}

#[derive(Subcommand, Debug)]
pub enum RunnerEnvCmd {
    /// Append a runner file-env target to a Pkl secret registry.
    Add(RunnerEnvAddArgs),
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Pkl registry to evaluate.
    #[arg(long, value_name = "PATH")]
    pub input: PathBuf,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Pkl registry to evaluate.
    #[arg(long, value_name = "PATH")]
    pub input: PathBuf,

    /// Output format.
    #[arg(long, value_enum)]
    pub format: ExportFormat,

    /// Output path. Use `-` for stdout.
    #[arg(long, value_name = "PATH")]
    pub output: PathBuf,
}

#[derive(Args, Debug)]
pub struct RunnerEnvAddArgs {
    /// Pkl registry to update.
    #[arg(long, value_name = "PATH")]
    pub registry: PathBuf,

    /// Registry entry id.
    #[arg(long)]
    pub id: String,

    /// Agenix secret path, relative to the data repository root.
    #[arg(long)]
    pub secret: String,

    /// Runner instance name, for example `codeberg` or `nixTrusted`.
    #[arg(long = "instance", num_args = 1..)]
    pub instances: Vec<String>,

    /// Job-visible environment variable that points to the mounted secret file.
    #[arg(long)]
    pub env: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Nix,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRegistry {
    #[serde(default)]
    pub scopes: BTreeMap<String, EnvRegistry>,
    #[serde(default)]
    pub can_personal_pc_env: Option<EnvRegistry>,
    #[serde(default)]
    pub shared_personal_pc_env: Option<EnvRegistry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct EnvRegistry {
    #[serde(default)]
    pub encrypted: BTreeMap<String, EncryptedSecret>,
    #[serde(default)]
    pub plain: BTreeMap<String, PlainSecret>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Source {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTarget {
    pub target: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub codeberg_user: bool,
    #[serde(
        default,
        deserialize_with = "null_to_empty_vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub codeberg: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_to_empty_vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub codefloe: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_to_empty_vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub github: Vec<String>,
    #[serde(
        default,
        deserialize_with = "null_to_empty_vec",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub codeberg_orgs: Vec<String>,
    #[serde(default = "default_host", skip_serializing_if = "is_default_host")]
    pub host: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunnerFileEnvTarget {
    pub env: String,
    #[serde(default)]
    pub instances: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedSecret {
    pub source: Source,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runner_file_env: Vec<RunnerFileEnvTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker_registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copr_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PlainSecret {
    pub source: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncTarget>,
}

impl RegistryCmd {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Check(args) => args.run(),
            Self::Export(args) => args.run(),
        }
    }
}

impl RunnerEnvCmd {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Add(args) => args.run(),
        }
    }
}

impl CheckArgs {
    pub fn run(self) -> Result<()> {
        let registry = load_registry(&self.input)?;
        let summary = summarize(&registry);
        println!("registry: {}", self.input.display());
        println!("scopes: {}", summary.scopes);
        println!("encrypted: {}", summary.encrypted);
        println!("plain: {}", summary.plain);
        println!("sync targets: {}", summary.sync_targets);
        println!(
            "runner file env targets: {}",
            summary.runner_file_env_targets
        );
        Ok(())
    }
}

impl ExportArgs {
    pub fn run(self) -> Result<()> {
        let registry = load_registry(&self.input)?;
        let body = match self.format {
            ExportFormat::Json => serde_json::to_string_pretty(&registry)? + "\n",
            ExportFormat::Nix => render_registry_nix(&registry, &self.input),
        };
        if self.output.as_os_str() == "-" {
            print!("{body}");
        } else {
            fs::write(&self.output, body)
                .with_context(|| format!("writing {}", self.output.display()))?;
        }
        Ok(())
    }
}

impl RunnerEnvAddArgs {
    pub fn run(self) -> Result<()> {
        validate_slug(&self.id)?;
        validate_runner_env(&self.env)?;
        validate_secret_path(&self.secret)?;
        let instances = sorted_instances(&self.instances)?;
        if instances.is_empty() {
            bail!("runner file-env delivery requires at least one --instance");
        }

        let registry = load_registry(&self.registry)?;
        ensure_id_absent(&registry, &self.id)?;
        let block = render_runner_env_append(&self.id, &self.secret, &self.env, &instances);
        append_pkl_block(&self.registry, &block)?;
        eprintln!(
            "registered runner file env `{}` -> {} for {}",
            self.env,
            self.secret,
            instances.join(", ")
        );
        Ok(())
    }
}

pub fn load_registry(path: &Path) -> Result<SecretRegistry> {
    let registry: SecretRegistry = pkl::load_sync(path)?;
    validate_registry(&registry)?;
    Ok(registry)
}

fn validate_registry(registry: &SecretRegistry) -> Result<()> {
    for (scope_name, scope) in &registry.scopes {
        validate_scope(scope_name, scope)?;
    }
    if let Some(scope) = &registry.can_personal_pc_env {
        validate_scope("canPersonalPcEnv", scope)?;
    }
    if let Some(scope) = &registry.shared_personal_pc_env {
        validate_scope("sharedPersonalPcEnv", scope)?;
    }
    Ok(())
}

fn validate_scope(scope_name: &str, scope: &EnvRegistry) -> Result<()> {
    for (id, entry) in &scope.encrypted {
        validate_secret_entry(scope_name, id, entry)?;
    }
    Ok(())
}

fn validate_secret_entry(scope_name: &str, id: &str, entry: &EncryptedSecret) -> Result<()> {
    if let Some(relative) = &entry.source.relative {
        validate_secret_path(relative)?;
    }
    for target in &entry.runner_file_env {
        validate_runner_env(&target.env)
            .with_context(|| format!("invalid runner file env on {scope_name}.{id}"))?;
        if target.instances.is_empty() {
            bail!("{scope_name}.{id}: runnerFileEnv target has no instances");
        }
        for instance in &target.instances {
            validate_ident(instance, "runner instance")?;
        }
    }
    Ok(())
}

fn validate_runner_env(env: &str) -> Result<()> {
    validate_ident(env, "env")?;
    if !env.ends_with("_FILE") {
        bail!("runner file-env variable `{env}` must end with _FILE");
    }
    Ok(())
}

fn validate_secret_path(path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains("..") || !path.ends_with(".age") {
        bail!("secret path `{path}` must be a repo-relative .age path without `..`");
    }
    Ok(())
}

fn sorted_instances(instances: &[String]) -> Result<Vec<String>> {
    let mut sorted = BTreeSet::new();
    for instance in instances {
        validate_ident(instance, "instance")?;
        sorted.insert(instance.clone());
    }
    Ok(sorted.into_iter().collect())
}

fn ensure_id_absent(registry: &SecretRegistry, id: &str) -> Result<()> {
    for (scope_name, scope) in &registry.scopes {
        if scope.encrypted.contains_key(id) || scope.plain.contains_key(id) {
            bail!("registry id `{id}` already exists in scope `{scope_name}`");
        }
    }
    Ok(())
}

fn append_pkl_block(path: &Path, block: &str) -> Result<()> {
    let mut current =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if !current.ends_with('\n') {
        current.push('\n');
    }
    current.push_str(block);
    fs::write(path, current).with_context(|| format!("writing {}", path.display()))
}

fn render_runner_env_append(id: &str, secret: &str, env: &str, instances: &[String]) -> String {
    let source_name = secret
        .strip_prefix("age/secrets/modules/")
        .and_then(|s| s.strip_suffix(".age"))
        .unwrap_or(id);
    format!(
        "\n// Added by `secret-manager forgejo runner-env add`.\nscopes = (scopes) {{\n  [\"can\"] = (scopes[\"can\"]) {{\n    encrypted = (scopes[\"can\"].encrypted) {{\n      [{}] = new S.EncryptedSecret {{\n        source = new S.Source {{ kind = \"module\"; name = {}; relative = {} }}\n        runnerFileEnv = new Listing {{ new S.RunnerFileEnvTarget {{ env = {}; instances = new Listing {{ {} }} }} }}\n      }}\n    }}\n  }}\n}}\n",
        pkl::string_literal(id),
        pkl::string_literal(source_name),
        pkl::string_literal(secret),
        pkl::string_literal(env),
        instances
            .iter()
            .map(|v| pkl::string_literal(v))
            .collect::<Vec<_>>()
            .join("; ")
    )
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RegistrySummary {
    scopes: usize,
    encrypted: usize,
    plain: usize,
    sync_targets: usize,
    runner_file_env_targets: usize,
}

fn summarize(registry: &SecretRegistry) -> RegistrySummary {
    let mut summary = RegistrySummary {
        scopes: registry.scopes.len(),
        ..RegistrySummary::default()
    };
    for scope in registry.scopes.values() {
        summary.encrypted += scope.encrypted.len();
        summary.plain += scope.plain.len();
        summary.sync_targets += scope
            .encrypted
            .values()
            .filter(|entry| entry.sync.is_some())
            .count();
        summary.sync_targets += scope
            .plain
            .values()
            .filter(|entry| entry.sync.is_some())
            .count();
        summary.runner_file_env_targets += scope
            .encrypted
            .values()
            .map(|entry| entry.runner_file_env.len())
            .sum::<usize>();
    }
    summary
}

fn render_registry_nix(registry: &SecretRegistry, source: &Path) -> String {
    let mut out = format!(
        "# Generated from {}; do not edit by hand.\n{{\n",
        source.display()
    );
    if let Some(scope) = registry
        .can_personal_pc_env
        .as_ref()
        .or_else(|| registry.scopes.get("can"))
    {
        out.push_str("  canPersonalPcEnv = ");
        render_env_registry(&mut out, scope, 2);
        out.push_str(";\n");
    }
    if let Some(scope) = registry
        .shared_personal_pc_env
        .as_ref()
        .or_else(|| registry.scopes.get("shared"))
    {
        out.push_str("  sharedPersonalPcEnv = ");
        render_env_registry(&mut out, scope, 2);
        out.push_str(";\n");
    }
    out.push_str("  scopes = ");
    render_attrset(&mut out, registry.scopes.iter(), 1, render_env_registry);
    out.push_str(";\n");
    out.push_str("}\n");
    out
}

fn render_env_registry(out: &mut String, registry: &EnvRegistry, level: usize) {
    out.push_str("{\n");
    indent(out, level + 1);
    out.push_str("encrypted = ");
    render_attrset(out, registry.encrypted.iter(), level + 1, render_encrypted);
    out.push_str(";\n");
    indent(out, level + 1);
    out.push_str("plain = ");
    render_attrset(out, registry.plain.iter(), level + 1, render_plain);
    out.push_str(";\n");
    indent(out, level);
    out.push('}');
}

fn render_attrset<'a, T, I, F>(out: &mut String, values: I, level: usize, render: F)
where
    I: Iterator<Item = (&'a String, &'a T)>,
    T: 'a,
    F: Fn(&mut String, &'a T, usize),
{
    out.push_str("{\n");
    for (name, value) in values {
        indent(out, level + 1);
        out.push_str(&format!("{} = ", nix_attr_name(name)));
        render(out, value, level + 1);
        out.push_str(";\n");
    }
    indent(out, level);
    out.push('}');
}

fn render_encrypted(out: &mut String, entry: &EncryptedSecret, level: usize) {
    out.push_str("{\n");
    render_field(out, "source", level + 1, |out| {
        render_source(out, &entry.source, level + 1)
    });
    render_string_list_field(out, "env", &entry.env, level + 1);
    if let Some(sync) = &entry.sync {
        render_field(out, "sync", level + 1, |out| {
            render_sync(out, sync, level + 1)
        });
    }
    render_field(out, "runnerFileEnv", level + 1, |out| {
        render_list(
            out,
            &entry.runner_file_env,
            level + 1,
            render_runner_file_env,
        )
    });
    if let Some(value) = &entry.docker_registry {
        render_string_field(out, "dockerRegistry", value, level + 1);
    }
    if let Some(value) = &entry.copr_file {
        render_string_field(out, "coprFile", value, level + 1);
    }
    indent(out, level);
    out.push('}');
}

fn render_plain(out: &mut String, entry: &PlainSecret, level: usize) {
    out.push_str("{\n");
    render_string_field(out, "source", &entry.source, level + 1);
    render_string_field(out, "value", &entry.value, level + 1);
    if let Some(sync) = &entry.sync {
        render_field(out, "sync", level + 1, |out| {
            render_sync(out, sync, level + 1)
        });
    }
    indent(out, level);
    out.push('}');
}

fn render_source(out: &mut String, source: &Source, level: usize) {
    out.push_str("{\n");
    render_string_field(out, "kind", &source.kind, level + 1);
    if let Some(user) = &source.user {
        render_string_field(out, "user", user, level + 1);
    }
    render_string_field(out, "name", &source.name, level + 1);
    if let Some(relative) = &source.relative {
        render_string_field(out, "relative", relative, level + 1);
    }
    indent(out, level);
    out.push('}');
}

fn render_sync(out: &mut String, sync: &SyncTarget, level: usize) {
    out.push_str("{\n");
    render_string_field(out, "target", &sync.target, level + 1);
    render_string_field(out, "name", &sync.name, level + 1);
    render_bool_field(out, "codebergUser", sync.codeberg_user, level + 1);
    if !sync.codeberg.is_empty() {
        render_string_list_field(out, "codeberg", &sync.codeberg, level + 1);
    }
    if !sync.codefloe.is_empty() {
        render_string_list_field(out, "codefloe", &sync.codefloe, level + 1);
    }
    if !sync.github.is_empty() {
        render_string_list_field(out, "github", &sync.github, level + 1);
    }
    if !sync.codeberg_orgs.is_empty() {
        render_string_list_field(out, "codebergOrgs", &sync.codeberg_orgs, level + 1);
    }
    render_string_field(out, "host", &sync.host, level + 1);
    indent(out, level);
    out.push('}');
}

fn render_runner_file_env(out: &mut String, target: &RunnerFileEnvTarget, level: usize) {
    out.push_str("{\n");
    render_string_field(out, "env", &target.env, level + 1);
    render_string_list_field(out, "instances", &target.instances, level + 1);
    indent(out, level);
    out.push('}');
}

fn render_list<T, F>(out: &mut String, values: &[T], level: usize, render: F)
where
    F: Fn(&mut String, &T, usize),
{
    out.push_str("[\n");
    for value in values {
        indent(out, level + 1);
        render(out, value, level + 1);
        out.push('\n');
    }
    indent(out, level);
    out.push(']');
}

fn render_field<F>(out: &mut String, name: &str, level: usize, render: F)
where
    F: FnOnce(&mut String),
{
    indent(out, level);
    out.push_str(name);
    out.push_str(" = ");
    render(out);
    out.push_str(";\n");
}

fn render_string_field(out: &mut String, name: &str, value: &str, level: usize) {
    render_field(out, name, level, |out| {
        out.push('"');
        out.push_str(&nix_string(value));
        out.push('"');
    });
}

fn render_bool_field(out: &mut String, name: &str, value: bool, level: usize) {
    render_field(out, name, level, |out| {
        out.push_str(if value { "true" } else { "false" });
    });
}

fn render_string_list_field(out: &mut String, name: &str, values: &[String], level: usize) {
    render_field(out, name, level, |out| {
        out.push('[');
        for (idx, value) in values.iter().enumerate() {
            if idx > 0 {
                out.push(' ');
            }
            out.push('"');
            out.push_str(&nix_string(value));
            out.push('"');
        }
        out.push(']');
    });
}

fn indent(out: &mut String, level: usize) {
    out.push_str(&"  ".repeat(level));
}

fn nix_attr_name(name: &str) -> String {
    if name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        name.to_string()
    } else {
        format!("\"{}\"", nix_string(name))
    }
}

fn default_host() -> String {
    "codeberg.org".to_string()
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_default_host(value: &str) -> bool {
    value == "codeberg.org"
}

fn null_to_empty_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_env_requires_file_suffix() {
        assert!(validate_runner_env("COPR_TOKEN_FILE").is_ok());
        assert!(validate_runner_env("COPR_TOKEN").is_err());
    }

    #[test]
    fn render_nix_includes_runner_file_env() {
        let mut registry = SecretRegistry {
            scopes: BTreeMap::new(),
            can_personal_pc_env: None,
            shared_personal_pc_env: None,
        };
        registry.scopes.insert(
            "can".to_string(),
            EnvRegistry {
                encrypted: BTreeMap::from([(
                    "copr-token".to_string(),
                    EncryptedSecret {
                        source: Source {
                            kind: "module".to_string(),
                            user: None,
                            name: "repos/coppr/token".to_string(),
                            relative: Some("age/secrets/modules/repos/coppr/token.age".to_string()),
                        },
                        env: vec!["COPR_TOKEN".to_string()],
                        sync: None,
                        runner_file_env: vec![RunnerFileEnvTarget {
                            env: "COPR_TOKEN_FILE".to_string(),
                            instances: vec!["nixTrusted".to_string()],
                        }],
                        docker_registry: None,
                        copr_file: None,
                    },
                )]),
                plain: BTreeMap::new(),
            },
        );

        let rendered = render_registry_nix(&registry, Path::new("registry.pkl"));

        assert!(rendered.contains("runnerFileEnv"));
        assert!(rendered.contains("COPR_TOKEN_FILE"));
        assert!(rendered.contains("nixTrusted"));
    }

    #[test]
    fn render_sync_includes_codefloe_and_github() {
        let sync = SyncTarget {
            target: "ci-token".to_string(),
            name: "CI_TOKEN".to_string(),
            codeberg_user: false,
            codeberg: Vec::new(),
            codefloe: vec!["caniko/codefloe-repo".to_string()],
            github: vec!["caniko/github-repo".to_string()],
            codeberg_orgs: Vec::new(),
            host: default_host(),
        };
        let mut rendered = String::new();
        render_sync(&mut rendered, &sync, 0);
        assert!(rendered.contains("codefloe = [\"caniko/codefloe-repo\"]"));
        assert!(rendered.contains("github = [\"caniko/github-repo\"]"));
    }
}
