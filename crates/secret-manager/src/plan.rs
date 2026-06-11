use anyhow::{anyhow, bail, Result};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nix_manager_core::exec;

use crate::io::{
    adopt_age_file, display_rel, encrypt_plaintext_to_age, read_plaintext,
    read_plaintext_editor_when_tty, splice_import, stage_and_rekey, validate_ident, validate_slug,
    TempDir,
};
use crate::render::{
    camel, default_forgejo_ssh_key_age_name, nix_string, render_modules, GeneratorSpec,
    RenderedModule, TargetSpec, LIB_BINDING,
};

#[derive(Debug, Clone, Default)]
pub struct CommonSourceArgs {
    pub from_file: Option<PathBuf>,
    pub editor_when_tty: bool,
    pub force_existing: bool,
    pub no_rekey: bool,
    pub no_stage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Generate(GeneratorSpec),
    Plaintext,
    FromAge(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddPlan {
    pub slug: String,
    pub source: SourceKind,
    pub targets: Vec<TargetSpec>,
    pub source_only_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgejoSshKeyPlan {
    pub slug: String,
    pub credential_name: String,
    pub pubkey_var: String,
    pub rotate: bool,
    pub target: TargetSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpgKeyPairSource {
    Generate,
    FromFile(PathBuf),
    FromAge(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgejoGpgKeyPairPlan {
    pub slug: String,
    pub credential_name: String,
    pub module_dir: String,
    pub user_id: String,
    pub source: GpgKeyPairSource,
    pub rotate: bool,
    pub secret_path: PathBuf,
}

pub fn run_plan(args: &CommonSourceArgs, plan: AddPlan) -> Result<()> {
    let repo_root = std::env::current_dir()?;
    let modules = render_modules(
        &plan.targets,
        match &plan.source {
            SourceKind::Generate(generator) => Some(generator),
            SourceKind::Plaintext | SourceKind::FromAge(_) => None,
        },
    );

    validate_module_destinations(&repo_root, &modules)?;
    prepare_secret_sources(&repo_root, args, &plan, &modules)?;
    write_modules(&repo_root, &modules)?;

    match &plan.source {
        SourceKind::Generate(generator) => {
            if !modules.is_empty() {
                stage_modules_for_generate(&repo_root, &modules, args.no_stage)?;
            }
            generate_declared_secrets(&repo_root, &modules, &plan.source_only_paths, generator)?;
            finish_generate(
                &repo_root,
                &modules,
                &plan.source_only_paths,
                args.no_rekey,
                args.no_stage,
            )?;
            print_generated_summary(&repo_root, &modules, &plan.source_only_paths);
        }
        SourceKind::Plaintext | SourceKind::FromAge(_) => {
            let paths = touched_paths(&repo_root, &modules, &plan.source_only_paths, true);
            let refs = paths.iter().map(PathBuf::as_path).collect::<Vec<_>>();
            stage_and_rekey(&repo_root, &refs, args.no_stage, args.no_rekey)?;
            print_written_summary(&repo_root, &modules, &plan.source_only_paths);
        }
    }

    Ok(())
}

pub fn build_forgejo_gpg_key_pair_plan(
    name: &str,
    cred: &str,
    module_dir: &str,
    user_id: Option<&str>,
    from_file: Option<PathBuf>,
    from_age: Option<PathBuf>,
    rotate: bool,
) -> Result<ForgejoGpgKeyPairPlan> {
    validate_slug(name)?;
    validate_ident(cred, "cred")?;
    validate_module_dir(module_dir)?;
    validate_gpg_key_pair_slug(name)?;

    let source = match (from_file, from_age) {
        (Some(path), None) => GpgKeyPairSource::FromFile(path),
        (None, Some(path)) => GpgKeyPairSource::FromAge(path),
        (None, None) => GpgKeyPairSource::Generate,
        (Some(_), Some(_)) => bail!("--from-file and --from-age are mutually exclusive"),
    };

    let user_id = user_id
        .map(str::to_string)
        .unwrap_or_else(|| format!("{name} <{name}@secrets.invalid>"));
    if user_id.trim().is_empty() {
        bail!("--user-id must not be empty");
    }

    Ok(ForgejoGpgKeyPairPlan {
        slug: name.to_string(),
        credential_name: cred.to_string(),
        module_dir: module_dir.trim_matches('/').to_string(),
        user_id,
        source,
        rotate,
        secret_path: PathBuf::from(format!(
            "age/secrets/modules/{}/{}.age",
            module_dir.trim_matches('/'),
            name
        )),
    })
}

pub fn run_forgejo_gpg_key_pair_plan(
    plan: &ForgejoGpgKeyPairPlan,
    no_stage: bool,
    no_rekey: bool,
) -> Result<()> {
    let repo_root = std::env::current_dir()?;
    let secret_path = repo_root.join(&plan.secret_path);
    let public_path = secret_path.with_extension("asc");
    let fingerprint_path = secret_path.with_extension("fingerprint");

    if let Some(parent) = secret_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let should_write_private = plan.rotate || !secret_path.exists();
    if should_write_private {
        match &plan.source {
            GpgKeyPairSource::Generate => {
                let private_key = generate_gpg_private_key(&plan.user_id)?;
                encrypt_plaintext_to_age(&secret_path, &private_key)?;
            }
            GpgKeyPairSource::FromFile(path) => {
                let private_key = read_plaintext(Some(path))?;
                validate_armored_private_gpg_key(&private_key)?;
                encrypt_plaintext_to_age(&secret_path, &private_key)?;
            }
            GpgKeyPairSource::FromAge(path) => {
                if path == &plan.secret_path || repo_root.join(path) == secret_path {
                    if !secret_path.exists() {
                        bail!(
                            "--from-age points at {}, but that destination does not exist",
                            display_rel(&repo_root, &secret_path)
                        );
                    }
                } else {
                    adopt_age_file(&repo_root, path, &secret_path, false)?;
                }
            }
        }
    } else {
        eprintln!(
            "preserving existing private key source: {}",
            display_rel(&repo_root, &secret_path)
        );
    }

    let private_key = view_age_secret(&plan.secret_path)?;
    validate_armored_private_gpg_key(&private_key)?;
    let public = derive_gpg_public_metadata(&private_key)?;
    fs::write(&public_path, &public.public_key)?;
    fs::write(&fingerprint_path, format!("{}\n", public.fingerprint))?;

    let mut paths = vec![secret_path, public_path, fingerprint_path];
    paths.sort();
    stage_paths(&repo_root, &paths, no_stage)?;

    if should_write_private && !no_rekey {
        exec::run("agenix", ["rekey", "-a"])?;
    } else if should_write_private {
        eprintln!();
        eprintln!("skipped rekey — run `agenix rekey -a` before deploying.");
    }

    eprintln!();
    eprintln!("private key Actions secret: {}", plan.credential_name);
    eprintln!(
        "private key source: {}",
        display_rel(&repo_root, &repo_root.join(&plan.secret_path))
    );
    eprintln!(
        "public key: {}",
        display_rel(
            &repo_root,
            &repo_root.join(&plan.secret_path).with_extension("asc")
        )
    );
    eprintln!(
        "fingerprint: {}",
        display_rel(
            &repo_root,
            &repo_root
                .join(&plan.secret_path)
                .with_extension("fingerprint")
        )
    );
    println!("{}", public.fingerprint);
    Ok(())
}

pub fn build_forgejo_ssh_plan(
    name: &str,
    cred: &str,
    pubkey_var: Option<&String>,
    instances: &[String],
    rotate: bool,
) -> Result<ForgejoSshKeyPlan> {
    validate_slug(name)?;
    validate_ident(cred, "cred")?;
    let pubkey_var = pubkey_var
        .cloned()
        .unwrap_or_else(|| default_pubkey_var(name));
    validate_nix_identifier(&pubkey_var, "pubkey-var")?;

    let instances = crate::add::sorted_instances(instances, "instance")?;
    let credential_name = if instances.is_empty() {
        None
    } else {
        Some(cred.to_string())
    };

    Ok(ForgejoSshKeyPlan {
        slug: name.to_string(),
        credential_name: cred.to_string(),
        pubkey_var,
        rotate,
        target: TargetSpec::Forgejo(crate::render::ForgejoTarget {
            slug: name.to_string(),
            age_name: default_forgejo_ssh_key_age_name(name),
            credential_name,
            instances,
        }),
    })
}

pub fn run_forgejo_ssh_key_plan(
    plan: &ForgejoSshKeyPlan,
    no_stage: bool,
    no_rekey: bool,
) -> Result<()> {
    let repo_root = std::env::current_dir()?;
    let generator = GeneratorSpec::SshKey {
        algorithm: "ed25519".to_string(),
    };
    let module = render_modules(std::slice::from_ref(&plan.target), Some(&generator))
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("internal error: forgejo ssh-key plan rendered no module"))?;

    let module_path = repo_root.join(&module.path);
    let default_nix = repo_root.join(&module.default_nix);
    let secret_path = repo_root.join(&module.secret_path);
    let module_existed = module_path.exists();

    if module_existed {
        let existing = fs::read_to_string(&module_path)?;
        validate_existing_forgejo_ssh_key_module(&existing, plan)?;
        write_forgejo_ssh_key_module(&repo_root, &module, &module.body, false)?;
    } else {
        if secret_path.exists() {
            bail!(
                "{} exists but {} does not; refusing to attach to a private key without its defining Nix module",
                display_rel(&repo_root, &secret_path),
                display_rel(&repo_root, &module_path)
            );
        }
        validate_module_destinations(&repo_root, std::slice::from_ref(&module))?;
        write_forgejo_ssh_key_module(&repo_root, &module, &module.body, true)?;
    }

    if !module_existed || plan.rotate {
        stage_modules_for_generate(&repo_root, std::slice::from_ref(&module), no_stage)?;
    }

    let generated = generate_or_preserve_forgejo_ssh_key(&module, &secret_path, plan.rotate)?;
    if generated && !no_rekey {
        exec::run("agenix", ["rekey", "-a"])?;
    } else if generated {
        eprintln!();
        eprintln!("skipped rekey — run `agenix rekey -a` before deploying.");
    }

    let pubkey = read_or_derive_pubkey(&repo_root, &module.secret_path)?;
    let body = upsert_forgejo_pubkey_comment(
        &module.body,
        &plan.credential_name,
        &plan.pubkey_var,
        &pubkey,
    )?;
    fs::write(&module_path, body)?;

    let mut paths = vec![module_path, secret_path];
    if !module_existed {
        paths.push(default_nix);
    }
    let pub_path = repo_root.join(&module.secret_path).with_extension("pub");
    if pub_path.exists() {
        paths.push(pub_path);
    }
    stage_paths(&repo_root, &paths, no_stage)?;

    eprintln!();
    eprintln!(
        "{} private key source: {}",
        if generated { "generated" } else { "refreshed" },
        display_rel(&repo_root, &repo_root.join(&module.secret_path))
    );
    eprintln!("public key variable: {}", plan.pubkey_var);
    println!("{pubkey}");
    Ok(())
}

fn validate_existing_forgejo_ssh_key_module(body: &str, plan: &ForgejoSshKeyPlan) -> Result<()> {
    let source_line = format!(
        "source = secrets.module \"foregejo-runner/{}\";",
        nix_string(&plan.slug)
    );
    let mk_secret_call = format!("{LIB_BINDING}.mkSecret");
    for required in [
        mk_secret_call.as_str(),
        source_line.as_str(),
        "generator = \"ssh-key\";",
        "algorithm = \"ed25519\";",
    ] {
        if !body.contains(required) {
            bail!(
                "existing forgejo ssh-key module for `{}` is not the expected generated Ed25519 secret module; missing `{required}`",
                plan.slug
            );
        }
    }
    Ok(())
}

fn write_forgejo_ssh_key_module(
    repo_root: &Path,
    module: &RenderedModule,
    body: &str,
    splice: bool,
) -> Result<()> {
    let path = repo_root.join(&module.path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, body)?;
    eprintln!("wrote {}", display_rel(repo_root, &path));

    if splice {
        let default_nix = repo_root.join(&module.default_nix);
        let slug = module
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                anyhow!(
                    "generated module path has no UTF-8 stem: {}",
                    module.path.display()
                )
            })?;
        splice_import(&default_nix, slug)?;
        eprintln!("updated {}", display_rel(repo_root, &default_nix));
    }
    Ok(())
}

fn generate_or_preserve_forgejo_ssh_key(
    module: &RenderedModule,
    secret_path: &Path,
    rotate: bool,
) -> Result<bool> {
    let rel = module.secret_path.display().to_string();
    if secret_path.exists() {
        if rotate {
            exec::run(
                "agenix",
                ["generate", "--force-generate", "-a", rel.as_str()],
            )?;
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        exec::run("agenix", ["generate", "-a", rel.as_str()])?;
        Ok(true)
    }
}

fn stage_paths(repo_root: &Path, paths: &[PathBuf], no_stage: bool) -> Result<()> {
    if no_stage {
        eprintln!();
        eprintln!("skipped staging — run `git add` for the generated secret files.");
        return Ok(());
    }
    let rels = paths
        .iter()
        .map(|p| display_rel(repo_root, p))
        .collect::<Vec<_>>();
    exec::run(
        "git",
        std::iter::once("add").chain(rels.iter().map(String::as_str)),
    )
}

fn validate_module_destinations(repo_root: &Path, modules: &[RenderedModule]) -> Result<()> {
    for module in modules {
        let path = repo_root.join(&module.path);
        if path.exists() {
            bail!(
                "{} already exists — pick a different --name.",
                path.display()
            );
        }
        let default_nix = repo_root.join(&module.default_nix);
        if !default_nix.is_file() {
            bail!(
                "missing {} — cannot splice generated module import",
                default_nix.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn prepare_secret_sources(
    repo_root: &Path,
    args: &CommonSourceArgs,
    plan: &AddPlan,
    modules: &[RenderedModule],
) -> Result<()> {
    let secret_paths = planned_secret_paths(modules, &plan.source_only_paths);
    for secret_path in &secret_paths {
        if let Some(parent) = repo_root.join(secret_path).parent() {
            fs::create_dir_all(parent)?;
        }
    }

    match &plan.source {
        SourceKind::Generate(_) => {
            for rel_secret_path in &secret_paths {
                let secret_path = repo_root.join(rel_secret_path);
                if secret_path.exists() {
                    bail!(
                        "{} already exists — pick a different --name or edit it with `agenix edit`.",
                        secret_path.display()
                    );
                }
            }
            Ok(())
        }
        SourceKind::Plaintext => {
            let plaintext = if args.editor_when_tty {
                read_plaintext_editor_when_tty(args.from_file.as_deref())?
            } else {
                read_plaintext(args.from_file.as_deref())?
            };
            for rel_secret_path in &secret_paths {
                let secret_path = repo_root.join(rel_secret_path);
                if secret_path.exists() {
                    bail!(
                        "{} already exists — pick a different --name or edit it with `agenix edit`.",
                        secret_path.display()
                    );
                }
                encrypt_plaintext_to_age(&secret_path, &plaintext)?;
            }
            Ok(())
        }
        SourceKind::FromAge(src) => {
            for rel_secret_path in &secret_paths {
                let secret_path = repo_root.join(rel_secret_path);
                adopt_age_file(repo_root, src, &secret_path, args.force_existing)?;
            }
            Ok(())
        }
    }
}

fn write_modules(repo_root: &Path, modules: &[RenderedModule]) -> Result<()> {
    for module in modules {
        let path = repo_root.join(&module.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &module.body)?;
        eprintln!("wrote {}", display_rel(repo_root, &path));

        let default_nix = repo_root.join(&module.default_nix);
        let slug = module
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                anyhow!(
                    "generated module path has no UTF-8 stem: {}",
                    module.path.display()
                )
            })?;
        splice_import(&default_nix, slug)?;
        eprintln!("updated {}", display_rel(repo_root, &default_nix));
    }
    Ok(())
}

fn stage_modules_for_generate(
    repo_root: &Path,
    modules: &[RenderedModule],
    no_stage: bool,
) -> Result<()> {
    if no_stage {
        eprintln!();
        eprintln!(
            "warning: --no-stage with --generate may make the new generator module invisible to agenix"
        );
        return Ok(());
    }
    let paths = touched_paths(repo_root, modules, &[], false);
    let rels = paths
        .iter()
        .map(|p| display_rel(repo_root, p))
        .collect::<Vec<_>>();
    exec::run(
        "git",
        std::iter::once("add").chain(rels.iter().map(String::as_str)),
    )
}

fn generate_declared_secrets(
    repo_root: &Path,
    modules: &[RenderedModule],
    source_only_paths: &[PathBuf],
    generator: &GeneratorSpec,
) -> Result<()> {
    for rel_path in planned_secret_paths(modules, source_only_paths) {
        let rel = rel_path.display().to_string();
        exec::run("agenix", ["generate", "-a", rel.as_str()])?;
        if matches!(generator, GeneratorSpec::SshKey { .. }) {
            print_or_derive_pubkey(repo_root, &rel_path)?;
        }
    }
    Ok(())
}

fn finish_generate(
    repo_root: &Path,
    modules: &[RenderedModule],
    source_only_paths: &[PathBuf],
    no_rekey: bool,
    no_stage: bool,
) -> Result<()> {
    if !no_rekey {
        exec::run("agenix", ["rekey", "-a"])?;
    } else {
        eprintln!();
        eprintln!("skipped rekey — run `agenix rekey -a` before deploying.");
    }
    let paths = touched_paths(repo_root, modules, source_only_paths, true);
    stage_paths(repo_root, &paths, no_stage)
}

fn print_or_derive_pubkey(repo_root: &Path, secret_path: &Path) -> Result<()> {
    let pubkey = read_or_derive_pubkey(repo_root, secret_path)?;
    let pub_path = repo_root.join(secret_path).with_extension("pub");
    eprintln!();
    if pub_path.is_file() {
        eprintln!("public key from {}:", display_rel(repo_root, &pub_path));
    } else {
        eprintln!(
            "public key derived from {}:",
            display_rel(repo_root, &repo_root.join(secret_path))
        );
    }
    println!("{pubkey}");
    eprintln!("wire it up where the consuming service expects the public key.");
    Ok(())
}

fn read_or_derive_pubkey(repo_root: &Path, secret_path: &Path) -> Result<String> {
    let pub_path = repo_root.join(secret_path).with_extension("pub");
    if pub_path.is_file() {
        let pubkey = fs::read_to_string(&pub_path)?;
        return validate_single_line_pubkey(&pubkey);
    }

    let rel = secret_path.display().to_string();
    let private_key = exec::capture("agenix", ["view", rel.as_str()])?;
    let tmp = TempDir::new()?;
    let private_path = tmp.path.join("ssh-key");
    fs::write(&private_path, private_key)?;
    fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600))?;
    let pubkey = exec::capture("ssh-keygen", ["-y", "-f", private_path.to_str().unwrap()])?;
    validate_single_line_pubkey(&pubkey)
}

fn validate_single_line_pubkey(pubkey: &str) -> Result<String> {
    let trimmed = pubkey.trim();
    if trimmed.is_empty() {
        bail!("derived public key is empty");
    }
    if trimmed.contains('\n') {
        bail!("derived public key contains multiple lines");
    }
    Ok(trimmed.to_string())
}

fn validate_ed25519_pubkey(pubkey: &str) -> Result<String> {
    let trimmed = validate_single_line_pubkey(pubkey)?;
    if !trimmed.starts_with("ssh-ed25519 ") {
        bail!("expected an Ed25519 public key, got `{trimmed}`");
    }
    Ok(trimmed)
}

pub(crate) fn upsert_forgejo_pubkey_comment(
    body: &str,
    credential_name: &str,
    pubkey_var: &str,
    pubkey: &str,
) -> Result<String> {
    let pubkey = validate_ed25519_pubkey(pubkey)?;
    let mut lines = Vec::new();
    let mut skip_value_line = false;
    for line in body.lines() {
        if skip_value_line {
            skip_value_line = false;
            if line.trim_start().starts_with("# ") {
                continue;
            }
        }
        if line
            .trim_start()
            .starts_with("# canix generated public key for Forgejo Actions secret ")
        {
            skip_value_line = true;
            continue;
        }
        lines.push(line.to_string());
    }

    let mut cleaned = lines.join("\n");
    if body.ends_with('\n') || !cleaned.is_empty() {
        cleaned.push('\n');
    }

    let imports_idx = cleaned
        .find("imports = [")
        .ok_or_else(|| anyhow!("`imports = [` not found in generated Forgejo secret module"))?;
    let line_start = cleaned[..imports_idx]
        .rfind('\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let indent = &cleaned[line_start..imports_idx];
    let block = format!(
        "{indent}# canix generated public key for Forgejo Actions secret {}.\n{indent}# {} = \"{}\";\n",
        credential_name,
        pubkey_var,
        nix_string(&pubkey)
    );

    let mut out = String::with_capacity(cleaned.len() + block.len());
    out.push_str(&cleaned[..line_start]);
    out.push_str(&block);
    out.push_str(&cleaned[line_start..]);
    Ok(out)
}

fn default_pubkey_var(slug: &str) -> String {
    let mut name = camel(slug);
    if let Some(stripped) = name.strip_suffix("Key") {
        name = stripped.to_string();
    }
    lower_first_ascii(&name) + "PublicKey"
}

fn lower_first_ascii(value: &str) -> String {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = first.to_ascii_lowercase().to_string();
    out.extend(chars);
    out
}

fn validate_nix_identifier(value: &str, label: &str) -> Result<()> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        bail!("{label} is empty");
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        bail!("{label} `{value}` must start with an ASCII letter or `_`");
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("{label} `{value}` must use ASCII alphanumerics or `_`");
    }
    Ok(())
}

fn validate_module_dir(value: &str) -> Result<()> {
    let trimmed = value.trim_matches('/');
    if trimmed.is_empty() {
        bail!("--module-dir must not be empty");
    }
    if trimmed
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("--module-dir `{value}` must be a relative module-secret directory");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'))
    {
        bail!("--module-dir `{value}` must use ASCII alphanumerics, '-', '_', or '/'");
    }
    Ok(())
}

fn validate_gpg_key_pair_slug(slug: &str) -> Result<()> {
    let lower = slug.to_ascii_lowercase();
    if lower.ends_with("-id")
        || lower.ends_with("-key-id")
        || lower.ends_with("-fingerprint")
        || lower.ends_with("-public-key")
        || lower.ends_with("-pub")
    {
        bail!("`{slug}` looks like public GPG metadata; only the private key should be encrypted");
    }
    Ok(())
}

fn validate_armored_private_gpg_key(value: &str) -> Result<()> {
    if !value.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        bail!("expected an ASCII-armored OpenPGP private key");
    }
    Ok(())
}

fn view_age_secret(secret_path: &Path) -> Result<String> {
    let rel = secret_path.display().to_string();
    exec::capture("agenix", ["view", rel.as_str()])
}

fn generate_gpg_private_key(user_id: &str) -> Result<String> {
    let tmp = TempDir::new()?;
    let gnupg = tmp.path.join("gnupg");
    fs::create_dir_all(&gnupg)?;
    fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700))?;
    run_with_env(
        "gpg",
        [
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            user_id,
            "rsa4096",
            "sign",
            "0",
        ],
        [("GNUPGHOME", gnupg.as_os_str())],
    )?;
    let metadata = export_gpg_public_metadata(&gnupg)?;
    capture_with_env(
        "gpg",
        [
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--armor",
            "--export-secret-keys",
            &metadata.fingerprint,
        ],
        [("GNUPGHOME", gnupg.as_os_str())],
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GpgPublicMetadata {
    fingerprint: String,
    public_key: String,
}

fn derive_gpg_public_metadata(private_key: &str) -> Result<GpgPublicMetadata> {
    let tmp = TempDir::new()?;
    let gnupg = tmp.path.join("gnupg");
    fs::create_dir_all(&gnupg)?;
    fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700))?;
    let key_path = tmp.path.join("private.asc");
    fs::write(&key_path, private_key)?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    run_with_env(
        "gpg",
        [
            "--batch",
            "--import",
            key_path
                .to_str()
                .ok_or_else(|| anyhow!("non-utf8 tmp key path"))?,
        ],
        [("GNUPGHOME", gnupg.as_os_str())],
    )?;
    export_gpg_public_metadata(&gnupg)
}

fn export_gpg_public_metadata(gnupg: &Path) -> Result<GpgPublicMetadata> {
    let listing = capture_with_env(
        "gpg",
        ["--batch", "--with-colons", "--list-secret-keys"],
        [("GNUPGHOME", gnupg.as_os_str())],
    )?;
    let fingerprint = listing
        .lines()
        .find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.first() == Some(&"fpr") {
                fields.get(9).map(|value| value.to_string())
            } else {
                None
            }
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("gpg import produced no secret-key fingerprint"))?;
    let public_key = capture_with_env(
        "gpg",
        ["--batch", "--armor", "--export", &fingerprint],
        [("GNUPGHOME", gnupg.as_os_str())],
    )?;
    if !public_key.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        bail!("gpg public-key export did not produce an armored public key");
    }
    Ok(GpgPublicMetadata {
        fingerprint,
        public_key,
    })
}

fn run_with_env<I, S, K, V>(
    program: &str,
    args: I,
    envs: impl IntoIterator<Item = (K, V)>,
) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let captured = exec::cap_with_env(program, args, envs);
    if captured.ok() {
        Ok(())
    } else {
        Err(anyhow!(
            "{program} exited with status {}: {}",
            captured.exit_code,
            captured.stderr.trim()
        ))
    }
}

fn capture_with_env<I, S, K, V>(
    program: &str,
    args: I,
    envs: impl IntoIterator<Item = (K, V)>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let captured = exec::cap_with_env(program, args, envs);
    if captured.ok() {
        Ok(captured.stdout.trim().to_string())
    } else {
        Err(anyhow!(
            "{program} exited with status {}: {}",
            captured.exit_code,
            captured.stderr.trim()
        ))
    }
}

fn touched_paths(
    repo_root: &Path,
    modules: &[RenderedModule],
    source_only_paths: &[PathBuf],
    include_secret: bool,
) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    for module in modules {
        paths.insert(repo_root.join(&module.path));
        paths.insert(repo_root.join(&module.default_nix));
        if include_secret {
            paths.insert(repo_root.join(&module.secret_path));
            let pub_path = repo_root.join(&module.secret_path).with_extension("pub");
            if pub_path.exists() {
                paths.insert(pub_path);
            }
        }
    }
    if include_secret {
        for source_path in source_only_paths {
            paths.insert(repo_root.join(source_path));
            let pub_path = repo_root.join(source_path).with_extension("pub");
            if pub_path.exists() {
                paths.insert(pub_path);
            }
        }
    }
    paths.into_iter().collect()
}

fn planned_secret_paths(modules: &[RenderedModule], source_only_paths: &[PathBuf]) -> Vec<PathBuf> {
    modules
        .iter()
        .map(|module| module.secret_path.clone())
        .chain(source_only_paths.iter().cloned())
        .collect()
}

fn print_written_summary(
    repo_root: &Path,
    modules: &[RenderedModule],
    source_only_paths: &[PathBuf],
) {
    eprintln!();
    for source_path in planned_secret_paths(modules, source_only_paths) {
        eprintln!(
            "secret source: {}",
            display_rel(repo_root, &repo_root.join(source_path))
        );
    }
    if !modules.is_empty() {
        eprintln!("rebuild the consuming host to deliver the secret.");
    }
}

fn print_generated_summary(
    repo_root: &Path,
    modules: &[RenderedModule],
    source_only_paths: &[PathBuf],
) {
    eprintln!();
    for source_path in planned_secret_paths(modules, source_only_paths) {
        eprintln!(
            "generated source: {}",
            display_rel(repo_root, &repo_root.join(source_path))
        );
    }
    if !modules.is_empty() {
        eprintln!("rebuild the consuming host to deliver the secret.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Stack;

    #[test]
    fn existing_generated_secret_source_refuses_overwrite() {
        let temp = TempDir::new().unwrap();
        let secret_path = temp.path.join("age/secrets/users/can/app-token.age");
        fs::create_dir_all(secret_path.parent().unwrap()).unwrap();
        fs::write(&secret_path, "existing").unwrap();

        let module = RenderedModule {
            path: PathBuf::from("home/user/can/repositories/app-token.nix"),
            body: String::new(),
            default_nix: PathBuf::from("home/user/can/repositories/default.nix"),
            secret_path: PathBuf::from("age/secrets/users/can/app-token.age"),
            stack: Stack::Home,
        };
        let plan = AddPlan {
            slug: "app-token".to_string(),
            source: SourceKind::Generate(GeneratorSpec::Passphrase { length: 32 }),
            targets: Vec::new(),
            source_only_paths: Vec::new(),
        };
        let err = prepare_secret_sources(
            &temp.path,
            &CommonSourceArgs::default(),
            &plan,
            std::slice::from_ref(&module),
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn forgejo_pubkey_comment_upsert_replaces_existing_block() {
        let body = "{\n  imports = [\n    ./old.nix\n  ];\n}\n";
        let once = upsert_forgejo_pubkey_comment(
            body,
            "AUR_SSH_KEY",
            "aurSshPublicKey",
            "ssh-ed25519 AAAA first",
        )
        .unwrap();
        let twice = upsert_forgejo_pubkey_comment(
            &once,
            "AUR_SSH_KEY",
            "aurSshPublicKey",
            "ssh-ed25519 BBBB second",
        )
        .unwrap();
        assert!(twice.contains(
            "# canix generated public key for Forgejo Actions secret AUR_SSH_KEY.\n  # aurSshPublicKey = \"ssh-ed25519 BBBB second\";"
        ));
        assert!(!twice.contains("ssh-ed25519 AAAA first"));
        assert_eq!(twice.matches("canix generated public key").count(), 1);
    }
}
