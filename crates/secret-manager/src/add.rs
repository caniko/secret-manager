use anyhow::{Result, anyhow, bail};
use clap::{Args, Subcommand};
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::env::StoreEnv;
use crate::io::{default_slug, validate_ident, validate_slug, validate_unit_name};
use crate::plan::{
    AddPlan, CommonSourceArgs, ForgejoGpgKeyPairPlan, ForgejoSshKeyPlan, SourceKind,
    build_forgejo_gpg_key_pair_plan, build_forgejo_ssh_plan, run_forgejo_gpg_key_pair_plan,
    run_forgejo_ssh_key_plan, run_plan,
};
use crate::render::{
    ForgejoTarget, GeneratorSpec, HomeTarget, SharedHomeTarget, SystemTarget, TargetSpec,
    default_forgejo_age_name,
};

#[derive(Subcommand, Debug)]
pub enum HmCmd {
    /// Generate an SSH private key and expose it as a home-manager file.
    Ssh(HmSshArgs),
    /// Generate a passphrase and expose it as env vars or a home-manager file.
    Password(HmPasswordArgs),
    /// Encrypt text from the editor, stdin, or --from-file and expose it as env vars.
    Text(HmTextArgs),
    /// Encrypt a file payload and expose it as a home-manager file.
    File(HmFileArgs),
}

#[derive(Subcommand, Debug)]
pub enum NixosCmd {
    /// Generate an SSH private key and expose it as a NixOS file.
    Ssh(NixosSshArgs),
    /// Generate a passphrase and expose it as service env vars or a NixOS file.
    Password(NixosPasswordArgs),
    /// Encrypt text from stdin or --from-file and expose it as service env vars.
    Text(NixosTextArgs),
    /// Encrypt a file payload and expose it as a NixOS file.
    File(NixosFileArgs),
}

#[derive(Subcommand, Debug)]
pub enum ForgejoCmd {
    /// Generate or refresh a Forgejo Actions SSH deploy key source.
    Ssh(ForgejoSshArgs),
    /// Generate, adopt, or refresh an OpenPGP signing key source.
    #[command(name = "gpg-key-pair")]
    GpgKeyPair(ForgejoGpgKeyPairArgs),
    /// Generate a passphrase and expose it as a runner credential.
    Password(ForgejoPasswordArgs),
    /// Encrypt text from stdin or --from-file and expose it as a runner credential.
    Text(ForgejoTextArgs),
    /// Encrypt a file payload and expose it as a runner credential.
    File(ForgejoFileArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct ExecutionArgs {
    /// Skip `agenix rekey -a`.
    #[arg(long, default_value_t = false)]
    pub no_rekey: bool,

    /// Skip `git add` staging where possible.
    #[arg(long, default_value_t = false)]
    pub no_stage: bool,
}

#[derive(Args, Debug, Clone)]
pub struct HmBaseArgs {
    /// Home-manager user that will consume the secret. Defaults to the current login user.
    #[arg(long, conflicts_with = "shared")]
    pub user: Option<String>,

    /// Store under age/secrets/users/shared and optionally register as shared HM env.
    #[arg(long, default_value_t = false)]
    pub shared: bool,
}

#[derive(Args, Debug, Clone)]
pub struct NixosBaseArgs {
    /// NixOS host that will consume the secret.
    #[arg(long)]
    pub host: String,
}

#[derive(Args, Debug, Clone)]
pub struct FileSourceArgs {
    /// Read plaintext from this file. If no source flag is passed, plaintext is read from stdin.
    #[arg(long = "from-file")]
    pub from_file: Option<PathBuf>,

    /// Adopt an existing encrypted .age file.
    #[arg(long = "from-age", conflicts_with = "from_file")]
    pub from_age: Option<PathBuf>,

    /// Bypass duplicate-reference checks when adopting --from-age.
    #[arg(long, default_value_t = false)]
    pub force_existing: bool,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct HmSshArgs {
    #[command(flatten)]
    pub target: HmBaseArgs,

    /// Secret slug used for the agenix source path.
    #[arg(long)]
    pub name: String,

    /// File path exposed to the home profile.
    #[arg(long = "file")]
    pub file: Option<String>,

    /// SSH key algorithm.
    #[arg(long, default_value = "ed25519")]
    pub algorithm: String,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct HmPasswordArgs {
    #[command(flatten)]
    pub target: HmBaseArgs,

    /// Secret slug used for the agenix source path.
    #[arg(long)]
    pub name: String,

    /// Environment variable names exposed to the home profile.
    #[arg(long = "env", num_args = 1..)]
    pub env: Vec<String>,

    /// File path exposed to the home profile.
    #[arg(long = "file", num_args = 1..)]
    pub file: Vec<String>,

    /// Passphrase length.
    #[arg(long, default_value_t = 32)]
    pub length: u32,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct HmTextArgs {
    #[command(flatten)]
    pub target: HmBaseArgs,

    /// Secret slug. Defaults from the first --env value.
    #[arg(long)]
    pub name: Option<String>,

    /// Environment variable names exposed to the home profile.
    #[arg(long = "env", num_args = 1..)]
    pub env: Vec<String>,

    /// Read plaintext from this file. If omitted, plaintext is read from stdin.
    #[arg(long = "from-file")]
    pub from_file: Option<PathBuf>,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct HmFileArgs {
    #[command(flatten)]
    pub target: HmBaseArgs,

    /// Secret slug. Required unless --from-age can provide a filename stem.
    #[arg(long)]
    pub name: Option<String>,

    /// File path exposed to the home profile.
    #[arg(long = "file")]
    pub file: Option<String>,

    #[command(flatten)]
    pub source: FileSourceArgs,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct NixosSshArgs {
    #[command(flatten)]
    pub target: NixosBaseArgs,

    /// Secret slug used for the agenix source path.
    #[arg(long)]
    pub name: String,

    /// File path exposed on the host.
    #[arg(long = "file")]
    pub file: String,

    /// SSH key algorithm.
    #[arg(long, default_value = "ed25519")]
    pub algorithm: String,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct NixosPasswordArgs {
    #[command(flatten)]
    pub target: NixosBaseArgs,

    /// Secret slug used for the agenix source path.
    #[arg(long)]
    pub name: String,

    /// Environment variable names exposed to systemd services.
    #[arg(long = "env", num_args = 1..)]
    pub env: Vec<String>,

    /// Systemd service names that receive the env file.
    #[arg(long = "service", num_args = 1..)]
    pub service: Vec<String>,

    /// File path exposed on the host.
    #[arg(long = "file", num_args = 1..)]
    pub file: Vec<String>,

    /// Passphrase length.
    #[arg(long, default_value_t = 32)]
    pub length: u32,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct NixosTextArgs {
    #[command(flatten)]
    pub target: NixosBaseArgs,

    /// Secret slug. Defaults from the first --env value.
    #[arg(long)]
    pub name: Option<String>,

    /// Environment variable names exposed to systemd services.
    #[arg(long = "env", num_args = 1..)]
    pub env: Vec<String>,

    /// Systemd service names that receive the env file.
    #[arg(long = "service", num_args = 1..)]
    pub service: Vec<String>,

    /// Read plaintext from this file. If omitted, plaintext is read from stdin.
    #[arg(long = "from-file")]
    pub from_file: Option<PathBuf>,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct NixosFileArgs {
    #[command(flatten)]
    pub target: NixosBaseArgs,

    /// Secret slug. Required unless --from-age can provide a filename stem.
    #[arg(long)]
    pub name: Option<String>,

    /// File path exposed on the host.
    #[arg(long = "file")]
    pub file: String,

    #[command(flatten)]
    pub source: FileSourceArgs,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct ForgejoSshArgs {
    /// Secret slug used for the agenix source path.
    #[arg(long)]
    pub name: String,

    /// Forgejo Actions secret or runner credential name.
    #[arg(long)]
    pub cred: String,

    /// Commented Nix variable name used for the generated public key.
    #[arg(long = "pubkey-var")]
    pub pubkey_var: Option<String>,

    /// Runner instance that should receive this key through runner credentials.
    #[arg(long = "instance", value_name = "INSTANCE")]
    pub instance: Vec<String>,

    /// Rotate the private key instead of preserving an existing one.
    #[arg(long, default_value_t = false)]
    pub rotate: bool,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct ForgejoGpgKeyPairArgs {
    /// Secret slug used for the agenix source path.
    #[arg(long)]
    pub name: String,

    /// Forgejo Actions secret name for the private key.
    #[arg(long)]
    pub cred: String,

    /// Module-secret directory under age/secrets/modules.
    #[arg(long = "module-dir", default_value = "repos/apt")]
    pub module_dir: String,

    /// User ID for newly generated OpenPGP keys.
    #[arg(long = "user-id")]
    pub user_id: Option<String>,

    /// Read an armored OpenPGP private key from this plaintext file.
    #[arg(long = "from-file", conflicts_with = "from_age")]
    pub from_file: Option<PathBuf>,

    /// Adopt an existing encrypted .age file containing an armored OpenPGP private key.
    #[arg(long = "from-age", conflicts_with = "from_file")]
    pub from_age: Option<PathBuf>,

    /// Rotate the private key instead of preserving an existing one.
    #[arg(long, default_value_t = false)]
    pub rotate: bool,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct ForgejoPasswordArgs {
    /// Secret slug used for the agenix source path.
    #[arg(long)]
    pub name: String,

    /// Runner credential name.
    #[arg(long)]
    pub cred: String,

    /// Runner instance that should receive this credential.
    #[arg(long = "instance", value_name = "INSTANCE", num_args = 1..)]
    pub instance: Vec<String>,

    /// Passphrase length.
    #[arg(long, default_value_t = 32)]
    pub length: u32,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct ForgejoTextArgs {
    /// Secret slug. Defaults from --cred.
    #[arg(long)]
    pub name: Option<String>,

    /// Runner credential name.
    #[arg(long)]
    pub cred: String,

    /// Runner instance that should receive this credential.
    #[arg(long = "instance", value_name = "INSTANCE", num_args = 1..)]
    pub instance: Vec<String>,

    /// Read plaintext from this file. If omitted, plaintext is read from stdin.
    #[arg(long = "from-file")]
    pub from_file: Option<PathBuf>,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true)]
pub struct ForgejoFileArgs {
    /// Secret slug. Defaults from --cred unless --from-age provides a filename stem.
    #[arg(long)]
    pub name: Option<String>,

    /// Runner credential name.
    #[arg(long)]
    pub cred: String,

    /// Runner instance that should receive this credential.
    #[arg(long = "instance", value_name = "INSTANCE", num_args = 1..)]
    pub instance: Vec<String>,

    #[command(flatten)]
    pub source: FileSourceArgs,

    #[command(flatten)]
    pub exec: ExecutionArgs,
}

impl HmCmd {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        match self {
            HmCmd::Ssh(args) => args.run(env),
            HmCmd::Password(args) => args.run(env),
            HmCmd::Text(args) => args.run(env),
            HmCmd::File(args) => args.run(env),
        }
    }
}

impl NixosCmd {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        match self {
            NixosCmd::Ssh(args) => args.run(env),
            NixosCmd::Password(args) => args.run(env),
            NixosCmd::Text(args) => args.run(env),
            NixosCmd::File(args) => args.run(env),
        }
    }
}

impl ForgejoCmd {
    pub fn run(self) -> Result<()> {
        match self {
            ForgejoCmd::Ssh(args) => args.run(),
            ForgejoCmd::GpgKeyPair(args) => args.run(),
            ForgejoCmd::Password(args) => args.run(),
            ForgejoCmd::Text(args) => args.run(),
            ForgejoCmd::File(args) => args.run(),
        }
    }
}

impl HmSshArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let plan = self.build_plan(env)?;
        run_plan(&common_generate_ssh(&self.algorithm, &self.exec)?, plan)
    }

    fn build_plan(&self, env: &dyn StoreEnv) -> Result<AddPlan> {
        validate_slug(&self.name)?;
        validate_ssh_algorithm(&self.algorithm)?;
        if self.target.shared {
            if self.file.is_some() {
                bail!("hm ssh --shared stores a source only and does not accept --file");
            }
            return Ok(AddPlan {
                slug: self.name.clone(),
                source: SourceKind::Generate(GeneratorSpec::SshKey {
                    algorithm: self.algorithm.clone(),
                }),
                targets: Vec::new(),
                source_only_paths: vec![shared_secret_path(&self.name)],
            });
        }
        let file = self
            .file
            .clone()
            .ok_or_else(|| anyhow!("hm ssh requires --file unless --shared is passed"))?;
        let user = resolve_home_user(&self.target.user, env)?;
        let target = home_target(&user, &self.name, Vec::new(), Some(file))?;
        Ok(AddPlan {
            slug: self.name.clone(),
            source: SourceKind::Generate(GeneratorSpec::SshKey {
                algorithm: self.algorithm.clone(),
            }),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl HmPasswordArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let plan = self.build_plan(env)?;
        run_plan(&common_generate_password(self.length, &self.exec)?, plan)
    }

    fn build_plan(&self, env: &dyn StoreEnv) -> Result<AddPlan> {
        validate_slug(&self.name)?;
        validate_passphrase_length(self.length)?;
        if self.target.shared {
            if !self.file.is_empty() {
                bail!(
                    "hm password --shared supports --env registration or source-only storage, not --file"
                );
            }
            let targets = if self.env.is_empty() {
                Vec::new()
            } else {
                vec![shared_home_target(&self.name, self.env.clone())?]
            };
            let source_only_paths = if targets.is_empty() {
                vec![shared_secret_path(&self.name)]
            } else {
                Vec::new()
            };
            return Ok(AddPlan {
                slug: self.name.clone(),
                source: SourceKind::Generate(GeneratorSpec::Passphrase {
                    length: self.length,
                }),
                targets,
                source_only_paths,
            });
        }
        validate_home_delivery(&self.env, &self.file)?;
        let user = resolve_home_user(&self.target.user, env)?;
        let target = home_target(
            &user,
            &self.name,
            self.env.clone(),
            self.file.first().cloned(),
        )?;
        Ok(AddPlan {
            slug: self.name.clone(),
            source: SourceKind::Generate(GeneratorSpec::Passphrase {
                length: self.length,
            }),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl HmTextArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let plan = self.build_plan(env)?;
        run_plan(
            &common_plaintext_with_editor(self.from_file.clone(), &self.exec),
            plan,
        )
    }

    fn build_plan(&self, env: &dyn StoreEnv) -> Result<AddPlan> {
        if self.env.is_empty() && !self.target.shared {
            bail!("hm text requires at least one --env target");
        }
        let slug = resolve_slug(self.name.as_ref(), &SourceKind::Plaintext, self.env.first())?;
        validate_slug(&slug)?;
        if self.target.shared {
            let targets = if self.env.is_empty() {
                Vec::new()
            } else {
                vec![shared_home_target(&slug, self.env.clone())?]
            };
            let source_only_paths = if targets.is_empty() {
                vec![shared_secret_path(&slug)]
            } else {
                Vec::new()
            };
            return Ok(AddPlan {
                slug,
                source: SourceKind::Plaintext,
                targets,
                source_only_paths,
            });
        }
        let user = resolve_home_user(&self.target.user, env)?;
        let target = home_target(&user, &slug, self.env.clone(), None)?;
        Ok(AddPlan {
            slug,
            source: SourceKind::Plaintext,
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl HmFileArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let source = file_source_kind(&self.source);
        let plan = self.build_plan(&source, env)?;
        run_plan(
            &common_source(
                source,
                self.source.from_file.clone(),
                self.source.force_existing,
                &self.exec,
            ),
            plan,
        )
    }

    fn build_plan(&self, source: &SourceKind, env: &dyn StoreEnv) -> Result<AddPlan> {
        let slug = resolve_slug(self.name.as_ref(), source, None)?;
        validate_slug(&slug)?;
        if self.target.shared {
            if self.file.is_some() {
                bail!("hm file --shared stores a source only and does not accept --file");
            }
            return Ok(AddPlan {
                slug: slug.clone(),
                source: source.clone(),
                targets: Vec::new(),
                source_only_paths: vec![shared_secret_path(&slug)],
            });
        }
        let file = self
            .file
            .clone()
            .ok_or_else(|| anyhow!("hm file requires --file unless --shared is passed"))?;
        let user = resolve_home_user(&self.target.user, env)?;
        let target = home_target(&user, &slug, Vec::new(), Some(file))?;
        Ok(AddPlan {
            slug,
            source: source.clone(),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl NixosSshArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let plan = self.build_plan(env)?;
        run_plan(&common_generate_ssh(&self.algorithm, &self.exec)?, plan)
    }

    fn build_plan(&self, env: &dyn StoreEnv) -> Result<AddPlan> {
        validate_slug(&self.name)?;
        validate_ssh_algorithm(&self.algorithm)?;
        let target = system_target(
            env,
            &self.target.host,
            &self.name,
            Vec::new(),
            Vec::new(),
            Some(self.file.clone()),
        )?;
        Ok(AddPlan {
            slug: self.name.clone(),
            source: SourceKind::Generate(GeneratorSpec::SshKey {
                algorithm: self.algorithm.clone(),
            }),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl NixosPasswordArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let plan = self.build_plan(env)?;
        run_plan(&common_generate_password(self.length, &self.exec)?, plan)
    }

    fn build_plan(&self, env: &dyn StoreEnv) -> Result<AddPlan> {
        validate_slug(&self.name)?;
        validate_passphrase_length(self.length)?;
        validate_system_delivery(&self.env, &self.service, &self.file)?;
        let target = system_target(
            env,
            &self.target.host,
            &self.name,
            self.env.clone(),
            self.service.clone(),
            self.file.first().cloned(),
        )?;
        Ok(AddPlan {
            slug: self.name.clone(),
            source: SourceKind::Generate(GeneratorSpec::Passphrase {
                length: self.length,
            }),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl NixosTextArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let plan = self.build_plan(env)?;
        run_plan(&common_plaintext(self.from_file.clone(), &self.exec), plan)
    }

    fn build_plan(&self, env: &dyn StoreEnv) -> Result<AddPlan> {
        if self.env.is_empty() {
            bail!("nixos text requires at least one --env target");
        }
        if self.service.is_empty() {
            bail!("nixos text --env requires at least one --service");
        }
        let slug = resolve_slug(self.name.as_ref(), &SourceKind::Plaintext, self.env.first())?;
        validate_slug(&slug)?;
        let target = system_target(
            env,
            &self.target.host,
            &slug,
            self.env.clone(),
            self.service.clone(),
            None,
        )?;
        Ok(AddPlan {
            slug,
            source: SourceKind::Plaintext,
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl NixosFileArgs {
    pub fn run(self, env: &dyn StoreEnv) -> Result<()> {
        let source = file_source_kind(&self.source);
        let plan = self.build_plan(&source, env)?;
        run_plan(
            &common_source(
                source,
                self.source.from_file.clone(),
                self.source.force_existing,
                &self.exec,
            ),
            plan,
        )
    }

    fn build_plan(&self, source: &SourceKind, env: &dyn StoreEnv) -> Result<AddPlan> {
        let slug = resolve_slug(self.name.as_ref(), source, None)?;
        validate_slug(&slug)?;
        let target = system_target(
            env,
            &self.target.host,
            &slug,
            Vec::new(),
            Vec::new(),
            Some(self.file.clone()),
        )?;
        Ok(AddPlan {
            slug,
            source: source.clone(),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl ForgejoSshArgs {
    pub fn run(self) -> Result<()> {
        let plan = self.build_plan()?;
        run_forgejo_ssh_key_plan(&plan, self.exec.no_stage, self.exec.no_rekey)
    }

    fn build_plan(&self) -> Result<ForgejoSshKeyPlan> {
        build_forgejo_ssh_plan(
            &self.name,
            &self.cred,
            self.pubkey_var.as_ref(),
            &self.instance,
            self.rotate,
        )
    }
}

impl ForgejoGpgKeyPairArgs {
    pub fn run(self) -> Result<()> {
        let plan = self.build_plan()?;
        run_forgejo_gpg_key_pair_plan(&plan, self.exec.no_stage, self.exec.no_rekey)
    }

    fn build_plan(&self) -> Result<ForgejoGpgKeyPairPlan> {
        build_forgejo_gpg_key_pair_plan(
            &self.name,
            &self.cred,
            &self.module_dir,
            self.user_id.as_deref(),
            self.from_file.clone(),
            self.from_age.clone(),
            self.rotate,
        )
    }
}

impl ForgejoPasswordArgs {
    pub fn run(self) -> Result<()> {
        let plan = self.build_plan()?;
        run_plan(&common_generate_password(self.length, &self.exec)?, plan)
    }

    fn build_plan(&self) -> Result<AddPlan> {
        validate_slug(&self.name)?;
        validate_passphrase_length(self.length)?;
        let target = forgejo_target(&self.name, &self.cred, &self.instance, false)?;
        Ok(AddPlan {
            slug: self.name.clone(),
            source: SourceKind::Generate(GeneratorSpec::Passphrase {
                length: self.length,
            }),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl ForgejoTextArgs {
    pub fn run(self) -> Result<()> {
        let plan = self.build_plan()?;
        run_plan(&common_plaintext(self.from_file.clone(), &self.exec), plan)
    }

    fn build_plan(&self) -> Result<AddPlan> {
        let slug = resolve_slug(self.name.as_ref(), &SourceKind::Plaintext, Some(&self.cred))?;
        validate_slug(&slug)?;
        let target = forgejo_target(&slug, &self.cred, &self.instance, false)?;
        Ok(AddPlan {
            slug,
            source: SourceKind::Plaintext,
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

impl ForgejoFileArgs {
    pub fn run(self) -> Result<()> {
        let source = file_source_kind(&self.source);
        let plan = self.build_plan(&source)?;
        run_plan(
            &common_source(
                source,
                self.source.from_file.clone(),
                self.source.force_existing,
                &self.exec,
            ),
            plan,
        )
    }

    fn build_plan(&self, source: &SourceKind) -> Result<AddPlan> {
        let slug = resolve_slug(self.name.as_ref(), source, Some(&self.cred))?;
        validate_slug(&slug)?;
        let target = forgejo_target(&slug, &self.cred, &self.instance, false)?;
        Ok(AddPlan {
            slug,
            source: source.clone(),
            targets: vec![target],
            source_only_paths: Vec::new(),
        })
    }
}

fn common_generate_ssh(algorithm: &str, exec: &ExecutionArgs) -> Result<CommonSourceArgs> {
    validate_ssh_algorithm(algorithm)?;
    Ok(CommonSourceArgs {
        no_rekey: exec.no_rekey,
        no_stage: exec.no_stage,
        ..CommonSourceArgs::default()
    })
}

fn common_generate_password(length: u32, exec: &ExecutionArgs) -> Result<CommonSourceArgs> {
    validate_passphrase_length(length)?;
    Ok(CommonSourceArgs {
        no_rekey: exec.no_rekey,
        no_stage: exec.no_stage,
        ..CommonSourceArgs::default()
    })
}

fn common_plaintext(from_file: Option<PathBuf>, exec: &ExecutionArgs) -> CommonSourceArgs {
    CommonSourceArgs {
        from_file,
        no_rekey: exec.no_rekey,
        no_stage: exec.no_stage,
        ..CommonSourceArgs::default()
    }
}

fn common_plaintext_with_editor(
    from_file: Option<PathBuf>,
    exec: &ExecutionArgs,
) -> CommonSourceArgs {
    CommonSourceArgs {
        from_file,
        editor_when_tty: true,
        no_rekey: exec.no_rekey,
        no_stage: exec.no_stage,
        ..CommonSourceArgs::default()
    }
}

fn common_source(
    source: SourceKind,
    from_file: Option<PathBuf>,
    force_existing: bool,
    exec: &ExecutionArgs,
) -> CommonSourceArgs {
    CommonSourceArgs {
        from_file: match source {
            SourceKind::Plaintext => from_file,
            SourceKind::FromAge(_) | SourceKind::Generate(_) => None,
        },
        editor_when_tty: false,
        force_existing,
        no_rekey: exec.no_rekey,
        no_stage: exec.no_stage,
    }
}

fn resolve_home_user(user: &Option<String>, env: &dyn StoreEnv) -> Result<String> {
    if let Some(user) = user {
        return Ok(user.clone());
    }
    env.resolve_home_user()
}

fn shared_secret_path(slug: &str) -> PathBuf {
    PathBuf::from(format!(
        "age/secrets/users/shared/{}.age",
        slug.replace('-', "_")
    ))
}

fn shared_home_target(slug: &str, env_vars: Vec<String>) -> Result<TargetSpec> {
    if env_vars.is_empty() {
        bail!("shared home env target requires at least one --env");
    }
    Ok(TargetSpec::SharedHome(SharedHomeTarget {
        slug: slug.to_string(),
        age_name: format!("shared-{slug}"),
        env_vars,
    }))
}

fn file_source_kind(source: &FileSourceArgs) -> SourceKind {
    match &source.from_age {
        Some(path) => SourceKind::FromAge(path.clone()),
        None => SourceKind::Plaintext,
    }
}

fn resolve_slug(
    name: Option<&String>,
    source: &SourceKind,
    target_default: Option<&String>,
) -> Result<String> {
    if let Some(name) = name {
        return Ok(name.clone());
    }
    if let SourceKind::FromAge(path) = source {
        return path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
            .ok_or_else(|| {
                anyhow!(
                    "--from-age: cannot extract filename stem from {}",
                    path.display()
                )
            });
    }
    if let Some(default) = target_default {
        return Ok(default_slug(default));
    }
    bail!("--name is required when no env var or forgejo credential can provide a default slug")
}

fn home_target(
    user: &str,
    slug: &str,
    env_vars: Vec<String>,
    file_path: Option<String>,
) -> Result<TargetSpec> {
    validate_ident(user, "user")?;
    Ok(TargetSpec::Home(HomeTarget {
        user: user.to_string(),
        slug: slug.to_string(),
        age_name: format!("{user}-{slug}"),
        env_vars,
        file_path,
    }))
}

fn system_target(
    env: &dyn StoreEnv,
    host: &str,
    slug: &str,
    env_vars: Vec<String>,
    services: Vec<String>,
    file_path: Option<String>,
) -> Result<TargetSpec> {
    env.validate_host(host)?;
    for service in &services {
        validate_unit_name(service)?;
    }
    Ok(TargetSpec::System(SystemTarget {
        host: host.to_string(),
        slug: slug.to_string(),
        age_name: format!("{host}-{slug}"),
        env_vars,
        services,
        file_path,
    }))
}

fn forgejo_target(
    slug: &str,
    cred: &str,
    instances: &[String],
    allow_source_only: bool,
) -> Result<TargetSpec> {
    validate_ident(cred, "cred")?;
    let instances = sorted_instances(instances, "instance")?;
    if instances.is_empty() && !allow_source_only {
        bail!("forgejo credential delivery requires at least one --instance");
    }
    let first_instance = instances
        .first()
        .cloned()
        .unwrap_or_else(|| "actions".to_string());
    Ok(TargetSpec::Forgejo(ForgejoTarget {
        slug: slug.to_string(),
        age_name: default_forgejo_age_name(&first_instance, slug),
        credential_name: Some(cred.to_string()),
        instances,
    }))
}

pub(crate) fn sorted_instances(instances: &[String], label: &str) -> Result<Vec<String>> {
    let mut sorted = BTreeSet::new();
    for instance in instances {
        validate_ident(instance, label)?;
        sorted.insert(instance.clone());
    }
    Ok(sorted.into_iter().collect())
}

fn validate_home_delivery(env: &[String], files: &[String]) -> Result<()> {
    if env.is_empty() && files.is_empty() {
        bail!("home secret requires at least one --env or --file target");
    }
    if files.len() > 1 {
        bail!("mkSecret supports one home file target per secret");
    }
    Ok(())
}

fn validate_system_delivery(env: &[String], services: &[String], files: &[String]) -> Result<()> {
    if env.is_empty() && files.is_empty() {
        bail!("nixos secret requires at least one --env or --file target");
    }
    if !env.is_empty() && services.is_empty() {
        bail!("nixos --env requires at least one --service");
    }
    if files.len() > 1 {
        bail!("mkSecret supports one system file target per secret");
    }
    for service in services {
        validate_unit_name(service)?;
    }
    Ok(())
}

fn validate_ssh_algorithm(algorithm: &str) -> Result<()> {
    if !matches!(algorithm, "ed25519" | "rsa") {
        bail!("--algorithm must be ed25519 or rsa");
    }
    Ok(())
}

fn validate_passphrase_length(length: u32) -> Result<()> {
    if !matches!(length, 32 | 48 | 64) {
        bail!("--length must be 32, 48, or 64");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::TestEnv;
    use crate::render::{Stack, default_forgejo_ssh_key_age_name};

    fn hm_base() -> HmBaseArgs {
        HmBaseArgs {
            user: Some("can".to_string()),
            shared: false,
        }
    }

    fn hm_shared_base() -> HmBaseArgs {
        HmBaseArgs {
            user: None,
            shared: true,
        }
    }

    fn nixos_base() -> NixosBaseArgs {
        NixosBaseArgs {
            host: "thething".to_string(),
        }
    }

    fn file_source_from_stdin() -> FileSourceArgs {
        FileSourceArgs {
            from_file: None,
            from_age: None,
            force_existing: false,
        }
    }

    fn file_source_from_age(path: &str) -> FileSourceArgs {
        FileSourceArgs {
            from_file: None,
            from_age: Some(PathBuf::from(path)),
            force_existing: false,
        }
    }

    #[test]
    fn home_ssh_plan_generates_file_delivered_key() {
        let args = HmSshArgs {
            target: hm_base(),
            name: "deploy-key".to_string(),
            file: Some("~/.ssh/deploy-key".to_string()),
            algorithm: "ed25519".to_string(),
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan(&TestEnv).unwrap();
        assert_eq!(plan.slug, "deploy-key");
        assert_eq!(
            plan.source,
            SourceKind::Generate(GeneratorSpec::SshKey {
                algorithm: "ed25519".to_string()
            })
        );
        assert_eq!(
            plan.targets,
            vec![TargetSpec::Home(HomeTarget {
                user: "can".to_string(),
                slug: "deploy-key".to_string(),
                age_name: "can-deploy-key".to_string(),
                env_vars: Vec::new(),
                file_path: Some("~/.ssh/deploy-key".to_string()),
            })]
        );
    }

    #[test]
    fn home_password_plan_supports_env_delivery() {
        let args = HmPasswordArgs {
            target: hm_base(),
            name: "app-token".to_string(),
            env: vec!["APP_TOKEN".to_string()],
            file: Vec::new(),
            length: 48,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan(&TestEnv).unwrap();
        assert_eq!(
            plan.source,
            SourceKind::Generate(GeneratorSpec::Passphrase { length: 48 })
        );
        assert_eq!(
            plan.targets,
            vec![TargetSpec::Home(HomeTarget {
                user: "can".to_string(),
                slug: "app-token".to_string(),
                age_name: "can-app-token".to_string(),
                env_vars: vec!["APP_TOKEN".to_string()],
                file_path: None,
            })]
        );
    }

    #[test]
    fn home_text_plan_derives_slug_and_age_name_from_env() {
        let args = HmTextArgs {
            target: hm_base(),
            name: None,
            env: vec!["KAGGLE_API_TOKEN".to_string()],
            from_file: Some(PathBuf::from("./token")),
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan(&TestEnv).unwrap();
        assert_eq!(plan.slug, "kaggle");
        assert_eq!(
            plan.targets,
            vec![TargetSpec::Home(HomeTarget {
                user: "can".to_string(),
                slug: "kaggle".to_string(),
                age_name: "can-kaggle".to_string(),
                env_vars: vec!["KAGGLE_API_TOKEN".to_string()],
                file_path: None,
            })]
        );
    }

    #[test]
    fn home_text_plan_defaults_user_from_env_hook() {
        let args = HmTextArgs {
            target: HmBaseArgs {
                user: None,
                shared: false,
            },
            name: None,
            env: vec!["KAGGLE_API_TOKEN".to_string()],
            from_file: None,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan(&TestEnv).unwrap();
        assert_eq!(
            plan.targets,
            vec![TargetSpec::Home(HomeTarget {
                user: "can".to_string(),
                slug: "kaggle".to_string(),
                age_name: "can-kaggle".to_string(),
                env_vars: vec!["KAGGLE_API_TOKEN".to_string()],
                file_path: None,
            })]
        );
    }

    #[test]
    fn home_file_plan_adopts_age_file_and_derives_slug() {
        let source = file_source_from_age("./kubeconfig.age");
        let args = HmFileArgs {
            target: hm_base(),
            name: None,
            file: Some("~/.kube/config".to_string()),
            source,
            exec: ExecutionArgs::default(),
        };
        let source = file_source_kind(&args.source);
        let plan = args.build_plan(&source, &TestEnv).unwrap();
        assert_eq!(plan.slug, "kubeconfig");
        assert_eq!(
            plan.source,
            SourceKind::FromAge(PathBuf::from("./kubeconfig.age"))
        );
        assert_eq!(
            plan.targets,
            vec![TargetSpec::Home(HomeTarget {
                user: "can".to_string(),
                slug: "kubeconfig".to_string(),
                age_name: "can-kubeconfig".to_string(),
                env_vars: Vec::new(),
                file_path: Some("~/.kube/config".to_string()),
            })]
        );
    }

    #[test]
    fn shared_home_text_env_plan_registers_shared_module() {
        let args = HmTextArgs {
            target: hm_shared_base(),
            name: None,
            env: vec!["DEEPSEEK_API_KEY".to_string()],
            from_file: None,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan(&TestEnv).unwrap();
        assert_eq!(plan.slug, "deepseek");
        assert!(plan.source_only_paths.is_empty());
        assert_eq!(
            plan.targets,
            vec![TargetSpec::SharedHome(SharedHomeTarget {
                slug: "deepseek".to_string(),
                age_name: "shared-deepseek".to_string(),
                env_vars: vec!["DEEPSEEK_API_KEY".to_string()],
            })]
        );
    }

    #[test]
    fn shared_home_text_source_only_plan_has_no_targets() {
        let args = HmTextArgs {
            target: hm_shared_base(),
            name: Some("deepseek".to_string()),
            env: Vec::new(),
            from_file: None,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan(&TestEnv).unwrap();
        assert!(plan.targets.is_empty());
        assert_eq!(
            plan.source_only_paths,
            vec![PathBuf::from("age/secrets/users/shared/deepseek.age")]
        );
    }

    #[test]
    fn shared_home_password_supports_env_and_source_only() {
        let env_args = HmPasswordArgs {
            target: hm_shared_base(),
            name: "app-token".to_string(),
            env: vec!["APP_TOKEN".to_string()],
            file: Vec::new(),
            length: 32,
            exec: ExecutionArgs::default(),
        };
        let env_plan = env_args.build_plan(&TestEnv).unwrap();
        assert_eq!(
            env_plan.targets,
            vec![TargetSpec::SharedHome(SharedHomeTarget {
                slug: "app-token".to_string(),
                age_name: "shared-app-token".to_string(),
                env_vars: vec!["APP_TOKEN".to_string()],
            })]
        );

        let source_only_args = HmPasswordArgs {
            target: hm_shared_base(),
            name: "app-token".to_string(),
            env: Vec::new(),
            file: Vec::new(),
            length: 32,
            exec: ExecutionArgs::default(),
        };
        let source_only_plan = source_only_args.build_plan(&TestEnv).unwrap();
        assert!(source_only_plan.targets.is_empty());
        assert_eq!(
            source_only_plan.source_only_paths,
            vec![PathBuf::from("age/secrets/users/shared/app_token.age")]
        );
    }

    #[test]
    fn shared_home_ssh_and_file_are_source_only() {
        let ssh = HmSshArgs {
            target: hm_shared_base(),
            name: "deploy-key".to_string(),
            file: None,
            algorithm: "ed25519".to_string(),
            exec: ExecutionArgs::default(),
        };
        let ssh_plan = ssh.build_plan(&TestEnv).unwrap();
        assert!(ssh_plan.targets.is_empty());
        assert_eq!(
            ssh_plan.source_only_paths,
            vec![PathBuf::from("age/secrets/users/shared/deploy_key.age")]
        );

        let file = HmFileArgs {
            target: hm_shared_base(),
            name: Some("payload".to_string()),
            file: None,
            source: file_source_from_stdin(),
            exec: ExecutionArgs::default(),
        };
        let source = file_source_kind(&file.source);
        let file_plan = file.build_plan(&source, &TestEnv).unwrap();
        assert!(file_plan.targets.is_empty());
        assert_eq!(
            file_plan.source_only_paths,
            vec![PathBuf::from("age/secrets/users/shared/payload.age")]
        );
    }

    #[test]
    fn nixos_secret_type_plans_cover_ssh_password_text_and_file() {
        let ssh = NixosSshArgs {
            target: nixos_base(),
            name: "service-key".to_string(),
            file: "/run/secrets/service-key".to_string(),
            algorithm: "ed25519".to_string(),
            exec: ExecutionArgs::default(),
        };
        assert_eq!(
            ssh.build_plan(&TestEnv).unwrap().source,
            SourceKind::Generate(GeneratorSpec::SshKey {
                algorithm: "ed25519".to_string()
            })
        );

        let password = NixosPasswordArgs {
            target: nixos_base(),
            name: "vikunja-mailer".to_string(),
            env: vec!["VIKUNJA_MAILER_PASSWORD".to_string()],
            service: vec!["vikunja".to_string()],
            file: Vec::new(),
            length: 32,
            exec: ExecutionArgs::default(),
        };
        let password_plan = password.build_plan(&TestEnv).unwrap();
        assert_eq!(
            password_plan.targets,
            vec![TargetSpec::System(SystemTarget {
                host: "thething".to_string(),
                slug: "vikunja-mailer".to_string(),
                age_name: "thething-vikunja-mailer".to_string(),
                env_vars: vec!["VIKUNJA_MAILER_PASSWORD".to_string()],
                services: vec!["vikunja".to_string()],
                file_path: None,
            })]
        );

        let text = NixosTextArgs {
            target: nixos_base(),
            name: None,
            env: vec!["API_TOKEN".to_string()],
            service: vec!["demo".to_string()],
            from_file: None,
            exec: ExecutionArgs::default(),
        };
        assert_eq!(text.build_plan(&TestEnv).unwrap().slug, "api");

        let file = NixosFileArgs {
            target: nixos_base(),
            name: Some("service-key".to_string()),
            file: "/run/secrets/service-key".to_string(),
            source: file_source_from_stdin(),
            exec: ExecutionArgs::default(),
        };
        assert_eq!(
            file.build_plan(&SourceKind::Plaintext, &TestEnv)
                .unwrap()
                .source,
            SourceKind::Plaintext
        );
    }

    #[test]
    fn forgejo_secret_type_plans_cover_ssh_password_text_and_file() {
        let ssh = ForgejoSshArgs {
            name: "aur-ssh-key".to_string(),
            cred: "AUR_SSH_KEY".to_string(),
            pubkey_var: None,
            instance: Vec::new(),
            rotate: false,
            exec: ExecutionArgs::default(),
        };
        let ssh_plan = ssh.build_plan().unwrap();
        assert_eq!(ssh_plan.slug, "aur-ssh-key");
        assert_eq!(ssh_plan.credential_name, "AUR_SSH_KEY");
        assert_eq!(ssh_plan.pubkey_var, "aurSshPublicKey");
        assert_eq!(
            ssh_plan.target,
            TargetSpec::Forgejo(ForgejoTarget {
                slug: "aur-ssh-key".to_string(),
                age_name: "forgejoActionsAurSshKey".to_string(),
                credential_name: None,
                instances: Vec::new(),
            })
        );

        let password = ForgejoPasswordArgs {
            name: "copr-token".to_string(),
            cred: "copr-token".to_string(),
            instance: vec!["codeberg".to_string()],
            length: 64,
            exec: ExecutionArgs::default(),
        };
        assert_eq!(
            password.build_plan().unwrap().source,
            SourceKind::Generate(GeneratorSpec::Passphrase { length: 64 })
        );

        let text = ForgejoTextArgs {
            name: None,
            cred: "COPR_TOKEN".to_string(),
            instance: vec!["codeberg".to_string()],
            from_file: None,
            exec: ExecutionArgs::default(),
        };
        assert_eq!(text.build_plan().unwrap().slug, "copr");

        let file = ForgejoFileArgs {
            name: Some("copr-token".to_string()),
            cred: "COPR_TOKEN".to_string(),
            instance: vec!["codeberg".to_string()],
            source: file_source_from_stdin(),
            exec: ExecutionArgs::default(),
        };
        assert_eq!(
            file.build_plan(&SourceKind::Plaintext).unwrap().source,
            SourceKind::Plaintext
        );
    }

    #[test]
    fn forgejo_gpg_key_pair_defaults_to_repos_apt_source_only_path() {
        let args = ForgejoGpgKeyPairArgs {
            name: "modde-apt-repo-gpg-key".to_string(),
            cred: "modde_apt_repo_gpg_key".to_string(),
            module_dir: "repos/apt".to_string(),
            user_id: None,
            from_file: None,
            from_age: Some(PathBuf::from(
                "age/secrets/modules/repos/apt/modde-apt-repo-gpg-key.age",
            )),
            rotate: false,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan().unwrap();
        assert_eq!(
            plan.secret_path,
            PathBuf::from("age/secrets/modules/repos/apt/modde-apt-repo-gpg-key.age")
        );
        assert_eq!(plan.credential_name, "modde_apt_repo_gpg_key");
    }

    #[test]
    fn forgejo_gpg_key_pair_rejects_public_metadata_slugs() {
        let args = ForgejoGpgKeyPairArgs {
            name: "modde-apt-repo-gpg-key-id".to_string(),
            cred: "modde_apt_repo_gpg_key_id".to_string(),
            module_dir: "repos/apt".to_string(),
            user_id: None,
            from_file: None,
            from_age: None,
            rotate: false,
            exec: ExecutionArgs::default(),
        };
        let err = args.build_plan().unwrap_err();
        assert!(err.to_string().contains("public GPG metadata"));
    }

    #[test]
    fn forgejo_ssh_injected_instances_are_sorted_and_deduped() {
        let args = ForgejoSshArgs {
            name: "aur-ssh-key".to_string(),
            cred: "AUR_SSH_KEY".to_string(),
            pubkey_var: Some("aurSshPublicKey".to_string()),
            instance: vec![
                "nixTrusted".to_string(),
                "codeberg".to_string(),
                "nixTrusted".to_string(),
            ],
            rotate: false,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan().unwrap();
        assert_eq!(
            plan.target,
            TargetSpec::Forgejo(ForgejoTarget {
                slug: "aur-ssh-key".to_string(),
                age_name: "forgejoActionsAurSshKey".to_string(),
                credential_name: Some("AUR_SSH_KEY".to_string()),
                instances: vec!["codeberg".to_string(), "nixTrusted".to_string()],
            })
        );
    }

    #[test]
    fn forgejo_password_instances_are_sorted_and_deduped() {
        let args = ForgejoPasswordArgs {
            name: "copr-token".to_string(),
            cred: "copr-token".to_string(),
            instance: vec![
                "nixTrusted".to_string(),
                "codeberg".to_string(),
                "nixTrusted".to_string(),
            ],
            length: 32,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan().unwrap();
        assert_eq!(
            plan.targets,
            vec![TargetSpec::Forgejo(ForgejoTarget {
                slug: "copr-token".to_string(),
                age_name: "forgejoRunnerCodebergCoprToken".to_string(),
                credential_name: Some("copr-token".to_string()),
                instances: vec!["codeberg".to_string(), "nixTrusted".to_string()],
            })]
        );
    }

    #[test]
    fn forgejo_ssh_rotate_is_explicit() {
        let args = ForgejoSshArgs {
            name: "aur-ssh-key".to_string(),
            cred: "AUR_SSH_KEY".to_string(),
            pubkey_var: None,
            instance: Vec::new(),
            rotate: true,
            exec: ExecutionArgs::default(),
        };
        let plan = args.build_plan().unwrap();
        assert!(plan.rotate);
    }

    #[test]
    fn nixos_env_delivery_requires_service() {
        let args = NixosPasswordArgs {
            target: nixos_base(),
            name: "mailer".to_string(),
            env: vec!["MAILER_PASSWORD".to_string()],
            service: Vec::new(),
            file: Vec::new(),
            length: 32,
            exec: ExecutionArgs::default(),
        };
        let err = args.build_plan(&TestEnv).unwrap_err();
        assert!(err.to_string().contains("requires at least one --service"));
    }

    #[test]
    fn shared_file_targets_are_rejected() {
        let ssh = HmSshArgs {
            target: hm_shared_base(),
            name: "deploy-key".to_string(),
            file: Some("~/.ssh/deploy-key".to_string()),
            algorithm: "ed25519".to_string(),
            exec: ExecutionArgs::default(),
        };
        assert!(
            ssh.build_plan(&TestEnv)
                .unwrap_err()
                .to_string()
                .contains("does not accept --file")
        );

        let file = HmFileArgs {
            target: hm_shared_base(),
            name: Some("payload".to_string()),
            file: Some("~/.config/payload".to_string()),
            source: file_source_from_stdin(),
            exec: ExecutionArgs::default(),
        };
        let source = file_source_kind(&file.source);
        assert!(
            file.build_plan(&source, &TestEnv)
                .unwrap_err()
                .to_string()
                .contains("does not accept --file")
        );
    }

    #[test]
    fn non_shared_ssh_and_file_require_file_target() {
        let ssh = HmSshArgs {
            target: hm_base(),
            name: "deploy-key".to_string(),
            file: None,
            algorithm: "ed25519".to_string(),
            exec: ExecutionArgs::default(),
        };
        assert!(
            ssh.build_plan(&TestEnv)
                .unwrap_err()
                .to_string()
                .contains("requires --file")
        );

        let file = HmFileArgs {
            target: hm_base(),
            name: Some("payload".to_string()),
            file: None,
            source: file_source_from_stdin(),
            exec: ExecutionArgs::default(),
        };
        let source = file_source_kind(&file.source);
        assert!(
            file.build_plan(&source, &TestEnv)
                .unwrap_err()
                .to_string()
                .contains("requires --file")
        );
    }

    #[test]
    fn forgejo_ssh_default_age_name_formula_holds() {
        assert_eq!(
            default_forgejo_ssh_key_age_name("aur-ssh-key"),
            "forgejoActionsAurSshKey"
        );
    }

    #[test]
    fn stack_mapping_is_stable() {
        assert_eq!(
            TargetSpec::SharedHome(SharedHomeTarget {
                slug: "x".into(),
                age_name: "shared-x".into(),
                env_vars: vec!["X".into()],
            })
            .stack(),
            Stack::Home
        );
    }
}
