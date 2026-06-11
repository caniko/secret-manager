use std::path::PathBuf;

/// Nix binding the generated modules call `mkSecret` through. This is the
/// data repo's convention (the store passes its bound secret lib under this
/// argument name to imported modules); kept as the historical default so
/// generated modules are byte-identical to the pre-extraction engine.
pub const LIB_BINDING: &str = "canixLib";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stack {
    Home,
    System,
    Forgejo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceExpr {
    User { user: String, slug: String },
    Host { host: String, slug: String },
    Module { subpath: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratorSpec {
    Passphrase { length: u32 },
    SshKey { algorithm: String },
    GpgKeyPair { user_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedModule {
    pub path: PathBuf,
    pub body: String,
    pub default_nix: PathBuf,
    pub secret_path: PathBuf,
    pub stack: Stack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTarget {
    pub user: String,
    pub slug: String,
    pub age_name: String,
    pub env_vars: Vec<String>,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedHomeTarget {
    pub slug: String,
    pub age_name: String,
    pub env_vars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemTarget {
    pub host: String,
    pub slug: String,
    pub age_name: String,
    pub env_vars: Vec<String>,
    pub services: Vec<String>,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgejoTarget {
    pub slug: String,
    pub age_name: String,
    pub credential_name: Option<String>,
    pub instances: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSpec {
    Home(HomeTarget),
    SharedHome(SharedHomeTarget),
    System(SystemTarget),
    Forgejo(ForgejoTarget),
}

impl TargetSpec {
    pub fn source_expr(&self) -> SourceExpr {
        match self {
            TargetSpec::Home(t) => SourceExpr::User {
                user: t.user.clone(),
                slug: t.slug.clone(),
            },
            TargetSpec::SharedHome(t) => SourceExpr::User {
                user: "shared".to_string(),
                slug: t.slug.clone(),
            },
            TargetSpec::System(t) => SourceExpr::Host {
                host: t.host.clone(),
                slug: t.slug.clone(),
            },
            TargetSpec::Forgejo(t) => SourceExpr::Module {
                subpath: format!("foregejo-runner/{}", t.slug),
            },
        }
    }

    pub fn secret_path(&self) -> PathBuf {
        match self {
            TargetSpec::Home(t) => {
                PathBuf::from(format!("age/secrets/users/{}/{}.age", t.user, t.slug))
            }
            TargetSpec::SharedHome(t) => {
                PathBuf::from(format!("age/secrets/users/shared/{}.age", t.slug))
            }
            TargetSpec::System(t) => {
                PathBuf::from(format!("age/secrets/hosts/{}/{}.age", t.host, t.slug))
            }
            TargetSpec::Forgejo(t) => PathBuf::from(format!(
                "age/secrets/modules/foregejo-runner/{}.age",
                t.slug
            )),
        }
    }

    pub fn module_path(&self) -> PathBuf {
        match self {
            TargetSpec::Home(t) => {
                PathBuf::from(format!("home/user/{}/repositories/{}.nix", t.user, t.slug))
            }
            TargetSpec::SharedHome(t) => PathBuf::from(format!("home/user/shared/{}.nix", t.slug)),
            TargetSpec::System(t) => {
                PathBuf::from(format!("root/hosts/{}/server/{}.nix", t.host, t.slug))
            }
            TargetSpec::Forgejo(t) => PathBuf::from(format!(
                "root/modules/server/forgejo-runner-secrets/{}.nix",
                t.slug
            )),
        }
    }

    pub fn default_nix(&self) -> PathBuf {
        match self {
            TargetSpec::Home(t) => {
                PathBuf::from(format!("home/user/{}/repositories/default.nix", t.user))
            }
            TargetSpec::SharedHome(_) => PathBuf::from("home/user/shared/default.nix"),
            TargetSpec::System(t) => {
                PathBuf::from(format!("root/hosts/{}/server/default.nix", t.host))
            }
            TargetSpec::Forgejo(_) => {
                PathBuf::from("root/modules/server/forgejo-runner-secrets/default.nix")
            }
        }
    }

    pub fn stack(&self) -> Stack {
        match self {
            TargetSpec::Home(_) => Stack::Home,
            TargetSpec::SharedHome(_) => Stack::Home,
            TargetSpec::System(_) => Stack::System,
            TargetSpec::Forgejo(_) => Stack::Forgejo,
        }
    }
}

pub fn render_modules(
    targets: &[TargetSpec],
    generator: Option<&GeneratorSpec>,
) -> Vec<RenderedModule> {
    targets
        .iter()
        .map(|target| RenderedModule {
            path: target.module_path(),
            body: render_body(target, generator),
            default_nix: target.default_nix(),
            secret_path: target.secret_path(),
            stack: target.stack(),
        })
        .collect()
}

pub fn render_body(target: &TargetSpec, generator: Option<&GeneratorSpec>) -> String {
    let age_name = match target {
        TargetSpec::Home(t) => &t.age_name,
        TargetSpec::SharedHome(t) => &t.age_name,
        TargetSpec::System(t) => &t.age_name,
        TargetSpec::Forgejo(t) => &t.age_name,
    };
    let stack = match target {
        TargetSpec::Home(_) => "home",
        TargetSpec::SharedHome(_) => "home",
        TargetSpec::System(_) => "system",
        TargetSpec::Forgejo(_) => "forgejo",
    };

    let source = render_source(&target.source_expr());
    let generator_lines = render_generator(generator);
    let targets = render_targets(target);

    format!(
        "{{\n  {lib},\n  secrets,\n  ...\n}}: {{\n  imports = [\n    ({lib}.mkSecret {{\n      name = \"{}\";\n      stack = \"{}\";\n      source = {};\n{}{}    }})\n  ];\n}}\n",
        nix_string(age_name),
        stack,
        source,
        generator_lines,
        targets,
        lib = LIB_BINDING,
    )
}

fn render_generator(generator: Option<&GeneratorSpec>) -> String {
    match generator {
        None => String::new(),
        Some(GeneratorSpec::Passphrase { length }) => {
            format!("      generator = \"passphrase\";\n      length = {length};\n")
        }
        Some(GeneratorSpec::SshKey { algorithm }) => {
            format!(
                "      generator = \"ssh-key\";\n      algorithm = \"{}\";\n",
                nix_string(algorithm)
            )
        }
        Some(GeneratorSpec::GpgKeyPair { user_id }) => {
            format!(
                "      generator = \"gpg-key-pair\";\n      userId = \"{}\";\n",
                nix_string(user_id)
            )
        }
    }
}

fn render_source(source: &SourceExpr) -> String {
    match source {
        SourceExpr::User { user, slug } => {
            format!(
                "secrets.user \"{}\" \"{}\"",
                nix_string(user),
                nix_string(slug)
            )
        }
        SourceExpr::Host { host, slug } => {
            format!(
                "secrets.host \"{}\" \"{}\"",
                nix_string(host),
                nix_string(slug)
            )
        }
        SourceExpr::Module { subpath } => format!("secrets.module \"{}\"", nix_string(subpath)),
    }
}

fn render_targets(target: &TargetSpec) -> String {
    match target {
        TargetSpec::Home(t) => {
            let mut out = String::new();
            if !t.env_vars.is_empty() {
                out.push_str(&format!(
                    "      targets.home.env = [{}];\n",
                    render_string_list(&t.env_vars)
                ));
            }
            if let Some(path) = &t.file_path {
                out.push_str(&format!(
                    "      targets.home.file = {{\n        path = \"{}\";\n      }};\n",
                    nix_string(path)
                ));
            }
            out
        }
        TargetSpec::SharedHome(t) => {
            if t.env_vars.is_empty() {
                String::new()
            } else {
                format!(
                    "      targets.home.env = [{}];\n",
                    render_string_list(&t.env_vars)
                )
            }
        }
        TargetSpec::System(t) => {
            let mut out = String::new();
            if !t.env_vars.is_empty() {
                out.push_str(&format!(
                    "      targets.system.env = {{\n        vars = [{}];\n        services = [{}];\n      }};\n",
                    render_string_list(&t.env_vars),
                    render_string_list(&t.services)
                ));
            }
            if let Some(path) = &t.file_path {
                out.push_str(&format!(
                    "      targets.system.file = {{\n        path = \"{}\";\n      }};\n",
                    nix_string(path)
                ));
            }
            out
        }
        TargetSpec::Forgejo(t) => match &t.credential_name {
            Some(name) if !t.instances.is_empty() => format!(
                "      targets.forgejo.credential = {{\n        name = \"{}\";\n        instances = [{}];\n      }};\n",
                nix_string(name),
                render_string_list(&t.instances)
            ),
            _ => String::new(),
        },
    }
}

fn render_string_list(values: &[String]) -> String {
    values
        .iter()
        .map(|v| format!("\"{}\"", nix_string(v)))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn nix_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace("${", "\\${")
}

pub fn default_forgejo_age_name(instance: &str, slug: &str) -> String {
    format!("forgejoRunner{}{}", camel(instance), camel(slug))
        .replace(|c: char| !c.is_ascii_alphanumeric(), "")
}

pub fn default_forgejo_ssh_key_age_name(slug: &str) -> String {
    format!("forgejoActions{}", camel(slug)).replace(|c: char| !c.is_ascii_alphanumeric(), "")
}

/// kebab/snake -> CamelCase. Treats `-` and `_` as boundaries; an already-cased
/// segment keeps its internal casing (`nixTrusted` -> `NixTrusted`).
pub fn camel(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut next_upper = true;
    for c in s.chars() {
        if c == '-' || c == '_' {
            next_upper = true;
            continue;
        }
        if next_upper {
            out.extend(c.to_uppercase());
            next_upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_name_matches_formula() {
        assert_eq!(
            default_forgejo_age_name("codeberg", "copr-token"),
            "forgejoRunnerCodebergCoprToken"
        );
        assert_eq!(
            default_forgejo_age_name("nixTrusted", "github-token"),
            "forgejoRunnerNixTrustedGithubToken"
        );
    }

    #[test]
    fn camel_preserves_internal_casing() {
        assert_eq!(camel("nixTrusted"), "NixTrusted");
        assert_eq!(camel("copr-token"), "CoprToken");
        assert_eq!(camel("atlas"), "Atlas");
        assert_eq!(camel("a_b_c"), "ABC");
    }

    #[test]
    fn render_home_mksecret_shape() {
        let got = render_body(
            &TargetSpec::Home(HomeTarget {
                user: "can".to_string(),
                slug: "kaggle-api-token".to_string(),
                age_name: "can-kaggle-api-token".to_string(),
                env_vars: vec!["KAGGLE_API_TOKEN".to_string()],
                file_path: None,
            }),
            None,
        );
        assert!(got.contains("name = \"can-kaggle-api-token\";"));
        assert!(got.contains("stack = \"home\";"));
        assert!(got.contains("source = secrets.user \"can\" \"kaggle-api-token\";"));
        assert!(got.contains("targets.home.env = [\"KAGGLE_API_TOKEN\"];"));
        assert!(got.contains("canixLib.mkSecret"));
    }

    #[test]
    fn render_shared_home_mksecret_shape() {
        let got = render_body(
            &TargetSpec::SharedHome(SharedHomeTarget {
                slug: "deepseek".to_string(),
                age_name: "shared-deepseek".to_string(),
                env_vars: vec!["DEEPSEEK_API_KEY".to_string()],
            }),
            None,
        );
        assert!(got.contains("name = \"shared-deepseek\";"));
        assert!(got.contains("stack = \"home\";"));
        assert!(got.contains("source = secrets.user \"shared\" \"deepseek\";"));
        assert!(got.contains("targets.home.env = [\"DEEPSEEK_API_KEY\"];"));
    }

    #[test]
    fn render_system_mksecret_shape() {
        let got = render_body(
            &TargetSpec::System(SystemTarget {
                host: "thething".to_string(),
                slug: "vikunja-mailer".to_string(),
                age_name: "thething-vikunja-mailer".to_string(),
                env_vars: vec!["VIKUNJA_MAILER_PASSWORD".to_string()],
                services: vec!["vikunja".to_string()],
                file_path: Some("/run/secrets/vikunja-mailer".to_string()),
            }),
            Some(&GeneratorSpec::Passphrase { length: 48 }),
        );
        assert!(got.contains("name = \"thething-vikunja-mailer\";"));
        assert!(got.contains("stack = \"system\";"));
        assert!(got.contains("source = secrets.host \"thething\" \"vikunja-mailer\";"));
        assert!(got.contains("generator = \"passphrase\";"));
        assert!(got.contains("length = 48;"));
        assert!(got.contains("vars = [\"VIKUNJA_MAILER_PASSWORD\"];"));
        assert!(got.contains("services = [\"vikunja\"];"));
        assert!(got.contains("path = \"/run/secrets/vikunja-mailer\";"));
    }

    #[test]
    fn render_forgejo_mksecret_shape() {
        let got = render_body(
            &TargetSpec::Forgejo(ForgejoTarget {
                slug: "copr-token".to_string(),
                age_name: "forgejoRunnerCodebergCoprToken".to_string(),
                credential_name: Some("copr-token".to_string()),
                instances: vec!["codeberg".to_string()],
            }),
            None,
        );
        assert!(got.contains("name = \"forgejoRunnerCodebergCoprToken\";"));
        assert!(got.contains("stack = \"forgejo\";"));
        assert!(got.contains("source = secrets.module \"foregejo-runner/copr-token\";"));
        assert!(got.contains("name = \"copr-token\";"));
        assert!(got.contains("instances = [\"codeberg\"];"));
    }

    #[test]
    fn render_forgejo_source_only_ssh_key_shape() {
        let got = render_body(
            &TargetSpec::Forgejo(ForgejoTarget {
                slug: "aur-ssh-key".to_string(),
                age_name: default_forgejo_ssh_key_age_name("aur-ssh-key"),
                credential_name: None,
                instances: Vec::new(),
            }),
            Some(&GeneratorSpec::SshKey {
                algorithm: "ed25519".to_string(),
            }),
        );
        assert!(got.contains("name = \"forgejoActionsAurSshKey\";"));
        assert!(got.contains("stack = \"forgejo\";"));
        assert!(got.contains("source = secrets.module \"foregejo-runner/aur-ssh-key\";"));
        assert!(got.contains("generator = \"ssh-key\";"));
        assert!(got.contains("algorithm = \"ed25519\";"));
        assert!(!got.contains("targets.forgejo.credential"));
    }

    #[test]
    fn render_forgejo_runner_injected_ssh_key_shape() {
        let got = render_body(
            &TargetSpec::Forgejo(ForgejoTarget {
                slug: "aur-ssh-key".to_string(),
                age_name: default_forgejo_ssh_key_age_name("aur-ssh-key"),
                credential_name: Some("AUR_SSH_KEY".to_string()),
                instances: vec!["codeberg".to_string(), "nixTrusted".to_string()],
            }),
            Some(&GeneratorSpec::SshKey {
                algorithm: "ed25519".to_string(),
            }),
        );
        assert!(got.contains("name = \"forgejoActionsAurSshKey\";"));
        assert!(got.contains("targets.forgejo.credential = {"));
        assert!(got.contains("name = \"AUR_SSH_KEY\";"));
        assert!(got.contains("instances = [\"codeberg\" \"nixTrusted\"];"));
    }

    #[test]
    fn target_paths_match_legacy_formulas() {
        let home = TargetSpec::Home(HomeTarget {
            user: "can".to_string(),
            slug: "kaggle-api-token".to_string(),
            age_name: "can-kaggle-api-token".to_string(),
            env_vars: vec!["KAGGLE_API_TOKEN".to_string()],
            file_path: None,
        });
        assert_eq!(
            home.secret_path(),
            PathBuf::from("age/secrets/users/can/kaggle-api-token.age")
        );
        assert_eq!(
            home.module_path(),
            PathBuf::from("home/user/can/repositories/kaggle-api-token.nix")
        );

        let shared = TargetSpec::SharedHome(SharedHomeTarget {
            slug: "deepseek".to_string(),
            age_name: "shared-deepseek".to_string(),
            env_vars: vec!["DEEPSEEK_API_KEY".to_string()],
        });
        assert_eq!(
            shared.secret_path(),
            PathBuf::from("age/secrets/users/shared/deepseek.age")
        );
        assert_eq!(
            shared.module_path(),
            PathBuf::from("home/user/shared/deepseek.nix")
        );
        assert_eq!(
            shared.default_nix(),
            PathBuf::from("home/user/shared/default.nix")
        );

        let forgejo = TargetSpec::Forgejo(ForgejoTarget {
            slug: "copr-token".to_string(),
            age_name: default_forgejo_age_name("codeberg", "copr-token"),
            credential_name: Some("copr-token".to_string()),
            instances: vec!["codeberg".to_string()],
        });
        assert_eq!(
            forgejo.secret_path(),
            PathBuf::from("age/secrets/modules/foregejo-runner/copr-token.age")
        );
    }
}
