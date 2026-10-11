use clap::{Parser, Subcommand};

use secret_manager::env::LocalEnv;
use secret_manager::{add, github_app, gpg, legacy, push, registry, rotate, sync};

#[derive(Parser)]
#[command(
    version,
    about = "Declarative secret management for Nix store repositories"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add an agenix secret for a home-manager target.
    #[command(subcommand, arg_required_else_help = true)]
    Hm(add::HmCmd),

    /// Add an agenix secret for a NixOS host target.
    #[command(subcommand, arg_required_else_help = true)]
    Nixos(add::NixosCmd),

    /// Add an agenix secret for Forgejo Actions or runner credentials.
    #[command(subcommand, arg_required_else_help = true)]
    Forgejo(add::ForgejoCmd),

    /// Register public signing keys on authenticated forge accounts.
    #[command(subcommand, arg_required_else_help = true)]
    Gpg(gpg::GpgCmd),

    /// Enroll and publish GitHub-issued App credentials.
    #[command(subcommand, arg_required_else_help = true)]
    Github(github_app::GithubCmd),

    /// Validate or export Pkl secret registries.
    #[command(subcommand, arg_required_else_help = true)]
    Registry(registry::RegistryCmd),

    /// List every *.age file tracked in the repo.
    List,

    /// Read collected sync targets and push each declared value to its
    /// declared forge Actions destinations.
    Sync(sync::SyncArgs),

    /// Decrypt an agenix secret and push it to repo Actions secret stores
    /// (Codeberg/Forgejo, Codefloe, GitHub) so workflows can read it as
    /// `${{ secrets.<NAME> }}`. The plaintext is never written to disk.
    #[command(arg_required_else_help = true)]
    Push(push::PushArgs),

    /// Decrypt an agenix secret and print the plaintext to stdout (for
    /// piping into other tools; prompts and diagnostics stay on stderr).
    #[command(arg_required_else_help = true)]
    Decrypt(push::DecryptArgs),

    /// Generate a WireGuard keypair, store the private key as an age secret,
    /// and print the public key.
    #[command(name = "wg-keygen", arg_required_else_help = true)]
    WgKeygen {
        /// Path to the agenix-tracked .age file.
        secret_path: String,
    },

    /// Bootstrap the Rauthy env-file secret end to end.
    #[command(name = "rauthy-env")]
    RauthyEnv(legacy::RauthyEnvArgs),

    /// Encrypt a Gerrit `.gitcookies` payload into an agenix secret.
    #[command(name = "gerrit-cookies")]
    GerritCookies(legacy::GerritCookiesArgs),

    /// Rotate a generated agenix secret source in place. The secret's Nix
    /// declaration must carry a `generator`; the previous source is restored
    /// if regeneration fails.
    #[command(name = "rotate", arg_required_else_help = true)]
    Rotate(rotate::RotateArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let env = LocalEnv;
    match cli.command {
        Command::Hm(cmd) => cmd.run(&env),
        Command::Nixos(cmd) => cmd.run(&env),
        Command::Forgejo(cmd) => cmd.run(),
        Command::Gpg(cmd) => cmd.run(),
        Command::Github(cmd) => cmd.run(),
        Command::Registry(cmd) => cmd.run(),
        Command::List => legacy::list(),
        Command::Sync(args) => args.run(),
        Command::Push(args) => args.run(),
        Command::Decrypt(args) => args.run(),
        Command::WgKeygen { secret_path } => legacy::wg_keygen(&secret_path),
        Command::RauthyEnv(args) => legacy::rauthy_env(&args),
        Command::GerritCookies(args) => legacy::gerrit_cookies(&args),
        Command::Rotate(args) => args.run(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn rbw_source_cli_rejects_conflicting_sources_and_missing_uuid() {
        let base = [
            "secret-manager",
            "hm",
            "file",
            "--shared",
            "--name",
            "fixture",
        ];
        for flags in [
            vec!["--rbw-field", "password"],
            vec!["--rbw-rotate"],
            vec![
                "--from-rbw",
                "12345678-1234-1234-1234-123456789abc",
                "--from-file",
                "plaintext",
            ],
            vec![
                "--from-rbw",
                "12345678-1234-1234-1234-123456789abc",
                "--rbw-field",
                "password",
                "--rbw-map",
                "password=password",
            ],
            vec![
                "--from-rbw",
                "12345678-1234-1234-1234-123456789abc",
                "--rbw-timeout-seconds",
                "301",
            ],
        ] {
            assert!(Cli::try_parse_from(base.into_iter().chain(flags)).is_err());
        }
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--from-rbw",
                "12345678-1234-1234-1234-123456789abc",
                "--rbw-rotate"
            ]))
            .is_ok()
        );
    }

    #[test]
    fn gpg_publish_cli_accepts_all_platforms_and_read_only_checks() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from([
            "secret-manager",
            "gpg",
            "publish",
            "nomad.asc",
            "--codefloe",
            "--github",
            "--codeberg",
            "--check",
            "--expected-fingerprint",
            "AE014BE8DCCAC36257D6B5601FA180C8C14B2CAA",
        ])
        .unwrap();
        let Command::Gpg(gpg::GpgCmd::Publish(args)) = cli.command else {
            panic!("expected gpg publish");
        };
        assert!(args.codefloe && args.github && args.codeberg && args.check);
        assert!(!args.dry_run);
    }

    #[test]
    fn gpg_publish_cli_does_not_combine_offline_and_online_checks() {
        assert!(
            Cli::try_parse_from([
                "secret-manager",
                "gpg",
                "publish",
                "nomad.asc",
                "--github",
                "--check",
                "--dry-run",
            ])
            .is_err()
        );
    }
}
