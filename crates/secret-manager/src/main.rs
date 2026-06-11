use clap::{Parser, Subcommand};

use secret_manager::env::LocalEnv;
use secret_manager::{add, legacy, push, sync};

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

    /// List every *.age file tracked in the repo.
    List,

    /// Read collected sync targets and push each declared value to its
    /// declared forge Actions destinations.
    Sync(sync::SyncArgs),

    /// Decrypt an agenix secret and push it to repo Actions secret stores
    /// (Codeberg/Forgejo, GitHub) so workflows can read it as
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let env = LocalEnv;
    match cli.command {
        Command::Hm(cmd) => cmd.run(&env),
        Command::Nixos(cmd) => cmd.run(&env),
        Command::Forgejo(cmd) => cmd.run(),
        Command::List => legacy::list(),
        Command::Sync(args) => args.run(),
        Command::Push(args) => args.run(),
        Command::Decrypt(args) => args.run(),
        Command::WgKeygen { secret_path } => legacy::wg_keygen(&secret_path),
        Command::RauthyEnv(args) => legacy::rauthy_env(&args),
        Command::GerritCookies(args) => legacy::gerrit_cookies(&args),
    }
}
