use clap::Parser;

#[derive(Parser)]
#[command(version, about = "Declarative secret management for NixOS")]
struct Cli;

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();
    Ok(())
}
