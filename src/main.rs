mod crypto;
mod vault;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use vault::Vault;

#[derive(Parser, Debug)]
#[command(name = "secret-manager", about = "AES-256-GCM encrypted secret vault")]
struct Cli {
    /// Path to the vault file
    #[arg(short, long, default_value = "vault.json")]
    vault: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize an empty vault
    Init,
    /// Store a secret value under a name
    Set {
        name: String,
        /// Value to store; prompts if omitted
        value: Option<String>,
    },
    /// Retrieve and decrypt a secret
    Get { name: String },
    /// List secret names (not values)
    List,
    /// Delete a secret
    Delete { name: String },
    /// Encrypt a file to `<path>.enc`
    EncryptFile { path: PathBuf },
    /// Decrypt a `.enc` file
    DecryptFile { path: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            if cli.vault.exists() {
                bail!("vault already exists at {}", cli.vault.display());
            }
            let password = prompt_password("Master password: ")?;
            let confirm = prompt_password("Confirm password: ")?;
            if password != confirm {
                bail!("passwords do not match");
            }
            let vault = Vault::create(&password)?;
            vault.save(&cli.vault)?;
            println!("initialized {}", cli.vault.display());
        }
        Commands::Set { name, value } => {
            let password = prompt_password("Master password: ")?;
            let mut vault = Vault::load(&cli.vault, &password)?;
            let value = match value {
                Some(v) => v,
                None => prompt_password(&format!("Value for '{name}': "))?,
            };
            vault.set(&name, &value)?;
            vault.save(&cli.vault)?;
            println!("stored '{name}'");
        }
        Commands::Get { name } => {
            let password = prompt_password("Master password: ")?;
            let vault = Vault::load(&cli.vault, &password)?;
            let value = vault.get(&name)?.context("secret not found")?;
            println!("{value}");
        }
        Commands::List => {
            let password = prompt_password("Master password: ")?;
            let vault = Vault::load(&cli.vault, &password)?;
            for name in vault.list() {
                println!("{name}");
            }
        }
        Commands::Delete { name } => {
            let password = prompt_password("Master password: ")?;
            let mut vault = Vault::load(&cli.vault, &password)?;
            if !vault.delete(&name) {
                bail!("secret not found");
            }
            vault.save(&cli.vault)?;
            println!("deleted '{name}'");
        }
        Commands::EncryptFile { path } => {
            let password = prompt_password("Password: ")?;
            let data = std::fs::read(&path)?;
            let encrypted = crypto::encrypt(&password, &data)?;
            let out = PathBuf::from(format!("{}.enc", path.display()));
            std::fs::write(&out, encrypted)?;
            println!("wrote {}", out.display());
        }
        Commands::DecryptFile { path } => {
            let password = prompt_password("Password: ")?;
            let data = std::fs::read(&path)?;
            let plain = crypto::decrypt(&password, &data)?;
            let out = path
                .to_str()
                .and_then(|s| s.strip_suffix(".enc"))
                .map(PathBuf::from)
                .unwrap_or_else(|| path.with_extension("dec"));
            std::fs::write(&out, plain)?;
            println!("wrote {}", out.display());
        }
    }
    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}
