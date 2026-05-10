//! `lbc-edge` command-line interface.

use clap::{Parser, Subcommand};

use crate::auth::Role;

#[derive(Debug, Parser)]
#[command(version, about = "LBC Edge Node", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the edge node (default).
    Run,
    /// Administrative tools.
    Admin {
        #[command(subcommand)]
        cmd: AdminCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Seed a user. Intended for first-launch admin bootstrap.
    Seed {
        /// User email (must be unique).
        #[arg(long)]
        email: String,
        /// Cleartext password. Prefer `--password-env` to keep it out of shell history.
        #[arg(long, env = "LBC_ADMIN_PASSWORD", hide_env_values = true)]
        password: String,
        /// Role to assign. Defaults to `admin`.
        #[arg(long, default_value = "admin", value_parser = parse_role)]
        role: Role,
    },
}

fn parse_role(s: &str) -> Result<Role, String> {
    s.parse().map_err(|e: anyhow::Error| e.to_string())
}
