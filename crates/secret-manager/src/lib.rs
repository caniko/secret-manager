//! secret-manager — the agenix secret-management engine for Nix "store"
//! repositories (the data repo owns `age/secrets/**` and the master
//! identities; this crate owns plan building, module rendering, secret IO,
//! and forge Actions-secret pushes).
//!
//! Extracted from the canix CLI; the canix `secret` command family is a
//! thin shim over this library.

pub mod add;
pub mod claude_token;
pub mod credential_process;
pub mod dockerhub_pat;
pub mod encryption;
pub mod env;
pub mod github_app;
pub mod github_pat;
pub mod github_token;
pub mod gpg;
pub mod graph;
pub mod guide;
pub mod inventory;
pub mod io;
pub mod layout;
pub mod legacy;
pub mod meta;
pub mod passphrase;
pub mod pkl;
pub mod plan;
pub mod protection;
pub mod push;
pub mod rbw;
pub mod registry;
pub mod release_signing;
pub mod render;
pub mod rotate;
pub mod social;
pub mod store;
pub mod sync;
mod sync_kubernetes;
pub mod sync_state;
pub mod sync_targets;
pub mod target;
pub mod verify;

/// age decryption and identity resolution live in the shared engine core;
/// re-exported so `secret_manager::age` keeps working for embedders.
pub use nix_manager_core::age;
