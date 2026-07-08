//! secret-manager — the agenix secret-management engine for Nix "store"
//! repositories (the data repo owns `age/secrets/**` and the master
//! identities; this crate owns plan building, module rendering, secret IO,
//! and forge Actions-secret pushes).
//!
//! Extracted from the canix CLI; the canix `secret` command family is a
//! thin shim over this library.

pub mod add;
pub mod env;
pub mod io;
pub mod legacy;
pub mod pkl;
pub mod plan;
pub mod push;
pub mod registry;
pub mod render;
pub mod store;
pub mod sync;
pub mod sync_state;
pub mod sync_targets;
pub mod target;

/// age decryption and identity resolution live in the shared engine core;
/// re-exported so `secret_manager::age` keeps working for embedders.
pub use nix_manager_core::age;
