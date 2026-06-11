//! secret-manager — the agenix secret-management engine for Nix "store"
//! repositories (the data repo owns `age/secrets/**` and the master
//! identities; this crate owns plan building, module rendering, secret IO,
//! and forge Actions-secret pushes).
//!
//! Extracted from the canix CLI; the canix `secret` command family is a
//! thin shim over this library.

pub mod add;
pub mod age;
pub mod env;
pub mod io;
pub mod legacy;
pub mod plan;
pub mod push;
pub mod render;
pub mod store;
pub mod sync;
pub mod sync_targets;
pub mod target;
