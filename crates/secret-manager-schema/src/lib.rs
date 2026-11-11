//! Data schema for secret-manager registries, kept apart from the engine
//! crate so data repositories and their tooling can decode it without the
//! engine's dependencies.

pub mod accounts;
