use std::path::Path;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

pub fn load_sync<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create Pkl evaluation runtime")?;
    runtime
        .block_on(pklx::eval_to_typed(
            path,
            pklx::pklr::EvalOptions::default(),
        ))
        .map_err(|e| anyhow::anyhow!("evaluate {}: {}", path.display(), e))
}

pub fn string_literal(value: &str) -> String {
    pklx::pkl_string_literal(value)
}
