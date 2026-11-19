//! Versioned, value-free metadata stored beside encrypted sources.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::layout::Category;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    External,
    Generated,
    Signing,
    GeneratedWithHistory,
}

impl Kind {
    pub fn for_category(category: Category) -> Self {
        match category {
            Category::Signing | Category::Ssh => Self::Signing,
            Category::App | Category::System => Self::Generated,
            _ => Self::External,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Generate,
    Replace,
    Reissue,
    Manual,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub method: Option<Method>,
    pub command: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub schema: u32,
    pub expiry: Option<String>,
    pub rotated_at: Option<String>,
    pub project: Option<String>,
    pub custodian: Option<String>,
    pub kind: Option<Kind>,
    pub rotation: Option<Rotation>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            schema: 1,
            expiry: None,
            rotated_at: None,
            project: None,
            custodian: None,
            kind: None,
            rotation: None,
        }
    }
}

/// Validate a strict Gregorian calendar date.
pub fn valid_date(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || !b
            .iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return false;
    }
    let year: u32 = value[0..4].parse().unwrap_or(0);
    let month: u32 = value[5..7].parse().unwrap_or(0);
    let day: u32 = value[8..10].parse().unwrap_or(0);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    year > 0 && day > 0 && day <= max
}

impl Metadata {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            bail!("unsupported metadata schema {}", self.schema);
        }
        if self
            .expiry
            .as_deref()
            .is_some_and(|s| s != "never" && !valid_date(s))
        {
            bail!("invalid expiry date");
        }
        if self.rotated_at.as_deref().is_some_and(|s| !valid_date(s)) {
            bail!("invalid rotated_at date");
        }
        Ok(())
    }

    /// Missing sidecars have unknown metadata; malformed sidecars fail closed.
    pub fn load(source: &Path) -> Result<Self> {
        let path = sidecar_path(source);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let metadata: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        metadata.validate()?;
        Ok(metadata)
    }

    /// Replace only the sidecar, atomically, with stable serialized field order.
    pub fn save(&self, source: &Path) -> Result<()> {
        self.validate()?;
        let path = sidecar_path(source);
        let mut tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))?;
        tmp.write_all(toml::to_string(self)?.as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(path)?;
        Ok(())
    }
}

pub fn sidecar_path(source: &Path) -> PathBuf {
    source.with_extension("meta.toml")
}

/// Metadata-only classification; does not alter the encrypted source or rotation date.
#[derive(clap::Args, Debug)]
pub struct ClassifyArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub expires: Option<String>,
    #[arg(long)]
    pub kind: Option<Kind>,
    #[arg(long)]
    pub custodian: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    #[arg(long)]
    pub rotation_method: Option<Method>,
    #[arg(long)]
    pub rotation_command: Option<String>,
    #[arg(long)]
    pub note: Option<String>,
}

impl ClassifyArgs {
    pub fn run(&self) -> Result<()> {
        if self.path.extension().is_none_or(|ext| ext != "age") || !self.path.is_file() {
            bail!("source must be an existing .age file");
        }
        let mut meta = Metadata::load(&self.path)?;
        if let Some(value) = &self.expires {
            meta.expiry = Some(value.clone());
        }
        if let Some(value) = self.kind {
            meta.kind = Some(value);
        }
        if let Some(value) = &self.custodian {
            meta.custodian = Some(value.clone());
        }
        if let Some(value) = &self.project {
            meta.project = Some(value.clone());
        }
        if self.rotation_method.is_some() || self.rotation_command.is_some() || self.note.is_some()
        {
            let rotation = meta.rotation.get_or_insert_with(Rotation::default);
            if let Some(value) = self.rotation_method {
                rotation.method = Some(value);
            }
            if let Some(value) = &self.rotation_command {
                rotation.command = Some(value.clone());
            }
            if let Some(value) = &self.note {
                rotation.note = Some(value.clone());
            }
        }
        meta.save(&self.path)?;
        print!("{}", toml::to_string(&meta)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_validation_and_atomic_save() {
        assert!(valid_date("2028-02-29"));
        assert!(!valid_date("2027-02-29"));
        assert!(!valid_date("1900-02-29"));
        assert!(valid_date("2000-02-29"));
        assert_eq!(Kind::for_category(Category::Oauth), Kind::External);
        assert_eq!(Kind::for_category(Category::System), Kind::Generated);
        assert_eq!(Kind::for_category(Category::Ssh), Kind::Signing);
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("secret.age");
        std::fs::write(&source, b"ciphertext").unwrap();
        let metadata = Metadata {
            expiry: Some("never".into()),
            ..Default::default()
        };
        metadata.save(&source).unwrap();
        assert_eq!(
            Metadata::load(&source).unwrap().expiry.as_deref(),
            Some("never")
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"ciphertext");
        std::fs::write(sidecar_path(&source), "schema = 2\n").unwrap();
        assert!(Metadata::load(&source).is_err());
        std::fs::write(sidecar_path(&source), "schema = 1\nunknown = 1\n").unwrap();
        assert!(Metadata::load(&source).is_err());
    }

    #[test]
    fn classify_preserves_rotation_date() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.age");
        std::fs::write(&path, b"placeholder").unwrap();
        Metadata {
            rotated_at: Some("2026-11-18".into()),
            ..Default::default()
        }
        .save(&path)
        .unwrap();
        ClassifyArgs {
            path: path.clone(),
            expires: Some("never".into()),
            kind: None,
            custodian: None,
            project: None,
            rotation_method: None,
            rotation_command: None,
            note: None,
        }
        .run()
        .unwrap();
        assert_eq!(
            Metadata::load(&path).unwrap().rotated_at.as_deref(),
            Some("2026-11-18")
        );
    }
}
