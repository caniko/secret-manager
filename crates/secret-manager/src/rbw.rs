//! Read one Bitwarden item through rbw's private pipes, without a vault export.
//!
//! The raw JSON schema is rbw 1.15's DecryptedCipher. It includes password
//! history and notes; typed deserialization intentionally ignores unselected
//! fields and never forwards JSON/parser diagnostics containing secret values.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer};
use std::{collections::BTreeMap, path::Path, process::Command, time::Duration};
use zeroize::Zeroizing;

use crate::credential_process::{MAX_BYTES, capture_with_timeout, disable_core_dumps};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RbwSource {
    pub item_id: String,
    pub field: String,
    pub json_fields: BTreeMap<String, String>,
    pub sync: bool,
    pub timeout: Duration,
}

impl RbwSource {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_uuid(&self.item_id),
            "--from-rbw requires an exact Bitwarden item UUID"
        );
        ensure!(
            !self.field.is_empty() && !self.field.chars().any(char::is_control),
            "rbw field must be a nonempty field name"
        );
        ensure!(
            self.json_fields.iter().all(|(key, field)| !key.is_empty()
                && !field.is_empty()
                && !key.chars().chain(field.chars()).any(char::is_control)),
            "rbw JSON mappings require nonempty output and source field names"
        );
        ensure!(
            self.json_fields.len() <= 64,
            "rbw JSON documents support at most 64 selected fields"
        );
        ensure!(
            !self.timeout.is_zero() && self.timeout <= Duration::from_secs(300),
            "rbw timeout must be 1–300 seconds"
        );
        Ok(())
    }

    /// Read one consistent item snapshot. rbw handles unlocking through pinentry.
    /// Sync is explicit: otherwise rbw reads its encrypted local cache.
    pub fn read(&self) -> Result<RbwItem> {
        self.read_with(Path::new("rbw"))
    }

    pub fn read_with(&self, executable: &Path) -> Result<RbwItem> {
        self.validate()?;
        disable_core_dumps()?;
        if self.sync {
            capture_with_timeout(Command::new(executable).arg("sync"), None, self.timeout)
                .context("rbw sync failed; authenticate/unlock the vault before retrying")?;
        }
        let raw = capture_with_timeout(
            Command::new(executable).args(["get", "--raw", "--", &self.item_id]),
            None,
            self.timeout,
        )
        .context("rbw lookup failed; verify the item UUID and unlock the vault with rbw unlock")?;
        RbwItem::from_json(&raw, &self.item_id)
    }

    pub fn payload(&self) -> Result<Zeroizing<Vec<u8>>> {
        let item = self.read()?;
        self.project(&item)
    }

    /// Project selected fields from one snapshot; applications can validate or
    /// normalize their own schema before handing the bytes to StreamEncryptor.
    pub fn project(&self, item: &RbwItem) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        if self.json_fields.is_empty() {
            let value = item.field(&self.field)?;
            return Ok(Zeroizing::new(value.as_bytes().to_vec()));
        }
        let fields = self
            .json_fields
            .iter()
            .map(|(name, field)| Ok((name, item.field(field)?)))
            .collect::<Result<Vec<_>>>()?;
        let borrowed = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut bytes = Zeroizing::new(vec![0; MAX_BYTES / 2]);
        let length = {
            let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
            serde_json::to_writer(&mut writer, &borrowed).map_err(|_| {
                anyhow::anyhow!("selected rbw document exceeds size limit or cannot be encoded")
            })?;
            writer.position() as usize
        };
        bytes.truncate(length);
        Ok(bytes)
    }
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.map(Zeroizing::new))
}

#[derive(Deserialize)]
struct Login {
    #[serde(default, deserialize_with = "secret")]
    username: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    password: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    totp: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
struct CustomField {
    #[serde(default, deserialize_with = "secret")]
    name: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret")]
    value: Option<Zeroizing<String>>,
}

/// Secret-bearing snapshot: deliberately neither Debug nor Serialize.
#[derive(Deserialize)]
pub struct RbwItem {
    id: String,
    data: Option<Login>,
    #[serde(default)]
    fields: Vec<CustomField>,
    #[serde(default, deserialize_with = "secret")]
    notes: Option<Zeroizing<String>>,
}

impl RbwItem {
    /// Validate rbw's response against the requested UUID, never accepting a
    /// fuzzy name match. Only the selected item is decoded, never the full vault.
    pub fn from_json(bytes: &[u8], expected_id: &str) -> Result<Self> {
        ensure!(
            valid_uuid(expected_id),
            "expected Bitwarden item UUID is invalid"
        );
        ensure!(bytes.len() <= MAX_BYTES, "rbw item exceeds size limit");
        let item: Self = serde_json::from_slice(bytes).map_err(|_| {
            anyhow::anyhow!("invalid rbw item JSON; credential diagnostics suppressed")
        })?;
        ensure!(
            item.id.eq_ignore_ascii_case(expected_id),
            "rbw returned a different item UUID"
        );
        Ok(item)
    }

    /// `totp` selects the stored seed/URI, never a generated one-time code.
    /// Prefix custom names with `custom:` to disambiguate built-in field names.
    pub fn field(&self, name: &str) -> Result<Zeroizing<String>> {
        let value = match name {
            "username" => self.data.as_ref().and_then(|data| data.username.as_deref()),
            "password" => self.data.as_ref().and_then(|data| data.password.as_deref()),
            "totp" => self.data.as_ref().and_then(|data| data.totp.as_deref()),
            "notes" => self.notes.as_deref(),
            name => {
                let name = name.strip_prefix("custom:").unwrap_or(name);
                let mut matches = self
                    .fields
                    .iter()
                    .filter(|field| field.name.as_deref().is_some_and(|value| value == name));
                let value = matches.next().and_then(|field| field.value.as_deref());
                if matches.next().is_some() {
                    bail!("rbw custom field is ambiguous");
                }
                value
            }
        }
        .context("selected rbw field is missing")?;
        ensure!(!value.trim().is_empty(), "selected rbw field is empty");
        ensure!(
            value.len() <= MAX_BYTES / 2,
            "selected rbw field exceeds size limit"
        );
        Ok(Zeroizing::new(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "12345678-1234-1234-1234-123456789abc";
    const ITEM: &[u8] = br#"{"id":"12345678-1234-1234-1234-123456789abc","data":{"username":"fixture-user","password":"fixture-password","totp":"otpauth://totp/fixture?secret=GEZDGNBVGY3TQOJQ"},"fields":[{"name":"token","value":"fixture-token"}],"history":[{"password":"old-secret"}]}"#;

    #[test]
    fn raw_item_selects_exact_fields_and_stored_totp_seed() {
        let item = RbwItem::from_json(ITEM, ID).unwrap();
        assert_eq!(item.field("password").unwrap().as_str(), "fixture-password");
        assert_eq!(item.field("username").unwrap().as_str(), "fixture-user");
        assert!(item.field("totp").unwrap().starts_with("otpauth://totp/"));
        assert_eq!(
            item.field("custom:token").unwrap().as_str(),
            "fixture-token"
        );
        assert!(item.field("history").is_err());
        assert!(item.field("missing").is_err());
    }

    #[test]
    fn wrong_ids_invalid_json_missing_and_duplicate_fields_fail_closed() {
        assert!(RbwItem::from_json(ITEM, "abcdefab-1234-1234-1234-123456789abc").is_err());
        assert!(RbwItem::from_json(ITEM, "item name").is_err());
        let error = RbwItem::from_json(b"{fixture-secret", ID).err().unwrap();
        assert!(!format!("{error:#}").contains("fixture-secret"));
        let item = RbwItem::from_json(br#"{"id":"12345678-1234-1234-1234-123456789abc","data":{"password":""},"fields":[{"name":"token","value":"one"},{"name":"token","value":"two"}]}"#, ID).unwrap();
        assert!(item.field("password").is_err());
        assert!(item.field("username").is_err());
        assert!(item.field("custom:token").is_err());
    }

    #[test]
    fn projection_is_one_selected_document_and_notes_support_secure_notes() {
        let source = RbwSource {
            item_id: ID.into(),
            field: "password".into(),
            json_fields: BTreeMap::from([
                ("username".into(), "username".into()),
                ("password".into(), "password".into()),
                ("totpSecret".into(), "totp".into()),
            ]),
            sync: false,
            timeout: Duration::from_secs(120),
        };
        let document = source
            .project(&RbwItem::from_json(ITEM, ID).unwrap())
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&document).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["password"], "fixture-password");
        assert!(
            !std::str::from_utf8(&document)
                .unwrap()
                .contains("old-secret")
        );
        let note = RbwItem::from_json(
            br#"{"id":"12345678-1234-1234-1234-123456789abc","data":null,"notes":"fixture-note"}"#,
            ID,
        )
        .unwrap();
        assert_eq!(note.field("notes").unwrap().as_str(), "fixture-note");
        assert!(note.field("password").is_err());
    }

    #[test]
    fn rbw_subprocess_uses_raw_uuid_lookup_and_redacts_failures() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("rbw-fixture");
        let source = RbwSource {
            item_id: ID.into(),
            field: "password".into(),
            json_fields: BTreeMap::new(),
            sync: false,
            timeout: Duration::from_secs(1),
        };
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\n[ \"$*\" = 'get --raw -- {ID}' ] || exit 2\nprintf '%s' '{}'\n",
                std::str::from_utf8(ITEM).unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            source
                .read_with(&executable)
                .unwrap()
                .field("password")
                .unwrap()
                .as_str(),
            "fixture-password"
        );
        std::fs::write(&executable, "#!/bin/sh\necho fixture-secret >&2\nexit 1\n").unwrap();
        let error = source.read_with(&executable).err().unwrap();
        assert!(!format!("{error:#}").contains("fixture-secret"));
        std::fs::write(&executable, "#!/bin/sh\nsleep 10\n").unwrap();
        assert!(source.read_with(&executable).is_err());
    }
}
