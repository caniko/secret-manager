//! Yescrypt shadow hash validation, generation, and password confirmation
//! helpers.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use zeroize::Zeroizing;

/// Extract the `$y$<params>$<salt>$` setting prefix from a yescrypt shadow hash.
pub fn yescrypt_setting(hash: &str) -> Result<String> {
    if hash.chars().any(|c| c.is_control() || c.is_whitespace()) {
        bail!("not a valid yescrypt shadow hash");
    }
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() != 5
        || !parts[0].is_empty()
        || parts[1] != "y"
        || parts[2].is_empty()
        || parts[3].is_empty()
        || parts[4].is_empty()
    {
        bail!("not a valid yescrypt shadow hash");
    }
    Ok(format!("$y${}${}$", parts[2], parts[3]))
}

/// Validate that `hash` is structurally a yescrypt shadow hash without echoing
/// the hash value in any error message.
pub fn validate_yescrypt_hash(label: &str, hash: &str) -> Result<()> {
    yescrypt_setting(hash)
        .map(|_| ())
        .map_err(|_| anyhow!("password hash for {label} is not a valid yescrypt shadow hash"))
}

fn hash_password_with_setting(password: &str, setting: &str) -> Result<String> {
    let mut child = Command::new("mkpasswd")
        .args(["-s", "-m", "yescrypt", "-S", setting])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("mkpasswd missing; cannot verify password hashes")?;
    {
        let mut stdin = child
            .stdin
            .take()
            .context("mkpasswd stdin closed before write")?;
        stdin.write_all(password.as_bytes())?;
    }
    let output = child
        .wait_with_output()
        .context("mkpasswd failed to exit")?;
    if !output.status.success() {
        bail!(
            "mkpasswd could not verify the password hash (exit status {})",
            output.status
        );
    }
    Ok(String::from_utf8(output.stdout)
        .context("mkpasswd returned a non-UTF-8 hash")?
        .trim()
        .to_string())
}

/// Return `true` if `hash` verifies the empty password `""`.
///
/// Fails closed if `hash` is malformed or `mkpasswd` is unavailable.
pub fn hash_matches_empty_password(hash: &str) -> Result<bool> {
    let setting = yescrypt_setting(hash)?;
    let computed = hash_password_with_setting("", &setting)?;
    Ok(computed == hash)
}

/// Hash a non-empty password using `mkpasswd -s -m yescrypt`.
pub fn hash_password_yescrypt(password: &str) -> Result<String> {
    if password.is_empty() {
        bail!("refusing empty password");
    }
    if password.contains(['\0', '\n', '\r']) {
        bail!("password must not contain NUL or newline characters");
    }
    let mut child = Command::new("mkpasswd")
        .args(["-s", "-m", "yescrypt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("mkpasswd missing; cannot hash password")?;
    {
        let mut stdin = child
            .stdin
            .take()
            .context("mkpasswd stdin closed before write")?;
        stdin.write_all(password.as_bytes())?;
    }
    let output = child
        .wait_with_output()
        .context("mkpasswd failed to exit")?;
    if !output.status.success() {
        bail!(
            "mkpasswd failed to hash password (exit status {})",
            output.status
        );
    }
    let hash = String::from_utf8(output.stdout)
        .context("mkpasswd returned a non-UTF-8 hash")?
        .trim()
        .to_string();
    if hash.is_empty() {
        bail!("mkpasswd returned an empty hash");
    }
    if hash_matches_empty_password(&hash)? {
        bail!("refusing empty password");
    }
    Ok(hash)
}

/// Parse a single non-empty password line from redirected stdin.
pub fn parse_stdin_password(input: &str) -> Result<&str> {
    let mut lines = input.lines();
    let password = lines
        .next()
        .ok_or_else(|| anyhow!("password input is empty"))?;
    if password.is_empty() {
        bail!("refusing empty password");
    }
    if lines.any(|line| !line.is_empty()) {
        bail!("password input contains unexpected additional non-empty lines");
    }
    Ok(password)
}

/// Confirm that two entered passwords are non-empty and identical.
pub fn confirm_password(first: String, second: String) -> Result<Zeroizing<String>> {
    let first = Zeroizing::new(first);
    let second = Zeroizing::new(second);
    if first.is_empty() {
        bail!("refusing empty password");
    }
    if *first != *second {
        bail!("passwords do not match");
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_mkpasswd() -> bool {
        Command::new("mkpasswd")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    #[test]
    fn refuses_empty_and_control_char_passwords() {
        assert!(hash_password_yescrypt("").is_err());
        assert!(hash_password_yescrypt("abc\ndef").is_err());
        assert!(hash_password_yescrypt("abc\rdef").is_err());
        assert!(hash_password_yescrypt("abc\0def").is_err());
    }

    #[test]
    fn hashes_nonempty_password() {
        if !has_mkpasswd() {
            return;
        }
        let hash = hash_password_yescrypt("x").unwrap();
        assert!(hash.starts_with("$y$"));
        assert!(!hash_matches_empty_password(&hash).unwrap());
    }

    #[test]
    fn setting_from_hash() {
        assert_eq!(
            yescrypt_setting("$y$j9T$salt$hash").unwrap(),
            "$y$j9T$salt$"
        );
        for bad in [
            "prefix$y$j9T$salt$hash",
            "$y$j9T$salt$hash$extra",
            "$y$j9T$salt$hash\n",
            "$y$j9T$salt $hash",
            "$y$j9T$salt\0$hash",
        ] {
            assert!(yescrypt_setting(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn empty_check_fails_closed_on_garbage() {
        assert!(hash_matches_empty_password("not-a-hash").is_err());
    }

    #[test]
    fn invalid_hash_error_does_not_disclose_hash() {
        let hash = "not-a-hash-secret-marker";
        let error = validate_yescrypt_hash("can", hash).unwrap_err().to_string();
        assert!(!error.contains(hash));
    }

    #[test]
    fn rejects_empty_password_hash() {
        if !has_mkpasswd() {
            return;
        }
        let hash = "$y$j9T$cGUiP4cjrNQmdkfY81ZEr1$d1JVptvnMmqXf4QU/YifJy0/pHbqkNkloXs.kH6puT6";
        assert!(hash_matches_empty_password(hash).unwrap());
    }

    #[test]
    fn accepts_nonempty_password_hash() {
        if !has_mkpasswd() {
            return;
        }
        let hash = "$y$j9T$qLpICyR.yrI9NVgWlZexh/$RvAKxHnAZbQ3QOGl/78QHlnyUDyVBgWVqKCeKTVChC8";
        assert!(!hash_matches_empty_password(hash).unwrap());
    }

    #[test]
    fn confirms_matching_nonempty_passwords() {
        assert_eq!(
            confirm_password("secret".to_owned(), "secret".to_owned())
                .unwrap()
                .as_str(),
            "secret"
        );
        assert!(confirm_password(String::new(), String::new()).is_err());
        assert!(confirm_password("first".to_owned(), "second".to_owned()).is_err());
    }

    #[test]
    fn parses_single_stdin_password() {
        assert_eq!(parse_stdin_password("secret\n").unwrap(), "secret");
        assert_eq!(parse_stdin_password("secret\r\n").unwrap(), "secret");
        assert_eq!(parse_stdin_password("secret\n\n").unwrap(), "secret");
        assert!(parse_stdin_password("").is_err());
        assert!(parse_stdin_password("\n").is_err());
        assert!(parse_stdin_password("secret\nsecond\n").is_err());
    }
}
