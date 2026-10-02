use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use zeroize::Zeroizing;

pub fn sha256(bytes: &[u8]) -> String {
    STANDARD.encode(digest::digest(&digest::SHA256, bytes))
}

pub struct Key(RsaKeyPair);

impl Key {
    pub fn parse(pem: &str) -> Result<Self> {
        let pem = pem.trim();
        let (kind, pkcs8) = if pem.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
            ("RSA PRIVATE KEY", false)
        } else {
            ("PRIVATE KEY", true)
        };
        let start = format!("-----BEGIN {kind}-----");
        let end = format!("-----END {kind}-----");
        let body = pem.strip_prefix(&start).and_then(|p| p.strip_suffix(&end));
        ensure!(
            body.is_some(),
            "expected one unencrypted RSA private key PEM"
        );
        let encoded = Zeroizing::new(
            body.unwrap_or_default()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        );
        let der = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid private key PEM"))?,
        );
        let key = if pkcs8 {
            RsaKeyPair::from_pkcs8(&der)
        } else {
            RsaKeyPair::from_der(&der)
        }
        .map_err(|_| {
            anyhow::anyhow!("invalid RSA key; GitHub App keys must be at least 2048 bits")
        })?;
        Ok(Self(key))
    }

    /// GitHub's fingerprint hashes DER SubjectPublicKeyInfo, matching
    /// `openssl rsa -pubout -outform DER | openssl sha256 -binary`.
    pub fn fingerprint(&self) -> String {
        let algorithm = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let mut bits = vec![0];
        bits.extend_from_slice(self.0.public().as_ref());
        let mut content = algorithm.to_vec();
        content.extend(der(0x03, &bits));
        sha256(&der(0x30, &content))
    }

    pub fn jwt(&self, app_id: u64, now: u64) -> Result<Zeroizing<String>> {
        ensure!(app_id > 0, "app ID must be positive");
        let payload = serde_json::to_vec(
            &serde_json::json!({"iat": now.saturating_sub(30), "exp": now + 120, "iss": app_id.to_string()}),
        )?;
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let mut signature = vec![0; self.0.public().modulus_len()];
        self.0
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow::anyhow!("RSA signing failed"))?;
        Ok(Zeroizing::new(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let bytes = content.len().to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}
