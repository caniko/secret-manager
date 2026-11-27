//! `secret-manager-passphrase LENGTH`: print one strong passphrase, no newline.

use std::io::{Error, ErrorKind, Write};

mod passphrase;

fn main() -> std::io::Result<()> {
    let len = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "usage: secret-manager-passphrase LENGTH",
            )
        })?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(passphrase::from_urandom(len)?.as_bytes())?;
    stdout.flush()
}
