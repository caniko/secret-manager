//! Strong passphrases for agenix-rekey generators.
//!
//! std-only on purpose: `nix/passphrase-package.nix` compiles this file alone
//! into `secret-manager-passphrase`, so secret generation does not depend on
//! the whole CLI (and the wiping is hand-rolled for the same reason; `zeroize`
//! is not in that build).

use std::io::{self, Read};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &str = "0123456789";
/// No character that is special to a systemd `KEY=value` EnvironmentFile or a
/// bash/nushell `export VAR="$val"` (no `$ " ' \` backtick `#`, no
/// whitespace), so one value is safe in every delivery target.
const SYMBOL: &str = "@%_+=.,:/?-";
const CLASSES: [&str; 4] = [LOWER, UPPER, DIGIT, SYMBOL];

/// Overwrite every byte so an optimizing build cannot elide the wipe. A
/// volatile write is an observable side effect, and the fence keeps the
/// compiler from moving the wipe past the point where the buffer dies.
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a valid, aligned pointer into this live slice.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Entropy scratch that is zeroed however the draw ends.
struct Scratch([u8; 256]);

impl Scratch {
    fn wipe(&mut self) {
        wipe(&mut self.0);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Zero a rejected candidate in place. Every accepted byte is ASCII, so
/// overwriting each byte with NUL keeps the buffer valid UTF-8.
fn zero(value: &mut str) {
    // SAFETY: the bytes were ASCII and stay valid UTF-8 when replaced by NUL.
    wipe(unsafe { value.as_bytes_mut() });
}

/// A candidate that wipes itself unless it is handed out.
struct Candidate(String);

impl Candidate {
    fn take(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Candidate {
    fn drop(&mut self) {
        zero(&mut self.0);
    }
}

/// A passphrase of `len` characters, uniform over the four classes above and
/// containing at least one character of each. Entropy bytes outside the
/// alphabet are discarded (rejection sampling), so no character is favoured.
/// Rejected candidates and the entropy scratch are wiped before they are
/// dropped: neither may linger in memory.
pub fn strong_passphrase(len: usize, entropy: &mut impl Read) -> io::Result<String> {
    if len < CLASSES.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a passphrase needs at least four characters",
        ));
    }
    let mut chunk = Scratch([0u8; 256]);
    loop {
        let mut candidate = Candidate(String::with_capacity(len));
        while candidate.0.len() < len {
            let read = entropy.read(&mut chunk.0)?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            candidate.0.extend(
                chunk.0[..read]
                    .iter()
                    .map(|&byte| char::from(byte))
                    .filter(|&c| CLASSES.iter().any(|class| class.contains(c)))
                    .take(len - candidate.0.len()),
            );
        }
        if CLASSES
            .iter()
            .all(|class| candidate.0.chars().any(|c| class.contains(c)))
        {
            return Ok(candidate.take());
        }
    }
}

/// A passphrase drawn from the kernel random source.
pub fn from_urandom(len: usize) -> io::Result<String> {
    strong_passphrase(len, &mut std::fs::File::open("/dev/urandom")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingReader(io::ErrorKind);

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "injected entropy failure"))
        }
    }

    struct OneByteReader<'a>(&'a [u8]);

    impl Read for OneByteReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.0[0];
            self.0 = &self.0[1..];
            Ok(1)
        }
    }

    #[test]
    fn rejects_lengths_shorter_than_four_and_accepts_four() {
        for len in 0..CLASSES.len() {
            let err = strong_passphrase(len, &mut b"aA0@".as_slice()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        assert_eq!(
            strong_passphrase(4, &mut b"aA0@".as_slice()).unwrap(),
            "aA0@"
        );
    }

    #[test]
    fn propagates_eof_short_reads_and_io_errors() {
        let empty_err = strong_passphrase(8, &mut b"".as_slice()).unwrap_err();
        assert_eq!(empty_err.kind(), io::ErrorKind::UnexpectedEof);

        let short_err = strong_passphrase(8, &mut b"aA0@x".as_slice()).unwrap_err();
        assert_eq!(short_err.kind(), io::ErrorKind::UnexpectedEof);

        let mut failing = FailingReader(io::ErrorKind::PermissionDenied);
        let io_err = strong_passphrase(8, &mut failing).unwrap_err();
        assert_eq!(io_err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn handles_multi_chunk_and_256_byte_scratch_boundaries() {
        // More than 256 non-alphabet bytes followed by valid bytes forces
        // multiple 256-byte scratch refills before a full candidate forms.
        let mut bytes = vec![0u8; 300];
        bytes.extend_from_slice(b"zZ9?qW2/");
        assert_eq!(
            strong_passphrase(8, &mut bytes.as_slice()).unwrap(),
            "zZ9?qW2/"
        );

        // One-byte-at-a-time reads assemble the same deterministic output.
        let mut one_by_one = OneByteReader(b"$\"'\\`# aA0@bB1-");
        assert_eq!(strong_passphrase(8, &mut one_by_one).unwrap(), "aA0@bB1-");
    }

    #[test]
    fn output_keeps_the_environment_file_safe_alphabet() {
        // Every byte value appears; the prefix satisfies all four classes even
        // for the shortest output.
        let values: Vec<u8> = (0..=255).collect();
        for len in [32, 48, 64] {
            for offset in [0, 64, 128, 192] {
                let mut bytes = b"aA0@".to_vec();
                bytes.extend(&values[offset..]);
                bytes.extend(&values[..offset]);
                let passphrase = strong_passphrase(len, &mut bytes.as_slice()).unwrap();
                assert_eq!(passphrase.len(), len);
                for class in CLASSES {
                    assert!(passphrase.chars().any(|c| class.contains(c)));
                }
                assert!(
                    passphrase
                        .chars()
                        .all(|c| CLASSES.iter().any(|class| class.contains(c)))
                );
            }
        }
        // Unsafe bytes are dropped, and a draw missing a class is redrawn.
        // The rest of a rejected read is discarded, like the shell original.
        let mut bytes = b"$\"'\\`# \naaaaaaaa".chain(b"bB1-cdef".as_slice());
        assert_eq!(strong_passphrase(8, &mut bytes).unwrap(), "bB1-cdef");
    }

    #[test]
    fn rejected_candidates_and_the_entropy_scratch_are_wiped() {
        // Both wipes are in place and used on every exit: a rejected
        // candidate is zeroed in place, and so is the entropy scratch.
        let mut rejected = String::from("bB1-cdef");
        zero(&mut rejected);
        assert!(rejected.as_bytes().iter().all(|byte| *byte == 0));
        assert_eq!(rejected.len(), 8);

        let mut scratch = Scratch([7u8; 256]);
        scratch.wipe();
        assert!(scratch.0.iter().all(|byte| *byte == 0));

        // Dropping a non-taken Candidate invokes zero() without panicking, and
        // taking hands out the intact value while leaving an empty buffer.
        let dropped = Candidate(String::from("aA0@bB1-"));
        drop(dropped);
        let taken = Candidate(String::from("aA0@bB1-")).take();
        assert_eq!(taken, "aA0@bB1-");

        // The generator still yields a usable passphrase through the guard.
        let mut bytes = b"aA0@".chain(b"bB1-cdef".as_slice());
        assert_eq!(strong_passphrase(8, &mut bytes).unwrap(), "aA0@bB1-");
    }
}
