"""Run the rendered passphrase generators the way agenix does."""

import string
import subprocess
import sys
from pathlib import Path

SYMBOLS = "@%_+=.,:/?-"


def check(bash, length, script_path):
    alphabet = set(string.ascii_letters + string.digits + SYMBOLS)
    script = Path(script_path).read_text()
    # The deterministic alphabet contract is a Rust test that the generator
    # package runs at build time; this proves the rendered script delivers it.
    for _ in range(64):
        result = subprocess.run(
            [bash, "-euo", "pipefail", "-c", script],
            capture_output=True,
            check=True,
            timeout=10,
        )
        password = result.stdout.decode("ascii")
        assert len(password) == length, f"wrong output length for {length}"
        assert set(password) <= alphabet, f"unsafe character from {length}-character generator"
        for category in (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS):
            assert set(password) & set(category), f"missing character class for {length}"
    print(f"PASS: {length}-character generator preserves the environment-file-safe alphabet")


if __name__ == "__main__":
    bash, *pairs = sys.argv[1:]
    assert len(pairs) == 6, "expected the 32, 48 and 64 character generator scripts"
    for length, path in zip(pairs[::2], pairs[1::2], strict=True):
        check(bash, int(length), path)
