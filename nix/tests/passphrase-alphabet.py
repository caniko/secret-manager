"""Run the rendered passphrase generators against deterministic byte fixtures."""

import os
import string
import subprocess
import sys
import tempfile
from pathlib import Path


def check(bash, length, script_path):
    alphabet = set(string.ascii_letters + string.digits + "@%_+=.,:/?-")
    script = Path(script_path).read_text()
    with tempfile.TemporaryDirectory() as temporary:
        entropy = Path(temporary) / "entropy"
        # Every byte gets near the front in one of these rotations. The prefix
        # satisfies all four character classes even for the shortest output.
        for offset in (0, 64, 128, 192):
            values = bytes(range(256))
            entropy.write_bytes(b"aA0@" + values[offset:] + values[:offset])
            result = subprocess.run(
                [bash, "-euo", "pipefail", "-c", script.replace("/dev/urandom", str(entropy))],
                capture_output=True,
                check=True,
                timeout=10,
                env={**os.environ, "LC_ALL": "C"},
            )
            password = result.stdout.decode("ascii")
            assert len(password) == length, f"wrong output length for {length}"
            assert set(password) <= alphabet, f"unsafe character from {length}-character generator"
            for category in (string.ascii_lowercase, string.ascii_uppercase, string.digits, "@%_+=.,:/?-"):
                assert set(password) & set(category), f"missing character class for {length}"
    print(f"PASS: {length}-character generator preserves the environment-file-safe alphabet")


if __name__ == "__main__":
    bash, *pairs = sys.argv[1:]
    assert len(pairs) == 6, "expected the 32, 48 and 64 character generator scripts"
    for length, path in zip(pairs[::2], pairs[1::2], strict=True):
        check(bash, int(length), path)
