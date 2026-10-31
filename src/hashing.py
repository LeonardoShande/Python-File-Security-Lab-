"""
hashing.py
==========

Responsibilities
-----------------
Provides hashing utilities used throughout the lab to:

1. Compute strong, modern digests (SHA-256) used for real integrity
   verification of protected files.
2. Compute legacy digests (MD5, SHA-1) *strictly for educational
   comparison* in Scenario B, to demonstrate why these algorithms are
   no longer considered safe for integrity or security purposes
   (collision attacks, speed-of-brute-force, etc.).
3. Offer simple helpers to compare two hashes and report whether a
   file has been modified.

Security note
-------------
MD5 and SHA-1 are included ONLY so the lab can visually demonstrate
their weaknesses (see docs/security_analysis.md). They must never be
used in this project to protect real data — that responsibility
belongs exclusively to the SHA-256 based integrity checks and the
AES-256-GCM authenticated encryption in encryption.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# Chunk size used for streaming large files instead of loading them
# fully into memory.
_CHUNK_SIZE = 65536  # 64 KB


@dataclass(frozen=True)
class HashResult:
    """Container for a computed hash and metadata about how it was produced."""

    algorithm: str
    hexdigest: str
    file_path: str

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return f"{self.algorithm.upper():7s} {self.hexdigest}  {self.file_path}"


def _hash_file(path: Path, algorithm: str) -> HashResult:
    """Stream a file through the given hashlib algorithm and return the digest.

    Streaming (rather than `path.read_bytes()`) keeps memory usage constant
    regardless of file size, which matters for a "professional quality"
    implementation even in a lab context.
    """
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    hasher = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            hasher.update(chunk)

    return HashResult(algorithm=algorithm, hexdigest=hasher.hexdigest(), file_path=str(path))


def sha256_file(path: Path) -> HashResult:
    """Compute the SHA-256 digest of a file.

    This is the algorithm used for real integrity verification
    throughout the lab (Scenario A).
    """
    return _hash_file(path, "sha256")


def sha1_file(path: Path) -> HashResult:
    """Compute the SHA-1 digest of a file.

    EDUCATIONAL USE ONLY — SHA-1 is cryptographically broken for
    collision resistance (see docs/security_analysis.md) and must not
    be relied on for integrity or security in real systems.
    """
    return _hash_file(path, "sha1")


def md5_file(path: Path) -> HashResult:
    """Compute the MD5 digest of a file.

    EDUCATIONAL USE ONLY — MD5 is cryptographically broken and
    trivially collision-prone. Included only to contrast against
    SHA-256 in Scenario B.
    """
    return _hash_file(path, "md5")


def hash_all(path: Path) -> dict[str, HashResult]:
    """Compute SHA-256, SHA-1 and MD5 for a file in one pass-friendly call.

    Useful for the "Generate security report" menu option, where we want
    to show the contrast between a modern and legacy algorithms side by side.
    """
    return {
        "sha256": sha256_file(path),
        "sha1": sha1_file(path),
        "md5": md5_file(path),
    }


def hashes_match(hash_a: str, hash_b: str) -> bool:
    """Constant-time-ish comparison of two hex digests.

    Uses hmac.compare_digest to avoid leaking timing information, which
    is good practice even though hash comparison for integrity checks
    (not secrets) is less timing-sensitive than password comparison.
    """
    import hmac

    return hmac.compare_digest(hash_a.lower(), hash_b.lower())


def describe_modification(original: str, current: str) -> str:
    """Return a human-readable verdict comparing two hex digests."""
    if hashes_match(original, current):
        return "INTACT — hashes match, no modification detected."
    return "MODIFIED — hashes differ, file integrity has been compromised."
