"""
encryption.py
=============

Responsibilities
-----------------
Implements the "real" protection mechanism of the lab (Scenario A):

1. Derive a strong 256-bit key from a user-supplied passphrase using
   a slow, salted KDF (Scrypt) — so brute-forcing the passphrase is
   expensive even if the ciphertext is stolen.
2. Encrypt files with AES-256 in GCM mode, which provides both
   confidentiality AND integrity/authenticity (an attacker cannot
   silently tamper with ciphertext without detection, unlike AES-CBC).
3. Write a self-contained, versioned container file that stores the
   salt, nonce, KDF parameters and ciphertext together, so decryption
   only needs the file and the original passphrase.

Container format (binary, all multi-byte integers big-endian)
---------------------------------------------------------------
    MAGIC        4 bytes   b"FSLB"   (File Security LaB)
    VERSION      1 byte    0x01
    KDF_N        4 bytes   scrypt cost parameter N
    KDF_R        4 bytes   scrypt block size r
    KDF_P        4 bytes   scrypt parallelization p
    SALT_LEN     1 byte
    SALT         SALT_LEN bytes
    NONCE_LEN    1 byte
    NONCE        NONCE_LEN bytes
    CIPHERTEXT   remainder (includes the 16-byte GCM tag appended by
                 the `cryptography` library)

No key or passphrase is ever written to disk — only the salt and KDF
parameters needed to re-derive the key from a passphrase the user
re-enters at decryption time.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FSLB"
VERSION = 1

# Scrypt cost parameters. N must be a power of two. These values are a
# reasonable interactive-use default (~100-300ms on modern hardware).
# Increasing N/r/p raises the cost of brute-forcing the passphrase.
DEFAULT_SCRYPT_N = 2**14
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

SALT_SIZE = 16   # 128-bit salt
NONCE_SIZE = 12  # 96-bit nonce, recommended size for AES-GCM
KEY_SIZE = 32    # 256-bit key


class ContainerError(ValueError):
    """Raised when a .fslb container is malformed or has an unsupported version."""


@dataclass(frozen=True)
class KdfParams:
    n: int = DEFAULT_SCRYPT_N
    r: int = DEFAULT_SCRYPT_R
    p: int = DEFAULT_SCRYPT_P


def derive_key(passphrase: str, salt: bytes, params: KdfParams = KdfParams()) -> bytes:
    """Derive a 256-bit AES key from a passphrase using Scrypt.

    Scrypt is deliberately memory-hard and CPU-expensive, which makes
    large-scale offline brute-force or dictionary attacks against the
    passphrase significantly more costly than with a fast hash like
    SHA-256 alone. This directly supports Scenario B's demonstration
    of why key derivation choice matters.
    """
    if not passphrase:
        raise ValueError("Passphrase must not be empty.")

    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=params.n, r=params.r, p=params.p)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_file(
    source: Path,
    destination: Path,
    passphrase: str,
    *,
    kdf_params: KdfParams = KdfParams(),
    associated_data: bytes | None = None,
) -> Path:
    """Encrypt `source` with AES-256-GCM, writing a .fslb container to `destination`.

    `associated_data` (AAD) is authenticated but not encrypted — useful
    for binding metadata (like the original filename) to the ciphertext
    without exposing it as a secret. If provided, the SAME value must
    be supplied when decrypting.
    """
    if not source.is_file():
        raise FileNotFoundError(f"Source file not found: {source}")

    plaintext = source.read_bytes()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt, kdf_params)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    header = (
        MAGIC
        + struct.pack(">B", VERSION)
        + struct.pack(">III", kdf_params.n, kdf_params.r, kdf_params.p)
        + struct.pack(">B", len(salt))
        + salt
        + struct.pack(">B", len(nonce))
        + nonce
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(header + ciphertext)

    # Defensively wipe the plaintext bytearray reference; Python strings/
    # bytes are immutable so this is best-effort, documented for clarity.
    del plaintext

    return destination


def parse_container(path: Path) -> dict:
    """Parse a .fslb container's header without decrypting, for inspection."""
    data = path.read_bytes()
    if data[:4] != MAGIC:
        raise ContainerError("Not a valid .fslb container (bad magic bytes).")

    version = data[4]
    if version != VERSION:
        raise ContainerError(f"Unsupported container version: {version}")

    offset = 5
    n, r, p = struct.unpack_from(">III", data, offset)
    offset += 12

    salt_len = data[offset]
    offset += 1
    salt = data[offset : offset + salt_len]
    offset += salt_len

    nonce_len = data[offset]
    offset += 1
    nonce = data[offset : offset + nonce_len]
    offset += nonce_len

    ciphertext = data[offset:]

    return {
        "version": version,
        "kdf_params": KdfParams(n=n, r=r, p=p),
        "salt": salt,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }


__all__ = [
    "encrypt_file",
    "derive_key",
    "parse_container",
    "KdfParams",
    "ContainerError",
    "InvalidTag",
]
