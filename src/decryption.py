"""
decryption.py
=============

Responsibilities
-----------------
Reverses the process in encryption.py:

1. Parse a .fslb container to recover the salt, nonce and KDF
   parameters (none of which are secret — only the passphrase is).
2. Re-derive the AES-256 key from the user-supplied passphrase.
3. Decrypt and AUTHENTICATE the ciphertext using AES-GCM. If the file
   was tampered with, or the passphrase is wrong, decryption fails
   loudly (InvalidTag) instead of silently returning garbage — this
   is the key advantage of an authenticated cipher mode over plain
   AES-CBC, and is called out explicitly in docs/security_analysis.md.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encryption import derive_key, parse_container


class DecryptionError(Exception):
    """Raised when decryption fails due to a wrong passphrase or a tampered file."""


def decrypt_file(
    source: Path,
    destination: Path,
    passphrase: str,
    *,
    associated_data: bytes | None = None,
) -> Path:
    """Decrypt a .fslb container produced by encrypt_file().

    Raises DecryptionError if the passphrase is wrong or the ciphertext
    (or its associated data) has been modified — GCM's authentication
    tag makes tampering detectable rather than silently accepted.
    """
    container = parse_container(source)
    key = derive_key(passphrase, container["salt"], container["kdf_params"])

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(container["nonce"], container["ciphertext"], associated_data)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong passphrase or the file has been "
            "tampered with (GCM authentication tag mismatch)."
        ) from exc

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plaintext)
    return destination


def try_decrypt(source: Path, passphrase: str, *, associated_data: bytes | None = None) -> bool:
    """Attempt decryption in-memory without writing output.

    Returns True if the passphrase is correct (and the file is intact),
    False otherwise. Used by vulnerability_lab.py to run controlled
    dictionary attacks without littering the filesystem with partial
    output files for every guess.
    """
    try:
        container = parse_container(source)
        key = derive_key(passphrase, container["salt"], container["kdf_params"])
        aesgcm = AESGCM(key)
        aesgcm.decrypt(container["nonce"], container["ciphertext"], associated_data)
        return True
    except InvalidTag:
        return False


__all__ = ["decrypt_file", "try_decrypt", "DecryptionError"]
