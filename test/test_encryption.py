from pathlib import Path

import pytest

from src import decryption, encryption


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "secret.txt"
    p.write_bytes(b"Top secret lab content.\n" * 10)
    return p


FAST_KDF = encryption.KdfParams(n=2**10, r=8, p=1)


def test_encrypt_decrypt_roundtrip(tmp_path: Path, sample_file: Path):
    enc_path = tmp_path / "secret.fslb"
    dec_path = tmp_path / "secret.decrypted"
    password = "CorrectHorseBatteryStaple!"

    encryption.encrypt_file(sample_file, enc_path, password, kdf_params=FAST_KDF)
    assert enc_path.is_file()
    assert enc_path.read_bytes()[:4] == encryption.MAGIC

    decryption.decrypt_file(enc_path, dec_path, password)
    assert dec_path.read_bytes() == sample_file.read_bytes()


def test_wrong_password_fails(tmp_path: Path, sample_file: Path):
    enc_path = tmp_path / "secret.fslb"
    dec_path = tmp_path / "secret.decrypted"

    encryption.encrypt_file(sample_file, enc_path, "RightPassword1!", kdf_params=FAST_KDF)

    with pytest.raises(decryption.DecryptionError):
        decryption.decrypt_file(enc_path, dec_path, "WrongPassword", )


def test_try_decrypt_boolean(tmp_path: Path, sample_file: Path):
    enc_path = tmp_path / "secret.fslb"
    encryption.encrypt_file(sample_file, enc_path, "weak", kdf_params=FAST_KDF)

    assert decryption.try_decrypt(enc_path, "weak") is True
    assert decryption.try_decrypt(enc_path, "wrong") is False


def test_tampering_detected_by_gcm(tmp_path: Path, sample_file: Path):
    enc_path = tmp_path / "secret.fslb"
    password = "AnotherStrongPass!2026"
    encryption.encrypt_file(sample_file, enc_path, password, kdf_params=FAST_KDF)

    data = bytearray(enc_path.read_bytes())
    # Flip a byte somewhere in the ciphertext (well past the header).
    data[-1] ^= 0xFF
    enc_path.write_bytes(bytes(data))

    assert decryption.try_decrypt(enc_path, password) is False


def test_empty_passphrase_rejected(tmp_path: Path, sample_file: Path):
    enc_path = tmp_path / "secret.fslb"
    with pytest.raises(ValueError):
        encryption.encrypt_file(sample_file, enc_path, "", kdf_params=FAST_KDF)


def test_parse_container_rejects_bad_magic(tmp_path: Path):
    bogus = tmp_path / "bogus.fslb"
    bogus.write_bytes(b"NOTF" + b"\x00" * 20)
    with pytest.raises(encryption.ContainerError):
        encryption.parse_container(bogus)
