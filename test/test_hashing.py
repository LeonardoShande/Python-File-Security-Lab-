from pathlib import Path

import pytest

from src import hashing


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "sample.txt"
    p.write_bytes(b"Hello, File Security Lab!\n")
    return p


def test_sha256_file_known_value(sample_file: Path):
    result = hashing.sha256_file(sample_file)
    assert result.algorithm == "sha256"
    assert len(result.hexdigest) == 64
    # SHA-256 is deterministic: hashing the same bytes again must match.
    assert hashing.sha256_file(sample_file).hexdigest == result.hexdigest


def test_md5_and_sha1_shorter_than_sha256(sample_file: Path):
    results = hashing.hash_all(sample_file)
    assert len(results["md5"].hexdigest) == 32
    assert len(results["sha1"].hexdigest) == 40
    assert len(results["sha256"].hexdigest) == 64


def test_hashes_match_case_insensitive():
    assert hashing.hashes_match("ABCDEF", "abcdef") is True
    assert hashing.hashes_match("abcdef", "abcdee") is False


def test_describe_modification(sample_file: Path):
    original = hashing.sha256_file(sample_file).hexdigest
    assert "INTACT" in hashing.describe_modification(original, original)

    sample_file.write_bytes(b"tampered content")
    modified = hashing.sha256_file(sample_file).hexdigest
    assert "MODIFIED" in hashing.describe_modification(original, modified)


def test_hash_missing_file_raises(tmp_path: Path):
    missing = tmp_path / "does_not_exist.txt"
    with pytest.raises(FileNotFoundError):
        hashing.sha256_file(missing)
