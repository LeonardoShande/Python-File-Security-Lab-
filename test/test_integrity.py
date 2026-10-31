from pathlib import Path

import pytest

from src import integrity


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "doc.txt"
    p.write_bytes(b"Integrity-checked content.\n")
    return p


def test_manifest_roundtrip(tmp_path: Path, sample_file: Path):
    manifest = integrity.Manifest()
    integrity.add_file_to_manifest(manifest, sample_file)

    manifest_path = tmp_path / "manifest.json"
    integrity.save_manifest(manifest, manifest_path)

    loaded = integrity.load_manifest(manifest_path)
    assert sample_file.name in loaded.records
    assert loaded.records[sample_file.name].sha256 == manifest.records[sample_file.name].sha256


def test_verify_file_intact(tmp_path: Path, sample_file: Path):
    manifest = integrity.Manifest()
    integrity.add_file_to_manifest(manifest, sample_file)

    result = integrity.verify_file(manifest, sample_file)
    assert result.status == "INTACT"


def test_verify_file_modified(tmp_path: Path, sample_file: Path):
    manifest = integrity.Manifest()
    integrity.add_file_to_manifest(manifest, sample_file)

    sample_file.write_bytes(b"this content has been changed")
    result = integrity.verify_file(manifest, sample_file)
    assert result.status == "MODIFIED"


def test_verify_file_missing(tmp_path: Path, sample_file: Path):
    manifest = integrity.Manifest()
    integrity.add_file_to_manifest(manifest, sample_file)

    sample_file.unlink()
    result = integrity.verify_file(manifest, sample_file)
    assert result.status == "MISSING"


def test_verify_unknown_file_raises(tmp_path: Path):
    manifest = integrity.Manifest()
    unknown = tmp_path / "unknown.txt"
    unknown.write_bytes(b"x")
    with pytest.raises(KeyError):
        integrity.verify_file(manifest, unknown)


def test_verify_all(tmp_path: Path):
    manifest = integrity.Manifest()
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_bytes(b"aaa")
    f2.write_bytes(b"bbb")
    integrity.add_file_to_manifest(manifest, f1)
    integrity.add_file_to_manifest(manifest, f2)

    results = integrity.verify_all(manifest, tmp_path)
    statuses = {r.file_name: r.status for r in results}
    assert statuses == {"a.txt": "INTACT", "b.txt": "INTACT"}
