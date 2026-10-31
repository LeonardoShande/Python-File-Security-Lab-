"""
integrity.py
============

Responsibilities
-----------------
Builds on hashing.py to provide file-level and manifest-level
integrity verification:

1. Generate a JSON "manifest" recording the SHA-256 of one or more
   files at protection time.
2. Re-check files against that manifest later, reporting which are
   INTACT, MODIFIED, or MISSING.
3. Provide a single-file convenience check (hash now vs hash then)
   used by the "Analyze integrity" menu option.

This module intentionally only depends on SHA-256 (via hashing.py) for
anything that claims to "protect" integrity — MD5/SHA-1 are only ever
touched inside vulnerability_lab.py, which is clearly scoped to
Scenario B (weakness demonstration), never to real protection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .hashing import HashResult, hashes_match, sha256_file

MANIFEST_VERSION = 1


@dataclass
class IntegrityRecord:
    file_path: str
    sha256: str
    recorded_at: str


@dataclass
class Manifest:
    version: int = MANIFEST_VERSION
    records: dict[str, IntegrityRecord] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "records": {
                key: {
                    "file_path": rec.file_path,
                    "sha256": rec.sha256,
                    "recorded_at": rec.recorded_at,
                }
                for key, rec in self.records.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Manifest":
        records = {
            key: IntegrityRecord(**value) for key, value in data.get("records", {}).items()
        }
        return cls(version=data.get("version", MANIFEST_VERSION), records=records)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_file_to_manifest(manifest: Manifest, path: Path) -> Manifest:
    """Hash `path` with SHA-256 and record it in the manifest (keyed by file name)."""
    result: HashResult = sha256_file(path)
    manifest.records[path.name] = IntegrityRecord(
        file_path=str(path),
        sha256=result.hexdigest,
        recorded_at=_now_iso(),
    )
    return manifest


def save_manifest(manifest: Manifest, manifest_path: Path) -> Path:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
    return manifest_path


def load_manifest(manifest_path: Path) -> Manifest:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    return Manifest.from_dict(data)


@dataclass
class VerificationResult:
    file_name: str
    status: str          # "INTACT" | "MODIFIED" | "MISSING"
    original_hash: str
    current_hash: str | None


def verify_file(manifest: Manifest, file_path: Path) -> VerificationResult:
    """Check a single file against its recorded manifest entry."""
    record = manifest.records.get(file_path.name)
    if record is None:
        raise KeyError(f"No manifest record found for {file_path.name}")

    if not file_path.is_file():
        return VerificationResult(
            file_name=file_path.name,
            status="MISSING",
            original_hash=record.sha256,
            current_hash=None,
        )

    current = sha256_file(file_path).hexdigest
    status = "INTACT" if hashes_match(record.sha256, current) else "MODIFIED"
    return VerificationResult(
        file_name=file_path.name,
        status=status,
        original_hash=record.sha256,
        current_hash=current,
    )


def verify_all(manifest: Manifest, base_dir: Path) -> list[VerificationResult]:
    """Verify every file recorded in the manifest, looked up under base_dir."""
    results = []
    for name in manifest.records:
        results.append(verify_file(manifest, base_dir / name))
    return results


__all__ = [
    "Manifest",
    "IntegrityRecord",
    "VerificationResult",
    "add_file_to_manifest",
    "save_manifest",
    "load_manifest",
    "verify_file",
    "verify_all",
]
