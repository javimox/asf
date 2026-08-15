#!/usr/bin/env python3
"""Regenerate the ASF source/deployment SPDX inventory deterministically.

The previous SBOM was produced by a one-off pre-release inventory generator
that did not live in the repository, so the document went stale the moment
the tree changed. This tool makes the SBOM reproducible: anyone can rerun it
and compare digests.

The package digest is a deterministic SHA-256 over the sorted list of
``<relative-path>\\n<sha256(file)>\\n`` entries for every tracked source file,
excluding generated caches, build outputs, session artifacts, local editor
settings, and the SBOM file itself. ``created`` is derived from the newest
file mtime so an unchanged tree yields a byte-identical document.

Usage:  python3 tools/generate_sbom.py [--check]
  --check   verify the committed SBOM matches the tree (exit 1 on drift)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SBOM_DIR = ROOT / "docs" / "sbom"

_EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    ".claude",
    "build",
    "dist",
    "persistent",
    "sessions",  # .devcontainer/sessions
}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pyd"}
_EXCLUDED_NAMES = {".DS_Store", ".firewall-hash", ".current-agent"}


def _version() -> str:
    return (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def _excluded(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    parts = relative.parts
    if any(part in _EXCLUDED_DIRS for part in parts):
        return True
    if any(part.endswith(".egg-info") for part in parts):
        return True
    if parts[:2] == ("docs", "sbom"):
        return True
    if path.name in _EXCLUDED_NAMES or path.suffix in _EXCLUDED_SUFFIXES:
        return True
    if parts[0] == "secrets" and path.suffix == ".env":
        return True
    if len(parts) > 1 and parts[0] == ".devcontainer" and (
        parts[1].startswith(".open-lock-")
        or parts[1].startswith(".broker-host-")
        or parts[1] == "devcontainer.json"
    ):
        return True
    return False


def _inventory() -> tuple[list[Path], str, float]:
    files = sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not path.is_symlink() and not _excluded(path)
    )
    digest = hashlib.sha256()
    newest = 0.0
    for path in files:
        newest = max(newest, path.stat().st_mtime)
        digest.update(str(path.relative_to(ROOT)).encode("utf-8"))
        digest.update(b"\n")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode())
        digest.update(b"\n")
    return files, digest.hexdigest(), newest


def _document(file_count: int, tree_digest: str, newest_mtime: float) -> dict:
    version = _version()
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(newest_mtime))
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "annotations": [
            {
                "annotationDate": created,
                "annotationType": "OTHER",
                "annotator": "Tool: tools/generate_sbom.py",
                "comment": (
                    "Source/deployment inventory only; container image "
                    "layers were not scanned."
                ),
            }
        ],
        "creationInfo": {
            "created": created,
            "creators": ["Tool: tools/generate_sbom.py"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": ["SPDXRef-Package-ASF"],
        "documentNamespace": (
            f"https://asf.invalid/spdx/{version}/{tree_digest[:16]}"
        ),
        "name": f"ASF-{version}-source-deployment-inventory",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-ASF",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": tree_digest}
                ],
                "comment": (
                    f"Deterministic source-tree digest over {file_count} "
                    "files using sorted SHA-256 file digests and relative "
                    "paths; excludes generated caches, build outputs, "
                    "session artifacts, local .claude settings, and the "
                    "docs/sbom/ directory itself. Regenerate with "
                    "tools/generate_sbom.py."
                ),
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "BSD-4-Clause",
                "licenseDeclared": "BSD-4-Clause",
                "name": "Agent Sandboxing Framework",
                "packageVerificationCode": {
                    "packageVerificationCodeValue": tree_digest
                },
                "versionInfo": version,
            }
        ],
        "spdxVersion": "SPDX-2.3",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed SBOM matches the tree without writing",
    )
    arguments = parser.parse_args(argv)

    files, tree_digest, newest = _inventory()
    document = _document(len(files), tree_digest, newest)
    destination = SBOM_DIR / f"asf-v{_version()}.spdx.json"
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"

    if arguments.check:
        if not destination.exists():
            print(f"✗ {destination.relative_to(ROOT)} does not exist")
            return 1
        existing = json.loads(destination.read_text(encoding="utf-8"))
        recorded = existing["packages"][0]["checksums"][0]["checksumValue"]
        if recorded != tree_digest:
            print(
                "✗ SBOM is stale: recorded digest "
                f"{recorded[:16]}… != tree digest {tree_digest[:16]}…"
            )
            return 1
        print(f"✓ SBOM matches the tree ({len(files)} files)")
        return 0

    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    for stale in SBOM_DIR.glob("asf-v*.spdx.json"):
        if stale != destination:
            stale.unlink()
    destination.write_text(payload, encoding="utf-8")
    print(
        f"✓ wrote {destination.relative_to(ROOT)} "
        f"({len(files)} files, digest {tree_digest[:16]}…)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
