#!/usr/bin/env python3
"""Regenerate the ASF source/deployment SPDX inventory deterministically.

The package digest is a SHA-256 over the sorted list of
``<relative-path>\n<sha256(file)>\n`` entries for tracked source files. In a
Git checkout the inventory comes from ``git ls-files`` so local untracked files
cannot change the release SBOM. Source archives fall back to walking the archive
contents with the same generated-file exclusions.

The SPDX ``created`` timestamp comes from the release date in ``CITATION.cff``.
An unchanged tree therefore produces a byte-identical document across checkouts.

Usage:  python3 tools/generate_sbom.py [--check]
  --check   verify the committed SBOM matches the tree (exit 1 on drift)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
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
}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".pyd"}
_EXCLUDED_NAMES = {".DS_Store", ".firewall-hash", ".current-agent"}
_RELEASE_DATE_RE = re.compile(
    r"^date-released:\s*(\d{4}-\d{2}-\d{2})\s*$", re.MULTILINE
)


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
    if parts[:2] == (".devcontainer", "sessions"):
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


def _git_tracked_files() -> list[Path] | None:
    try:
        top = subprocess.run(
            ("git", "-C", str(ROOT), "rev-parse", "--show-toplevel"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except OSError:
        return None
    if top.returncode != 0:
        return None
    try:
        git_root = Path(top.stdout.strip()).resolve(strict=True)
    except OSError:
        return None
    if git_root != ROOT.resolve():
        return None

    result = subprocess.run(
        ("git", "-C", str(ROOT), "ls-files", "-z", "--cached"),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        return None

    files: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("git returned a non-UTF-8 tracked path") from exc
        path = ROOT / relative
        if path.is_file() and not path.is_symlink() and not _excluded(path):
            files.append(path)
    return sorted(files)


def _inventory_files() -> list[Path]:
    tracked = _git_tracked_files()
    if tracked is not None:
        return tracked
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not path.is_symlink() and not _excluded(path)
    )


def _inventory() -> tuple[list[Path], str]:
    files = _inventory_files()
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(ROOT)).encode("utf-8"))
        digest.update(b"\n")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode())
        digest.update(b"\n")
    return files, digest.hexdigest()


def _created_timestamp() -> str:
    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    match = _RELEASE_DATE_RE.search(citation)
    if match is None:
        raise RuntimeError("CITATION.cff must contain date-released: YYYY-MM-DD")
    return f"{match.group(1)}T00:00:00Z"


def _document(file_count: int, tree_digest: str, created: str) -> dict:
    version = _version()
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
                    "paths. Git checkouts inventory tracked files only; "
                    "source archives use the archive contents. Generated "
                    "caches, build outputs, session artifacts, local .claude "
                    "settings, and docs/sbom/ are excluded. Regenerate with "
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

    files, tree_digest = _inventory()
    document = _document(len(files), tree_digest, _created_timestamp())
    destination = SBOM_DIR / f"asf-v{_version()}.spdx.json"
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"

    if arguments.check:
        if not destination.exists():
            print(f"✗ {destination.relative_to(ROOT)} does not exist")
            return 1
        if destination.read_text(encoding="utf-8") != payload:
            existing = json.loads(destination.read_text(encoding="utf-8"))
            recorded = existing["packages"][0]["checksums"][0]["checksumValue"]
            if recorded != tree_digest:
                print(
                    "✗ SBOM is stale: recorded digest "
                    f"{recorded[:16]}… != tree digest {tree_digest[:16]}…"
                )
            else:
                print("✗ SBOM metadata is stale; regenerate with tools/generate_sbom.py")
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
