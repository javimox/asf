#!/usr/bin/env bash
# pin_digests.sh — resolve the tag-pinned images in asf.conf to immutable
# digest references, on the release host.
#
# Why: tags are mutable. The security claims in TRUST.md and the SBOM are only
# reproducible when every deployed image is pinned by content digest. The Caddy
# builder and runtime images are already digest-pinned in asf/proxy.py; this
# closes the gap for the images configured in asf.conf.
#
# What it does:
#   1. pulls each KEY=image reference listed in PIN_KEYS below
#   2. resolves its RepoDigest
#   3. rewrites asf.conf in place as  KEY=tag@sha256:...   # was: old-ref
#
# Run it on the machine that builds the release, then commit the result and
# regenerate the SBOM (tools/generate_sbom.py). Safe to re-run: an already
# digest-pinned value is left unchanged.
set -euo pipefail

ENGINE="${ENGINE:-podman}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONF="$ROOT/asf.conf"

PIN_KEYS=(NODE_IMAGE UV_IMAGE LITELLM_IMAGE)

command -v "$ENGINE" >/dev/null || { echo "✗ $ENGINE not found" >&2; exit 1; }
[[ -f "$CONF" ]] || { echo "✗ $CONF not found" >&2; exit 1; }

changed=0
for key in "${PIN_KEYS[@]}"; do
    line="$(grep -E "^${key}=" "$CONF" || true)"
    if [[ -z "$line" ]]; then
        echo "  · $key not present in asf.conf — skipping"
        continue
    fi
    ref="${line#"${key}"=}"
    ref="${ref%%#*}"
    ref="$(echo "$ref" | xargs)"
    if [[ "$ref" == *"@sha256:"* ]]; then
        echo "  ✓ $key already digest-pinned"
        continue
    fi

    echo "  → resolving $key ($ref)"
    "$ENGINE" pull --quiet "$ref" >/dev/null
    repo_digest="$("$ENGINE" image inspect --format '{{index .RepoDigests 0}}' "$ref")"
    if [[ -z "$repo_digest" || "$repo_digest" != *"@sha256:"* ]]; then
        echo "✗ could not resolve a RepoDigest for $ref" >&2
        exit 1
    fi
    digest="${repo_digest##*@}"
    pinned="${ref}@${digest}"

    tmp="$(mktemp "$CONF.XXXXXX")"
    awk -v key="$key" -v pinned="$pinned" -v old="$ref" '
        index($0, key "=") == 1 { print key "=" pinned "   # was: " old; next }
        { print }
    ' "$CONF" > "$tmp"
    mv "$tmp" "$CONF"
    echo "  ✓ $key -> $pinned"
    changed=1
done

if [[ "$changed" -eq 1 ]]; then
    echo
    echo "asf.conf updated. Review the diff, rebuild images, rerun the test"
    echo "suite, and regenerate the SBOM before tagging the release."
else
    echo "Nothing to do — every listed image is already digest-pinned."
fi
