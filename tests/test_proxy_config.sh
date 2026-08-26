#!/usr/bin/env bash
# Generated proxy policy and image inputs are correct by construction.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PYTHONPATH="$ROOT" python3 - "$ROOT" "$TMP" <<'PY'
from pathlib import Path
import sys

from asf.config import AsfConfig, AsfConfigError
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.proxy import (
    CADDY_BUILDER_IMAGE,
    CADDY_FORWARDPROXY,
    CADDY_IMAGE_REVISION,
    CADDY_RUNTIME_IMAGE,
    CADDY_VERSION,
    effective_proxy_domains,
    render_caddyfile,
    render_containerfile,
)
from asf.runtime_plan import build_runtime_plan

root = Path(sys.argv[1])
tmp = Path(sys.argv[2])
policy = render_caddyfile(("files.pythonhosted.org", "pypi.org"), access_logs=True)
(tmp / "Caddyfile").write_text(policy, encoding="utf-8")
assert "ports 443" in policy
# Access records feed the per-session egress evidence, not stdout.
assert "output file /var/log/asf/caddy-access.jsonl" in policy
assert "format json" in policy
assert "allow pypi.org" in policy and "allow files.pythonhosted.org" in policy
assert policy.index("deny 10.0.0.0/8") < policy.index("allow pypi.org")
assert "deny 169.254.0.0/16" in policy
assert "deny fc00::/7" in policy
assert "deny 64:ff9b::/96" in policy
assert "deny 2002::/16" in policy
assert "deny all" in policy and "deny *" not in policy
assert policy.rindex("allow ") < policy.index("deny all")
assert "allow github.com" not in policy
assert "output file" not in render_caddyfile(("pypi.org",), access_logs=False)
assert "allow " not in render_caddyfile((), access_logs=True)

paths = RepoPaths.for_root(root)
manifest = load_model(paths.identity.runtime_manifest("claude"))
plan = build_runtime_plan(
    manifest, paths=paths, owner_pid=4242, broker_globally_enabled=True
)
domains = effective_proxy_domains(manifest, plan)
assert "api.anthropic.com" not in domains
assert "statsig.com" in domains

assert "@sha256:" in CADDY_BUILDER_IMAGE
assert "@sha256:" in CADDY_RUNTIME_IMAGE
assert "@" in CADDY_FORWARDPROXY
containerfile = render_containerfile()
(tmp / "Containerfile").write_text(containerfile, encoding="utf-8")
assert f"xcaddy build {CADDY_VERSION}" in containerfile
assert CADDY_FORWARDPROXY in containerfile
assert "ENTRYPOINT []" in containerfile
assert "USER 10001:10001" in containerfile
assert CADDY_IMAGE_REVISION == "v2"
assert "COPY Caddyfile" not in containerfile

config = AsfConfig.load(paths.config_file)
config.require_caddy()
for value in ("tinyproxy", "g3proxy"):
    modified = dict(config.values)
    modified["PROXY_IMPL"] = value
    try:
        AsfConfig(config.path, modified).require_caddy()
    except AsfConfigError:
        pass
    else:
        raise AssertionError(f"production lifecycle accepted {value}")
PY

production_test="$ROOT/tests/test_caddy_proxy_paths.sh"
grep -q 'python3 -m asf.proxy image-info --field tag' "$production_test"
grep -q 'python3 -m asf.proxy format-file' "$production_test"
if grep -q 'tinyproxy' "$ROOT/tests/run-host.sh"; then
    echo "default host suite still runs Tinyproxy" >&2
    exit 1
fi
grep -q 'test_caddy_proxy_paths.sh' "$ROOT/tests/run-host.sh"
[[ ! -d "$ROOT/lib" ]]

echo "test_proxy_config.sh: all assertions passed"
