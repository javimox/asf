#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$TMP/bin" "$TMP/asf/secrets"
printf '%s\n' 'ANTHROPIC_API_KEY=provider-secret' > "$TMP/asf/secrets/claude.env"
chmod 600 "$TMP/asf/secrets/claude.env"
cat > "$TMP/bin/devcontainer" <<'DEVCONTAINER'
#!/usr/bin/env bash
exit 0
DEVCONTAINER
chmod 755 "$TMP/bin/devcontainer"

cat > "$TMP/bin/podman" <<'PODMAN'
#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
prefix = os.environ["ASF_TEST_PREFIX"]


def document(identifier, name, role, networks, user=""):
    labels = {
        "asf.sandbox": os.environ.get("ASF_TEST_ROOT", ""),
        "asf.agent": "claude",
        "asf.role": role,
    }
    if role == "runtime":
        labels["asf.session"] = prefix + "-claude"
    return {
        "Id": identifier,
        "Name": name,
        "Config": {"Image": "image:test", "Labels": labels, "User": user},
        "State": {"Status": "running", "Running": True, "ExitCode": 0},
        "NetworkSettings": {"Networks": {network: {} for network in networks}},
        "HostConfig": {"ReadonlyRootfs": True, "PortBindings": {}},
    }


def finish(code=0, stdout="", stderr=""):
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    raise SystemExit(code)


if not args:
    finish()
if args[0] == "ps":
    joined = " ".join(args)
    if "asf.role=proxy" in joined:
        finish(stdout="proxy-id\n")
    if "asf.role=broker" in joined:
        finish(stdout="broker-id\n")
    if "asf.role=routed-gateway" in joined or "asf.role=routed-init" in joined:
        finish()
    if "asf.session" in joined:
        if os.environ.get("MOCK_NO_SESSION") == "true":
            finish()
        finish(stdout="agent-id\n")
    finish()
if args[0] == "inspect" and len(args) >= 4 and args[1] == "-f":
    template = args[2]
    reference = args[3]
    networks = {
        "agent-id": (prefix + "-claude-internal",),
        "proxy-id": (prefix + "-claude-egress", prefix + "-claude-internal"),
        "broker-id": (prefix + "-claude-internal", prefix + "-claude-provider"),
    }
    if reference not in networks:
        finish(125, stderr="Error: no such container\n")
    if "NetworkSettings.Networks" in template:
        finish(stdout="".join(network + "\n" for network in networks[reference]))
    if "PortBindings" in template:
        finish(stdout="none\n")
    if "ReadonlyRootfs" in template:
        finish(stdout="true\n")
    if ".Config.User" in template:
        user = "10001:10001" if reference == "proxy-id" else ""
        finish(stdout=user + "\n")
    if "asf.persistent-net-admin" in template:
        finish(stdout="\n")
    finish(stdout="\n")
if args[:3] == ["inspect", "--type", "container"]:
    docs = {
        "agent-id": document(
            "agent-id",
            prefix + "-claude",
            "runtime",
            (prefix + "-claude-internal",),
            "1000:1000",
        ),
        "proxy-id": document(
            "proxy-id",
            "proxy",
            "proxy",
            (prefix + "-claude-egress", prefix + "-claude-internal"),
            "10001:10001",
        ),
        "broker-id": document(
            "broker-id",
            "broker",
            "broker",
            (prefix + "-claude-internal", prefix + "-claude-provider"),
        ),
    }
    refs = args[3:]
    if any(ref not in docs for ref in refs):
        finish(125, stderr="Error: no such container\n")
    finish(stdout=json.dumps([docs[ref] for ref in refs]))
if args[0] == "exec":
    offset = 1
    interactive = False
    while offset < len(args) and args[offset].startswith("-"):
        option = args[offset]
        if option == "-i":
            interactive = True
            offset += 1
        elif option in ("-e", "--env"):
            offset += 2
        else:
            finish(125, stderr=f"unsupported exec option: {option}\n")
    reference = args[offset]
    command = args[offset + 1 :]
    rendered = " ".join(command)
    payload = sys.stdin.read() if interactive else ""
    if payload:
        if os.environ.get("MOCK_INFRA_FAIL") == "true" and "example.com:443" in payload:
            finish(125, stderr="engine failure\n")
        code = 200 if "statsig.com:443" in payload else 403
        finish(stdout=f"HTTP/1.1 {code} Result\r\n")
    if reference == "proxy-id" and command == ["cat", "/etc/caddy/Caddyfile"]:
        finish(stdout=""":3128 {
    route {
        forward_proxy {
            ports 443
            acl {
                deny 10.0.0.0/8
                deny 169.254.0.0/16
                allow sentry.io
                allow statsig.com
                deny all
            }
        }
    }
}
""")
    if command and command[0] == "printenv":
        finish(1)
    if os.environ.get("MOCK_SUDO_PRESENT") == "true" and "command -v sudo" in rendered:
        finish(1)
    if ".asf-write-test" in rendered or "/etc/.asf-write-test" in rendered:
        finish(1, stderr="Read-only file system\n")
    if command and command[0] == "nc":
        finish()
    if command[:4] in (["ip", "-4", "route", "show"], ["ip", "-6", "route", "show"]):
        finish()
    if command[:4] in (["ip", "-4", "route", "get"], ["ip", "-6", "route", "get"]):
        finish(2, stderr="RTNETLINK: Network is unreachable\n")
    finish()
finish()
PODMAN
chmod 755 "$TMP/bin/podman"

ASF_TEST_PREFIX=$(cd "$TMP/asf" && PYTHONPATH="$PWD" python3 -c 'from asf.paths import RepoPaths; print(RepoPaths.for_root(".").identity.prefix, end="")')
export ASF_TEST_PREFIX ASF_TEST_ROOT="$TMP/asf"
# Keep the shell-facing smoke test intentionally small.  Full successful
# reports and all mode/failure combinations are protected by the permanent
# in-memory vectors and focused Python tests; the real-host suite exercises a
# complete live report.  Here we prove the top-level launcher reaches Python,
# preserves stderr/status, and does not hang on a missing session.
set +e
output=$(cd "$TMP/asf" && MOCK_NO_SESSION=true PATH="$TMP/bin:$PATH" \
    ./sandbox.sh test claude 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]]
grep -q 'No running claude container' <<< "$output"
! grep -q 'Traceback' <<< "$output"
[[ -f "$TMP/asf/tests/reference/security_test_vectors.json" ]]

# The final launcher must enter Python without sourcing production libraries.
cp "$TMP/asf/sandbox.sh" "$TMP/asf/sandbox-no-libs.sh"
rm -rf "$TMP/asf/lib"
set +e
no_libs=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox-no-libs.sh test missing 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]]
grep -q 'Unknown agent: missing' <<< "$no_libs"

echo "test_security_cli.sh: all assertions passed"
