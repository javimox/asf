# Security policy

ASF is a security boundary for AI agent workloads, so reports about the
boundary itself are the most valuable contribution this project can receive.

## Reporting a vulnerability

Please **do not** open a public issue for a suspected vulnerability. Use
GitHub's *Report a vulnerability* (private security advisory) on this
repository instead. Include the ASF version (`./sandbox.sh --version`), your
Podman version, the network mode, and — ideally — a reproducing script.

Coordinated disclosure is appreciated; a fix, a regression test, and an entry in BUGS.md
will credit the reporter unless anonymity is requested.

## Scope

In scope: anything that falsifies a security claim in [TRUST.md](TRUST.md),
including egress or route bypasses, credential exposure to the agent,
secret-mask failures, capability or privilege escalation, cleanup leaving
undeclared resources, or a verification check passing without evidence.

Out of scope: vulnerabilities in the agent workloads themselves, in upstream
images (report those upstream; ASF pins them by digest), and deployments that
modified the enforced hardening in `asf/config.py`.
