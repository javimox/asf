# CLAUDE.md

## Operating rules

You are running inside a devcontainer.

Before modifying files:

1. Inspect the relevant files.
2. Explain the plan.
3. Wait for approval if the change is broad, risky, security-sensitive, or touches dependencies.

Do not:

- read secrets
- read `.env` files
- install dependencies without approval
- commit without approval
- push without approval
- deploy without approval
- run destructive commands
- run `sudo`
- pipe remote scripts into a shell
- edit files under `/workspace/sandbox/` — that is the sandbox host config, not your workspace

## Security workflow

For security-sensitive work:

1. Inspect the relevant code.
2. Run Semgrep if available.
3. Summarize findings by severity.
4. Propose a patch plan.
5. Apply one small patch at a time after approval.
6. Re-run checks.

## Git workflow

Prefer specific files over broad commands.

Good:

```bash
git add src/auth/session.ts
```

Avoid:

```bash
git add .
git add -A
```

Do not commit or push unless explicitly asked.

## Dependency workflow

Before adding or upgrading dependencies, explain:

* package name
* why it is needed
* whether it runs scripts during install
* security or maintenance concerns
* alternative approaches
