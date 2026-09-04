# Releasing ASF

A release is reproducible evidence, not just a tag. Order matters: the SBOM
hashes the source tree, so it is regenerated **last**.

```bash
# 0. Working tree contains no generated state (all of this is .gitignore'd,
#    but verify before tagging):
git status --ignored

# 1. Fill in identity placeholders once per fork: LICENSE, CITATION.cff.

# 2. Pin image digests on the release host, review the diff. The script keeps
#    the exact human-readable tag and appends its immutable digest:
#    image:version@sha256:...
bash tools/pin_digests.sh

# 3. Bump VERSION, pyproject.toml, asf/version.py, and the pins in
#    tests/test_release.py together, and summarise the changes in the
#    release description (e.g. the annotated git tag / GitHub release).

# 4. Full deterministic suite, then real-host acceptance:
bash tests/run.sh
ASF_INTEGRATION=1 \
ASF_ROUTED_TARGET_IP=<target> ASF_ROUTED_ALLOWED_PORT=<open> \
ASF_ROUTED_BLOCKED_PORT=<blocked> bash tests/run-host.sh

# 5. Regenerate the SBOM (must be the last tree-changing step) and re-run
#    the release checks. In a Git checkout only tracked files are inventoried;
#    the timestamp comes from the stable release date in CITATION.cff:
python3 tools/generate_sbom.py
python3 -m unittest tests.test_release

# 6. Tag. The tag, VERSION, and the SBOM's versionInfo must agree.
```

Notes: the SBOM is a source/deployment inventory; it does not replace
image-layer SBOM generation on the release host. Generated checkout state under
`.asf/sessions/` and host evidence under `$XDG_STATE_HOME/asf/` (or
`~/.local/state/asf/`) are never part of a release.
If a source archive is produced manually, use `git archive` rather than zipping
a live working tree so ignored caches and local files cannot leak into it.
