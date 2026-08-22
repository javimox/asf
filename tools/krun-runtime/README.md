# ASF verified crun runtime

Routed krun sessions need one small crun extension that maps the OCI annotation
`krun.tap_name=<tap>` to libkrun's public `krun_add_net_tap()` API.

The repository ships **source and provenance only** — never a compiled binary.
A committed executable cannot be independently verified (the build is not
bit-reproducible across toolchains), and a security framework should not ask
its users to trust an opaque blob. What is committed:

- `VERSION` and `COMMIT` — the exact upstream crun release ASF validates;
- `build.sh` — builds that release with the guarded TAP source edit;
- `patches/crun-tap-reference.patch` — the exact edit, in reviewable patch
  form (documentation; `build.sh` performs the same edit with layout guards
  and fails if upstream's krun networking code changes shape);
- `verify-runtime.sh` — checks a local install against the pin.

## Host setup

```bash
tools/krun-runtime/build.sh          # builds the pinned release into bin/
tools/krun-runtime/verify-runtime.sh # optional explicit check
```

`bin/` is git-ignored. Routed ASF resolves `tools/krun-runtime/bin/crun`
automatically and fails closed at `open` time if the install is missing or was
built from a different release than the pin. `CRUN_TAP_RUNTIME` remains an
explicit development override and skips the pin check.

Build requirements: autotools, gcc, pkg-config, and a libkrun 1.x development
install that exports `krun_add_net_tap` (virtio-net enabled). The host still
provides Podman, `/dev/kvm`, and `/dev/net/tun`.

## CI: the `crun TAP` workflow

Push and pull-request runs build the **pinned** release and test it over a real
KVM/TAP positive/negative network policy, then install it as the local runtime
and test ASF's default resolution path. Review CI is therefore deterministic:
an upstream crun release cannot break an unrelated ASF change.

Scheduled and manually dispatched runs build the **latest** upstream release
instead. If upstream has moved past the pin, `verify-runtime.sh` fails — the
intended drift alarm — and the tested candidate is uploaded as an artifact.
Updating the pin is then an explicit, reviewed change to `VERSION` + `COMMIT`,
after reading the upstream release notes.
