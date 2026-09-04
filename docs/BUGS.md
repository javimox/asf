# Known bugs and limitations

This file lists current known bugs and limitations. Security items first.

---

## Security

### 1. Proxy port-ACL ordering — mitigated by design
The Squid config bug (a domain-based `allow` after port-restricted `CONNECT`
rules re-permits every port) is why ASF **generates** proxy config rather than
shipping a hand-written one, and why `StartupVerifier` tests the running
proxy before the agent starts. Keep both properties if the proxy is changed.

### 2. Writable repository mounts include `.git` metadata — open
A runtime with an `rw` repository can modify `.git/config`, hooks, remotes,
and other metadata that may cause later host-side Git commands to execute
repository-controlled behavior. ASF therefore does not present host Git commands
as a safe post-session review path. The structural fix is to keep the working
tree writable while protecting `.git`; that changes the commit workflow and is
left for a focused follow-up rather than a partial command-by-command workaround.

---

## Correctness / portability

### 3. Claude's verification domain is an external availability dependency — mitigated
`statsig.com` is Claude's positive proxy control. Since the advisory-control
change, an *inconclusively* unreachable positive control (host down, 5xx)
degrades to an explicit startup warning instead of aborting; every deny check
remains fatal, and an outright proxy denial of an allowlisted host still
aborts as a policy misconfiguration. `network.verify_domain` in the manifest
still selects a different control domain when preferred.

---


