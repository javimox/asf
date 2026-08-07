# Known bugs and limitations

This file lists current known bugs and limitations. Security items first.

---

## Security

### 1. Proxy port-ACL ordering — mitigated by design
The Squid config bug (a domain-based `allow` after port-restricted `CONNECT`
rules re-permits every port) is why ASF **generates** proxy config rather than
shipping a hand-written one, and why `StartupVerifier` tests the running
proxy before the agent starts. Keep both properties if the proxy is changed.

---

## Correctness / portability

### 2. Claude's verification domain is an external availability dependency — mitigated
`statsig.com` is Claude's positive proxy control. Since the advisory-control
change, an *inconclusively* unreachable positive control (host down, 5xx)
degrades to an explicit startup warning instead of aborting; every deny check
remains fatal, and an outright proxy denial of an allowlisted host still
aborts as a policy misconfiguration. `network.verify_domain` in the manifest
still selects a different control domain when preferred.

---


