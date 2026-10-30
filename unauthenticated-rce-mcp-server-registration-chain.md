# Vulnerability Report: Unauthenticated Remote Code Execution via MCP Server Registration (Chained Exploit)

**Target:** [REDACTED — open-source, Kubernetes-native MCP aggregation platform]
**Disclosure status:** Reported privately to the maintainers; published here with target identity, version, and exploit payloads withheld per responsible disclosure practice.

---

## Severity

| Finding | CVSS v3.1 | CWE |
|---|---|---|
| Unauthenticated Remote Code Execution | 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | CWE-78 (OS Command Injection) |
| Server-Side Request Forgery | 8.6 (High) — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N | CWE-918 (SSRF) |

Both were remotely exploitable by an unauthenticated attacker with nothing more than network access to the application's HTTP endpoint.

## Summary

The platform aggregates multiple backend tool servers behind a single MCP-based API, exposed over HTTP to any client — including AI agents — that can reach it. Four independent weaknesses, none severe in isolation, combined into a complete pre-auth RCE chain:

1. **Authentication is disabled by default.** A fresh install ships with no auth requirement on the aggregator's HTTP endpoint.
2. **Incomplete operation restrictions.** The application maintains a list of operations treated as sensitive/destructive, but the operations that *register* and *start* new backend tool servers are not included in it.
3. **No validation on server registration.** When registering a new backend server of a certain type, the executable path and arguments supplied by the client are used directly to spawn a subprocess, with no allowlist or sanity checking.
4. **No authorization on the dispatch layer.** The central tool-invocation function forwards any requested operation name to its handler without checking whether the caller is permitted to invoke it.

## Root Cause Analysis

- **Factor 1 — Default-open auth.** The server's authentication subsystem is explicitly disabled in the shipped default configuration. Nothing in a standard install prompts or requires enabling it.
- **Factor 2 — Denylist gap.** The restricted-operations list covers several categories of sensitive actions but omits the registration and lifecycle-control operations for backend servers — the two operations this chain depends on.
- **Factor 3 — Unvalidated subprocess spawn.** The code path responsible for creating a new backend connection of the "local process" type accepts a command string and argument list from the request body and passes them, unmodified, into a subprocess-spawning call. There is no allowlist of permitted executables and no inspection of the arguments.
- **Factor 4 — Unchecked dispatch.** The function that resolves and invokes a named operation on behalf of a caller performs no authorization check before dispatching — any reachable operation name is forwarded to its handler.

## Proof of Concept (redacted)

PoC structure is shown below for reproducibility of the *logic*; specific endpoint names, tool identifiers, and payload contents have been withheld.

```
Step 1 — Initialize session
  POST [ENDPOINT] (no auth header required)
  → session established, no credentials checked

Step 2 — Register malicious backend server
  POST [ENDPOINT]
  operation: [REDACTED — "server registration" operation]
  params: {
    type: "local-process",
    command: [REDACTED],
    args: [REDACTED]
  }
  → server registered successfully, no validation performed

Step 3 — Trigger execution
  POST [ENDPOINT]
  operation: [REDACTED — "server start" operation]
  params: { name: <registered-server-name> }
  → subprocess spawned; protocol handshake fails afterward,
    but the command has already executed at that point

Step 4 — Verify execution
  → confirmed via out-of-band evidence (file write / listener capture)
```

The SSRF variant follows the identical two-step pattern (register → start), substituting a server type that accepts an arbitrary URL instead of a local command — the outbound request fires the moment the server starts.

Both were verified against a freshly started, default-configuration instance, over the network, with no local shell access or modified configuration involved.

## Impact

- Full compromise of the application host process
- In Kubernetes-native deployments, likely access to the service account's permitted API operations (commonly including read access to secrets in its namespace)
- Exfiltration of environment variables, mounted credentials, and configuration
- SSRF path additionally exposes cloud metadata endpoints and internal-only services to the same unauthenticated attacker

## Remediation

- Enable authentication by default; do not ship a reachable unauthenticated control-plane endpoint
- Add server-registration and server-lifecycle operations to the restricted-operations list
- Allowlist permitted executables (or disallow the "local process" backend type entirely) rather than trusting client-supplied commands
- Validate outbound URLs for HTTP/SSE-type backends — block loopback, private ranges, and metadata addresses
- Add an authorization check to the central dispatch function before any operation is forwarded to its handler

## Disclosure Timeline

- Vulnerability discovered and independently verified same day
- Reported privately to the maintainers as two separate findings (RCE, SSRF)
- Acknowledged by the maintainers

## Credit

Discovered and reported by **Abhijith S** ([kakashi-kx](https://github.com/kakashi-kx) / [LinkedIn](https://www.linkedin.com/in/abhixjith))

---

## Notes for Other Researchers

This chain didn't require anything exotic — it came from checking whether four very ordinary defaults held up under "what happens if this is reachable with zero credentials." If you're evaluating MCP aggregators or gateways, that's the cheap, high-yield checklist: is auth actually on out of the box, does the sensitive-operations list cover *everything* that can register or start new capabilities (not just the obviously destructive ones), and does anything that spawns a process or issues an outbound request validate what it's been handed before doing so. None of that takes cleverness. It takes reading the defaults the project ships with.
