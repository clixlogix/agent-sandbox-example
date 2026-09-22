# Clixlogix Agent Sandbox Reference Implementation

**Status**: Draft reference implementation for the accompanying knowledge base entry. Requires validation by Clixlogix engineering before publication to `github.com/clixlogix/agent-sandbox-example`.

**Companion article**: [How To Build An AI Agent Sandbox For Production Agents With A 7 Ring Model](https://clixlogix.com/ai-agent-sandbox-production-security)

**License**: MIT

## Files in this bundle

| File | Purpose | Ring coverage |
|---|---|---|
| `agent_sandbox.py` | Managed E2B harness with tool allowlist, fail closed approval gate, broker target guard, broker dispatch split, workspace path guard, and correlated audit redaction | Ring 4, 5, 6, 7 |
| `template.py` | E2B template definition. Creates an agent account with no sudo rights, one writable directory, root owned reference material outside it, and root owned login files | Ring 3 |
| `audit.py` | Ring 6. Per-agent HMAC digests and a hash chained append only sink, with a `verify_chain` CLI | Ring 6 |
| `broker.py` | Ring 4. Working broker with a pluggable `SecretBackend`. Enforces tool, target, scope and TTL, mints a per-call token, executes downstream, revokes | Ring 4 |
| `approvals.py` | Ring 7. File backed approval queue plus a reviewer CLI. Timeout denies | Ring 7 |
| `test_rings.py` | 36 offline tests against a stubbed SDK. No account needed | All rings |
| `test_live.py` | 4 live tests against real sandboxes. Skipped without `E2B_API_KEY` | Rings 1, 2, 3 |
| `reference/docs/` | Sample read only material copied to `/srv/reference/docs` | Feeds Ring 3 |
| `verify_ring3.py` | Opens a sandbox from the built template and probes each file system boundary from inside it as the agent account | Verifies Ring 3 |
| `agent-manifest.yaml` | Permission manifest declaring what one agent instance is allowed to do, including the custom E2B template name, egress hostname allowlist, sandbox and per command timeouts, broker tool set, secrets policy, structured approval rules, and named approval exemptions | Feeds Ring 2, 3, 4, 5, 7 |

Ring 1 (Runtime Isolation) comes from the E2B microVM opened by `Sandbox.create()`. Ring 2 (Network Egress Control) comes from the `network={"allow_out": ..., "deny_out": ...}` argument on that same call, driven by `sandbox.allowed_domains` in the manifest. Ring 3 (File System Boundaries) comes from `template.py`, which builds `company-agent-python-hardened`.

E2B's default sandbox user is `user`, and that account holds passwordless sudo, so ownership and mode enforce nothing under it. The template therefore creates a separate `agent` account in no privileged group, denies it in sudoers, and makes it the sandbox default. Reference material sits at `/srv/reference` rather than inside `/workspace`, because the agent owns the workspace and can unlink anything in it whatever mode a subdirectory carries. Login files are root owned because E2B runs commands through `bash -l -c`, which would otherwise execute agent supplied code from `~/.bashrc` on every later command.

**A gap the template cannot close.** E2B runs its own configuration script *after* the template's layers, and that script makes `/usr/local` and `/code` world writable. `/usr/local/bin` is first on `PATH` and holds the Python interpreter and `site-packages`, so on an unrepaired sandbox the agent can shadow binaries, overwrite the interpreter, and plant importable modules that persist across tool calls for the life of the session. This was verified by doing it: `python3 -V` returned `PWNED`. The harness closes it at session start via `HARDEN_CMD`, before any agent code runs, and refuses the session if the repair does not take. That is the only command the harness issues as root.

**Verification status.** Built and verified against E2B's live API on `e2b==2.37.1`. `verify_ring3.py` reports **21 of 21 controls holding** inside a sandbox opened from this template. Separately confirmed live: E2B's default `user` account holds passwordless sudo; `set_user("agent")` survives E2B's configuration script; the Ring 2 hostname allowlist works end to end, with `pypi.org` reachable and `evil.example.com` blocked from inside the sandbox.

## Deployment model

Managed E2B path. The harness process opens an E2B microVM through the E2B SDK and dispatches each tool call to one of two paths:

- **Broker tools** (`write_record`, `http_post` in this manifest) execute inside an internal broker service. The broker holds the credential, applies scope and target constraints from `secrets_access`, executes the downstream call, and returns only the response. The credential never enters the sandbox. Before the harness dispatches to the broker it requires a `target`, requires that target to be declared under `secrets_access` for that tool, and requires human approval unless `auto_approve` names that exact operation and target pair.
- **Sandbox tools** (`read_file`, `list_directory`, `run_python`, `search_documentation` in this manifest) execute inside the E2B microVM through a fixed dispatch table that normalizes paths, quotes shell arguments, and refuses paths outside the workspace.

No Kubernetes NetworkPolicy applies. The sandbox does not run in the caller's cluster.

## Validation checklist for Clixlogix engineering

Before publishing to the public GitHub repository, the engineering team should verify:

- [x] `agent_sandbox.py` runs against E2B's live API on `e2b==2.37.1` without errors
- [x] `template.py` builds against E2B's live API and `verify_ring3.py` reports every control holding inside the built sandbox (21/21)
- [x] E2B's base layer does not reintroduce a sudo path for the `agent` account, and does not depend on the default `user` account in a way this template breaks
- [x] `HARDEN_CMD` closes the world writable `/usr/local` and `/code` that E2B's configuration script creates, and the session is refused if it fails
- [x] `Sandbox.create(..., network={"allow_out": [...], "deny_out": lambda ctx: [ctx.all_traffic]})` accepts the shape shown and enforces the allowlist at runtime (verified from inside the sandbox: allowlisted host reachable, non-allowlisted host blocked)
- [x] `REFERENCE` is populated at build time via `.copy("reference/docs", ..., user="root", mode=0o555)`. Replace the sample content with real material
- [x] `agent-manifest.yaml` loads through `PermissionManifest.load()` and every field is consumed by the harness
- [x] `PermissionManifest.load()` rejects a broker tool absent from `allowed_tools` and a broker tool with no declared `secrets_access` targets
- [x] A broker tool call with a missing target, an undeclared target, or no matching `auto_approve` entry is refused before dispatch, and each refusal is audited with its reason
- [x] `broker.py` enforces tool, target, scope and TTL, mints a per-call token, executes downstream and revokes. Verified that no credential reaches the harness, the audit log, or the approval record. **Swap `LocalFileBackend` for your own `SecretBackend`** before production
- [x] `approvals.py` blocks on a real human decision and denies on timeout. Verified end to end through the reviewer CLI. Slack or ticketing becomes an adapter over the same two methods
- [x] `ChainedFileSink` writes fsynced, hash chained JSONL. Verified that an edited record and a removed record both fail `verify_chain`. **Ship these lines off host** before production
- [x] Audit events for `write_record` and `http_post` carry `session_id`, `call_id`, `payload_fields`, and `payload_digest`, and never an empty `args` object
- [x] `sandbox.tool_timeout_seconds` reaches every `commands.run()` call, since the SDK default of 60 seconds does not inherit `max_runtime_seconds`
- [x] `search_documentation` returns an empty result for a query with no matches rather than raising `CommandExitException`
- [x] `AuditDigest` is HMAC under a per-agent key derived from `CLX_AUDIT_HMAC_KEY`, and warns loudly when the key is absent
- [x] 36 offline tests and 4 live tests cover every ring, including traversal rejection, unknown tools, missing and undeclared broker targets, approval precedence, digest correlation, chain tamper detection, credential non-leakage, and egress denial
- [x] Symlink behaviour characterised: the target's own ownership and mode decide the outcome. Links to credential paths and `/etc/shadow` are refused; a link to a world readable file reads, which is correct OS behaviour
- [x] License headers are present in every published file

## Dependencies to declare in the public repo

```
e2b==2.37.1
pyyaml>=6.0
pytest>=8.0   # tests only
```

The harness, the template, and the verification script all import from `e2b`. `Template.build` is a staticmethod taking the template as its first argument, and `CommandExitException` carries `exit_code`, `stdout`, and `stderr`. Both were confirmed against the installed SDK.

## Still yours to do before production

The two seams are marked in bold above. `LocalFileBackend` reads secrets from a
local JSON file and derives a token, which is real enough to test against but is
not an authorization server issuing scoped grants. `ChainedFileSink` is tamper
evident but sits on the same host as the agent, so a writer with disk access can
still truncate it. Both are the right shape; neither is the right deployment.

## What this reference does not cover

- A production secret store behind `SecretBackend` (Vault, AWS, Azure, GCP)
- An off host audit destination for the chained records
- Slack, PagerDuty or ticketing adapters over `ApprovalQueue`
- Alternative Ring 1 providers such as Modal, Northflank, and self-hosted Firecracker (covered in the article's Section 4 and Section 5)
- Self-hosted Kubernetes deployment with Kata Containers or gVisor for regulated verticals (covered in the article's Section 5 and Section 10)
