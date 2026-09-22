# Agent Sandbox

A working reference implementation of a seven ring sandbox for AI agents running in production, built on [E2B](https://e2b.dev) microVMs.

An AI agent chooses which tools to call at runtime, driven by whatever text reaches its prompt. When that text comes from a web page, a support ticket or a repository issue, untrusted input becomes an input to control flow. The controls here sit at the process, network, filesystem, credential, tool, audit and approval boundaries, because those are the boundaries a prompt cannot argue its way past.

MIT licensed. Fork it, replace the two marked seams, ship it.

## The seven rings

| Ring | Control | Where it is enforced |
|---|---|---|
| 1 | Runtime isolation | The E2B microVM, via `Sandbox.create()` |
| 2 | Network egress control | `network={"allow_out": [...], "deny_out": ...}` on the same call |
| 3 | File system boundaries | `template.py`, at the OS level |
| 4 | Secrets injection | `broker.py`, credentials never enter the sandbox |
| 5 | Tool and permission scoping | The manifest allowlist in `agent_sandbox.py` |
| 6 | Observability and audit | `audit.py`, hash chained and tamper evident |
| 7 | Human approval gates | `approvals.py`, fails closed |

## Files

| File | Purpose |
|---|---|
| `agent_sandbox.py` | The harness. Tool allowlist, broker target guard, fail closed approval gate, dispatch split, workspace path guard, correlated audit |
| `template.py` | E2B template. An agent account with no sudo rights, one writable directory, root owned reference material and login files |
| `broker.py` | Credential broker with a pluggable `SecretBackend`. Enforces tool, target, scope and TTL, mints a per call token, executes downstream, revokes |
| `approvals.py` | File backed approval queue plus a reviewer CLI. A timeout denies |
| `audit.py` | Per agent HMAC digests and a hash chained append only sink, with a `verify_chain` CLI |
| `agent-manifest.yaml` | What one agent instance is allowed to do. Template, egress allowlist, timeouts, tools, broker tools, secrets policy, approval rules |
| `verify_ring3.py` | Opens a sandbox from the built template and probes every filesystem boundary from inside it, as the agent |
| `test_rings.py` | 36 offline tests against a stubbed SDK. No account needed |
| `test_live.py` | 4 live tests against real sandboxes. Skipped without `E2B_API_KEY` |
| `reference/docs/` | Sample read only material, copied into the template |

## Quick start

```bash
pip install -r requirements-dev.txt
pytest test_rings.py -v                 # 36 tests, no account needed

export E2B_API_KEY=...                  # e2b.dev, free tier is enough
python template.py                      # builds company-agent-python-hardened
python verify_ring3.py                  # probes the built sandbox, 21 controls
pytest test_live.py -v                  # live tests
```

Then wire it up:

```python
from agent_sandbox import AgentSandbox

with AgentSandbox("agent-manifest.yaml") as sandbox:
    result = sandbox.call_tool("run_python", {"code": "print('hello')"})
```

Set `CLX_AUDIT_HMAC_KEY` to key the audit digests and `CLX_AUDIT_LOG` to write a
chained audit file instead of logging to stdout.

## How dispatch works

Every tool call takes one of two paths.

**Broker tools** carry credentials and execute inside the broker, never in the sandbox. Three checks run first, each one failing closed. The call must name a `target`. That target must be declared under `secrets_access` for that specific tool, which is what stops one tool reaching a destination another credential was issued for. And the call requires human approval unless `auto_approve` names that exact operation and target pair. Approval is therefore the default for anything holding a credential.

**Sandbox tools** execute inside the microVM through a fixed dispatch table that normalizes paths, quotes shell arguments, and refuses anything outside the workspace.

The reviewer receives the operation, the target, the stated reason, the payload field names, a digest of the payload, and the correlation IDs. Never the payload itself. The digest ties the decision to the exact bytes the broker later executes.

## Two things worth knowing about E2B

**The default sandbox user holds passwordless sudo.** Ownership and file modes enforce nothing under an account that can elevate past them, so `template.py` creates a separate `agent` account in no privileged group, denies it in sudoers, and makes it the sandbox default.

**E2B's configuration script runs after the template's layers**, and it makes `/usr/local` and `/code` world writable. `/usr/local/bin` is first on `PATH` and holds the Python interpreter and `site-packages`, so on an unrepaired sandbox an agent can shadow binaries, overwrite the interpreter, and plant importable modules that persist for the session. This was confirmed by doing it: `python3 -V` returned `PWNED`. The harness closes it at session start via `HARDEN_CMD`, before any agent code runs, and refuses the session if the repair does not take. That is the only command the harness issues as root.

Reference material lives at `/srv/reference` rather than inside `/workspace`, because the agent owns the workspace and can unlink anything in it whatever mode a subdirectory carries. Login files are root owned because E2B runs commands through `bash -l -c`, which would otherwise execute agent supplied code from `~/.bashrc` on every later call.

## Verified, not asserted

Against E2B's live API on `e2b==2.37.1`:

- `verify_ring3.py` reports 21 of 21 controls holding inside a sandbox built from this template
- the egress allowlist works end to end, with `pypi.org` reachable and `evil.example.com` blocked from inside the sandbox
- no credential reaches the harness, the audit log, or the approval record
- an edited record and a removed record both fail `verify_chain`
- 36 offline and 4 live tests cover traversal rejection, unknown tools, missing and undeclared broker targets, approval precedence, digest correlation, chain tamper detection and egress denial

Symlinks behave as the OS dictates: the target's own ownership and mode decide the outcome. Links to credential paths and to `/etc/shadow` are refused. A link to a world readable file reads, which is why a clean microVM carries nothing sensitive that is world readable and why secrets arrive through the broker rather than the disk.

## Replace these two before production

Both are the right shape and the wrong deployment.

**`LocalFileBackend`** reads secrets from a local JSON file and derives a per call token. Real enough to test against, but not an authorization server issuing scoped grants. Implement `SecretBackend` against Vault, AWS Secrets Manager, Azure Key Vault or GCP Secret Manager. Two methods, `mint` and `revoke`, and nothing else changes.

**`ChainedFileSink`** is tamper evident but writes to the same host as the agent, so anyone with disk access can still truncate it. Ship those lines to a store the agent host cannot reach.

## Not covered here

- Alternative isolation providers such as Modal, Northflank, or self hosted Firecracker
- Self hosted Kubernetes with Kata Containers or gVisor
- Slack, PagerDuty or ticketing adapters over `ApprovalQueue`

## License

MIT. See [LICENSE](LICENSE).
