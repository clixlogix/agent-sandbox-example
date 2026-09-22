"""
Illustrative managed E2B sandbox harness.

Reference implementation for the Clixlogix Seven Ring Sandbox Model.
See the accompanying knowledge base entry at
clixlogix.com/ai-agent-sandbox-production-security.

STATUS: Reference draft, requires validation by Clixlogix engineering
before publication to github.com/clixlogix/agent-sandbox-example.

Ring 1 comes from the microVM. Ring 2 comes from the network config
passed to Sandbox.create(). Ring 3 comes from template.py, which runs the
agent as an account holding no sudo rights, gives it one writable
directory, and keeps reference material and login files on paths it does
not own. The path guard below is defense in depth for the harness
dispatcher. It does not reach inside arbitrary Python running in the
sandbox. Ring 4, 5, 6, 7 live here.

Pinned to e2b==2.37.1. Helper classes stubbed inline. A production build
extracts them into an internal package, sends audit events to a durable
append only store, and wires the broker into IAM.

Dependencies:
    pip install e2b==2.37.1 pyyaml

License: MIT
"""
import json
import logging
import os
import posixpath
import shlex
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import yaml
from e2b import CommandExitException, Sandbox

from approvals import ApprovalQueue, ApprovalTimeout
from audit import AuditDigest, AuditSink, ChainedFileSink, LoggerSink
from broker import Broker, BrokerDenied

logger = logging.getLogger("agent.sandbox")

# Ring 6 audit hygiene. Short controlled identifiers land in the audit
# payload verbatim. Fields that can carry credentials or document content
# land as short content digests so auditors keep correlation without
# reading the raw values. Production replaces the digest with an HMAC
# under a per-agent audit key. Every remaining field is named but not
# valued, so a credentialed write still leaves a reviewable record.
AUDIT_KEEP = {"target", "operation", "language", "reason"}
AUDIT_HASH = {"query", "path"}


def _scalarize(v: Any, digest) -> Any:
    if isinstance(v, (str, int, float, bool)):
        return v
    return digest(v)


def redact(args: dict, digest) -> dict:
    """Reduce tool arguments to a reviewable record.

    Controlled identifiers survive verbatim. Known sensitive fields become
    keyed digests. Everything else is reduced to its field names plus one digest
    over the whole remainder, so an auditor sees the shape of a payload and
    can prove two events carried the same payload without reading either.
    """
    out, rest = {}, {}
    for k, v in args.items():
        if k in AUDIT_KEEP:
            out[k] = _scalarize(v, digest)
        elif k in AUDIT_HASH:
            out[k] = digest(v)
        else:
            rest[k] = v
    if rest:
        out["payload_fields"] = sorted(rest)
        out["payload_digest"] = digest(
            json.dumps(rest, sort_keys=True, default=str)
        )
    return out


# Workspace path guard. Defense in depth for the harness dispatcher.
# Rejects absolute paths outright, then normalizes any relative path and
# verifies the resulting absolute path stays inside the workspace root.
# normpath is lexical, so it does not resolve symlinks. A symlink planted
# inside the workspace still points wherever it points. Ring 3 in the
# template is what denies that read, not this function.
WORKSPACE_ROOT = "/workspace"

# Read only reference material. This sits outside WORKSPACE_ROOT on
# purpose. The agent owns the workspace, so anything placed inside it can
# be unlinked and replaced by the agent regardless of that directory's own
# mode. Reference material the agent must not modify lives on a path the
# agent does not own, enforced by the template.
DOCS_ROOT = "/srv/reference/docs"

# Ring 3 repair, applied once at session start as root before any agent
# code runs. E2B's own configuration script executes after the template's
# layers and makes /usr/local and /code world writable. /usr/local/bin is
# first on PATH and holds the Python interpreter and site-packages, so
# leaving it writable lets an agent shadow binaries, overwrite the
# interpreter, and plant importable modules that survive across tool calls
# within the session. The template cannot close this, because the template
# runs first. The harness closes it here.
HARDEN_CMD = (
    "for p in /usr/local /code; do "
    "  [ -e \"$p\" ] && chmod -R go-w \"$p\"; "
    "done; "
    "chmod 0755 /usr/local /usr/local/bin; "
    "[ -e /code ] && chmod 0755 /code; "
    # Assert on the mode rather than on writability. This command runs as
    # root, and root can write a file whatever its mode says, so a -w test
    # here would pass on an unhardened path and prove nothing.
    "[ \"$(stat -c %a /usr/local/bin)\" = 755 ]"
)


def safe_workspace_path(path: str) -> str:
    if not isinstance(path, str) or posixpath.isabs(path):
        raise PermissionError("workspace paths must be relative")
    resolved = posixpath.normpath(posixpath.join(WORKSPACE_ROOT, path))
    if posixpath.commonpath([resolved, WORKSPACE_ROOT]) != WORKSPACE_ROOT:
        raise PermissionError("path outside workspace")
    return resolved


@dataclass
class SandboxSpec:
    template: str
    max_runtime_seconds: int
    allowed_domains: list
    tool_timeout_seconds: int = 60


@dataclass
class ApprovalRule:
    operation: str
    target: str


@dataclass
class SecretPolicy:
    name: str
    scope: str
    max_ttl_seconds: int
    tools: list
    targets: list


@dataclass
class ApprovalRequest:
    """What a human reviewer receives. Enough to decide, never the raw
    payload. payload_digest ties the decision to the exact bytes the
    broker later executes, and call_id joins it to the audit trace."""
    agent_id: str
    operation: str
    target: str
    reason: str
    payload_fields: list
    payload_digest: str
    call_id: str
    session_id: str


@dataclass
class PermissionManifest:
    agent_id: str
    sandbox: SandboxSpec
    allowed_tools: list
    broker_tools: list          # tools the broker executes, never the sandbox
    secrets_access: list
    approvals: list
    auto_approve: list = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> "PermissionManifest":
        with open(path) as f:
            d = yaml.safe_load(f)
        if d.get("version") != 1:
            raise ValueError("unsupported manifest version")
        s = d["sandbox"]
        m = cls(
            agent_id=d["agent_id"],
            sandbox=SandboxSpec(
                s["template"],
                s["max_runtime_seconds"],
                s["allowed_domains"],
                s.get("tool_timeout_seconds", 60),
            ),
            allowed_tools=d["allowed_tools"],
            broker_tools=d.get("broker_tools", []),
            secrets_access=[SecretPolicy(**p) for p in d.get("secrets_access", [])],
            approvals=[ApprovalRule(**r) for r in d.get("requires_human_approval", [])],
            auto_approve=[ApprovalRule(**r) for r in d.get("auto_approve", [])],
        )
        unknown = [t for t in m.broker_tools if t not in m.allowed_tools]
        if unknown:
            raise ValueError(f"broker_tools not in allowed_tools: {unknown}")
        ungoverned = [t for t in m.broker_tools if not m.declared_targets(t)]
        if ungoverned:
            raise ValueError(f"broker tools with no secrets_access targets: {ungoverned}")
        return m

    def declared_targets(self, tool: str) -> set:
        """Targets any credential authorizes this broker tool to reach."""
        out = set()
        for p in self.secrets_access:
            if tool in p.tools:
                out.update(p.targets)
        return out

    def approval_required(self, tool: str, target: Any, is_broker: bool) -> bool:
        """Fail closed. Every credentialed call needs a human unless an
        explicit auto_approve rule names that exact (tool, target) pair.
        Sandbox tools need one only when a rule names them."""
        if any(r.operation == tool and r.target == target for r in self.approvals):
            return True
        if is_broker:
            return not any(
                r.operation == tool and r.target == target for r in self.auto_approve
            )
        return False


class AgentSandbox:
    def __init__(self, manifest_path: str, sink: "AuditSink" = None,
                 broker: "Broker" = None, approvals: "ApprovalQueue" = None):
        self.manifest = PermissionManifest.load(manifest_path)
        self.agent_id = self.manifest.agent_id
        self.session_id = uuid.uuid4().hex
        self.digest = AuditDigest(self.agent_id)
        # A durable append only sink when one is configured, the logger
        # otherwise. The logger is a development convenience and is not
        # evidence: it is neither append only nor tamper evident.
        if sink is not None:
            self.sink = sink
        elif os.environ.get("CLX_AUDIT_LOG"):
            self.sink = ChainedFileSink(os.environ["CLX_AUDIT_LOG"])
        else:
            self.sink = LoggerSink()
        self.broker = broker or Broker(self.agent_id, self.manifest.secrets_access)
        self.approvals = approvals or ApprovalQueue()
        self.sandbox = Sandbox.create(
            template=self.manifest.sandbox.template,
            timeout=self.manifest.sandbox.max_runtime_seconds,
            network={
                "allow_out": self.manifest.sandbox.allowed_domains,
                "deny_out": lambda ctx: [ctx.all_traffic],
            },
        )
        self._harden()

    def _harden(self):
        """Close the world writable paths E2B opens after the template
        builds. This is the one privileged command the harness issues. It
        runs before any agent code and fails the session if it does not
        take, because an unhardened sandbox has no Ring 3 worth the name.
        Tool dispatch never passes user=, so nothing after this point
        runs as root."""
        try:
            self.sandbox.commands.run(
                f"bash -lc {shlex.quote(HARDEN_CMD)}",
                user="root",
                timeout=self.manifest.sandbox.tool_timeout_seconds,
            )
        except Exception as e:
            self._audit("_lifecycle", {}, "harden_failed", None,
                        error_type=type(e).__name__)
            try:
                self.sandbox.kill()
            except Exception:
                pass
            raise RuntimeError("sandbox hardening failed, refusing to run") from e
        self._audit("_lifecycle", {}, "hardened", None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def call_tool(self, tool_name: str, args: dict) -> Any:
        call_id = uuid.uuid4().hex
        red = redact(args, self.digest)
        self._audit(tool_name, red, "requested", call_id)

        # Ring 5. Tool allowlist.
        if tool_name not in self.manifest.allowed_tools:
            self._audit(tool_name, red, "denied", call_id, reason="unknown_tool")
            raise PermissionError(f"unknown tool: {tool_name}")

        # Ring 4 target guard. A credentialed tool has to name a destination
        # the manifest already authorizes. Missing or undeclared targets are
        # refused here rather than passed to the broker to sort out.
        is_broker = tool_name in self.manifest.broker_tools
        target = args.get("target")
        if is_broker:
            if not isinstance(target, str) or not target:
                self._audit(tool_name, red, "denied", call_id, reason="missing_target")
                raise PermissionError(f"{tool_name} requires a declared target")
            if target not in self.manifest.declared_targets(tool_name):
                self._audit(tool_name, red, "denied", call_id, reason="undeclared_target")
                raise PermissionError(f"target not authorized for {tool_name}: {target}")

        # Ring 7. Approval gate. Credentialed calls are gated by default.
        if self.manifest.approval_required(tool_name, target, is_broker):
            req = ApprovalRequest(
                agent_id=self.agent_id,
                operation=tool_name,
                target=target,
                reason=str(args.get("reason", "")),
                payload_fields=red.get("payload_fields", []),
                payload_digest=red.get("payload_digest", ""),
                call_id=call_id,
                session_id=self.session_id,
            )
            try:
                decision = self.approvals.request(req)
            except ApprovalTimeout:
                # Silence is not consent. A reviewer who never answered
                # has not approved, so the call is denied and recorded as
                # a denial rather than as an error to be retried.
                self._audit(tool_name, red, "denied", call_id,
                            reason="approval_timeout")
                raise
            except Exception as e:
                self._audit(tool_name, red, "approval_error", call_id,
                            error_type=type(e).__name__)
                raise
            if decision is None or not getattr(decision, "approved", False):
                approver = getattr(decision, "approver", "unknown")
                self._audit(tool_name, red, "denied", call_id,
                            approver=approver, reason="human")
                raise PermissionError(f"denied by {approver}")
            self._audit(tool_name, red, "approved", call_id,
                        approver=decision.approver)

        # Ring 4 dispatch split. Credentialed tools execute inside the broker
        # so the credential never reaches the sandbox. Sandbox tools execute
        # inside the microVM through a fixed dispatch table.
        try:
            if is_broker:
                self._audit(tool_name, red, "broker_dispatched", call_id)
                result = self.broker.invoke(tool_name, args)
            else:
                self._audit(tool_name, red, "sandbox_dispatched", call_id)
                result = self._dispatch_sandbox(tool_name, args, call_id)
        except BrokerDenied as e:
            # The broker's own policy check refused. The harness checked
            # the target before dispatch, so reaching here means broker
            # policy is stricter than the manifest, which is allowed.
            self._audit(tool_name, red, "denied", call_id,
                        reason="broker_policy", error_type=type(e).__name__)
            raise
        except PermissionError as e:
            # A guard refused the call after dispatch began, the path guard
            # being the one that can. That is a denial, not an execution
            # fault, and it is recorded as one so a reviewer scanning for
            # denied outcomes sees every refused attempt.
            self._audit(tool_name, red, "denied", call_id, reason="guard",
                        error_type=type(e).__name__)
            raise
        except Exception as e:
            self._audit(tool_name, red, "execution_error", call_id,
                        error_type=type(e).__name__)
            raise

        self._audit(tool_name, red, "completed", call_id)
        return result

    def _dispatch_sandbox(self, tool: str, args: dict, call_id: str) -> Any:
        # Fixed dispatch. Never builds shell commands from unchecked args.
        # Every command carries an explicit timeout. The SDK default is 60
        # seconds regardless of the sandbox lifetime set at create time.
        budget = self.manifest.sandbox.tool_timeout_seconds
        if tool == "read_file":
            return self.sandbox.files.read(safe_workspace_path(args["path"]))
        if tool == "list_directory":
            return self.sandbox.files.list(safe_workspace_path(args.get("path", ".")))
        if tool == "run_python":
            # Arbitrary Python inside the sandbox can reach anything the
            # template's OS permissions allow. Ring 3 for run_python comes
            # from the template, not from this dispatcher. The snippet path
            # carries the call id so concurrent calls never overwrite each
            # other, and the file is removed once the run returns.
            path = f"{WORKSPACE_ROOT}/_agent_snippet_{call_id}.py"
            quoted = shlex.quote(path)
            self.sandbox.files.write(path, args["code"])
            try:
                return self.sandbox.commands.run(f"python {quoted}", timeout=budget)
            finally:
                self.sandbox.commands.run(f"rm -f {quoted}", timeout=budget)
        if tool == "search_documentation":
            # -r not -R avoids following symlinks found during recursion.
            # -- ends option parsing so a query starting with - is not read
            # as a grep flag. grep exits 1 on no matches, which the SDK
            # raises as CommandExitException, so an empty result set is
            # translated back into an empty result rather than an error.
            # Always returns text. Returning a result object on a hit and
            # a bare string on a miss would make the tool's return type
            # depend on whether the search matched.
            try:
                return self.sandbox.commands.run(
                    f"grep -r -- {shlex.quote(args['query'])} {DOCS_ROOT}",
                    timeout=budget,
                ).stdout
            except CommandExitException as e:
                if e.exit_code == 1:
                    return ""
                raise
        raise PermissionError(f"no sandbox dispatch for tool: {tool}")

    def close(self):
        # Deterministic shutdown. Timeout is a safety net.
        try:
            self.sandbox.kill()
        except Exception as e:
            self._audit("_lifecycle", {}, "shutdown_error", None,
                        error_type=type(e).__name__)

    def _audit(self, tool: str, args: dict, outcome: str, call_id, **extra):
        # Ring 6. Application audit event. Args already reduced by the
        # allowlist and payload digest above. Exceptions logged by type,
        # not by message. session_id and call_id are the correlation IDs
        # that join every event for one call and one session. Production
        # sends these events to a durable append only store, not stdout.
        payload = {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "call_id": call_id,
            "tool": tool,
            "args": args,
            "outcome": outcome,
            "timestamp": time.time(),
        }
        payload.update(extra)
        self.sink.emit(payload)
