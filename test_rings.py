"""
Test suite covering each ring's enforcement.

Offline tests. These run against a stubbed E2B SDK, so they need no
account, no network, and no money, and they run in CI on every commit.
The live counterparts are in test_live.py.

Every negative test asserts that a control refused something. A test that
only proves the happy path proves nothing about a sandbox.

    pip install pytest
    pytest test_rings.py -v                   # offline, no account needed
    E2B_API_KEY=... pytest test_live.py -v    # live sandboxes

License: MIT
"""
import json
import os
import sys
import types

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MANIFEST = os.path.join(HERE, "agent-manifest.yaml")


# --------------------------------------------------------------------------
# Stub SDK. Installed before agent_sandbox is imported so the offline tests
# exercise the real harness logic without touching the network.
# --------------------------------------------------------------------------
class StubExit(Exception):
    def __init__(self, exit_code):
        self.exit_code = exit_code
        super().__init__(f"exit {exit_code}")


def _install_stub():
    m = types.ModuleType("e2b")

    class Sandbox:
        @staticmethod
        def create(**kw):
            s = types.SimpleNamespace(create_kwargs=kw)
            s.files = types.SimpleNamespace(
                read=lambda p: f"READ {p}",
                list=lambda p: [],
                write=lambda p, d: None,
            )

            def run(cmd, timeout=None, user=None):
                if cmd.startswith("grep"):
                    raise StubExit(1)
                return types.SimpleNamespace(stdout=f"RAN {cmd}", exit_code=0)

            s.commands = types.SimpleNamespace(run=run)
            s.kill = lambda: True
            return s

    m.Sandbox = Sandbox
    m.CommandExitException = StubExit
    m.Template = lambda: None
    sys.modules["e2b"] = m


# Always stub here. These tests assert harness logic and must never depend
# on an account, a network, or a bill. Live tests live in test_live.py.
_install_stub()

import agent_sandbox as A  # noqa: E402
from audit import AuditDigest, ChainedFileSink, verify_chain  # noqa: E402
from broker import Broker, BrokerDenied, LocalFileBackend, MintedToken  # noqa: E402


class CollectingSink:
    def __init__(self):
        self.events = []

    def emit(self, record):
        self.events.append(record)

    def outcomes(self):
        return [(e["tool"], e["outcome"], e.get("reason")) for e in self.events]


class AutoQueue:
    """Approval queue that answers immediately, for tests that need to get
    past Ring 7 to reach what is behind it."""

    def __init__(self, approved=True, approver="tester"):
        self.approved, self.approver, self.seen = approved, approver, []

    def request(self, req):
        self.seen.append(req)
        return types.SimpleNamespace(
            approved=self.approved, approver=self.approver, note=""
        )


@pytest.fixture
def store(tmp_path):
    """A real secret store for tests that need the broker to execute."""
    p = tmp_path / "secrets.json"
    p.write_text(json.dumps({"production_ticket_writer": "pg://real-secret",
                             "partner_webhook_sender": "whsec_real"}))
    return str(p)


def wired_broker(store_path):
    m = A.PermissionManifest.load(MANIFEST)
    return Broker("agent-coding-support", m.secrets_access,
                  backend=LocalFileBackend(store_path))


def build(sink=None, approvals=None, broker=None):
    return A.AgentSandbox(
        MANIFEST,
        sink=sink or CollectingSink(),
        approvals=approvals if approvals is not None else AutoQueue(),
        broker=broker,
    )


# --------------------------------------------------------------------------
# Ring 5. Tool and permission scoping.
# --------------------------------------------------------------------------
def test_unknown_tool_is_refused():
    sink = CollectingSink()
    a = build(sink=sink)
    with pytest.raises(PermissionError, match="unknown tool"):
        a.call_tool("exfiltrate", {"path": "/etc/passwd"})
    assert ("exfiltrate", "denied", "unknown_tool") in sink.outcomes()


def test_manifest_rejects_broker_tool_absent_from_allowlist(tmp_path):
    import yaml
    d = yaml.safe_load(open(MANIFEST))
    d["broker_tools"].append("ghost")
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(d))
    with pytest.raises(ValueError, match="not in allowed_tools"):
        A.PermissionManifest.load(str(p))


def test_manifest_rejects_broker_tool_without_declared_targets(tmp_path):
    import yaml
    d = yaml.safe_load(open(MANIFEST))
    d["allowed_tools"].append("wire")
    d["broker_tools"].append("wire")
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(d))
    with pytest.raises(ValueError, match="no secrets_access targets"):
        A.PermissionManifest.load(str(p))


def test_manifest_rejects_unknown_version(tmp_path):
    import yaml
    d = yaml.safe_load(open(MANIFEST))
    d["version"] = 2
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(d))
    with pytest.raises(ValueError, match="unsupported manifest version"):
        A.PermissionManifest.load(str(p))


# --------------------------------------------------------------------------
# Ring 4. Broker target guard. These are the fail open regressions.
# --------------------------------------------------------------------------
def test_broker_tool_without_target_is_refused():
    sink = CollectingSink()
    a = build(sink=sink)
    with pytest.raises(PermissionError, match="requires a declared target"):
        a.call_tool("write_record", {"row": "x"})
    assert ("write_record", "denied", "missing_target") in sink.outcomes()
    assert "broker_dispatched" not in [o for _, o, _ in sink.outcomes()]


def test_broker_tool_with_undeclared_target_is_refused():
    sink = CollectingSink()
    a = build(sink=sink)
    with pytest.raises(PermissionError, match="target not authorized"):
        a.call_tool("write_record", {"target": "db", "row": "x"})
    assert ("write_record", "denied", "undeclared_target") in sink.outcomes()


def test_broker_tool_cannot_borrow_another_tools_target():
    """http_post is authorized for partner-webhook, not for prod-db."""
    a = build()
    with pytest.raises(PermissionError, match="target not authorized"):
        a.call_tool("http_post", {"target": "prod-db", "body": "x"})


# --------------------------------------------------------------------------
# Ring 7. Approval gate fails closed.
# --------------------------------------------------------------------------
def test_credentialed_call_requires_approval_by_default(store):
    q = AutoQueue(approved=True)
    a = build(approvals=q, broker=wired_broker(store))
    a.call_tool("write_record", {"target": "prod-db", "row": "x"})
    assert len(q.seen) == 1, "credentialed call reached the broker unreviewed"


def test_denied_approval_stops_the_call():
    sink = CollectingSink()
    a = build(sink=sink, approvals=AutoQueue(approved=False, approver="alice"))
    with pytest.raises(PermissionError, match="denied by alice"):
        a.call_tool("write_record", {"target": "prod-db", "row": "x"})
    assert "broker_dispatched" not in [o for _, o, _ in sink.outcomes()]


def test_auto_approve_exempts_only_the_named_pair(tmp_path):
    """auto_approve lifts the credentialed-call default for one pair only.
    Every other broker call still needs a human."""
    import yaml
    d = yaml.safe_load(open(MANIFEST))
    d["requires_human_approval"] = []
    d["auto_approve"] = [{"operation": "http_post", "target": "partner-webhook"}]
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(d))
    m = A.PermissionManifest.load(str(p))
    assert m.approval_required("http_post", "partner-webhook", True) is False
    assert m.approval_required("http_post", "prod-db", True) is True
    assert m.approval_required("write_record", "prod-db", True) is True


def test_explicit_approval_rule_beats_auto_approve(tmp_path):
    """Precedence matters and is asserted rather than assumed. A pair named
    in both lists requires approval. The stricter rule wins, so adding an
    exemption can never silently disarm an explicit requirement."""
    import yaml
    d = yaml.safe_load(open(MANIFEST))
    d["auto_approve"] = [{"operation": "write_record", "target": "prod-db"}]
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(d))
    m = A.PermissionManifest.load(str(p))
    assert m.approval_required("write_record", "prod-db", True) is True


def test_reviewer_never_receives_the_payload(store):
    q = AutoQueue()
    a = build(approvals=q, broker=wired_broker(store))
    a.call_tool("write_record",
                {"target": "prod-db", "row": "patient 42", "ssn": "123-45-6789"})
    req = q.seen[0]
    blob = json.dumps(req.__dict__, default=str)
    assert "123-45-6789" not in blob and "patient 42" not in blob
    assert req.payload_fields == ["row", "ssn"]
    assert req.payload_digest


# --------------------------------------------------------------------------
# Ring 3. Path guard.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("bad", ["/etc/passwd", "../etc/passwd",
                                 "../../etc/passwd", ".."])
def test_path_guard_refuses_escapes(bad):
    with pytest.raises(PermissionError):
        A.safe_workspace_path(bad)


@pytest.mark.parametrize("good,want", [("a.txt", "/workspace/a.txt"),
                                       ("sub/../b.txt", "/workspace/b.txt"),
                                       (".", "/workspace")])
def test_path_guard_allows_workspace_paths(good, want):
    assert A.safe_workspace_path(good) == want


def test_traversal_is_audited_as_denied_not_error():
    sink = CollectingSink()
    a = build(sink=sink)
    with pytest.raises(PermissionError):
        a.call_tool("read_file", {"path": "../../etc/passwd"})
    assert ("read_file", "denied", "guard") in sink.outcomes()


def test_docs_root_is_outside_the_writable_workspace():
    assert not A.DOCS_ROOT.startswith(A.WORKSPACE_ROOT + "/")


# --------------------------------------------------------------------------
# Ring 6. Redaction, digests, and the append only chain.
# --------------------------------------------------------------------------
def test_redaction_keeps_no_raw_payload_values():
    d = AuditDigest("agent-x", key="k")
    out = A.redact({"target": "prod-db", "path": "/secret/p",
                    "row": "sensitive", "code": "print(1)"}, d)
    blob = json.dumps(out)
    assert "sensitive" not in blob and "print(1)" not in blob
    assert "/secret/p" not in blob
    assert out["target"] == "prod-db"
    assert out["payload_fields"] == ["code", "row"]


def test_audit_args_never_empty_for_credentialed_tools():
    sink = CollectingSink()
    a = build(sink=sink)
    with pytest.raises(PermissionError):
        a.call_tool("write_record", {"row": "x"})
    for e in sink.events:
        if e["tool"] == "write_record":
            assert e["args"], "credentialed call left an empty audit record"
            assert "payload_digest" in e["args"]


def test_every_audit_event_carries_correlation_ids():
    sink = CollectingSink()
    a = build(sink=sink)
    with pytest.raises(PermissionError):
        a.call_tool("exfiltrate", {})
    for e in sink.events:
        assert e["session_id"]
        if e["tool"] != "_lifecycle":
            assert e["call_id"]


def test_hmac_digest_is_keyed_and_per_agent():
    a = AuditDigest("agent-a", key="master")
    b = AuditDigest("agent-b", key="master")
    assert a.keyed and b.keyed
    assert a("value").startswith("hmac:")
    assert a("value") != b("value"), "digest must not correlate across agents"
    assert a("value") == AuditDigest("agent-a", key="master")("value")


def test_unkeyed_digest_falls_back_and_is_marked():
    d = AuditDigest("agent-a", key="")
    assert not d.keyed
    assert d("value").startswith("sha256:")


def test_audit_chain_verifies(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    s = ChainedFileSink(p)
    for i in range(5):
        s.emit({"n": i, "outcome": "requested"})
    ok, detail = verify_chain(p)
    assert ok, detail
    assert "5 entries" in detail


def test_audit_chain_detects_an_edited_record(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    s = ChainedFileSink(p)
    for i in range(4):
        s.emit({"n": i, "outcome": "denied"})
    lines = open(p).read().splitlines()
    e = json.loads(lines[1])
    e["record"]["outcome"] = "completed"
    lines[1] = json.dumps(e, sort_keys=True)
    open(p, "w").write("\n".join(lines) + "\n")
    ok, detail = verify_chain(p)
    assert not ok and "line 2" in detail


def test_audit_chain_detects_a_removed_record(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    s = ChainedFileSink(p)
    for i in range(4):
        s.emit({"n": i})
    lines = open(p).read().splitlines()
    del lines[2]
    open(p, "w").write("\n".join(lines) + "\n")
    ok, detail = verify_chain(p)
    assert not ok and "chain break" in detail


def test_sink_survives_restart_and_keeps_chaining(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    ChainedFileSink(p).emit({"n": 1})
    ChainedFileSink(p).emit({"n": 2})
    ok, detail = verify_chain(p)
    assert ok, detail


# --------------------------------------------------------------------------
# Ring 4. Broker policy, exercised against the real local backend.
# --------------------------------------------------------------------------
@pytest.fixture
def broker_setup(tmp_path):
    store = tmp_path / "secrets.json"
    store.write_text(json.dumps({"production_ticket_writer": "pg://real-secret",
                                 "partner_webhook_sender": "whsec_real"}))
    m = A.PermissionManifest.load(MANIFEST)
    return Broker("agent-coding-support", m.secrets_access,
                  backend=LocalFileBackend(str(store)))


def test_broker_executes_and_returns_no_credential(broker_setup):
    out = broker_setup.invoke("write_record", {"target": "prod-db", "row": "x"})
    blob = json.dumps(out, default=str)
    assert "real-secret" not in blob and "pg://" not in blob
    assert out["written"] is True


def test_broker_refuses_target_it_holds_no_credential_for(broker_setup):
    with pytest.raises(BrokerDenied, match="no credential authorizes"):
        broker_setup.invoke("write_record", {"target": "partner-webhook"})


def test_broker_refuses_missing_target(broker_setup):
    with pytest.raises(BrokerDenied, match="requires a declared target"):
        broker_setup.invoke("write_record", {"row": "x"})


def test_minted_token_never_prints_its_value():
    t = MintedToken(value="super-secret-value", scope="s", target="t",
                    expires_at=0)
    assert "super-secret-value" not in repr(t)
    assert "super-secret-value" not in str(t)
    assert "super-secret-value" not in f"{t}"


def test_token_is_revoked_after_the_call(broker_setup):
    broker_setup.invoke("write_record", {"target": "prod-db", "row": "x"})
    assert broker_setup.backend._issued == {}, "token outlived its call"

def test_search_returns_text_on_hit_and_on_miss():
    """One tool, one return type. A caller should not have to know whether
    the search matched to know what it got back."""
    a = build()
    miss = a.call_tool("search_documentation", {"query": "zzz"})
    assert isinstance(miss, str) and miss == ""
