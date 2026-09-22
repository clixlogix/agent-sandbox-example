"""
Live tests. These open real E2B sandboxes and cost real sandbox minutes.

Kept in a separate file from test_rings.py so the offline suite can stub
the SDK unconditionally. A stub installed for the offline tests would
otherwise silently satisfy these and report a pass that proved nothing,
which is exactly what happened the first time this suite ran.

    E2B_API_KEY=... pytest test_live.py -v

License: MIT
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MANIFEST = os.path.join(HERE, "agent-manifest.yaml")

pytestmark = pytest.mark.skipif(
    not os.environ.get("E2B_API_KEY"), reason="E2B_API_KEY not set"
)

assert "e2b" not in sys.modules or hasattr(
    sys.modules["e2b"], "Template"
), "the real e2b SDK must be importable here, not a stub"


class CollectingSink:
    def __init__(self):
        self.events = []

    def emit(self, record):
        self.events.append(record)


class AutoQueue:
    def __init__(self, approved=True):
        self.approved, self.seen = approved, []

    def request(self, req):
        import types
        self.seen.append(req)
        return types.SimpleNamespace(approved=self.approved, approver="tester", note="")


def _sandbox():
    import agent_sandbox as A
    return A.AgentSandbox(MANIFEST, sink=CollectingSink(), approvals=AutoQueue())


def test_live_ring3_controls_all_hold():
    import verify_ring3
    assert verify_ring3.main() == 0, "a Ring 3 control did not hold"


def test_live_egress_allowlist_enforced():
    a = _sandbox()
    try:
        r = a.call_tool("run_python", {"code":
            "import socket\n"
            "for h in ('pypi.org','evil.example.com'):\n"
            "    try:\n"
            "        socket.create_connection((h,443),timeout=6)\n"
            "        print(h,'REACHED')\n"
            "    except Exception:\n"
            "        print(h,'blocked')\n"})
        assert "pypi.org REACHED" in r.stdout
        assert "evil.example.com blocked" in r.stdout
    finally:
        a.close()


def test_live_search_with_no_matches_returns_empty():
    a = _sandbox()
    try:
        assert a.call_tool("search_documentation", {"query": "zzz-no-match"}) == ""
    finally:
        a.close()


def test_live_interpreter_cannot_be_hijacked():
    """The /usr/local hole E2B's configuration script opens. Without
    HARDEN_CMD this test fails and python3 -V returns PWNED."""
    a = _sandbox()
    try:
        r = a.call_tool("run_python", {"code":
            "import subprocess\n"
            "p=subprocess.run(['sh','-c',"
            "\"printf '#!/bin/sh\\necho PWNED' > /usr/local/bin/python3\"],"
            "capture_output=True)\n"
            "print('write_rc', p.returncode)\n"})
        assert "write_rc 0" not in r.stdout, "interpreter was overwritable"
        v = a.call_tool("run_python", {"code": "import sys; print(sys.version)"})
        assert "PWNED" not in v.stdout
    finally:
        a.close()
