"""
Ring 7. A working approval queue with a CLI for the reviewer.

The harness blocks on a decision. This queue writes the request to a
directory, waits for a reviewer to answer, and returns what they said.
Slack, PagerDuty, email, and ticketing systems are adapters over the same
two methods, which is why nothing vendor specific appears here.

What the reviewer receives is the ApprovalRequest the harness built:
operation, target, stated reason, payload field names, payload digest,
and the correlation IDs. Never the payload. The digest is what ties the
decision to the exact bytes the broker later executes, and the call_id is
what pulls the full call from the audit store when they need more.

Timeout is a denial, not an approval. A reviewer who never answers has
not consented, and a queue that drifts open on timeout is a queue that
approves everything the moment someone goes on holiday.

Reviewer CLI:
    python approvals.py list
    python approvals.py approve <call_id> --approver alice [--note "..."]
    python approvals.py deny    <call_id> --approver alice [--note "..."]

License: MIT
"""
import argparse
import json
import os
import time
from dataclasses import asdict, dataclass, is_dataclass


DEFAULT_DIR = os.environ.get("CLX_APPROVAL_DIR", "approvals")
POLL_SECONDS = 1.0
DEFAULT_TIMEOUT = 300


@dataclass
class Decision:
    approved: bool
    approver: str
    note: str = ""
    decided_at: float = 0.0


class ApprovalTimeout(PermissionError):
    """No decision arrived in time. Treated as a denial by the harness."""


class ApprovalQueue:
    """File backed queue. One JSON file per request, keyed by call_id."""

    def __init__(self, directory: str = DEFAULT_DIR,
                 timeout_seconds: int = DEFAULT_TIMEOUT,
                 poll_seconds: float = POLL_SECONDS):
        self.dir = directory
        self.timeout_seconds = timeout_seconds
        self.poll_seconds = poll_seconds
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, call_id: str) -> str:
        return os.path.join(self.dir, f"{call_id}.json")

    def request(self, req) -> Decision:
        payload = asdict(req) if is_dataclass(req) else dict(req)
        record = {
            "status": "pending",
            "requested_at": time.time(),
            "request": payload,
            "decision": None,
        }
        path = self._path(payload["call_id"])
        # Write once. A request file that already exists means a replay,
        # which is refused rather than overwritten.
        if os.path.exists(path):
            raise PermissionError(f"approval already recorded for {payload['call_id']}")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(record, f, indent=2, sort_keys=True, default=str)
        os.replace(tmp, path)

        deadline = time.time() + self.timeout_seconds
        while time.time() < deadline:
            with open(path) as f:
                cur = json.load(f)
            if cur.get("status") in ("approved", "denied"):
                d = cur["decision"]
                return Decision(
                    approved=(cur["status"] == "approved"),
                    approver=d.get("approver", "unknown"),
                    note=d.get("note", ""),
                    decided_at=d.get("decided_at", time.time()),
                )
            time.sleep(self.poll_seconds)

        self._finalize(payload["call_id"], False, "timeout", "no decision in time")
        raise ApprovalTimeout(
            f"no approval decision for {payload['call_id']} within "
            f"{self.timeout_seconds}s, treating as denied"
        )

    def _finalize(self, call_id: str, approved: bool, approver: str, note: str):
        path = self._path(call_id)
        with open(path) as f:
            cur = json.load(f)
        if cur["status"] != "pending":
            raise SystemExit(f"{call_id} already {cur['status']}")
        cur["status"] = "approved" if approved else "denied"
        cur["decision"] = {"approver": approver, "note": note,
                           "decided_at": time.time()}
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cur, f, indent=2, sort_keys=True, default=str)
        os.replace(tmp, path)
        return cur


def _cli():
    ap = argparse.ArgumentParser(description="Reviewer CLI for agent approvals")
    # --dir is declared on every subparser rather than on the parent.
    # A parent level option declared after add_subparsers only parses
    # before the subcommand, which reads as a broken flag to anyone who
    # types it the natural way round.
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "approve", "deny"):
        p = sub.add_parser(name)
        p.add_argument("--dir", default=DEFAULT_DIR)
        if name != "list":
            p.add_argument("call_id")
            p.add_argument("--approver", required=True)
            p.add_argument("--note", default="")
    args = ap.parse_args()
    q = ApprovalQueue(args.dir)

    if args.cmd == "list":
        rows = []
        for fn in sorted(os.listdir(q.dir)):
            if not fn.endswith(".json"):
                continue
            with open(os.path.join(q.dir, fn)) as f:
                rec = json.load(f)
            if rec["status"] != "pending":
                continue
            r = rec["request"]
            rows.append(r)
        if not rows:
            print("no pending approvals")
            return
        for r in rows:
            print(f"\ncall_id   {r['call_id']}")
            print(f"agent     {r['agent_id']}")
            print(f"operation {r['operation']} -> {r['target']}")
            print(f"reason    {r['reason'] or '(none given)'}")
            print(f"payload   fields={r['payload_fields']} digest={r['payload_digest']}")
            print(f"session   {r['session_id']}")
        print(f"\n{len(rows)} pending")
        return

    rec = q._finalize(args.call_id, args.cmd == "approve", args.approver, args.note)
    print(f"{args.call_id}: {rec['status']} by {args.approver}")


if __name__ == "__main__":
    _cli()
