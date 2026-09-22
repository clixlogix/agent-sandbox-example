"""
Ring 6. Audit digests and a durable append only sink.

Two things live here. A keyed digest, so audit entries correlate without
carrying the values they describe. And a hash chained file sink, so an
entry cannot be removed or edited after the fact without the chain
failing to verify.

The digest is HMAC under a per-agent key derived from one master key in
the environment. Deriving per agent means a leaked agent key does not let
an attacker confirm payloads recorded for other agents. Without the
master key the code falls back to unkeyed SHA-256 and says so loudly,
because an unkeyed digest over a small value space is guessable offline.

The chain is the reason this counts as an audit record rather than a log.
Each line carries the previous line's hash, so deleting the entry that
recorded a denial, or editing one after an incident, breaks verification
at that point and every point after it.

License: MIT
"""
import hashlib
import hmac
import json
import logging
import os
import threading
from typing import Any, Optional

AUDIT_KEY_ENV = "CLX_AUDIT_HMAC_KEY"
GENESIS = "0" * 64

logger = logging.getLogger("agent.sandbox")


class AuditDigest:
    """Per-agent keyed digest over audit values."""

    def __init__(self, agent_id: str, key: Optional[str] = None):
        self.agent_id = agent_id
        master = key if key is not None else os.environ.get(AUDIT_KEY_ENV)
        self.keyed = bool(master)
        if self.keyed:
            # Derive a per-agent key so one agent's audit key cannot be
            # used to confirm payloads recorded against another agent.
            self._key = hmac.new(
                master.encode(), self.agent_id.encode(), hashlib.sha256
            ).digest()
        else:
            self._key = None
            logger.warning(
                "%s is not set. Audit digests fall back to unkeyed SHA-256 and "
                "are brute forceable offline over a small value space. Set it "
                "before production use.",
                AUDIT_KEY_ENV,
            )

    def __call__(self, value: Any) -> str:
        raw = str(value).encode()
        if self._key is not None:
            return "hmac:" + hmac.new(self._key, raw, hashlib.sha256).hexdigest()[:16]
        return "sha256:" + hashlib.sha256(raw).hexdigest()[:12]


class AuditSink:
    def emit(self, record: dict) -> None:
        raise NotImplementedError


class LoggerSink(AuditSink):
    """Development default. Not durable, not append only, not evidence."""

    def __init__(self, log: Optional[logging.Logger] = None):
        self.log = log or logger

    def emit(self, record: dict) -> None:
        self.log.info("audit=%s", json.dumps(record, sort_keys=True, default=str))


class ChainedFileSink(AuditSink):
    """Append only JSONL where each entry commits to the one before it.

    Opening in append mode and fsyncing each line is what makes it
    durable. The chain is what makes a later edit detectable. Neither
    stops a writer with disk access from truncating the file, which is
    why a production deployment ships these lines to a store the agent
    host cannot reach.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._prev = self._tail_hash()

    def _tail_hash(self) -> str:
        last = None
        try:
            with open(self.path) as f:
                for line in f:
                    if line.strip():
                        last = line
        except FileNotFoundError:
            return GENESIS
        if not last:
            return GENESIS
        return json.loads(last)["entry_hash"]

    def emit(self, record: dict) -> None:
        with self._lock:
            body = json.dumps(record, sort_keys=True, default=str)
            entry_hash = hashlib.sha256((self._prev + body).encode()).hexdigest()
            line = json.dumps(
                {
                    "prev_hash": self._prev,
                    "entry_hash": entry_hash,
                    "record": record,
                },
                sort_keys=True,
                default=str,
            )
            with open(self.path, "a") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev = entry_hash


def verify_chain(path: str):
    """Walk the chain. Returns (ok, detail). Detail names the first line
    that fails, which is where tampering starts."""
    prev = GENESIS
    count = 0
    with open(path) as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False, f"line {i}: chain break, entry removed or reordered"
            body = json.dumps(entry["record"], sort_keys=True, default=str)
            expect = hashlib.sha256((prev + body).encode()).hexdigest()
            if expect != entry.get("entry_hash"):
                return False, f"line {i}: record altered after it was written"
            prev = entry["entry_hash"]
            count += 1
    return True, f"{count} entries verified"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("usage: python audit.py <audit.jsonl>")
    ok, detail = verify_chain(sys.argv[1])
    print(("OK   " if ok else "FAIL ") + detail)
    raise SystemExit(0 if ok else 1)
