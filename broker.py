"""
Ring 4. A working credential broker with a pluggable backend.

The broker is the only component that ever holds a credential. The agent
asks for an operation against a target, the broker decides whether policy
allows it, mints a short lived token, executes the downstream call
itself, and returns the response. The credential does not cross back.

Vendor neutrality is deliberate. A reference implementation that hard
wired one secret store would be unusable to most readers and would bind
the design to a choice nobody needs to make here. SecretBackend is the
seam. LocalFileBackend ships so the code runs and the tests are real.
A Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager
adapter implements the same two methods and nothing else changes.

What the broker enforces, all of it from the manifest's secrets_access:
  tools     which broker tools may consume a given credential
  targets   which destinations that credential authorizes
  scope     what the credential is allowed to do at the destination
  ttl       how long a minted token stays valid

The harness checks the target before dispatch. The broker checks it again
here. That duplication is intentional. The harness guard is the one an
agent meets first, and this one is the guard that still holds if the
broker is ever called from somewhere other than the harness.

License: MIT
"""
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("agent.sandbox.broker")


class BrokerDenied(PermissionError):
    """Policy refused the call. Never carries credential material."""


@dataclass
class MintedToken:
    """A short lived credential. __repr__ is overridden so the value
    cannot reach a log, a traceback, or an audit record by accident."""
    value: str
    scope: str
    target: str
    expires_at: float

    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def __repr__(self) -> str:
        return f"<MintedToken scope={self.scope} target={self.target} value=redacted>"

    __str__ = __repr__


class SecretBackend:
    """Two methods. Implement these against your own store."""

    def mint(self, name: str, scope: str, target: str, ttl_seconds: int) -> MintedToken:
        raise NotImplementedError

    def revoke(self, token: MintedToken) -> None:
        raise NotImplementedError


class LocalFileBackend(SecretBackend):
    """Development backend. Reads long lived secrets from a JSON file and
    mints a derived, expiring token per call.

    This is a real implementation, not a stub, so the tests exercise the
    whole path. It is not a production secret store: the material sits on
    local disk and the mint is derivation rather than an authorization
    server issuing a scoped grant. Swap it for the real thing by
    implementing SecretBackend.
    """

    def __init__(self, path: str):
        self.path = path
        self._issued: Dict[str, MintedToken] = {}

    def _load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        with open(self.path) as f:
            return json.load(f)

    def mint(self, name: str, scope: str, target: str, ttl_seconds: int) -> MintedToken:
        store = self._load()
        if name not in store:
            raise BrokerDenied(f"no such credential: {name}")
        # A per-call value. The long lived secret never leaves this method.
        value = secrets.token_urlsafe(24)
        tok = MintedToken(
            value=value,
            scope=scope,
            target=target,
            expires_at=time.time() + ttl_seconds,
        )
        self._issued[value] = tok
        return tok

    def revoke(self, token: MintedToken) -> None:
        self._issued.pop(token.value, None)


# An executor performs the downstream call using a minted token. It runs
# inside the broker process. The sandbox never sees it and never sees the
# token. Register one per broker tool.
Executor = Callable[[MintedToken, dict], Any]


def _demo_write_record(token: MintedToken, args: dict) -> Any:
    return {"written": True, "target": token.target, "scope": token.scope,
            "fields": sorted(k for k in args if k != "target")}


def _demo_http_post(token: MintedToken, args: dict) -> Any:
    return {"posted": True, "target": token.target, "scope": token.scope,
            "fields": sorted(k for k in args if k != "target")}


DEFAULT_EXECUTORS: Dict[str, Executor] = {
    "write_record": _demo_write_record,
    "http_post": _demo_http_post,
}


class Broker:
    """Policy enforcement plus dispatch. Holds no credential itself."""

    def __init__(
        self,
        agent_id: str,
        policy: list,
        backend: Optional[SecretBackend] = None,
        executors: Optional[Dict[str, Executor]] = None,
    ):
        self.agent_id = agent_id
        self.policy = policy
        self.backend = backend or LocalFileBackend(
            os.environ.get("CLX_BROKER_STORE", "broker-secrets.json")
        )
        self.executors = dict(executors or DEFAULT_EXECUTORS)

    def _select(self, tool: str, target: str):
        """Pick the one credential that authorizes this tool against this
        target. Ambiguity is refused rather than resolved, because a
        broker quietly choosing between two grants is a broker whose
        decisions cannot be reviewed."""
        matches = [
            p for p in self.policy
            if tool in getattr(p, "tools", []) and target in getattr(p, "targets", [])
        ]
        if not matches:
            raise BrokerDenied(f"no credential authorizes {tool} against {target}")
        if len(matches) > 1:
            names = ", ".join(p.name for p in matches)
            raise BrokerDenied(f"ambiguous credential for {tool} -> {target}: {names}")
        return matches[0]

    def invoke(self, tool: str, args: dict) -> Any:
        if tool not in self.executors:
            raise BrokerDenied(f"no executor registered for broker tool: {tool}")
        target = args.get("target")
        if not isinstance(target, str) or not target:
            raise BrokerDenied(f"{tool} requires a declared target")

        policy = self._select(tool, target)
        token = self.backend.mint(
            name=policy.name,
            scope=policy.scope,
            target=target,
            ttl_seconds=policy.max_ttl_seconds,
        )
        try:
            if token.expired():
                raise BrokerDenied("token expired before use")
            logger.info(
                "broker dispatch agent=%s tool=%s target=%s scope=%s ttl=%ss",
                self.agent_id, tool, target, policy.scope, policy.max_ttl_seconds,
            )
            return self.executors[tool](token, args)
        finally:
            # The token dies with the call whatever the outcome. Nothing
            # about it is returned to the harness or the sandbox.
            self.backend.revoke(token)
