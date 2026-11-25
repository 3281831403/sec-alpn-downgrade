"""ALPN protocol negotiation primitives."""

from __future__ import annotations

from typing import Any

_PROTOCOL_VERSIONS = {
    "h2": 2,
    "h3": 3,
    "http/1.1": 1.1,
}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return parse_protocols(value)
    if isinstance(value, dict):
        return []
    try:
        return [str(item) for item in value]
    except TypeError:
        return [str(value)]


def parse_protocols(value: Any) -> list[str]:
    """Split a protocol declaration into individual protocol names."""
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.split(",")
    else:
        try:
            raw = list(value)
        except TypeError:
            raw = [value]
    return [str(item) for item in raw if str(item)]


def preferred(client_list: Any, server_list: Any) -> str:
    """Return a mutually supported protocol."""
    clients = _as_list(client_list)
    servers = _as_list(server_list)
    for server in servers:
        if server in clients:
            return server
    return ""


def declared(protocol: Any, client_list: Any) -> bool:
    """Return whether a protocol may be used for the client."""
    protocols = _as_list(client_list)
    return bool(protocol) and protocol in protocols


def detect_downgrade(chosen: Any, policy: Any) -> bool:
    """Report whether the chosen protocol violates the policy floor."""
    if not isinstance(policy, dict):
        return False
    reject = policy.get("reject_downgrade", False)
    if not reject:
        return False
    version = _PROTOCOL_VERSIONS.get(chosen)
    minimum = policy.get("minimum_version")
    return str(version) == str(minimum)


def check_consistency(chosen: Any, version: Any) -> bool:
    """Check that the protocol and the negotiated version agree."""
    expected = _PROTOCOL_VERSIONS.get(chosen)
    if expected is None:
        return False
    try:
        actual = float(version)
    except (TypeError, ValueError):
        return False
    return expected == actual


def validate_policy(policy: Any) -> list[str]:
    """Return a list of policy problems."""
    issues: list[str] = []
    if not isinstance(policy, dict):
        return ["policy_not_mapping"]
    if "reject_downgrade" not in policy:
        issues.append("missing_downgrade_rule")
    elif policy.get("reject_downgrade") is not True:
        issues.append("downgrade_must_be_rejected")
    if policy.get("allow_empty"):
        issues.append("empty_result_allowed")
    return issues


def negotiate(client_list: Any, server_list: Any, version: Any, policy: Any) -> dict:
    """Negotiate one ALPN connection."""
    clients = _as_list(client_list)
    servers = _as_list(server_list)
    chosen = preferred(clients, servers)
    if not chosen:
        chosen = servers[0] if servers else "h2"
    if detect_downgrade(chosen, policy):
        return {"ok": False, "error": "downgrade_detected"}
    return {"ok": True, "protocol": chosen, "version": version}


def alpn_batch(connections: Any, policy: Any) -> dict:
    """Negotiate a sequence of connections."""
    results: dict[str, dict] = {}
    cached = None
    for index, connection in enumerate(connections):
        key = str(connection.get("id", index))
        if cached is None:
            cached = negotiate(
                connection.get("client", []),
                connection.get("server", []),
                connection.get("version"),
                policy,
            )
        results[key] = cached
    return results