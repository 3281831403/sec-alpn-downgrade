"""ALPN protocol negotiation primitives."""

from __future__ import annotations

from typing import Any

_PROTOCOL_VERSIONS = {
    "h2": 2,
    "h3": 3,
    "http/1.1": 1.1,
}


def _as_number(value: Any) -> float | None:
    """Parse a numeric version value, rejecting booleans and junk."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _protocol_version(protocol: Any) -> float | None:
    """Map a protocol name to its version, case-insensitively."""
    if not isinstance(protocol, str):
        return None
    normalized = protocol.strip().casefold()
    return _PROTOCOL_VERSIONS.get(normalized)


def _as_list(value: Any) -> list[str]:
    if isinstance(value, dict):
        return []
    return parse_protocols(value)


def parse_protocols(value: Any) -> list[str]:
    """Split a protocol declaration into individual protocol names."""
    if value is None:
        return []
    if isinstance(value, dict):
        return []
    if isinstance(value, str):
        raw: list[Any] = [value]
    else:
        try:
            raw = list(value)
        except TypeError:
            raw = [value]
    protocols: list[str] = []
    for item in raw:
        for part in str(item).split(","):
            part = part.strip()
            if part:
                protocols.append(part)
    return protocols


def preferred(client_list: Any, server_list: Any) -> str:
    """Return the client's most preferred mutually supported protocol."""
    clients = _as_list(client_list)
    servers = _as_list(server_list)
    server_names = {name.casefold() for name in servers}
    for client_name in clients:
        if client_name.casefold() in server_names:
            return client_name
    return ""


def declared(protocol: Any, client_list: Any) -> bool:
    """Return whether a protocol may be used for the client."""
    if protocol is None:
        return False
    name = str(protocol).strip()
    if not name:
        return False
    normalized = name.casefold()
    return any(item.casefold() == normalized for item in _as_list(client_list))


def detect_downgrade(chosen: Any, policy: Any) -> bool:
    """Report whether the chosen protocol violates the policy floor.

    Missing or malformed downgrade rules are treated as unsafe, so an
    unverifiable selection is reported as a downgrade.
    """
    if not isinstance(policy, dict):
        return True
    if policy.get("reject_downgrade") is not True:
        return True
    minimum = _as_number(policy.get("minimum_version"))
    if minimum is None:
        return True
    version = _protocol_version(chosen)
    if version is None:
        return True
    return version < minimum


def check_consistency(chosen: Any, version: Any) -> bool:
    """Check that the protocol and the negotiated version agree."""
    expected = _protocol_version(chosen)
    if expected is None:
        return False
    actual = _as_number(version)
    if actual is None:
        return False
    return expected == actual


def validate_policy(policy: Any) -> list[str]:
    """Return a list of policy problems."""
    if not isinstance(policy, dict):
        return ["invalid_policy"]
    issues: list[str] = []
    if "minimum_version" not in policy or policy.get("minimum_version") is None:
        issues.append("missing_minimum_version")
    elif _as_number(policy.get("minimum_version")) is None:
        issues.append("invalid_minimum_version")
    if "reject_downgrade" not in policy:
        issues.append("missing_downgrade_rule")
    elif policy.get("reject_downgrade") is not True:
        issues.append("downgrade_must_be_rejected")
    if policy.get("allow_empty"):
        issues.append("empty_result_allowed")
    return issues


def negotiate(client_list: Any, server_list: Any, version: Any, policy: Any) -> dict:
    """Negotiate one ALPN connection.

    The selected protocol must come from the client's declared list and
    must match the negotiated version; no default is ever substituted.
    """
    clients = _as_list(client_list)
    servers = _as_list(server_list)
    if not clients or not servers:
        return {"ok": False, "error": "empty_negotiation"}
    chosen = preferred(clients, servers)
    if not chosen:
        return {"ok": False, "error": "no_common_protocol"}
    if not declared(chosen, clients):
        return {"ok": False, "error": "undeclared_protocol"}
    if not check_consistency(chosen, version):
        return {"ok": False, "error": "version_mismatch"}
    if detect_downgrade(chosen, policy):
        return {"ok": False, "error": "downgrade_detected"}
    return {
        "ok": True,
        "protocol": chosen,
        "version": _PROTOCOL_VERSIONS[chosen.strip().casefold()],
    }


def alpn_batch(connections: Any, policy: Any) -> dict:
    """Negotiate a sequence of connections, each independently."""
    results: dict[Any, dict] = {}
    for index, connection in enumerate(connections):
        if not isinstance(connection, dict):
            connection = {}
        key = connection.get("id")
        if key is None:
            key = index
        results[key] = negotiate(
            connection.get("client", []),
            connection.get("server", []),
            connection.get("version"),
            policy,
        )
    return results
