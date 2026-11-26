"""ALPN protocol negotiation primitives."""

from __future__ import annotations

import math
from typing import Any

_PROTOCOL_VERSIONS = {
    "h2": 2,
    "h3": 3,
    "http/1.1": 1.1,
}

_MINIMUM_VERSION_FIELDS = ("minimum_version", "min_version")


# ---------------------------------------------------------------------------
# parsing helpers
# ---------------------------------------------------------------------------


def _clean_item(item: Any) -> str:
    """Normalize one declared protocol entry."""
    if item is None:
        return ""
    text = str(item).strip()
    return text


def parse_protocols(value: Any) -> list[str]:
    """Split a protocol declaration into individual protocol names.

    A string is comma separated; a sequence is taken as one name per item.
    Surrounding whitespace and empty entries are dropped while the original
    order and case are preserved.
    """
    if value is None:
        return []
    if isinstance(value, str):
        raw: list[Any] = value.split(",")
    elif isinstance(value, (bytes, bytearray)):
        return parse_protocols(bytes(value).decode("latin-1"))
    else:
        try:
            raw = list(value)
        except TypeError:
            raw = [value]
    result: list[str] = []
    for item in raw:
        text = _clean_item(item)
        if text:
            result.append(text)
    return result


def _as_list(value: Any) -> list[str]:
    """Return the declared protocols for ``value`` as a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return parse_protocols(value)
    if isinstance(value, (bytes, bytearray)):
        return parse_protocols(bytes(value).decode("latin-1"))
    if isinstance(value, dict):
        return []
    try:
        return parse_protocols(list(value))
    except TypeError:
        return parse_protocols([value])


# ---------------------------------------------------------------------------
# protocol / policy helpers
# ---------------------------------------------------------------------------


def _normalize(protocol: Any) -> str:
    if protocol is None:
        return ""
    return str(protocol).strip().lower()


def _canonical(protocol: str) -> str:
    """Map a protocol name to the canonical key used for version lookups."""
    key = protocol.strip().lower()
    if key in _PROTOCOL_VERSIONS:
        return key
    if key.startswith("h") and key[1:].isdigit():
        return "h" + str(int(key[1:]))
    return key


def preferred(client_list: Any, server_list: Any) -> str:
    """Return the client's most preferred mutually supported protocol.

    The client's declaration order is authoritative and the protocol is
    returned using the client's spelling. Comparison is case-insensitive.
    """
    clients = _as_list(client_list)
    server_keys = {_normalize(item) for item in _as_list(server_list)}
    server_keys.discard("")
    for client in clients:
        key = _normalize(client)
        if key and key in server_keys:
            return client
    return ""


def declared(protocol: Any, client_list: Any) -> bool:
    """Return whether ``protocol`` is part of the client's declared set."""
    key = _normalize(protocol)
    if not key:
        return False
    return any(_normalize(item) == key for item in _as_list(client_list))


def _protocol_version(protocol: Any) -> float | None:
    key = _canonical(_normalize(protocol))
    return _PROTOCOL_VERSIONS.get(key)


def _parse_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        try:
            number = float(str(value).strip())
        except (TypeError, ValueError):
            return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def _policy_minimum(policy: Any) -> float | None:
    if not isinstance(policy, dict):
        return None
    for field in _MINIMUM_VERSION_FIELDS:
        if field in policy:
            return _parse_number(policy.get(field))
    return None


def detect_downgrade(chosen: Any, policy: Any) -> bool:
    """Report whether ``chosen`` violates the policy's minimum version.

    Downgrades must be explicitly enforced: a missing or malformed downgrade
    rule, or a minimum version that cannot be evaluated, is treated as unsafe
    and reported as a downgrade. An unknown protocol is never accepted.
    """
    version = _protocol_version(chosen)
    if version is None:
        return True
    if not isinstance(policy, dict):
        return True
    if policy.get("reject_downgrade") is not True:
        return True
    minimum = _policy_minimum(policy)
    if minimum is None:
        return True
    return version < minimum


def check_consistency(chosen: Any, version: Any) -> bool:
    """Check that the protocol and the negotiated version agree."""
    expected = _protocol_version(chosen)
    if expected is None:
        return False
    actual = _parse_number(version)
    if actual is None:
        return False
    return expected == actual


# ---------------------------------------------------------------------------
# policy validation
# ---------------------------------------------------------------------------


def validate_policy(policy: Any) -> list[str]:
    """Return a list of policy problems (empty when the policy is valid)."""
    if not isinstance(policy, dict):
        return ["invalid_policy"]
    issues: list[str] = []

    if not any(field in policy for field in _MINIMUM_VERSION_FIELDS):
        issues.append("missing_minimum_version")
    else:
        minimum_value = None
        for field in _MINIMUM_VERSION_FIELDS:
            if field in policy:
                minimum_value = policy.get(field)
                break
        minimum = _parse_number(minimum_value)
        if minimum is None or minimum < 0:
            issues.append("invalid_minimum_version")

    if "reject_downgrade" not in policy:
        issues.append("missing_downgrade_rule")
    elif policy.get("reject_downgrade") is not True:
        issues.append("downgrade_must_be_rejected")

    if policy.get("allow_empty"):
        issues.append("empty_result_allowed")

    return issues


# ---------------------------------------------------------------------------
# negotiation
# ---------------------------------------------------------------------------


def _fail(error: str) -> dict:
    return {"ok": False, "error": error}


def negotiate(
    client_list: Any,
    server_list: Any,
    version: Any,
    policy: Any,
    *,
    strict_policy: bool = True,
) -> dict:
    """Negotiate one ALPN connection.

    The result is a pure function of the inputs: identical inputs always
    produce an identical result, and a successful ``protocol`` is always a
    member of the client's declared set.
    """
    # A malformed policy can never negotiate anything safely.
    if strict_policy and validate_policy(policy):
        return _fail("invalid_policy")

    clients = _as_list(client_list)
    servers = _as_list(server_list)

    if not clients or not servers:
        return _fail("empty_negotiation")

    chosen = preferred(clients, servers)
    if not chosen:
        return _fail("no_common_protocol")

    # Defence in depth: never accept a server choice the client didn't declare.
    if not declared(chosen, clients):
        return _fail("undeclared_protocol")

    # Unknown protocols are treated as inconsistent and never accepted.
    if not check_consistency(chosen, version):
        return _fail("version_mismatch")

    if detect_downgrade(chosen, policy):
        return _fail("downgrade_detected")

    return {"ok": True, "protocol": chosen, "version": version}


def _connection_value(connection: Any, *names: str) -> Any:
    for name in names:
        if isinstance(connection, dict) and name in connection:
            return connection.get(name)
        if not isinstance(connection, dict) and hasattr(connection, name):
            return getattr(connection, name)
    return None


def alpn_batch(connections: Any, policy: Any, *, strict_policy: bool = True) -> dict:
    """Negotiate a sequence of connections, independently, keyed by id/index."""
    results: dict[str, dict] = {}
    if connections is None:
        return results
    if isinstance(connections, (str, bytes, bytearray, dict)):
        return results
    try:
        items = list(connections)
    except TypeError:
        return results

    for index, connection in enumerate(items):
        raw_key = _connection_value(connection, "id")
        key = str(index if raw_key is None else raw_key)
        results[key] = negotiate(
            _connection_value(connection, "client", "client_list", "protocols"),
            _connection_value(connection, "server", "server_list"),
            _connection_value(connection, "version", "negotiated_version"),
            policy,
            strict_policy=strict_policy,
        )
    return results
