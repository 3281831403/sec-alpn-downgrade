from alpn.neg import (
    alpn_batch,
    negotiate,
    parse_protocols,
    preferred,
)


def policy_floor_two():
    return {"minimum_version": 2, "reject_downgrade": True}


def policy_floor_one():
    return {"minimum_version": 1, "reject_downgrade": True}


def test_parse_protocols():
    assert parse_protocols("h2, http/1.1,, h3 ") == ["h2", "http/1.1", "h3"]


def test_preferred_follows_client_preference():
    assert preferred(["http/1.1", "h2"], ["h2", "http/1.1"]) == "http/1.1"


def test_undeclared_protocol_rejected():
    result = negotiate(["h2"], ["http/1.1"], 1.1, policy_floor_two())
    assert result["ok"] is False
    assert result["error"] in {"no_common_protocol", "undeclared_protocol"}


def test_downgrade_detected():
    result = negotiate(["http/1.1"], ["http/1.1"], 1.1, policy_floor_two())
    assert result["ok"] is False
    assert result["error"] == "downgrade_detected"


def test_batch_connections_are_independent():
    connections = [
        {
            "id": "first",
            "client": ["h2", "h3"],
            "server": ["h2", "h3"],
            "version": 2,
        },
        {
            "id": "second",
            "client": ["h3", "h2"],
            "server": ["h2", "h3"],
            "version": 3,
        },
    ]
    results = alpn_batch(connections, policy_floor_one())
    assert results["first"]["ok"] is True
    assert results["first"]["protocol"] == "h2"
    assert results["second"]["ok"] is True
    assert results["second"]["protocol"] == "h3"