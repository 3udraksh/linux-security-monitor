from src.collectors.auth_monitor import parse_auth_event


def test_parse_auth_event_ignores_malformed_line():
    assert parse_auth_event("incomplete log") is None

def test_parse_auth_event_ignores_empty_line():
    assert parse_auth_event("") is None