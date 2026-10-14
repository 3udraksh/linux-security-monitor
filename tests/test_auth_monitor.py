from src.collectors.auth_monitor import parse_auth_event


def test_parse_auth_event_ignores_malformed_line():
    assert parse_auth_event("incomplete log") is None

def test_parse_auth_event_ignores_empty_line():
    assert parse_auth_event("") is None

def test_parse_auth_event_detects_successful_password():
    line = (
        "Oct 12 10:30:00 ubuntu sshd[1234]: "
        "Accepted password for rudraksh from 192.0.2.10 port 54321 ssh2"
    )

    event = parse_auth_event(line)

    assert event["event_type"] == "authentication_success"



def test_parse_auth_event_detects_failed_password():
    line = (
        "Oct 14 10:30:00 ubuntu sshd[1234]: "
        "Failed password for rudraksh from 192.0.2.10 port 54321 ssh2"
    )

    event = parse_auth_event(line)

    assert event["event_type"] == "authentication_failure"
