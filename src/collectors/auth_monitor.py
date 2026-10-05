from pathlib import Path


AUTH_LOG = Path("/var/log/auth.log")


def read_auth_log():
    if not AUTH_LOG.exists():
        return []

    try:
        with AUTH_LOG.open("r", encoding="utf-8", errors="replace") as log:
            return log.readlines()

    except PermissionError:
        return []


def get_new_auth_events(previous_lines, current_lines):
    previous_count = len(previous_lines)

    if previous_count > len(current_lines):
        # Log was rotated or truncated.
        return current_lines

    return current_lines[previous_count:]

def parse_auth_event(line):
    parts = line.split()

    if len(parts) < 5:
        return None

    event = {
        "timestamp": " ".join(parts[:3]),
        "hostname": parts[3],
        "message": " ".join(parts[4:]),
        "raw": line.rstrip(),
    }

    message = event["message"].lower()

    if "failed password" in message:
        event["event_type"] = "authentication_failure"

    elif "accepted password" in message:
        event["event_type"] = "authentication_success"

    elif "sudo:" in message:
        event["event_type"] = "sudo_activity"

    else:
        event["event_type"] = "other"

    return event


def parse_auth_events(lines):
    events = []

    for line in lines:
        event = parse_auth_event(line)

        if event:
            events.append(event)

    return events