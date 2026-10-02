SUSPICIOUS_REMOTE_PORTS = (
    21,    # FTP
    23,    # Telnet
    445,   # SMB
    3389,  # RDP
)


def check_suspicious_remote_port(connection):
    remote_address = connection.get("remote_address")

    if not remote_address:
        return False

    try:
        port = int(remote_address.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return False

    return port in SUSPICIOUS_REMOTE_PORTS
