import psutil


def collect_connections():
    connections = []

    for connection in psutil.net_connections(kind="inet"):
        try:
            connections.append({
                "fd": connection.fd,
                "family": str(connection.family),
                "type": str(connection.type),
                "local_address": (
                    f"{connection.laddr.ip}:{connection.laddr.port}"
                    if connection.laddr
                    else None
                ),
                "remote_address": (
                    f"{connection.raddr.ip}:{connection.raddr.port}"
                    if connection.raddr
                    else None
                ),
                "status": connection.status,
                "pid": connection.pid,
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return connections


def build_process_map():
    process_map = {}

    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "username",
            "exe",
            "cmdline",
        ]
    ):
        try:
            process_map[process.info["pid"]] = process.info

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return process_map


def correlate_connections(connections, process_map):
    correlated = []

    for connection in connections:
        pid = connection["pid"]

        process = process_map.get(pid)

        correlated_connection = connection.copy()

        if process:
            correlated_connection["process_name"] = process.get("name")
            correlated_connection["username"] = process.get("username")
            correlated_connection["executable"] = process.get("exe")

            cmdline = process.get("cmdline")

            if cmdline:
                correlated_connection["command"] = " ".join(cmdline)
            else:
                correlated_connection["command"] = None

        else:
            correlated_connection["process_name"] = "Unknown"
            correlated_connection["username"] = "Unknown"
            correlated_connection["executable"] = "Unknown"
            correlated_connection["command"] = None

        correlated.append(correlated_connection)

    return correlated
def connection_key(connection):
    return (
    connection.get("pid"),
    connection.get("local_address"),
    connection.get("remote_address"),
    connection.get("status"),
    )


def detect_new_connections(previous_connections, current_connections):
    previous_keys = {
        connection_key(connection)
        for connection in previous_connections
    }

    new_connections = []

    for connection in current_connections:
        if connection_key(connection) not in previous_keys:
            new_connections.append(connection)

    return new_connections

def display_connections(connections):
    for connection in connections:
        print(
            f"PID: {connection['pid']} | "
            f"Process: {connection['process_name']} | "
            f"User: {connection['username']} | "
            f"Local: {connection['local_address']} | "
            f"Remote: {connection['remote_address']} | "
            f"Status: {connection['status']} | "
            f"Executable: {connection['executable']} | "
            f"Command: {connection['command'] or 'N/A'}"
        )


if __name__ == "__main__":
    import time

    from src.detection.network_analyzer import analyze_connection

    print("Network Security Monitor")
    print("========================")
    print("Starting network monitoring...\n")

    previous_connections = collect_connections()

    while True:
        time.sleep(3)

        current_connections = collect_connections()

        new_connections = detect_new_connections(
            previous_connections,
            current_connections
        )

        if new_connections:
            process_map = build_process_map()

            correlated_connections = correlate_connections(
                new_connections,
                process_map
            )

            for connection in correlated_connections:
                print("\n[NEW NETWORK CONNECTION]")

                print(
                    f"  PID: {connection['pid']}\n"
                    f"  Process: {connection['process_name']}\n"
                    f"  User: {connection['username']}\n"
                    f"  Local: {connection['local_address']}\n"
                    f"  Remote: {connection['remote_address']}\n"
                    f"  Status: {connection['status']}\n"
                    f"  Executable: {connection['executable']}\n"
                    f"  Command: {connection['command'] or 'N/A'}"
                )

                findings = analyze_connection(connection)

                if findings:
                    print("  Security Findings:")

                    for finding in findings:
                        print(
                            f"    - [{finding['severity'].upper()}] "
                            f"{finding['rule']}: "
                            f"{finding['reason']}"
                        )

        previous_connections = current_connections