import time

from src.collectors.process_monitor import collect_processes
from src.collectors.network_monitor import (
    collect_connections,
    build_process_map,
    correlate_connections,
    detect_new_connections,
)

from src.detection.analyzer import (
    detect_new_processes,
    add_parent_context,
    analyze_process,
)

from src.detection.network_analyzer import analyze_connection

MONITOR_INTERVAL = 3

def display_process_alert(process, findings):
    print("\n[NEW PROCESS]")

    print(
        f"  PID: {process['pid']}\n"
        f"  PPID: {process['ppid']}\n"
        f"  Name: {process['name']}\n"
        f"  User: {process['username']}\n"
        f"  Executable: {process['exe']}\n"
        f"  Command: "
        f"{' '.join(process['cmdline']) if process['cmdline'] else 'N/A'}\n"
        f"  Parent: {process['parent_name']}\n"
        f"  Parent executable: {process['parent_executable']}\n"
    )

    if findings:
        print("  Security Findings:")

        for finding in findings:
            print(
                f"    - [{finding['severity'].upper()}] "
                f"{finding['rule']}: "
                f"{finding['reason']}"
            )


def display_network_alert(connection, findings):
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

    if findings:
        print("  Security Findings:")

        for finding in findings:
            print(
                f"    - [{finding['severity'].upper()}] "
                f"{finding['rule']}: "
                f"{finding['reason']}"
            )


def main():
    print("Linux Security Monitor")
    print("======================")
    print("Starting monitoring...\n")

    previous_processes = add_parent_context(
        collect_processes()
    )

    previous_connections = collect_connections()

    while True:
        time.sleep(MONITOR_INTERVAL)

        # -------------------------
        # PROCESS MONITORING
        # -------------------------

        current_processes = add_parent_context(
            collect_processes()
        )

        new_processes = detect_new_processes(
            previous_processes,
            current_processes,
        )

        for process in new_processes:
            findings = analyze_process(process)

            display_process_alert(
                process,
                findings,
            )

        previous_processes = current_processes

        # -------------------------
        # NETWORK MONITORING
        # -------------------------

        current_connections = collect_connections()

        new_connections = detect_new_connections(
            previous_connections,
            current_connections,
        )

        if new_connections:
            process_map = build_process_map()

            correlated_connections = correlate_connections(
                new_connections,
                process_map,
            )

            for connection in correlated_connections:
                findings = analyze_connection(connection)

                display_network_alert(
                    connection,
                    findings,
                )

        previous_connections = current_connections


if __name__ == "__main__":
    main()