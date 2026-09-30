import time

from collectors.process_monitor import collect_processes
from detection.analyzer import (
    detect_new_processes,
    add_parent_context,
)

def main():
    print("Linux Security Monitor")
    print("======================")
    print("Starting process monitoring...\n")

    previous_processes = add_parent_context(
    collect_processes()
    )

    while True:
        time.sleep(3)

        current_processes = add_parent_context(
            collect_processes()
        )
        new_processes = detect_new_processes(
            previous_processes,
            current_processes
        )

        for process in new_processes:
            print(
                f"\n[NEW PROCESS]\n"
                f"  PID: {process['pid']}\n"
                f"  PPID: {process['ppid']}\n"
                f"  Name: {process['name']}\n"
                f"  User: {process['username']}\n"
                f"  Executable: {process['exe']}\n"
                f"  Command: {' '.join(process['cmdline']) if process['cmdline'] else 'N/A'}\n"
                f"  Parent: {process['parent_name']}\n"
                f"  Parent executable: {process['parent_executable']}\n"
            )

        previous_processes = current_processes


if __name__ == "__main__":
    main()
    