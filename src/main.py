import time

from collectors.process_monitor import collect_processes
from detection.analyzer import detect_new_processes


def main():
    print("Linux Security Monitor")
    print("======================")
    print("Starting process monitoring...\n")

    previous_processes = collect_processes()

    while True:
        time.sleep(3)

        current_processes = collect_processes()

        new_processes = detect_new_processes(
            previous_processes,
            current_processes
        )

        for process in new_processes:
            print(
                f"[NEW PROCESS] "
                f"PID: {process['pid']} | "
                f"Name: {process['name']} | "
                f"User: {process['username']} | "
                f"Executable: {process['exe']}"
            )

        previous_processes = current_processes


if __name__ == "__main__":
    main()
    