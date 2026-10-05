import psutil
from datetime import datetime


def collect_processes():
    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "username",
            "cpu_percent",
            "memory_percent",
            "exe",
            "status",
            "cmdline",
            "create_time",
        ]
    ):
        try:
            processes.append(process.info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes

def format_command(cmdline):
    if cmdline:
        return " ".join(cmdline)

    return "N/A"

def display_processes(processes):
    for process in processes:
        command_line = process["cmdline"]

        command_line = format_command(process["cmdline"])

        create_time = process["create_time"]

        if create_time:
            create_time = datetime.fromtimestamp(create_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        else:
            create_time = "N/A"

        print(
            f"PID: {process['pid']} | "
            f"PPID: {process['ppid']} | "
            f"Name: {process['name']} | "
            f"User: {process['username']} | "
            f"CPU: {process['cpu_percent']}% | "
            f"Memory: {process['memory_percent']:.2f}% | "
            f"Status: {process['status']} | "
            f"Executable: {process['exe']} | "
            f"Command: {command_line} | "
            f"Created: {create_time}"
        )


if __name__ == "__main__":
    processes = collect_processes()
    display_processes(processes)