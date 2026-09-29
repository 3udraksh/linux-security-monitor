import psutil


def collect_processes():
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent", "exe", "status"]
    ):
        try:
            processes.append(process.info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def display_processes(processes):
    for process in processes:
        print(
            f"PID: {process['pid']} | "
            f"Name: {process['name']} | "
            f"User: {process['username']} | "
            f"CPU: {process['cpu_percent']}% | "
            f"Memory: {process['memory_percent']:.2f}% | "
            f"Status: {process['status']} | "
            f"Executable: {process['exe']}"
        )


if __name__ == "__main__":
    processes = collect_processes()
    display_processes(processes)