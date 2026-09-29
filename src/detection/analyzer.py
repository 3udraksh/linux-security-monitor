def get_process_map(processes):
    return {
        process["pid"]: process
        for process in processes
    }


def detect_new_processes(previous_processes, current_processes):
    previous_map = get_process_map(previous_processes)
    current_map = get_process_map(current_processes)

    new_processes = []

    for pid, process in current_map.items():
        if pid not in previous_map:
            new_processes.append(process)

    return new_processes
