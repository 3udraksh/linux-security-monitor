from .rules import (
    check_suspicious_path,
    check_root_process,
    check_suspicious_command,
)

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


def add_parent_context(processes):
    process_map = get_process_map(processes)

    enriched_processes = []

    for process in processes:
        parent_pid = process.get("ppid")

        parent = process_map.get(parent_pid)

        if parent:
            parent_name = parent.get("name")
            parent_executable = parent.get("exe")
        else:
            parent_name = "Unknown"
            parent_executable = "Unknown"

        enriched_process = process.copy()

        enriched_process["parent_name"] = parent_name
        enriched_process["parent_executable"] = parent_executable

        enriched_processes.append(enriched_process)

    return enriched_processes
def analyze_process(process):
    findings = []

    if check_suspicious_path(process):
        findings.append({
            "rule": "suspicious_path",
            "severity": "medium",
            "reason": "Executable is running from a potentially suspicious location"
        })

    if check_root_process(process):
        findings.append({
            "rule": "root_process",
            "severity": "low",
            "reason": "Process is running as root"
        })

    if check_suspicious_command(process):
        findings.append({
            "rule": "suspicious_command",
            "severity": "medium",
            "reason": "Command contains a security-relevant command pattern"
        })

    return findings