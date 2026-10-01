from src.detection.analyzer import (
    detect_new_processes,
    add_parent_context,
    analyze_process
)


def test_detect_new_process():
    previous = [
        {
            "pid": 100,
            "name": "bash"
        }
    ]

    current = [
        {
            "pid": 100,
            "name": "bash"
        },
        {
            "pid": 200,
            "name": "python"
        }
    ]

    result = detect_new_processes(previous, current)

    assert len(result) == 1
    assert result[0]["pid"] == 200
    assert result[0]["name"] == "python"


def test_parent_context():
    processes = [
        {
            "pid": 100,
            "ppid": 1,
            "name": "bash",
            "exe": "/usr/bin/bash",
        },
        {
            "pid": 200,
            "ppid": 100,
            "name": "python",
            "exe": "/usr/bin/python3",
        },
    ]

    result = add_parent_context(processes)

    child = result[1]

    assert child["parent_name"] == "bash"
    assert child["parent_executable"] == "/usr/bin/bash"

def test_analyze_process():
    process = {
        "pid": 200,
        "username": "root",
        "exe": "/tmp/test-program",
        "cmdline": ["curl", "https://example.com"]
    }

    findings = analyze_process(process)

    assert len(findings) == 3

    rules = [finding["rule"] for finding in findings]

    assert "suspicious_path" in rules
    assert "root_process" in rules
    assert "suspicious_command" in rules
