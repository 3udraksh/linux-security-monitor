from src.detection.rules import (
    check_suspicious_path,
    check_root_process,
    check_suspicious_command,
)


def test_suspicious_path():
    process = {
        "exe": "/tmp/test-program"
    }

    assert check_suspicious_path(process) is True


def test_normal_path():
    process = {
        "exe": "/usr/bin/python3"
    }

    assert check_suspicious_path(process) is False


def test_root_process():
    process = {
        "username": "root"
    }

    assert check_root_process(process) is True


def test_normal_user():
    process = {
        "username": "rudraksh"
    }

    assert check_root_process(process) is False


def test_suspicious_command():
    process = {
        "cmdline": ["curl", "https://example.com"]
    }

    assert check_suspicious_command(process) is True


def test_normal_command():
    process = {
        "cmdline": ["python", "script.py"]
    }

    assert check_suspicious_command(process) is False