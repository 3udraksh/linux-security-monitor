SUSPICIOUS_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


def check_suspicious_path(process):
    executable = process.get("exe")

    if not executable:
        return False

    return executable.startswith(SUSPICIOUS_PATHS)


def check_root_process(process):
    username = process.get("username")

    return username == "root"


def check_suspicious_command(process):
    cmdline = process.get("cmdline")

    if not cmdline:
        return False

    command = " ".join(cmdline).lower()

    suspicious_terms = (
        "curl ",
        "wget ",
        "nc ",
        "netcat ",
        "chmod ",
        "chown ",
    )

    return any(term in command for term in suspicious_terms)