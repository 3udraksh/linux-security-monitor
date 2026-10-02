from .network_rules import check_suspicious_remote_port


def analyze_connection(connection):
    findings = []

    if check_suspicious_remote_port(connection):
        findings.append({
            "rule": "suspicious_remote_port",
            "severity": "medium",
            "reason": (
                "Connection uses a remote port commonly associated "
                "with administrative or legacy network services"
            )
        })

    return findings