from models.security_event import SecurityEvent


def analyze_event(event: SecurityEvent) -> dict:
    """
    Analyze a security event using rule-based detection.
    Returns threat score, level, type and explanation.
    """

    score = 0
    threat_type = "NORMAL"
    reasons = []

    event_type = event.event_type.upper()
    severity = event.severity.lower()

    # Rule 1: Port scanning
    if event_type == "PORT_SCAN":
        score += 70
        threat_type = "PORT_SCAN"
        reasons.append("Possible network port scanning activity")

    # Rule 2: Failed SSH login
    elif event_type in ["SSH_LOGIN_FAILURE", "SSH_LOGIN_FAILED"]:
        score += 50
        threat_type = "BRUTE_FORCE"
        reasons.append("Failed SSH login attempt detected")

    # Rule 3: Suspicious event
    elif event_type in [
        "MALWARE",
        "MALWARE_DETECTED",
        "SUSPICIOUS_PROCESS",
        "UNAUTHORIZED_ACCESS"
    ]:
        score += 80
        threat_type = "MALWARE_OR_UNAUTHORIZED_ACCESS"
        reasons.append("Suspicious security event detected")

    # Rule 4: High severity
    if severity == "high":
        score += 15
        reasons.append("Event has high severity")

    elif severity == "medium":
        score += 8
        reasons.append("Event has medium severity")

    # Rule 5: Suspicious ports
    suspicious_ports = {
        21: "FTP",
        23: "TELNET",
        445: "SMB",
        3389: "RDP"
    }

    if event.destination_port in suspicious_ports:
        score += 10

        reasons.append(
            f"Connection to commonly targeted "
            f"{suspicious_ports[event.destination_port]} port"
        )

    # Keep score between 0 and 100
    score = min(score, 100)

    # Determine threat level
    if score >= 80:
        threat_level = "CRITICAL"

    elif score >= 60:
        threat_level = "HIGH"

    elif score >= 30:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"

    # Normal event
    if score == 0:
        threat_type = "NORMAL"
        reasons.append("No suspicious activity detected")

    return {
        "threat_score": score,
        "threat_level": threat_level,
        "threat_type": threat_type,
        "reasons": reasons
    }