from sqlmodel import Session, select

from models.security_event import SecurityEvent


SUSPICIOUS_EVENT_TYPES = {
    "SSH_LOGIN_FAILURE",
    "SSH_LOGIN_FAILED",
    "PORT_SCAN",
    "MALWARE",
    "MALWARE_DETECTED",
    "SUSPICIOUS_PROCESS",
    "UNAUTHORIZED_ACCESS",
}


def get_ip_activity(
    session: Session,
    source_ip: str
) -> list[SecurityEvent]:

    statement = (
        select(SecurityEvent)
        .where(SecurityEvent.source_ip == source_ip)
    )

    return list(session.exec(statement))


def count_suspicious_events(
    session: Session,
    source_ip: str
) -> int:

    events = get_ip_activity(session, source_ip)

    return sum(
        1
        for event in events
        if event.event_type.upper()
        in SUSPICIOUS_EVENT_TYPES
    )

def analyze_ip_behavior(
    session: Session,
    source_ip: str
) -> dict:

    events = get_ip_activity(session, source_ip)

    suspicious_events = [
        event
        for event in events
        if event.event_type.upper()
        in SUSPICIOUS_EVENT_TYPES
    ]

    suspicious_count = len(suspicious_events)

    if suspicious_count >= 10:
        behavior_level = "CRITICAL"
        behavior_score = 40

    elif suspicious_count >= 5:
        behavior_level = "HIGH"
        behavior_score = 30

    elif suspicious_count >= 3:
        behavior_level = "MEDIUM"
        behavior_score = 20

    elif suspicious_count >= 1:
        behavior_level = "LOW"
        behavior_score = 10

    else:
        behavior_level = "NORMAL"
        behavior_score = 0

    return {
        "source_ip": source_ip,
        "suspicious_event_count": suspicious_count,
        "behavior_score": behavior_score,
        "behavior_level": behavior_level
    }