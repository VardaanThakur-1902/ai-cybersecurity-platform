from datetime import datetime

from sqlmodel import Session, select

from models.security_event import SecurityEvent
from detection.rule_engine import analyze_event
from services.behavior_service import analyze_ip_behavior


def create_event(
    session: Session,
    event: SecurityEvent
) -> SecurityEvent:

    if isinstance(event.timestamp, str):
        event.timestamp = datetime.fromisoformat(event.timestamp)

    # First save the event so it can participate
    # in behavioral analysis.
    session.add(event)
    session.commit()
    session.refresh(event)

    # Individual event detection
    detection_result = analyze_event(event)

    # IP behavioral detection
    behavior_result = analyze_ip_behavior(
        session,
        event.source_ip
    )

    # Combine individual and behavioral scores
    final_score = (
        detection_result["threat_score"]
        + behavior_result["behavior_score"]
    )

    final_score = min(final_score, 100)

    # Determine final threat level
    if final_score >= 80:
        final_level = "CRITICAL"

    elif final_score >= 60:
        final_level = "HIGH"

    elif final_score >= 30:
        final_level = "MEDIUM"

    else:
        final_level = "LOW"

    # Store detection results
    event.threat_score = final_score

    event.threat_level = final_level

    event.threat_type = detection_result[
        "threat_type"
    ]

    reasons = detection_result["reasons"].copy()

    if behavior_result["behavior_score"] > 0:
        reasons.append(
            f"{behavior_result['suspicious_event_count']} "
            f"suspicious events detected from this IP"
        )

    event.detection_reasons = "; ".join(reasons)

    event.detected_at = datetime.utcnow()

    session.add(event)
    session.commit()
    session.refresh(event)

    return event


def get_events(
    session: Session
) -> list[SecurityEvent]:

    statement = select(SecurityEvent)

    return list(session.exec(statement))