from sqlmodel import Session, select

from models.security_alert import SecurityAlert
from models.security_event import SecurityEvent


def create_alert(
    session: Session,
    event: SecurityEvent
) -> SecurityAlert:

    alert = SecurityAlert(
        event_id=event.id,
        source_ip=event.source_ip,
        threat_type=event.threat_type,
        threat_level=event.threat_level,
        threat_score=event.threat_score,
        message=(
            f"{event.threat_type} detected from "
            f"{event.source_ip}. "
            f"{event.detection_reasons or event.message}"
        )
    )

    session.add(alert)
    session.commit()
    session.refresh(alert)

    return alert


def get_alerts(
    session: Session
) -> list[SecurityAlert]:

    statement = (
        select(SecurityAlert)
        .order_by(SecurityAlert.created_at.desc())
    )

    return list(session.exec(statement))