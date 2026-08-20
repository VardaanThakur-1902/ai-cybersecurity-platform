from datetime import datetime

from sqlmodel import Session, select

from models.security_event import SecurityEvent


def create_event(
    session: Session,
    event: SecurityEvent
) -> SecurityEvent:

    # Make sure timestamp is a Python datetime object
    if isinstance(event.timestamp, str):
        event.timestamp = datetime.fromisoformat(event.timestamp)

    session.add(event)
    session.commit()
    session.refresh(event)

    return event


def get_events(
    session: Session
) -> list[SecurityEvent]:

    statement = select(SecurityEvent)

    return list(session.exec(statement))