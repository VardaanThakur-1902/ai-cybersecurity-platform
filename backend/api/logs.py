from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from models.security_event import SecurityEvent
from services.log_service import create_event, get_events
from fastapi import APIRouter, Depends, File, UploadFile
from services.csv_service import process_csv
from sqlmodel import Session, select


router = APIRouter(
    prefix="/logs",
    tags=["Security Logs"]
)


@router.post("/")
def add_log(
    event: SecurityEvent,
    session: Session = Depends(get_session)
):
    return create_event(session, event)


@router.post("/bulk")
def add_logs(
    events: list[SecurityEvent],
    session: Session = Depends(get_session)
):
    created_events = []

    for event in events:
        created_events.append(
            create_event(session, event)
        )

    return {
        "count": len(created_events),
        "events": created_events
    }

@router.post("/upload-csv")
async def upload_csv(
    file: UploadFile = File(...),
    session: Session = Depends(get_session)
):
    content = await file.read()

    count = process_csv(
        content,
        session
    )

    return {
        "message": "CSV uploaded successfully",
        "records_imported": count
    }


@router.get("/")
def list_logs(
    session: Session = Depends(get_session)
):
    return get_events(session)

@router.get("/")
def get_logs(
    skip: int = 0,
    limit: int = 50,
    threat_level: str | None = None,
    source_ip: str | None = None,
    threat_type: str | None = None,
    session: Session = Depends(get_session)
):
    statement = select(SecurityEvent)

    if threat_level:
        statement = statement.where(
            SecurityEvent.threat_level == threat_level.upper()
        )

    if source_ip:
        statement = statement.where(
            SecurityEvent.source_ip == source_ip
        )

    if threat_type:
        statement = statement.where(
            SecurityEvent.threat_type == threat_type
        )

    all_results = list(session.exec(statement))

    total = len(all_results)

    items = all_results[skip:skip + limit]

    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit
    }