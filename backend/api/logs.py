from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from models.security_event import SecurityEvent
from services.log_service import create_event, get_events
from fastapi import APIRouter, Depends, File, UploadFile
from services.csv_service import process_csv


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