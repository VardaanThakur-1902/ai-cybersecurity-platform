from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from detection.rule_engine import analyze_event
from models.security_event import SecurityEvent
from services.behavior_service import analyze_ip_behavior


router = APIRouter(
    prefix="/detection",
    tags=["Threat Detection"]
)


@router.post("/analyze")
def analyze_security_event(
    event: SecurityEvent
):
    return analyze_event(event)

@router.get("/ip/{source_ip}")
def analyze_ip(
    source_ip: str,
    session: Session = Depends(get_session)
):
    return analyze_ip_behavior(
        session,
        source_ip
    )