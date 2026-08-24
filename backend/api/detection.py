from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from detection.rule_engine import analyze_event
from models.security_event import SecurityEvent


router = APIRouter(
    prefix="/detection",
    tags=["Threat Detection"]
)


@router.post("/analyze")
def analyze_security_event(
    event: SecurityEvent
):
    return analyze_event(event)