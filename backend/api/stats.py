from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from services.stats_service import get_dashboard_stats


router = APIRouter(
    prefix="/stats",
    tags=["Statistics"]
)


@router.get("/")
def dashboard_stats(
    session: Session = Depends(get_session)
):

    return get_dashboard_stats(
        session
    )