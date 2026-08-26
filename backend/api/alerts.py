from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from models.security_alert import SecurityAlert
from services.alert_service import get_alerts
from fastapi import HTTPException


router = APIRouter(
    prefix="/alerts",
    tags=["Security Alerts"]
)


@router.get("/")
def list_alerts(
    session: Session = Depends(get_session)
) -> list[SecurityAlert]:

    return get_alerts(session)

@router.patch("/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    session: Session = Depends(get_session)
):

    alert = session.get(SecurityAlert, alert_id)

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    alert.is_acknowledged = True

    session.add(alert)
    session.commit()
    session.refresh(alert)

    return alert