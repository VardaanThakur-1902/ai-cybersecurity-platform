from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from models.security_alert import SecurityAlert
from services.alert_service import get_alerts
from fastapi import HTTPException
from sqlmodel import Session, select


router = APIRouter(
    prefix="/alerts",
    tags=["Security Alerts"]
)

@router.get("/")
def get_alerts(
    skip: int = 0,
    limit: int = 50,
    threat_level: str | None = None,
    acknowledged: bool | None = None,
    session: Session = Depends(get_session)
):
    statement = select(SecurityAlert)

    if threat_level:
        statement = statement.where(
            SecurityAlert.threat_level == threat_level.upper()
        )

    if acknowledged is not None:
        statement = statement.where(
            SecurityAlert.is_acknowledged == acknowledged
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