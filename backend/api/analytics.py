from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from services.analytics_service import (
    get_threat_analytics
)


router = APIRouter(
    prefix="/analytics",
    tags=["Analytics"]
)


@router.get("/")
def threat_analytics(
    session: Session = Depends(get_session)
):

    return get_threat_analytics(
        session
    )

from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from services.analytics_service import (
    get_top_attacking_ips,
    get_attack_type_distribution,
    get_network_attack_distribution,
    get_threats_by_hour,
    get_threats_by_day
)

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/")
def get_analytics(
    session: Session = Depends(get_session)
):
    return {
        "top_attacking_ips": get_top_attacking_ips(session),

        "attack_type_distribution":
            get_attack_type_distribution(session),

        "network_attack_distribution":
            get_network_attack_distribution(session),

        "threats_by_hour":
            get_threats_by_hour(session),

        "threats_by_day":
            get_threats_by_day(session)
    }