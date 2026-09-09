from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from services.stats_service import get_dashboard_stats
from services.analytics_service import (
    get_top_attacking_ips,
    get_attack_type_distribution,
    get_network_attack_distribution,
    get_threats_by_hour,
    get_threats_by_day
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/")
def get_dashboard(
    session: Session = Depends(get_session)
):
    return {
        "stats": get_dashboard_stats(session),

        "analytics": {
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
    }