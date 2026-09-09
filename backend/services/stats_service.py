from sqlmodel import Session, select

from models.security_event import SecurityEvent
from models.security_alert import SecurityAlert
from models.network_flow import NetworkFlow


def get_dashboard_stats(
    session: Session
) -> dict:

    events = list(
        session.exec(
            select(SecurityEvent)
        )
    )

    alerts = list(
        session.exec(
            select(SecurityAlert)
        )
    )

    flows = list(
        session.exec(
            select(NetworkFlow)
        )
    )

    # -----------------------------------------
    # Event statistics
    # -----------------------------------------

    total_events = len(events)

    critical_events = sum(
        1
        for event in events
        if event.threat_level == "CRITICAL"
    )

    high_events = sum(
        1
        for event in events
        if event.threat_level == "HIGH"
    )

    medium_events = sum(
        1
        for event in events
        if event.threat_level == "MEDIUM"
    )

    low_events = sum(
        1
        for event in events
        if event.threat_level == "LOW"
    )

    # -----------------------------------------
    # Network flow statistics
    # -----------------------------------------

    total_flows = len(flows)

    malicious_flows = sum(
        1
        for flow in flows
        if flow.ml_prediction == 1
    )

    # -----------------------------------------
    # Alert statistics
    # -----------------------------------------

    total_alerts = len(alerts)

    active_alerts = sum(
        1
        for alert in alerts
        if not alert.is_acknowledged
    )

    acknowledged_alerts = sum(
        1
        for alert in alerts
        if alert.is_acknowledged
    )

    return {
        "total_events": total_events,

        "threat_levels": {
            "critical": critical_events,
            "high": high_events,
            "medium": medium_events,
            "low": low_events,
        },

        "network_flows": {
            "total": total_flows,
            "malicious": malicious_flows,
        },

        "alerts": {
            "total": total_alerts,
            "active": active_alerts,
            "acknowledged": acknowledged_alerts,
        }
    }