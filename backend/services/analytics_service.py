from collections import Counter

from sqlmodel import Session, select

from models.security_event import SecurityEvent
from models.network_flow import NetworkFlow

from collections import Counter
from models.security_event import SecurityEvent
from models.network_flow import NetworkFlow
from sqlmodel import Session, select



def get_threat_analytics(
    session: Session
) -> dict:

    events = list(
        session.exec(
            select(SecurityEvent)
        )
    )

    flows = list(
        session.exec(
            select(NetworkFlow)
        )
    )

    # -----------------------------------------
    # Top attacking IPs from security events
    # -----------------------------------------

    attacking_ips = Counter(
        event.source_ip
        for event in events
        if event.threat_level in [
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ]
    )

    top_attacking_ips = [
        {
            "source_ip": ip,
            "threat_count": count
        }
        for ip, count in attacking_ips.most_common(10)
    ]

    # -----------------------------------------
    # Threat type distribution
    # -----------------------------------------

    threat_types = Counter(
        event.threat_type
        for event in events
        if event.threat_type != "NORMAL"
    )

    threat_type_distribution = [
        {
            "threat_type": threat_type,
            "count": count
        }
        for threat_type, count
        in threat_types.most_common()
    ]

    # -----------------------------------------
    # Threat level distribution
    # -----------------------------------------

    threat_levels = Counter(
        event.threat_level
        for event in events
    )

    threat_level_distribution = {
        "LOW": threat_levels.get("LOW", 0),
        "MEDIUM": threat_levels.get("MEDIUM", 0),
        "HIGH": threat_levels.get("HIGH", 0),
        "CRITICAL": threat_levels.get("CRITICAL", 0),
    }

    # -----------------------------------------
    # Network attack types
    # -----------------------------------------

    network_attack_types = Counter(
        flow.label
        for flow in flows
        if flow.ml_prediction == 1
        and flow.label
    )

    network_attack_distribution = [
        {
            "attack_type": attack_type,
            "count": count
        }
        for attack_type, count
        in network_attack_types.most_common()
    ]

    # -----------------------------------------
    # Recent threats
    # -----------------------------------------

    recent_events = sorted(
        [
            event
            for event in events
            if event.threat_level in [
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]
        ],
        key=lambda event: event.timestamp,
        reverse=True
    )[:10]

    recent_threats = [
        {
            "id": event.id,
            "timestamp": event.timestamp,
            "source_ip": event.source_ip,
            "threat_type": event.threat_type,
            "threat_level": event.threat_level,
            "threat_score": event.threat_score,
        }
        for event in recent_events
    ]

    return {
        "top_attacking_ips": top_attacking_ips,
        "threat_type_distribution": (
            threat_type_distribution
        ),
        "threat_level_distribution": (
            threat_level_distribution
        ),
        "network_attack_distribution": (
            network_attack_distribution
        ),
        "recent_threats": recent_threats,
    }

def get_threats_by_hour(session: Session):
    events = session.exec(select(SecurityEvent)).all()

    counter = Counter()

    for event in events:
        if event.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]:
            hour = event.timestamp.hour
            counter[hour] += 1

    return [
        {
            "hour": hour,
            "count": counter.get(hour, 0)
        }
        for hour in range(24)
    ]


def get_threats_by_day(session: Session):
    events = session.exec(select(SecurityEvent)).all()

    counter = Counter()

    for event in events:
        if event.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]:
            day = event.timestamp.strftime("%Y-%m-%d")
            counter[day] += 1

    return [
        {
            "date": day,
            "count": count
        }
        for day, count in sorted(counter.items())
    ]


def get_top_attacking_ips(session: Session, limit: int = 10):
    events = session.exec(select(SecurityEvent)).all()

    counter = Counter()

    for event in events:
        if event.threat_level in ["MEDIUM", "HIGH", "CRITICAL"]:
            counter[event.source_ip] += 1

    return [
        {
            "source_ip": ip,
            "count": count
        }
        for ip, count in counter.most_common(limit)
    ]


def get_attack_type_distribution(session: Session):
    events = session.exec(select(SecurityEvent)).all()

    counter = Counter()

    for event in events:
        if event.threat_type != "NORMAL":
            counter[event.threat_type] += 1

    return [
        {
            "threat_type": threat_type,
            "count": count
        }
        for threat_type, count in counter.most_common()
    ]


def get_network_attack_distribution(session: Session):
    flows = session.exec(select(NetworkFlow)).all()

    counter = Counter()

    for flow in flows:
        if flow.ml_prediction == 1:
            label = flow.label or "UNKNOWN_ATTACK"
            counter[label] += 1

    return [
        {
            "attack_type": attack_type,
            "count": count
        }
        for attack_type, count in counter.most_common()
    ]