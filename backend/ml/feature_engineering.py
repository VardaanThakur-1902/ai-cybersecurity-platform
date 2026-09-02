from models.security_event import SecurityEvent

from sqlmodel import Session

from services.behavior_service import analyze_ip_behavior


PROTOCOL_MAPPING = {
    "TCP": 1,
    "UDP": 2,
    "ICMP": 3
}


SEVERITY_MAPPING = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


EVENT_TYPE_MAPPING = {
    "HTTP_REQUEST": 0,
    "SSH_LOGIN": 1,
    "SSH_LOGIN_FAILURE": 2,
    "SSH_LOGIN_FAILED": 2,
    "PORT_SCAN": 3,
    "MALWARE": 4,
    "MALWARE_DETECTED": 4,
    "SUSPICIOUS_PROCESS": 5,
    "UNAUTHORIZED_ACCESS": 6
}


FEATURE_NAMES = [
    "source_port",
    "destination_port",
    "protocol",
    "severity",
    "event_type",
    "is_ssh",
    "is_http",
    "is_suspicious_port",
    "is_failed_login",
    "is_port_scan",
    "is_malware",
    "suspicious_event_count",
    "behavior_score"
]


def extract_features(
    event: SecurityEvent
) -> dict:

    protocol = (
        event.protocol.upper()
        if event.protocol
        else "UNKNOWN"
    )

    severity = (
        event.severity.lower()
        if event.severity
        else "low"
    )

    event_type = event.event_type.upper()

    return {
        "source_port": event.source_port or 0,

        "destination_port": (
            event.destination_port or 0
        ),

        "protocol": PROTOCOL_MAPPING.get(
            protocol,
            0
        ),

        "severity": SEVERITY_MAPPING.get(
            severity,
            1
        ),

        "event_type": EVENT_TYPE_MAPPING.get(
            event_type,
            -1
        ),

        "is_ssh": int(
            event.destination_port == 22
        ),

        "is_http": int(
            event.destination_port in [80, 443]
        ),

        "is_suspicious_port": int(
            event.destination_port in [
                21,
                23,
                445,
                3389
            ]
        ),

        "is_failed_login": int(
            event_type in [
                "SSH_LOGIN_FAILURE",
                "SSH_LOGIN_FAILED"
            ]
        ),

        "is_port_scan": int(
            event_type == "PORT_SCAN"
        ),

        "is_malware": int(
            event_type in [
                "MALWARE",
                "MALWARE_DETECTED"
            ]
        )
    }


def extract_behavior_features(
    event: SecurityEvent,
    session: Session
) -> dict:

    behavior = analyze_ip_behavior(
        session,
        event.source_ip
    )

    return {
        "suspicious_event_count": (
            behavior["suspicious_event_count"]
        ),

        "behavior_score": (
            behavior["behavior_score"]
        )
    }


def create_feature_vector(
    event: SecurityEvent,
    session: Session
) -> dict:

    features = extract_features(event)

    behavior_features = extract_behavior_features(
        event,
        session
    )

    features.update(
        behavior_features
    )

    return features


def features_to_list(
    features: dict
) -> list:

    return [
        features[name]
        for name in FEATURE_NAMES
    ]