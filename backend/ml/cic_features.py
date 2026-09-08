from models.security_event import SecurityEvent


CIC_FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd IAT Total",
    "Bwd IAT Total",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "SYN Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Average Packet Size",
    "Active Mean",
    "Idle Mean",
]


def event_to_cic_features(
    event: SecurityEvent
) -> dict:

    source_port = event.source_port or 0
    destination_port = event.destination_port or 0

    # Basic values available from SecurityEvent
    packet_size = max(
        source_port % 1500,
        destination_port % 1500,
        64
    )

    suspicious = (
        event.threat_level in ["HIGH", "CRITICAL"]
        or event.event_type in [
            "PORT_SCAN",
            "MALWARE",
            "MALWARE_DETECTED",
            "SSH_LOGIN_FAILURE",
            "SSH_LOGIN_FAILED",
        ]
    )

    return {
        "Flow Duration": 0,
        "Total Fwd Packets": 1,
        "Total Backward Packets": 1,

        "Total Length of Fwd Packets": packet_size,
        "Total Length of Bwd Packets": packet_size,

        "Fwd Packet Length Max": packet_size,
        "Fwd Packet Length Min": packet_size,

        "Bwd Packet Length Max": packet_size,
        "Bwd Packet Length Min": packet_size,

        "Flow Bytes/s": 0,
        "Flow Packets/s": 0,

        "Fwd IAT Total": 0,
        "Bwd IAT Total": 0,

        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,

        "SYN Flag Count": (
            1 if destination_port in [22, 80, 443]
            else 0
        ),

        "ACK Flag Count": 1,

        "URG Flag Count": (
            1 if suspicious else 0
        ),

        "Average Packet Size": packet_size,

        "Active Mean": 0,
        "Idle Mean": 0,
    }


def cic_features_to_list(
    features: dict
) -> list:

    return [
        features[name]
        for name in CIC_FEATURE_NAMES
    ]