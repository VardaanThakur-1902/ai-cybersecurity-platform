from datetime import datetime

from models.security_event import SecurityEvent
from ml.feature_engineering import extract_features


event = SecurityEvent(
    timestamp=datetime.fromisoformat(
        "2026-09-02T20:00:00"
    ),

    source_ip="185.10.20.50",

    destination_ip="192.168.1.10",

    source_port=50001,

    destination_port=22,

    protocol="TCP",

    event_type="SSH_LOGIN_FAILURE",

    severity="high",

    message="Failed SSH login attempt"
)


features = extract_features(event)

print("Extracted Features:")
print(features)