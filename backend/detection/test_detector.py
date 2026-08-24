from datetime import datetime

from models.security_event import SecurityEvent
from detection.rule_engine import analyze_event


event = SecurityEvent(
    timestamp=datetime.fromisoformat("2026-08-24T20:00:00"),
    source_ip="185.10.20.30",
    destination_ip="192.168.1.10",
    source_port=54321,
    destination_port=22,
    protocol="TCP",
    event_type="SSH_LOGIN_FAILURE",
    severity="high",
    message="Multiple failed SSH login attempts"
)


result = analyze_event(event)

print(result)