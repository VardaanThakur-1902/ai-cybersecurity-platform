from datetime import datetime

from sqlmodel import Field, SQLModel


class SecurityEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    # Event information
    timestamp: datetime

    source_ip: str
    destination_ip: str | None = None

    source_port: int | None = None
    destination_port: int | None = None

    protocol: str | None = None

    event_type: str
    severity: str = "low"

    message: str

    # Original label if available
    is_malicious: bool | None = None

    # Detection results
    threat_score: int = 0
    threat_level: str = "LOW"
    threat_type: str = "NORMAL"
    detection_reasons: str | None = None

    # Time when detection was performed
    detected_at: datetime | None = None