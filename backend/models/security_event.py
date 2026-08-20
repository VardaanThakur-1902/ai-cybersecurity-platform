from datetime import datetime

from sqlmodel import Field, SQLModel


class SecurityEvent(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    timestamp: datetime

    source_ip: str
    destination_ip: str | None = None

    source_port: int | None = None
    destination_port: int | None = None

    protocol: str | None = None

    event_type: str
    severity: str = "low"

    message: str

    is_malicious: bool | None = None