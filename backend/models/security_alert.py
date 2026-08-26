from datetime import datetime

from sqlmodel import Field, SQLModel


class SecurityAlert(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    event_id: int

    source_ip: str

    threat_type: str

    threat_level: str

    threat_score: int

    message: str

    is_acknowledged: bool = False

    created_at: datetime = Field(
        default_factory=datetime.utcnow
    )