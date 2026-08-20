import csv
import io
from datetime import datetime

from sqlmodel import Session

from models.security_event import SecurityEvent
from services.log_service import create_event


def process_csv(
    file_content: bytes,
    session: Session
) -> int:

    text = file_content.decode("utf-8")

    reader = csv.DictReader(io.StringIO(text))

    count = 0

    for row in reader:
        event = SecurityEvent(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source_ip=row["source_ip"],
            destination_ip=row.get("destination_ip"),
            source_port=int(row["source_port"]) if row.get("source_port") else None,
            destination_port=(
                int(row["destination_port"])
                if row.get("destination_port")
                else None
            ),
            protocol=row.get("protocol"),
            event_type=row["event_type"],
            severity=row.get("severity", "low"),
            message=row["message"],
            is_malicious=(
                row["is_malicious"].lower() == "true"
                if row.get("is_malicious")
                else None
            ),
        )

        create_event(session, event)
        count += 1

    return count