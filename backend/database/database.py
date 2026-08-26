from sqlmodel import SQLModel, Session, create_engine

from models.security_event import SecurityEvent
from models.security_alert import SecurityAlert


DATABASE_URL = "sqlite:///cybersecurity.db"

engine = create_engine(
    DATABASE_URL,
    echo=True
)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session