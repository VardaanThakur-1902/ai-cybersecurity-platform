from fastapi import FastAPI

from database.database import create_db_and_tables
from api.logs import router as logs_router


app = FastAPI(
    title="AI-Powered Cybersecurity Platform",
    description="AI-powered cybersecurity threat detection and analysis platform",
    version="0.2.0"
)


@app.on_event("startup")
def startup():
    create_db_and_tables()


@app.get("/")
def root():
    return {
        "message": "AI Cybersecurity Platform is running",
        "version": "0.2.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


app.include_router(logs_router)