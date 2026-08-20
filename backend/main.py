from fastapi import FastAPI

app = FastAPI(
    title="AI-Powered Cybersecurity Platform",
    description="AI-powered cybersecurity threat detection and analysis platform",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "message": "AI Cybersecurity Platform is running",
        "version": "0.1.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }