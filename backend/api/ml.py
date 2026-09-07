from fastapi import APIRouter, Depends
from sqlmodel import Session

from database.database import get_session
from models.security_event import SecurityEvent
from ml.feature_engineering import create_feature_vector
from ml.predict import predict_threat


router = APIRouter(
    prefix="/ml",
    tags=["Machine Learning"]
)


@router.post("/predict")
def predict_event(
    event: SecurityEvent,
    session: Session = Depends(get_session)
):
    """
    Predict whether a security event is malicious
    using the trained ML model.
    """

    features = create_feature_vector(
        event,
        session
    )

    result = predict_threat(features)

    return {
        "prediction": result["prediction"],
        "classification": (
            "MALICIOUS"
            if result["prediction"] == 1
            else "BENIGN"
        ),
        "attack_probability": result["attack_probability"],
        "features": features
    }