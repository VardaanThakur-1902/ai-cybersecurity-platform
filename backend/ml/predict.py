from pathlib import Path

import joblib
import pandas as pd


MODEL_PATH = (
    Path(__file__).resolve().parent
    / "model"
    / "threat_detector.joblib"
)


FEATURES = [
    "duration",
    "source_bytes",
    "destination_bytes",
    "source_port",
    "destination_port",
    "failed_attempts",
    "packet_count"
]


model = joblib.load(MODEL_PATH)


def predict_threat(
    duration: float,
    source_bytes: float,
    destination_bytes: float,
    source_port: int,
    destination_port: int,
    failed_attempts: int,
    packet_count: int
) -> dict:

    data = pd.DataFrame([{
        "duration": duration,
        "source_bytes": source_bytes,
        "destination_bytes": destination_bytes,
        "source_port": source_port,
        "destination_port": destination_port,
        "failed_attempts": failed_attempts,
        "packet_count": packet_count
    }])

    prediction = model.predict(data)[0]

    probabilities = model.predict_proba(data)[0]

    attack_probability = probabilities[1]

    if prediction == 1:
        label = "attack"
    else:
        label = "normal"

    return {
        "prediction": label,
        "attack_probability": round(
            float(attack_probability),
            4
        )
    }