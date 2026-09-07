import os
import joblib

from ml.feature_engineering import FEATURE_NAMES


MODEL_PATH = "ml/model/threat_detector.joblib"


model = joblib.load(MODEL_PATH)


def predict_threat(features: dict):

    feature_vector = [
        features[name]
        for name in FEATURE_NAMES
    ]

    prediction = model.predict([feature_vector])[0]

    probabilities = model.predict_proba([feature_vector])[0]

    attack_probability = probabilities[1]

    return {
        "prediction": int(prediction),
        "attack_probability": round(
            float(attack_probability),
            4
        )
    }