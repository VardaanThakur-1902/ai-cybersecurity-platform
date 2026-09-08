import joblib
import pandas as pd

from ml.cic_features import (
    CIC_FEATURE_NAMES,
    cic_features_to_list,
)


MODEL_PATH = "ml/model/cicids_threat_detector.joblib"


model = joblib.load(MODEL_PATH)


def predict_cic_threat(features: dict) -> dict:

    feature_vector = cic_features_to_list(
        features
    )

    # Keep the same feature names used during training
    input_data = pd.DataFrame(
        [feature_vector],
        columns=CIC_FEATURE_NAMES
    )

    prediction = model.predict(
        input_data
    )[0]

    probabilities = model.predict_proba(
        input_data
    )[0]

    return {
        "prediction": int(prediction),
        "classification": (
            "MALICIOUS"
            if prediction == 1
            else "BENIGN"
        ),
        "attack_probability": round(
            float(probabilities[1]),
            4
        ),
    }