from models.security_event import SecurityEvent

from ml.cic_features import (
    event_to_cic_features
)

from ml.cic_predict import (
    predict_cic_threat
)


event = SecurityEvent(
    timestamp="2026-09-08T01:00:00",
    source_ip="192.168.1.99",
    destination_ip="192.168.1.10",
    source_port=45678,
    destination_port=22,
    protocol="TCP",
    event_type="SSH_LOGIN_FAILURE",
    severity="high",
    message="Repeated failed SSH login attempts",
)


features = event_to_cic_features(
    event
)


print("\nCIC Features:")

for name, value in features.items():
    print(
        f"{name}: {value}"
    )


result = predict_cic_threat(
    features
)


print("\nPrediction:")
print(result)