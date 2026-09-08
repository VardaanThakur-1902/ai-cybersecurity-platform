def calculate_network_threat(
    prediction: int,
    attack_probability: float
) -> dict:

    ml_score = round(
        attack_probability * 100
    )

    if prediction == 1:

        if attack_probability >= 0.80:
            threat_level = "CRITICAL"

        elif attack_probability >= 0.60:
            threat_level = "HIGH"

        elif attack_probability >= 0.30:
            threat_level = "MEDIUM"

        else:
            threat_level = "LOW"

    else:

        # A benign prediction should not
        # automatically become a high threat.
        if attack_probability >= 0.70:
            threat_level = "MEDIUM"
        elif attack_probability >= 0.40:
            threat_level = "LOW"
        else:
            threat_level = "LOW"

    reasons = [
        f"ML attack probability: {attack_probability:.2f}"
    ]

    if prediction == 1:
        reasons.append(
            "ML model classified network flow as malicious"
        )
    else:
        reasons.append(
            "ML model classified network flow as benign"
        )

    return {
        "threat_score": ml_score,
        "threat_level": threat_level,
        "threat_type": (
            "NETWORK_ATTACK"
            if prediction == 1
            else "NORMAL_NETWORK_TRAFFIC"
        ),
        "detection_reasons": "; ".join(reasons)
    }