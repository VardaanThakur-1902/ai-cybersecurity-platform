from datetime import datetime

from sqlmodel import Session, select

from models.security_event import SecurityEvent
from detection.rule_engine import analyze_event
from services.behavior_service import analyze_ip_behavior
from services.alert_service import create_alert

from ml.feature_engineering import create_feature_vector
from ml.predict import predict_threat


def create_event(
    session: Session,
    event: SecurityEvent
) -> SecurityEvent:

    if isinstance(event.timestamp, str):
        event.timestamp = datetime.fromisoformat(event.timestamp)

    # Save event first so it gets an ID
    session.add(event)
    session.commit()
    session.refresh(event)

    # Individual event detection
    detection_result = analyze_event(event)

    # IP behavioral detection
    behavior_result = analyze_ip_behavior(
        session,
        event.source_ip
    )

    # -----------------------------------------
    # ML threat prediction
    # -----------------------------------------

    features = create_feature_vector(event, session)

    ml_result = predict_threat(features)

    ml_prediction = ml_result["prediction"]
    ml_probability = ml_result["attack_probability"]

    # Combine scores
        # -----------------------------------------
    # Combine rule + behavior + ML scores
    # -----------------------------------------

    rule_score = detection_result["threat_score"]
    behavior_score = behavior_result["behavior_score"]

    ml_score = int(ml_probability * 40)

    final_score = (
        rule_score
        + behavior_score
        + ml_score
    )

    final_score = min(final_score, 100)

    final_score = min(final_score, 100)

    # Determine final threat level
    if final_score >= 80:
        final_level = "CRITICAL"

    elif final_score >= 60:
        final_level = "HIGH"

    elif final_score >= 30:
        final_level = "MEDIUM"

    else:
        final_level = "LOW"

    # Store detection result
    event.threat_score = final_score
    event.threat_level = final_level
    event.threat_type = detection_result["threat_type"]

    reasons = detection_result["reasons"].copy()

    if behavior_result["behavior_score"] > 0:
        reasons.append(
            f"{behavior_result['suspicious_event_count']} "
            f"suspicious events detected from this IP"
        )

        reasons.append(
        f"ML attack probability: {ml_probability:.2f}"
    )

    if ml_prediction == 1:
        reasons.append("ML model classified event as suspicious")

    event.detection_reasons = "; ".join(reasons)
    event.detected_at = datetime.utcnow()

    session.add(event)
    session.commit()
    session.refresh(event)

    # Generate alert for HIGH / CRITICAL threats
    if event.threat_level in ["HIGH", "CRITICAL"]:
        create_alert(session, event)

    return event


def get_events(
    session: Session
) -> list[SecurityEvent]:

    statement = select(SecurityEvent)

    return list(session.exec(statement))