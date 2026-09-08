from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from database.database import get_session
from models.network_flow import NetworkFlow

from ml.cic_features import (
    CIC_FEATURE_NAMES,
)

from ml.cic_predict import (
    predict_cic_threat,
)

from services.network_threat_service import (
    calculate_network_threat
)

from services.alert_service import (
    create_network_flow_alert
)

router = APIRouter(
    prefix="/network-flows",
    tags=["Network Flows"]
)


def flow_to_features(
    flow: NetworkFlow
) -> dict:

    return {
        "Flow Duration": flow.flow_duration,
        "Total Fwd Packets": flow.total_fwd_packets,
        "Total Backward Packets": flow.total_backward_packets,
        "Total Length of Fwd Packets": flow.total_length_fwd_packets,
        "Total Length of Bwd Packets": flow.total_length_bwd_packets,
        "Fwd Packet Length Max": flow.fwd_packet_length_max,
        "Fwd Packet Length Min": flow.fwd_packet_length_min,
        "Bwd Packet Length Max": flow.bwd_packet_length_max,
        "Bwd Packet Length Min": flow.bwd_packet_length_min,
        "Flow Bytes/s": flow.flow_bytes_per_second,
        "Flow Packets/s": flow.flow_packets_per_second,
        "Fwd IAT Total": flow.fwd_iat_total,
        "Bwd IAT Total": flow.bwd_iat_total,
        "Fwd PSH Flags": flow.fwd_psh_flags,
        "Bwd PSH Flags": flow.bwd_psh_flags,
        "SYN Flag Count": flow.syn_flag_count,
        "ACK Flag Count": flow.ack_flag_count,
        "URG Flag Count": flow.urg_flag_count,
        "Average Packet Size": flow.average_packet_size,
        "Active Mean": flow.active_mean,
        "Idle Mean": flow.idle_mean,
    }


@router.post("/")
def create_network_flow(
    flow: NetworkFlow,
    session: Session = Depends(get_session)
):
    # -----------------------------------------
    # Convert flow to ML features
    # -----------------------------------------

    features = flow_to_features(flow)

    # -----------------------------------------
    # Run CIC Random Forest
    # -----------------------------------------

    prediction = predict_cic_threat(
        features
    )

    threat_result = calculate_network_threat(
        prediction["prediction"],
        prediction["attack_probability"]
    )

    # -----------------------------------------
    # Store ML result
    # -----------------------------------------

    flow.ml_prediction = prediction[
        "prediction"
    ]

    flow.attack_probability = prediction[
        "attack_probability"
    ]

    flow.threat_score = threat_result[
        "threat_score"
    ]

    flow.threat_level = threat_result[
        "threat_level"
    ]

    flow.threat_type = threat_result[
        "threat_type"
    ]

    flow.detection_reasons = threat_result[
        "detection_reasons"
    ]

    # -----------------------------------------
    # Create alert for serious network threats
    # -----------------------------------------

    alert = None

    if flow.threat_level in [
        "HIGH",
        "CRITICAL"
    ]:

        alert = create_network_flow_alert(
            session,
            flow
        )

    session.add(flow)
    session.commit()
    session.refresh(flow)

    return {
        "flow": flow,
        "ml_result": prediction,
        "threat_result": threat_result,
        "alert": alert
    }


@router.get("/")
def get_network_flows(
    session: Session = Depends(get_session)
):
    statement = select(NetworkFlow)

    return list(
        session.exec(statement)
    )