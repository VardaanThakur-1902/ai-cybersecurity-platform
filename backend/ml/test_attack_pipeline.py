import glob
import os

import pandas as pd

from sqlmodel import Session

from database.database import engine
from models.network_flow import NetworkFlow

from ml.cic_predict import predict_cic_threat
from ml.cic_features import CIC_FEATURE_NAMES

from services.network_threat_service import (
    calculate_network_threat
)

from services.alert_service import (
    create_network_flow_alert
)


DATA_DIR = "../data/raw"


def find_real_attack():

    files = glob.glob(
        os.path.join(DATA_DIR, "*.csv")
    )

    for file in files:

        df = pd.read_csv(
            file,
            encoding="latin1",
            low_memory=False
        )

        df.columns = (
            df.columns
            .str.strip()
        )

        attack_mask = (
            df["Label"]
            .astype(str)
            .str.strip()
            .str.upper()
            != "BENIGN"
        )

        attacks = df.loc[attack_mask]

        if not attacks.empty:

            return (
                attacks.iloc[0],
                df,
                file
            )

    raise ValueError(
        "No attack found."
    )


def main():

    row, _, file = find_real_attack()

    print("\n==============================")
    print("REAL ATTACK")
    print("==============================")

    print(
        "File:",
        os.path.basename(file)
    )

    print(
        "Label:",
        row["Label"]
    )

    # -----------------------------------------
    # Extract features
    # -----------------------------------------

    features = {}

    for feature in CIC_FEATURE_NAMES:

        value = pd.to_numeric(
            row[feature],
            errors="coerce"
        )

        if pd.isna(value):
            value = 0

        features[feature] = float(value)

    # -----------------------------------------
    # ML prediction
    # -----------------------------------------

    prediction = predict_cic_threat(
        features
    )

    print("\nML Prediction:")
    print(prediction)

    # -----------------------------------------
    # Threat scoring
    # -----------------------------------------

    threat = calculate_network_threat(
        prediction["prediction"],
        prediction["attack_probability"]
    )

    print("\nThreat Result:")
    print(threat)

    # -----------------------------------------
    # Create NetworkFlow
    # -----------------------------------------

    flow = NetworkFlow(
        source_ip=str(
            row.get("Source IP", "unknown")
        ),

        destination_ip=str(
            row.get(
                "Destination IP",
                "unknown"
            )
        ),

        flow_duration=features[
            "Flow Duration"
        ],

        total_fwd_packets=features[
            "Total Fwd Packets"
        ],

        total_backward_packets=features[
            "Total Backward Packets"
        ],

        total_length_fwd_packets=features[
            "Total Length of Fwd Packets"
        ],

        total_length_bwd_packets=features[
            "Total Length of Bwd Packets"
        ],

        fwd_packet_length_max=features[
            "Fwd Packet Length Max"
        ],

        fwd_packet_length_min=features[
            "Fwd Packet Length Min"
        ],

        bwd_packet_length_max=features[
            "Bwd Packet Length Max"
        ],

        bwd_packet_length_min=features[
            "Bwd Packet Length Min"
        ],

        flow_bytes_per_second=features[
            "Flow Bytes/s"
        ],

        flow_packets_per_second=features[
            "Flow Packets/s"
        ],

        fwd_iat_total=features[
            "Fwd IAT Total"
        ],

        bwd_iat_total=features[
            "Bwd IAT Total"
        ],

        fwd_psh_flags=features[
            "Fwd PSH Flags"
        ],

        bwd_psh_flags=features[
            "Bwd PSH Flags"
        ],

        syn_flag_count=features[
            "SYN Flag Count"
        ],

        ack_flag_count=features[
            "ACK Flag Count"
        ],

        urg_flag_count=features[
            "URG Flag Count"
        ],

        average_packet_size=features[
            "Average Packet Size"
        ],

        active_mean=features[
            "Active Mean"
        ],

        idle_mean=features[
            "Idle Mean"
        ],

        ml_prediction=prediction[
            "prediction"
        ],

        attack_probability=prediction[
            "attack_probability"
        ],

        threat_score=threat[
            "threat_score"
        ],

        threat_level=threat[
            "threat_level"
        ],

        threat_type=threat[
            "threat_type"
        ],

        detection_reasons=threat[
            "detection_reasons"
        ],

        label=str(row["Label"])
    )

    # -----------------------------------------
    # Save flow + alert
    # -----------------------------------------

    with Session(engine) as session:

        session.add(flow)

        session.commit()

        session.refresh(flow)

        flow_id = flow.id
        flow_threat_level = flow.threat_level
        flow_threat_score = flow.threat_score

        alert = None
        alert_id = None

        if flow.threat_level in [
            "HIGH",
            "CRITICAL"
        ]:

            alert = create_network_flow_alert(
                session,
                flow
            )

            if alert:
                session.refresh(alert)
                alert_id = alert.id

    print("\n==============================")
    print("DATABASE RESULT")
    print("==============================")

    print(
        "Flow ID:",
        flow_id
    )

    print(
        "Threat level:",
        flow_threat_level
    )

    print(
        "Threat score:",
        flow_threat_score
    )

    print(
        "Alert ID:",
        alert_id
    )


if __name__ == "__main__":
    main()