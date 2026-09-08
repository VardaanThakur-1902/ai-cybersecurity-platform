import glob
import os

import pandas as pd

from ml.cic_predict import predict_cic_threat


DATA_DIR = "../data/raw"


FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd IAT Total",
    "Bwd IAT Total",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "SYN Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Average Packet Size",
    "Active Mean",
    "Idle Mean",
]


# --------------------------------------------------
# Find CSV files
# --------------------------------------------------

files = glob.glob(
    os.path.join(DATA_DIR, "*.csv")
)

if not files:
    raise FileNotFoundError(
        "No CIC-IDS2017 CSV files found."
    )


print(f"Found {len(files)} CSV files.")


# --------------------------------------------------
# Find first real attack
# --------------------------------------------------

attack_row = None
attack_label = None
attack_file = None


for file in files:

    print(
        f"Checking: {os.path.basename(file)}"
    )

    df = pd.read_csv(
        file,
        encoding="latin1",
        low_memory=False
    )

    df.columns = (
        df.columns
        .str.strip()
    )

    # Find rows that aren't BENIGN
    attack_mask = (
        df["Label"]
        .astype(str)
        .str.strip()
        .str.upper()
        != "BENIGN"
    )

    attacks = df.loc[attack_mask]

    if not attacks.empty:

        attack_row = attacks.iloc[0]
        attack_label = attack_row["Label"]
        attack_file = file

        break


if attack_row is None:

    raise ValueError(
        "No attack records found."
    )


print("\n==============================")
print("REAL ATTACK FOUND")
print("==============================")

print(
    f"File: {os.path.basename(attack_file)}"
)

print(
    f"Label: {attack_label}"
)


# --------------------------------------------------
# Extract real CIC features
# --------------------------------------------------

features = {}


for feature in FEATURES:

    value = attack_row[feature]

    value = pd.to_numeric(
        value,
        errors="coerce"
    )

    if pd.isna(value):

        value = 0

    features[feature] = float(value)


# --------------------------------------------------
# Display features
# --------------------------------------------------

print("\nReal CIC Features:")

for name, value in features.items():

    print(
        f"{name}: {value}"
    )


# --------------------------------------------------
# Run ML prediction
# --------------------------------------------------

result = predict_cic_threat(
    features
)


print("\n==============================")
print("ML PREDICTION")
print("==============================")

print(
    f"Actual label: {attack_label}"
)

print(
    f"Prediction: {result['prediction']}"
)

print(
    f"Classification: {result['classification']}"
)

print(
    f"Attack probability: "
    f"{result['attack_probability']}"
)


# --------------------------------------------------
# Compare prediction with actual label
# --------------------------------------------------

print("\n==============================")
print("VALIDATION")
print("==============================")


if result["prediction"] == 1:

    print(
        "✓ Model classified the real "
        "attack as MALICIOUS."
    )

else:

    print(
        "✗ Model classified the real "
        "attack as BENIGN."
    )