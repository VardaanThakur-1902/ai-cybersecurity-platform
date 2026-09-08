import os
import glob
import joblib

import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)


DATA_DIR = "../data/raw"
MODEL_PATH = "ml/model/cicids_threat_detector.joblib"

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
    "Idle Mean"
]


# --------------------------------------------------
# Load model
# --------------------------------------------------

print("Loading model...")

model = joblib.load(MODEL_PATH)


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

files = glob.glob(
    os.path.join(DATA_DIR, "*.csv")
)

frames = []

for file in files:

    print(f"Loading: {file}")

    df = pd.read_csv(
        file,
        encoding="latin1",
        low_memory=False
    )

    frames.append(df)


data = pd.concat(
    frames,
    ignore_index=True
)


data.columns = (
    data.columns
    .str.strip()
)


# --------------------------------------------------
# Create binary target
# --------------------------------------------------

data["target"] = (
    data["Label"]
    .astype(str)
    .str.strip()
    .str.upper()
    .ne("BENIGN")
    .astype(int)
)


# --------------------------------------------------
# Prepare features
# --------------------------------------------------

X = data[FEATURES].copy()

y = data["target"]


# Convert all features to numeric
X = X.apply(
    pd.to_numeric,
    errors="coerce"
)

# Replace infinity values with NaN
X = X.replace(
    [float("inf"), float("-inf")],
    float("nan")
)

# Remove rows containing invalid values
valid_rows = X.notna().all(axis=1)

X = X.loc[valid_rows].copy()
y = y.loc[valid_rows].copy()

# --------------------------------------------------
# Use same sample size as training
# --------------------------------------------------

MAX_ROWS = 200000

if len(X) > MAX_ROWS:

    sample_indices = (
        X.sample(
            n=MAX_ROWS,
            random_state=42
        ).index
    )

    X = X.loc[sample_indices]

    y = y.loc[sample_indices]


# --------------------------------------------------
# Predictions
# --------------------------------------------------

print("\nGenerating predictions...")

predictions = model.predict(X)


# --------------------------------------------------
# Evaluation
# --------------------------------------------------

accuracy = accuracy_score(
    y,
    predictions
)


print("\n==============================")
print("MODEL EVALUATION")
print("==============================")

print(
    f"\nAccuracy: {accuracy:.4f}"
)


print("\nClassification Report:")

print(
    classification_report(
        y,
        predictions,
        target_names=[
            "BENIGN",
            "ATTACK"
        ]
    )
)


# --------------------------------------------------
# Confusion matrix
# --------------------------------------------------

cm = confusion_matrix(
    y,
    predictions
)


print("\nConfusion Matrix:")

print(cm)


os.makedirs(
    "ml/evaluation",
    exist_ok=True
)


disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=[
        "BENIGN",
        "ATTACK"
    ]
)


disp.plot()

plt.title(
    "CIC-IDS2017 Threat Detection Confusion Matrix"
)

plt.tight_layout()

plt.savefig(
    "ml/evaluation/confusion_matrix.png",
    dpi=300
)

plt.close()


# --------------------------------------------------
# Feature importance
# --------------------------------------------------

importance = model.feature_importances_


feature_importance = pd.DataFrame({
    "feature": FEATURES,
    "importance": importance
})


feature_importance = (
    feature_importance
    .sort_values(
        "importance",
        ascending=False
    )
)


print("\n==============================")
print("FEATURE IMPORTANCE")
print("==============================")


print(
    feature_importance.to_string(
        index=False
    )
)


# --------------------------------------------------
# Feature importance plot
# --------------------------------------------------

plt.figure(
    figsize=(10, 7)
)


plt.barh(
    feature_importance["feature"],
    feature_importance["importance"]
)


plt.gca().invert_yaxis()


plt.xlabel(
    "Importance"
)

plt.ylabel(
    "Feature"
)

plt.title(
    "Random Forest Feature Importance"
)


plt.tight_layout()


plt.savefig(
    "ml/evaluation/feature_importance.png",
    dpi=300
)


plt.close()


# --------------------------------------------------
# Save feature importance
# --------------------------------------------------

feature_importance.to_csv(
    "ml/evaluation/feature_importance.csv",
    index=False
)


print(
    "\nEvaluation files saved to:"
)

print(
    "ml/evaluation/confusion_matrix.png"
)

print(
    "ml/evaluation/feature_importance.png"
)

print(
    "ml/evaluation/feature_importance.csv"
)