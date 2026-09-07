import os
import glob

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


DATA_DIR = "../data/raw"
MODEL_DIR = "ml/model"
MODEL_PATH = os.path.join(
    MODEL_DIR,
    "cicids_threat_detector.joblib"
)


# --------------------------------------------------
# Load CSV files
# --------------------------------------------------

files = glob.glob(
    os.path.join(DATA_DIR, "*.csv")
)

if not files:
    raise FileNotFoundError(
        f"No CSV files found in {DATA_DIR}"
    )


print(f"Found {len(files)} CSV files")


frames = []

for file in files:

    print(f"Loading: {file}")

    df = pd.read_csv(
        file,
        encoding="latin1"
    )

    frames.append(df)


data = pd.concat(
    frames,
    ignore_index=True
)


print("\nDataset shape:")
print(data.shape)


# --------------------------------------------------
# Clean column names
# --------------------------------------------------

data.columns = (
    data.columns
    .str.strip()
)


# --------------------------------------------------
# Normalize labels
# --------------------------------------------------

label_column = "Label"

if label_column not in data.columns:
    raise ValueError(
        "Label column not found in dataset"
    )


data[label_column] = (
    data[label_column]
    .astype(str)
    .str.strip()
)


# --------------------------------------------------
# Convert labels to binary
# --------------------------------------------------

data["target"] = (
    data[label_column]
    .str.upper()
    .ne("BENIGN")
    .astype(int)
)


print("\nLabel distribution:")

print(
    data["target"]
    .value_counts()
)


# --------------------------------------------------
# Select useful network features
# --------------------------------------------------

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


missing_features = [
    feature
    for feature in FEATURES
    if feature not in data.columns
]


if missing_features:

    raise ValueError(
        "Missing features:\n"
        + "\n".join(missing_features)
    )


X = data[FEATURES].copy()

y = data["target"]


# --------------------------------------------------
# Clean numeric values
# --------------------------------------------------

# Convert all selected features to numeric first
X = X.apply(
    pd.to_numeric,
    errors="coerce"
)

# Replace positive/negative infinity with NaN
X = X.replace(
    [float("inf"), float("-inf")],
    float("nan")
)

# Remove rows containing invalid values
valid_rows = X.notna().all(axis=1)

X = X.loc[valid_rows].copy()

y = y.loc[valid_rows].copy()


# --------------------------------------------------
# Limit dataset for local development
# --------------------------------------------------

MAX_ROWS = 200000

if len(X) > MAX_ROWS:

    sampled_indices = (
        X.sample(
            n=MAX_ROWS,
            random_state=42
        ).index
    )

    X = X.loc[sampled_indices]

    y = y.loc[sampled_indices]


print("\nTraining rows:")
print(len(X))


# --------------------------------------------------
# Train/test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining set:")
print(X_train.shape)

print("\nTesting set:")
print(X_test.shape)


# --------------------------------------------------
# Train Random Forest
# --------------------------------------------------

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


print("\nTraining model...")

model.fit(
    X_train,
    y_train
)


# --------------------------------------------------
# Predictions
# --------------------------------------------------

predictions = model.predict(
    X_test
)


# --------------------------------------------------
# Evaluation
# --------------------------------------------------

accuracy = accuracy_score(
    y_test,
    predictions
)


print("\n==============================")
print("MODEL RESULTS")
print("==============================")

print(
    f"\nAccuracy: {accuracy:.4f}"
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "BENIGN",
            "ATTACK"
        ]
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# --------------------------------------------------
# Save model
# --------------------------------------------------

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


import joblib

joblib.dump(
    model,
    MODEL_PATH
)


print(
    f"\nModel saved to:\n{MODEL_PATH}"
)