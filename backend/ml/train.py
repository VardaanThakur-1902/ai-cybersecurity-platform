from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


# Project paths
BASE_DIR = Path(__file__).resolve().parents[2]

DATA_PATH = BASE_DIR / "data" / "sample_ml_data.csv"

MODEL_DIR = Path(__file__).resolve().parent / "model"
MODEL_PATH = MODEL_DIR / "threat_detector.joblib"


# Load dataset
df = pd.read_csv(DATA_PATH)

print("Dataset loaded")
print(f"Rows: {len(df)}")
print(f"Columns: {len(df.columns)}")


# Features
features = [
    "duration",
    "source_bytes",
    "destination_bytes",
    "source_port",
    "destination_port",
    "failed_attempts",
    "packet_count"
]

X = df[features]

# Target
y = df["label"]


# Convert labels to numbers
y = y.map({
    "normal": 0,
    "attack": 1
})


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.3,
    random_state=42,
    stratify=y
)


# Create model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# Train
model.fit(X_train, y_train)


# Evaluate
predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print(f"\nAccuracy: {accuracy:.2f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["normal", "attack"]
    )
)


# Save model
MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_PATH
)

print(f"\nModel saved to:")
print(MODEL_PATH)