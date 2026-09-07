import os
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


MODEL_DIR = "ml/model"
MODEL_PATH = os.path.join(MODEL_DIR, "threat_detector.joblib")


# --------------------------------------------------
# Create training data
# --------------------------------------------------

data = [
    # source_port, destination_port, protocol, severity,
    # event_type, is_ssh, is_http, is_suspicious_port,
    # is_failed_login, is_port_scan, is_malware,
    # suspicious_event_count, behavior_score, label

    [12345, 80, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    [12346, 443, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    [12347, 8080, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0],
    [12348, 22, 1, 2, 2, 1, 0, 0, 1, 0, 0, 3, 20, 1],
    [12349, 22, 1, 3, 2, 1, 0, 0, 1, 0, 0, 5, 30, 1],
    [12350, 23, 1, 4, 6, 0, 0, 1, 0, 0, 0, 10, 40, 1],
    [12351, 445, 1, 4, 4, 0, 0, 1, 0, 0, 1, 10, 40, 1],
    [12352, 3389, 1, 4, 4, 0, 0, 1, 0, 0, 1, 5, 30, 1],
    [12353, 21, 1, 3, 5, 0, 0, 1, 0, 0, 1, 3, 20, 1],
    [12354, 80, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    [12355, 443, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    [12356, 22, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    [12357, 22, 1, 2, 1, 1, 0, 0, 0, 0, 0, 1, 10, 0],
    [12358, 22, 1, 4, 2, 1, 0, 0, 1, 1, 0, 5, 30, 1],
    [12359, 445, 1, 4, 4, 0, 0, 1, 0, 0, 1, 10, 40, 1],
    [12360, 80, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    [12361, 443, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [12362, 3389, 1, 3, 6, 0, 0, 1, 0, 0, 0, 3, 20, 1],
    [12363, 23, 1, 4, 6, 0, 0, 1, 0, 0, 0, 5, 30, 1],
    [12364, 22, 1, 2, 2, 1, 0, 0, 1, 0, 0, 3, 20, 1],
]


FEATURE_NAMES = [
    "source_port",
    "destination_port",
    "protocol",
    "severity",
    "event_type",
    "is_ssh",
    "is_http",
    "is_suspicious_port",
    "is_failed_login",
    "is_port_scan",
    "is_malware",
    "suspicious_event_count",
    "behavior_score",
]


columns = FEATURE_NAMES + ["label"]

df = pd.DataFrame(data, columns=columns)

X = df[FEATURE_NAMES]
y = df["label"]


# --------------------------------------------------
# Train / test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


# --------------------------------------------------
# Train Random Forest
# --------------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)


# --------------------------------------------------
# Evaluate
# --------------------------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nModel Accuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, predictions))


# --------------------------------------------------
# Save model
# --------------------------------------------------

os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(model, MODEL_PATH)

print(f"\nModel saved to: {MODEL_PATH}")