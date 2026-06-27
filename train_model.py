"""train_model.py

Train a RandomForestClassifier to classify Smart Honeypot IDS events.

This script:
1) Loads a synthetic CSV dataset (dataset/training_data.csv)
2) Builds features (failed_attempts, login_speed, repeated_ips, suspicious_behavior_score)
3) Trains a supervised classifier
4) Saves the trained model to models/anomaly_model.joblib

Beginner-friendly notes (short):
- Supervised learning means we have examples with labels (Safe/Suspicious/Threat).
- Feature engineering means turning raw data into numbers the model can learn from.
- A classifier predicts the label for new events.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
DATASET_PATH = os.path.join(PROJECT_ROOT, "dataset", "training_data.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "anomaly_model.joblib")


@dataclass(frozen=True)
class TrainConfig:
    test_size: float = 0.2
    random_state: int = 42
    n_estimators: int = 200


FEATURES = [
    "failed_attempts",
    "login_speed",
    "repeated_ips",
    "suspicious_behavior_score",
]
LABEL_COL = "label"


def _load_dataset(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}")

    df = pd.read_csv(path)

    missing = [c for c in FEATURES + [LABEL_COL] if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    # Ensure numeric features
    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    # Drop rows with NaNs after coercion
    df = df.dropna(subset=FEATURES + [LABEL_COL])
    return df


def train_and_save_model(dataset_path: str = DATASET_PATH, model_path: str = MODEL_PATH) -> None:
    """Train the model and persist it with joblib."""

    cfg = TrainConfig()
    df = _load_dataset(dataset_path)

    X = df[FEATURES].to_numpy(dtype=float)
    y_raw = df[LABEL_COL].astype(str).to_numpy()

    # Encode string labels to integers for scikit-learn
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=cfg.test_size, random_state=cfg.random_state, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=cfg.n_estimators,
        random_state=cfg.random_state,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    # Basic sanity check
    accuracy = float(model.score(X_test, y_test))
    print(f"[train_model] Validation accuracy: {accuracy:.3f}")

    # Save everything needed for inference: model + label mapping + feature order
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    artifact = {
        "model": model,
        "label_encoder": label_encoder,
        "features": FEATURES,
    }
    joblib.dump(artifact, model_path)
    print(f"[train_model] Saved model artifact to: {model_path}")


if __name__ == "__main__":
    train_and_save_model()

