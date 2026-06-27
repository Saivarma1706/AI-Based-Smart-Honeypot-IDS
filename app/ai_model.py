"""app.ai_model.py

AI-based anomaly detection for Smart Honeypot IDS.

This module loads a trained scikit-learn model (RandomForestClassifier)
from models/anomaly_model.joblib and predicts whether an event is:
- Safe
- Suspicious
- Threat

Cybersecurity intuition (beginner-friendly):
- Intrusion detection tries to classify observed login behavior as normal or harmful.
- A machine-learning model learns patterns from labeled examples.
- We pass structured numeric features (feature engineering) to the model.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import joblib

try:
    from .config import MODEL_PATH
except ImportError:  # pragma: no cover
    from config import MODEL_PATH


@dataclass(frozen=True)
class AiResult:
    predicted_label: str
    threat_score: float
    details: str


_MODEL_ARTIFACT: dict[str, Any] | None = None


def _load_artifact() -> dict[str, Any] | None:
    global _MODEL_ARTIFACT
    if _MODEL_ARTIFACT is not None:
        return _MODEL_ARTIFACT

    if not os.path.exists(MODEL_PATH):
        return None

    artifact = joblib.load(MODEL_PATH)
    _MODEL_ARTIFACT = artifact
    return artifact


def _features_from_input(features: dict[str, Any], ordered_features: list[str]) -> list[float]:
    """Extract features in the exact order expected by training."""

    values: list[float] = []
    for f in ordered_features:
        if f not in features:
            raise KeyError(f"Missing required feature: {f}")
        values.append(float(features[f]))
    return values


def ai_predict_label_and_score(features: dict[str, Any]) -> AiResult:
    """Predict Safe/Suspicious/Threat using a trained model. // TAMpered integrity test



    If the model isn't trained yet, the function falls back to a simple rule
    based on suspicious_behavior_score.
    """

    artifact = _load_artifact()
    if not artifact:
        # Safe fallback: if score is high, call it Threat/Suspicious.
        sb = float(features.get("suspicious_behavior_score", 0.0))
        if sb >= 70:
            label = "Threat"
            threat_score = min(100.0, sb)
        elif sb >= 35:
            label = "Suspicious"
            threat_score = min(100.0, sb * 1.2)
        else:
            label = "Safe"
            threat_score = min(100.0, sb)

        return AiResult(
            predicted_label=label,
            threat_score=threat_score,
            details="AI model not found; using fallback rule based on suspicious_behavior_score.",
        )

    model = artifact["model"]
    label_encoder = artifact["label_encoder"]
    ordered_features = artifact["features"]

    X = [_features_from_input(features, ordered_features)]

    # Predict label
    y_pred = model.predict(X)[0]
    label = str(label_encoder.inverse_transform([y_pred])[0])

    # Predict probability where available -> convert to a cybersecurity-friendly threat_score
    threat_score = 0.0
    details = "Prediction from trained RandomForestClassifier."

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]  # array aligned with encoded labels
        # We interpret highest-probability class as label; for score we map:
        # Threat -> 100, Suspicious -> 60, Safe -> 10 (based on probability weight).
        # This keeps a beginner-friendly, monotonic score.
        class_names = list(label_encoder.classes_)
        proba_by_label = {class_names[i]: float(proba[i]) for i in range(len(class_names))}

        if "Threat" in proba_by_label:
            threat_score = proba_by_label.get("Threat", 0.0) * 100.0
        elif len(proba_by_label) > 0:
            threat_score = max(proba) * 100.0

        details += " Probabilities used to compute threat_score."

    return AiResult(
        predicted_label=label,
        threat_score=float(max(0.0, min(100.0, threat_score))),
        details=details,
    )


# Backwards-compatible name expected by older scaffolds (if any)
# This keeps the rest of the app architecture stable.

def ai_predict_anomaly_score(features: dict[str, Any]) -> AiResult:
    """Predict anomaly label + threat score.

    This function name matches the existing project scaffold.
    It returns:
    - predicted_label: Safe / Suspicious / Threat
    - threat_score: 0..100 (beginner-friendly)
    """

    return ai_predict_label_and_score(features)


