#!/usr/bin/env python3
# =============================
# codeGuardian Static Feature Inference Script - Phase 2
# Author: Urva Gandhi
# Model: XGBoost (Inference Mode)
# Purpose: Ultra-fast vulnerability probability prediction
# Standard: CodeGuardian Inference Standard v5.1
# =============================

"""
CodeGuardian Static Inference Engine - Production Standard v5.1
===================================================================
Production-ready Ultra-Fast Inference Engine for Static Features.
Loads decoupled artifacts (Model, Scaler, Metadata) and performs sub-20ms inference.

Features:
✅ Decoupled Artifact Loading (Model, Scaler, Metadata)
✅ Strict 107-Feature Schema Validation
✅ Feature Vector Normalization (List/Dict support)
✅ Pre-processing Pipeline integration (Imputer + Scaler)
✅ Structured JSON Output (Probability, Label, Confidence, Version)
✅ High-performance (<20ms latency target)
✅ Error Handling & Graceful Failures

Inference Configuration:
- Input: List[107] or Dict
- Output: JSON
- Artifacts: static_model_{type}.pkl, static_scaler.pkl, metadata.json

Usage (CLI):
    python src/ml/inference/inference_static.py --features-file row.json
    python src/ml/inference/inference_static.py --features-raw "0.5, 12.0, ..."

Usage (API):
    from src.ml.inference.inference_static import StaticInferenceEngine
    engine = StaticInferenceEngine()
    result = engine.predict(features)
"""

import argparse
import json
import time
import sys
import joblib
import numpy as np
from pathlib import Path
from typing import Union, List, Dict, Any, Optional

# Constants
EXPECTED_FEATURE_COUNT = 107
STATIC_MODELS_DIR = Path("models/static").resolve()
# Robust default path that works across environments (Kaggle, local, etc.)

class StaticInferenceEngine:
    def __init__(self, models_dir: Optional[Union[str, Path]] = None):
        if models_dir:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = STATIC_MODELS_DIR

        self.model = None
        self.scaler = None
        self.metadata = None
        self.feature_order = None

        self._load_artifacts()

    def _load_artifacts(self):
        """Loads model, scaler, and metadata from disk."""
        scaler_path = self.models_dir / "static_scaler.pkl"
        metadata_path = self.models_dir / "metadata.json"

        # PATCH 1: Auto-detect model file (supports xgb, lgb, rf, lr, svm)
        model_files = list(self.models_dir.glob("static_model_*.pkl"))
        if len(model_files) == 0:
            raise FileNotFoundError(
                f"No static_model_*.pkl found in {self.models_dir}. "
                "Ensure train_static.py has been run."
            )
        model_path = model_files[0]

        if not scaler_path.exists():
            raise FileNotFoundError(f"Missing static_scaler.pkl in {self.models_dir}")
        if not metadata_path.exists():
            raise FileNotFoundError(f"Missing metadata.json in {self.models_dir}")

        try:
            # Using joblib for fast loading
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)

            with open(metadata_path, 'r') as f:
                self.metadata = json.load(f)

            self.feature_order = self.metadata.get("feature_order", [])

            # PATCH 2: Enforce strict feature count validation
            if len(self.feature_order) != EXPECTED_FEATURE_COUNT:
                raise ValueError(
                    f"Feature order mismatch ({len(self.feature_order)}). "
                    f"Expected {EXPECTED_FEATURE_COUNT}. Static inference aborted."
                )

        except Exception as e:
            raise RuntimeError(f"Failed to load static inference artifacts: {e}")

    def predict(self, features: Union[List[float], Dict[str, float]]) -> Dict[str, Any]:
        """
        Runs inference on a single record.

        Args:
            features: List of 107 floats OR Dictionary {feature_name: value}

        Returns:
            Dict containing probability, label, confidence, etc.
        """
        start_time = time.perf_counter()

        # 1. Normalizing Input
        feature_vector = []

        if isinstance(features, dict):
            # Map dict to list using feature_order
            try:
                feature_vector = [float(features.get(f, 0.0)) for f in self.feature_order]
            except ValueError as e:
                return self._error_response("Feature values must be numeric", start_time)
        elif isinstance(features, (list, tuple, np.ndarray)):
            # Validate length
            if len(features) != len(self.feature_order):
                return self._error_response(
                    f"Expected {len(self.feature_order)} features, got {len(features)}",
                    start_time
                )
            try:
                feature_vector = [float(x) for x in features]
            except ValueError:
                return self._error_response("Feature values must be numeric", start_time)
        else:
            return self._error_response("Invalid input format. Expected list or dict.", start_time)

        # 2. Reshape for sklearn (1, n_features)
        X = np.array(feature_vector).reshape(1, -1)

        # 3. Scale (Pre-processing pipeline includes Imputer + Scaler)
        try:
            X_scaled = self.scaler.transform(X)
        except Exception as e:
            return self._error_response(f"Scaling failed: {e}", start_time)

        # 4. Predict
        try:
            # predict_proba returns [prob_0, prob_1]
            probs = self.model.predict_proba(X_scaled)[0]
            prob_vuln = float(probs[1]) # Probability of class 1 (Vulnerable)

            # Decide label (0.5 threshold is standard, but fusion layer might override)
            label = 1 if prob_vuln >= 0.5 else 0

            # Confidence is distance from 0.5 boundary * 2 (0.5 -> 0, 1.0 -> 1, 0.0 -> 1)
            confidence = abs(prob_vuln - 0.5) * 2

        except Exception as e:
            return self._error_response(f"Model inference failed: {e}", start_time)

        inference_time = time.perf_counter() - start_time

        return {
            "probability": prob_vuln,
            "class_label": label,
            "confidence": confidence,
            "model_version": self.metadata.get("model_version", "unknown"),
            "inference_time_seconds": inference_time
        }

    def _error_response(self, msg: str, start_time: float) -> Dict[str, Any]:
        return {
            "error": msg,
            "probability": -1.0,
            "class_label": -1,
            "inference_time_seconds": time.perf_counter() - start_time
        }


def main():
    parser = argparse.ArgumentParser(description="Static Engine Inference CLI")
    parser.add_argument("--features-file", help="Path to JSON file containing features (list or dict)")
    parser.add_argument("--features-raw", help="Comma-separated string of numbers", type=str)
    parser.add_argument("--models-dir", help="Path to models directory", default=None)

    args = parser.parse_args()

    try:
        engine = StaticInferenceEngine(models_dir=args.models_dir)

        features = None
        if args.features_file:
            with open(args.features_file, 'r') as f:
                features = json.load(f)
        elif args.features_raw:
            features = [float(x.strip()) for x in args.features_raw.split(',')]
        else:
            # Demo / Test Input
            # Generate random 107 features
            features = np.random.rand(107).tolist()

        result = engine.predict(features)
        print(json.dumps(result, indent=2))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()
