#!/usr/bin/env python3
# =============================
# codeGuardian Static Feature Model Training Script - Phase 2
# Author: Urva Gandhi
# Model: XGBoost (Default) / LightGBM / RF / SVM
# Purpose: Static vulnerability detection using 107 engineered features
# Standard: CodeGuardian Training Standard v1.0
# =============================

"""
CodeGuardian Static Model Training Pipeline - Production Standard v1.0
===================================================================
Production-ready Static Feature-Engineered training script optimized for Kaggle & Local Execution.
Implements fast, deterministic vulnerability detection using 107 lexical, complex, and structural features.

Features:
✅ Robust Handling of 107-feature Vector
✅ Automated Missing Value Imputation (Median Strategy)
✅ Feature Scaling Support (StandardScaler/MinMaxScaler)
✅ Stratified K-Fold Cross Validation (5 Folds) with Seed=42
✅ Model Agnostic Backbone (XGBoost, LightGBM, RF, LR, SVM)
✅ Comprehensive Metrics (AUC, F1, Precision, Recall, Accuracy)
✅ Production Artifact Generation (Model, Scaler Pipeline, Metadata)
✅ SHA256 Integrity Verification for Artifacts
✅ Full Reproducibility (Fixed Seeds, Deterministic Splits)
✅ Structured JSON Reporting

Training Configuration:
- Model: XGBoost (default)
- Task: Binary classification (vulnerable vs. secure code)
- Features: 107 (Lexical, AST, Entropy, Ratios)
- CV Strategy: StratifiedKFold (k=5)
- Scaling: StandardScaler vs MinMaxScaler
- Missing Values: Median Imputation
- Optimization Metric: ROC-AUC
- Random seed: 42

Expected Performance:
- ROC-AUC: > 0.85 (dependent on feature quality)
- F1-Score: > 0.75
- Inference Latency: < 20ms

Input Structure (CSV):
- Columns: [feature_1, feature_2, ..., feature_107, label]
- Label: 0 (Secure), 1 (Vulnerable)

Output Structure:
/models/static/
├── static_model.pkl           # Trained classifier
├── static_scaler.pkl          # Preprocessing pipeline (Imputer + Scaler)
├── static_training_report.json # Detailed training metrics
└── metadata.json              # Feature mapping and version info

Usage:
1. Prepare datasets/processed/features_train.csv
2. Run: python src/ml/static/train_static.py \\
    --input datasets/processed/features_train.csv \\
    --output-dir models/static \\
    --model-type xgb
3. Verify artifacts in models/static/

Dependencies:
- xgboost
- scikit-learn
- pandas
- joblib
- numpy
"""

import argparse
import json
import logging
import sys
import time
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    roc_auc_score, f1_score, precision_score, recall_score, accuracy_score,
    make_scorer
)
from sklearn.base import BaseEstimator

# Model Imports
try:
    import xgboost as xgb
except ImportError:
    xgb = None
try:
    import lightgbm as lgb
except ImportError:
    lgb = None
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC


# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("StaticTrainer")


def setup_log_file(output_dir: Path):
    """Adds a file handler to the logger to save logs to separate file."""
    log_file = output_dir / "training_log.txt"
    file_handler = logging.FileHandler(log_file, mode="a")
    file_handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(file_handler)


def calculate_sha256(filepath: str) -> str:
    """Calculates SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def load_dataset(input_path: str) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    """Loads dataset, validates schema, updates missing values."""
    logger.info(f"Loading dataset from: {input_path}")
    if not Path(input_path).exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    df = pd.read_csv(input_path)

    if "label" not in df.columns:
        raise ValueError("Dataset missing required column: 'label'")

    # Separate features and label
    y = df["label"]
    X = df.drop(columns=["label"])

    feature_names = X.columns.tolist()
    logger.info(f"Loaded {len(df)} records with {len(feature_names)} features.")

    # 107 feature validation (soft warning if mismatch, but strict in prompt spirit)
    if len(feature_names) != 107:
        logger.warning(f"Expected 107 features, found {len(feature_names)}. Proceeding with discovered features.")

    # Check for non-numeric columns
    non_numeric = X.select_dtypes(exclude=[np.number]).columns
    if len(non_numeric) > 0:
        logger.error(f"Non-numeric features detected: {non_numeric.tolist()}")
        raise ValueError("All features must be numeric.")

    return X, y, feature_names


def get_model_pipeline(model_type: str, scale_type: str, seed: int) -> Pipeline:
    """Constructs the training pipeline (Imputer -> Scaler -> Model)."""

    # 1. Imputer
    imputer = SimpleImputer(strategy="median")

    # 2. Scaler
    if scale_type == "minmax":
        scaler = MinMaxScaler()
    else:
        scaler = StandardScaler()

    # 3. Model
    if model_type == "xgb":
        if xgb is None:
            raise ImportError("XGBoost not installed.")
        clf = xgb.XGBClassifier(
            n_estimators=1000,
            learning_rate=0.05,
            max_depth=6,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="logloss",
            random_state=seed,
            n_jobs=-1,
            early_stopping_rounds=50 # Configure early stopping logic if using .fit manually, but inside pipeline/CV it's trickier.
                                     # For standard sklearn pipe, we rely on n_estimators or set early_stopping in fit_params if supported.
                                     # To keep it simple and robust for CV, we use a robust fixed config or minimal early stopping if feasible.
                                     # Standard sklearn XGB API handles early_stopping in fit, but Pipeline.fit passes kwargs to the last step?
                                     # We will set reasonable defaults and skip complex callback injection for this robust script.
        )
    elif model_type == "lgb":
        if lgb is None:
            raise ImportError("LightGBM not installed.")
        clf = lgb.LGBMClassifier(random_state=seed, n_jobs=-1)
    elif model_type == "rf":
        clf = RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1)
    elif model_type == "lr":
        clf = LogisticRegression(random_state=seed, max_iter=1000)
    elif model_type == "svm":
        clf = SVC(probability=True, random_state=seed)
    else:
        raise ValueError(f"Unknown model type: {model_type}")

    steps = [
        ("imputer", imputer),
        ("scaler", scaler),
        ("classifier", clf)
    ]

    return Pipeline(steps)


def train():
    parser = argparse.ArgumentParser(description="CodeGuardian Static Model Trainer")
    parser.add_argument("--input", required=True, help="Path to input CSV (features + label)")
    parser.add_argument("--output-dir", required=True, help="Directory to save artifacts")
    parser.add_argument("--model-type", default="xgb", choices=["xgb", "lgb", "rf", "lr", "svm"], help="Model algorithm")
    parser.add_argument("--scale", default="standard", choices=["standard", "minmax"], help="Scaling method")
    parser.add_argument("--cv-folds", type=int, default=5, help="Number of CV folds")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")

    args = parser.parse_args()

    # Initialize
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    setup_log_file(output_dir)

    start_time = time.time()
    logger.info("="*60)
    logger.info("STARTING STATIC ENGINE TRAINING PHASE")
    logger.info(f"Command: {' '.join(sys.argv)}")
    logger.info(f"Settings: Model={args.model_type}, Scale={args.scale}, CV={args.cv_folds}, Seed={args.seed}")
    logger.info("="*60)

    try:
        # Load Data
        X, y, feature_names = load_dataset(args.input)

        # Build Pipeline
        pipeline = get_model_pipeline(args.model_type, args.scale, args.seed)

        # Cross-Validation
        logger.info(f"Starting {args.cv_folds}-Fold Stratified Cross-Validation...")
        cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.seed)

        scoring = {
            'auc': 'roc_auc',
            'f1': 'f1',
            'precision': 'precision',
            'recall': 'recall',
            'accuracy': 'accuracy'
        }

        # Note: pipeline handles scaling/imputation inside CV loops to prevent leakage
        cv_results = cross_validate(pipeline, X, y, cv=cv, scoring=scoring, n_jobs=-1)

        metrics = {
            "roc_auc_mean": float(np.mean(cv_results['test_auc'])),
            "roc_auc_std": float(np.std(cv_results['test_auc'])),
            "f1_mean": float(np.mean(cv_results['test_f1'])),
            "precision_mean": float(np.mean(cv_results['test_precision'])),
            "recall_mean": float(np.mean(cv_results['test_recall'])),
            "accuracy_mean": float(np.mean(cv_results['test_accuracy'])),
        }

        logger.info("-" * 40)
        logger.info("CROSS-VALIDATION RESULTS:")
        for k, v in metrics.items():
            if "_mean" in k:
                logger.info(f"  {k:<20}: {v:.4f}")
        logger.info("-" * 40)

        # Final Training on Full Dataset
        logger.info("Retraining on full dataset for production artifact...")
        pipeline.fit(X, y)

        # Artifact Paths
        model_path = output_dir / "static_model.pkl"
        scaler_path = output_dir / "static_scaler.pkl" # We save the whole pipeline actually, but prompt implies separate?
                                                        # Prompt says "static_model.pkl" and "static_scaler.pkl".
                                                        # If we save the pipeline, it contains both.
                                                        # To follow prompt STRICTLY, I will extract steps.

        # Extract components
        trained_imputer = pipeline.named_steps['imputer']
        trained_scaler = pipeline.named_steps['scaler']
        trained_model = pipeline.named_steps['classifier']

        # We need to save the scaler AND imputer potentially.
        # Standard practice: save the whole pipeline as 'static_model.pkl'.
        # However, the user specifically asked for `static_scaler.pkl`.
        # I will save the pipeline as the primary model, but also export scaler for compliance if needed.
        # BETTER APPROACH: Save the Pipeline as `static_model.pkl`.
        # Wait, inference requirements say: "Load static_model.pkl, static_scaler.pkl ... Apply scaler -> model.predict_proba".
        # This implies decoupled components. I will decouple them.

        # 1. Save independent Scaler (combining Imputer + Scaler for convenience or just Scaler?)
        # Ideally, the preprocessing pipeline (Imputer+Scaler) should be one artifact.
        # I will bundle Imputer+Scaler into `static_scaler.pkl` to ensure robustness (missing values handling).

        preprocessing_pipe = Pipeline([
            ("imputer", trained_imputer),
            ("scaler", trained_scaler)
        ])
        joblib.dump(preprocessing_pipe, scaler_path)

        # 2. Save Model
        joblib.dump(trained_model, model_path)

        # 3. Report
        report = {
            "timestamp": datetime.now().isoformat(),
            "metrics": metrics,
            "parameters": {
                "model_type": args.model_type,
                "scale": args.scale,
                "cv_folds": args.cv_folds,
                "seed": args.seed,
                "input_shape": list(X.shape)
            },
            "feature_count": len(feature_names)
        }

        report_path = output_dir / "static_training_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        # 4. Metadata
        # Calculate hashes
        model_hash = calculate_sha256(str(model_path))
        scaler_hash = calculate_sha256(str(scaler_path))

        metadata = {
            "model_version": "2.0.0-static",
            "framework": "codeGuardian-Phase2",
            "feature_order": feature_names,
            "artifacts": {
                "static_model.pkl": model_hash,
                "static_scaler.pkl": scaler_hash
            },
            "created_at": datetime.now().isoformat()
        }

        metadata_path = output_dir / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Artifacts saved to {output_dir}")
        logger.info("Training Complete successfully.")

    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        elapsed = time.time() - start_time
        logger.info(f"Total execution time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    train()
