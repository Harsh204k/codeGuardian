#!/usr/bin/env python3
# =============================
# codeGuardian Static Feature Training Script - Phase 2
# Author: Urva Gandhi
# Model: XGBoost (Default) / LightGBM / RF / SVM
# Purpose: Static vulnerability detection using 107 engineered features
# Standard: CodeGuardian Training Standard v5.1
# =============================

"""
CodeGuardian Static Model Training Pipeline - Production Standard v5.1
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
├── static_model_{type}.pkl    # Trained classifier (e.g., static_model_xgb.pkl)
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
import hashlib
import json
import logging
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    make_scorer,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.svm import SVC

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================
EXPECTED_FEATURE_COUNT = 107
SEED_DEFAULT = 42

# Suppress minor warnings for cleaner output
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# ==============================================================================
# LOGGING SETUP
# ==============================================================================
logger = logging.getLogger("StaticTrainer")
logger.setLevel(logging.INFO)

def setup_logging(output_dir: Path):
    """Configures logging to both console and training_log.txt"""
    # Clear existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler
    log_file = output_dir / "training_log.txt"
    file_handler = logging.FileHandler(log_file, mode="a")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info(f"Logging initialized. Log file: {log_file}")


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================
def calculate_sha256(filepath: Path) -> str:
    """Calculates SHA256 hash of a file for integrity verification."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def load_and_validate_data(input_path: str) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    """
    Loads dataset, renames columns, and performs strict validation.
    """
    logger.info(f"Loading dataset: {input_path}")
    if not Path(input_path).exists():
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    try:
        df = pd.read_csv(input_path)
    except Exception as e:
        logger.error(f"Failed to read CSV: {e}")
        sys.exit(1)

    # 1. Rename 'is_vulnerable' -> 'label'
    if "is_vulnerable" in df.columns:
        logger.info("Renaming 'is_vulnerable' column to 'label'...")
        df.rename(columns={"is_vulnerable": "label"}, inplace=True)

    # 2. Check for label
    if "label" not in df.columns:
        logger.error("Dataset missing required 'label' (or 'is_vulnerable') column.")
        sys.exit(1)

    y = df["label"]
    X = df.drop(columns=["label"])

    # Optional Polish: 1. Strict Binary Label Check
    unique_labels = set(y.unique())
    if not unique_labels.issubset({0, 1}):
        logger.error(f"Invalid labels found: {unique_labels}. Must be {{0, 1}}.")
        sys.exit(1)

    # Optional Polish: 2. Imbalance Warning
    pos_ratio = y.mean()
    if pos_ratio < 0.05 or pos_ratio > 0.95:
        logger.warning(
            f"⚠️ HIGH CLASS IMBALANCE DETECTED! Positive ratio: {pos_ratio:.4f}. "
            "Metrics like Accuracy may be misleading. Focus on F1/AUC."
        )

    # 3. Numeric Validation
    non_numeric = X.select_dtypes(exclude=[np.number]).columns
    if len(non_numeric) > 0:
        logger.error(f"Found non-numeric features: {list(non_numeric)}")
        logger.error("Static engine requires PURE NUMERIC features (107 float/int).")
        sys.exit(1)

    feature_names = X.columns.tolist()

    # 4. Feature Count Validation
    if len(feature_names) != EXPECTED_FEATURE_COUNT:
        logger.warning(
            f"Feature count mismatch! Expected {EXPECTED_FEATURE_COUNT}, found {len(feature_names)}. "
            "Proceeding, but ensure model inputs align."
        )
    else:
        logger.info(f"Successfully validated {len(feature_names)} features.")

    logger.info(f"Loaded {len(df)} records. Class dist: {y.value_counts().to_dict()}")

    return X, y, feature_names


def get_model(model_type: str, seed: int) -> BaseEstimator:
    """Returns the requested classifier instance."""
    if model_type == "xgb":
        try:
            import xgboost as xgb
            return xgb.XGBClassifier(
                n_estimators=1000,
                max_depth=6,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                tree_method="hist",  # Fast CPU/GPU
                random_state=seed,
                n_jobs=-1
            )
        except ImportError:
            logger.error("XGBoost not installed. Install with: pip install xgboost")
            sys.exit(1)

    elif model_type == "lgb":
        try:
            import lightgbm as lgb
            return lgb.LGBMClassifier(random_state=seed, n_jobs=-1)
        except ImportError:
            logger.error("LightGBM not installed.")
            sys.exit(1)

    elif model_type == "rf":
        return RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1)

    elif model_type == "lr":
        return LogisticRegression(max_iter=1000, random_state=seed)

    elif model_type == "svm":
        return SVC(probability=True, random_state=seed)

    else:
        logger.error(f"Unknown model type: {model_type}")
        sys.exit(1)


# ==============================================================================
# MAIN TRAINING LOGIC
# ==============================================================================
def train():
    parser = argparse.ArgumentParser(description="CodeGuardian Static Feature Training")
    parser.add_argument("--input", required=True, help="Path to validated_features.csv")
    parser.add_argument("--output-dir", required=True, help="Artifact output directory")
    parser.add_argument("--model-type", default="xgb", choices=["xgb", "lgb", "rf", "lr", "svm"])
    parser.add_argument("--scale", default="standard", choices=["standard", "minmax"])
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=SEED_DEFAULT)

    args = parser.parse_args()

    # 1. Setup Directories & Logging
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(output_dir)

    start_time_glob = time.time()
    logger.info("=" * 60)
    logger.info(" STARTING STATIC ENGINE TRAINING (Phase 2)")
    logger.info(f" Config: Model={args.model_type.upper()}, Scale={args.scale}, CV={args.cv_folds}, Seed={args.seed}")
    logger.info("=" * 60)

    # 2. Load Data
    X, y, feature_names = load_and_validate_data(args.input)

    # 3. Construct Preprocessing Pipeline
    # Median Imputer -> Scaler
    if args.scale == "minmax":
        scaler = MinMaxScaler()
    else:
        scaler = StandardScaler()

    preprocessing_pipe = Pipeline([
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', scaler)
    ])

    # 4. Get Model
    clf = get_model(args.model_type, args.seed)

    # 5. Cross-Validation (Full Pipeline to avoid leakage)
    full_cv_pipeline = Pipeline([
        ('preprocessor', preprocessing_pipe),
        ('classifier', clf)
    ])

    logger.info(f"Statring Stratified {args.cv_folds}-Fold Cross-Validation...")
    cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=args.seed)

    scoring = {
        'auc': 'roc_auc',
        'f1': 'f1',
        'precision': 'precision',
        'recall': 'recall',
        'accuracy': 'accuracy'
    }

    try:
        cv_results = cross_validate(
            full_cv_pipeline, X, y, cv=cv, scoring=scoring, n_jobs=-1, return_train_score=False
        )
    except Exception as e:
        logger.error(f"Cross-Validation failed: {e}")
        sys.exit(1)

    # Summarize Metrics
    metrics_summary = {}
    logger.info("-" * 40)
    logger.info(" CROSS-VALIDATION RESULTS (Mean ± Std)")
    logger.info("-" * 40)
    for score_name in scoring.keys():
        key = f"test_{score_name}"
        mean_val = np.mean(cv_results[key])
        std_val = np.std(cv_results[key])
        metrics_summary[f"{score_name}_mean"] = float(mean_val)
        metrics_summary[f"{score_name}_std"] = float(std_val)
        logger.info(f" {score_name.upper():<10}: {mean_val:.4f} ± {std_val:.4f}")
    logger.info("-" * 40)

    # 6. Final Retraining (Decoupled Artifacts)
    # We must save the Preprocessing Pipeline and the Classifier SEPARATELY.

    logger.info("Retraining final model on FULL dataset...")

    # Fit Preprocessing Pipeline
    preprocessing_pipe.fit(X, y)
    X_transformed = preprocessing_pipe.transform(X)

    # Fit Classifier on Transformed Data
    # Clone classifier to ensure fresh start
    final_model = clone(clf)
    final_model.fit(X_transformed, y)

    # 7. Artifact Export
    model_filename = f"static_model_{args.model_type}.pkl"
    model_path = output_dir / model_filename
    scaler_path = output_dir / "static_scaler.pkl"

    logger.info(f"Saving artifacts to {output_dir}...")

    # Save Model (Classifier Only)
    joblib.dump(final_model, model_path)

    # Save Scaler (Pipeline: Imputer -> Scaler)
    joblib.dump(preprocessing_pipe, scaler_path)

    # Calculate Hashes
    model_hash = calculate_sha256(model_path)
    scaler_hash = calculate_sha256(scaler_path)

    # Metadata
    metadata = {
        "model_version": "2.0.0-static-phase2",
        "training_version": "static-v2.0",
        "algorithm": args.model_type,
        "timestamp": datetime.now().isoformat(),
        "feature_order": feature_names,
        "input_hashes": {
            model_filename: model_hash,
            "static_scaler.pkl": scaler_hash
        },
        "model_parameters": final_model.get_params(),
        "training_config": vars(args)
    }

    with open(output_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    # Training Report
    report = {
        "metrics": metrics_summary,
        "input_shape": list(X.shape),
        "settings": vars(args),
        "seed": args.seed,
        "execution_time_seconds": time.time() - start_time_glob
    }

    with open(output_dir / "static_training_report.json", "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Training Complete. Time: {time.time() - start_time_glob:.2f}s")
    logger.info("Successfully generated all artifacts.")
    logger.info("=" * 60)


if __name__ == "__main__":
    train()
