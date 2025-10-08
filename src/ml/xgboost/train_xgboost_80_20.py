#!/usr/bin/env python3
"""
Professional XGBoost Training with 80/20 Split on DiverseVul Dataset
Proper train/test split for accurate performance evaluation
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
import joblib
import logging
import re
from datetime import datetime
import time

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityFeatureExtractor:
    """Professional feature engineering for vulnerability detection"""

    def __init__(self):
        # Vulnerability keywords (based on CWE patterns)
        self.vuln_keywords = {
            "buffer_overflow": [
                "strcpy",
                "strcat",
                "sprintf",
                "gets",
                "scanf",
                "strncpy",
            ],
            "injection": ["eval", "exec", "system", "shell_exec", "popen", "sql"],
            "memory_issues": ["malloc", "free", "delete", "new", "calloc", "realloc"],
            "crypto_weak": ["md5", "sha1", "des", "rc4", "random", "rand"],
            "auth_bypass": ["strcmp", "password", "auth", "login", "session"],
            "path_traversal": ["../", "..\\", "path", "file", "directory"],
            "xss_csrf": ["innerHTML", "eval", "script", "document", "cookie"],
            "race_condition": ["thread", "lock", "mutex", "atomic", "volatile"],
            "integer_overflow": ["int", "long", "short", "size_t", "unsigned"],
            "format_string": ["printf", "fprintf", "sprintf", "snprintf", "%s", "%d"],
        }

        # Dangerous functions by language
        self.dangerous_funcs = [
            "strcpy",
            "strcat",
            "sprintf",
            "gets",
            "scanf",
            "system",
            "exec",
            "eval",
            "shell_exec",
            "passthru",
            "popen",
            "proc_open",
            "assert",
            "create_function",
            "file_get_contents",
            "file_put_contents",
            "fopen",
            "mysql_query",
            "mysqli_query",
            "pg_query",
            "sqlite_query",
        ]

    def extract_features(self, code_samples, labels=None):
        """Extract comprehensive features from code samples"""
        logger.info(f"🔧 Extracting features from {len(code_samples)} code samples...")

        features = []

        for i, code in enumerate(code_samples):
            if i % 10000 == 0:
                logger.info(f"   Processed {i:,}/{len(code_samples):,} samples")

            feature_vector = self._extract_single_features(code)
            features.append(feature_vector)

        logger.info("✅ Feature extraction completed")
        return np.array(features)

    def _extract_single_features(self, code):
        """Extract features from a single code sample"""
        code_lower = code.lower()
        lines = code.split("\n")

        features = {}

        # 1. Basic code metrics
        features["code_length"] = len(code)
        features["line_count"] = len(lines)
        features["avg_line_length"] = (
            np.mean([len(line) for line in lines]) if lines else 0
        )
        features["max_line_length"] = max([len(line) for line in lines]) if lines else 0
        features["empty_lines"] = sum(1 for line in lines if not line.strip())
        features["comment_lines"] = sum(
            1 for line in lines if line.strip().startswith(("//", "#", "/*", "*"))
        )

        # 2. Complexity metrics
        features["brace_depth"] = self._calculate_brace_depth(code)
        features["function_count"] = len(
            re.findall(
                r"\b(def|function|void|int|char|float|double)\s+\w+\s*\(", code_lower
            )
        )
        features["if_statements"] = len(re.findall(r"\bif\s*\(", code_lower))
        features["loop_statements"] = len(
            re.findall(r"\b(for|while|do)\s*\(", code_lower)
        )
        features["return_statements"] = len(re.findall(r"\breturn\b", code_lower))

        # 3. Vulnerability keyword analysis
        for category, keywords in self.vuln_keywords.items():
            count = sum(code_lower.count(keyword) for keyword in keywords)
            features[f"vuln_{category}_count"] = count
            features[f"vuln_{category}_present"] = int(count > 0)

        # 4. Dangerous function detection
        dangerous_count = sum(code_lower.count(func) for func in self.dangerous_funcs)
        features["dangerous_functions_count"] = dangerous_count
        features["dangerous_functions_present"] = int(dangerous_count > 0)

        # 5. Security-specific patterns
        features["bounds_checks"] = len(
            re.findall(r"(length|size|bounds|check|validate)", code_lower)
        )
        features["string_concat"] = len(
            re.findall(r'(\+\s*"|strcat|concat)', code_lower)
        )
        features["hardcoded_values"] = len(
            re.findall(r'(password|secret|key)\s*=\s*["\']', code_lower)
        )
        features["file_operations"] = len(
            re.findall(r"(fopen|fread|fwrite|file_get|file_put)", code_lower)
        )
        features["network_calls"] = len(
            re.findall(r"(socket|connect|send|recv|http|url)", code_lower)
        )
        features["privilege_calls"] = len(
            re.findall(r"(admin|root|sudo|privilege|permission)", code_lower)
        )

        # Convert to array maintaining consistent order
        feature_names = [
            "code_length",
            "line_count",
            "avg_line_length",
            "max_line_length",
            "empty_lines",
            "comment_lines",
            "brace_depth",
            "function_count",
            "if_statements",
            "loop_statements",
            "return_statements",
        ]

        # Add vulnerability features
        for category in self.vuln_keywords.keys():
            feature_names.extend([f"vuln_{category}_count", f"vuln_{category}_present"])

        # Add other security features
        feature_names.extend(
            [
                "dangerous_functions_count",
                "dangerous_functions_present",
                "bounds_checks",
                "string_concat",
                "hardcoded_values",
                "file_operations",
                "network_calls",
                "privilege_calls",
            ]
        )

        return [features.get(name, 0) for name in feature_names]

    def _calculate_brace_depth(self, code):
        """Calculate maximum brace nesting depth"""
        max_depth = 0
        current_depth = 0

        for char in code:
            if char in "{[(":
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char in "}])":
                current_depth = max(0, current_depth - 1)

        return max_depth


def load_diversevul_dataset(max_samples=None):
    """Load the complete DiverseVul dataset"""
    dataset_path = Path("DiverseVul Dataset/diversevul_20230702.json")

    if not dataset_path.exists():
        raise FileNotFoundError(f"DiverseVul dataset not found at {dataset_path}")

    logger.info(f"📊 Loading DiverseVul dataset from {dataset_path}")

    code_samples = []
    labels = []

    with open(dataset_path, "r") as f:
        for i, line in enumerate(f):
            if max_samples and i >= max_samples:
                break

            if i % 50000 == 0:
                logger.info(f"   Processed {i:,} lines")

            try:
                data = json.loads(line.strip())
                code_samples.append(data["func"])
                labels.append(int(data["target"]))
            except (json.JSONDecodeError, KeyError) as e:
                continue

    logger.info(f"✅ Loaded {len(code_samples):,} samples")
    logger.info(f"   Vulnerable: {sum(labels):,}")
    logger.info(f"   Safe: {len(labels) - sum(labels):,}")

    return code_samples, labels


def train_xgboost_with_proper_split():
    """Train XGBoost with proper 80/20 train/test split"""

    print("🚀 XGBOOST TRAINING WITH 80/20 SPLIT")
    print("=" * 60)

    # Load complete dataset
    code_samples, labels = load_diversevul_dataset(
        max_samples=100000
    )  # Use 100K for faster training

    # Proper 80/20 split BEFORE feature extraction
    logger.info("🔄 Creating 80/20 train/test split...")
    train_codes, test_codes, train_labels, test_labels = train_test_split(
        code_samples, labels, test_size=0.2, random_state=42, stratify=labels
    )

    logger.info(f"📊 Split complete:")
    logger.info(
        f"   Train: {len(train_codes):,} samples ({sum(train_labels):,} vulnerable)"
    )
    logger.info(
        f"   Test:  {len(test_codes):,} samples ({sum(test_labels):,} vulnerable)"
    )

    # Extract features
    feature_extractor = VulnerabilityFeatureExtractor()

    logger.info("🔧 Extracting training features...")
    X_train = feature_extractor.extract_features(train_codes)

    logger.info("🔧 Extracting test features...")
    X_test = feature_extractor.extract_features(test_codes)

    y_train = np.array(train_labels)
    y_test = np.array(test_labels)

    logger.info(f"📊 Feature matrices:")
    logger.info(f"   Train: {X_train.shape}")
    logger.info(f"   Test:  {X_test.shape}")

    # Train XGBoost
    logger.info("🚀 Training XGBoost model...")
    start_time = time.time()

    # Professional XGBoost parameters
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        eval_metric="logloss",
    )

    xgb_model.fit(X_train, y_train)
    training_time = time.time() - start_time

    # Evaluate on test set
    logger.info("📊 Evaluating on test set...")
    y_pred = xgb_model.predict(X_test)
    y_pred_proba = xgb_model.predict_proba(X_test)[:, 1]

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    # Get feature importance
    feature_importance = xgb_model.feature_importances_

    # Save model and results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_dir = Path(f"models/xgboost_80_20_split_{timestamp}")
    model_dir.mkdir(parents=True, exist_ok=True)

    # Save model and feature extractor
    joblib.dump(xgb_model, model_dir / "xgboost_model.joblib")
    joblib.dump(feature_extractor, model_dir / "feature_extractor.joblib")

    # Print results
    print("\n" + "=" * 60)
    print("🏆 XGBOOST 80/20 SPLIT RESULTS")
    print("=" * 60)
    print(f"⏱️  Training Time: {training_time:.1f} seconds")
    print(f"📊 Train Dataset: {len(train_codes):,} samples")
    print(f"📊 Test Dataset: {len(test_codes):,} samples")
    print(f"🎯 Test Performance Metrics:")
    print(f"   📈 Accuracy:  {accuracy:.3f}")
    print(f"   🎲 F1-Score:  {f1:.3f}")
    print(f"   📊 Precision: {precision:.3f}")
    print(f"   📋 Recall:    {recall:.3f}")
    print()
    print(f"📋 Confusion Matrix (Test Set):")
    print(f"   True Negatives:  {cm[0,0]:,}")
    print(f"   False Positives: {cm[0,1]:,}")
    print(f"   False Negatives: {cm[1,0]:,}")
    print(f"   True Positives:  {cm[1,1]:,}")

    print(f"\n✅ Model saved to: {model_dir}")
    print(f"🔗 Ready for production deployment!")

    results = {
        "training_time": training_time,
        "train_samples": len(train_codes),
        "test_samples": len(test_codes),
        "test_accuracy": accuracy,
        "test_f1_score": f1,
        "test_precision": precision,
        "test_recall": recall,
        "confusion_matrix": cm.tolist(),
        "model_path": str(model_dir),
    }

    print(f"\n🎉 SUCCESS: XGBoost trained with proper 80/20 split!")
    print(f"📈 Test F1-Score: {f1:.3f} on {len(test_codes):,} unseen samples")

    return str(model_dir), results


if __name__ == "__main__":
    try:
        model_path, results = train_xgboost_with_proper_split()
        print(f"\n✅ Training completed successfully!")
        print(f"📁 Model saved at: {model_path}")

    except Exception as e:
        logger.error(f"❌ Training failed: {e}")
        raise
