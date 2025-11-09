#!/usr/bin/env python3
# =============================
# codeGuardian Threshold Optimization Script
# Author: Urva Gandhi
# Purpose: Post-training calibration and threshold optimization for ensemble models
# Standard: CodeGuardian Post-Training Standard v1.0
# =============================

"""
CodeGuardian Threshold Optimization Pipeline
=============================================
Post-training calibration and threshold optimization for vulnerability detection models.

This script performs:
1. Temperature scaling calibration for CodeBERT and GraphCodeBERT
2. Weighted ensemble combination of calibrated probabilities
3. Global and per-language threshold optimization (F1-score maximization)
4. Abstention band definition for uncertain predictions
5. Comprehensive evaluation and visualization

Features:
✅ Temperature scaling via log-loss minimization
✅ Weighted ensemble (default: 60% GraphCodeBERT, 40% CodeBERT)
✅ Global threshold optimization for maximum F1-score
✅ Per-language threshold tuning for minority classes
✅ Expected Calibration Error (ECE) computation
✅ Abstention margin for low-confidence predictions
✅ Comprehensive plots (PR curve, F1-vs-threshold, reliability diagram)
✅ Structured JSON configuration export
✅ Reproducible with fixed random seed

Input:
- val_logits.csv: [language, logits_codebert, logits_graphcodebert, y_true]
- val_logits_meta.json: metadata from export_val_logits.py

Output:
- calibration_values.json: per-model temperature values
- thresholds.json: global + per-language decision thresholds
- ensemble_config.json: unified inference configuration
- calibrated_val_results.csv: predictions with calibrated probabilities
- plots/: diagnostic visualizations

Usage:
    python threshold_optimizer.py --input /kaggle/input/.../val_logits.csv

Dependencies:
- numpy, pandas, matplotlib, scipy, scikit-learn, torch, tqdm
"""

import os
import json
import argparse
import logging
import time
from datetime import datetime
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from scipy.optimize import minimize
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    precision_recall_curve,
    confusion_matrix,
    log_loss,
    roc_auc_score
)
import matplotlib.pyplot as plt
from tqdm import tqdm

# Set consistent plot style
plt.style.use('seaborn-v0_8-whitegrid')

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Input path
INPUT_CSV = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/val_logits.csv"

# Output paths
OUTPUT_DIR = "/kaggle/working"
CALIBRATION_JSON = f"{OUTPUT_DIR}/calibration_values.json"
THRESHOLDS_JSON = f"{OUTPUT_DIR}/thresholds.json"
ENSEMBLE_CONFIG_JSON = f"{OUTPUT_DIR}/ensemble_config.json"
CALIBRATED_CSV = f"{OUTPUT_DIR}/calibrated_val_results.csv"
PLOTS_DIR = f"{OUTPUT_DIR}/plots"

# Ensemble weights
WEIGHT_GRAPHCODEBERT = 0.6
WEIGHT_CODEBERT = 0.4

# Abstention configuration
ABSTAIN_MARGIN = 0.08

# Per-language threshold strategies
LANGUAGE_STRATEGIES = {
    "C": "high_recall",      # Favor detection (min recall 0.55)
    "PHP": "high_precision"  # Favor quality (min precision 0.92)
}

# Reproducibility
SEED = 42

# Numerical stability
EPS = 1e-7

# 🧮 Weighted Ensemble Validation: Ensure weights sum to 1.0
assert abs((WEIGHT_CODEBERT + WEIGHT_GRAPHCODEBERT) - 1.0) < 1e-6, \
    f"❌ Ensemble weights must sum to 1.0 (got {WEIGHT_CODEBERT + WEIGHT_GRAPHCODEBERT})"

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def set_seed(seed):
    """Set random seeds for reproducibility."""
    np.random.seed(seed)
    torch.manual_seed(seed)

def sigmoid(x):
    """Numerically stable sigmoid function."""
    return 1 / (1 + np.exp(-np.clip(x, -50, 50)))

def compute_ece(y_true, y_prob, n_bins=10):
    """
    Compute Expected Calibration Error.

    Args:
        y_true: Ground truth labels
        y_prob: Predicted probabilities
        n_bins: Number of calibration bins

    Returns:
        ECE value and bin statistics
    """
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    bin_lowers = bin_boundaries[:-1]
    bin_uppers = bin_boundaries[1:]

    ece = 0.0
    bin_stats = []

    for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
        in_bin = (y_prob > bin_lower) & (y_prob <= bin_upper)
        prop_in_bin = in_bin.mean()

        if prop_in_bin > 0:
            accuracy_in_bin = y_true[in_bin].mean()
            avg_confidence_in_bin = y_prob[in_bin].mean()
            ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin

            bin_stats.append({
                'bin_lower': bin_lower,
                'bin_upper': bin_upper,
                'confidence': avg_confidence_in_bin,
                'accuracy': accuracy_in_bin,
                'count': in_bin.sum()
            })

    return ece, bin_stats

# ═══════════════════════════════════════════════════════════════════════════
# TEMPERATURE SCALING
# ═══════════════════════════════════════════════════════════════════════════

class TemperatureScaler:
    """
    Temperature scaling calibration for model logits.

    Optimizes a single scalar temperature T to minimize binary cross-entropy.
    Calibrated probability: p = sigmoid(logit / T)
    """

    def __init__(self, logits, labels):
        """
        Args:
            logits: Raw model logits (1D array)
            labels: Ground truth binary labels (1D array)
        """
        self.logits = np.array(logits)
        self.labels = np.array(labels)
        self.temperature = 1.0

    def _loss(self, T):
        """Compute binary cross-entropy loss for given temperature."""
        T = T[0]  # scipy.minimize passes array
        if T <= 0:
            return 1e10  # Invalid temperature

        # 🧾 Numerical Stability: Clip scaled logits before sigmoid
        scaled_logits = np.clip(self.logits / T, -50, 50)
        probs = sigmoid(scaled_logits)

        # Clip probabilities to avoid log(0)
        probs = np.clip(probs, EPS, 1 - EPS)

        # Binary cross-entropy
        loss = -np.mean(
            self.labels * np.log(probs) + (1 - self.labels) * np.log(1 - probs)
        )

        return loss

    def optimize(self):
        """Find optimal temperature via L-BFGS-B optimization."""
        logger.info("   Optimizing temperature via L-BFGS-B...")

        result = minimize(
            self._loss,
            x0=[1.0],
            method='L-BFGS-B',
            bounds=[(0.01, 10.0)],
            options={'maxiter': 100}
        )

        # 🧠 Calibration Optimization Robustness: Fallback on failure
        if not result.success:
            logger.warning(f"⚠️  Optimization failed ({result.message}). Falling back to T=1.0")
            self.temperature = 1.0
        else:
            self.temperature = result.x[0]
            logger.info(f"   ✅ Optimal temperature: {self.temperature:.4f}")
            logger.info(f"   Loss: {result.fun:.6f}")

        return self.temperature

    def get_calibrated_probs(self):
        """Get calibrated probabilities using optimized temperature."""
        return sigmoid(self.logits / self.temperature)

# ═══════════════════════════════════════════════════════════════════════════
# THRESHOLD OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════

def optimize_threshold_f1(y_true, y_prob):
    """
    Find threshold that maximizes F1-score.

    Args:
        y_true: Ground truth labels
        y_prob: Predicted probabilities

    Returns:
        optimal_threshold, best_f1, threshold_curve
    """
    thresholds = np.linspace(0.01, 0.99, 200)
    f1_scores = []

    for thresh in thresholds:
        y_pred = (y_prob >= thresh).astype(int)
        _, _, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average='binary', zero_division=0
        )
        f1_scores.append(f1)

    best_idx = np.argmax(f1_scores)
    optimal_threshold = thresholds[best_idx]
    best_f1 = f1_scores[best_idx]

    threshold_curve = list(zip(thresholds, f1_scores))

    return optimal_threshold, best_f1, threshold_curve

def optimize_language_threshold(y_true, y_prob, strategy):
    """
    Optimize threshold with language-specific constraints.

    Args:
        y_true: Ground truth labels
        y_prob: Predicted probabilities
        strategy: 'high_recall' or 'high_precision'

    Returns:
        optimal_threshold
    """
    thresholds = np.linspace(0.01, 0.99, 200)

    if strategy == "high_recall":
        # Find threshold where recall >= 0.55
        for thresh in thresholds:
            y_pred = (y_prob >= thresh).astype(int)
            _, recall, _, _ = precision_recall_fscore_support(
                y_true, y_pred, average='binary', zero_division=0
            )
            if recall >= 0.55:
                return thresh
        return thresholds[0]  # Lowest threshold if constraint not met

    elif strategy == "high_precision":
        # Find threshold where precision >= 0.92
        for thresh in reversed(thresholds):
            y_pred = (y_prob >= thresh).astype(int)
            precision, _, _, _ = precision_recall_fscore_support(
                y_true, y_pred, average='binary', zero_division=0
            )
            if precision >= 0.92:
                return thresh
        return thresholds[-1]  # Highest threshold if constraint not met

    else:
        # Default: maximize F1
        thresh, _, _ = optimize_threshold_f1(y_true, y_prob)
        return thresh

# ═══════════════════════════════════════════════════════════════════════════
# EVALUATION METRICS
# ═══════════════════════════════════════════════════════════════════════════

def compute_metrics(y_true, y_pred):
    """Compute comprehensive classification metrics."""
    acc = accuracy_score(y_true, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average='binary', zero_division=0
    )

    return {
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1
    }

# ═══════════════════════════════════════════════════════════════════════════
# VISUALIZATION
# ═══════════════════════════════════════════════════════════════════════════

def plot_precision_recall_curve(y_true, y_prob_before, y_prob_after, save_path):
    """Plot Precision-Recall curves before and after calibration."""
    plt.figure(figsize=(10, 6))

    # Before calibration
    prec_before, rec_before, _ = precision_recall_curve(y_true, y_prob_before)
    plt.plot(rec_before, prec_before, label='Before Calibration', linewidth=2)

    # After calibration
    prec_after, rec_after, _ = precision_recall_curve(y_true, y_prob_after)
    plt.plot(rec_after, prec_after, label='After Calibration', linewidth=2, linestyle='--')

    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curve', fontsize=14, fontweight='bold')
    plt.legend(fontsize=11)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    logger.info(f"   Saved: {save_path}")

def plot_f1_vs_threshold(threshold_curve, optimal_threshold, save_path):
    """Plot F1-score vs threshold curve."""
    thresholds, f1_scores = zip(*threshold_curve)

    plt.figure(figsize=(10, 6))
    plt.plot(thresholds, f1_scores, linewidth=2, color='#2ecc71')
    plt.axvline(optimal_threshold, color='red', linestyle='--', linewidth=2,
                label=f'Optimal τ = {optimal_threshold:.3f}')
    plt.xlabel('Threshold', fontsize=12)
    plt.ylabel('F1-Score', fontsize=12)
    plt.title('F1-Score vs Classification Threshold', fontsize=14, fontweight='bold')
    plt.legend(fontsize=11)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    logger.info(f"   Saved: {save_path}")

def plot_calibration_reliability(y_true, y_prob, bin_stats, title, save_path):
    """Plot reliability diagram for calibration assessment."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Reliability diagram
    confidences = [b['confidence'] for b in bin_stats]
    accuracies = [b['accuracy'] for b in bin_stats]

    ax1.plot([0, 1], [0, 1], 'k--', linewidth=2, label='Perfect Calibration')
    ax1.plot(confidences, accuracies, 'o-', linewidth=2, markersize=8, label='Model')
    ax1.set_xlabel('Mean Predicted Probability', fontsize=12)
    ax1.set_ylabel('Fraction of Positives', fontsize=12)
    ax1.set_title(f'Reliability Diagram - {title}', fontsize=13, fontweight='bold')
    ax1.legend(fontsize=10)
    ax1.grid(alpha=0.3)

    # Confidence histogram
    ax2.hist(y_prob, bins=20, edgecolor='black', alpha=0.7, color='#3498db')
    ax2.set_xlabel('Predicted Probability', fontsize=12)
    ax2.set_ylabel('Count', fontsize=12)
    ax2.set_title(f'Confidence Distribution - {title}', fontsize=13, fontweight='bold')
    ax2.grid(alpha=0.3, axis='y')

    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    logger.info(f"   Saved: {save_path}")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Main threshold optimization pipeline."""

    # Parse arguments
    parser = argparse.ArgumentParser(description='codeGuardian Threshold Optimizer')
    parser.add_argument(
        '--input',
        type=str,
        default=INPUT_CSV,
        help='Path to val_logits.csv (default: Kaggle dataset path)'
    )
    args = parser.parse_args()

    # Set seed for reproducibility
    set_seed(SEED)

    # Start timing
    start_time = time.time()

    logger.info("=" * 80)
    logger.info("🚀 codeGuardian - Threshold Optimization")
    logger.info("=" * 80)
    logger.info(f"Input CSV: {args.input}")
    logger.info(f"Ensemble weights: GraphCodeBERT={WEIGHT_GRAPHCODEBERT}, CodeBERT={WEIGHT_CODEBERT}")
    logger.info(f"Abstention margin: {ABSTAIN_MARGIN}")

    # 🧩 Input Integrity & Reproducibility Guarantee: Load and validate metadata
    meta_path = args.input.replace('.csv', '_meta.json')
    metadata_loaded = False
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r') as f:
                input_meta = json.load(f)
            logger.info(f"\n🧾 Loaded metadata from: {meta_path}")
            logger.info(f"   Export timestamp: {input_meta.get('export_timestamp', 'N/A')}")
            logger.info(f"   CodeBERT adapter SHA: {input_meta.get('codebert_adapter_sha', 'N/A')}")
            logger.info(f"   GraphCodeBERT adapter SHA: {input_meta.get('graphcodebert_adapter_sha', 'N/A')}")
            logger.info(f"   Val dataset rows: {input_meta.get('val_dataset_rows', 'N/A'):,}")
            metadata_loaded = True
        except Exception as e:
            logger.warning(f"⚠️  Failed to parse metadata file: {e}")
    else:
        logger.warning("⚠️  Metadata file not found — continuing without version traceability.")

    # Create output directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(PLOTS_DIR, exist_ok=True)    # -------------------------------------------------------------------------
    # Step 1: Load Data
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("📂 LOADING DATA")
    logger.info("=" * 80)

    if not os.path.exists(args.input):
        raise FileNotFoundError(f"❌ Input file not found: {args.input}")

    df = pd.read_csv(args.input)
    logger.info(f"✅ Loaded {len(df):,} samples from CSV")

    # Validate schema
    required_cols = ['language', 'logits_codebert', 'logits_graphcodebert', 'y_true']
    missing_cols = set(required_cols) - set(df.columns)
    if missing_cols:
        raise ValueError(f"❌ Missing columns: {missing_cols}")

    # Check for NaNs
    nan_counts = df[required_cols].isna().sum()
    if nan_counts.any():
        logger.warning(f"⚠️  Found NaN values:\n{nan_counts[nan_counts > 0]}")
        df = df.dropna(subset=required_cols)
        logger.info(f"   Dropped rows with NaNs. Remaining: {len(df):,}")

    logger.info(f"   Languages: {df['language'].nunique()}")
    logger.info(f"   Label distribution: {df['y_true'].value_counts().to_dict()}")

    # Extract data
    logits_codebert = df['logits_codebert'].values
    logits_graphcodebert = df['logits_graphcodebert'].values
    y_true = df['y_true'].values
    languages = df['language'].values

    # -------------------------------------------------------------------------
    # Step 2: Temperature Scaling Calibration
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("🌡️  TEMPERATURE SCALING CALIBRATION")
    logger.info("=" * 80)

    calibration_start = time.time()

    # Calibrate CodeBERT
    logger.info("Calibrating CodeBERT...")
    cb_scaler = TemperatureScaler(logits_codebert, y_true)
    T_codebert = cb_scaler.optimize()
    p_codebert_cal = cb_scaler.get_calibrated_probs()

    # Calibrate GraphCodeBERT
    logger.info("\nCalibrating GraphCodeBERT...")
    gcb_scaler = TemperatureScaler(logits_graphcodebert, y_true)
    T_graphcodebert = gcb_scaler.optimize()
    p_graphcodebert_cal = gcb_scaler.get_calibrated_probs()

    calibration_time = time.time() - calibration_start
    logger.info(f"\n⏱️  Calibration completed in {calibration_time:.1f}s")

    # Save calibration values
    calibration_values = {
        "codebert": float(T_codebert),
        "graphcodebert": float(T_graphcodebert)
    }

    # 💾 Atomic JSON Writes: Use temporary file for consistency
    temp_path = CALIBRATION_JSON + ".tmp"
    with open(temp_path, 'w') as f:
        json.dump(calibration_values, f, indent=2)
    os.replace(temp_path, CALIBRATION_JSON)
    logger.info(f"💾 Saved: {CALIBRATION_JSON}")    # Compute ECE before/after calibration
    p_codebert_uncal = sigmoid(logits_codebert)
    p_graphcodebert_uncal = sigmoid(logits_graphcodebert)

    ece_cb_before, _ = compute_ece(y_true, p_codebert_uncal)
    ece_cb_after, bins_cb = compute_ece(y_true, p_codebert_cal)

    ece_gcb_before, _ = compute_ece(y_true, p_graphcodebert_uncal)
    ece_gcb_after, bins_gcb = compute_ece(y_true, p_graphcodebert_cal)

    # 📈 Evaluation Completeness: Add AUC metrics
    auc_cb_before = roc_auc_score(y_true, p_codebert_uncal)
    auc_cb_after = roc_auc_score(y_true, p_codebert_cal)
    auc_gcb_before = roc_auc_score(y_true, p_graphcodebert_uncal)
    auc_gcb_after = roc_auc_score(y_true, p_graphcodebert_cal)

    logger.info(f"\n📊 Calibration Improvement:")
    logger.info(f"   CodeBERT ECE:      {ece_cb_before:.4f} → {ece_cb_after:.4f}")
    logger.info(f"   CodeBERT ROC-AUC:  {auc_cb_before:.4f} → {auc_cb_after:.4f}")
    logger.info(f"   GraphCodeBERT ECE: {ece_gcb_before:.4f} → {ece_gcb_after:.4f}")
    logger.info(f"   GraphCodeBERT ROC-AUC: {auc_gcb_before:.4f} → {auc_gcb_after:.4f}")

    # -------------------------------------------------------------------------
    # Step 3: Ensemble Combination
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("🔗 ENSEMBLE COMBINATION")
    logger.info("=" * 80)

    # Weighted ensemble
    p_ensemble = (WEIGHT_CODEBERT * p_codebert_cal +
                  WEIGHT_GRAPHCODEBERT * p_graphcodebert_cal)

    logger.info(f"✅ Combined {len(p_ensemble):,} predictions")
    logger.info(f"   Ensemble probability range: [{p_ensemble.min():.4f}, {p_ensemble.max():.4f}]")
    logger.info(f"   Ensemble probability mean: {p_ensemble.mean():.4f}")

    # -------------------------------------------------------------------------
    # Step 4: Global Threshold Optimization
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("🎯 GLOBAL THRESHOLD OPTIMIZATION")
    logger.info("=" * 80)

    threshold_start = time.time()

    tau_global, best_f1, threshold_curve = optimize_threshold_f1(y_true, p_ensemble)

    logger.info(f"✅ Optimal global threshold: τ = {tau_global:.4f}")
    logger.info(f"   Best F1-score: {best_f1:.4f}")

    # Compute metrics at optimal threshold
    y_pred_global = (p_ensemble >= tau_global).astype(int)
    metrics_global = compute_metrics(y_true, y_pred_global)

    logger.info(f"\n📊 Global Metrics @ τ={tau_global:.3f}:")
    logger.info(f"   Accuracy:  {metrics_global['accuracy']:.4f}")
    logger.info(f"   Precision: {metrics_global['precision']:.4f}")
    logger.info(f"   Recall:    {metrics_global['recall']:.4f}")
    logger.info(f"   F1-Score:  {metrics_global['f1']:.4f}")

    # -------------------------------------------------------------------------
    # Step 5: Per-Language Threshold Optimization
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("🌍 PER-LANGUAGE THRESHOLD OPTIMIZATION")
    logger.info("=" * 80)

    per_language_thresholds = {}
    language_metrics = {}

    unique_languages = np.unique(languages)

    for lang in sorted(unique_languages):
        lang_mask = languages == lang
        n_samples = lang_mask.sum()

        # 🧩 Language Imbalance Guard: Report F1 for small languages
        if n_samples < 100:
            logger.info(f"\n⚠️  {lang}: Insufficient samples ({n_samples}), reusing global τ={tau_global:.3f}")
            per_language_thresholds[lang] = tau_global

            # Still compute metrics for reporting
            y_true_lang = y_true[lang_mask]
            p_ensemble_lang = p_ensemble[lang_mask]
            y_pred_temp = (p_ensemble_lang >= tau_global).astype(int)
            metrics_temp = compute_metrics(y_true_lang, y_pred_temp)
            language_metrics[lang] = metrics_temp
            logger.info(f"   F1 @ global τ: {metrics_temp['f1']:.4f}")
            continue

        logger.info(f"\n{lang}: {n_samples:,} samples")

        y_true_lang = y_true[lang_mask]
        p_ensemble_lang = p_ensemble[lang_mask]

        # Check if language has special strategy
        if lang in LANGUAGE_STRATEGIES:
            strategy = LANGUAGE_STRATEGIES[lang]
            tau_lang = optimize_language_threshold(y_true_lang, p_ensemble_lang, strategy)
            logger.info(f"   Strategy: {strategy}")
        else:
            tau_lang, _, _ = optimize_threshold_f1(y_true_lang, p_ensemble_lang)
            logger.info(f"   Strategy: maximize F1")

        per_language_thresholds[lang] = float(tau_lang)

        # Compute language-specific metrics
        y_pred_lang = (p_ensemble_lang >= tau_lang).astype(int)
        metrics_lang = compute_metrics(y_true_lang, y_pred_lang)
        language_metrics[lang] = metrics_lang

        logger.info(f"   Optimal τ: {tau_lang:.4f}")
        logger.info(f"   F1: {metrics_lang['f1']:.4f} | "
                   f"Prec: {metrics_lang['precision']:.4f} | "
                   f"Rec: {metrics_lang['recall']:.4f}")

    threshold_time = time.time() - threshold_start
    logger.info(f"\n⏱️  Threshold optimization completed in {threshold_time:.1f}s")

    # Save thresholds
    thresholds_config = {
        "global": float(tau_global),
        "per_language": per_language_thresholds,
        "abstain_margin": ABSTAIN_MARGIN
    }

    # 💾 Atomic JSON Writes
    temp_path = THRESHOLDS_JSON + ".tmp"
    with open(temp_path, 'w') as f:
        json.dump(thresholds_config, f, indent=2)
    os.replace(temp_path, THRESHOLDS_JSON)
    logger.info(f"💾 Saved: {THRESHOLDS_JSON}")    # -------------------------------------------------------------------------
    # Step 6: Abstention Band Analysis
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("🤔 ABSTENTION BAND ANALYSIS")
    logger.info("=" * 80)

    # Compute abstention flags
    abstain_mask = np.abs(p_ensemble - tau_global) < ABSTAIN_MARGIN
    n_abstain = abstain_mask.sum()
    abstain_rate = n_abstain / len(p_ensemble)

    logger.info(f"Abstention margin: ±{ABSTAIN_MARGIN}")
    logger.info(f"Samples in abstention band: {n_abstain:,} ({abstain_rate*100:.2f}%)")

    if n_abstain > 0:
        # Metrics on confident predictions only
        confident_mask = ~abstain_mask
        y_true_confident = y_true[confident_mask]
        y_pred_confident = y_pred_global[confident_mask]
        metrics_confident = compute_metrics(y_true_confident, y_pred_confident)

        logger.info(f"\n📊 Metrics on Confident Predictions ({confident_mask.sum():,} samples):")
        logger.info(f"   Accuracy:  {metrics_confident['accuracy']:.4f}")
        logger.info(f"   Precision: {metrics_confident['precision']:.4f}")
        logger.info(f"   Recall:    {metrics_confident['recall']:.4f}")
        logger.info(f"   F1-Score:  {metrics_confident['f1']:.4f}")

    # -------------------------------------------------------------------------
    # Step 7: Save Ensemble Configuration
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("💾 SAVING ENSEMBLE CONFIGURATION")
    logger.info("=" * 80)

    ensemble_config = {
        "models": {
            "graphcodebert": {
                "weight": WEIGHT_GRAPHCODEBERT,
                "temperature": float(T_graphcodebert)
            },
            "codebert": {
                "weight": WEIGHT_CODEBERT,
                "temperature": float(T_codebert)
            }
        },
        "thresholds": {
            "global": float(tau_global),
            "per_language": per_language_thresholds,
            "abstain_margin": ABSTAIN_MARGIN
        },
        "meta": {
            "source_csv": args.input,
            "generated_at": datetime.now().isoformat(),
            "validation_samples": len(df),
            "seed": SEED,
            "global_metrics": {
                "accuracy": float(metrics_global['accuracy']),
                "precision": float(metrics_global['precision']),
                "recall": float(metrics_global['recall']),
                "f1": float(metrics_global['f1'])
            },
            "calibration": {
                "codebert_ece_before": float(ece_cb_before),
                "codebert_ece_after": float(ece_cb_after),
                "graphcodebert_ece_before": float(ece_gcb_before),
                "graphcodebert_ece_after": float(ece_gcb_after)
            }
        }
    }

    # 💾 Atomic JSON Writes
    temp_path = ENSEMBLE_CONFIG_JSON + ".tmp"
    with open(temp_path, 'w') as f:
        json.dump(ensemble_config, f, indent=2)
    os.replace(temp_path, ENSEMBLE_CONFIG_JSON)
    logger.info(f"✅ Saved: {ENSEMBLE_CONFIG_JSON}")

    # -------------------------------------------------------------------------
    # Step 8: Save Calibrated Results
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("💾 SAVING CALIBRATED RESULTS")
    logger.info("=" * 80)

    results_df = pd.DataFrame({
        'language': languages,
        'y_true': y_true,
        'logits_codebert': logits_codebert,
        'logits_graphcodebert': logits_graphcodebert,
        'p_codebert_calibrated': p_codebert_cal,
        'p_graphcodebert_calibrated': p_graphcodebert_cal,
        'p_ensemble': p_ensemble,
        'y_pred_global': y_pred_global,
        'abstain': abstain_mask
    })

    results_df.to_csv(CALIBRATED_CSV, index=False)
    logger.info(f"✅ Saved {len(results_df):,} calibrated predictions to: {CALIBRATED_CSV}")
    logger.info(f"   File size: {os.path.getsize(CALIBRATED_CSV) / 1e6:.2f} MB")

    # -------------------------------------------------------------------------
    # Step 9: Generate Visualizations
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("📊 GENERATING VISUALIZATIONS")
    logger.info("=" * 80)

    # Before/after ensemble probabilities
    p_ensemble_uncal = WEIGHT_CODEBERT * p_codebert_uncal + WEIGHT_GRAPHCODEBERT * p_graphcodebert_uncal

    # Precision-Recall curve
    plot_precision_recall_curve(
        y_true, p_ensemble_uncal, p_ensemble,
        f"{PLOTS_DIR}/precision_recall_curve.png"
    )

    # F1 vs Threshold
    plot_f1_vs_threshold(
        threshold_curve, tau_global,
        f"{PLOTS_DIR}/f1_vs_threshold.png"
    )

    # Calibration reliability diagrams
    ece_ensemble, bins_ensemble = compute_ece(y_true, p_ensemble)
    plot_calibration_reliability(
        y_true, p_ensemble, bins_ensemble, "Ensemble",
        f"{PLOTS_DIR}/calibration_reliability.png"
    )

    logger.info(f"✅ Saved 3 diagnostic plots to: {PLOTS_DIR}/")

    # -------------------------------------------------------------------------
    # Step 10: Generate Summary Report
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("📘 GENERATING SUMMARY REPORT")
    logger.info("=" * 80)

    # Compute ensemble AUC
    auc_ensemble_before = roc_auc_score(y_true, p_ensemble_uncal)
    auc_ensemble_after = roc_auc_score(y_true, p_ensemble)

    # 🧰 Diagnostics Summary File
    summary = {
        "execution": {
            "total_time_seconds": round(time.time() - start_time, 2),
            "calibration_time_seconds": round(calibration_time, 2),
            "threshold_time_seconds": round(threshold_time, 2)
        },
        "dataset": {
            "num_samples": len(df),
            "num_languages": len(unique_languages),
            "label_distribution": {
                "vulnerable": int((y_true == 1).sum()),
                "secure": int((y_true == 0).sum())
            }
        },
        "calibration": {
            "temperatures": calibration_values,
            "ece_improvement": {
                "codebert": {"before": float(ece_cb_before), "after": float(ece_cb_after)},
                "graphcodebert": {"before": float(ece_gcb_before), "after": float(ece_gcb_after)}
            },
            "auc": {
                "codebert": {"before": float(auc_cb_before), "after": float(auc_cb_after)},
                "graphcodebert": {"before": float(auc_gcb_before), "after": float(auc_gcb_after)},
                "ensemble": {"before": float(auc_ensemble_before), "after": float(auc_ensemble_after)}
            }
        },
        "ensemble": {
            "weights": {
                "codebert": WEIGHT_CODEBERT,
                "graphcodebert": WEIGHT_GRAPHCODEBERT
            }
        },
        "thresholds": {
            "global": float(tau_global),
            "num_language_specific": len([t for t in per_language_thresholds.values() if t != tau_global])
        },
        "performance": {
            "global_metrics": {
                "accuracy": float(metrics_global['accuracy']),
                "precision": float(metrics_global['precision']),
                "recall": float(metrics_global['recall']),
                "f1": float(metrics_global['f1'])
            },
            "abstain_rate": float(abstain_rate)
        },
        "metadata": {
            "input_csv": args.input,
            "metadata_loaded": metadata_loaded,
            "generated_at": datetime.now().isoformat(),
            "seed": SEED
        }
    }

    summary_path = f"{OUTPUT_DIR}/summary.json"
    temp_path = summary_path + ".tmp"
    with open(temp_path, 'w') as f:
        json.dump(summary, f, indent=2)
    os.replace(temp_path, summary_path)
    logger.info(f"📘 Saved summary report to: {summary_path}")

    # -------------------------------------------------------------------------
    # Step 11: Final Summary
    # -------------------------------------------------------------------------    total_time = time.time() - start_time

    logger.info("\n" + "=" * 80)
    logger.info("📊 OPTIMIZATION SUMMARY")
    logger.info("=" * 80)

    logger.info(f"\n🌡️  Temperature Scaling:")
    logger.info(f"   CodeBERT:      T = {T_codebert:.4f}")
    logger.info(f"   GraphCodeBERT: T = {T_graphcodebert:.4f}")

    logger.info(f"\n🎯 Optimal Thresholds:")
    logger.info(f"   Global:        τ = {tau_global:.4f} (F1={best_f1:.4f})")
    for lang, tau in sorted(per_language_thresholds.items())[:5]:
        logger.info(f"   {lang:<15} τ = {tau:.4f}")
    if len(per_language_thresholds) > 5:
        logger.info(f"   ... and {len(per_language_thresholds) - 5} more languages")

    logger.info(f"\n📈 Performance Improvement:")
    logger.info(f"   Ensemble ECE:      {ece_ensemble:.4f}")
    logger.info(f"   Ensemble ROC-AUC:  {auc_ensemble_before:.4f} → {auc_ensemble_after:.4f}")
    logger.info(f"   Global F1:         {metrics_global['f1']:.4f}")
    logger.info(f"   Abstain Rate:      {abstain_rate*100:.1f}%")

    total_time = time.time() - start_time

    logger.info(f"\n⏱️  Runtime:")
    logger.info(f"   Calibration:   {calibration_time:.1f}s")
    logger.info(f"   Thresholds:    {threshold_time:.1f}s")
    logger.info(f"   Total:         {total_time:.1f}s ({total_time/60:.1f} min)")

    logger.info(f"\n💾 Output Files:")
    logger.info(f"   {CALIBRATION_JSON}")
    logger.info(f"   {THRESHOLDS_JSON}")
    logger.info(f"   {ENSEMBLE_CONFIG_JSON}")
    logger.info(f"   {CALIBRATED_CSV}")
    logger.info(f"   {PLOTS_DIR}/ (3 plots)")

    logger.info("\n" + "=" * 80)
    logger.info("✅ THRESHOLD OPTIMIZATION COMPLETE")
    logger.info("=" * 80)
    logger.info("\n🎯 Next Steps:")
    logger.info("   1. Review ensemble_config.json for inference configuration")
    logger.info("   2. Check plots/ for calibration diagnostics")
    logger.info("   3. Use calibrated_val_results.csv for further analysis")
    logger.info("   4. Deploy ensemble_config.json to production inference pipeline")
    logger.info("=" * 80)

    # 🧹 Memory & Exit Clean-Up: Free resources before exit
    logger.info("\n🧹 Cleaning up memory...")
    del df, results_df, p_ensemble, p_codebert_cal, p_graphcodebert_cal
    del p_ensemble_uncal, p_codebert_uncal, p_graphcodebert_uncal
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    logger.info("✅ Memory cleanup complete")

if __name__ == "__main__":
    main()
