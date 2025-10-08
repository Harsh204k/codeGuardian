#!/usr/bin/env python3
"""
Fusion XGBoost Model Training Script
Phase 3.2 - Production-Grade ML Pipeline

This script trains a meta-model (fusion) that combines outputs from:
- Static analyzer (XGBoost on M1-M15 features)
- CodeBERT classifier
- GraphCodeBERT classifier

Features:
- Feature engineering (interactions, ratios, ensemble features)
- Optuna hyperparameter tuning
- Stratified k-fold CV with out-of-fold predictions
- Model calibration
- SHAP explainability with subsystem contribution analysis
- Comprehensive evaluation
- Model versioning and metadata tracking
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import optuna
import pandas as pd
import shap
import yaml
from matplotlib import pyplot as plt
from sklearn.calibration import CalibratedClassifierCV
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from xgboost import XGBClassifier

# Set random seeds for reproducibility
np.random.seed(42)


class XGBoostFusionTrainer:
    """Production-grade trainer for Fusion XGBoost meta-model."""
    
    def __init__(self, config_path: str, seed: int = 42):
        """Initialize trainer with configuration.
        
        Args:
            config_path: Path to fusion_config.yml
            seed: Random seed for reproducibility
        """
        self.seed = seed
        np.random.seed(seed)
        
        # Load config
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Setup logging
        self._setup_logging()
        
        # Create output directories
        self._create_output_dirs()
        
        # Initialize metadata
        self.metadata = {
            'model_name': self.config['model_name'],
            'version': self.config['version'],
            'timestamp': datetime.now().isoformat(),
            'config_path': config_path,
            'seed': seed,
        }
        
        self.logger.info(f"Initialized {self.config['model_name']} trainer")
    
    def _setup_logging(self):
        """Setup logging to console and file."""
        log_dir = Path(self.config.get('output', {}).get('logs', 'logs/fusion'))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"training_fusion_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Logging to {log_file}")
    
    def _create_output_dirs(self):
        """Create output directories for models, metrics, plots, etc."""
        output_config = self.config.get('output', {})
        dirs = [
            output_config.get('models', 'models/fusion'),
            output_config.get('metrics', 'metrics'),
            output_config.get('plots', 'plots/fusion'),
            output_config.get('shap', 'shap/fusion'),
            output_config.get('logs', 'logs/fusion'),
        ]
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    def load_data(self, split: str = "train") -> pd.DataFrame:
        """Load fused JSONL data.
        
        Args:
            split: Which split to load (train/val/test)
        
        Returns:
            DataFrame with all features
        """
        self.logger.info(f"Loading {split} data...")
        
        data_config = self.config['data']
        fused_dir = Path(data_config['fused_dir'])
        split_file = fused_dir / data_config['splits'][split]
        
        if not split_file.exists():
            raise FileNotFoundError(f"Split file not found: {split_file}")
        
        # Load JSONL
        records = []
        with open(split_file, 'r') as f:
            for line in f:
                records.append(json.loads(line))
        
        df = pd.DataFrame(records)
        self.logger.info(f"Loaded {len(df)} samples from {split_file}")
        
        # Validate required features
        required = set(data_config['required_features'])
        missing = required - set(df.columns)
        if missing:
            raise ValueError(f"Missing required features: {missing}")
        
        return df
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create interaction, ratio, and ensemble features.
        
        Args:
            df: Input DataFrame
        
        Returns:
            DataFrame with engineered features
        """
        self.logger.info("Engineering features...")
        fe_config = self.config['feature_engineering']
        
        # Create interactions
        if fe_config.get('create_interactions', True):
            for feat1, feat2 in fe_config['interactions']:
                if feat1 in df.columns and feat2 in df.columns:
                    df[f"{feat1}_x_{feat2}"] = df[feat1] * df[feat2]
        
        # Create ratios (with safe division)
        if fe_config.get('create_ratios', True):
            for num_feat, denom_feat, name in fe_config['ratios']:
                if num_feat in df.columns and denom_feat in df.columns:
                    df[name] = df[num_feat] / (df[denom_feat] + 1e-10)
        
        # Create ensemble features
        if fe_config.get('create_ensemble_features', True):
            ensemble_config = fe_config['ensemble']
            for agg_name, feature_list in ensemble_config.items():
                available = [f for f in feature_list if f in df.columns]
                if available:
                    if 'mean' in agg_name:
                        df[agg_name] = df[available].mean(axis=1)
                    elif 'max' in agg_name:
                        df[agg_name] = df[available].max(axis=1)
                    elif 'min' in agg_name:
                        df[agg_name] = df[available].min(axis=1)
        
        self.logger.info(f"Engineered features. New shape: {df.shape}")
        return df
    
    def preprocess_data(
        self,
        train_df: pd.DataFrame,
        val_df: Optional[pd.DataFrame] = None,
        test_df: Optional[pd.DataFrame] = None
    ) -> Tuple:
        """Preprocess train/val/test splits.
        
        Args:
            train_df: Training DataFrame
            val_df: Validation DataFrame (optional)
            test_df: Test DataFrame (optional)
        
        Returns:
            Tuple of (X_train, y_train, X_val, y_val, X_test, y_test, feature_names)
        """
        self.logger.info("Preprocessing data...")
        
        data_config = self.config['data']
        preproc_config = self.config['preprocessing']
        
        # Separate features and labels
        target_col = data_config['target_column']
        id_col = data_config['id_column']
        
        drop_cols = [target_col, id_col]
        
        y_train = train_df[target_col].values
        X_train = train_df.drop(columns=drop_cols, errors='ignore')
        
        y_val = val_df[target_col].values if val_df is not None else None
        X_val = val_df.drop(columns=drop_cols, errors='ignore') if val_df is not None else None
        
        y_test = test_df[target_col].values if test_df is not None else None
        X_test = test_df.drop(columns=drop_cols, errors='ignore') if test_df is not None else None
        
        # Clip probabilities
        if preproc_config.get('clip_probabilities', True):
            prob_cols = [c for c in X_train.columns if 'prob' in c.lower()]
            for col in prob_cols:
                X_train[col] = X_train[col].clip(0, 1)
                if X_val is not None:
                    X_val[col] = X_val[col].clip(0, 1)
                if X_test is not None:
                    X_test[col] = X_test[col].clip(0, 1)
        
        # Handle categorical features
        cat_cols = [c for c in X_train.columns if X_train[c].dtype == 'object']
        if cat_cols and preproc_config.get('handle_categorical') == 'onehot':
            self.logger.info(f"One-hot encoding {len(cat_cols)} categorical features")
            encoder = OneHotEncoder(
                max_categories=preproc_config.get('max_categories', 50),
                handle_unknown='ignore',
                sparse_output=False
            )
            
            train_encoded = encoder.fit_transform(X_train[cat_cols])
            X_train = X_train.drop(columns=cat_cols)
            X_train = pd.concat([
                X_train.reset_index(drop=True),
                pd.DataFrame(train_encoded, columns=encoder.get_feature_names_out())
            ], axis=1)
            
            if X_val is not None:
                val_encoded = encoder.transform(X_val[cat_cols])
                X_val = X_val.drop(columns=cat_cols)
                X_val = pd.concat([
                    X_val.reset_index(drop=True),
                    pd.DataFrame(val_encoded, columns=encoder.get_feature_names_out())
                ], axis=1)
            
            if X_test is not None:
                test_encoded = encoder.transform(X_test[cat_cols])
                X_test = X_test.drop(columns=cat_cols)
                X_test = pd.concat([
                    X_test.reset_index(drop=True),
                    pd.DataFrame(test_encoded, columns=encoder.get_feature_names_out())
                ], axis=1)
        
        # Impute missing values
        self.imputer = SimpleImputer(strategy=preproc_config.get('impute_strategy', 'median'))
        X_train = pd.DataFrame(
            self.imputer.fit_transform(X_train),
            columns=X_train.columns
        )
        
        if X_val is not None:
            X_val = pd.DataFrame(
                self.imputer.transform(X_val),
                columns=X_val.columns
            )
        
        if X_test is not None:
            X_test = pd.DataFrame(
                self.imputer.transform(X_test),
                columns=X_test.columns
            )
        
        feature_names = X_train.columns.tolist()
        self.logger.info(f"Preprocessed data. Features: {len(feature_names)}")
        
        return X_train, y_train, X_val, y_val, X_test, y_test, feature_names
    
    def train_model(
        self,
        X_train: pd.DataFrame,
        y_train: np.ndarray,
        X_val: Optional[pd.DataFrame] = None,
        y_val: Optional[np.ndarray] = None,
        tune: bool = False,
        n_trials: int = 30
    ) -> XGBClassifier:
        """Train XGBoost fusion model.
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels
            tune: Whether to tune hyperparameters
            n_trials: Number of Optuna trials
        
        Returns:
            Trained XGBClassifier
        """
        self.logger.info("Training fusion model...")
        
        # Calculate scale_pos_weight
        model_config = self.config['model'].copy()
        if model_config['scale_pos_weight'] is None:
            pos_count = np.sum(y_train == 1)
            neg_count = np.sum(y_train == 0)
            model_config['scale_pos_weight'] = neg_count / (pos_count + 1e-10)
            self.logger.info(f"Auto scale_pos_weight: {model_config['scale_pos_weight']:.2f}")
        
        # Tune hyperparameters
        if tune:
            self.logger.info(f"Starting hyperparameter tuning ({n_trials} trials)...")
            best_params = self._tune_hyperparameters(
                X_train, y_train, X_val, y_val, n_trials
            )
            model_config.update(best_params)
        
        # Train final model
        model = XGBClassifier(**model_config)
        
        if X_val is not None and y_val is not None:
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                verbose=False
            )
        else:
            model.fit(X_train, y_train, verbose=False)
        
        self.logger.info(f"Training complete. Best iteration: {model.best_iteration}")
        return model
    
    def _tune_hyperparameters(
        self,
        X_train: pd.DataFrame,
        y_train: np.ndarray,
        X_val: pd.DataFrame,
        y_val: np.ndarray,
        n_trials: int
    ) -> Dict:
        """Tune hyperparameters using Optuna.
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels
            n_trials: Number of trials
        
        Returns:
            Best hyperparameters dict
        """
        tuning_config = self.config['tuning']
        search_space = tuning_config['search_space']
        
        def objective(trial):
            params = self.config['model'].copy()
            
            # Sample hyperparameters
            for param_name, param_config in search_space.items():
                if param_config['type'] == 'int':
                    params[param_name] = trial.suggest_int(
                        param_name,
                        param_config['low'],
                        param_config['high'],
                        step=param_config.get('step', 1)
                    )
                elif param_config['type'] == 'float':
                    params[param_name] = trial.suggest_float(
                        param_name,
                        param_config['low'],
                        param_config['high'],
                        log=param_config.get('log', False)
                    )
            
            # Train model
            model = XGBClassifier(**params)
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                verbose=False
            )
            
            # Evaluate
            y_pred_proba = model.predict_proba(X_val)[:, 1]
            
            # Use PR-AUC as primary metric
            precision, recall, _ = precision_recall_curve(y_val, y_pred_proba)
            pr_auc = np.trapz(recall, precision)
            
            return pr_auc
        
        study = optuna.create_study(
            direction=tuning_config.get('direction', 'maximize'),
            sampler=optuna.samplers.TPESampler(seed=self.seed)
        )
        study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
        
        self.logger.info(f"Best trial: {study.best_trial.number}")
        self.logger.info(f"Best {tuning_config['metric']}: {study.best_value:.4f}")
        
        return study.best_params
    
    def train_with_cv(
        self,
        X: pd.DataFrame,
        y: np.ndarray
    ) -> List[XGBClassifier]:
        """Train with stratified k-fold cross-validation.
        
        Args:
            X: Features
            y: Labels
        
        Returns:
            List of trained models (one per fold)
        """
        cv_config = self.config['cross_validation']
        if not cv_config.get('enabled', True):
            return []
        
        n_folds = cv_config.get('n_folds', 5)
        self.logger.info(f"Training with {n_folds}-fold CV...")
        
        skf = StratifiedKFold(
            n_splits=n_folds,
            shuffle=True,
            random_state=self.seed
        )
        
        models = []
        fold_metrics = []
        oof_predictions = np.zeros(len(y))
        
        for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            self.logger.info(f"Training fold {fold_idx + 1}/{n_folds}...")
            
            X_train_fold = X.iloc[train_idx]
            y_train_fold = y[train_idx]
            X_val_fold = X.iloc[val_idx]
            y_val_fold = y[val_idx]
            
            # Train model
            model = self.train_model(X_train_fold, y_train_fold, X_val_fold, y_val_fold)
            models.append(model)
            
            # Out-of-fold predictions
            oof_predictions[val_idx] = model.predict_proba(X_val_fold)[:, 1]
            
            # Evaluate fold
            metrics = self.evaluate_model(model, X_val_fold, y_val_fold, f"fold{fold_idx+1}")
            fold_metrics.append(metrics)
        
        # Save OOF predictions
        if cv_config.get('save_fold_predictions', True):
            oof_dir = Path(self.config['output']['metrics'])
            oof_file = oof_dir / "fusion_oof_predictions.csv"
            pd.DataFrame({
                'oof_prob': oof_predictions,
                'true_label': y
            }).to_csv(oof_file, index=False)
            self.logger.info(f"Saved OOF predictions to {oof_file}")
        
        # Aggregate fold metrics
        avg_metrics = {}
        for key in fold_metrics[0].keys():
            avg_metrics[f"cv_{key}"] = np.mean([m[key] for m in fold_metrics])
        
        self.logger.info(f"CV PR-AUC: {avg_metrics['cv_pr_auc']:.4f}")
        
        return models
    
    def calibrate_model(
        self,
        model: XGBClassifier,
        X_val: pd.DataFrame,
        y_val: np.ndarray
    ) -> CalibratedClassifierCV:
        """Calibrate model probabilities.
        
        Args:
            model: Trained model
            X_val: Validation features
            y_val: Validation labels
        
        Returns:
            Calibrated model
        """
        calib_config = self.config.get('calibration', {})
        if not calib_config.get('enabled', True):
            return None
        
        self.logger.info("Calibrating model...")
        
        calibrated = CalibratedClassifierCV(
            model,
            method=calib_config.get('method', 'isotonic'),
            cv=calib_config.get('cv_folds', 5)
        )
        calibrated.fit(X_val, y_val)
        
        return calibrated
    
    def evaluate_model(
        self,
        model: XGBClassifier,
        X: pd.DataFrame,
        y: np.ndarray,
        split_name: str
    ) -> Dict:
        """Evaluate model and compute metrics.
        
        Args:
            model: Trained model
            X: Features
            y: True labels
            split_name: Name of split (e.g., 'val', 'test')
        
        Returns:
            Dictionary of metrics
        """
        self.logger.info(f"Evaluating on {split_name}...")
        
        y_pred_proba = model.predict_proba(X)[:, 1]
        y_pred = model.predict(X)
        
        # Compute metrics
        precision, recall, thresholds = precision_recall_curve(y, y_pred_proba)
        pr_auc = np.trapz(recall, precision)
        
        fpr, tpr, _ = roc_curve(y, y_pred_proba)
        roc_auc = roc_auc_score(y, y_pred_proba)
        
        metrics = {
            'pr_auc': pr_auc,
            'roc_auc': roc_auc,
            'f1': f1_score(y, y_pred),
            'precision': precision_score(y, y_pred),
            'recall': recall_score(y, y_pred),
            'accuracy': accuracy_score(y, y_pred),
            'brier_score': brier_score_loss(y, y_pred_proba),
        }
        
        self.logger.info(f"{split_name} - PR-AUC: {pr_auc:.4f}, ROC-AUC: {roc_auc:.4f}, F1: {metrics['f1']:.4f}")
        
        # Save metrics
        metrics_dir = Path(self.config['output']['metrics'])
        metrics_file = metrics_dir / f"fusion_eval_{split_name}.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        return metrics
    
    def generate_shap_explanations(
        self,
        model: XGBClassifier,
        X: pd.DataFrame,
        split_name: str
    ):
        """Generate SHAP explanations.
        
        Args:
            model: Trained model
            X: Features
            split_name: Name of split
        """
        shap_config = self.config.get('explainability', {})
        if not shap_config.get('enabled', True):
            return
        
        self.logger.info("Generating SHAP explanations...")
        
        # Sample data
        n_samples = min(shap_config.get('n_samples', 500), len(X))
        X_sample = X.sample(n=n_samples, random_state=self.seed)
        
        # Compute SHAP values
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_sample)
        
        # Save plots
        plots_dir = Path(self.config['output']['shap'])
        
        # Summary plot
        if shap_config.get('save_summary_plot', True):
            plt.figure(figsize=(10, 8))
            shap.summary_plot(shap_values, X_sample, show=False)
            plt.tight_layout()
            plt.savefig(plots_dir / f"fusion_shap_summary_{split_name}.png", dpi=300)
            plt.close()
        
        # Importance bar plot
        if shap_config.get('save_importance_plot', True):
            plt.figure(figsize=(10, 8))
            shap.summary_plot(shap_values, X_sample, plot_type="bar", show=False)
            plt.tight_layout()
            plt.savefig(plots_dir / f"fusion_shap_importance_{split_name}.png", dpi=300)
            plt.close()
        
        # Subsystem contribution analysis
        if shap_config.get('analyze_subsystem_contribution', True):
            self._analyze_subsystem_contribution(shap_values, X_sample, split_name)
        
        self.logger.info(f"SHAP explanations saved to {plots_dir}")
    
    def _analyze_subsystem_contribution(
        self,
        shap_values: np.ndarray,
        X: pd.DataFrame,
        split_name: str
    ):
        """Analyze contribution of each subsystem (static, codebert, graph).
        
        Args:
            shap_values: SHAP values array
            X: Features DataFrame
            split_name: Name of split
        """
        self.logger.info("Analyzing subsystem contributions...")
        
        # Group features by subsystem
        static_features = [f for f in X.columns if 'static' in f.lower()]
        codebert_features = [f for f in X.columns if 'codebert' in f.lower()]
        graph_features = [f for f in X.columns if 'graph' in f.lower()]
        
        # Compute mean absolute SHAP for each subsystem
        static_idx = [X.columns.get_loc(f) for f in static_features if f in X.columns]
        codebert_idx = [X.columns.get_loc(f) for f in codebert_features if f in X.columns]
        graph_idx = [X.columns.get_loc(f) for f in graph_features if f in X.columns]
        
        contributions = {
            'static': np.abs(shap_values[:, static_idx]).mean() if static_idx else 0,
            'codebert': np.abs(shap_values[:, codebert_idx]).mean() if codebert_idx else 0,
            'graphcodebert': np.abs(shap_values[:, graph_idx]).mean() if graph_idx else 0,
        }
        
        self.logger.info(f"Subsystem contributions: {contributions}")
        
        # Save to JSON
        metrics_dir = Path(self.config['output']['metrics'])
        contrib_file = metrics_dir / f"fusion_subsystem_contrib_{split_name}.json"
        with open(contrib_file, 'w') as f:
            json.dump(contributions, f, indent=2)
    
    def save_model(
        self,
        model: XGBClassifier,
        feature_names: List[str],
        calibrated_model: Optional[CalibratedClassifierCV] = None
    ):
        """Save model and metadata.
        
        Args:
            model: Trained model
            feature_names: List of feature names
            calibrated_model: Calibrated model (optional)
        """
        self.logger.info("Saving model...")
        
        models_dir = Path(self.config['output']['models'])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save base model
        model_file = models_dir / f"xgb_fusion_v{timestamp}.joblib"
        joblib.dump(model, model_file)
        self.logger.info(f"Saved model to {model_file}")
        
        # Save calibrated model
        if calibrated_model is not None:
            calib_file = models_dir / f"calibrated_xgb_fusion_v{timestamp}.joblib"
            joblib.dump(calibrated_model, calib_file)
            self.logger.info(f"Saved calibrated model to {calib_file}")
        
        # Save imputer
        imputer_file = models_dir / f"imputer_fusion_v{timestamp}.joblib"
        joblib.dump(self.imputer, imputer_file)
        
        # Get git commit
        try:
            git_commit = subprocess.check_output(
                ['git', 'rev-parse', 'HEAD']
            ).decode('utf-8').strip()
        except:
            git_commit = "unknown"
        
        # Save metadata
        self.metadata.update({
            'feature_names': feature_names,
            'n_features': len(feature_names),
            'model_params': model.get_params(),
            'best_iteration': model.best_iteration,
            'git_commit': git_commit,
        })
        
        metadata_file = models_dir / f"metadata_xgb_fusion_v{timestamp}.yaml"
        with open(metadata_file, 'w') as f:
            yaml.dump(self.metadata, f)
        
        self.logger.info(f"Saved metadata to {metadata_file}")


def main():
    """Main training script."""
    parser = argparse.ArgumentParser(description="Train Fusion XGBoost meta-model")
    parser.add_argument(
        '--fused-dir',
        type=str,
        default='datasets/fused',
        help='Path to fused dataset directory'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='src/ml/fusion/fusion_config.yml',
        help='Path to fusion configuration file'
    )
    parser.add_argument(
        '--tune',
        action='store_true',
        help='Enable hyperparameter tuning'
    )
    parser.add_argument(
        '--n-trials',
        type=int,
        default=30,
        help='Number of Optuna trials for tuning'
    )
    parser.add_argument(
        '--cv',
        action='store_true',
        help='Enable cross-validation'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Random seed for reproducibility'
    )
    parser.add_argument(
        '--save-model',
        action='store_true',
        help='Save trained model to disk'
    )
    
    args = parser.parse_args()
    
    # Initialize trainer
    trainer = XGBoostFusionTrainer(args.config, seed=args.seed)
    
    # Load data
    train_df = trainer.load_data('train')
    val_df = trainer.load_data('val')
    
    # Engineer features
    train_df = trainer.engineer_features(train_df)
    val_df = trainer.engineer_features(val_df)
    
    # Preprocess
    X_train, y_train, X_val, y_val, _, _, feature_names = trainer.preprocess_data(
        train_df, val_df
    )
    
    # Train with CV or single model
    if args.cv:
        # Combine train and val for CV
        X_combined = pd.concat([X_train, X_val], ignore_index=True)
        y_combined = np.concatenate([y_train, y_val])
        models = trainer.train_with_cv(X_combined, y_combined)
        
        # Use first fold model as main model
        model = models[0]
    else:
        # Train single model
        model = trainer.train_model(
            X_train, y_train, X_val, y_val,
            tune=args.tune, n_trials=args.n_trials
        )
    
    # Calibrate
    calibrated_model = trainer.calibrate_model(model, X_val, y_val)
    
    # Evaluate
    trainer.evaluate_model(model, X_val, y_val, 'val')
    
    # SHAP explanations
    trainer.generate_shap_explanations(model, X_val, 'val')
    
    # Save model
    if args.save_model:
        trainer.save_model(model, feature_names, calibrated_model)
    
    trainer.logger.info("Training complete!")


if __name__ == '__main__':
    main()
