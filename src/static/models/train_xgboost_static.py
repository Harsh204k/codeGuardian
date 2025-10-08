#!/usr/bin/env python3
"""
XGBoost Static Model Training Script (Phase 3.2 Enhanced)
==========================================================

Production-grade training pipeline for static analysis features (M1-M15).

Features:
- Hyperparameter tuning with Optuna
- Class imbalance handling (SMOTE, scale_pos_weight)
- Model calibration (isotonic/sigmoid)
- SHAP explainability
- Reproducible training with metadata tracking

Usage:
    python src/static/models/train_xgboost_static.py \\
        --features-csv datasets/features/features_all.csv \\
        --split train \\
        --config src/static/models/model_config.yml \\
        --tune --n-trials 50 --seed 42 --save-model

Author: CodeGuardian Team
Version: 3.2.0
"""

import argparse
import json
import logging
import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
import warnings

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.calibration import CalibratedClassifierCV
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    roc_auc_score, average_precision_score, f1_score,
    precision_score, recall_score, accuracy_score,
    confusion_matrix, classification_report,
    roc_curve, precision_recall_curve, brier_score_loss
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_selection import VarianceThreshold
import xgboost as xgb
from tqdm import tqdm

warnings.filterwarnings('ignore')

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# Optional imports
try:
    import optuna
    from optuna.samplers import TPESampler
    HAS_OPTUNA = True
except ImportError:
    HAS_OPTUNA = False
    print("⚠️  Optuna not installed. Hyperparameter tuning disabled.")

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    print("⚠️  SHAP not installed. Explainability features disabled.")

try:
    from imblearn.over_sampling import SMOTE, RandomOverSampler
    from imblearn.under_sampling import RandomUnderSampler
    HAS_IMBLEARN = True
except ImportError:
    HAS_IMBLEARN = False
    print("⚠️  imbalanced-learn not installed. SMOTE unavailable.")

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_PLOTTING = True
    sns.set_style('whitegrid')
except ImportError:
    HAS_PLOTTING = False
    print("⚠️  matplotlib/seaborn not installed. Plotting disabled.")


class XGBoostStaticTrainer:
    """Production-grade XGBoost trainer for static analysis features."""
    
    def __init__(self, config: Dict[str, Any], seed: int = 42):
        """
        Initialize trainer with configuration.
        
        Args:
            config: Configuration dictionary from YAML
            seed: Random seed for reproducibility
        """
        self.config = config
        self.seed = seed
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Set random seeds
        np.random.seed(seed)
        
        # Setup logging
        self._setup_logging()
        
        # Create output directories
        self._create_output_dirs()
        
        # Initialize attributes
        self.model = None
        self.calibrated_model = None
        self.feature_names = None
        self.preprocessor = {}
        self.metadata = {}
        
        self.logger.info("XGBoost Static Trainer initialized")
        self.logger.info(f"Seed: {seed}, Timestamp: {self.timestamp}")
    
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config['logging']['level'])
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Console handler
        logging.basicConfig(level=log_level, format=log_format)
        self.logger = logging.getLogger(__name__)
        
        # File handler
        if self.config['logging']['save_to_file']:
            log_dir = Path(self.config['output']['logs_dir'])
            log_dir.mkdir(parents=True, exist_ok=True)
            
            log_filename = self.config['logging']['log_filename'].format(
                timestamp=self.timestamp
            )
            log_path = log_dir / log_filename
            
            file_handler = logging.FileHandler(log_path)
            file_handler.setFormatter(logging.Formatter(log_format))
            self.logger.addHandler(file_handler)
            
            self.logger.info(f"Logging to: {log_path}")
    
    def _create_output_dirs(self):
        """Create all required output directories."""
        dirs = [
            self.config['output']['models_dir'],
            self.config['output']['metrics_dir'],
            self.config['output']['plots_dir'],
            self.config['output']['shap_dir'],
            self.config['output']['logs_dir']
        ]
        
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    def load_data(self, features_csv: str, split: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Load and prepare data for training.
        
        Args:
            features_csv: Path to features CSV
            split: Data split (train/val/test)
        
        Returns:
            Tuple of (train_df, val_df, test_df)
        """
        self.logger.info(f"Loading data from {features_csv}")
        
        # Load features
        if Path(features_csv).exists():
            df = pd.read_csv(features_csv)
            self.logger.info(f"Loaded {len(df)} records from features CSV")
        else:
            # Alternative: load from JSONL and join with features
            self.logger.info(f"Features CSV not found. Loading from JSONL...")
            df = self._load_from_jsonl(split)
        
        # Validate required columns
        required_cols = (
            [self.config['data']['id_column'], self.config['data']['target_column']] +
            self.config['data']['feature_columns']
        )
        
        missing_cols = set(required_cols) - set(df.columns)
        if missing_cols:
            self.logger.warning(f"Missing columns: {missing_cols}")
        
        # Split data
        if split == 'train':
            # Use 80-20 split for train-val
            from sklearn.model_selection import train_test_split
            train_df, val_df = train_test_split(
                df, test_size=0.2, random_state=self.seed,
                stratify=df[self.config['data']['target_column']]
            )
            test_df = pd.DataFrame()  # Empty test set
        else:
            train_df = df[df['split'] == 'train'] if 'split' in df.columns else df
            val_df = df[df['split'] == 'val'] if 'split' in df.columns else pd.DataFrame()
            test_df = df[df['split'] == 'test'] if 'split' in df.columns else pd.DataFrame()
        
        self.logger.info(f"Data splits - Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")
        
        return train_df, val_df, test_df
    
    def _load_from_jsonl(self, split: str) -> pd.DataFrame:
        """Load data from JSONL files and join with features."""
        processed_dir = Path(self.config['data']['processed_dir'])
        
        # Load JSONL
        split_file = processed_dir / self.config['data']['splits'][split]
        
        records = []
        with open(split_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
        
        df = pd.DataFrame(records)
        self.logger.info(f"Loaded {len(df)} records from {split_file}")
        
        # Extract static metrics if nested
        if 'static_analysis' in df.columns:
            static_df = pd.json_normalize(df['static_analysis'])
            static_df = static_df.add_prefix('static_')
            df = pd.concat([df, static_df], axis=1)
        
        return df
    
    def preprocess_data(self, train_df: pd.DataFrame, val_df: pd.DataFrame, 
                       test_df: pd.DataFrame) -> Tuple:
        """
        Preprocess data: imputation, encoding, feature selection.
        
        Args:
            train_df, val_df, test_df: DataFrames
        
        Returns:
            Tuple of (X_train, y_train, X_val, y_val, X_test, y_test)
        """
        self.logger.info("Preprocessing data...")
        
        # Extract features and target
        feature_cols = (
            self.config['data']['feature_columns'] +
            self.config['data'].get('additional_features', [])
        )
        
        # Filter to available columns
        feature_cols = [c for c in feature_cols if c in train_df.columns]
        self.feature_names = feature_cols.copy()
        
        target_col = self.config['data']['target_column']
        categorical_cols = self.config['data'].get('categorical_features', [])
        
        # Separate numeric and categorical
        numeric_cols = [c for c in feature_cols if c not in categorical_cols]
        categorical_cols = [c for c in categorical_cols if c in train_df.columns]
        
        self.logger.info(f"Numeric features: {len(numeric_cols)}, Categorical: {len(categorical_cols)}")
        
        # Extract X, y
        X_train = train_df[feature_cols].copy()
        y_train = train_df[target_col].values
        
        X_val = val_df[feature_cols].copy() if len(val_df) > 0 else pd.DataFrame()
        y_val = val_df[target_col].values if len(val_df) > 0 else np.array([])
        
        X_test = test_df[feature_cols].copy() if len(test_df) > 0 else pd.DataFrame()
        y_test = test_df[target_col].values if len(test_df) > 0 else np.array([])
        
        # Impute numeric features
        if len(numeric_cols) > 0:
            imputer = SimpleImputer(strategy=self.config['preprocessing']['impute_strategy'])
            X_train[numeric_cols] = imputer.fit_transform(X_train[numeric_cols])
            
            if len(X_val) > 0:
                X_val[numeric_cols] = imputer.transform(X_val[numeric_cols])
            if len(X_test) > 0:
                X_test[numeric_cols] = imputer.transform(X_test[numeric_cols])
            
            self.preprocessor['imputer'] = imputer
            self.logger.info(f"Imputed {len(numeric_cols)} numeric features")
        
        # Encode categorical features
        if len(categorical_cols) > 0:
            if self.config['preprocessing']['handle_categorical'] == 'onehot':
                encoder = OneHotEncoder(
                    max_categories=self.config['preprocessing']['max_categories'],
                    handle_unknown='ignore',
                    sparse_output=False
                )
                
                encoded_train = encoder.fit_transform(X_train[categorical_cols])
                encoded_cols = encoder.get_feature_names_out(categorical_cols)
                
                # Replace categorical with encoded
                X_train = X_train.drop(columns=categorical_cols)
                X_train[encoded_cols] = encoded_train
                
                if len(X_val) > 0:
                    encoded_val = encoder.transform(X_val[categorical_cols])
                    X_val = X_val.drop(columns=categorical_cols)
                    X_val[encoded_cols] = encoded_val
                
                if len(X_test) > 0:
                    encoded_test = encoder.transform(X_test[categorical_cols])
                    X_test = X_test.drop(columns=categorical_cols)
                    X_test[encoded_cols] = encoded_test
                
                self.preprocessor['encoder'] = encoder
                self.feature_names = list(X_train.columns)
                self.logger.info(f"One-hot encoded {len(categorical_cols)} categorical features")
        
        # Remove low-variance features
        if self.config['preprocessing']['remove_low_variance']:
            selector = VarianceThreshold(
                threshold=self.config['preprocessing']['variance_threshold']
            )
            
            X_train = pd.DataFrame(
                selector.fit_transform(X_train),
                columns=np.array(self.feature_names)[selector.get_support()]
            )
            
            if len(X_val) > 0:
                X_val = pd.DataFrame(
                    selector.transform(X_val),
                    columns=np.array(self.feature_names)[selector.get_support()]
                )
            
            if len(X_test) > 0:
                X_test = pd.DataFrame(
                    selector.transform(X_test),
                    columns=np.array(self.feature_names)[selector.get_support()]
                )
            
            self.preprocessor['variance_selector'] = selector
            self.feature_names = list(X_train.columns)
            self.logger.info(f"Removed low-variance features. Remaining: {len(self.feature_names)}")
        
        self.logger.info(f"Final feature count: {len(self.feature_names)}")
        
        return X_train, y_train, X_val, y_val, X_test, y_test
    
    def handle_class_imbalance(self, X: pd.DataFrame, y: np.ndarray) -> Tuple:
        """
        Handle class imbalance using configured strategy.
        
        Args:
            X: Feature matrix
            y: Target labels
        
        Returns:
            Tuple of (X_resampled, y_resampled)
        """
        # Check imbalance ratio
        unique, counts = np.unique(y, return_counts=True)
        neg_count, pos_count = counts[0], counts[1]
        imbalance_ratio = neg_count / pos_count
        
        self.logger.info(f"Class distribution - Neg: {neg_count}, Pos: {pos_count}, Ratio: {imbalance_ratio:.2f}")
        
        strategy = self.config['imbalance']['strategy']
        threshold = self.config['imbalance']['threshold_ratio']
        
        if imbalance_ratio < threshold:
            self.logger.info(f"Imbalance ratio {imbalance_ratio:.2f} < threshold {threshold}. No resampling.")
            return X, y
        
        if strategy == 'scale_pos_weight':
            # Will be handled in model training
            self.metadata['scale_pos_weight'] = imbalance_ratio
            self.logger.info(f"Using scale_pos_weight: {imbalance_ratio:.2f}")
            return X, y
        
        elif strategy == 'oversample' and HAS_IMBLEARN:
            sampler = SMOTE(
                k_neighbors=self.config['imbalance']['smote']['k_neighbors'],
                sampling_strategy=self.config['imbalance']['smote']['sampling_strategy'],
                random_state=self.seed
            )
            X_res, y_res = sampler.fit_resample(X, y)
            self.logger.info(f"SMOTE oversampling: {len(X)} → {len(X_res)} samples")
            return X_res, y_res
        
        elif strategy == 'undersample' and HAS_IMBLEARN:
            sampler = RandomUnderSampler(
                sampling_strategy=self.config['imbalance']['undersample']['sampling_strategy'],
                random_state=self.seed
            )
            X_res, y_res = sampler.fit_resample(X, y)
            self.logger.info(f"Undersampling: {len(X)} → {len(X_res)} samples")
            return X_res, y_res
        
        else:
            self.logger.warning(f"Strategy '{strategy}' not available. Using original data.")
            return X, y
    
    def train_model(self, X_train, y_train, X_val, y_val, tune: bool = False, 
                   n_trials: int = 50) -> xgb.XGBClassifier:
        """
        Train XGBoost model with optional hyperparameter tuning.
        
        Args:
            X_train, y_train: Training data
            X_val, y_val: Validation data
            tune: Whether to perform hyperparameter tuning
            n_trials: Number of Optuna trials
        
        Returns:
            Trained XGBoost model
        """
        self.logger.info("Training XGBoost model...")
        
        # Get base parameters
        params = self.config['model'].copy()
        params['random_state'] = self.seed
        
        # Handle scale_pos_weight
        if params['scale_pos_weight'] is None and 'scale_pos_weight' in self.metadata:
            params['scale_pos_weight'] = self.metadata['scale_pos_weight']
        
        if tune and HAS_OPTUNA:
            self.logger.info(f"Starting hyperparameter tuning with {n_trials} trials...")
            best_params = self._tune_hyperparameters(X_train, y_train, X_val, y_val, n_trials)
            params.update(best_params)
            self.logger.info(f"Best parameters: {best_params}")
        
        # Train model
        model = xgb.XGBClassifier(**params)
        
        eval_set = [(X_train, y_train)]
        if len(X_val) > 0:
            eval_set.append((X_val, y_val))
        
        self.logger.info("Fitting model with early stopping...")
        model.fit(
            X_train, y_train,
            eval_set=eval_set,
            verbose=False
        )
        
        self.logger.info(f"Training complete. Best iteration: {model.best_iteration}")
        
        return model
    
    def _tune_hyperparameters(self, X_train, y_train, X_val, y_val, n_trials: int) -> Dict:
        """Hyperparameter tuning using Optuna."""
        
        def objective(trial):
            params = {}
            search_space = self.config['tuning']['search_space']
            
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
            
            # Add fixed params
            params['random_state'] = self.seed
            params['tree_method'] = self.config['model']['tree_method']
            params['n_jobs'] = self.config['model']['n_jobs']
            params['verbosity'] = 0
            
            if 'scale_pos_weight' in self.metadata:
                params['scale_pos_weight'] = self.metadata['scale_pos_weight']
            
            # Train model
            model = xgb.XGBClassifier(**params)
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                early_stopping_rounds=self.config['model']['early_stopping_rounds'],
                verbose=False
            )
            
            # Evaluate
            y_pred_proba = model.predict_proba(X_val)[:, 1]
            score = average_precision_score(y_val, y_pred_proba)
            
            return score
        
        study = optuna.create_study(
            direction=self.config['tuning']['direction'],
            sampler=TPESampler(seed=self.seed)
        )
        
        study.optimize(
            objective,
            n_trials=n_trials,
            timeout=self.config['tuning']['timeout'],
            show_progress_bar=True
        )
        
        self.logger.info(f"Best trial: {study.best_trial.number}, Score: {study.best_value:.4f}")
        
        return study.best_params
    
    def calibrate_model(self, model, X_val, y_val):
        """Calibrate model probabilities using isotonic or sigmoid calibration."""
        if not self.config['calibration']['enabled']:
            return model
        
        self.logger.info("Calibrating model...")
        
        calibrated = CalibratedClassifierCV(
            model,
            method=self.config['calibration']['method'],
            cv='prefit'
        )
        
        calibrated.fit(X_val, y_val)
        
        self.logger.info(f"Calibration complete using {self.config['calibration']['method']} method")
        
        return calibrated
    
    def evaluate_model(self, model, X, y, split_name: str) -> Dict:
        """
        Evaluate model and compute comprehensive metrics.
        
        Args:
            model: Trained model
            X: Features
            y: True labels
            split_name: Name of split (train/val/test)
        
        Returns:
            Dictionary of metrics
        """
        self.logger.info(f"Evaluating model on {split_name} set...")
        
        y_pred = model.predict(X)
        y_pred_proba = model.predict_proba(X)[:, 1]
        
        metrics = {
            'split': split_name,
            'n_samples': len(y),
            'roc_auc': roc_auc_score(y, y_pred_proba),
            'pr_auc': average_precision_score(y, y_pred_proba),
            'f1': f1_score(y, y_pred),
            'precision': precision_score(y, y_pred),
            'recall': recall_score(y, y_pred),
            'accuracy': accuracy_score(y, y_pred),
            'brier_score': brier_score_loss(y, y_pred_proba)
        }
        
        # Confusion matrix
        cm = confusion_matrix(y, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        metrics['tn'], metrics['fp'], metrics['fn'], metrics['tp'] = cm.ravel()
        
        # Classification report
        report = classification_report(y, y_pred, output_dict=True)
        metrics['classification_report'] = report
        
        self.logger.info(f"{split_name} Metrics:")
        self.logger.info(f"  ROC-AUC: {metrics['roc_auc']:.4f}")
        self.logger.info(f"  PR-AUC: {metrics['pr_auc']:.4f}")
        self.logger.info(f"  F1: {metrics['f1']:.4f}")
        self.logger.info(f"  Precision: {metrics['precision']:.4f}")
        self.logger.info(f"  Recall: {metrics['recall']:.4f}")
        
        return metrics
    
    def generate_shap_explanations(self, model, X, split_name: str):
        """Generate SHAP explanations and save visualizations."""
        if not self.config['explainability']['enabled'] or not HAS_SHAP:
            return
        
        self.logger.info("Generating SHAP explanations...")
        
        # Create explainer
        explainer = shap.TreeExplainer(
            model,
            check_additivity=self.config['explainability']['shap']['check_additivity']
        )
        
        # Sample data if too large
        n_samples = min(len(X), self.config['explainability']['n_samples'])
        X_sample = X.sample(n=n_samples, random_state=self.seed)
        
        # Calculate SHAP values
        shap_values = explainer.shap_values(X_sample)
        
        # Save plots
        if self.config['explainability']['save_plots'] and HAS_PLOTTING:
            shap_dir = Path(self.config['output']['shap_dir'])
            
            # Summary plot
            plt.figure(figsize=(12, 8))
            shap.summary_plot(shap_values, X_sample, show=False)
            plt.tight_layout()
            plt.savefig(shap_dir / f"static_shap_summary_{split_name}.png", dpi=300)
            plt.close()
            
            # Feature importance
            plt.figure(figsize=(10, 8))
            shap.summary_plot(shap_values, X_sample, plot_type="bar", show=False)
            plt.tight_layout()
            plt.savefig(shap_dir / f"static_shap_importance_{split_name}.png", dpi=300)
            plt.close()
            
            self.logger.info(f"SHAP plots saved to {shap_dir}")
        
        # Save per-sample SHAP values
        if self.config['explainability']['save_samples']:
            shap_samples = []
            for i in range(len(X_sample)):
                shap_samples.append({
                    'id': X_sample.index[i],
                    'shap_values': shap_values[i].tolist(),
                    'features': X_sample.iloc[i].to_dict()
                })
            
            shap_file = Path(self.config['output']['shap_dir']) / f"static_shap_samples_{split_name}.json"
            with open(shap_file, 'w') as f:
                json.dump(shap_samples, f, indent=2)
            
            self.logger.info(f"SHAP samples saved to {shap_file}")
    
    def save_model(self, model, calibrated_model=None):
        """Save model, metadata, and training artifacts."""
        models_dir = Path(self.config['output']['models_dir'])
        
        # Model filename
        model_filename = self.config['output']['model_filename'].format(
            timestamp=self.timestamp
        )
        model_path = models_dir / model_filename
        
        # Save model
        joblib.dump(model, model_path)
        self.logger.info(f"Model saved to {model_path}")
        
        # Save calibrated model
        if calibrated_model is not None:
            calib_path = models_dir / f"calibrated_{model_filename}"
            joblib.dump(calibrated_model, calib_path)
            self.logger.info(f"Calibrated model saved to {calib_path}")
        
        # Save metadata
        metadata_filename = self.config['output']['metadata_filename'].format(
            timestamp=self.timestamp
        )
        metadata_path = models_dir / metadata_filename
        
        metadata = {
            'timestamp': self.timestamp,
            'model_type': 'xgboost',
            'version': self.config['version'],
            'seed': self.seed,
            'feature_names': self.feature_names,
            'n_features': len(self.feature_names),
            'model_params': model.get_params(),
            'best_iteration': model.best_iteration if hasattr(model, 'best_iteration') else None,
            'preprocessor_steps': list(self.preprocessor.keys()),
            'imbalance_strategy': self.config['imbalance']['strategy'],
            'calibrated': calibrated_model is not None
        }
        
        # Add git commit if available
        if self.config['reproducibility']['save_git_commit']:
            try:
                commit = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('ascii').strip()
                metadata['git_commit'] = commit
            except:
                metadata['git_commit'] = None
        
        with open(metadata_path, 'w') as f:
            yaml.dump(metadata, f, default_flow_style=False)
        
        self.logger.info(f"Metadata saved to {metadata_path}")
        
        return model_path, metadata_path


def main():
    parser = argparse.ArgumentParser(
        description='Train XGBoost Static Model (Phase 3.2)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--features-csv',
        type=str,
        default='datasets/features/features_all.csv',
        help='Path to features CSV file'
    )
    
    parser.add_argument(
        '--split',
        type=str,
        default='train',
        choices=['train', 'val', 'test', 'all'],
        help='Dataset split to use'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='src/static/models/model_config.yml',
        help='Path to model configuration YAML'
    )
    
    parser.add_argument(
        '--tune',
        action='store_true',
        help='Enable hyperparameter tuning'
    )
    
    parser.add_argument(
        '--n-trials',
        type=int,
        default=50,
        help='Number of Optuna trials for tuning'
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
    
    # Load configuration
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
    
    # Override config with CLI args
    if args.tune:
        config['tuning']['enabled'] = True
        config['tuning']['n_trials'] = args.n_trials
    
    # Initialize trainer
    trainer = XGBoostStaticTrainer(config, seed=args.seed)
    
    try:
        # Load data
        train_df, val_df, test_df = trainer.load_data(args.features_csv, args.split)
        
        # Preprocess
        X_train, y_train, X_val, y_val, X_test, y_test = trainer.preprocess_data(
            train_df, val_df, test_df
        )
        
        # Handle class imbalance
        X_train, y_train = trainer.handle_class_imbalance(X_train, y_train)
        
        # Train model
        model = trainer.train_model(X_train, y_train, X_val, y_val, 
                                   tune=args.tune, n_trials=args.n_trials)
        
        # Calibrate
        calibrated_model = None
        if len(X_val) > 0:
            calibrated_model = trainer.calibrate_model(model, X_val, y_val)
        
        # Evaluate
        train_metrics = trainer.evaluate_model(model, X_train, y_train, 'train')
        
        if len(X_val) > 0:
            val_metrics = trainer.evaluate_model(model, X_val, y_val, 'val')
        
        if len(X_test) > 0:
            test_metrics = trainer.evaluate_model(model, X_test, y_test, 'test')
        
        # Generate SHAP explanations
        if len(X_val) > 0:
            trainer.generate_shap_explanations(model, X_val, 'val')
        
        # Save model
        if args.save_model:
            model_path, metadata_path = trainer.save_model(model, calibrated_model)
            print(f"\n✓ Model saved to: {model_path}")
            print(f"✓ Metadata saved to: {metadata_path}")
        
        print("\n" + "="*70)
        print("TRAINING COMPLETE")
        print("="*70)
        print(f"Train ROC-AUC: {train_metrics['roc_auc']:.4f}")
        if len(X_val) > 0:
            print(f"Val ROC-AUC: {val_metrics['roc_auc']:.4f}")
            print(f"Val PR-AUC: {val_metrics['pr_auc']:.4f}")
        print("="*70)
        
    except Exception as e:
        trainer.logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
