#!/usr/bin/env python3
"""
Static XGBoost Model Inference Script
Phase 3.2 - Production-Grade ML Pipeline

This script performs inference using trained XGBoost static model.

Features:
- Load trained model + metadata + preprocessor
- Batch inference with chunk processing
- SHAP explainability for predictions
- CWE mapping support
- Consistent JSONL output format
- Integration with main pipeline
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import shap
import yaml
from xgboost import XGBClassifier

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class StaticModelInference:
    """Inference engine for static XGBoost model."""
    
    def __init__(
        self,
        model_path: str,
        metadata_path: Optional[str] = None,
        imputer_path: Optional[str] = None,
        config_path: Optional[str] = None
    ):
        """Initialize inference engine.
        
        Args:
            model_path: Path to trained model (.joblib or .pkl)
            metadata_path: Path to metadata YAML (optional, auto-detected)
            imputer_path: Path to fitted imputer (optional, auto-detected)
            config_path: Path to model_config.yml (optional)
        """
        self.model_path = Path(model_path)
        
        # Auto-detect metadata and imputer paths
        if metadata_path is None:
            metadata_path = self._find_companion_file(self.model_path, 'metadata_')
        if imputer_path is None:
            imputer_path = self._find_companion_file(self.model_path, 'imputer_')
        
        self.metadata_path = Path(metadata_path) if metadata_path else None
        self.imputer_path = Path(imputer_path) if imputer_path else None
        self.config_path = Path(config_path) if config_path else None
        
        # Load components
        self.model = self._load_model()
        self.metadata = self._load_metadata()
        self.imputer = self._load_imputer()
        self.config = self._load_config()
        
        # Initialize SHAP explainer
        self.explainer = None
        
        logger.info(f"Initialized inference engine with model: {model_path}")
    
    def _find_companion_file(self, model_path: Path, prefix: str) -> Optional[str]:
        """Find companion file (metadata/imputer) based on model filename.
        
        Args:
            model_path: Path to model file
            prefix: Prefix to search for ('metadata_' or 'imputer_')
        
        Returns:
            Path to companion file or None
        """
        # Extract version from model filename
        # e.g., xgb_static_v20231008_143022.joblib -> 20231008_143022
        model_name = model_path.stem
        if '_v' in model_name:
            version = model_name.split('_v')[-1]
            companion_name = f"{prefix}xgb_static_v{version}.{'yaml' if prefix == 'metadata_' else 'joblib'}"
            companion_path = model_path.parent / companion_name
            
            if companion_path.exists():
                return str(companion_path)
        
        return None
    
    def _load_model(self) -> XGBClassifier:
        """Load trained XGBoost model."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        
        logger.info(f"Loading model from {self.model_path}")
        model = joblib.load(self.model_path)
        
        return model
    
    def _load_metadata(self) -> Dict:
        """Load model metadata."""
        if self.metadata_path is None or not self.metadata_path.exists():
            logger.warning("Metadata file not found. Using defaults.")
            return {}
        
        logger.info(f"Loading metadata from {self.metadata_path}")
        with open(self.metadata_path, 'r') as f:
            metadata = yaml.safe_load(f)
        
        return metadata
    
    def _load_imputer(self):
        """Load fitted imputer."""
        if self.imputer_path is None or not self.imputer_path.exists():
            logger.warning("Imputer file not found. Skipping imputation.")
            return None
        
        logger.info(f"Loading imputer from {self.imputer_path}")
        imputer = joblib.load(self.imputer_path)
        
        return imputer
    
    def _load_config(self) -> Dict:
        """Load model configuration."""
        if self.config_path is None or not self.config_path.exists():
            logger.warning("Config file not found. Using defaults.")
            return {}
        
        logger.info(f"Loading config from {self.config_path}")
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        return config
    
    def load_input_data(
        self,
        input_path: str,
        format: str = 'auto'
    ) -> pd.DataFrame:
        """Load input data from CSV or JSONL.
        
        Args:
            input_path: Path to input file
            format: Input format ('csv', 'jsonl', or 'auto')
        
        Returns:
            DataFrame with input data
        """
        input_path = Path(input_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Auto-detect format
        if format == 'auto':
            if input_path.suffix == '.csv':
                format = 'csv'
            elif input_path.suffix in ['.jsonl', '.json']:
                format = 'jsonl'
            else:
                raise ValueError(f"Cannot auto-detect format for: {input_path}")
        
        logger.info(f"Loading input data from {input_path} (format: {format})")
        
        if format == 'csv':
            df = pd.read_csv(input_path)
        elif format == 'jsonl':
            records = []
            with open(input_path, 'r') as f:
                for line in f:
                    records.append(json.loads(line))
            df = pd.DataFrame(records)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Loaded {len(df)} samples")
        
        return df
    
    def preprocess_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Preprocess features for inference.
        
        Args:
            df: Input DataFrame
        
        Returns:
            Tuple of (features_df, metadata_df)
        """
        logger.info("Preprocessing features...")
        
        # Store metadata columns
        metadata_cols = ['id', 'file', 'function', 'label', 'cwe', 'severity']
        metadata_df = df[[c for c in metadata_cols if c in df.columns]].copy()
        
        # Get expected feature names from metadata
        expected_features = self.metadata.get('feature_names', [])
        
        if expected_features:
            # Select and reorder features
            missing_features = set(expected_features) - set(df.columns)
            if missing_features:
                logger.warning(f"Missing features: {missing_features}. Filling with zeros.")
                for feat in missing_features:
                    df[feat] = 0.0
            
            X = df[expected_features].copy()
        else:
            # Drop metadata columns
            X = df.drop(columns=[c for c in metadata_cols if c in df.columns], errors='ignore')
        
        # Apply imputation
        if self.imputer is not None:
            logger.info("Applying imputation...")
            X = pd.DataFrame(
                self.imputer.transform(X),
                columns=X.columns,
                index=X.index
            )
        
        logger.info(f"Preprocessed features: {X.shape}")
        
        return X, metadata_df
    
    def predict(
        self,
        X: pd.DataFrame,
        use_calibrated: bool = True
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Run inference on features.
        
        Args:
            X: Feature DataFrame
            use_calibrated: Whether to use calibrated model (if available)
        
        Returns:
            Tuple of (predictions, probabilities)
        """
        logger.info(f"Running inference on {len(X)} samples...")
        
        # Check if calibrated model exists
        model = self.model
        if use_calibrated:
            calibrated_path = self._find_companion_file(self.model_path, 'calibrated_')
            if calibrated_path and Path(calibrated_path).exists():
                logger.info("Using calibrated model")
                model = joblib.load(calibrated_path)
        
        # Predict
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)[:, 1]
        
        logger.info(f"Predictions complete. Positive rate: {predictions.mean():.2%}")
        
        return predictions, probabilities
    
    def map_cwe(
        self,
        predictions: np.ndarray,
        probabilities: np.ndarray,
        metadata_df: pd.DataFrame
    ) -> List[str]:
        """Map predictions to CWE IDs.
        
        Args:
            predictions: Binary predictions
            probabilities: Prediction probabilities
            metadata_df: Metadata DataFrame
        
        Returns:
            List of CWE IDs
        """
        logger.info("Mapping CWE IDs...")
        
        cwe_list = []
        
        # If CWE column exists in input, use it
        if 'cwe' in metadata_df.columns:
            cwe_list = metadata_df['cwe'].fillna('Unknown').tolist()
        else:
            # Use rule-based mapping from config
            cwe_mapping = self.config.get('cwe_mapping', {})
            
            for pred, prob in zip(predictions, probabilities):
                if pred == 1:
                    # Map based on probability threshold
                    if prob >= 0.9:
                        cwe_list.append(cwe_mapping.get('high_confidence', 'CWE-79'))
                    elif prob >= 0.7:
                        cwe_list.append(cwe_mapping.get('medium_confidence', 'CWE-89'))
                    else:
                        cwe_list.append(cwe_mapping.get('low_confidence', 'CWE-20'))
                else:
                    cwe_list.append('N/A')
        
        return cwe_list
    
    def compute_explainability(
        self,
        X: pd.DataFrame,
        output_dir: Path,
        n_samples: int = 500
    ):
        """Compute and save feature importance and SHAP values.
        
        Args:
            X: Feature DataFrame
            output_dir: Directory to save explainability outputs
            n_samples: Number of samples for SHAP computation
        """
        logger.info("Computing explainability...")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Feature Importance (from model)
        try:
            feature_importance = pd.DataFrame({
                'feature': X.columns,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            importance_file = output_dir / 'feature_importance.csv'
            feature_importance.to_csv(importance_file, index=False)
            logger.info(f"Saved feature importance to {importance_file}")
        except Exception as e:
            logger.warning(f"Could not compute feature importance: {e}")
        
        # 2. SHAP Values
        try:
            if self.explainer is None:
                logger.info("Initializing SHAP explainer...")
                self.explainer = shap.TreeExplainer(self.model)
            
            # Sample data for SHAP
            n_samples = min(n_samples, len(X))
            X_sample = X.sample(n=n_samples, random_state=42)
            
            logger.info(f"Computing SHAP values for {n_samples} samples...")
            shap_values = self.explainer.shap_values(X_sample)
            
            # Save SHAP values
            shap_df = pd.DataFrame(
                shap_values,
                columns=X.columns,
                index=X_sample.index
            )
            shap_file = output_dir / 'shap_values.csv'
            shap_df.to_csv(shap_file)
            logger.info(f"Saved SHAP values to {shap_file}")
            
            # Compute mean absolute SHAP
            mean_shap = pd.DataFrame({
                'feature': X.columns,
                'mean_abs_shap': np.abs(shap_values).mean(axis=0)
            }).sort_values('mean_abs_shap', ascending=False)
            
            mean_shap_file = output_dir / 'mean_shap_importance.csv'
            mean_shap.to_csv(mean_shap_file, index=False)
            logger.info(f"Saved mean SHAP importance to {mean_shap_file}")
            
        except Exception as e:
            logger.warning(f"Could not compute SHAP values: {e}")
    
    def save_results(
        self,
        predictions: np.ndarray,
        probabilities: np.ndarray,
        metadata_df: pd.DataFrame,
        cwe_list: List[str],
        output_path: str
    ):
        """Save inference results to JSONL.
        
        Args:
            predictions: Binary predictions
            probabilities: Prediction probabilities
            metadata_df: Metadata DataFrame
            cwe_list: List of CWE IDs
            output_path: Path to output JSONL file
        """
        logger.info(f"Saving results to {output_path}")
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare results
        results = []
        for idx, (pred, prob, cwe) in enumerate(zip(predictions, probabilities, cwe_list)):
            result = {
                'id': metadata_df.iloc[idx].get('id', idx) if not metadata_df.empty else idx,
                'file': metadata_df.iloc[idx].get('file', 'unknown') if not metadata_df.empty else 'unknown',
                'function': metadata_df.iloc[idx].get('function', 'unknown') if not metadata_df.empty else 'unknown',
                'vulnerability_label': int(pred),
                'vulnerability_probability': float(prob),
                'cwe_hint': cwe,
                'source': 'static_analyzer',
                'timestamp': datetime.now().isoformat()
            }
            
            # Add true label if available
            if not metadata_df.empty and 'label' in metadata_df.columns:
                result['true_label'] = int(metadata_df.iloc[idx]['label'])
            
            results.append(result)
        
        # Save as JSONL
        with open(output_path, 'w') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        
        logger.info(f"Saved {len(results)} predictions to {output_path}")
        
        # Save summary statistics
        summary = {
            'total_samples': len(predictions),
            'positive_predictions': int(predictions.sum()),
            'negative_predictions': int((1 - predictions).sum()),
            'mean_probability': float(probabilities.mean()),
            'positive_rate': float(predictions.mean()),
            'timestamp': datetime.now().isoformat()
        }
        
        summary_path = output_path.parent / f"{output_path.stem}_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Saved summary to {summary_path}")
    
    def run_inference(
        self,
        input_path: str,
        output_path: str,
        explain: bool = True,
        chunk_size: Optional[int] = None
    ):
        """Run full inference pipeline.
        
        Args:
            input_path: Path to input data
            output_path: Path to output JSONL
            explain: Whether to compute explainability
            chunk_size: Process data in chunks (for large datasets)
        """
        logger.info("=" * 80)
        logger.info("Starting Static Model Inference")
        logger.info("=" * 80)
        
        # Load data
        df = self.load_input_data(input_path)
        
        # Process in chunks if specified
        if chunk_size and len(df) > chunk_size:
            logger.info(f"Processing {len(df)} samples in chunks of {chunk_size}")
            
            all_predictions = []
            all_probabilities = []
            all_metadata = []
            
            for i in range(0, len(df), chunk_size):
                chunk_df = df.iloc[i:i+chunk_size]
                logger.info(f"Processing chunk {i//chunk_size + 1}/{(len(df)-1)//chunk_size + 1}")
                
                X, metadata_df = self.preprocess_features(chunk_df)
                predictions, probabilities = self.predict(X)
                
                all_predictions.append(predictions)
                all_probabilities.append(probabilities)
                all_metadata.append(metadata_df)
            
            # Concatenate results
            predictions = np.concatenate(all_predictions)
            probabilities = np.concatenate(all_probabilities)
            metadata_df = pd.concat(all_metadata, ignore_index=True)
            X = None  # Don't use for explainability in chunked mode
        else:
            # Process all at once
            X, metadata_df = self.preprocess_features(df)
            predictions, probabilities = self.predict(X)
        
        # Map CWE
        cwe_list = self.map_cwe(predictions, probabilities, metadata_df)
        
        # Save results
        self.save_results(predictions, probabilities, metadata_df, cwe_list, output_path)
        
        # Compute explainability
        if explain and X is not None:
            output_dir = Path(output_path).parent / 'explainability'
            self.compute_explainability(X, output_dir)
        
        logger.info("=" * 80)
        logger.info("Inference Complete!")
        logger.info("=" * 80)


def main():
    """Main inference CLI."""
    parser = argparse.ArgumentParser(
        description="Static XGBoost Model Inference",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '--model-path',
        type=str,
        required=True,
        help='Path to trained XGBoost model (.joblib or .pkl)'
    )
    parser.add_argument(
        '--input-path',
        type=str,
        required=True,
        help='Path to input data (CSV or JSONL)'
    )
    parser.add_argument(
        '--output-path',
        type=str,
        default='outputs/inference/static_results.jsonl',
        help='Path to output JSONL file'
    )
    parser.add_argument(
        '--metadata-path',
        type=str,
        default=None,
        help='Path to model metadata YAML (auto-detected if not provided)'
    )
    parser.add_argument(
        '--imputer-path',
        type=str,
        default=None,
        help='Path to fitted imputer (auto-detected if not provided)'
    )
    parser.add_argument(
        '--config',
        type=str,
        default=None,
        help='Path to model_config.yml'
    )
    parser.add_argument(
        '--format',
        type=str,
        default='auto',
        choices=['auto', 'csv', 'jsonl'],
        help='Input data format'
    )
    parser.add_argument(
        '--explain',
        action='store_true',
        help='Compute explainability (SHAP and feature importance)'
    )
    parser.add_argument(
        '--chunk-size',
        type=int,
        default=None,
        help='Process data in chunks (for large datasets)'
    )
    parser.add_argument(
        '--use-calibrated',
        action='store_true',
        default=True,
        help='Use calibrated model if available'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize inference engine
        inference = StaticModelInference(
            model_path=args.model_path,
            metadata_path=args.metadata_path,
            imputer_path=args.imputer_path,
            config_path=args.config
        )
        
        # Run inference
        inference.run_inference(
            input_path=args.input_path,
            output_path=args.output_path,
            explain=args.explain,
            chunk_size=args.chunk_size
        )
        
        logger.info("✅ Inference completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Inference failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
