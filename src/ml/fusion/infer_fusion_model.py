#!/usr/bin/env python3
"""
Fusion XGBoost Model Inference Script
Phase 3.2 - Production-Grade ML Pipeline

This script performs meta-inference by combining outputs from:
- Static analyzer (XGBoost on M1-M15 features)
- CodeBERT classifier
- GraphCodeBERT classifier

Features:
- Load and merge multiple model outputs
- Feature engineering (interactions, ratios, ensembles)
- Batch inference with fusion model
- SHAP explainability with subsystem contribution
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


class FusionModelInference:
    """Inference engine for fusion XGBoost meta-model."""
    
    def __init__(
        self,
        model_path: str,
        metadata_path: Optional[str] = None,
        imputer_path: Optional[str] = None,
        config_path: Optional[str] = None
    ):
        """Initialize fusion inference engine.
        
        Args:
            model_path: Path to trained fusion model (.joblib or .pkl)
            metadata_path: Path to metadata YAML (optional, auto-detected)
            imputer_path: Path to fitted imputer (optional, auto-detected)
            config_path: Path to fusion_config.yml (optional)
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
        
        logger.info(f"Initialized fusion inference engine with model: {model_path}")
    
    def _find_companion_file(self, model_path: Path, prefix: str) -> Optional[str]:
        """Find companion file based on model filename."""
        model_name = model_path.stem
        if '_v' in model_name:
            version = model_name.split('_v')[-1]
            companion_name = f"{prefix}xgb_fusion_v{version}.{'yaml' if prefix == 'metadata_' else 'joblib'}"
            companion_path = model_path.parent / companion_name
            
            if companion_path.exists():
                return str(companion_path)
        
        return None
    
    def _load_model(self) -> XGBClassifier:
        """Load trained fusion model."""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        
        logger.info(f"Loading fusion model from {self.model_path}")
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
        """Load fusion configuration."""
        if self.config_path is None or not self.config_path.exists():
            logger.warning("Config file not found. Using defaults.")
            return {}
        
        logger.info(f"Loading config from {self.config_path}")
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        return config
    
    def load_predictions(
        self,
        static_path: Optional[str] = None,
        codebert_path: Optional[str] = None,
        graphcodebert_path: Optional[str] = None,
        llm_path: Optional[str] = None
    ) -> pd.DataFrame:
        """Load and merge predictions from multiple models.
        
        Args:
            static_path: Path to static model predictions (JSONL)
            codebert_path: Path to CodeBERT predictions (JSONL)
            graphcodebert_path: Path to GraphCodeBERT predictions (JSONL)
            llm_path: Path to LLM predictions (JSONL) - alternative to codebert/graph
        
        Returns:
            Merged DataFrame with all predictions
        """
        logger.info("Loading predictions from subsystems...")
        
        dfs = []
        
        # Load static predictions
        if static_path:
            static_path = Path(static_path)
            if static_path.exists():
                logger.info(f"Loading static predictions from {static_path}")
                static_df = self._load_jsonl(static_path)
                static_df = static_df.rename(columns={
                    'vulnerability_probability': 'static_prob',
                    'vulnerability_label': 'static_label'
                })
                dfs.append(('static', static_df))
            else:
                logger.warning(f"Static predictions not found: {static_path}")
        
        # Load CodeBERT predictions
        if codebert_path:
            codebert_path = Path(codebert_path)
            if codebert_path.exists():
                logger.info(f"Loading CodeBERT predictions from {codebert_path}")
                codebert_df = self._load_jsonl(codebert_path)
                codebert_df = codebert_df.rename(columns={
                    'vulnerability_probability': 'codebert_prob',
                    'vulnerability_label': 'codebert_label'
                })
                dfs.append(('codebert', codebert_df))
            else:
                logger.warning(f"CodeBERT predictions not found: {codebert_path}")
        
        # Load GraphCodeBERT predictions
        if graphcodebert_path:
            graphcodebert_path = Path(graphcodebert_path)
            if graphcodebert_path.exists():
                logger.info(f"Loading GraphCodeBERT predictions from {graphcodebert_path}")
                graph_df = self._load_jsonl(graphcodebert_path)
                graph_df = graph_df.rename(columns={
                    'vulnerability_probability': 'graphcodebert_prob',
                    'vulnerability_label': 'graphcodebert_label'
                })
                dfs.append(('graph', graph_df))
            else:
                logger.warning(f"GraphCodeBERT predictions not found: {graphcodebert_path}")
        
        # Load LLM predictions (alternative)
        if llm_path:
            llm_path = Path(llm_path)
            if llm_path.exists():
                logger.info(f"Loading LLM predictions from {llm_path}")
                llm_df = self._load_jsonl(llm_path)
                llm_df = llm_df.rename(columns={
                    'vulnerability_probability': 'llm_prob',
                    'vulnerability_label': 'llm_label'
                })
                dfs.append(('llm', llm_df))
            else:
                logger.warning(f"LLM predictions not found: {llm_path}")
        
        if not dfs:
            raise ValueError("No prediction files found. Need at least one input.")
        
        # Merge all predictions
        logger.info(f"Merging {len(dfs)} prediction sources...")
        
        # Start with first df
        name, merged_df = dfs[0]
        key_cols = ['id', 'file', 'function']
        
        # Merge remaining dfs
        for name, df in dfs[1:]:
            # Find common key columns
            common_keys = [k for k in key_cols if k in merged_df.columns and k in df.columns]
            
            if common_keys:
                merged_df = merged_df.merge(
                    df,
                    on=common_keys,
                    how='outer',
                    suffixes=('', f'_{name}')
                )
            else:
                # Merge by index if no common keys
                logger.warning(f"No common keys found. Merging {name} by index.")
                merged_df = pd.concat([merged_df, df], axis=1)
        
        logger.info(f"Merged predictions: {merged_df.shape}")
        
        return merged_df
    
    def _load_jsonl(self, path: Path) -> pd.DataFrame:
        """Load JSONL file into DataFrame."""
        records = []
        with open(path, 'r') as f:
            for line in f:
                records.append(json.loads(line))
        return pd.DataFrame(records)
    
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create interaction, ratio, and ensemble features.
        
        Args:
            df: Input DataFrame with model predictions
        
        Returns:
            DataFrame with engineered features
        """
        logger.info("Engineering fusion features...")
        
        fe_config = self.config.get('feature_engineering', {})
        
        # Ensure probability columns exist
        prob_cols = [c for c in df.columns if 'prob' in c.lower()]
        logger.info(f"Found probability columns: {prob_cols}")
        
        # Create confidence scores
        for col in prob_cols:
            if col in df.columns:
                conf_col = col.replace('_prob', '_confidence')
                df[conf_col] = np.abs(df[col] - 0.5) * 2  # Distance from 0.5, scaled to [0, 1]
        
        # Create interactions
        if fe_config.get('create_interactions', True):
            interactions = fe_config.get('interactions', [])
            for feat1, feat2 in interactions:
                if feat1 in df.columns and feat2 in df.columns:
                    df[f"{feat1}_x_{feat2}"] = df[feat1] * df[feat2]
        
        # Create ratios (with safe division)
        if fe_config.get('create_ratios', True):
            ratios = fe_config.get('ratios', [])
            for num_feat, denom_feat, name in ratios:
                if num_feat in df.columns and denom_feat in df.columns:
                    df[name] = df[num_feat] / (df[denom_feat] + 1e-10)
        
        # Create ensemble features
        if fe_config.get('create_ensemble_features', True):
            ensemble_config = fe_config.get('ensemble', {})
            for agg_name, feature_list in ensemble_config.items():
                available = [f for f in feature_list if f in df.columns]
                if available:
                    if 'mean' in agg_name:
                        df[agg_name] = df[available].mean(axis=1)
                    elif 'max' in agg_name:
                        df[agg_name] = df[available].max(axis=1)
                    elif 'min' in agg_name:
                        df[agg_name] = df[available].min(axis=1)
                    elif 'std' in agg_name:
                        df[agg_name] = df[available].std(axis=1)
        
        logger.info(f"Engineered features. New shape: {df.shape}")
        
        return df
    
    def preprocess_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Preprocess features for fusion inference.
        
        Args:
            df: Input DataFrame
        
        Returns:
            Tuple of (features_df, metadata_df)
        """
        logger.info("Preprocessing fusion features...")
        
        # Store metadata columns
        metadata_cols = ['id', 'file', 'function', 'true_label', 'label', 'cwe', 'severity']
        metadata_df = df[[c for c in metadata_cols if c in df.columns]].copy()
        
        # Get expected feature names from metadata
        expected_features = self.metadata.get('feature_names', [])
        
        if expected_features:
            # Select and reorder features
            missing_features = set(expected_features) - set(df.columns)
            if missing_features:
                logger.warning(f"Missing features: {missing_features}. Filling with defaults.")
                for feat in missing_features:
                    # Fill with mean of probability features or 0.5
                    if 'prob' in feat:
                        df[feat] = 0.5
                    else:
                        df[feat] = 0.0
            
            X = df[expected_features].copy()
        else:
            # Drop metadata columns
            X = df.drop(columns=[c for c in metadata_cols if c in df.columns], errors='ignore')
        
        # Clip probabilities
        prob_cols = [c for c in X.columns if 'prob' in c.lower()]
        for col in prob_cols:
            X[col] = X[col].clip(0, 1)
        
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
        """Run fusion inference.
        
        Args:
            X: Feature DataFrame
            use_calibrated: Whether to use calibrated model (if available)
        
        Returns:
            Tuple of (predictions, probabilities)
        """
        logger.info(f"Running fusion inference on {len(X)} samples...")
        
        # Check if calibrated model exists
        model = self.model
        if use_calibrated:
            calibrated_path = self._find_companion_file(self.model_path, 'calibrated_')
            if calibrated_path and Path(calibrated_path).exists():
                logger.info("Using calibrated fusion model")
                model = joblib.load(calibrated_path)
        
        # Predict
        predictions = model.predict(X)
        probabilities = model.predict_proba(X)[:, 1]
        
        logger.info(f"Fusion predictions complete. Positive rate: {predictions.mean():.2%}")
        
        return predictions, probabilities
    
    def map_cwe(
        self,
        predictions: np.ndarray,
        probabilities: np.ndarray,
        metadata_df: pd.DataFrame
    ) -> List[str]:
        """Map fusion predictions to CWE IDs.
        
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
            cwe_mapping = self.config.get('cwe_mapping', {
                'high_confidence': 'CWE-79',  # XSS
                'medium_confidence': 'CWE-89',  # SQL Injection
                'low_confidence': 'CWE-20'  # Input Validation
            })
            
            for pred, prob in zip(predictions, probabilities):
                if pred == 1:
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
        logger.info("Computing fusion explainability...")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Feature Importance
        try:
            feature_importance = pd.DataFrame({
                'feature': X.columns,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            importance_file = output_dir / 'fusion_feature_importance.csv'
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
            shap_file = output_dir / 'fusion_shap_values.csv'
            shap_df.to_csv(shap_file)
            logger.info(f"Saved SHAP values to {shap_file}")
            
            # Compute mean absolute SHAP
            mean_shap = pd.DataFrame({
                'feature': X.columns,
                'mean_abs_shap': np.abs(shap_values).mean(axis=0)
            }).sort_values('mean_abs_shap', ascending=False)
            
            mean_shap_file = output_dir / 'fusion_mean_shap_importance.csv'
            mean_shap.to_csv(mean_shap_file, index=False)
            logger.info(f"Saved mean SHAP importance to {mean_shap_file}")
            
            # Subsystem contribution analysis
            self._analyze_subsystem_contribution(shap_values, X_sample, output_dir)
            
        except Exception as e:
            logger.warning(f"Could not compute SHAP values: {e}")
    
    def _analyze_subsystem_contribution(
        self,
        shap_values: np.ndarray,
        X: pd.DataFrame,
        output_dir: Path
    ):
        """Analyze contribution of each subsystem.
        
        Args:
            shap_values: SHAP values array
            X: Features DataFrame
            output_dir: Output directory
        """
        logger.info("Analyzing subsystem contributions...")
        
        # Group features by subsystem
        static_features = [f for f in X.columns if 'static' in f.lower()]
        codebert_features = [f for f in X.columns if 'codebert' in f.lower()]
        graph_features = [f for f in X.columns if 'graph' in f.lower()]
        llm_features = [f for f in X.columns if 'llm' in f.lower()]
        
        # Compute mean absolute SHAP for each subsystem
        contributions = {}
        
        if static_features:
            static_idx = [X.columns.get_loc(f) for f in static_features]
            contributions['static'] = float(np.abs(shap_values[:, static_idx]).mean())
        
        if codebert_features:
            codebert_idx = [X.columns.get_loc(f) for f in codebert_features]
            contributions['codebert'] = float(np.abs(shap_values[:, codebert_idx]).mean())
        
        if graph_features:
            graph_idx = [X.columns.get_loc(f) for f in graph_features]
            contributions['graphcodebert'] = float(np.abs(shap_values[:, graph_idx]).mean())
        
        if llm_features:
            llm_idx = [X.columns.get_loc(f) for f in llm_features]
            contributions['llm'] = float(np.abs(shap_values[:, llm_idx]).mean())
        
        logger.info(f"Subsystem contributions: {contributions}")
        
        # Save to JSON
        contrib_file = output_dir / 'subsystem_contributions.json'
        with open(contrib_file, 'w') as f:
            json.dump(contributions, f, indent=2)
        
        logger.info(f"Saved subsystem contributions to {contrib_file}")
    
    def save_results(
        self,
        predictions: np.ndarray,
        probabilities: np.ndarray,
        metadata_df: pd.DataFrame,
        cwe_list: List[str],
        output_path: str
    ):
        """Save fusion inference results to JSONL.
        
        Args:
            predictions: Binary predictions
            probabilities: Prediction probabilities
            metadata_df: Metadata DataFrame
            cwe_list: List of CWE IDs
            output_path: Path to output JSONL file
        """
        logger.info(f"Saving fusion results to {output_path}")
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare results
        results = []
        for idx, (pred, prob, cwe) in enumerate(zip(predictions, probabilities, cwe_list)):
            result = {
                'id': metadata_df.iloc[idx].get('id', idx) if not metadata_df.empty else idx,
                'file': metadata_df.iloc[idx].get('file', 'unknown') if not metadata_df.empty else 'unknown',
                'function': metadata_df.iloc[idx].get('function', 'unknown') if not metadata_df.empty else 'unknown',
                'final_vulnerability_label': int(pred),
                'final_vulnerability_probability': float(prob),
                'selected_cwe_id': cwe,
                'source': 'fusion',
                'timestamp': datetime.now().isoformat()
            }
            
            # Add true label if available
            if not metadata_df.empty:
                if 'true_label' in metadata_df.columns:
                    result['true_label'] = int(metadata_df.iloc[idx]['true_label'])
                elif 'label' in metadata_df.columns:
                    result['true_label'] = int(metadata_df.iloc[idx]['label'])
            
            results.append(result)
        
        # Save as JSONL
        with open(output_path, 'w') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        
        logger.info(f"Saved {len(results)} fusion predictions to {output_path}")
        
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
        static_path: Optional[str] = None,
        codebert_path: Optional[str] = None,
        graphcodebert_path: Optional[str] = None,
        llm_path: Optional[str] = None,
        output_path: str = 'outputs/inference/fusion_results.jsonl',
        explain: bool = True
    ):
        """Run full fusion inference pipeline.
        
        Args:
            static_path: Path to static predictions
            codebert_path: Path to CodeBERT predictions
            graphcodebert_path: Path to GraphCodeBERT predictions
            llm_path: Path to LLM predictions (alternative)
            output_path: Path to output JSONL
            explain: Whether to compute explainability
        """
        logger.info("=" * 80)
        logger.info("Starting Fusion Model Inference")
        logger.info("=" * 80)
        
        # Load and merge predictions
        df = self.load_predictions(
            static_path=static_path,
            codebert_path=codebert_path,
            graphcodebert_path=graphcodebert_path,
            llm_path=llm_path
        )
        
        # Engineer features
        df = self.engineer_features(df)
        
        # Preprocess
        X, metadata_df = self.preprocess_features(df)
        
        # Predict
        predictions, probabilities = self.predict(X)
        
        # Map CWE
        cwe_list = self.map_cwe(predictions, probabilities, metadata_df)
        
        # Save results
        self.save_results(predictions, probabilities, metadata_df, cwe_list, output_path)
        
        # Compute explainability
        if explain:
            output_dir = Path(output_path).parent / 'explainability'
            self.compute_explainability(X, output_dir)
        
        logger.info("=" * 80)
        logger.info("Fusion Inference Complete!")
        logger.info("=" * 80)


def main():
    """Main fusion inference CLI."""
    parser = argparse.ArgumentParser(
        description="Fusion XGBoost Model Inference",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '--model-path',
        type=str,
        required=True,
        help='Path to trained fusion model (.joblib or .pkl)'
    )
    parser.add_argument(
        '--static-results',
        type=str,
        default=None,
        help='Path to static model predictions (JSONL)'
    )
    parser.add_argument(
        '--codebert-results',
        type=str,
        default=None,
        help='Path to CodeBERT predictions (JSONL)'
    )
    parser.add_argument(
        '--graphcodebert-results',
        type=str,
        default=None,
        help='Path to GraphCodeBERT predictions (JSONL)'
    )
    parser.add_argument(
        '--llm-results',
        type=str,
        default=None,
        help='Path to LLM predictions (JSONL) - alternative to codebert/graph'
    )
    parser.add_argument(
        '--output-path',
        type=str,
        default='outputs/inference/fusion_results.jsonl',
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
        help='Path to fusion_config.yml'
    )
    parser.add_argument(
        '--explain',
        action='store_true',
        help='Compute explainability (SHAP and feature importance)'
    )
    parser.add_argument(
        '--use-calibrated',
        action='store_true',
        default=True,
        help='Use calibrated model if available'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not any([args.static_results, args.codebert_results, args.graphcodebert_results, args.llm_results]):
        parser.error("Must provide at least one of: --static-results, --codebert-results, --graphcodebert-results, --llm-results")
    
    try:
        # Initialize fusion inference engine
        inference = FusionModelInference(
            model_path=args.model_path,
            metadata_path=args.metadata_path,
            imputer_path=args.imputer_path,
            config_path=args.config
        )
        
        # Run fusion inference
        inference.run_inference(
            static_path=args.static_results,
            codebert_path=args.codebert_results,
            graphcodebert_path=args.graphcodebert_results,
            llm_path=args.llm_results,
            output_path=args.output_path,
            explain=args.explain
        )
        
        logger.info("✅ Fusion inference completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Fusion inference failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
