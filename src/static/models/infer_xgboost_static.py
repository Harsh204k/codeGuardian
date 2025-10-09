#!/usr/bin/env python3
"""
Static XGBoost Model Inference Script
Phase 3.2 - Production-Grade ML Pipeline (ENHANCED)

This script performs inference using trained XGBoost static model.

Features:
- Load trained model + metadata + preprocessor
- **RAW CODE INPUT SUPPORT**: Extract features from raw code automatically
- Automatic static feature extraction (M1-M15 metrics)
- Rule-based analyzer integration (CWE flags, vulnerability patterns)
- Batch inference with chunk processing
- SHAP explainability for predictions
- CWE mapping support
- Consistent JSONL/JSON output format
- Integration with main pipeline

Usage:
    # Pre-engineered dataset:
    python infer_xgboost_static.py --model-path <model.pkl> --input-path features.csv
    
    # Raw code input (single file):
    python infer_xgboost_static.py --model-path <model.pkl> --raw-code-file app.py --language python
    
    # Raw code input (directory):
    python infer_xgboost_static.py --model-path <model.pkl> --raw-code-dir ./code --language python
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import joblib
import numpy as np
import pandas as pd
import shap
import yaml
from xgboost import XGBClassifier

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class RawCodeFeatureExtractor:
    """
    Extracts static features and analyzer outputs from raw code.
    Integrates static_feature_extractor.py and multi_analyzer.py.
    """
    
    def __init__(self):
        """Initialize feature extractor and analyzers."""
        try:
            from src.static.features.static_feature_extractor import StaticFeatureExtractor
            from src.static.analyzers.multi_analyzer import EnhancedMultiAnalyzer
            from src.static.analyzers.rule_engine import RuleEngine
            
            self.static_extractor = StaticFeatureExtractor()
            
            # Initialize rule engine and multi-analyzer
            rule_engine = RuleEngine()
            rule_engine.load_rules()
            self.multi_analyzer = EnhancedMultiAnalyzer(max_workers=4, rule_engine=rule_engine)
            
            logger.info("✅ Initialized raw code feature extractor with static metrics and analyzers")
        except ImportError as e:
            logger.error(f"Failed to import required modules: {e}")
            raise
    
    def extract_from_code(
        self,
        code: str,
        language: str,
        file_path: str = "unknown",
        record_id: str = None
    ) -> Dict[str, Any]:
        """
        Extract complete feature set from raw code.
        
        Args:
            code: Source code string
            language: Programming language
            file_path: File path (for metadata)
            record_id: Unique identifier
        
        Returns:
            Dictionary with all features (M1-M15 + analyzer outputs)
        """
        logger.info(f"Extracting features from {file_path} ({language})")
        
        # 1. Extract static metrics (M1-M15)
        static_features = self.static_extractor.extract_all_features(code, language)
        
        # 2. Run static analyzers for CWE flags and vulnerability patterns
        analyzer_results = self._run_analyzers(code, language, file_path)
        
        # 3. Combine features
        combined_features = self._combine_features(
            static_features,
            analyzer_results,
            code,
            language,
            file_path,
            record_id
        )
        
        return combined_features
    
    def _run_analyzers(self, code: str, language: str, file_path: str) -> Dict[str, Any]:
        """Run rule-based analyzers to detect vulnerabilities."""
        try:
            # Get language-specific analyzer
            analyzer = self.multi_analyzer.analyzers.get(language.lower())
            
            if analyzer is None:
                logger.warning(f"No analyzer found for language: {language}")
                return self._get_empty_analyzer_results()
            
            # Run analysis
            findings = analyzer.analyze(code, file_path, app_name="inference")
            
            # Process findings
            cwe_set = set()
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            rule_flags = {}
            
            for finding in findings:
                if isinstance(finding, dict):
                    cwe = finding.get('cwe', 'Unknown')
                    severity = finding.get('severity', 'info').lower()
                    rule_id = finding.get('rule_id', '')
                    
                    cwe_set.add(cwe)
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    rule_flags[rule_id] = 1
            
            # Compute aggregate metrics
            vulnerability_count = len(findings)
            has_vulnerabilities = 1 if vulnerability_count > 0 else 0
            
            # Risk score (weighted by severity)
            risk_score = (
                severity_counts['critical'] * 10 +
                severity_counts['high'] * 5 +
                severity_counts['medium'] * 2 +
                severity_counts['low'] * 1
            )
            
            # Confidence (based on number of findings)
            static_confidence = min(0.95, 0.5 + (vulnerability_count * 0.05))
            
            return {
                'findings': findings,
                'detected_cwes': list(cwe_set),
                'vulnerability_count': vulnerability_count,
                'has_vulnerabilities': has_vulnerabilities,
                'critical_count': severity_counts['critical'],
                'high_count': severity_counts['high'],
                'medium_count': severity_counts['medium'],
                'low_count': severity_counts['low'],
                'info_count': severity_counts.get('info', 0),
                'risk_score': risk_score,
                'static_confidence': static_confidence,
                'rule_flags': rule_flags,
                'severity_score': risk_score / max(vulnerability_count, 1)
            }
        
        except Exception as e:
            logger.warning(f"Analyzer failed: {e}")
            return self._get_empty_analyzer_results()
    
    def _get_empty_analyzer_results(self) -> Dict[str, Any]:
        """Return empty analyzer results for missing data."""
        return {
            'findings': [],
            'detected_cwes': [],
            'vulnerability_count': 0,
            'has_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0,
            'risk_score': 0.0,
            'static_confidence': 0.0,
            'rule_flags': {},
            'severity_score': 0.0
        }
    
    def _combine_features(
        self,
        static_features: Dict[str, Any],
        analyzer_results: Dict[str, Any],
        code: str,
        language: str,
        file_path: str,
        record_id: str
    ) -> Dict[str, Any]:
        """Combine static metrics and analyzer results into unified feature schema."""
        
        # Base record
        record = {
            'id': record_id or f"raw_{hash(code) % 1000000}",
            'file': file_path,
            'language': language,
            'code': code,
            'function': Path(file_path).stem if file_path != "unknown" else "unknown"
        }
        
        # Add M1-M15 static metrics (ensure correct naming for model)
        # Map from static_feature_extractor output to model expected features
        feature_mapping = {
            'M1_cyclomatic_complexity': static_features.get('M1_cyclomatic_complexity', 0),
            'M2_nesting_depth': static_features.get('M2_nesting_depth', 0),
            'M3_num_operators': static_features.get('M3_function_call_count', 0),  # Approximation
            'M4_num_operands': static_features.get('M11_variable_count', 0),  # Approximation
            'M5_num_unique_operators': static_features.get('M7_api_call_count', 0),  # Approximation
            'M6_num_unique_operands': static_features.get('M5_string_literal_count', 0) + static_features.get('M6_numeric_literal_count', 0),
            'M7_halstead_length': static_features.get('M3_function_call_count', 0) + static_features.get('M11_variable_count', 0),
            'M8_halstead_vocabulary': static_features.get('M7_api_call_count', 0),
            'M9_halstead_volume': 0.0,  # Computed below
            'M10_halstead_difficulty': 0.0,  # Computed below
            'M11_halstead_effort': 0.0,  # Computed below
            'M12_maintainability_index': 100.0 - (static_features.get('M15_code_complexity_score', 0) * 10),
            'M13_loc': static_features.get('M4_lines_of_code', 0),
            'M14_cognitive_complexity': static_features.get('M1_cyclomatic_complexity', 0) + static_features.get('M2_nesting_depth', 0),
            'M15_code_complexity_score': static_features.get('M15_code_complexity_score', 0)
        }
        
        # Compute Halstead metrics
        N = feature_mapping['M7_halstead_length']
        n = feature_mapping['M8_halstead_vocabulary']
        if n > 0 and N > 0:
            import math
            feature_mapping['M9_halstead_volume'] = N * math.log2(n) if n > 1 else N
            feature_mapping['M10_halstead_difficulty'] = (n / 2) * (feature_mapping['M4_num_operands'] / max(feature_mapping['M6_num_unique_operands'], 1))
            feature_mapping['M11_halstead_effort'] = feature_mapping['M9_halstead_volume'] * feature_mapping['M10_halstead_difficulty']
        
        record.update(feature_mapping)
        
        # Add analyzer-based features
        record.update({
            'vulnerability_count': analyzer_results['vulnerability_count'],
            'has_vulnerabilities': analyzer_results['has_vulnerabilities'],
            'critical_count': analyzer_results['critical_count'],
            'high_count': analyzer_results['high_count'],
            'medium_count': analyzer_results['medium_count'],
            'low_count': analyzer_results['low_count'],
            'risk_score': analyzer_results['risk_score'],
            'static_confidence': analyzer_results['static_confidence'],
            'severity_score': analyzer_results['severity_score'],
            'detected_cwes': analyzer_results['detected_cwes'],
            'findings': analyzer_results['findings']
        })
        
        # Add rule flags as binary features
        for rule_id, flag in analyzer_results['rule_flags'].items():
            record[f'rule_{rule_id}'] = flag
        
        return record


class StaticModelInference:
    """Inference engine for static XGBoost model (ENHANCED with raw code support)."""
    
    def __init__(
        self,
        model_path: str,
        metadata_path: Optional[str] = None,
        imputer_path: Optional[str] = None,
        config_path: Optional[str] = None,
        enable_raw_code: bool = True
    ):
        """Initialize inference engine.
        
        Args:
            model_path: Path to trained model (.joblib or .pkl)
            metadata_path: Path to metadata YAML (optional, auto-detected)
            imputer_path: Path to fitted imputer (optional, auto-detected)
            config_path: Path to model_config.yml (optional)
            enable_raw_code: Enable raw code input support (default: True)
        """
        self.model_path = Path(model_path)
        self.enable_raw_code = enable_raw_code
        
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
        
        # Initialize raw code feature extractor if enabled
        self.raw_code_extractor = None
        if self.enable_raw_code:
            try:
                self.raw_code_extractor = RawCodeFeatureExtractor()
                logger.info("✅ Raw code input support enabled")
            except Exception as e:
                logger.warning(f"⚠️  Raw code support disabled: {e}")
                self.enable_raw_code = False
        
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
    
    def load_raw_code_file(
        self,
        code_file: str,
        language: str
    ) -> pd.DataFrame:
        """Load and extract features from a single raw code file.
        
        Args:
            code_file: Path to code file
            language: Programming language
        
        Returns:
            DataFrame with extracted features
        """
        if not self.enable_raw_code or self.raw_code_extractor is None:
            raise RuntimeError("Raw code input support is not enabled")
        
        code_path = Path(code_file)
        if not code_path.exists():
            raise FileNotFoundError(f"Code file not found: {code_file}")
        
        logger.info(f"📄 Loading raw code from {code_file}")
        
        # Read code
        with open(code_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        # Extract features
        record = self.raw_code_extractor.extract_from_code(
            code=code,
            language=language,
            file_path=str(code_path),
            record_id=f"raw_{code_path.stem}"
        )
        
        # Convert to DataFrame
        df = pd.DataFrame([record])
        logger.info(f"✅ Extracted features from 1 file")
        
        return df
    
    def load_raw_code_directory(
        self,
        code_dir: str,
        language: str,
        recursive: bool = True,
        extensions: List[str] = None
    ) -> pd.DataFrame:
        """Load and extract features from all code files in a directory.
        
        Args:
            code_dir: Path to directory containing code files
            language: Programming language
            recursive: Search recursively (default: True)
            extensions: File extensions to include (default: language-specific)
        
        Returns:
            DataFrame with extracted features from all files
        """
        if not self.enable_raw_code or self.raw_code_extractor is None:
            raise RuntimeError("Raw code input support is not enabled")
        
        dir_path = Path(code_dir)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {code_dir}")
        
        # Default extensions by language
        if extensions is None:
            ext_mapping = {
                'python': ['.py'],
                'java': ['.java'],
                'javascript': ['.js', '.jsx'],
                'typescript': ['.ts', '.tsx'],
                'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.h'],
                'c': ['.c', '.h'],
                'php': ['.php'],
                'go': ['.go'],
                'ruby': ['.rb']
            }
            extensions = ext_mapping.get(language.lower(), ['.txt'])
        
        # Find all code files
        code_files = []
        if recursive:
            for ext in extensions:
                code_files.extend(dir_path.rglob(f'*{ext}'))
        else:
            for ext in extensions:
                code_files.extend(dir_path.glob(f'*{ext}'))
        
        if not code_files:
            raise ValueError(f"No {language} files found in {code_dir}")
        
        logger.info(f"📂 Found {len(code_files)} {language} files in {code_dir}")
        
        # Extract features from all files
        records = []
        for code_file in code_files:
            try:
                with open(code_file, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                record = self.raw_code_extractor.extract_from_code(
                    code=code,
                    language=language,
                    file_path=str(code_file),
                    record_id=f"raw_{code_file.stem}_{hash(str(code_file)) % 10000}"
                )
                records.append(record)
                
            except Exception as e:
                logger.warning(f"⚠️  Failed to process {code_file}: {e}")
        
        df = pd.DataFrame(records)
        logger.info(f"✅ Extracted features from {len(df)} files")
        
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
        output_path: str,
        json_output_path: str = None
    ):
        """Save inference results to JSONL and JSON.
        
        Args:
            predictions: Binary predictions
            probabilities: Prediction probabilities
            metadata_df: Metadata DataFrame
            cwe_list: List of CWE IDs
            output_path: Path to output JSONL file
            json_output_path: Path to JSON summary (optional)
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
                'is_vulnerable': int(pred),
                'predicted_CWE': cwe,
                'confidence_score': float(prob),
                'vulnerability_label': int(pred),  # Legacy field
                'vulnerability_probability': float(prob),  # Legacy field
                'cwe_hint': cwe,  # Legacy field
                'source': 'static_analyzer',
                'timestamp': datetime.now().isoformat()
            }
            
            # Add true label if available
            if not metadata_df.empty and 'label' in metadata_df.columns:
                result['true_label'] = int(metadata_df.iloc[idx]['label'])
            
            # Add rule flags if available
            if not metadata_df.empty and 'findings' in metadata_df.columns:
                try:
                    findings = metadata_df.iloc[idx].get('findings', [])
                    if findings:
                        result['static_rule_hits'] = len(findings)
                        result['detected_rules'] = [f.get('rule_id', '') for f in findings if isinstance(f, dict)]
                except:
                    pass
            
            results.append(result)
        
        # Save as JSONL
        with open(output_path, 'w') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        
        logger.info(f"Saved {len(results)} predictions to {output_path}")
        
        # Save summary statistics
        summary = {
            'inference_summary': {
                'timestamp': datetime.now().isoformat(),
                'model_version': self.metadata.get('version', 'unknown'),
                'total_samples': len(predictions),
                'vulnerable_samples': int(predictions.sum()),
                'safe_samples': int((1 - predictions).sum()),
                'vulnerability_rate': float(predictions.mean()),
                'mean_confidence': float(probabilities.mean()),
                'min_confidence': float(probabilities.min()),
                'max_confidence': float(probabilities.max())
            },
            'predictions': results[:100]  # Include first 100 for quick review
        }
        
        # Save JSON summary
        if json_output_path is None:
            json_output_path = output_path.parent / 'static_inference_results.json'
        else:
            json_output_path = Path(json_output_path)
        
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Saved summary to {json_output_path}")
        
        # Also save legacy summary format
        summary_path = output_path.parent / f"{output_path.stem}_summary.json"
        legacy_summary = {
            'total_samples': len(predictions),
            'positive_predictions': int(predictions.sum()),
            'negative_predictions': int((1 - predictions).sum()),
            'mean_probability': float(probabilities.mean()),
            'positive_rate': float(predictions.mean()),
            'timestamp': datetime.now().isoformat()
        }
        
        with open(summary_path, 'w') as f:
            json.dump(legacy_summary, f, indent=2)
        
        logger.info(f"Saved legacy summary to {summary_path}")

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
    """Main inference CLI (ENHANCED with raw code support)."""
    parser = argparse.ArgumentParser(
        description="Static XGBoost Model Inference (with raw code support)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="""
Examples:
  # Pre-engineered dataset:
  python infer_xgboost_static.py --model-path model.pkl --input-path features.csv
  
  # Raw code file:
  python infer_xgboost_static.py --model-path model.pkl --raw-code-file app.py --language python
  
  # Raw code directory:
  python infer_xgboost_static.py --model-path model.pkl --raw-code-dir ./src --language python
        """
    )
    
    # Model configuration
    parser.add_argument(
        '--model-path',
        type=str,
        required=True,
        help='Path to trained XGBoost model (.joblib or .pkl)'
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
    
    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--input-path',
        type=str,
        help='Path to pre-engineered input data (CSV or JSONL)'
    )
    input_group.add_argument(
        '--raw-code-file',
        type=str,
        help='Path to single raw code file for analysis'
    )
    input_group.add_argument(
        '--raw-code-dir',
        type=str,
        help='Path to directory containing raw code files'
    )
    
    # Language (required for raw code)
    parser.add_argument(
        '--language',
        type=str,
        choices=['python', 'java', 'javascript', 'typescript', 'cpp', 'c', 'php', 'go', 'ruby'],
        help='Programming language (required for raw code input)'
    )
    
    # Output options
    parser.add_argument(
        '--output-path',
        type=str,
        default='outputs/inference/static_results.jsonl',
        help='Path to output JSONL file'
    )
    parser.add_argument(
        '--output-json',
        type=str,
        default='outputs/inference/static_inference_results.json',
        help='Path to output JSON summary file'
    )
    
    # Processing options
    parser.add_argument(
        '--format',
        type=str,
        default='auto',
        choices=['auto', 'csv', 'jsonl'],
        help='Input data format (for pre-engineered data)'
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
    parser.add_argument(
        '--recursive',
        action='store_true',
        default=True,
        help='Search recursively in directory (for --raw-code-dir)'
    )
    
    args = parser.parse_args()
    
    # Validate language for raw code inputs
    if (args.raw_code_file or args.raw_code_dir) and not args.language:
        parser.error("--language is required for raw code inputs")
    
    try:
        logger.info("🚀 Starting Static XGBoost Inference Pipeline")
        logger.info("=" * 80)
        
        # Initialize inference engine
        inference = StaticModelInference(
            model_path=args.model_path,
            metadata_path=args.metadata_path,
            imputer_path=args.imputer_path,
            config_path=args.config,
            enable_raw_code=bool(args.raw_code_file or args.raw_code_dir)
        )
        
        # Load data based on input type
        if args.input_path:
            # Pre-engineered data
            logger.info(f"📊 Loading pre-engineered data from: {args.input_path}")
            df = inference.load_input_data(args.input_path, format=args.format)
        
        elif args.raw_code_file:
            # Single raw code file
            logger.info(f"📄 Processing single raw code file: {args.raw_code_file}")
            df = inference.load_raw_code_file(args.raw_code_file, args.language)
        
        elif args.raw_code_dir:
            # Directory of raw code files
            logger.info(f"📂 Processing raw code directory: {args.raw_code_dir}")
            df = inference.load_raw_code_directory(
                args.raw_code_dir,
                args.language,
                recursive=args.recursive
            )
        
        logger.info(f"✅ Loaded {len(df)} samples for inference")
        logger.info("=" * 80)
        
        # Preprocess features
        X, metadata_df = inference.preprocess_features(df)
        
        # Run prediction
        predictions, probabilities = inference.predict(X)
        
        # Map CWE
        cwe_list = inference.map_cwe(predictions, probabilities, metadata_df)
        
        # Save results
        inference.save_results(
            predictions, 
            probabilities, 
            metadata_df, 
            cwe_list, 
            args.output_path,
            json_output_path=args.output_json if hasattr(args, 'output_json') else None
        )
        
        # Compute explainability
        if args.explain:
            output_dir = Path(args.output_path).parent / 'explainability'
            inference.compute_explainability(X, output_dir)
        
        # Print summary
        print("\n" + "=" * 80)
        print("✅ INFERENCE COMPLETE")
        print("=" * 80)
        print(f"📊 Total samples analyzed: {len(predictions)}")
        print(f"🔴 Vulnerable predictions: {predictions.sum()} ({predictions.mean():.1%})")
        print(f"🟢 Safe predictions: {(1-predictions).sum()} ({(1-predictions).mean():.1%})")
        print(f"📈 Mean confidence: {probabilities.mean():.3f}")
        print(f"💾 Results saved to: {args.output_path}")
        print(f"💾 Summary saved to: {args.output_json}")
        if args.explain:
            print(f"🔍 Explainability saved to: {output_dir}")
        print("=" * 80 + "\n")
        
        logger.info("✅ Inference completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Inference failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

