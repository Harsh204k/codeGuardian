#!/usr/bin/env python3
"""
Hybrid Vulnerability Detection Engine
Combines rule-based detection with XGBoost ML semantic analysis
"""

import json
import pickle
import numpy as np
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import logging
import re
import joblib

# Import existing components
import sys

sys.path.append(".")
from src.engine.scanner import scan_files, Finding
from src.engine.rules_loader import load_rules

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
                r"\\b(def|function|void|int|char|float|double)\\s+\\w+\\s*\\(",
                code_lower,
            )
        )
        features["if_statements"] = len(re.findall(r"\\bif\\s*\\(", code_lower))
        features["loop_statements"] = len(
            re.findall(r"\\b(for|while|do)\\s*\\(", code_lower)
        )
        features["return_statements"] = len(re.findall(r"\\breturn\\b", code_lower))

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
            re.findall(r'(\\+\\s*"|strcat|concat)', code_lower)
        )
        features["hardcoded_values"] = len(
            re.findall(r'(password|secret|key)\\s*=\\s*["\']', code_lower)
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

        # Convert to array maintaining consistent order (39 features to match training)
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


class MLVulnerabilityDetector:
    """ML-based vulnerability detector using trained XGBoost"""

    def __init__(self, model_dir=None):
        # Find the latest XGBoost model (prefer 80/20 split models)
        models_path = Path("models")
        if model_dir:
            self.model_path = Path(model_dir)
        else:
            # Prioritize 80/20 split models
            split_models = list(models_path.glob("xgboost_80_20_split_*"))
            if split_models:
                self.model_path = max(split_models, key=lambda p: p.stat().st_mtime)
            else:
                # Fall back to regular xgboost models
                xgboost_models = list(models_path.glob("xgboost_vulnerability_*"))
                if xgboost_models:
                    self.model_path = max(
                        xgboost_models, key=lambda p: p.stat().st_mtime
                    )
                else:
                    self.model_path = models_path / "xgboost_vulnerability_latest"

        self.model = None
        self.feature_extractor = None
        self.is_loaded = False

    def load_model(self):
        """Load the trained XGBoost model"""
        try:
            if not self.model_path.exists():
                logger.warning(
                    f"ML model not found at {self.model_path}. ML features disabled."
                )
                return False

            logger.info(f"Loading XGBoost model from {self.model_path}")

            # Load the model
            model_file = self.model_path / "xgboost_model.joblib"
            if model_file.exists():
                self.model = joblib.load(model_file)

                # Load or initialize feature extractor
                feature_file = self.model_path / "feature_extractor.joblib"
                if feature_file.exists():
                    self.feature_extractor = joblib.load(feature_file)
                else:
                    # Initialize feature extractor with same logic as training
                    self.feature_extractor = VulnerabilityFeatureExtractor()

                self.is_loaded = True
                logger.info("XGBoost model loaded successfully")
                return True
            else:
                logger.error(f"Model file not found: {model_file}")
                return False

        except Exception as e:
            logger.error(f"Failed to load XGBoost model: {e}")
            return False

    def predict_vulnerability(
        self, code: str, confidence_threshold: float = 0.5
    ) -> Tuple[bool, float, str]:
        """Predict if code contains vulnerabilities using XGBoost"""
        if not self.is_loaded:
            return False, 0.0, "ML model not loaded"

        try:
            # Extract features from the code
            features = self.feature_extractor._extract_single_features(code)
            features_array = np.array([features])  # XGBoost expects 2D array

            # Get prediction probabilities
            vuln_prob = self.model.predict_proba(features_array)[0][
                1
            ]  # Probability of vulnerability
            is_vulnerable = vuln_prob > confidence_threshold

            explanation = self._generate_explanation(vuln_prob, is_vulnerable)

            return is_vulnerable, vuln_prob, explanation

        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return False, 0.0, f"Prediction error: {str(e)}"

    def _generate_explanation(self, confidence: float, is_vulnerable: bool) -> str:
        """Generate human-readable explanation"""
        if is_vulnerable:
            if confidence > 0.9:
                return f"High confidence vulnerability detected (ML confidence: {confidence:.2%})"
            elif confidence > 0.7:
                return (
                    f"Likely vulnerability detected (ML confidence: {confidence:.2%})"
                )
            else:
                return f"Potential vulnerability detected (ML confidence: {confidence:.2%})"
        else:
            return f"Code appears safe (ML confidence: {(1-confidence):.2%})"


class HybridVulnerabilityScanner:
    """Enhanced scanner combining rules and ML"""

    def __init__(self, enable_ml: bool = True):
        # Load rules
        try:
            self.rules = load_rules("java,python,cpp,csharp,php")
            logger.info(f"Loaded {len(self.rules)} vulnerability detection rules")
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            self.rules = []

        # Initialize ML detector
        self.ml_detector = None
        if enable_ml:
            self.ml_detector = MLVulnerabilityDetector()
            if not self.ml_detector.load_model():
                logger.warning("ML detector disabled")
                self.ml_detector = None

    def scan_file(
        self, file_path: str, mode: str = "hybrid", ml_confidence: float = 0.5
    ) -> Dict:
        """
        Scan file with specified mode
        Modes: 'rules', 'ml', 'hybrid'
        """
        results = {
            "file": file_path,
            "mode": mode,
            "findings": [],
            "ml_analysis": None,
            "hybrid_score": 0.0,
            "confidence": 0.0,
        }

        try:
            # Read file content
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

        except Exception as e:
            results["error"] = f"Failed to read file: {e}"
            return results

        # Rule-based detection
        if mode in ["rules", "hybrid"]:
            rule_findings = scan_files([file_path], self.rules)
            results["findings"] = rule_findings

        # ML-based detection
        if mode in ["ml", "hybrid"] and self.ml_detector:
            ml_vulnerable, ml_confidence, ml_explanation = (
                self.ml_detector.predict_vulnerability(content, ml_confidence)
            )
            results["ml_analysis"] = {
                "vulnerable": ml_vulnerable,
                "confidence": ml_confidence,
                "explanation": ml_explanation,
            }

        # Hybrid scoring
        if mode == "hybrid":
            results = self._calculate_hybrid_score(results)
        elif mode == "rules":
            results["confidence"] = 1.0 if results["findings"] else 0.0
        elif mode == "ml" and results["ml_analysis"]:
            results["confidence"] = results["ml_analysis"]["confidence"]

        return results

    def _calculate_hybrid_score(self, results: Dict) -> Dict:
        """Calculate hybrid confidence score"""
        rule_score = 1.0 if results["findings"] else 0.0
        ml_score = (
            results["ml_analysis"]["confidence"] if results["ml_analysis"] else 0.0
        )

        # Weighted ensemble: Rules 60%, ML 40%
        hybrid_score = (0.6 * rule_score) + (0.4 * ml_score)

        results["hybrid_score"] = hybrid_score
        results["confidence"] = hybrid_score

        return results
