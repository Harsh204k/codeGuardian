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
                import joblib

                self.model = joblib.load(model_file)

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
        """
        Predict if code is vulnerable using XGBoost
        Returns: (is_vulnerable, confidence, explanation)
        """
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
            self.rules = load_rules(
                "java,python,cpp,csharp,php"
            )  # Load all language rules
            logger.info(f"Loaded {len(self.rules)} detection rules")
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            self.rules = []

        # Initialize ML detector
        self.ml_detector = MLVulnerabilityDetector() if enable_ml else None
        self.ml_enabled = False

        if self.ml_detector:
            self.ml_enabled = self.ml_detector.load_model()
            logger.info(
                f"ML enhancement: {'enabled' if self.ml_enabled else 'disabled'}"
            )

    def scan_file(self, file_path: str, mode: str = "hybrid") -> Dict:
        """
        Scan file with specified mode
        Modes: 'rules', 'ml', 'hybrid'
        """
        results = {
            "file_path": file_path,
            "mode": mode,
            "rule_findings": [],
            "ml_analysis": None,
            "hybrid_score": 0.0,
            "final_assessment": "safe",
            "confidence": 0.0,
        }

        try:
            # Read file content
            with open(file_path, "r", encoding="utf-8") as f:
                code_content = f.read()

            # Rule-based detection (always run)
            if mode in ["rules", "hybrid"]:
                rule_findings = self._run_rule_scanner(file_path)
                results["rule_findings"] = rule_findings

            # ML-based detection
            if mode in ["ml", "hybrid"] and self.ml_enabled:
                ml_result = self._run_ml_analysis(code_content)
                results["ml_analysis"] = ml_result

            # Combine results for hybrid mode
            if mode == "hybrid":
                results.update(
                    self._combine_analyses(
                        results["rule_findings"], results["ml_analysis"]
                    )
                )
            elif mode == "rules":
                results.update(self._assess_rule_findings(results["rule_findings"]))
            elif mode == "ml" and self.ml_enabled:
                results.update(self._assess_ml_findings(results["ml_analysis"]))

        except Exception as e:
            logger.error(f"Scan failed for {file_path}: {e}")
            results["error"] = str(e)

        return results

    def _run_rule_scanner(self, file_path: str) -> List[Dict]:
        """Run traditional rule-based scanner"""
        try:
            from pathlib import Path

            # Determine language from file extension
            file_ext = Path(file_path).suffix.lower()
            lang_map = {
                ".c": "cpp",
                ".cpp": "cpp",
                ".cc": "cpp",
                ".cxx": "cpp",
                ".h": "cpp",
                ".hpp": "cpp",
                ".java": "java",
                ".py": "python",
                ".php": "php",
                ".cs": "csharp",
                ".js": "javascript",
                ".ts": "javascript",
            }

            language = lang_map.get(
                file_ext, "cpp"
            )  # Default to cpp for unknown extensions

            # Create the file input format expected by scan_files
            file_pairs = [(language, Path(file_path))]

            # Use existing scanner logic
            findings = scan_files(
                file_pairs, self.rules, profile="balanced", appname="HybridScan"
            )

            rule_findings = []
            for finding in findings:
                rule_findings.append(
                    {
                        "rule_id": finding.rule_id,
                        "severity": finding.severity,
                        "line": finding.line,
                        "message": finding.name,
                        "cwe": finding.cwe,
                        "confidence": finding.confidence,
                    }
                )

            return rule_findings

        except Exception as e:
            logger.error(f"Rule scanner failed: {e}")
            return []

    def _run_ml_analysis(self, code_content: str) -> Optional[Dict]:
        """Run ML-based analysis"""
        if not self.ml_enabled:
            return None

        try:
            is_vulnerable, confidence, explanation = (
                self.ml_detector.predict_vulnerability(code_content)
            )

            return {
                "is_vulnerable": is_vulnerable,
                "confidence": confidence,
                "explanation": explanation,
            }

        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            return None

    def _combine_analyses(
        self, rule_findings: List[Dict], ml_analysis: Optional[Dict]
    ) -> Dict:
        """Combine rule and ML analyses using ensemble method"""
        # Rule-based score
        rule_score = 0.0
        high_severity_count = 0

        for finding in rule_findings:
            if finding["severity"].lower() in ["high", "critical"]:
                rule_score += 0.8
                high_severity_count += 1
            elif finding["severity"].lower() == "medium":
                rule_score += 0.5
            else:
                rule_score += 0.2

        # Normalize rule score
        rule_score = min(rule_score, 1.0)

        # ML score
        ml_score = 0.0
        if ml_analysis:
            ml_score = (
                ml_analysis["confidence"] if ml_analysis["is_vulnerable"] else 0.0
            )

        # Ensemble scoring (weighted combination)
        if ml_analysis:
            # Both available - weighted ensemble
            hybrid_score = 0.6 * rule_score + 0.4 * ml_score
            confidence = max(
                rule_score, ml_score
            )  # Higher confidence from either method
        else:
            # Only rules available
            hybrid_score = rule_score
            confidence = rule_score

        # Final assessment
        final_assessment = "vulnerable" if hybrid_score > 0.5 else "safe"

        return {
            "hybrid_score": hybrid_score,
            "final_assessment": final_assessment,
            "confidence": confidence,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "high_severity_findings": high_severity_count,
        }

    def _assess_rule_findings(self, rule_findings: List[Dict]) -> Dict:
        """Assess results from rule-based findings only"""
        rule_score = min(
            len(
                [
                    f
                    for f in rule_findings
                    if f["severity"].lower() in ["high", "critical"]
                ]
            )
            * 0.3,
            1.0,
        )

        return {
            "hybrid_score": rule_score,
            "final_assessment": "vulnerable" if rule_findings else "safe",
            "confidence": rule_score,
            "rule_score": rule_score,
            "ml_score": 0.0,
        }

    def _assess_ml_findings(self, ml_analysis: Optional[Dict]) -> Dict:
        """Assess results from ML analysis only"""
        if not ml_analysis:
            return {
                "hybrid_score": 0.0,
                "final_assessment": "safe",
                "confidence": 0.0,
                "rule_score": 0.0,
                "ml_score": 0.0,
            }

        ml_score = ml_analysis["confidence"] if ml_analysis["is_vulnerable"] else 0.0

        return {
            "hybrid_score": ml_score,
            "final_assessment": (
                "vulnerable" if ml_analysis["is_vulnerable"] else "safe"
            ),
            "confidence": ml_analysis["confidence"],
            "rule_score": 0.0,
            "ml_score": ml_score,
        }


def demo_hybrid_scanner():
    """Demo the hybrid scanner"""
    scanner = HybridVulnerabilityScanner(enable_ml=True)

    # Test with a sample file
    test_files = ["balanced_test_files/vuln_001.c", "balanced_test_files/safe_001.c"]

    for test_file in test_files:
        if Path(test_file).exists():
            print(f"\n📊 Scanning {test_file}:")

            # Test all modes
            for mode in ["rules", "hybrid"]:
                result = scanner.scan_file(test_file, mode=mode)
                print(f"\n{mode.upper()} MODE:")
                print(f"Assessment: {result['final_assessment']}")
                print(f"Confidence: {result['confidence']:.3f}")
                print(f"Hybrid Score: {result['hybrid_score']:.3f}")
                print(f"Rule Findings: {len(result['rule_findings'])}")
                if result["ml_analysis"]:
                    print(f"ML Analysis: {result['ml_analysis']['explanation']}")


if __name__ == "__main__":
    demo_hybrid_scanner()
