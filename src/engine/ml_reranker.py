import joblib
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

try:
    from transformers import AutoTokenizer, AutoModel
    import torch

    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

_model = None
_tokenizer = None
_codebert_model = None


def _read_snippet(path, line, radius=60):
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        s = max(0, (line or 1) - 1 - radius)
        e = min(len(lines), (line or 1) - 1 + radius)
        return "\n".join(lines[s:e])
    except:
        return ""


def _featurize(snippet: str, rule_id: str, cwe: str):
    lower = snippet.lower()
    return {
        "ruleId": rule_id or "",
        "cwe": cwe or "",
        "len": len(snippet),
        "plus_count": snippet.count("+"),
        "concat_sql": int(
            (
                "select" in lower
                or "insert" in lower
                or "update" in lower
                or "delete" in lower
            )
            and ("+" in snippet or "concat" in lower)
        ),
        "has_exec": int(
            "runtime.getruntime().exec" in lower or "processbuilder" in lower
        ),
        "has_header": int(
            "addheader" in lower or "setheader" in lower or "sendredirect" in lower
        ),
        "has_getparam": int(
            "getparameter" in lower
            or "getquerystring" in lower
            or "getheader(" in lower
            or "getreader().readline" in lower
        ),
        "has_writer": int(
            "getwriter().print" in lower
            or "getwriter().println" in lower
            or "out.print" in lower
        ),
        "has_md5_sha1": int(
            'messagedigest.getinstance("md5"' in lower
            or 'messagedigest.getinstance("sha1"' in lower
        ),
        "aes_ecb": int('cipher.getinstance("aes/ecb' in lower),
        "path_file": int("new file(" in lower or "paths.get(" in lower),
        "xxe_factory": int(
            "documentbuilderfactory.newinstance(" in lower
            or "saxparserfactory.newinstance(" in lower
            or "xmlinputfactory.newinstance(" in lower
        ),
    }


def load_model(path="models/reranker_java.joblib"):
    global _model
    if _model is None:
        _model = joblib.load(path)
    return _model


class MLReranker:
    """Enhanced ML-based vulnerability reranker with CodeBERT support."""

    def __init__(self, model_path="models", use_codebert=True):
        self.model_path = Path(model_path)
        self.use_codebert = use_codebert and TRANSFORMERS_AVAILABLE
        self.models = {}  # Store models per language
        self.tokenizer = None
        self.codebert_model = None
        self.logger = logging.getLogger(__name__)

        if self.use_codebert:
            self._initialize_codebert()

    def _initialize_codebert(self):
        """Initialize CodeBERT model for code embeddings."""
        try:
            model_name = "microsoft/codebert-base"
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.codebert_model = AutoModel.from_pretrained(model_name)
            self.codebert_model.eval()
            self.logger.info("CodeBERT initialized successfully")
        except Exception as e:
            self.logger.warning(f"CodeBERT initialization failed: {e}")
            self.use_codebert = False

    def load_models(self):
        """Load trained models for all supported languages."""
        language_models = {
            "java": "reranker_java.joblib",
            "python": "reranker_python.joblib",
            "cpp": "reranker_cpp.joblib",
            "php": "reranker_php.joblib",
            "js": "reranker_js.joblib",
            "go": "reranker_go.joblib",
        }

        for language, model_file in language_models.items():
            model_path = self.model_path / model_file
            if model_path.exists():
                try:
                    self.models[language] = joblib.load(model_path)
                    self.logger.info(f"Loaded {language} model: {model_file}")
                except Exception as e:
                    self.logger.warning(f"Failed to load {language} model: {e}")
            else:
                self.logger.warning(f"Model not found: {model_path}")

    def get_code_embedding(self, code_snippet: str) -> Optional[np.ndarray]:
        """Generate CodeBERT embedding for code snippet."""
        if not self.use_codebert:
            return None

        try:
            # Tokenize and encode
            inputs = self.tokenizer(
                code_snippet,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=512,
            )

            with torch.no_grad():
                outputs = self.codebert_model(**inputs)
                # Use CLS token embedding
                embedding = outputs.last_hidden_state[:, 0, :].numpy().flatten()

            return embedding

        except Exception as e:
            self.logger.warning(f"CodeBERT embedding failed: {e}")
            return None

    def enhanced_featurize(
        self, snippet: str, rule_id: str, cwe: str, language: str = "java"
    ) -> Dict[str, Any]:
        """Enhanced feature extraction with CodeBERT embeddings."""
        # Original features
        features = _featurize(snippet, rule_id, cwe)

        # Add language-specific features
        features["language"] = language

        # Add advanced code features
        lower = snippet.lower()
        features.update(
            {
                "has_user_input": int(
                    any(
                        pattern in lower
                        for pattern in [
                            "request.",
                            "input(",
                            "getparameter",
                            "args[",
                            "argv",
                        ]
                    )
                ),
                "has_sanitization": int(
                    any(
                        pattern in lower
                        for pattern in [
                            "escape",
                            "sanitize",
                            "validate",
                            "filter",
                            "clean",
                        ]
                    )
                ),
                "complexity_score": len(snippet.split("\n")) * snippet.count("{"),
                "string_operations": snippet.count("+") + snippet.count("concat"),
                "security_keywords": sum(
                    1 for kw in ["password", "token", "secret", "key"] if kw in lower
                ),
            }
        )

        # Add CodeBERT embedding features if available
        if self.use_codebert:
            embedding = self.get_code_embedding(snippet)
            if embedding is not None:
                # Add first 50 dimensions of CodeBERT embedding
                for i, val in enumerate(embedding[:50]):
                    features[f"codebert_{i}"] = float(val)

        return features

    def rerank_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]], language: str = "java"
    ) -> List[Dict[str, Any]]:
        """Rerank vulnerabilities using ML models."""
        if not vulnerabilities:
            return vulnerabilities

        # Check if model is available for this language
        if language not in self.models:
            self.logger.warning(
                f"No ML model available for {language}, using heuristic scoring"
            )
            return self._heuristic_rerank(vulnerabilities)

        try:
            import pandas as pd

            model = self.models[language]

            # Feature extraction
            features_list = []
            for vuln in vulnerabilities:
                file_path = vuln.get("file", "")
                line_num = vuln.get("line", 0)
                rule_id = vuln.get("rule_id", "")
                cwe = vuln.get("cwe", "")

                # Read code snippet
                snippet = _read_snippet(file_path, line_num)

                # Extract features
                features = self.enhanced_featurize(snippet, rule_id, cwe, language)
                features_list.append(features)

            # Create DataFrame
            X = pd.DataFrame(features_list)

            # Handle missing columns (for models trained on different feature sets)
            expected_cols = getattr(model, "feature_names_in_", None)
            if expected_cols is not None:
                for col in expected_cols:
                    if col not in X.columns:
                        X[col] = 0  # Default value for missing features
                X = X[expected_cols]  # Reorder columns

            # Predict probabilities
            probs = (
                model.predict_proba(X)[:, 1]
                if hasattr(model, "predict_proba")
                else model.predict(X)
            )

            # Add ML scores to vulnerabilities
            for vuln, score in zip(vulnerabilities, probs):
                vuln["ml_score"] = float(score)

            # Sort by ML score (highest first)
            ranked_vulns = sorted(
                vulnerabilities, key=lambda x: x.get("ml_score", 0), reverse=True
            )

            return ranked_vulns

        except Exception as e:
            self.logger.error(f"ML reranking failed for {language}: {e}")
            return self._heuristic_rerank(vulnerabilities)

    def _heuristic_rerank(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Fallback heuristic-based ranking when ML models are unavailable."""
        severity_weights = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        cwe_priority = {
            "CWE-89": 10,  # SQL Injection
            "CWE-78": 9,  # Command Injection
            "CWE-79": 8,  # XSS
            "CWE-22": 7,  # Path Traversal
            "CWE-611": 6,  # XXE
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "MEDIUM").upper()
            cwe = vuln.get("cwe", "")

            score = severity_weights.get(severity, 2)
            score += cwe_priority.get(cwe, 1)

            vuln["ml_score"] = float(score / 10)  # Normalize to 0-1

        return sorted(vulnerabilities, key=lambda x: x.get("ml_score", 0), reverse=True)


def score_findings(findings, threshold=0.35):
    """Legacy function for backward compatibility."""
    if not findings:
        return findings
    try:
        import pandas as pd
    except Exception:
        return findings

    model = load_model()
    rows = []
    for f in findings:
        snip = _read_snippet(f.file, getattr(f, "line", 0) or 0)
        rows.append(_featurize(snip, getattr(f, "rule_id", ""), getattr(f, "cwe", "")))
    X = pd.DataFrame(rows)
    probs = model.predict_proba(X)[:, 1]
    keep = [f for f, p in zip(findings, probs) if p >= threshold]
    return keep
