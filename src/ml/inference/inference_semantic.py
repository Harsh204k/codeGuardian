#!/usr/bin/env python3
# =============================
# codeGuardian Semantic Inference Module - Production Version
# Author: Urva Gandhi
# Purpose: Ensemble inference using LoRA-finetuned CodeBERT + GraphCodeBERT
# Standard: codeGuardian Inference Standard v1.0
# =============================

"""
codeGuardian Semantic Inference Engine
=======================================
Production-ready semantic vulnerability detection using calibrated ensemble
of LoRA-fine-tuned CodeBERT and GraphCodeBERT models.

Features:
✅ Dynamic LoRA adapter loading
✅ Configuration-driven ensemble weights & thresholds
✅ Temperature-scaled probability calibration
✅ Per-language threshold optimization
✅ Abstention margin for uncertain predictions
✅ GPU/CPU auto-detection
✅ Memory-efficient inference
✅ Comprehensive JSON output with metadata
✅ CLI interface for standalone execution
✅ Import-friendly for orchestrator integration

Architecture:
┌─────────────────────────────────────────────────────┐
│              Input: Code + Language                 │
└────────────────┬────────────────────────────────────┘
                 │
                 ├──────────────┐
                 ▼              ▼
         ┌──────────────┐ ┌──────────────┐
         │  CodeBERT    │ │GraphCodeBERT │
         │  + LoRA      │ │  + LoRA      │
         └──────┬───────┘ └──────┬───────┘
                │                │
                ▼                ▼
         ┌──────────────┐ ┌──────────────┐
         │ Temperature  │ │ Temperature  │
         │  Scaling     │ │  Scaling     │
         └──────┬───────┘ └──────┬───────┘
                │                │
                └────────┬───────┘
                         ▼
                  ┌──────────────┐
                  │   Weighted   │
                  │   Ensemble   │
                  └──────┬───────┘
                         ▼
                  ┌──────────────┐
                  │  Threshold   │
                  │  Application │
                  └──────┬───────┘
                         ▼
                  ┌──────────────┐
                  │   JSON       │
                  │   Output     │
                  └──────────────┘

Usage (CLI):
    python inference_semantic.py --code path/to/file.c --language C
    python inference_semantic.py --code "int main() {...}" --language C

Usage (Import):
    from src.ml.inference.inference_semantic import run_inference

    result = run_inference({
        "code": "int main() { ... }",
        "language": "C",
        "metadata": {"file": "main.c"}
    })
"""

import json
import os
import sys
import logging
import hashlib
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import warnings

import torch
import torch.nn.functional as F
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    RobertaTokenizer
)
from peft import PeftModel

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Setup colored logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ============================================================================
# CONSTANTS
# ============================================================================

# Model identifiers
CODEBERT_BASE = "microsoft/codebert-base"
GRAPHCODEBERT_BASE = "microsoft/graphcodebert-base"

# Default paths (can be overridden via config or environment)
DEFAULT_CODEBERT_ADAPTER = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_codebert"
DEFAULT_GRAPHCODEBERT_ADAPTER = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_graphcodebert"
DEFAULT_CONFIG_PATH = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/post_fine-tuning/callibration_threshold-optimizer/ensemble_config.json"

# Tokenization parameters
MAX_LENGTH = 512

# Supported languages
SUPPORTED_LANGUAGES = ["c", "python", "java", "cpp", "javascript", "go", "php", "ruby", "c#"]

# Exit codes for CLI
EXIT_CODES = {
    "secure": 0,
    "vulnerable": 1,
    "abstained": 2,
    "error": 3
}

# ============================================================================
# CONFIGURATION LOADER
# ============================================================================

def load_ensemble_config(config_path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Load ensemble configuration from JSON file.

    Args:
        config_path: Path to ensemble_config.json

    Returns:
        Configuration dictionary with weights, temperatures, thresholds

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    if not os.path.exists(config_path):
        logger.error(f"{Colors.FAIL}❌ Configuration file not found: {config_path}{Colors.ENDC}")
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # Handle both old and new config schema formats
        # New schema: {"models": {"codebert": {"weight": 0.4, "temperature": 0.5974}, ...}}
        # Old schema: {"weights": {...}, "temperatures": {...}}
        if "models" in config and ("weights" not in config or "temperatures" not in config):
            logger.info("Detected new config schema format, converting...")
            models = config["models"]
            config["weights"] = {
                "codebert": models.get("codebert", {}).get("weight", 0.5),
                "graphcodebert": models.get("graphcodebert", {}).get("weight", 0.5)
            }
            config["temperatures"] = {
                "codebert": models.get("codebert", {}).get("temperature", 1.0),
                "graphcodebert": models.get("graphcodebert", {}).get("temperature", 1.0)
            }

        # Validate required fields
        required_fields = ["weights", "temperatures", "thresholds"]
        missing_fields = [f for f in required_fields if f not in config]

        if missing_fields:
            raise ValueError(f"Missing required config fields: {missing_fields}")

        # Validate weights sum to 1.0
        weights = config["weights"]
        weight_sum = weights.get("codebert", 0) + weights.get("graphcodebert", 0)
        if not (0.99 <= weight_sum <= 1.01):  # Allow small floating point errors
            logger.warning(f"{Colors.WARNING}⚠️ Model weights sum to {weight_sum:.4f}, normalizing...{Colors.ENDC}")
            total = weights["codebert"] + weights["graphcodebert"]
            weights["codebert"] /= total
            weights["graphcodebert"] /= total

        logger.info(f"{Colors.OKGREEN}✓ Configuration loaded successfully{Colors.ENDC}")
        logger.info(f"  - CodeBERT weight: {weights['codebert']:.4f}, temp: {config['temperatures']['codebert']:.4f}")
        logger.info(f"  - GraphCodeBERT weight: {weights['graphcodebert']:.4f}, temp: {config['temperatures']['graphcodebert']:.4f}")
        logger.info(f"  - Global threshold: {config['thresholds']['global']:.4f}")
        logger.info(f"  - Abstention margin: {config['thresholds'].get('abstain_margin', 0.05):.4f}")

        return config

    except json.JSONDecodeError as e:
        logger.error(f"{Colors.FAIL}❌ Invalid JSON in config file: {e}{Colors.ENDC}")
        raise
    except Exception as e:
        logger.error(f"{Colors.FAIL}❌ Error loading config: {e}{Colors.ENDC}")
        raise

# ============================================================================
# MODEL LOADER
# ============================================================================

class SemanticInferenceEngine:
    """
    Production-grade semantic inference engine for vulnerability detection.
    Loads LoRA-adapted models and performs calibrated ensemble inference.
    """

    def __init__(
        self,
        config_path: str = DEFAULT_CONFIG_PATH,
        codebert_adapter_path: Optional[str] = None,
        graphcodebert_adapter_path: Optional[str] = None,
        device: Optional[str] = None
    ):
        """
        Initialize the inference engine.

        Args:
            config_path: Path to ensemble_config.json
            codebert_adapter_path: Path to CodeBERT LoRA adapter (optional)
            graphcodebert_adapter_path: Path to GraphCodeBERT LoRA adapter (optional)
            device: Device to use ('cuda', 'cpu', or None for auto-detect)
        """
        self.config = load_ensemble_config(config_path)

        # Set device
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        logger.info(f"{Colors.OKBLUE}🖥️  Using device: {self.device}{Colors.ENDC}")

        # Set default dtype for CUDA to ensure true FP16 inference
        if self.device.type == "cuda":
            torch.set_default_dtype(torch.float16)
            logger.info(f"{Colors.OKBLUE}🔧 Set default dtype to float16 for CUDA{Colors.ENDC}")

        # Set adapter paths
        self.codebert_adapter_path = codebert_adapter_path or DEFAULT_CODEBERT_ADAPTER
        self.graphcodebert_adapter_path = graphcodebert_adapter_path or DEFAULT_GRAPHCODEBERT_ADAPTER

        # Initialize models and tokenizer
        self.tokenizer = None
        self.codebert_model = None
        self.graphcodebert_model = None
        self.adapter_checksums = {}

        # Load models
        self._load_models()

    def _compute_adapter_checksum(self, adapter_path: str) -> str:
        """
        Compute MD5 checksum of adapter weights for traceability.
        Checks multiple possible file formats.

        Args:
            adapter_path: Path to adapter directory

        Returns:
            MD5 checksum string
        """
        # Try multiple adapter file formats
        adapter_file = None
        for fname in ["adapter_model.safetensors", "adapter_model.bin", "pytorch_model.bin"]:
            candidate = os.path.join(adapter_path, fname)
            if os.path.exists(candidate):
                adapter_file = candidate
                break

        if adapter_file is None:
            logger.warning(f"{Colors.WARNING}⚠️ No adapter weights file found in {adapter_path}{Colors.ENDC}")
            return "unknown"

        md5_hash = hashlib.md5()
        with open(adapter_file, "rb") as f:
            # Read in chunks for memory efficiency
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)

        return md5_hash.hexdigest()

    def _load_models(self):
        """Load tokenizer and both LoRA-adapted models."""
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}Loading Models{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")

        # Load shared tokenizer (RobertaTokenizer for both CodeBERT variants)
        logger.info("📦 Loading tokenizer...")
        try:
            self.tokenizer = RobertaTokenizer.from_pretrained(CODEBERT_BASE)

            # Validate tokenizer type for safety
            assert isinstance(self.tokenizer, RobertaTokenizer), \
                f"Unexpected tokenizer class: {type(self.tokenizer).__name__}"

            logger.info(f"{Colors.OKGREEN}✓ Tokenizer loaded (vocab size: {len(self.tokenizer)}){Colors.ENDC}")
        except Exception as e:
            logger.error(f"{Colors.FAIL}❌ Failed to load tokenizer: {e}{Colors.ENDC}")
            raise

        # Load CodeBERT + LoRA
        logger.info("\n🔹 Loading CodeBERT + LoRA adapter...")
        try:
            if not os.path.exists(self.codebert_adapter_path):
                raise FileNotFoundError(f"CodeBERT adapter not found: {self.codebert_adapter_path}")

            base_model = AutoModelForSequenceClassification.from_pretrained(
                CODEBERT_BASE,
                num_labels=2,
                torch_dtype=torch.float16 if self.device.type == "cuda" else torch.float32
            )
            self.codebert_model = PeftModel.from_pretrained(base_model, self.codebert_adapter_path)
            self.codebert_model = self.codebert_model.to(self.device)
            self.codebert_model.eval()

            self.adapter_checksums["codebert"] = self._compute_adapter_checksum(self.codebert_adapter_path)

            logger.info(f"{Colors.OKGREEN}✓ CodeBERT loaded successfully{Colors.ENDC}")
            logger.info(f"  - Adapter: {self.codebert_adapter_path}")
            logger.info(f"  - Checksum: {self.adapter_checksums['codebert']}")

        except Exception as e:
            logger.error(f"{Colors.FAIL}❌ Failed to load CodeBERT: {e}{Colors.ENDC}")
            raise

        # Load GraphCodeBERT + LoRA
        logger.info("\n🔹 Loading GraphCodeBERT + LoRA adapter...")
        try:
            if not os.path.exists(self.graphcodebert_adapter_path):
                raise FileNotFoundError(f"GraphCodeBERT adapter not found: {self.graphcodebert_adapter_path}")

            base_model = AutoModelForSequenceClassification.from_pretrained(
                GRAPHCODEBERT_BASE,
                num_labels=2,
                torch_dtype=torch.float16 if self.device.type == "cuda" else torch.float32
            )
            self.graphcodebert_model = PeftModel.from_pretrained(base_model, self.graphcodebert_adapter_path)
            self.graphcodebert_model = self.graphcodebert_model.to(self.device)
            self.graphcodebert_model.eval()

            self.adapter_checksums["graphcodebert"] = self._compute_adapter_checksum(self.graphcodebert_adapter_path)

            logger.info(f"{Colors.OKGREEN}✓ GraphCodeBERT loaded successfully{Colors.ENDC}")
            logger.info(f"  - Adapter: {self.graphcodebert_adapter_path}")
            logger.info(f"  - Checksum: {self.adapter_checksums['graphcodebert']}")

        except Exception as e:
            logger.error(f"{Colors.FAIL}❌ Failed to load GraphCodeBERT: {e}{Colors.ENDC}")
            raise

        logger.info(f"\n{Colors.OKGREEN}✅ All models loaded successfully{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

    def dispose(self):
        """
        Clean up models and release GPU memory.
        Use this for long-running sessions or when the engine is no longer needed.
        """
        logger.info(f"{Colors.OKCYAN}🧹 Disposing inference engine...{Colors.ENDC}")

        if self.codebert_model is not None:
            del self.codebert_model
            self.codebert_model = None

        if self.graphcodebert_model is not None:
            del self.graphcodebert_model
            self.graphcodebert_model = None

        if self.tokenizer is not None:
            del self.tokenizer
            self.tokenizer = None

        # Force GPU memory cleanup
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()

        logger.info(f"{Colors.OKGREEN}✓ Engine disposed and memory released{Colors.ENDC}")

    def _tokenize_code(self, code: str) -> Dict[str, torch.Tensor]:
        """
        Tokenize code snippet.

        Args:
            code: Source code string

        Returns:
            Dictionary with input_ids and attention_mask tensors
        """
        # Safeguard: trim extremely long code
        if len(code) > 30000:
            logger.warning(f"{Colors.WARNING}⚠️ Code length exceeds 30000 chars, truncating...{Colors.ENDC}")
            code = code[:30000]

        tokens = self.tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
            return_tensors="pt"
        )

        # Move to device
        return {k: v.to(self.device) for k, v in tokens.items()}

    def _get_model_probability(
        self,
        model: PeftModel,
        tokens: Dict[str, torch.Tensor],
        temperature: float
    ) -> float:
        """
        Get calibrated probability from a single model.

        Args:
            model: LoRA-adapted model
            tokens: Tokenized input
            temperature: Temperature scaling factor

        Returns:
            Calibrated probability for vulnerable class (class 1)
        """
        with torch.no_grad():
            outputs = model(**tokens)
            logits = outputs.logits[0]  # Shape: [2]

            # Get logit for vulnerable class (index 1)
            vulnerable_logit = logits[1].item()

            # Apply temperature scaling
            scaled_logit = vulnerable_logit / temperature

            # Convert to probability using sigmoid
            probability = torch.sigmoid(torch.tensor(scaled_logit)).item()

            return probability

    def _get_threshold(self, language: str) -> float:
        """
        Get appropriate threshold for the given language.

        Args:
            language: Programming language (normalized to lowercase)

        Returns:
            Threshold value (per-language or global fallback)
        """
        thresholds = self.config["thresholds"]

        # Normalize per-language thresholds to lowercase for case-insensitive matching
        per_language_thresholds = {
            k.lower(): v for k, v in thresholds.get("per_language", {}).items()
        }
        language_lower = language.lower()

        if language_lower in per_language_thresholds:
            threshold = per_language_thresholds[language_lower]
            logger.debug(f"Using per-language threshold for {language}: {threshold:.4f}")
            return threshold
        else:
            threshold = thresholds["global"]
            logger.debug(f"Using global threshold for {language}: {threshold:.4f}")
            return threshold

    def _determine_confidence(self, probability: float, threshold: float, abstain_margin: float) -> str:
        """
        Determine confidence level based on distance from threshold.

        Args:
            probability: Predicted probability
            threshold: Decision threshold
            abstain_margin: Margin for abstention

        Returns:
            Confidence level: "High", "Medium", "Low", or "Abstained"
        """
        distance = abs(probability - threshold)

        if distance < abstain_margin:
            return "Abstained"
        elif distance < 0.1:
            return "Low"
        elif distance < 0.2:
            return "Medium"
        else:
            return "High"

    def infer(
        self,
        code: str,
        language: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run semantic inference on code snippet.

        Args:
            code: Source code string
            language: Programming language
            metadata: Optional metadata (file path, commit ID, etc.)

        Returns:
            Comprehensive inference result dictionary

        Raises:
            ValueError: If language is not supported or code is empty
        """
        # Validate inputs
        if not code or not code.strip():
            raise ValueError("Code cannot be empty")

        language_normalized = language.lower()
        if language_normalized not in SUPPORTED_LANGUAGES:
            logger.warning(
                f"{Colors.WARNING}⚠️ Language '{language}' not in supported list, "
                f"proceeding with inference...{Colors.ENDC}"
            )

        logger.info(f"\n{Colors.OKCYAN}🔍 Running semantic inference...{Colors.ENDC}")
        logger.info(f"  - Language: {language}")
        logger.info(f"  - Code length: {len(code)} chars")

        # Tokenize
        start_time = datetime.utcnow()
        tokens = self._tokenize_code(code)

        # Get configuration parameters
        weights = self.config["weights"]
        temperatures = self.config["temperatures"]
        abstain_margin = self.config["thresholds"].get("abstain_margin", 0.05)

        # Run inference on both models
        logger.info("  - Running CodeBERT inference...")
        codebert_prob = self._get_model_probability(
            self.codebert_model,
            tokens,
            temperatures["codebert"]
        )

        logger.info("  - Running GraphCodeBERT inference...")
        graphcodebert_prob = self._get_model_probability(
            self.graphcodebert_model,
            tokens,
            temperatures["graphcodebert"]
        )

        # Compute weighted ensemble
        semantic_prob = (
            weights["codebert"] * codebert_prob +
            weights["graphcodebert"] * graphcodebert_prob
        )

        logger.info(f"  - CodeBERT probability: {codebert_prob:.4f}")
        logger.info(f"  - GraphCodeBERT probability: {graphcodebert_prob:.4f}")
        logger.info(f"  - Ensemble probability: {semantic_prob:.4f}")

        # Get threshold
        threshold = self._get_threshold(language_normalized)

        # Check abstention
        abstained = abs(semantic_prob - threshold) < abstain_margin

        # Make prediction
        is_vulnerable = semantic_prob >= threshold

        # Determine confidence
        confidence = self._determine_confidence(semantic_prob, threshold, abstain_margin)

        # Compute inference time
        end_time = datetime.utcnow()
        inference_time = (end_time - start_time).total_seconds()

        # Clean up GPU memory
        if self.device.type == "cuda":
            torch.cuda.empty_cache()

        # Determine canonical status for pipeline automation
        if abstained:
            status = "abstained"
        elif is_vulnerable:
            status = "vulnerable"
        else:
            status = "secure"

        # Build result
        result = {
            "status": status,  # Canonical status for orchestrators
            "language": language,
            "vulnerability_probability": round(semantic_prob, 4),
            "is_vulnerable": is_vulnerable if not abstained else None,
            "confidence_level": confidence,
            "threshold_used": round(threshold, 4),
            "abstained": abstained,
            "model_breakdown": {
                "codebert_prob": round(codebert_prob, 4),
                "graphcodebert_prob": round(graphcodebert_prob, 4),
                "weights": {
                    "codebert": round(weights["codebert"], 4),
                    "graphcodebert": round(weights["graphcodebert"], 4)
                },
                "temperatures": {
                    "codebert": round(temperatures["codebert"], 4),
                    "graphcodebert": round(temperatures["graphcodebert"], 4)
                }
            },
            "metadata": {
                "adapter_sha": self.adapter_checksums,
                "timestamp": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "inference_time_seconds": round(inference_time, 4),
                **(metadata or {})
            }
        }

        # Log result
        logger.info(f"\n{Colors.OKGREEN}✅ Inference completed in {inference_time:.2f}s{Colors.ENDC}")
        logger.info(f"🔹 Vulnerability Probability: {semantic_prob:.4f}")

        if abstained:
            logger.info(f"🔹 Prediction: {Colors.WARNING}ABSTAINED (Low Confidence){Colors.ENDC}")
        elif is_vulnerable:
            logger.info(f"🔹 Prediction: {Colors.FAIL}Vulnerable ({confidence} Confidence){Colors.ENDC}")
        else:
            logger.info(f"🔹 Prediction: {Colors.OKGREEN}Secure ({confidence} Confidence){Colors.ENDC}")

        return result

# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================

def run_inference(
    input_data: Dict[str, Any],
    config_path: str = DEFAULT_CONFIG_PATH,
    engine: Optional[SemanticInferenceEngine] = None
) -> Dict[str, Any]:
    """
    Convenience function to run semantic inference.

    This function can be imported by orchestrators and other modules.

    Args:
        input_data: Input dictionary with keys:
            - code: Source code string (required)
            - language: Programming language (required)
            - metadata: Optional metadata dictionary
        config_path: Path to ensemble configuration file
        engine: Optional pre-initialized engine (for reuse)

    Returns:
        Inference result dictionary

    Example:
        >>> result = run_inference({
        ...     "code": "int main() { ... }",
        ...     "language": "C",
        ...     "metadata": {"file": "main.c"}
        ... })
    """
    # Validate input
    if "code" not in input_data:
        raise ValueError("Input must contain 'code' field")
    if "language" not in input_data:
        raise ValueError("Input must contain 'language' field")

    # Initialize engine if not provided
    if engine is None:
        engine = SemanticInferenceEngine(config_path=config_path)

    # Run inference
    result = engine.infer(
        code=input_data["code"],
        language=input_data["language"],
        metadata=input_data.get("metadata")
    )

    return result

# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Command-line interface for semantic inference."""
    parser = argparse.ArgumentParser(
        description="codeGuardian Semantic Inference - Vulnerability Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a file
  python inference_semantic.py --code path/to/file.c --language C

  # Analyze inline code
  python inference_semantic.py --code "int main() { ... }" --language C

  # Custom config
  python inference_semantic.py --code file.py --language Python --config custom_config.json

  # Use CPU
  python inference_semantic.py --code file.c --language C --device cpu
        """
    )

    parser.add_argument(
        "--code",
        type=str,
        required=True,
        help="Source code string or path to code file"
    )

    parser.add_argument(
        "--language",
        type=str,
        required=True,
        help="Programming language (C, Python, Java, etc.)"
    )

    parser.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to ensemble_config.json (default: {DEFAULT_CONFIG_PATH})"
    )

    parser.add_argument(
        "--codebert-adapter",
        type=str,
        default=None,
        help=f"Path to CodeBERT LoRA adapter (default: {DEFAULT_CODEBERT_ADAPTER})"
    )

    parser.add_argument(
        "--graphcodebert-adapter",
        type=str,
        default=None,
        help=f"Path to GraphCodeBERT LoRA adapter (default: {DEFAULT_GRAPHCODEBERT_ADAPTER})"
    )

    parser.add_argument(
        "--device",
        type=str,
        choices=["cuda", "cpu", "auto"],
        default="auto",
        help="Device to use for inference (default: auto)"
    )

    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (default: print to stdout)"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress messages (only output JSON)"
    )

    args = parser.parse_args()

    # Set logging level
    if args.quiet:
        logger.setLevel(logging.ERROR)

    # Read code
    code_input = args.code
    if os.path.isfile(code_input):
        logger.info(f"📂 Reading code from file: {code_input}")
        with open(code_input, 'r', encoding='utf-8') as f:
            code = f.read()
        source_file = code_input
    else:
        code = code_input
        source_file = "inline"

    # Set device
    device = None if args.device == "auto" else args.device

    try:
        # Initialize engine
        logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}codeGuardian Semantic Inference Engine{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

        engine = SemanticInferenceEngine(
            config_path=args.config,
            codebert_adapter_path=args.codebert_adapter,
            graphcodebert_adapter_path=args.graphcodebert_adapter,
            device=device
        )

        # Run inference
        result = engine.infer(
            code=code,
            language=args.language,
            metadata={"source_file": source_file}
        )

        # Output result
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2)
            logger.info(f"\n💾 Result saved to: {args.output}")
        else:
            print("\n" + "="*80)
            print("INFERENCE RESULT (JSON)")
            print("="*80)
            print(json.dumps(result, indent=2))
            print("="*80)

        # Clean up resources
        engine.dispose()

        # Exit with appropriate status code
        exit_code = EXIT_CODES.get(result["status"], EXIT_CODES["error"])
        sys.exit(exit_code)

    except Exception as e:
        logger.error(f"\n{Colors.FAIL}❌ Inference failed: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(EXIT_CODES["error"])

if __name__ == "__main__":
    main()
