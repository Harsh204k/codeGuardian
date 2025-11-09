#!/usr/bin/env python3
# =============================
# codeGuardian Semantic Inference Module - Production Version (Optimized)
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
✅ Dynamic LoRA adapter loading with automatic merged model detection
✅ Configuration-driven ensemble weights & thresholds
✅ Temperature-scaled probability calibration
✅ Per-language threshold optimization
✅ Abstention margin for uncertain predictions
✅ GPU/CPU auto-detection
✅ Memory-efficient inference
✅ Comprehensive JSON output with metadata
✅ CLI interface for standalone execution
✅ Import-friendly for orchestrator integration
✅ Robust error handling with proper exit codes
✅ Optimized for Kaggle GPU runtime
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

# --- Environment Setup (must be before torch/transformers imports) ---
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"        # Silence TensorFlow/cuDNN noise
os.environ["TOKENIZERS_PARALLELISM"] = "false"  # Avoid tokenizer thread spam
os.environ["PYTHONWARNINGS"] = "ignore"         # Suppress UserWarnings

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

# Inference-only mode (saves memory by disabling autograd)
torch.set_grad_enabled(False)

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

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
# DEBUG HELPERS
# ============================================================================

def debug_get_model_probability(
    model,
    tokens: Dict[str, torch.Tensor],
    temperature: float,
    model_tag: str = "model",
    debug_path: str = "/kaggle/working/inference_debug.json"
) -> Tuple[float, list]:
    """
    Debug version of probability extraction with detailed logging.
    Returns (prob, logits_vector). Also writes debug JSON to disk.

    Args:
        model: The model to run inference on
        tokens: Tokenized input
        temperature: Temperature scaling factor
        model_tag: Identifier for this model (e.g., "codebert")
        debug_path: Path to save debug output

    Returns:
        Tuple of (vulnerability_probability, raw_logits_list)
    """
    model.eval()
    with torch.inference_mode():
        outputs = model(**tokens)
        logits = outputs.logits[0].cpu().float()  # tensor([logit0, logit1])

        # Safe temperature handling
        if temperature <= 0:
            logger.warning(f"{Colors.WARNING}⚠️ Invalid temperature {temperature}, using 1.0{Colors.ENDC}")
            temperature = 1.0

        scaled = logits / float(temperature)
        probs = torch.softmax(scaled, dim=-1).cpu().numpy().tolist()

    debug = {
        "model_tag": model_tag,
        "logits": logits.tolist(),
        "scaled_logits": scaled.tolist(),
        "probs": probs,
        "temperature": temperature,
        "device": str(next(model.parameters()).device) if any(True for _ in model.parameters()) else "unknown",
        "dtype": str(logits.dtype),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    # Write per-model debug file (append)
    try:
        if not os.path.exists(debug_path):
            with open(debug_path, "w") as f:
                json.dump({"runs": [debug]}, f, indent=2)
        else:
            with open(debug_path, "r+") as f:
                obj = json.load(f)
                if "runs" not in obj:
                    obj["runs"] = []
                obj["runs"].append(debug)
                f.seek(0)
                f.truncate()
                json.dump(obj, f, indent=2)
        logger.debug(f"Debug info written to {debug_path}")
    except Exception as e:
        logger.warning(f"{Colors.WARNING}Could not write debug file: {e}{Colors.ENDC}")

    return float(probs[1]), logits.tolist()


def inspect_classifier(model, tag: str) -> Dict[str, Any]:
    """
    Inspect classifier head parameters to detect initialization issues.

    Args:
        model: Model to inspect
        tag: Identifier tag for logging

    Returns:
        Dictionary with classifier parameter statistics
    """
    info = {
        "model_tag": tag,
        "has_classifier": False,
        "classifier_params": {},
        "config": {}
    }

    # Check for classifier attribute
    if hasattr(model, "classifier"):
        info["has_classifier"] = True
        for name, p in model.classifier.named_parameters():
            info["classifier_params"][name] = {
                "shape": list(p.shape),
                "mean": float(p.data.mean().cpu().numpy()),
                "std": float(p.data.std().cpu().numpy()),
                "min": float(p.data.min().cpu().numpy()),
                "max": float(p.data.max().cpu().numpy()),
                "abs_max": float(p.data.abs().max().cpu().numpy())
            }
    else:
        info["note"] = "classifier attr not present (may be PEFT wrapper)"
        # Try to find classifier in wrapped model
        if hasattr(model, "base_model") and hasattr(model.base_model, "classifier"):
            info["has_classifier"] = True
            info["note"] = "classifier found in base_model (PEFT wrapper)"
            for name, p in model.base_model.classifier.named_parameters():
                info["classifier_params"][name] = {
                    "shape": list(p.shape),
                    "mean": float(p.data.mean().cpu().numpy()),
                    "std": float(p.data.std().cpu().numpy()),
                    "min": float(p.data.min().cpu().numpy()),
                    "max": float(p.data.max().cpu().numpy()),
                    "abs_max": float(p.data.abs().max().cpu().numpy())
                }

    # Check config for label mapping
    if hasattr(model, "config"):
        config = model.config
        if hasattr(config, "id2label"):
            info["config"]["id2label"] = config.id2label
        if hasattr(config, "label2id"):
            info["config"]["label2id"] = config.label2id
        if hasattr(config, "num_labels"):
            info["config"]["num_labels"] = config.num_labels

    logger.info(f"\n{Colors.OKCYAN}[Classifier Inspection: {tag}]{Colors.ENDC}")
    logger.info(json.dumps(info, indent=2))

    return info

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
        logger.error(f"{Colors.FAIL}❌ Configuration file not found{Colors.ENDC}")
        logger.error(f"{Colors.FAIL}   Path: {config_path}{Colors.ENDC}")
        logger.error(f"{Colors.FAIL}   Current working directory: {os.getcwd()}{Colors.ENDC}")
        raise FileNotFoundError(f"Config file not found: {config_path}")

    try:
        logger.info(f"📋 Loading configuration from: {config_path}")
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # Handle both old and new config schema formats
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
        if not (0.99 <= weight_sum <= 1.01):
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

        # Set device with CUDA accessibility check
        if device is None:
            if torch.cuda.is_available():
                try:
                    # Test CUDA accessibility
                    torch.zeros(1).to("cuda")
                    self.device = torch.device("cuda")
                except Exception as e:
                    logger.warning(f"{Colors.WARNING}⚠️ CUDA available but not accessible: {e}{Colors.ENDC}")
                    logger.warning(f"{Colors.WARNING}⚠️ Falling back to CPU{Colors.ENDC}")
                    self.device = torch.device("cpu")
            else:
                self.device = torch.device("cpu")
        else:
            self.device = torch.device(device)

        logger.info(f"{Colors.OKBLUE}🖥️  Using device: {self.device}{Colors.ENDC}")

        # Determine dtype per-model
        self.model_dtype = torch.float16 if self.device.type == "cuda" else torch.float32
        logger.info(f"{Colors.OKBLUE}🔧 Model dtype: {self.model_dtype}{Colors.ENDC}")

        # Set adapter paths
        self.codebert_adapter_path = codebert_adapter_path or DEFAULT_CODEBERT_ADAPTER
        self.graphcodebert_adapter_path = graphcodebert_adapter_path or DEFAULT_GRAPHCODEBERT_ADAPTER

        # Initialize models and tokenizers
        self.codebert_tokenizer = None
        self.graphcodebert_tokenizer = None
        self.codebert_model = None
        self.graphcodebert_model = None
        self.adapter_checksums = {}
        self.model_load_types = {}
        self.classifier_info = {}

        # Debug mode (enabled via environment variable)
        self.debug_mode = os.environ.get("CODEGUARDIAN_DEBUG", "false").lower() == "true"
        if self.debug_mode:
            logger.info(f"{Colors.WARNING}⚠️ Debug mode enabled - detailed logs will be saved{Colors.ENDC}")

        # Load models
        self._load_models()

    def _compute_adapter_checksum(self, adapter_path: str) -> str:
        """
        Compute MD5 checksum of adapter weights for traceability.

        Args:
            adapter_path: Path to adapter directory

        Returns:
            MD5 checksum string
        """
        # Try multiple adapter file formats
        adapter_file = None
        for fname in ["adapter_model.safetensors", "adapter_model.bin", "pytorch_model.bin", "model.safetensors"]:
            candidate = os.path.join(adapter_path, fname)
            if os.path.exists(candidate):
                adapter_file = candidate
                break

        if adapter_file is None:
            logger.warning(f"{Colors.WARNING}⚠️ No adapter weights file found in {adapter_path}{Colors.ENDC}")
            return "unknown"

        md5_hash = hashlib.md5()
        with open(adapter_file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)

        return md5_hash.hexdigest()

    def _load_model_with_fallback(self, base_model_id: str, adapter_path: str, model_name: str):
        """
        Load model with fallback strategy: merged checkpoint first, then PEFT adapter.

        Args:
            base_model_id: Base model HuggingFace ID
            adapter_path: Path to adapter directory
            model_name: Name for logging (e.g., "CodeBERT")

        Returns:
            Tuple of (model, load_type) where load_type is "merged" or "peft"
        """
        # Strategy 1: Check for merged checkpoint in common locations
        merged_candidates = [
            os.path.join(adapter_path, f"{model_name.lower()}_merged"),
            os.path.join(adapter_path, "merged"),
            os.path.join(os.path.dirname(adapter_path), f"{model_name.lower()}_merged")
        ]

        for merged_path in merged_candidates:
            config_path = os.path.join(merged_path, "config.json")
            if os.path.exists(config_path):
                logger.info(f"  📦 Found merged checkpoint at: {merged_path}")
                try:
                    # Clear CUDA cache before loading
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()

                    # Load with explicit error handling
                    model = AutoModelForSequenceClassification.from_pretrained(
                        merged_path,
                        torch_dtype=self.model_dtype,
                        num_labels=2,
                        local_files_only=True,
                        trust_remote_code=False
                    )
                    model = model.to(self.device)
                    model.eval()

                    # Verify classifier head exists
                    if hasattr(model, 'classifier'):
                        logger.info(f"  {Colors.OKGREEN}✓ Merged model loaded with trained classifier{Colors.ENDC}")
                        return model, "merged"
                    else:
                        logger.warning(f"  {Colors.WARNING}⚠️ Merged model missing classifier, trying next...{Colors.ENDC}")
                        del model

                except Exception as e:
                    logger.warning(f"  {Colors.WARNING}⚠️ Merged load failed: {str(e)[:80]}...{Colors.ENDC}")
                    continue

        # Strategy 2: Load PEFT adapter
        logger.info(f"  📦 Loading PEFT adapter from: {adapter_path}")

        if not os.path.exists(adapter_path):
            raise FileNotFoundError(f"{model_name} adapter directory not found: {adapter_path}")

        # Check for adapter files
        adapter_files = ["adapter_model.safetensors", "adapter_model.bin"]
        has_adapter = any(os.path.exists(os.path.join(adapter_path, f)) for f in adapter_files)

        if not has_adapter:
            raise FileNotFoundError(
                f"{model_name} adapter not found. Expected adapter_model.safetensors or adapter_model.bin in {adapter_path}"
            )

        try:
            # Clear CUDA cache before loading
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

            # Load base model with suppressed warnings
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message=".*were not initialized.*")
                warnings.filterwarnings("ignore", message=".*not found in model.*")

                base_model = AutoModelForSequenceClassification.from_pretrained(
                    base_model_id,
                    num_labels=2,
                    torch_dtype=self.model_dtype,
                    local_files_only=False
                )

            # Load PEFT adapter (will override classifier if saved with modules_to_save)
            model = PeftModel.from_pretrained(
                base_model,
                adapter_path,
                is_trainable=False
            )

            model = model.to(self.device)
            model.eval()

            # Verify adapter loaded
            if hasattr(model, 'peft_config'):
                logger.info(f"  {Colors.OKGREEN}✓ PEFT adapter loaded successfully{Colors.ENDC}")
            else:
                logger.warning(f"  {Colors.WARNING}⚠️ PEFT config not found, model may be incomplete{Colors.ENDC}")

            return model, "peft"

        except Exception as e:
            logger.error(f"  {Colors.FAIL}❌ PEFT adapter load failed: {e}{Colors.ENDC}")
            raise RuntimeError(f"Failed to load {model_name} model from {adapter_path}: {e}")

    def _load_models(self):
        """Load tokenizers and both LoRA-adapted models with robust error handling."""
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}Loading Models & Tokenizers{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")

        # Load separate tokenizers for each model
        logger.info("📦 Loading CodeBERT tokenizer...")
        try:
            self.codebert_tokenizer = AutoTokenizer.from_pretrained(
                CODEBERT_BASE,
                use_fast=True,
                local_files_only=False
            )
            logger.info(f"{Colors.OKGREEN}✓ CodeBERT tokenizer loaded (vocab size: {len(self.codebert_tokenizer)}){Colors.ENDC}")
        except Exception as e:
            logger.error(f"{Colors.FAIL}❌ Failed to load CodeBERT tokenizer: {e}{Colors.ENDC}")
            raise RuntimeError(f"CodeBERT tokenizer initialization failed: {e}")

        logger.info("📦 Loading GraphCodeBERT tokenizer...")
        try:
            self.graphcodebert_tokenizer = AutoTokenizer.from_pretrained(
                GRAPHCODEBERT_BASE,
                use_fast=True,
                local_files_only=False
            )
            logger.info(f"{Colors.OKGREEN}✓ GraphCodeBERT tokenizer loaded (vocab size: {len(self.graphcodebert_tokenizer)}){Colors.ENDC}")
        except Exception as e:
            logger.error(f"{Colors.FAIL}❌ Failed to load GraphCodeBERT tokenizer: {e}{Colors.ENDC}")
            raise RuntimeError(f"GraphCodeBERT tokenizer initialization failed: {e}")

        # Load CodeBERT model
        logger.info("\n🔹 Loading CodeBERT model...")
        try:
            self.codebert_model, load_type = self._load_model_with_fallback(
                CODEBERT_BASE,
                self.codebert_adapter_path,
                "CodeBERT"
            )
            self.model_load_types["codebert"] = load_type
            self.adapter_checksums["codebert"] = self._compute_adapter_checksum(self.codebert_adapter_path)

            logger.info(f"{Colors.OKGREEN}✓ CodeBERT loaded successfully ({load_type} mode){Colors.ENDC}")
            logger.info(f"  - Adapter path: {self.codebert_adapter_path}")
            logger.info(f"  - Checksum: {self.adapter_checksums['codebert'][:16]}...")

        except Exception as e:
            logger.error(f"{Colors.FAIL}❌ Failed to load CodeBERT model: {e}{Colors.ENDC}")
            raise RuntimeError(f"CodeBERT model initialization failed: {e}")

        # Load GraphCodeBERT model
        logger.info("\n🔹 Loading GraphCodeBERT model...")
        try:
            self.graphcodebert_model, load_type = self._load_model_with_fallback(
                GRAPHCODEBERT_BASE,
                self.graphcodebert_adapter_path,
                "GraphCodeBERT"
            )
            self.model_load_types["graphcodebert"] = load_type
            self.adapter_checksums["graphcodebert"] = self._compute_adapter_checksum(self.graphcodebert_adapter_path)

            logger.info(f"{Colors.OKGREEN}✓ GraphCodeBERT loaded successfully ({load_type} mode){Colors.ENDC}")
            logger.info(f"  - Adapter path: {self.graphcodebert_adapter_path}")
            logger.info(f"  - Checksum: {self.adapter_checksums['graphcodebert'][:16]}...")

        except Exception as e:
            logger.error(f"{Colors.FAIL}❌ Failed to load GraphCodeBERT model: {e}{Colors.ENDC}")
            raise RuntimeError(f"GraphCodeBERT model initialization failed: {e}")

        logger.info(f"\n{Colors.OKGREEN}✅ All models and tokenizers loaded successfully{Colors.ENDC}")

        # Inspect classifier heads for debugging
        logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}Classifier Inspection{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")

        self.classifier_info = {
            "codebert": inspect_classifier(self.codebert_model, "CodeBERT"),
            "graphcodebert": inspect_classifier(self.graphcodebert_model, "GraphCodeBERT")
        }

        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

    def dispose(self):
        """Clean up models and release GPU memory."""
        logger.info(f"{Colors.OKCYAN}🧹 Disposing inference engine...{Colors.ENDC}")

        if self.codebert_model is not None:
            del self.codebert_model
            self.codebert_model = None

        if self.graphcodebert_model is not None:
            del self.graphcodebert_model
            self.graphcodebert_model = None

        if self.codebert_tokenizer is not None:
            del self.codebert_tokenizer
            self.codebert_tokenizer = None

        if self.graphcodebert_tokenizer is not None:
            del self.graphcodebert_tokenizer
            self.graphcodebert_tokenizer = None

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()

        logger.info(f"{Colors.OKGREEN}✓ Engine disposed and memory released{Colors.ENDC}")

    def _tokenize_code_for_model(self, code: str, model_type: str) -> Dict[str, torch.Tensor]:
        """Tokenize code snippet using the appropriate tokenizer."""
        if len(code) > 30000:
            logger.warning(f"{Colors.WARNING}⚠️ Code length exceeds 30000 chars, truncating...{Colors.ENDC}")
            code = code[:30000]

        tokenizer = self.codebert_tokenizer if model_type == "codebert" else self.graphcodebert_tokenizer

        tokens = tokenizer(
            code,
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
            return_tensors="pt"
        )

        return {k: v.to(self.device) for k, v in tokens.items()}

    def _get_model_probability(
        self,
        model,
        tokens: Dict[str, torch.Tensor],
        temperature: float,
        model_tag: str = "model",
        debug_mode: bool = False
    ) -> Tuple[float, Optional[list]]:
        """
        Get calibrated probability from a single model using temperature scaling.

        Args:
            model: Model to run inference on
            tokens: Tokenized input
            temperature: Temperature scaling factor
            model_tag: Identifier for debug logging
            debug_mode: If True, return logits and write debug info

        Returns:
            Tuple of (probability, logits) if debug_mode else (probability, None)
        """
        if debug_mode:
            prob, logits = debug_get_model_probability(
                model, tokens, temperature, model_tag
            )
            return prob, logits

        with torch.inference_mode():  # Faster and safer than no_grad for pure inference
            outputs = model(**tokens)
            logits = outputs.logits[0]

            # Safe temperature handling
            if temperature <= 0:
                logger.warning(f"{Colors.WARNING}⚠️ Invalid temperature {temperature}, using 1.0{Colors.ENDC}")
                temperature = 1.0

            # Apply temperature scaling then softmax
            scaled_logits = logits / temperature
            probs = torch.softmax(scaled_logits, dim=-1)

            return float(probs[1]), None

    def _get_threshold(self, language: str) -> float:
        """Get appropriate threshold for the given language."""
        thresholds = self.config["thresholds"]

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
        """Determine confidence level based on distance from threshold."""
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
            metadata: Optional metadata

        Returns:
            Comprehensive inference result dictionary

        Raises:
            ValueError: If language is not supported or code is empty
        """
        if not code or not code.strip():
            raise ValueError("Code cannot be empty")

        language_normalized = language.lower()
        if language_normalized not in SUPPORTED_LANGUAGES:
            logger.warning(
                f"{Colors.WARNING}⚠️ Language '{language}' not in supported list, "
                f"proceeding anyway...{Colors.ENDC}"
            )

        start_time = datetime.utcnow()

        logger.info(f"\n{Colors.OKCYAN}{'='*60}{Colors.ENDC}")
        logger.info(f"{Colors.OKCYAN}🔍 Running semantic inference{Colors.ENDC}")
        logger.info(f"{Colors.OKCYAN}   Started: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}{Colors.ENDC}")
        logger.info(f"{Colors.OKCYAN}{'='*60}{Colors.ENDC}")
        logger.info(f"  - Language: {language}")
        logger.info(f"  - Code length: {len(code)} chars")

        # Tokenize for each model
        logger.info("  - Tokenizing for CodeBERT...")
        codebert_tokens = self._tokenize_code_for_model(code, "codebert")

        logger.info("  - Tokenizing for GraphCodeBERT...")
        graphcodebert_tokens = self._tokenize_code_for_model(code, "graphcodebert")

        # Get configuration parameters
        weights = self.config["weights"]
        temperatures = self.config["temperatures"]
        abstain_margin = self.config["thresholds"].get("abstain_margin", 0.05)

        # Run inference with optional debug mode
        logger.info("  - Running CodeBERT inference...")
        codebert_prob, codebert_logits = self._get_model_probability(
            self.codebert_model,
            codebert_tokens,
            temperatures["codebert"],
            model_tag="codebert",
            debug_mode=self.debug_mode
        )

        logger.info("  - Running GraphCodeBERT inference...")
        graphcodebert_prob, graphcodebert_logits = self._get_model_probability(
            self.graphcodebert_model,
            graphcodebert_tokens,
            temperatures["graphcodebert"],
            model_tag="graphcodebert",
            debug_mode=self.debug_mode
        )

        # Compute weighted ensemble
        semantic_prob = (
            weights["codebert"] * codebert_prob +
            weights["graphcodebert"] * graphcodebert_prob
        )

        logger.info(f"  - CodeBERT probability: {codebert_prob:.4f}")
        if self.debug_mode and codebert_logits:
            logger.info(f"    Logits: {codebert_logits}")
        logger.info(f"  - GraphCodeBERT probability: {graphcodebert_prob:.4f}")
        if self.debug_mode and graphcodebert_logits:
            logger.info(f"    Logits: {graphcodebert_logits}")
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

        # Determine canonical status
        if abstained:
            status = "abstained"
        elif is_vulnerable:
            status = "vulnerable"
        else:
            status = "secure"

        # Build result
        result = {
            "status": status,
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
                "model_versions": {
                    "codebert": CODEBERT_BASE,
                    "graphcodebert": GRAPHCODEBERT_BASE
                },
                "model_load_types": self.model_load_types,
                "adapter_sha": self.adapter_checksums,
                "device": str(self.device),
                "dtype": str(self.model_dtype),
                "timestamp": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "inference_time_seconds": round(inference_time, 4),
                "debug_mode": self.debug_mode,
                **(metadata or {})
            }
        }

        # Add debug info if enabled
        if self.debug_mode:
            result["debug_info"] = {
                "raw_logits": {
                    "codebert": codebert_logits,
                    "graphcodebert": graphcodebert_logits
                },
                "classifier_inspection": self.classifier_info
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

    Args:
        input_data: Input dictionary with code, language, metadata
        config_path: Path to ensemble configuration file
        engine: Optional pre-initialized engine

    Returns:
        Inference result dictionary
    """
    if "code" not in input_data:
        raise ValueError("Input must contain 'code' field")
    if "language" not in input_data:
        raise ValueError("Input must contain 'language' field")

    if engine is None:
        engine = SemanticInferenceEngine(config_path=config_path)

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
  python inference_semantic.py --code path/to/file.c --language C
  python inference_semantic.py --code "int main() { ... }" --language C
  python inference_semantic.py --code file.py --language Python --config custom_config.json
        """
    )

    parser.add_argument("--code", type=str, required=True, help="Source code string or path to code file")
    parser.add_argument("--language", type=str, required=True, help="Programming language")
    parser.add_argument("--config", type=str, default=DEFAULT_CONFIG_PATH, help="Path to ensemble_config.json")
    parser.add_argument("--codebert-adapter", type=str, default=None, help="Path to CodeBERT LoRA adapter")
    parser.add_argument("--graphcodebert-adapter", type=str, default=None, help="Path to GraphCodeBERT LoRA adapter")
    parser.add_argument("--device", type=str, choices=["cuda", "cpu", "auto"], default="auto", help="Device to use")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file path")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress messages")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug mode (logits, classifier inspection)")
    parser.add_argument("--success-on-abstain", action="store_true", help="Exit with code 0 when abstained")

    args = parser.parse_args()

    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose:
        logger.setLevel(logging.DEBUG)

    # Set debug mode via environment variable
    if args.debug:
        os.environ["CODEGUARDIAN_DEBUG"] = "true"
        logger.info(f"{Colors.WARNING}🐛 Debug mode enabled - detailed diagnostics will be logged{Colors.ENDC}")

    # Read code
    code_input = args.code
    if os.path.isfile(code_input):
        logger.info(f"📂 Reading code from file: {code_input}")
        with open(code_input, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        source_file = code_input
    else:
        code = code_input
        source_file = "inline"

    device = None if args.device == "auto" else args.device

    engine = None
    try:
        logger.info(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}codeGuardian Semantic Inference Engine{Colors.ENDC}")
        logger.info(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

        engine = SemanticInferenceEngine(
            config_path=args.config,
            codebert_adapter_path=args.codebert_adapter,
            graphcodebert_adapter_path=args.graphcodebert_adapter,
            device=device
        )

        result = engine.infer(
            code=code,
            language=args.language,
            metadata={"source_file": source_file}
        )

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

        exit_code = EXIT_CODES.get(result["status"], EXIT_CODES["error"])

        if args.success_on_abstain and result["status"] == "abstained":
            exit_code = 0
            logger.info(f"{Colors.OKCYAN}ℹ️  Treating abstained prediction as success (--success-on-abstain){Colors.ENDC}")

        # Clean up
        if engine is not None:
            engine.dispose()

        logger.info(f"\n{Colors.OKBLUE}🚪 Exiting with code {exit_code} ({result['status']}){Colors.ENDC}")
        os._exit(exit_code)  # Use os._exit() to avoid IPython traceback recursion

    except KeyboardInterrupt:
        logger.info(f"\n{Colors.WARNING}⚠️ Interrupted by user{Colors.ENDC}")
        if engine is not None:
            try:
                engine.dispose()
            except:
                pass
        os._exit(EXIT_CODES["error"])  # Use os._exit() to avoid IPython traceback recursion

    except Exception as e:
        logger.error(f"\n{Colors.FAIL}❌ Inference failed: {e}{Colors.ENDC}")
        logger.error(f"{Colors.FAIL}Error type: {type(e).__name__}{Colors.ENDC}")

        import traceback
        logger.error(f"{Colors.FAIL}Traceback:{Colors.ENDC}")
        traceback.print_exc()

        if engine is not None:
            try:
                engine.dispose()
            except:
                pass

        os._exit(EXIT_CODES["error"])  # Use os._exit() to avoid IPython traceback recursion

if __name__ == "__main__":
    main()
