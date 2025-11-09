#!/usr/bin/env python3
"""
codeGuardian Semantic Inference Module
=======================================
Production-grade ensemble inference for vulnerability detection
using LoRA-fine-tuned CodeBERT and GraphCodeBERT models.
"""

from .inference_semantic import run_inference, SemanticInferenceEngine

__all__ = ["run_inference", "SemanticInferenceEngine"]
