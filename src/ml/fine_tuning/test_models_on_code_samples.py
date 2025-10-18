# type: ignore
"""
Kaggle-Ready Inference Script for CodeBERT/GraphCodeBERT Fine-Tuned Models
===========================================================================

Test trained CodeBERT/GraphCodeBERT PEFT models on source code files.

Features:
- Loads models trained with train_codebert_lora.py / train_graphcodebert_lora.py
- Supports single model or ensemble prediction
- Outputs predictions with vulnerability explanations
- Kaggle-compatible paths

Usage Examples:
  # Single model (CodeBERT)
  python test_models_on_code_samples.py \
      --input-dir ./samples \
      --output outputs/preds.jsonl \
      --model-choice codebert \
      --checkpoint /kaggle/input/.../codebert_final_layer.pt

  # Ensemble both models
  python test_models_on_code_samples.py \
      --input-dir ./samples \
      --output outputs/preds.jsonl \
      --ensemble \
      --codebert-checkpoint /kaggle/input/.../codebert_final_layer.pt \
      --graph-checkpoint /kaggle/input/.../graphcodebert_final_layer.pt

Author: CodeGuardian Team
Date: October 2025
"""

import os
import sys
import re
import json
import argparse
import csv
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from tqdm import tqdm

from transformers import RobertaModel, RobertaConfig, RobertaTokenizerFast
from peft import LoraConfig, get_peft_model, TaskType

# ============================================================================
# MODEL DEFINITION (Must match training scripts)
# ============================================================================


class CodeBERTForVulnerabilityDetection(nn.Module):
    """CodeBERT model with classification head - matches training script"""

    def __init__(self, model_name: str, num_labels: int = 2):
        super().__init__()

        print(f"Loading base model: {model_name}")
        try:
            self.config = RobertaConfig.from_pretrained(model_name)
            self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)
        except Exception as e:
            print(f"⚠️ Error loading model: {e}")
            raise

        # Classification head
        self.classifier = nn.Sequential(
            nn.Dropout(0.1), nn.Linear(self.config.hidden_size, num_labels)
        )

        # Freeze backbone
        for param in self.roberta.parameters():
            param.requires_grad = False

    def forward(self, input_ids=None, attention_mask=None, **kwargs):
        if input_ids is None and "inputs_embeds" in kwargs:
            outputs = self.roberta(
                inputs_embeds=kwargs["inputs_embeds"], attention_mask=attention_mask
            )
        else:
            outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)

        pooled_output = outputs.pooler_output
        logits = self.classifier(pooled_output)
        return logits


class GraphCodeBERTForVulnerabilityDetection(nn.Module):
    """GraphCodeBERT model with classification head - matches training script"""

    def __init__(self, model_name: str, num_labels: int = 2):
        super().__init__()

        print(f"Loading base model: {model_name}")
        try:
            self.config = RobertaConfig.from_pretrained(model_name)
            self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)
        except Exception as e:
            print(f"⚠️ Error loading model: {e}")
            raise

        # Classification head
        self.classifier = nn.Sequential(
            nn.Dropout(0.1), nn.Linear(self.config.hidden_size, num_labels)
        )

        # Freeze backbone
        for param in self.roberta.parameters():
            param.requires_grad = False

    def forward(self, input_ids=None, attention_mask=None, **kwargs):
        if input_ids is None and "inputs_embeds" in kwargs:
            outputs = self.roberta(
                inputs_embeds=kwargs["inputs_embeds"], attention_mask=attention_mask
            )
        else:
            outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)

        pooled_output = outputs.pooler_output
        logits = self.classifier(pooled_output)
        return logits


# ============================================================================
# VULNERABILITY DETECTORS (Heuristic explanations)
# ============================================================================

DETECTORS = {
    "sql_injection": [
        re.compile(r"\bSELECT\b.*\bFROM\b.*\bWHERE\b.*%s", re.I),
        re.compile(r"execute\(|executeQuery\(|exec\(", re.I),
        re.compile(r"LIKE\s*'%.+%'", re.I),
        re.compile(r"\bWHERE\b.*=\s*'.*'"),
    ],
    "command_injection": [
        re.compile(
            r"\bsystem\s*\(|\bexec\(|subprocess\.check_output|Runtime\.getRuntime\(\)\.exec",
            re.I,
        )
    ],
    "unsafe_deserialization": [
        re.compile(
            r"pickle\.loads|ObjectInputStream|pickle\.load|marshal\.loads", re.I
        ),
        re.compile(r"unserialize\(|deserialize\(|yaml\.load", re.I),
    ],
    "hardcoded_credentials": [
        re.compile(
            r"(?i)(password|secret|token|key|jwt|apikey)[\"']?\s*[:=]\s*[\"'][\w\-]{6,}",
            re.I,
        ),
        re.compile(r"\"[a-z0-9]{20,}\"", re.I),
    ],
    "path_traversal": [
        re.compile(r"\.\./|\bFiles\.write\(|open\(|fopen\(|FileOutputStream\(", re.I)
    ],
    "format_string": [
        re.compile(r"printf\s*\(|System\.out\.printf|String\.format|format\(", re.I)
    ],
    "use_after_free": [re.compile(r"\bfree\s*\(|delete\s+.*;", re.I)],
    "integer_overflow": [re.compile(r"atoi\(|strtol\(|unsigned\s+int|uint32_t", re.I)],
    "eval_exec": [re.compile(r"\beval\s*\(|\bexec\s*\(", re.I)],
    "buffer_overflow": [re.compile(r"strcpy\(|strcat\(|gets\(|sprintf\(", re.I)],
}


def detect_vulnerability_tags(code: str) -> List[str]:
    """Run heuristic detectors to generate explanation tags"""
    tags = set()
    for tag, patterns in DETECTORS.items():
        for pattern in patterns:
            try:
                if pattern.search(code):
                    tags.add(tag)
                    break
            except re.error:
                continue
    return sorted(list(tags))


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def sha1_hash(text: str) -> str:
    """Generate SHA1 hash of text"""
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()


def detect_language(filepath: str) -> str:
    """Detect programming language from file extension"""
    ext = Path(filepath).suffix.lower()
    lang_map = {
        ".py": "python",
        ".java": "java",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".c": "c",
        ".js": "javascript",
        ".jsx": "javascript",
        ".go": "go",
        ".php": "php",
        ".rb": "ruby",
        ".cs": "csharp",
        ".ts": "typescript",
    }
    return lang_map.get(ext, "unknown")


def read_file_safe(filepath: str) -> str:
    """Read file with error handling"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        print(f"⚠️ Failed to read {filepath}: {e}")
        return ""


# ============================================================================
# MODEL LOADER
# ============================================================================


def load_model_from_checkpoint(
    checkpoint_path: str, base_model_name: str, model_choice: str, device: torch.device
):
    """
    Load trained model from checkpoint (.pt file)

    Args:
        checkpoint_path: Path to .pt checkpoint file
        base_model_name: Base model name (microsoft/codebert-base or microsoft/graphcodebert-base)
        model_choice: 'codebert' or 'graphcodebert'
        device: torch device

    Returns:
        tokenizer, model
    """
    print(f"\n{'='*70}")
    print(f"LOADING MODEL: {model_choice.upper()}")
    print(f"{'='*70}")
    print(f"Checkpoint: {checkpoint_path}")
    print(f"Base model: {base_model_name}")

    # Load tokenizer
    tokenizer = RobertaTokenizerFast.from_pretrained(base_model_name)

    # Create base model (must match training script architecture)
    if model_choice == "codebert":
        model = CodeBERTForVulnerabilityDetection(base_model_name, num_labels=2)
    elif model_choice == "graphcodebert":
        model = GraphCodeBERTForVulnerabilityDetection(base_model_name, num_labels=2)
    else:
        raise ValueError(f"Invalid model_choice: {model_choice}")

    # Apply LoRA configuration (must match training)
    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=8,
        lora_alpha=16,
        lora_dropout=0.1,
        target_modules=["classifier.1", "roberta.encoder.layer.11.output.dense"],
        bias="none",
        inference_mode=True,  # Important for inference!
    )

    model = get_peft_model(model, lora_config)

    # Load checkpoint weights
    print(f"Loading checkpoint weights...")
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)

    # Extract model state dict
    if "model_state_dict" in checkpoint:
        state_dict = checkpoint["model_state_dict"]
        epoch = checkpoint.get("epoch", "unknown")
        best_f1 = checkpoint.get("best_f1", "unknown")
        print(f"✓ Checkpoint from epoch {epoch}, best F1: {best_f1}")
    else:
        state_dict = checkpoint
        print("✓ Loading raw state dict")

    # Load weights
    model.load_state_dict(state_dict, strict=False)

    model.to(device)
    model.eval()

    print(f"✓ Model loaded successfully on {device}")
    print(f"{'='*70}\n")

    return tokenizer, model


# ============================================================================
# INFERENCE ENGINE
# ============================================================================


class InferenceRunner:
    """Handles model inference with batching and mixed precision"""

    def __init__(
        self,
        device: Optional[torch.device] = None,
        batch_size: int = 32,
        max_length: int = 512,
    ):
        self.device = device or (
            torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")
        )
        self.batch_size = batch_size
        self.max_length = max_length

        # Check for BF16 support
        self.use_bf16 = False
        if torch.cuda.is_available():
            capability = torch.cuda.get_device_capability()
            self.use_bf16 = capability[0] >= 8  # Ampere or newer

        self.dtype = torch.bfloat16 if self.use_bf16 else torch.float16
        print(f"🔧 Inference device: {self.device}")
        print(f"🔧 Precision: {'BFloat16' if self.use_bf16 else 'Float16 (FP16)'}")

    def tokenize_batch(self, tokenizer, codes: List[str]):
        """Tokenize a batch of code samples"""
        encoding = tokenizer(
            codes,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        return encoding["input_ids"], encoding["attention_mask"]

    def predict_single_model(
        self, tokenizer, model, codes: List[str], model_name: str
    ) -> List[float]:
        """Run inference on a single model"""
        input_ids, attention_mask = self.tokenize_batch(tokenizer, codes)
        dataset = TensorDataset(input_ids, attention_mask)
        loader = DataLoader(
            dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=0,
            pin_memory=True if torch.cuda.is_available() else False,
        )

        probabilities = []

        with torch.no_grad():
            for batch in tqdm(loader, desc=f"Inferring {model_name}", leave=False):
                input_ids_b, attention_mask_b = [x.to(self.device) for x in batch]

                # Mixed precision inference
                if torch.cuda.is_available():
                    with torch.cuda.amp.autocast(dtype=self.dtype):
                        logits = model(
                            input_ids=input_ids_b, attention_mask=attention_mask_b
                        )
                else:
                    logits = model(
                        input_ids=input_ids_b, attention_mask=attention_mask_b
                    )

                # Softmax to get probabilities
                probs = torch.softmax(logits, dim=-1)[
                    :, 1
                ]  # Probability of class 1 (vulnerable)
                probabilities.extend(probs.cpu().numpy().tolist())

        return probabilities

    def predict_ensemble(
        self,
        tokenizer1,
        model1,
        tokenizer2,
        model2,
        codes: List[str],
        weights: tuple = (0.5, 0.5),
    ) -> List[float]:
        """Run ensemble prediction with two models"""
        print(
            f"🔀 Ensemble weights: CodeBERT={weights[0]:.2f}, GraphCodeBERT={weights[1]:.2f}"
        )

        probs1 = self.predict_single_model(tokenizer1, model1, codes, "CodeBERT")
        probs2 = self.predict_single_model(tokenizer2, model2, codes, "GraphCodeBERT")

        # Weighted average
        ensemble_probs = [
            weights[0] * p1 + weights[1] * p2 for p1, p2 in zip(probs1, probs2)
        ]

        return ensemble_probs


# ============================================================================
# INPUT/OUTPUT HANDLING
# ============================================================================


def gather_input_samples(
    input_dir: Optional[str], input_file: Optional[str]
) -> List[Dict[str, Any]]:
    """
    Gather code samples from directory or JSONL file

    Returns:
        List of dicts with keys: id, code, language, filename
    """
    samples = []

    # Supported extensions
    code_extensions = {
        ".py",
        ".java",
        ".cpp",
        ".c",
        ".cc",
        ".cxx",
        ".js",
        ".jsx",
        ".go",
        ".php",
        ".rb",
        ".cs",
        ".ts",
        ".txt",
    }

    # Read from directory
    if input_dir:
        input_path = Path(input_dir)
        if not input_path.exists():
            raise FileNotFoundError(f"Input directory not found: {input_dir}")

        files = []
        for ext in code_extensions:
            files.extend(list(input_path.rglob(f"*{ext}")))
        files = sorted(files)

        print(f"📂 Found {len(files)} files in {input_dir}")

        for filepath in files:
            code = read_file_safe(str(filepath))
            if code.strip():  # Skip empty files
                samples.append(
                    {
                        "id": sha1_hash(str(filepath) + code)[:12],
                        "code": code,
                        "language": detect_language(str(filepath)),
                        "filename": str(filepath),
                    }
                )

    # Read from JSONL file
    if input_file:
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        if input_path.suffix.lower() in {".jsonl", ".ndjson"}:
            with input_path.open("r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                        code = (
                            obj.get("code")
                            or obj.get("content")
                            or obj.get("source", "")
                        )
                        if code.strip():
                            samples.append(
                                {
                                    "id": obj.get("id") or f"line_{line_num}",
                                    "code": code,
                                    "language": obj.get("language")
                                    or detect_language(obj.get("filename", "")),
                                    "filename": obj.get("filename"),
                                }
                            )
                    except json.JSONDecodeError as e:
                        print(f"⚠️ Invalid JSON on line {line_num}: {e}")
                        continue
        else:
            # Plain text file - treat as single code sample
            code = read_file_safe(str(input_path))
            if code.strip():
                samples.append(
                    {
                        "id": sha1_hash(str(input_path))[:12],
                        "code": code,
                        "language": detect_language(str(input_path)),
                        "filename": str(input_path),
                    }
                )

    print(f"✓ Loaded {len(samples)} code samples")
    return samples


def save_results(results: List[Dict[str, Any]], output_path: str):
    """Save results to JSONL and CSV"""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save JSONL
    jsonl_path = output_path.with_suffix(".jsonl")
    with jsonl_path.open("w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(f"✓ Saved JSONL: {jsonl_path}")

    # Save CSV
    csv_path = output_path.with_suffix(".csv")
    if results:
        keys = list(results[0].keys())
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        print(f"✓ Saved CSV: {csv_path}")


# ============================================================================
# MAIN
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Test trained CodeBERT/GraphCodeBERT models on code samples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single model inference
  python test_models_on_code_samples.py \\
      --input-dir ./test_samples \\
      --output outputs/predictions.jsonl \\
      --model-choice codebert \\
      --checkpoint /kaggle/input/.../codebert_final_layer.pt

  # Ensemble both models
  python test_models_on_code_samples.py \\
      --input-dir ./test_samples \\
      --output outputs/predictions.jsonl \\
      --ensemble \\
      --codebert-checkpoint /kaggle/input/.../codebert_final_layer.pt \\
      --graph-checkpoint /kaggle/input/.../graphcodebert_final_layer.pt
        """,
    )

    # Input options
    parser.add_argument(
        "--input-dir", type=str, help="Directory with source files (recursive)"
    )
    parser.add_argument("--input-file", type=str, help="Single JSONL or text file")
    parser.add_argument(
        "--output",
        type=str,
        default="outputs/predictions.jsonl",
        help="Output path (will create .jsonl and .csv)",
    )

    # Model options
    parser.add_argument(
        "--model-choice",
        type=str,
        choices=["codebert", "graphcodebert"],
        default="codebert",
        help="Single model to use",
    )
    parser.add_argument(
        "--ensemble",
        action="store_true",
        help="Ensemble both models (requires both checkpoints)",
    )

    # Checkpoint paths (Kaggle-compatible)
    parser.add_argument(
        "--checkpoint", type=str, help="Checkpoint path for single model mode"
    )
    parser.add_argument(
        "--codebert-checkpoint",
        type=str,
        default="/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/codebert/codebert_final_layer.pt",
        help="CodeBERT checkpoint path",
    )
    parser.add_argument(
        "--graph-checkpoint",
        type=str,
        default="/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/graphcodebert/graphcodebert_final_layer.pt",
        help="GraphCodeBERT checkpoint path",
    )

    # Base model names
    parser.add_argument("--base-codebert", type=str, default="microsoft/codebert-base")
    parser.add_argument(
        "--base-graph", type=str, default="microsoft/graphcodebert-base"
    )

    # Inference options
    parser.add_argument(
        "--batch-size", type=int, default=32, help="Inference batch size"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Classification threshold (0.0-1.0)",
    )
    parser.add_argument(
        "--ensemble-weights",
        type=str,
        default="0.5,0.5",
        help="Ensemble weights as 'codebert,graphcodebert'",
    )

    args = parser.parse_args()

    # Validation
    if not args.input_dir and not args.input_file:
        parser.error("Provide --input-dir or --input-file")

    if args.ensemble:
        if not os.path.exists(args.codebert_checkpoint):
            parser.error(f"CodeBERT checkpoint not found: {args.codebert_checkpoint}")
        if not os.path.exists(args.graph_checkpoint):
            parser.error(f"GraphCodeBERT checkpoint not found: {args.graph_checkpoint}")
    else:
        checkpoint = args.checkpoint or (
            args.codebert_checkpoint
            if args.model_choice == "codebert"
            else args.graph_checkpoint
        )
        if not os.path.exists(checkpoint):
            parser.error(f"Checkpoint not found: {checkpoint}")

    print("\n" + "=" * 70)
    print("CODEGUARDIAN - MODEL INFERENCE")
    print("=" * 70)

    # Gather input samples
    samples = gather_input_samples(args.input_dir, args.input_file)
    if not samples:
        print("❌ No valid code samples found!")
        sys.exit(1)

    codes = [s["code"] for s in samples]

    # Initialize inference runner
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    runner = InferenceRunner(device=device, batch_size=args.batch_size)

    # Run inference
    results = []

    if args.ensemble:
        # Load both models
        tok_cb, model_cb = load_model_from_checkpoint(
            args.codebert_checkpoint, args.base_codebert, "codebert", device
        )
        tok_gcb, model_gcb = load_model_from_checkpoint(
            args.graph_checkpoint, args.base_graph, "graphcodebert", device
        )

        # Parse weights
        w1, w2 = [float(x) for x in args.ensemble_weights.split(",")]

        # Run ensemble
        probabilities = runner.predict_ensemble(
            tok_cb, model_cb, tok_gcb, model_gcb, codes, weights=(w1, w2)
        )

        model_name = "ensemble"

    else:
        # Single model
        checkpoint = args.checkpoint or (
            args.codebert_checkpoint
            if args.model_choice == "codebert"
            else args.graph_checkpoint
        )
        base_name = (
            args.base_codebert if args.model_choice == "codebert" else args.base_graph
        )

        tokenizer, model = load_model_from_checkpoint(
            checkpoint, base_name, args.model_choice, device
        )

        probabilities = runner.predict_single_model(
            tokenizer, model, codes, args.model_choice
        )

        model_name = args.model_choice

    # Process results
    print(f"\n{'='*70}")
    print("GENERATING RESULTS")
    print(f"{'='*70}")

    for sample, prob in zip(samples, probabilities):
        pred_label = int(prob >= args.threshold)
        tags = detect_vulnerability_tags(sample["code"])

        results.append(
            {
                "id": sample["id"],
                "filename": sample.get("filename"),
                "language": sample.get("language"),
                "model": model_name,
                "prob_vulnerable": round(float(prob), 4),
                "pred_label": pred_label,
                "pred_class": "vulnerable" if pred_label == 1 else "safe",
                "explanation_tags": tags if tags else [],
            }
        )

    # Save results
    save_results(results, args.output)

    # Summary
    print(f"\n{'='*70}")
    print("INFERENCE SUMMARY")
    print(f"{'='*70}")
    print(f"Total samples: {len(results)}")
    print(f"Predicted vulnerable: {sum(1 for r in results if r['pred_label'] == 1)}")
    print(f"Predicted safe: {sum(1 for r in results if r['pred_label'] == 0)}")
    print(f"Threshold: {args.threshold}")

    # Show top vulnerable samples
    vulnerable = [r for r in results if r["pred_label"] == 1]
    if vulnerable:
        print(f"\nTop 10 vulnerable predictions:")
        vulnerable_sorted = sorted(
            vulnerable, key=lambda x: x["prob_vulnerable"], reverse=True
        )[:10]
        for r in vulnerable_sorted:
            tags_str = (
                ", ".join(r["explanation_tags"]) if r["explanation_tags"] else "no tags"
            )
            print(
                f"  {r['id']} | p={r['prob_vulnerable']:.3f} | {tags_str} | {r['filename']}"
            )

    print(f"\n✅ Done! Results saved to {args.output}")


if __name__ == "__main__":
    main()
