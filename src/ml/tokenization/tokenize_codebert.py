#!/usr/bin/env python3
# =============================
# codeGuardian Tokenizer Script
# Author: Urva Gandhi
# Model: CodeBERT
# Purpose: Pure-code tokenization for vulnerability detection (LoRA training)
# =============================

"""
CodeBERT Tokenization Pipeline for Vulnerability Detection
================================================================
Production-ready tokenization script optimized for Kaggle/Colab environments.

Features:
✅ JSONL input from stratified dataset splits
✅ Pure-code architecture (no engineered features)
✅ Memory-efficient streaming with progress bars
✅ Exception-safe parsing with skip tracking
✅ Truncation handling for long code snippets
✅ Final validation and statistics

Input:
/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted/{split}.jsonl

Output:
/kaggle/working/tokenized/codebert/{split}_tokenized.pt
"""

import json
import torch
import os
from typing import Dict, List, Tuple
from tqdm import tqdm
from transformers import AutoTokenizer

# ============================================================================
# CONFIGURATION
# ============================================================================

MODEL_NAME = "microsoft/codebert-base"
INPUT_DIR = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted"
OUTPUT_DIR = f"/kaggle/working/tokenized/{MODEL_NAME.split('/')[-1]}"
MAX_LENGTH = 512
SPLITS = ["train", "val", "test"]

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 80)
print("🚀 GCodeBERT Tokenization Pipeline")
print("=" * 80)
print(f"Model: {MODEL_NAME}")
print(f"Input Directory: {INPUT_DIR}")
print(f"Output Directory: {OUTPUT_DIR}")
print(f"Max Sequence Length: {MAX_LENGTH}")
print("=" * 80)

# ============================================================================
# INITIALIZE TOKENIZER
# ============================================================================

# Set up HuggingFace cache for Kaggle/Colab stability
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["TRANSFORMERS_CACHE"] = "/kaggle/working/.cache"

print("\n📦 Loading tokenizer...")
try:
    # Try fast tokenizer first (Rust-based, faster)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, use_fast=True)
    print(f"✓ Tokenizer loaded successfully (fast tokenizer)")
except Exception:
    # Fallback to slow tokenizer if fast tokenizer fails
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, use_fast=False)
    print(f"✓ Tokenizer loaded successfully (slow tokenizer)")

print(f"  - Vocab size: {len(tokenizer)}")
print(f"  - Special tokens: {tokenizer.special_tokens_map}")

# ============================================================================
# TOKENIZATION FUNCTION
# ============================================================================


def tokenize_file(split: str) -> Tuple[int, int, int]:
    """
    Tokenize a single JSONL file and save as .pt

    Args:
        split: Split name (train/val/test)

    Returns:
        (total_processed, total_skipped, avg_tokens)
    """
    input_path = os.path.join(INPUT_DIR, f"{split}.jsonl")
    output_path = os.path.join(OUTPUT_DIR, f"{split}_tokenized.pt")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    print(f"\n{'='*80}")
    print(f"Processing {split.upper()} split")
    print(f"{'='*80}")
    print(f"Input: {input_path}")
    print(f"Output: {output_path}")

    tokenized_data = {
        "input_ids": [],
        "attention_mask": [],
        "labels": []
    }

    skipped = 0
    total_tokens = 0
    line_number = 0

    # Count total lines for progress bar
    with open(input_path, "r", encoding="utf-8") as f:
        total_lines = sum(1 for _ in f)

    # Process file
    with open(input_path, "r", encoding="utf-8") as f:
        for line in tqdm(f, total=total_lines, desc=f"Tokenizing {split}", ncols=100):
            line_number += 1
            try:
                # Parse JSON
                item = json.loads(line.strip())

                # Extract required fields
                code = item.get("code", "")
                label = item.get("is_vulnerable", None)

                # Validation
                if not isinstance(code, str) or code.strip() == "":
                    skipped += 1
                    continue

                if label is None:
                    skipped += 1
                    continue

                # Convert label to int (handle both int and bool)
                label = int(label)
                if label not in [0, 1]:
                    skipped += 1
                    continue

                # Safeguard: trim extremely long code (rare JSON noise)
                if len(code) > 30000:
                    code = code[:30000]

                # Tokenize
                tokens = tokenizer(
                    code,
                    truncation=True,
                    padding="max_length",
                    max_length=MAX_LENGTH,
                    return_tensors="pt"
                )

                # Store
                tokenized_data["input_ids"].append(tokens["input_ids"].squeeze(0))
                tokenized_data["attention_mask"].append(tokens["attention_mask"].squeeze(0))
                tokenized_data["labels"].append(torch.tensor(label, dtype=torch.long))

                # Track token usage
                actual_tokens = tokens["attention_mask"].sum().item()
                total_tokens += actual_tokens

            except json.JSONDecodeError as e:
                skipped += 1
                continue
            except KeyError as e:
                skipped += 1
                continue
            except Exception as e:
                skipped += 1
                continue

    # Convert lists to tensors (with safeguard for empty datasets)
    if len(tokenized_data["labels"]) == 0:
        print(f"\n⚠️ No valid samples for {split}, skipping save.")
        return 0, skipped, 0

    tokenized_data["input_ids"] = torch.stack(tokenized_data["input_ids"])
    tokenized_data["attention_mask"] = torch.stack(tokenized_data["attention_mask"])
    tokenized_data["labels"] = torch.stack(tokenized_data["labels"])

    # Add metadata for traceability
    tokenized_data["meta"] = {
        "model": MODEL_NAME,
        "split": split,
        "max_length": MAX_LENGTH,
        "samples": len(tokenized_data["labels"]),
        "skipped": skipped
    }

    # Save (use legacy format for older PyTorch compatibility)
    torch.save(tokenized_data, output_path, _use_new_zipfile_serialization=False)

    # Statistics
    total_processed = len(tokenized_data["labels"])
    avg_tokens = total_tokens / total_processed if total_processed > 0 else 0
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)

    # Label distribution
    label_counts = torch.bincount(tokenized_data["labels"])

    print(f"\n✅ {split.upper()} tokenization complete!")
    print(f"  - Total processed: {total_processed:,}")
    print(f"  - Total skipped: {skipped:,}")
    print(f"  - Average tokens: {avg_tokens:.1f}")
    print(f"  - Output size: {file_size_mb:.2f} MB")
    print(f"  - Label distribution:")
    print(f"    • Class 0 (Secure): {label_counts[0]:,} ({100*label_counts[0]/total_processed:.1f}%)")
    print(f"    • Class 1 (Vulnerable): {label_counts[1]:,} ({100*label_counts[1]/total_processed:.1f}%)")
    print(f"  - Shape: input_ids={tokenized_data['input_ids'].shape}")

    return total_processed, skipped, int(avg_tokens)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    print("\n" + "=" * 80)
    print("STARTING TOKENIZATION")
    print("=" * 80)

    statistics = {}

    for split in SPLITS:
        try:
            total, skipped, avg_tokens = tokenize_file(split)
            statistics[split] = {
                "processed": total,
                "skipped": skipped,
                "avg_tokens": avg_tokens
            }
        except Exception as e:
            print(f"\n❌ ERROR processing {split}: {e}")
            raise

    # ========================================================================
    # VALIDATION
    # ========================================================================

    print("\n" + "=" * 80)
    print("VALIDATION CHECK")
    print("=" * 80)

    validation_passed = True

    for split in SPLITS:
        output_path = os.path.join(OUTPUT_DIR, f"{split}_tokenized.pt")

        try:
            # Load saved file
            data = torch.load(output_path, map_location="cpu")

            # Check structure
            required_keys = ["input_ids", "attention_mask", "labels"]
            missing_keys = [k for k in required_keys if k not in data]

            if missing_keys:
                print(f"❌ {split}: Missing keys {missing_keys}")
                validation_passed = False
                continue

            # Check shapes
            n_samples = len(data["labels"])
            input_shape = data["input_ids"].shape
            mask_shape = data["attention_mask"].shape

            if input_shape[0] != n_samples or mask_shape[0] != n_samples:
                print(f"❌ {split}: Shape mismatch")
                validation_passed = False
                continue

            if input_shape[1] != MAX_LENGTH or mask_shape[1] != MAX_LENGTH:
                print(f"❌ {split}: Incorrect sequence length")
                validation_passed = False
                continue

            # Check label values
            unique_labels = torch.unique(data["labels"]).tolist()
            if not all(l in [0, 1] for l in unique_labels):
                print(f"❌ {split}: Invalid label values {unique_labels}")
                validation_passed = False
                continue

            print(f"✓ {split}: Valid")
            print(f"  - Keys: {list(data.keys())}")
            print(f"  - Samples: {n_samples:,}")
            print(f"  - Shape: {input_shape}")
            print(f"  - Labels: {unique_labels}")
            if "meta" in data:
                print(f"  - Metadata: {data['meta']}")

            # Clean up to prevent memory issues on large datasets
            del data

        except Exception as e:
            print(f"❌ {split}: Validation failed - {e}")
            validation_passed = False

    # ========================================================================
    # SUMMARY
    # ========================================================================

    print("\n" + "=" * 80)
    print("TOKENIZATION SUMMARY")
    print("=" * 80)

    total_processed = sum(s["processed"] for s in statistics.values())
    total_skipped = sum(s["skipped"] for s in statistics.values())

    print(f"\n📊 Overall Statistics:")
    print(f"  - Total processed: {total_processed:,}")
    print(f"  - Total skipped: {total_skipped:,}")
    print(f"  - Skip rate: {100*total_skipped/(total_processed+total_skipped):.2f}%")

    print(f"\n📁 Output Files:")
    for split in SPLITS:
        output_path = os.path.join(OUTPUT_DIR, f"{split}_tokenized.pt")
        if os.path.exists(output_path):
            size_mb = os.path.getsize(output_path) / (1024 * 1024)
            print(f"  ✓ {split}_tokenized.pt ({size_mb:.2f} MB)")

    if validation_passed:
        print("\n✅ All validation checks passed!")
        print("🎉 Tokenization pipeline completed successfully!")
    else:
        print("\n⚠️ Some validation checks failed. Please review the output.")

    print("\n💡 Next Steps:")
    print("  1. Run validation notebook to verify row counts")
    print("  2. Use tokenized data for LoRA fine-tuning")
    print("  3. Check train_codebert_lora.py for training pipeline")

    print("=" * 80)

    return 0 if validation_passed else 1


if __name__ == "__main__":
    exit(main())
