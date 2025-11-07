#!/usr/bin/env python3
# =============================
# codeGuardian Tokenizer Script - FINAL VERSION
# Author: Urva Gandhi
# Model: CodeBERT / GraphCodeBERT
# Purpose: Pure-code tokenization for vulnerability detection (LoRA training)
# Standard: CodeGuardian Tokenization Standard v1.0
# =============================

"""
CodeGuardian Tokenization Pipeline - Production Standard v1.0
================================================================
Production-ready tokenization script optimized for Kaggle/Colab environments.
Fully compatible with multi-model fine-tuning (CodeBERT, GraphCodeBERT, CodeT5+).

Features:
✅ JSONL input from stratified dataset splits
✅ Pure-code architecture (no engineered features)
✅ Language-aware tokenization with language_ids
✅ Memory-efficient streaming with progress bars
✅ Exception-safe parsing with skip tracking
✅ Truncation handling for long code snippets
✅ Comprehensive metadata tracking (CWE/CVE awareness)
✅ Final validation and statistics
✅ Per-language distribution reporting

Input Schema:
{
  "id": str,
  "language": str,
  "dataset": str,
  "code": str,
  "is_vulnerable": bool/int,
  "cwe_id": str (optional),
  "cve_id": str (optional),
  ...
}

Output Structure:
{
  "input_ids": Tensor[N, 512],
  "attention_mask": Tensor[N, 512],
  "labels": Tensor[N],
  "language_ids": Tensor[N],
  "language_vocab": List[str],
  "meta": {
    "model": str,
    "model_slug": str,
    "split": str,
    "max_length": int,
    "samples": int,
    "skipped": int,
    "languages": List[str],
    "num_languages": int,
    "has_cwe_field": bool,
    "timestamp": str
  }
}

Input:
/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted/{split}.jsonl

Output:
/kaggle/working/tokenized/{model_slug}/{split}_tokenized_{model_slug}.pt
"""

import json
import torch
import os
import gc
from datetime import datetime
from typing import Dict, List, Tuple
from collections import Counter
from tqdm import tqdm
from transformers import AutoTokenizer

# ============================================================================
# CONFIGURATION
# ============================================================================

# Set random seed for reproducibility
torch.manual_seed(42)
print(f"🎲 Random seed set to: 42")

# CHANGE THIS TO SWITCH MODELS:
# - "microsoft/codebert-base"
# - "microsoft/graphcodebert-base"
MODEL_NAME = "microsoft/codebert-base"

INPUT_DIR = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted"
OUTPUT_DIR = f"/kaggle/working/tokenized/{MODEL_NAME.split('/')[-1]}"
MAX_LENGTH = 512
SPLITS = ["train", "val", "test"]

# Extract model slug for file naming
MODEL_SLUG = MODEL_NAME.split('/')[-1]

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 80)
print("🚀 CodeGuardian Tokenization Pipeline v1.0")
print("=" * 80)
print(f"Model: {MODEL_NAME}")
print(f"Model Slug: {MODEL_SLUG}")
print(f"Input Directory: {INPUT_DIR}")
print(f"Output Directory: {OUTPUT_DIR}")
print(f"Max Sequence Length: {MAX_LENGTH}")
print(f"Standard: CodeGuardian Tokenization Standard v1.0")
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


def tokenize_file(split: str) -> Tuple[int, int, int, Dict]:
    """
    Tokenize a single JSONL file and save as .pt with full metadata

    Args:
        split: Split name (train/val/test)

    Returns:
        (total_processed, total_skipped, avg_tokens, stats_dict)
    """
    input_path = os.path.join(INPUT_DIR, f"{split}.jsonl")
    output_path = os.path.join(OUTPUT_DIR, f"{split}_tokenized_{MODEL_SLUG}.pt")

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
        "labels": [],
        "language_ids": []
    }

    skipped = 0
    total_tokens = 0
    line_number = 0

    # Track language vocabulary dynamically
    language_set = set()
    language_counter = Counter()

    # Track CWE/CVE presence
    has_cwe_field = False
    has_cve_field = False

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
                language = item.get("language", "unknown")

                # Track optional field presence
                if "cwe_id" in item and item["cwe_id"]:
                    has_cwe_field = True
                if "cve_id" in item and item["cve_id"]:
                    has_cve_field = True

                # Validation: code
                if not isinstance(code, str) or code.strip() == "":
                    skipped += 1
                    continue

                # Validation: label
                if label is None:
                    skipped += 1
                    continue

                # Convert label to int (handle both int and bool)
                label = int(label)
                if label not in [0, 1]:
                    skipped += 1
                    continue

                # Normalize language (lowercase for consistent mapping)
                language = str(language).strip().lower()
                if language == "" or language == "unknown":
                    language = "unknown"

                language_set.add(language)
                language_counter[language] += 1                # Safeguard: trim extremely long code (rare JSON noise)
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

                # Placeholder for language_id (will be mapped after vocabulary is built)
                tokenized_data["language_ids"].append(language)

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
        return 0, skipped, 0, {}

    # Build language vocabulary (sorted for consistency)
    language_vocab = sorted(list(language_set))
    language_to_id = {lang: idx for idx, lang in enumerate(language_vocab)}

    # Convert language strings to IDs
    language_ids_list = [language_to_id[lang] for lang in tokenized_data["language_ids"]]

    # Convert to tensors (with explicit dtypes for consistency)
    tokenized_data["input_ids"] = torch.stack(tokenized_data["input_ids"])
    tokenized_data["attention_mask"] = torch.stack(tokenized_data["attention_mask"])
    tokenized_data["labels"] = torch.stack(tokenized_data["labels"]).to(dtype=torch.int64)
    tokenized_data["language_ids"] = torch.tensor(language_ids_list, dtype=torch.int64)
    tokenized_data["language_vocab"] = language_vocab

    # Add comprehensive metadata for traceability
    tokenized_data["meta"] = {
        "model": MODEL_NAME,
        "model_slug": MODEL_SLUG,
        "split": split,
        "max_length": MAX_LENGTH,
        "samples": len(tokenized_data["labels"]),
        "skipped": skipped,
        "languages": language_vocab,
        "num_languages": len(language_vocab),
        "has_cwe_field": has_cwe_field,
        "has_cve_field": has_cve_field,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    # Save (use legacy format for older PyTorch compatibility)
    try:
        torch.save(tokenized_data, output_path, _use_new_zipfile_serialization=False)
        print(f"  💾 Saved to: {output_path}")
    except Exception as e:
        print(f"  ❌ ERROR saving file: {e}")
        raise

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
    print(f"  - Language distribution:")
    for lang in sorted(language_counter.keys()):
        count = language_counter[lang]
        pct = 100 * count / total_processed
        print(f"    • {lang.capitalize()}: {count:,} ({pct:.1f}%)")
    print(f"  - Shapes:")
    print(f"    • input_ids: {tokenized_data['input_ids'].shape}")
    print(f"    • attention_mask: {tokenized_data['attention_mask'].shape}")
    print(f"    • labels: {tokenized_data['labels'].shape}")
    print(f"    • language_ids: {tokenized_data['language_ids'].shape}")
    print(f"  - Metadata fields: {list(tokenized_data['meta'].keys())}")

    # Return statistics for summary
    stats = {
        "processed": total_processed,
        "skipped": skipped,
        "avg_tokens": int(avg_tokens),
        "languages": dict(language_counter),
        "label_dist": {
            "secure": int(label_counts[0]),
            "vulnerable": int(label_counts[1])
        }
    }

    return total_processed, skipped, int(avg_tokens), stats


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    print("\n" + "=" * 80)
    print("STARTING TOKENIZATION")
    print("=" * 80)

    statistics = {}
    all_statistics = {}

    for split in SPLITS:
        try:
            total, skipped, avg_tokens, stats = tokenize_file(split)
            statistics[split] = {
                "processed": total,
                "skipped": skipped,
                "avg_tokens": avg_tokens
            }
            all_statistics[split] = stats

            # Memory cleanup for large datasets
            gc.collect()

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
        output_path = os.path.join(OUTPUT_DIR, f"{split}_tokenized_{MODEL_SLUG}.pt")

        try:
            # Load saved file
            data = torch.load(output_path, map_location="cpu")

            # Check structure
            required_keys = ["input_ids", "attention_mask", "labels", "language_ids", "language_vocab", "meta"]
            missing_keys = [k for k in required_keys if k not in data]

            if missing_keys:
                print(f"❌ {split}: Missing keys {missing_keys}")
                validation_passed = False
                continue

            # Check shapes
            n_samples = len(data["labels"])
            input_shape = data["input_ids"].shape
            mask_shape = data["attention_mask"].shape
            lang_shape = data["language_ids"].shape

            if input_shape[0] != n_samples or mask_shape[0] != n_samples or lang_shape[0] != n_samples:
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

            # Check language_ids are within vocabulary range
            max_lang_id = torch.max(data["language_ids"]).item()
            if max_lang_id >= len(data["language_vocab"]):
                print(f"❌ {split}: language_id out of vocabulary range")
                validation_passed = False
                continue

            # Check metadata completeness
            required_meta_keys = ["model", "model_slug", "split", "max_length", "samples",
                                  "skipped", "languages", "num_languages", "has_cwe_field", "timestamp"]
            missing_meta_keys = [k for k in required_meta_keys if k not in data["meta"]]

            if missing_meta_keys:
                print(f"❌ {split}: Missing metadata keys {missing_meta_keys}")
                validation_passed = False
                continue

            # Verify metadata consistency
            if data["meta"]["samples"] != n_samples:
                print(f"❌ {split}: Metadata sample count mismatch")
                validation_passed = False
                continue

            if data["meta"]["num_languages"] != len(data["language_vocab"]):
                print(f"❌ {split}: Language vocabulary size mismatch")
                validation_passed = False
                continue

            print(f"✓ {split}: Valid")
            print(f"  - Keys: {list(data.keys())}")
            print(f"  - Samples: {n_samples:,}")
            print(f"  - Shapes: input_ids={input_shape}, labels={data['labels'].shape}, language_ids={lang_shape}")
            print(f"  - Labels: {unique_labels}")
            print(f"  - Languages: {data['language_vocab']}")
            print(f"  - Metadata keys: {list(data['meta'].keys())}")
            print(f"  - CWE field present: {data['meta']['has_cwe_field']}")
            print(f"  - Timestamp: {data['meta']['timestamp']}")

            # Clean up to prevent memory issues on large datasets
            del data
            gc.collect()

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
    print(f"  - Model: {MODEL_NAME}")
    print(f"  - Total processed: {total_processed:,}")
    print(f"  - Total skipped: {total_skipped:,}")
    print(f"  - Skip rate: {100*total_skipped/(total_processed+total_skipped):.2f}%")

    # Aggregate language statistics
    all_languages = set()
    for split_stats in all_statistics.values():
        all_languages.update(split_stats.get("languages", {}).keys())

    print(f"\n🌐 Language Coverage:")
    print(f"  - Unique languages: {len(all_languages)}")
    print(f"  - Languages: {[lang.capitalize() for lang in sorted(all_languages)]}")

    print(f"\n📁 Output Files:")
    for split in SPLITS:
        output_path = os.path.join(OUTPUT_DIR, f"{split}_tokenized_{MODEL_SLUG}.pt")
        if os.path.exists(output_path):
            size_mb = os.path.getsize(output_path) / (1024 * 1024)
            print(f"  ✓ {split}_tokenized_{MODEL_SLUG}.pt ({size_mb:.2f} MB)")

    # Save summary JSON
    summary_path = os.path.join(OUTPUT_DIR, "tokenization_summary.json")
    summary_data = {
        "model": MODEL_NAME,
        "model_slug": MODEL_SLUG,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_processed": total_processed,
        "total_skipped": total_skipped,
        "skip_rate": total_skipped / (total_processed + total_skipped) if (total_processed + total_skipped) > 0 else 0,
        "splits": all_statistics,
        "all_languages": sorted(all_languages),
        "validation_passed": validation_passed
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print(f"\n💾 Summary saved: {summary_path}")

    if validation_passed:
        print("\n✅ All validation checks passed!")
        print("🎉 Tokenization pipeline completed successfully!")
    else:
        print("\n⚠️ Some validation checks failed. Please review the output.")

    print("\n💡 Next Steps:")
    print("  1. Run validation notebook to verify row counts")
    print("  2. Use tokenized data for LoRA fine-tuning")
    print(f"  3. Check train_{MODEL_SLUG}_lora.py for training pipeline")
    print("  4. Review tokenization_summary.json for detailed statistics")

    print("=" * 80)

    return 0 if validation_passed else 1


if __name__ == "__main__":
    exit(main())
