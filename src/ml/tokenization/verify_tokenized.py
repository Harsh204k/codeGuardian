#!/usr/bin/env python3
"""
Quick Tokenization Verification Script
======================================
Verifies tokenized .pt files after running tokenization pipelines.

Usage:
    python verify_tokenized.py
"""

import torch
import os

print("=" * 80)
print("🔍 Quick Tokenization Verification")
print("=" * 80)

OUTPUT_BASE = "/kaggle/working/tokenized"
MODELS = ["codebert", "graphcodebert"]
SPLITS = ["train", "val", "test"]

all_valid = True

for model in MODELS:
    print(f"\n{'='*80}")
    print(f"📦 {model.upper()}")
    print(f"{'='*80}")

    model_dir = os.path.join(OUTPUT_BASE, model)

    if not os.path.exists(model_dir):
        print(f"❌ Directory not found: {model_dir}")
        all_valid = False
        continue

    for split in SPLITS:
        file_path = os.path.join(model_dir, f"{split}_tokenized.pt")

        if not os.path.exists(file_path):
            print(f"\n{split.upper()}: ❌ File not found")
            all_valid = False
            continue

        try:
            # Load file
            data = torch.load(file_path, map_location="cpu")

            # Get stats
            n_samples = len(data["labels"])
            keys = list(data.keys())
            shape = data["input_ids"].shape
            labels_unique = torch.unique(data["labels"]).tolist()
            label_counts = torch.bincount(data["labels"])

            # Print summary
            print(f"\n{split.upper()}: ✅")
            print(f"  Samples: {n_samples:,}")
            print(f"  Keys: {keys}")
            print(f"  Shape: {shape}")
            print(f"  Labels: {labels_unique}")
            print(f"  Distribution: 0={label_counts[0]:,}, 1={label_counts[1]:,}")

            if "meta" in data:
                print(f"  Meta: {data['meta']}")

            # Clean up
            del data

        except Exception as e:
            print(f"\n{split.upper()}: ❌ Error - {str(e)}")
            all_valid = False

print("\n" + "=" * 80)
if all_valid:
    print("✅ ALL FILES VERIFIED SUCCESSFULLY!")
else:
    print("❌ SOME FILES FAILED VERIFICATION")
print("=" * 80)
