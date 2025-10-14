#!/usr/bin/env python
"""
Example: Run Both Tokenization Pipelines
=========================================
This script demonstrates how to run both CodeBERT and GraphCodeBERT
tokenization pipelines programmatically.

Usage:
    python run_both_tokenizations.py
"""

import sys
import os
from pathlib import Path

# Add tokenization scripts to path
tokenization_dir = Path(__file__).parent
sys.path.insert(0, str(tokenization_dir))

print("=" * 80)
print("🚀 Running Both Tokenization Pipelines")
print("=" * 80)

# ============================================================================
# 1️⃣ CodeBERT Tokenization
# ============================================================================
print("\n" + "=" * 80)
print("📦 STEP 1: CodeBERT Tokenization")
print("=" * 80)

try:
    from tokenize_codebert import main as tokenize_codebert_main
    
    print("Starting CodeBERT tokenization...")
    codebert_score = tokenize_codebert_main()
    print(f"\n✅ CodeBERT tokenization completed with score: {codebert_score}/200")
    
except Exception as e:
    print(f"\n❌ CodeBERT tokenization failed: {e}")
    codebert_score = 0


# ============================================================================
# 2️⃣ GraphCodeBERT Tokenization
# ============================================================================
print("\n" + "=" * 80)
print("📦 STEP 2: GraphCodeBERT Tokenization")
print("=" * 80)

try:
    from tokenize_graphcodebert import main as tokenize_graphcodebert_main
    
    print("Starting GraphCodeBERT tokenization...")
    graphcodebert_score = tokenize_graphcodebert_main()
    print(f"\n✅ GraphCodeBERT tokenization completed with score: {graphcodebert_score}/200")
    
except Exception as e:
    print(f"\n❌ GraphCodeBERT tokenization failed: {e}")
    graphcodebert_score = 0


# ============================================================================
# 3️⃣ Summary
# ============================================================================
print("\n" + "=" * 80)
print("📊 TOKENIZATION SUMMARY")
print("=" * 80)

print(f"\n📈 Scores:")
print(f"   CodeBERT:        {codebert_score:3d}/200")
print(f"   GraphCodeBERT:   {graphcodebert_score:3d}/200")
print(f"   Average:         {(codebert_score + graphcodebert_score) // 2:3d}/200")

if codebert_score >= 180 and graphcodebert_score >= 180:
    print("\n🎊 EXCELLENT! Both pipelines executed successfully!")
elif codebert_score >= 160 and graphcodebert_score >= 160:
    print("\n✅ GOOD! Both pipelines completed with minor warnings.")
else:
    print("\n⚠️ Some issues detected. Check logs for details.")

# Verify output files
print("\n📁 Output Files:")

output_base = "/kaggle/working/datasets/tokenized"
for model in ["codebert", "graphcodebert"]:
    model_dir = os.path.join(output_base, model)
    if os.path.exists(model_dir):
        files = os.listdir(model_dir)
        pt_files = [f for f in files if f.endswith('.pt')]
        print(f"\n   {model}:")
        for f in pt_files:
            file_path = os.path.join(model_dir, f)
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            print(f"      ✓ {f} ({size_mb:.1f} MB)")
    else:
        print(f"\n   {model}: ❌ Directory not found")

print("\n" + "=" * 80)
print("✅ Tokenization pipelines completed!")
print("=" * 80)
print("\n💡 Next steps:")
print("   1. Inspect files: python scripts/check_tokenized.py <file_path>")
print("   2. Generate embeddings from tokenized data")
print("   3. Train/fine-tune models")
print("   4. Create hybrid ensemble")

print("\n📚 Documentation:")
print("   - README: src/ml/tokenization/README.md")
print("   - Comparison: src/ml/tokenization/COMPARISON.md")
print("=" * 80)
