#!/usr/bin/env python
"""
CodeGuardian: Run Both Tokenization Pipelines
==============================================
Orchestrates CodeBERT and GraphCodeBERT tokenization for vulnerability detection.

Author: Urva Gandhi
Usage: python run_both_tokenizations.py
"""

import sys
import os
import time
from pathlib import Path

# Add tokenization scripts to path
tokenization_dir = Path(__file__).parent
sys.path.insert(0, str(tokenization_dir))

print("=" * 80)
print("🚀 CodeGuardian Tokenization Pipeline Runner")
print("=" * 80)
print("Author: Urva Gandhi")
print("Purpose: Tokenize code dataset for LoRA fine-tuning")
print("=" * 80)

start_time = time.time()

# ============================================================================
# 1️⃣ CodeBERT Tokenization
# ============================================================================
print("\n" + "=" * 80)
print("📦 STEP 1: CodeBERT Tokenization")
print("=" * 80)

codebert_success = False
try:
    from tokenize_codebert import main as tokenize_codebert_main

    print("Starting CodeBERT tokenization...")
    exit_code = tokenize_codebert_main()

    if exit_code == 0:
        print("\n✅ CodeBERT tokenization completed successfully!")
        codebert_success = True
    else:
        print(f"\n⚠️ CodeBERT tokenization completed with warnings (exit code: {exit_code})")

except Exception as e:
    print(f"\n❌ CodeBERT tokenization failed: {e}")
    import traceback
    traceback.print_exc()


# ============================================================================
# 2️⃣ GraphCodeBERT Tokenization
# ============================================================================
print("\n" + "=" * 80)
print("📦 STEP 2: GraphCodeBERT Tokenization")
print("=" * 80)

graphcodebert_success = False
try:
    from tokenize_graphcodebert import main as tokenize_graphcodebert_main

    print("Starting GraphCodeBERT tokenization...")
    exit_code = tokenize_graphcodebert_main()

    if exit_code == 0:
        print("\n✅ GraphCodeBERT tokenization completed successfully!")
        graphcodebert_success = True
    else:
        print(f"\n⚠️ GraphCodeBERT tokenization completed with warnings (exit code: {exit_code})")

except Exception as e:
    print(f"\n❌ GraphCodeBERT tokenization failed: {e}")
    import traceback
    traceback.print_exc()


# ============================================================================
# 3️⃣ Verify Output Files
# ============================================================================
print("\n" + "=" * 80)
print("� OUTPUT FILE VERIFICATION")
print("=" * 80)

output_base = "/kaggle/working/tokenized"
splits = ["train", "val", "test"]
models = ["codebert", "graphcodebert"]

all_files_exist = True

for model in models:
    model_dir = os.path.join(output_base, model)
    print(f"\n{model.upper()}:")

    if not os.path.exists(model_dir):
        print(f"  ❌ Directory not found: {model_dir}")
        all_files_exist = False
        continue

    for split in splits:
        file_path = os.path.join(model_dir, f"{split}_tokenized.pt")
        if os.path.exists(file_path):
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            print(f"  ✓ {split}_tokenized.pt ({size_mb:.2f} MB)")
        else:
            print(f"  ❌ {split}_tokenized.pt - NOT FOUND")
            all_files_exist = False


# ============================================================================
# 4️⃣ Summary
# ============================================================================
elapsed_time = time.time() - start_time

print("\n" + "=" * 80)
print("📊 FINAL SUMMARY")
print("=" * 80)

print(f"\n⏱️  Total Runtime: {elapsed_time/60:.2f} minutes")

print(f"\n📈 Pipeline Status:")
print(f"  CodeBERT:       {'✅ SUCCESS' if codebert_success else '❌ FAILED'}")
print(f"  GraphCodeBERT:  {'✅ SUCCESS' if graphcodebert_success else '❌ FAILED'}")
print(f"  All Files:      {'✅ PRESENT' if all_files_exist else '❌ MISSING'}")

if codebert_success and graphcodebert_success and all_files_exist:
    print("\n🎉 TOKENIZATION COMPLETED SUCCESSFULLY!")
    print("\n✅ All tokenized files are ready for training")
    print("\n💡 Next Steps:")
    print("  1. Run validation notebook: validate_tokenization.ipynb")
    print("  2. Start LoRA fine-tuning: train_codebert_lora.py")
    print("  3. Train GraphCodeBERT: train_graphcodebert_lora.py")
    print("  4. Create hybrid ensemble model")
    exit_code = 0
elif codebert_success or graphcodebert_success:
    print("\n⚠️ PARTIAL SUCCESS")
    print("\nSome tokenization pipelines completed successfully.")
    print("Review the logs above for details on failures.")
    exit_code = 1
else:
    print("\n❌ TOKENIZATION FAILED")
    print("\nBoth pipelines encountered errors.")
    print("Please review the error messages above and:")
    print("  1. Check input JSONL files exist")
    print("  2. Verify sufficient disk space")
    print("  3. Ensure dependencies are installed")
    print("  4. Check error logs for details")
    exit_code = 2

print("\n📚 Documentation:")
print("  - Tokenization README: src/ml/tokenization/README.md")
print("  - Validation Notebook: src/ml/tokenization/validate_tokenization.ipynb")

print("=" * 80)

sys.exit(exit_code)
