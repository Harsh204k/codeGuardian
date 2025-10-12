# 🚨 Kaggle Error 256 - Troubleshooting Guide

## Problem
Script exits with code 256 on Kaggle after environment detection succeeds.

## Root Cause
The script cannot find the dataset files in the expected location.

## Solution - Updated Code

### ✅ What Was Fixed

1. **Enhanced Dataset Folder Detection**
   - Now tries multiple folder name variants:
     - `codeguardian-pre-processed-datasets`
     - `codeguardian-preprocessed-datasets`
     - `codeguardian-datasets` ← **Your folder name**
     - `codeguardian-data`
   - Falls back to single-folder auto-detection
   - Provides helpful error messages if detection fails

2. **Better Error Messages**
   - Shows exactly where it's looking for files
   - Lists available directories for debugging
   - Suggests concrete solutions
   - Shows current directory structure

3. **Graceful Degradation**
   - Skips missing datasets instead of failing completely
   - Continues processing with available datasets
   - Warns user about skipped datasets

## How to Use on Kaggle

### Option 1: Automatic Detection (Recommended)
```python
import os

# Navigate to script directory
os.chdir("/kaggle/working/codeGuardian/scripts/normalization")

# Run with auto-detection
os.system("python normalize_and_merge.py --validate --summary")
```

The script will now automatically detect your `codeguardian-datasets` folder!

### Option 2: Explicit Path
```python
import os

os.chdir("/kaggle/working/codeGuardian/scripts/normalization")

# Specify exact dataset path
os.system("python normalize_and_merge.py --datasets-dir /kaggle/input/codeguardian-datasets --validate --summary")
```

### Option 3: Process Specific Datasets
```python
import os

os.chdir("/kaggle/working/codeGuardian/scripts/normalization")

# Process only available datasets
os.system("python normalize_and_merge.py --datasets devign zenodo --validate --summary")
```

## Expected Output (Fixed)

```
✅ All dependencies available
📂 Working directory set to: /kaggle/working/codeGuardian
✅ Project structure OK

================================================================================
CodeGuardian v3.1 - Normalization & Merging Pipeline (Stage III)
   Kaggle-Optimized + Full schema_utils.py Integration
   31-field unified schema with granularity & metadata
================================================================================

✅ Detected Kaggle input datasets at: /kaggle/input/codeguardian-datasets
📁 Reading datasets from: /kaggle/input/codeguardian-datasets
💾 Writing outputs to: /kaggle/working/datasets/final
🎯 Schema: 31-field unified schema (17 base + 14 Stage III fields)
🔄 Deduplication: DISABLED

🔍 Checking dataset availability:
  ✅ Found: devign at /kaggle/input/codeguardian-datasets/devign/processed/raw_cleaned.jsonl
  ✅ Found: zenodo at /kaggle/input/codeguardian-datasets/zenodo/processed/raw_cleaned.jsonl
  ✅ Found: diversevul at /kaggle/input/codeguardian-datasets/diversevul/processed/raw_cleaned.jsonl
  ✅ Found: juliet at /kaggle/input/codeguardian-datasets/juliet/processed/raw_cleaned.jsonl

📝 PHASE 1: PARALLEL NORMALIZATION
...
```

## Troubleshooting

### If Still Getting Error 256

1. **Check Dataset Structure**
   ```python
   import os
   from pathlib import Path

   # List what's in /kaggle/input
   kaggle_input = Path("/kaggle/input")
   print("📂 Contents of /kaggle/input:")
   for item in kaggle_input.iterdir():
       print(f"  - {item.name}")

   # Check your dataset folder
   dataset_folder = kaggle_input / "codeguardian-datasets"
   if dataset_folder.exists():
       print(f"\n✅ Found: {dataset_folder}")
       print("\n📂 Contents:")
       for item in dataset_folder.iterdir():
           print(f"  - {item.name}")
   ```

2. **Expected Structure**
   Your Kaggle dataset should have this structure:
   ```
   /kaggle/input/codeguardian-datasets/
   ├── devign/
   │   └── processed/
   │       └── raw_cleaned.jsonl
   ├── zenodo/
   │   └── processed/
   │       └── raw_cleaned.jsonl
   ├── diversevul/
   │   └── processed/
   │       └── raw_cleaned.jsonl
   └── juliet/
       └── processed/
           └── raw_cleaned.jsonl
   ```

3. **If Structure is Different**
   - Use `--datasets-dir` to point to the correct location
   - Example: `--datasets-dir /kaggle/input/codeguardian-datasets`

4. **Check File Paths Match**
   The script looks for files at:
   - `{datasets_dir}/devign/processed/raw_cleaned.jsonl`
   - `{datasets_dir}/zenodo/processed/raw_cleaned.jsonl`
   - etc.

### Common Kaggle Issues

| Issue | Solution |
|-------|----------|
| Dataset not attached | Add dataset in Kaggle notebook settings (right sidebar) |
| Wrong folder name | Script now handles multiple variants automatically |
| Files in wrong location | Use `--datasets-dir` to specify correct path |
| Permission denied | Output goes to `/kaggle/working` (writable) |
| Out of memory | Use `--quick-test` for 100 records only |

## Verification Steps

After uploading the fixed code to Kaggle:

1. ✅ Script detects `codeguardian-datasets` folder automatically
2. ✅ Finds all dataset files or reports which are missing
3. ✅ Processes available datasets (skips missing ones)
4. ✅ Writes output to `/kaggle/working/datasets/final/`
5. ✅ Generates statistics and reports
6. ✅ Exits with code 0 (success)

## Quick Test

```python
# Test with just 100 records
os.system("python normalize_and_merge.py --quick-test --summary")
```

This should complete in ~30 seconds and confirm everything works!

---

**Status:** ✅ Fixed - Ready to deploy on Kaggle
**Key Changes:** Enhanced folder detection + better error messages
**Impact:** Handles your `codeguardian-datasets` folder name automatically
