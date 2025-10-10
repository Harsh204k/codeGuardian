# Kaggle Preprocessing Deployment Guide
**Date**: October 10, 2025  
**Status**: ✅ READY TO RUN ON KAGGLE

## Summary of Fixes Applied

### ✅ FIXED & TESTED:
1. **Zenodo** - SHA-256 dedup + provenance (Zenodo C: 4,092 unique records)
2. **Devign** - SHA-256 dedup + provenance  
3. **DiverseVul** - Field fixes + SHA-256 dedup + provenance + language inference

### ❌ MUST SKIP:
- **github_ppakshad** - NO SOURCE CODE (feature-only dataset, incompatible)

### ⏳ PENDING (Not Fixed Yet):
- `prepare_codexglue.py` - Still uses prefix dedup
- `prepare_juliet.py` - Still uses prefix dedup
- `prepare_megavul.py` - Not verified

---

## Quick Start on Kaggle

### 1. Clone Repository
```python
!git clone https://github.com/Harsh204k/codeGuardian.git
%cd codeGuardian
!git log --oneline -5  # Verify latest commit
```

### 2. Verify Environment
```python
from scripts.utils.kaggle_paths import print_environment_info
print_environment_info()
```

### 3. Run Preprocessing (SAFE DATASETS ONLY)

```python
# ✅ SAFE TO RUN - These are verified and fixed
!python scripts/preprocessing/prepare_zenodo.py
!python scripts/preprocessing/prepare_devign.py  
!python scripts/preprocessing/prepare_diversevul.py

# ❌ DO NOT RUN - Incompatible dataset
# !python scripts/preprocessing/prepare_github_ppakshad.py  # SKIP THIS

# ⚠️ UNTESTED - Use with caution (still have prefix dedup issues)
# !python scripts/preprocessing/prepare_codexglue.py
# !python scripts/preprocessing/prepare_juliet.py
```

---

## Expected Processing Times (Estimates)

| Dataset | Records | Size | Est. Time | Memory |
|---------|---------|------|-----------|--------|
| **Zenodo** | 27,338 | ~100 MB | 5-10 min | ~2 GB |
| **Devign** | 27,000 | ~50 MB | 3-5 min | ~2 GB |
| **DiverseVul** | 330,492 | ~703 MB | 30-45 min | ~4 GB |

---

## Verification Steps

### After Each Dataset Processes:

```python
import json
from pathlib import Path

# Example for Zenodo
dataset_name = "zenodo"  # or "devign", "diversevul"
processed_dir = Path(f"/kaggle/working/{dataset_name}/processed")

# 1. Check files exist
print(f"✓ Files in {processed_dir}:")
print(list(processed_dir.glob("*")))

# 2. Check provenance
with open(processed_dir / "raw_cleaned.jsonl") as f:
    sample = json.loads(f.readline())
    assert 'source_row_index' in sample, "Missing provenance!"
    assert 'source_file' in sample, "Missing provenance!"
    print(f"✓ Provenance: {sample['source_file']} row {sample['source_row_index']}")

# 3. Check stats
with open(processed_dir / "stats.json") as f:
    stats = json.load(f)
    print(f"✓ Total records: {stats['total_records']:,}")
    print(f"✓ Vulnerable: {stats['vulnerable_records']:,}")
    print(f"✓ Languages: {len(stats['languages'])}")
```

---

## Detailed Dataset Expectations

### Zenodo
```
Expected Output:
- Total records: ~27,338 (all languages combined)
- C records: ~4,092 (after SHA-256 dedup)
- Languages: C, C++, Go, Java, JavaScript, PHP, Python, Ruby
- Vulnerable ratio: 100% (all vulnerable)
- Unique CWEs: ~186
```

### Devign  
```
Expected Output:
- Total records: ~27,000 (C functions only)
- Projects: FFmpeg, Qemu
- Vulnerable ratio: ~50-60%
- Language: C only
```

### DiverseVul
```
Expected Output:
- Total records: ~310,000-320,000 (after SHA-256 dedup from 330,492)
- Languages: Mostly C/C++ (70-80%), Java, Python, JavaScript, PHP, Go
- Vulnerable ratio: ~50-60% (balanced dataset)
- Projects: 400+ open-source projects
- Unique CWEs: 100+
```

---

## Troubleshooting

### Issue: "No module named 'jsonschema'"
**Solution**: Manual validation fallback is already implemented. Script will continue with manual validation.

### Issue: Out of Memory
**Solution**: 
```python
# Process smaller batch
!python scripts/preprocessing/prepare_diversevul.py --max-records 50000
```

### Issue: "File not found"
**Solution**: Check Kaggle input dataset is mounted:
```python
!ls /kaggle/input/
```

### Issue: Slow Processing
**Expected**: DiverseVul takes 30-45 min (330k records is large)
**Monitor**: Check Kaggle notebook logs for progress bars

---

## After Preprocessing Completes

### 1. Verify All Outputs
```python
import os
for dataset in ['zenodo', 'devign', 'diversevul']:
    processed_path = f"/kaggle/working/{dataset}/processed"
    if os.path.exists(processed_path):
        files = os.listdir(processed_path)
        print(f"✓ {dataset}: {files}")
    else:
        print(f"✗ {dataset}: NOT FOUND")
```

### 2. Check Total Records
```python
import json
total = 0
for dataset in ['zenodo', 'devign', 'diversevul']:
    stats_file = f"/kaggle/working/{dataset}/processed/stats.json"
    if os.path.exists(stats_file):
        with open(stats_file) as f:
            stats = json.load(f)
            count = stats['total_records']
            total += count
            print(f"{dataset}: {count:,} records")
            
print(f"\nTOTAL PROCESSED: {total:,} records")
```

Expected total: **~340,000-360,000 records** (Zenodo + Devign + DiverseVul)

### 3. Copy to Kaggle Output
```python
# Make outputs available for download
!mkdir -p /kaggle/working/all_processed
!cp datasets/zenodo/processed/* /kaggle/working/all_processed/zenodo_* || true
!cp datasets/devign/processed/* /kaggle/working/all_processed/devign_* || true  
!cp datasets/diversevul/processed/* /kaggle/working/all_processed/diversevul_* || true

print("✓ All processed data copied to /kaggle/working/all_processed/")
!ls -lh /kaggle/working/all_processed/
```

---

## Next Steps After Preprocessing

1. **Normalization** (Optional):
   ```python
   !python scripts/normalization/normalize_all_datasets.py
   ```

2. **Validation**:
   ```python
   !python scripts/validation/validate_normalized_data.py
   ```

3. **Feature Engineering**:
   ```python
   !python scripts/features/feature_engineering.py
   ```

4. **Model Training**:
   - Use processed JSONL files for CodeBERT training
   - Or extract features for traditional ML models

---

## Important Reminders

### ✅ DO:
- Run only the 3 verified scripts (zenodo, devign, diversevul)
- Monitor memory usage during DiverseVul processing
- Verify provenance fields exist in outputs
- Check stats.json for expected record counts

### ❌ DON'T:
- Run `prepare_github_ppakshad.py` (will fail - no code in dataset)
- Run untested scripts (codexglue, juliet) without first fixing them
- Skip verification steps
- Delete intermediate outputs before verification

---

## Documentation Files

Created comprehensive documentation:
- `DIVERSEVUL_VERIFICATION.md` - DiverseVul dataset analysis
- `DATASET_VERIFICATION_REPORT.md` - All preprocessing issues  
- `PREPROCESSING_FIXES.md` - Technical implementation details

Read these for detailed information about fixes and expected behavior.

---

## Contact Information

**Repository**: https://github.com/Harsh204k/codeGuardian  
**Latest Commit**: Check with `git log --oneline -1` after cloning

---

**Status**: ✅ **READY FOR KAGGLE DEPLOYMENT**  
**Last Updated**: October 10, 2025  
**Version**: After complete Devign + DiverseVul fixes
