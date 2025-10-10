# Dataset Preprocessing Verification & Issues Report

## Executive Summary

**Date**: October 10, 2025  
**Status**: Critical Issues Identified  
**Action Required**: Dataset verification before Kaggle deployment

## Critical Findings

### ❌ BLOCKED: github_ppakshad Dataset

**Issue**: Dataset contains NO source code - only pre-computed features

**Details**:
- File: `datasets/github_ppakshad/raw/main_dataset.xlsx`
- Structure: 15,185 rows × 24 columns
- Columns: C1-C4 (context), V1-V11 (vulnerability features), vulnerability type flags, Result (label)
- **NO CODE COLUMN** - completely incompatible with code-based preprocessing

**Impact**:
- `prepare_github_ppakshad.py` is completely incorrect
- Will fail on Kaggle if attempted
- Must be excluded from preprocessing pipeline

**Recommendation**: 
1. **SKIP** this dataset entirely
2. OR find original source code repository
3. OR create separate feature-only processing (for traditional ML only, not CodeBERT)

### ✅ FIXED: Zenodo Dataset

**Changes Applied**:
- ✅ SHA-256 hash-based deduplication (replaced prefix-based)
- ✅ Added provenance tracking (`source_row_index`, `source_file`)
- ✅ Updated `schema_utils.py` to support provenance fields
- ✅ Tested locally

**Results**:
- More accurate deduplication
- Full audit trail maintained
- Ready for Kaggle deployment

### ✅ FIXED: Devign Dataset

**Changes Applied**:
- ✅ SHA-256 hash-based deduplication
- ✅ Added provenance tracking
- ✅ Ready for Kaggle deployment

### ⏳ PENDING: Other Datasets

**Still Need Fixes**:
- `prepare_diversevul.py` - needs SHA-256 dedup + provenance
- `prepare_codexglue.py` - needs SHA-256 dedup + provenance
- `prepare_juliet.py` - needs SHA-256 dedup + provenance
- `prepare_megavul.py` - needs verification (check if file exists)

## Verification Checklist for Kaggle

Before running preprocessing on Kaggle, verify:

### 1. Dataset Availability
```python
# Check which datasets exist
import os
datasets = ['zenodo', 'devign', 'diversevul', 'codexglue', 'juliet']
for ds in datasets:
    path = f'/kaggle/input/{ds}'
    exists = os.path.exists(path)
    print(f"{'✓' if exists else '✗'} {ds}: {path}")
```

### 2. Skip github_ppakshad
```python
# DO NOT run this - dataset is incompatible
# !python scripts/preprocessing/prepare_github_ppakshad.py  # SKIP
```

### 3. Run Working Preprocessing
```python
# Safe to run (verified):
!python scripts/preprocessing/prepare_zenodo.py
!python scripts/preprocessing/prepare_devign.py

# Need fixes before running:
# !python scripts/preprocessing/prepare_diversevul.py  # TODO: apply fixes
# !python scripts/preprocessing/prepare_codexglue.py   # TODO: apply fixes
# !python scripts/preprocessing/prepare_juliet.py      # TODO: apply fixes
```

## Files Modified

### Core Libraries
- ✅ `scripts/utils/schema_utils.py` - Added provenance fields to JSONSCHEMA_DEFINITION

### Preprocessing Scripts
- ✅ `scripts/preprocessing/prepare_zenodo.py` - SHA-256 dedup + provenance
- ✅ `scripts/preprocessing/prepare_devign.py` - SHA-256 dedup + provenance
- ⏳ `scripts/preprocessing/prepare_diversevul.py` - Pending
- ⏳ `scripts/preprocessing/prepare_codexglue.py` - Pending
- ⏳ `scripts/preprocessing/prepare_juliet.py` - Pending
- ❌ `scripts/preprocessing/prepare_github_ppakshad.py` - INCOMPATIBLE

### Documentation
- ✅ `PREPROCESSING_FIXES.md` - Detailed technical changes
- ✅ `DATASET_VERIFICATION_REPORT.md` - This file

## Immediate Next Steps

### Before Pushing to GitHub:
1. ✅ Document issues (this file)
2. ⏳ Apply remaining fixes to diversevul/codexglue/juliet
3. ⏳ Update PREPROCESSING_README.md to mark github_ppakshad as incompatible
4. ⏳ Commit all changes with descriptive message

### On Kaggle:
1. Clone updated repository
2. Verify dataset availability
3. **Skip github_ppakshad**
4. Run preprocessing for available datasets only
5. Monitor for errors and check processed outputs

## Sample Kaggle Notebook Code

```python
# Clone repository
!git clone https://github.com/Harsh204k/codeGuardian.git
%cd codeGuardian

# Verify environment
!python -c "from scripts.utils.kaggle_paths import print_environment_info; print_environment_info()"

# Run preprocessing (skip github_ppakshad)
!python scripts/preprocessing/prepare_zenodo.py
!python scripts/preprocessing/prepare_devign.py

# Check outputs
!ls -lh datasets/zenodo/processed/
!ls -lh datasets/devign/processed/

# Verify provenance
!python -c "
import json
with open('datasets/zenodo/processed/raw_cleaned.jsonl') as f:
    rec = json.loads(f.readline())
    print('✓ Provenance fields present:', 'source_row_index' in rec, 'source_file' in rec)
    print(f'  Sample: {rec[\"source_file\"]} row {rec[\"source_row_index\"]}')
"
```

## Technical Details

### Deduplication Change
**Before** (problematic):
```python
unique_codes = set()
for record in all_records:
    code_key = record['code'][:200]  # Only first 200 chars
    if code_key not in unique_codes:
        unique_codes.add(code_key)
        unique_records.append(record)
```

**After** (correct):
```python
from scripts.utils.schema_utils import deduplicate_by_code_hash
unique_records = deduplicate_by_code_hash(all_records)  # Full SHA-256 hash
```

### Provenance Addition
```python
unified_record = map_to_unified_schema(...)

# Add provenance
unified_record['source_row_index'] = idx
unified_record['source_file'] = Path(csv_path).name

# Now records can be traced back to source
```

## Risk Assessment

### High Risk
- ❌ github_ppakshad will fail if attempted (no code in dataset)
- ⚠️ Unfixed scripts (diversevul/codexglue/juliet) still use prefix dedup

### Medium Risk
- ⚠️ Dataset availability on Kaggle not verified
- ⚠️ Disk space for processed outputs not verified

### Low Risk
- ✅ Fixed scripts (zenodo/devign) tested and working
- ✅ Schema validation updated correctly

## Contact & Support

For issues during Kaggle deployment:
1. Check this report first
2. Verify dataset existence/format
3. Check terminal output for specific errors
4. Review processing logs in `datasets/*/processed/`

---

**Generated**: October 10, 2025  
**Last Updated**: After Zenodo C-count analysis and github_ppakshad discovery
