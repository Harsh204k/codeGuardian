# Preprocessing Pipeline Fixes - October 10, 2025

## Summary of Changes

### 1. Improved Deduplication (All Datasets)
**Problem**: Original scripts used prefix-based deduplication (`code[:200]`) which caused:
- False positives (different code with same 200-char prefix)
- Lost data (115 unique C records in Zenodo)

**Solution**: Switched to SHA-256 hash-based deduplication
- Uses `deduplicate_by_code_hash()` from `schema_utils.py`
- More accurate and deterministic
- Preserves all truly unique code snippets

**Impact**:
- Zenodo C dataset: 4,207 unique raw → 4,092 processed (was losing 115 due to prefix collisions)
- All other datasets: More accurate deduplication

### 2. Added Provenance Tracking
**Added fields to all processed records**:
- `source_row_index`: Original CSV/JSON row number
- `source_file`: Original filename

**Benefits**:
- Full audit trail from processed → raw data
- Easy debugging and validation
- Traceability for compliance/reproducibility

### 3. Updated Schema Validation
Modified `JSONSCHEMA_DEFINITION` in `schema_utils.py` to accept provenance fields:
```python
"source_row_index": {"type": "integer"},
"source_file": {"type": "string"}
```

## Dataset-Specific Issues

### ✅ FIXED: Zenodo
- Applied SHA-256 dedup
- Added provenance tracking
- Status: Ready for Kaggle

### ⚠️ ISSUE: github_ppakshad
**Problem**: This dataset contains **NO SOURCE CODE**
- File: `main_dataset.xlsx`
- Structure: Pre-computed features only (C1-C4, V1-V11, vulnerability flags)
- Current script: Tries to extract code fields that don't exist

**Options**:
1. **SKIP** this dataset (recommended) - not compatible with code-based pipeline
2. Create separate feature-only processing
3. Find original source code repository

**Action Taken**: Documented issue; dataset should be excluded from main preprocessing pipeline

### 🔄 PENDING: Other Datasets
Need to apply same fixes to:
- `prepare_devign.py`
- `prepare_diversevul.py`
- `prepare_codexglue.py`
- `prepare_juliet.py`
- `prepare_megavul.py`

## Files Modified

### Core Utilities
- ✅ `scripts/utils/schema_utils.py` - Added provenance fields to schema

### Preprocessing Scripts
- ✅ `scripts/preprocessing/prepare_zenodo.py` - SHA-256 dedup + provenance
- ⏳ `scripts/preprocessing/prepare_devign.py` - Pending
- ⏳ `scripts/preprocessing/prepare_diversevul.py` - Pending
- ⏳ `scripts/preprocessing/prepare_codexglue.py` - Pending
- ⏳ `scripts/preprocessing/prepare_juliet.py` - Pending
- ⏳ `scripts/preprocessing/prepare_megavul.py` - Pending
- ❌ `scripts/preprocessing/prepare_github_ppakshad.py` - INCOMPATIBLE (no code)

## Migration Notes for Kaggle

### Before Running on Kaggle:
1. ✅ Commit and push all preprocessing fixes
2. ✅ Clone repo in Kaggle notebook
3. ⚠️ Skip github_ppakshad dataset
4. ✅ Run other preprocessing scripts normally

### Example Kaggle Usage:
```python
# Clone repo
!git clone https://github.com/Harsh204k/codeGuardian.git
%cd codeGuardian

# Run preprocessing (skip github_ppakshad)
!python scripts/preprocessing/prepare_zenodo.py
!python scripts/preprocessing/prepare_devign.py
!python scripts/preprocessing/prepare_diversevul.py
# ... etc
```

## Verification Steps

### Test Deduplication Accuracy:
```python
# Compare raw vs processed counts
raw_count = len(pd.read_csv('datasets/zenodo/raw/data_C.csv'))
processed_count = len([1 for line in open('datasets/zenodo/processed/raw_cleaned.jsonl') 
                       if json.loads(line)['language'] == 'C'])
print(f"Raw: {raw_count}, Processed: {processed_count}")
```

### Check Provenance:
```python
# Verify provenance fields exist
import json
with open('datasets/zenodo/processed/raw_cleaned.jsonl') as f:
    record = json.loads(f.readline())
    assert 'source_row_index' in record
    assert 'source_file' in record
    print(f"✓ Provenance tracking working: {record['source_file']} row {record['source_row_index']}")
```

## Next Steps

1. **Immediate**: Apply same fixes to remaining preprocessing scripts
2. **Before Kaggle**: Test locally with small sample
3. **On Kaggle**: Run full preprocessing pipeline
4. **Future**: Decide on github_ppakshad dataset (skip or find original code)

## Related Files
- Analysis: See previous conversation about Zenodo C count discrepancy
- Tests: `scripts/test_kaggle_paths.py`
- Documentation: `scripts/PREPROCESSING_README.md`
