# 🚀 CodeGuardian Phase 2 - Production-Grade Pipeline Guide

## Overview

This document provides comprehensive guidance for running the enhanced Phase 2 pipeline with production-grade features including schema validation, profiling, caching, and automated reporting.

---

## 🎯 Quick Start

### Basic Usage

```bash
# Run full pipeline with default configuration
python scripts/run_pipeline_enhanced.py

# Run with custom config
python scripts/run_pipeline_enhanced.py --config configs/pipeline_config.yaml

# Run specific stages only
python scripts/run_pipeline_enhanced.py --steps normalization validation feature_engineering

# Resume from a specific stage
python scripts/run_pipeline_enhanced.py --resume feature_engineering

# Quick test mode (10k records)
python scripts/run_pipeline_enhanced.py --quick-test

# Dry run (validate without execution)
python scripts/run_pipeline_enhanced.py --dry-run

# Clear checkpoints and run fresh
python scripts/run_pipeline_enhanced.py --clear-checkpoints
```

---

## 📊 Pipeline Stages

### 1. **Preprocessing**
Prepare raw datasets from multiple sources

**Individual Scripts:**
```bash
python scripts/preprocessing/prepare_devign.py
python scripts/preprocessing/prepare_zenodo.py
python scripts/preprocessing/prepare_diversevul_parallel.py
python scripts/preprocessing/prepare_juliet_batch.py
```

**Outputs:**
- `datasets/devign/processed/*.jsonl`
- `datasets/zenodo/processed/*.jsonl`
- `datasets/diversevul/processed/*.jsonl`
- `datasets/juliet/processed/*.jsonl`

---

### 2. **Normalization**
Merge and normalize all datasets to unified schema

```bash
python scripts/normalization/normalize_and_merge.py
```

**Features:**
- ✅ CWE → attack_type/severity mapping
- ✅ Code SHA-256 deduplication
- ✅ Missing field auto-repair
- ✅ Source provenance tracking
- ✅ 32-field unified schema

**Outputs:**
- `datasets/merged/merged_normalized.jsonl` (~842k records)

---

### 3. **Validation**
Validate schema compliance and data quality

```bash
python scripts/validation/validate_normalized_data.py
```

**Checks:**
- ✅ Schema field compliance
- ✅ Data type validation
- ✅ Required field presence
- ✅ Duplicate detection
- ✅ Missing value analysis

**Outputs:**
- `datasets/validated/validated.jsonl` (~634k valid records)
- `datasets/validated/validation_report.json`
- `datasets/validated/validation_summary.json`
- `datasets/validated/validation_field_stats.csv`

---

### 4. **Feature Engineering** ⭐ (Enhanced)
Extract 45+ advanced features from code

```bash
# Basic usage
python scripts/features/feature_engineering_enhanced.py

# With multiprocessing (faster for large datasets)
python scripts/features/feature_engineering_enhanced.py --multiprocessing --n-jobs 8

# Disable schema validation (faster but less safe)
python scripts/features/feature_engineering_enhanced.py --no-validation

# With custom paths
python scripts/features/feature_engineering_enhanced.py \
  --input datasets/validated/validated.jsonl \
  --output-csv datasets/features/features_static.csv \
  --output-parquet datasets/features/features_static.parquet \
  --stats datasets/features/stats_features.json
```

**Features Extracted (45 total):**

**Code Metrics (9):**
- loc, total_lines, num_tokens, avg_line_len, max_line_len
- comment_density, function_length, total_chars, whitespace_ratio

**Lexical Features (7):**
- keyword_count, identifier_count, numeric_count, string_count
- special_char_count, operator_count, security_keyword_count

**Complexity Metrics (5):**
- cyclomatic_complexity, nesting_depth, ast_depth
- conditional_count, loop_count

**Diversity & Entropy (3):**
- token_diversity, shannon_entropy, identifier_entropy

**Ratio Features (5):**
- comment_code_ratio, identifier_keyword_ratio
- operator_operand_ratio, token_density, security_keyword_ratio

**Metadata (3):**
- has_cwe, has_cve, has_description

**Core Fields (13):**
- id, language, is_vulnerable, dataset + 9 others

**Outputs:**
- `datasets/features/features_static.csv` (~634k × 45 features)
- `datasets/features/features_static.parquet` (optimized binary format)
- `datasets/features/stats_features.json` (feature statistics)

---

### 5. **Dataset Splitting**
Split into train/validation/test sets

```bash
python scripts/splitting/split_datasets.py
```

**Default Split Ratios:**
- Train: 70%
- Validation: 15%
- Test: 15%

**Outputs:**
- `datasets/preprocessed/train.jsonl`
- `datasets/preprocessed/val.jsonl`
- `datasets/preprocessed/test.jsonl`
- `datasets/preprocessed/split_summary.json`

---

## 🔧 Configuration

### Pipeline Config (`configs/pipeline_config.yaml`)

```yaml
pipeline:
  stages:
    - preprocessing
    - normalization
    - validation
    - feature_engineering
    - splitting

  enable:
    preprocessing: true
    normalization: true
    validation: true
    feature_engineering: true
    splitting: true

error_handling:
  continue_on_error: false
  retry:
    enabled: true
    max_attempts: 3
    backoff_factor: 2

performance:
  enable_profiling: true
  enable_caching: true
  chunk_size: 10000
  use_multiprocessing: false

testing:
  quick_test: false
  quick_test_records: 10000
  integrity_checks:
    enabled: true
    verify_file_existence: true
    verify_file_sizes: true
    verify_record_counts: true
```

---

## 📊 Output Files & Sizes

### Validated Dataset
```
datasets/validated/
├── validated.jsonl              # ~2.3 GB, 634k records
├── validation_report.json       # ~500 KB
├── validation_summary.json      # ~2 KB
└── validation_field_stats.csv   # ~5 KB
```

### Features
```
datasets/features/
├── features_static.csv          # ~180 MB (634k × 45 features)
├── features_static.parquet      # ~45 MB (optimized)
└── stats_features.json          # ~15 KB
```

### Train/Val/Test Splits
```
datasets/preprocessed/
├── train.jsonl                  # ~1.6 GB (70%)
├── val.jsonl                    # ~350 MB (15%)
├── test.jsonl                   # ~350 MB (15%)
└── split_summary.json           # ~3 KB
```

---

## ⚡ Performance Optimization

### 1. Enable Multiprocessing (Feature Engineering)
```bash
python scripts/features/feature_engineering_enhanced.py --multiprocessing --n-jobs -1
```
**Speedup:** 3-5x faster on multi-core systems

### 2. Use Parquet Format
Parquet files are 4x smaller and 2-3x faster to read than CSV:
```python
import pandas as pd
df = pd.read_parquet('datasets/features/features_static.parquet')
```

### 3. Enable Caching
The pipeline automatically caches intermediate results in `cache/` directory.

### 4. Quick Test Mode
Test pipeline with 10k records before full run:
```bash
python scripts/run_pipeline_enhanced.py --quick-test
```

---

## 🐛 Troubleshooting

### Issue: "Schema validation failed"
**Solution:** Update `scripts/utils/schema_utils.py` with latest schema or disable validation:
```bash
python scripts/features/feature_engineering_enhanced.py --no-validation
```

### Issue: "Memory error during feature engineering"
**Solution:** Reduce chunk size:
```bash
python scripts/features/feature_engineering_enhanced.py --chunk-size 5000
```

### Issue: "Stage failed, pipeline stopped"
**Solution:** Enable continue-on-error in config or resume from failed stage:
```bash
python scripts/run_pipeline_enhanced.py --resume feature_engineering
```

### Issue: "Checkpoints preventing re-run"
**Solution:** Clear checkpoints:
```bash
python scripts/run_pipeline_enhanced.py --clear-checkpoints
```

---

## 📈 Monitoring & Profiling

### Logs
All logs are saved to:
```
logs/phase2/phase2_run_YYYYMMDD_HHMMSS.log
```

### Profiling Reports
Performance profiling reports:
```
logs/profiling/phase2_profile_YYYYMMDD_HHMMSS.txt
```

### Pipeline Report
Comprehensive execution report:
```
PIPELINE_REPORT.md
```

---

## 🎯 Expected Runtime

**On Standard System (8 cores, 16GB RAM):**
- Preprocessing: ~15-20 min
- Normalization: ~5-8 min
- Validation: ~3-5 min
- Feature Engineering: ~8-12 min (without multiprocessing)
- Feature Engineering: ~2-4 min (with multiprocessing)
- Splitting: ~2-3 min

**Total:** ~30-50 min for full pipeline

**On Kaggle (2 cores, 16GB RAM):**
- Total: ~45-75 min

---

## ✅ Success Criteria

After successful pipeline execution, verify:

1. ✅ `datasets/validated/validated.jsonl` exists (~634k records)
2. ✅ `datasets/features/features_static.csv` exists (45 features)
3. ✅ `datasets/preprocessed/train.jsonl` exists (70% split)
4. ✅ `PIPELINE_REPORT.md` generated with statistics
5. ✅ No failed stages in checkpoint file
6. ✅ Validation pass rate > 75%
7. ✅ All integrity checks passed

---

## 🔗 Next Steps

### Model Training
```python
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# Load features
df = pd.read_parquet('datasets/features/features_static.parquet')

# Separate features and labels
X = df.drop(['id', 'language', 'is_vulnerable', 'dataset'], axis=1)
y = df['is_vulnerable']

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)
```

### Evaluation
```bash
python scripts/ml/evaluate_model.py \
  --model models/rf_model.pkl \
  --test-data datasets/preprocessed/test.jsonl
```

---

## 📚 Additional Resources

- **Architecture Diagram:** `docs/0. ARCHITECTURE_DIAGRAM.md`
- **ML Summary:** `docs/3. ML_COMPLETE_SUMMARY.md`
- **Schema Documentation:** `scripts/utils/schema_utils.py`
- **Dataset Portfolio:** `datasets/COMPLETE_DATASET_PORTFOLIO.md`

---

## 🆘 Support

For issues or questions:
1. Check logs in `logs/phase2/`
2. Review `PIPELINE_REPORT.md`
3. Check validation reports in `datasets/validated/`
4. Contact: CodeGuardian Team (DPIIT PS-1)

---

**Last Updated:** 2025-10-12
**Pipeline Version:** 3.2.0 (Production-Grade Enhanced)
