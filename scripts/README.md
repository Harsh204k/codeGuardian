# CodeGuardian Data Processing Pipeline (v3.0 - Modular Architecture)

**🆕 NEW IN v3.0:** This pipeline has been refactored into a modular architecture with dynamic phase orchestration! See [Refactoring Guide](../docs/REFACTORING_GUIDE.md) for details.

Complete modular data processing pipeline for preprocessing and normalizing 7 vulnerability datasets into a unified format ready for model training and evaluation.

## 🚀 Quick Start (New Orchestrator)

**Use the new dynamic pipeline orchestrator for one-command execution:**
```bash
python scripts/run_pipeline.py
```

**Advanced options:**
```bash
# Skip already-completed phases
python scripts/run_pipeline.py --skip preprocessing

# Resume from specific phase
python scripts/run_pipeline.py --resume validation

# Debug mode
python scripts/run_pipeline.py --log-level DEBUG
```

See [Quick Start Guide](../docs/QUICKSTART.md) for more examples.

---

## 📁 New Modular Structure (v3.0)

```
scripts/
├── preprocessing/       # Phase 2.1: Dataset-specific preprocessing
│   ├── prepare_devign.py, prepare_zenodo.py, etc.
├── normalization/       # Phase 2.2: Merge & deduplicate
│   └── normalize_all_datasets.py
├── validation/          # Phase 2.3a: Validate data quality
│   └── validate_normalized_data.py
├── features/            # Phase 2.3b: Extract ML features
│   └── feature_engineering.py
├── splitting/           # Phase 2.3c: Create train/val/test splits
│   └── split_datasets.py
├── utils/              # Shared utilities (unchanged)
│   ├── io_utils.py, schema_utils.py, text_cleaner.py
├── run_pipeline.py     # 🆕 Dynamic orchestrator (USE THIS!)
└── test_refactored_structure.py  # 🆕 Verification tests
```

**Benefits:**
- ✅ Dynamic module discovery with `importlib`
- ✅ Phase dependency management
- ✅ Skip/resume functionality
- ✅ Comprehensive logging
- ✅ Clean separation of concerns

---

## 📋 Table of Contents

- [Overview](#overview)
- [Datasets](#datasets)
- [Pipeline Architecture](#pipeline-architecture)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Phase 1: Data Preprocessing & Normalization](#phase-1-data-preprocessing--normalization)
  - [Phase 2: Validation, Feature Engineering & Splitting](#phase-2-validation-feature-engineering--splitting)
- [Unified Schema](#unified-schema)
- [Output Structure](#output-structure)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

This pipeline processes 7 different vulnerability datasets into a standardized format:

1. **Devign** – Function-level vulnerability commits (FFmpeg, Qemu)
2. **Zenodo** – Multi-language dataset with CWE/CVE metadata (8 languages)
3. **DiverseVul** – Multi-language, CWE-tagged with metadata and label noise info
4. **github_ppakshad** – Function-level training data with static metrics M1-M15
5. **CodeXGLUE** – Binary classification validation set derived from Devign
6. **MegaVul** – Graph-based C/C++ dataset (placeholder - to be added)
7. **Juliet** – Synthetic NIST benchmark for robustness and CWE classification

## 📊 Datasets

### Devign

- **Source**: FFmpeg, Qemu projects
- **Language**: C
- **Files**: `ffmpeg.csv`, `qemu.csv`, `function.json`
- **Size**: ~27K functions

### Zenodo Multi-language

- **Languages**: C, C++, Go, Java, JavaScript, PHP, Python, Ruby
- **Files**: `data_<language>.csv`
- **Features**: CWE/CVE metadata

### DiverseVul

- **Source**: Multi-language open-source projects
- **Files**: `diversevul.json`, `diversevul_metadata.json`, `label_noise/`
- **Features**: CWE tags, metadata, label noise spreadsheet

### github_ppakshad

- **Source**: GitHub repositories
- **Files**: `main_dataset.xlsx`
- **Features**: Static metrics M1-M15, function-level data

### CodeXGLUE Defect Detection

- **Source**: Derived from Devign
- **Files**: `train.txt`, `valid.txt`, `test.txt`
- **Format**: `<label> <code>` per line

### MegaVul

- **Status**: Placeholder (dataset to be added)
- **Expected**: Graph-based C/C++ vulnerability data

### Juliet

- **Source**: NIST CWE test cases
- **Languages**: C, C++, Java, C#
- **Structure**: Organized by CWE, contains good/bad examples

## 🏗️ Pipeline Architecture

```text
scripts/
├── utils/                          # Shared utility modules
│   ├── __init__.py
│   ├── schema_utils.py            # Schema mapping & validation
│   ├── io_utils.py                # File I/O operations
│   └── text_cleaner.py            # Code cleaning & sanitization
│
├── PHASE 1: Data Preprocessing & Normalization
├── prepare_devign.py              # Devign preprocessor
├── prepare_zenodo.py              # Zenodo preprocessor
├── prepare_diversevul.py          # DiverseVul preprocessor
├── prepare_github_ppakshad.py     # GitHub ppakshad preprocessor
├── prepare_codexglue.py           # CodeXGLUE preprocessor
├── prepare_megavul.py             # MegaVul preprocessor (placeholder)
├── prepare_juliet.py              # Juliet preprocessor
├── normalize_all_datasets.py      # Universal normalization
│
├── PHASE 2: Validation, Feature Engineering & Splitting
├── validate_normalized_data.py    # Schema validation & cleaning
├── feature_engineering.py         # Extract ML features
├── split_datasets.py              # Train/val/test splitting
│
└── run_pipeline.py                # Master orchestration script
```

### Workflow

```
┌─────────────────────────────────────────────────────────────┐
│  Raw Datasets (CSV, JSON, JSONL, Excel, TXT)               │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 1: Individual Dataset Preprocessing                 │
│  • Load raw files                                           │
│  • Extract core fields                                      │
│  • Clean & validate code                                    │
│  • Save to processed/raw_cleaned.jsonl                      │
│  • Generate stats.json                                      │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 2: Universal Normalization                          │
│  • Map to unified schema                                    │
│  • Normalize fields (language, CWE, CVE)                    │
│  • Validate records                                         │
│  • Optional deduplication                                   │
│  • Generate unified dataset & statistics                    │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  Output: Unified Dataset Ready for Training                │
│  • datasets/unified/processed_all.jsonl                     │
│  • datasets/unified/stats_summary.csv                       │
│  • datasets/unified/schema.json                             │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

Ensure you have the required packages:

```bash
pip install pandas openpyxl tqdm
```

### Run Complete Pipeline

```bash
# Process all datasets
python scripts/run_pipeline.py

# Quick test with limited records
python scripts/run_pipeline.py --quick-test

# Process specific datasets
python scripts/run_pipeline.py --datasets devign zenodo codexglue
```

## 📖 Usage

### Phase 1: Data Preprocessing & Normalization

#### Individual Dataset Processing

Each dataset can be processed independently:

```bash
# Devign
python scripts/prepare_devign.py

# Zenodo (all languages)
python scripts/prepare_zenodo.py

# Zenodo (specific languages)
python scripts/prepare_zenodo.py --languages Python Java JavaScript

# DiverseVul
python scripts/prepare_diversevul.py

# DiverseVul (filter noisy labels)
python scripts/prepare_diversevul.py --filter-noisy

# GitHub ppakshad
python scripts/prepare_github_ppakshad.py

# CodeXGLUE
python scripts/prepare_codexglue.py

# Juliet (C only)
python scripts/prepare_juliet.py --languages c

# Juliet (multiple languages)
python scripts/prepare_juliet.py --languages c java csharp
```

#### Universal Normalization

After preprocessing individual datasets:

#### Master Pipeline (Recommended)

```bash
# Complete pipeline with new unified orchestrator
python scripts/run_pipeline.py

# Quick test with limited records
python scripts/run_pipeline.py --quick-test

# With specific options
python scripts/run_pipeline.py \
    --datasets devign zenodo codexglue \
    --max-records 1000 \
    --continue-on-error

# Skip validation for faster processing
python scripts/run_pipeline.py --skip-validation

# Custom output directory
python scripts/run_pipeline.py --output-dir /path/to/output
```

#### Legacy Normalization (if needed)

```bash
# Normalize all datasets
python scripts/normalize_all_datasets.py

# Normalize with deduplication
python scripts/normalize_all_datasets.py --deduplicate

# Normalize specific datasets
python scripts/normalize_all_datasets.py --datasets devign zenodo diversevul
```

Note: Without deduplication (use master orchestrator)

```bash
python scripts/run_pipeline.py --no-deduplicate
```

### Phase 2: Validation, Feature Engineering & Splitting

After Phase 1 completes, run Phase 2 to prepare model-ready datasets.

#### Step 1: Data Validation

Validate the normalized dataset against the unified schema:

```bash
# Run validation with defaults
python scripts/validate_normalized_data.py

# Custom paths
python scripts/validate_normalized_data.py \
    --input-file ../datasets/unified/processed_all.jsonl \
    --output-file ../datasets/unified/validated.jsonl \
    --report-file ../datasets/unified/validation_report.json

# Adjust minimum code length
python scripts/validate_normalized_data.py --min-code-length 20

# Keep duplicates
python scripts/validate_normalized_data.py --no-remove-duplicates
```

**Validation checks:**
- Required fields presence (`id`, `language`, `code`, `label`, `source_dataset`)
- Label validity (must be 0 or 1)
- Code quality (minimum length, non-empty)
- Duplicate detection (SHA-256 hash on code)
- Language normalization
- CWE/CVE format validation

**Outputs:**
- `datasets/unified/validated.jsonl` - Clean, validated records
- `datasets/unified/validation_report.json` - Comprehensive statistics

#### Step 2: Feature Engineering

Extract engineered features for ML training:

```bash
# Run feature engineering with defaults
python scripts/feature_engineering.py

# Custom paths
python scripts/feature_engineering.py \
    --input-file ../datasets/unified/validated.jsonl \
    --output-file ../datasets/features/features_all.jsonl \
    --stats-file ../datasets/features/stats_features.json
```

**Features extracted:**
- **Code metrics**: LOC, token count, average line length, comment density
- **Lexical features**: keyword counts, identifier counts, numeric/string literals
- **Complexity metrics**: cyclomatic complexity, nesting depth
- **Entropy**: Shannon entropy of code tokens

**Outputs:**
- `datasets/features/features_all.jsonl` - Feature-enriched records
- `datasets/features/stats_features.json` - Feature statistics and correlations

#### Step 3: Dataset Splitting

Split into stratified train/validation/test sets:

```bash
# Run splitting with defaults (80/10/10)
python scripts/split_datasets.py

# Custom split ratios
python scripts/split_datasets.py \
    --train-ratio 0.7 \
    --val-ratio 0.15 \
    --test-ratio 0.15

# Custom seed for reproducibility
python scripts/split_datasets.py --seed 12345

# Custom paths
python scripts/split_datasets.py \
    --input-file ../datasets/features/features_all.jsonl \
    --output-dir ../datasets/processed \
    --summary-file ../datasets/processed/split_summary.json
```

**Features:**
- Stratified splitting (maintains label balance across splits)
- Reproducible (default seed=42)
- Language and dataset distribution tracking

**Outputs:**
- `datasets/processed/train.jsonl` - Training set (80%)
- `datasets/processed/val.jsonl` - Validation set (10%)
- `datasets/processed/test.jsonl` - Test set (10%)
- `datasets/processed/split_summary.json` - Split statistics

#### Complete Phase 2 Pipeline

Run all Phase 2 steps sequentially:

```bash
# Validate
python scripts/validate_normalized_data.py

# Extract features
python scripts/feature_engineering.py

# Split dataset
python scripts/split_datasets.py
```

## 🗂️ Unified Schema

All records follow this standardized schema v2.0.0:

```json
{
  "id": "dataset_00001_hash",
  "language": "C|C++|Java|Python|etc.",
  "code": "source code snippet",
  "label": 0,
  "source_dataset": "dataset_name",
  "func_name": "function_name|null",
  "description": "Brief description|null",
  "cwe_id": "CWE-79|null",
  "cve_id": "CVE-2021-12345|null",
  "project": "project_name|null",
  "file_name": "filename.c|null",
  "commit_id": "git_commit_hash|null"
}
```

### Field Descriptions

| Field              | Type   | Required | Description                                               |
| ------------------ | ------ | -------- | --------------------------------------------------------- |
| `id`             | string | Yes      | Globally unique identifier with dataset prefix            |
| `language`       | string | Yes      | Programming language (auto-inferred from file extensions) |
| `code`           | string | Yes      | Source code snippet                                       |
| `label`          | int    | Yes      | Binary label: 0 (safe) or 1 (vulnerable)                  |
| `source_dataset` | string | Yes      | Source dataset name                                       |
| `func_name`      | string | No       | Function or method name                                   |
| `description`    | string | No       | Brief description of the vulnerability or code            |
| `cwe_id`         | string | No       | CWE identifier (format: CWE-XXX)                          |
| `cve_id`         | string | No       | CVE identifier (format: CVE-YYYY-XXXXX)                   |
| `project`        | string | No       | Project or repository name                                |
| `file_name`      | string | No       | Source file name                                          |
| `commit_id`      | string | No       | Git commit hash                                           |

## 📁 Output Structure

The pipeline produces outputs organized across three main directories:

### Phase 1 Outputs (Preprocessing & Normalization)

Per-dataset processed outputs are written under each dataset folder:

```text
datasets/
├── devign/
│   └── processed/
│       ├── raw_cleaned.jsonl        # Cleaned records from preprocessing
│       └── stats.json               # Dataset-specific statistics
├── zenodo/
│   └── processed/
│       ├── raw_cleaned.jsonl
│       └── stats.json
├── diversevul/
│   └── processed/
│       ├── raw_cleaned.jsonl
│       └── stats.json
├── github_ppakshad/
│   └── processed/
│       ├── raw_cleaned.jsonl
│       └── stats.json
├── codexglue_defect/
│   └── processed/
│       ├── raw_cleaned.jsonl
│       └── stats.json
├── megavul/
│   └── processed/
│       └── raw_cleaned.jsonl        # Placeholder: may be empty until dataset added
├── juliet/
│   └── processed/
│       ├── raw_cleaned.jsonl
│       └── stats.json
└── unified/                          # Phase 1 unified outputs
    ├── processed_all.jsonl          # All records in unified format
    ├── stats_overall.json           # Overall unified statistics
    ├── stats_summary.csv            # Per-dataset summary CSV
    └── schema.json                  # Schema documentation (v2.0.0)
```

### Phase 2 Outputs (Validation, Features & Splits)

Phase 2 produces model-ready datasets:

```text
datasets/
├── unified/                          # Validation outputs
│   ├── validated.jsonl              # ✅ Clean, validated records (Phase 2.1)
│   └── validation_report.json       # Validation statistics and errors
│
├── features/                         # Feature engineering outputs
│   ├── features_all.jsonl           # ✅ Feature-enriched records (Phase 2.2)
│   └── stats_features.json          # Feature statistics and correlations
│
└── processed/                        # Final train/val/test splits
    ├── train.jsonl                  # ✅ Training set - 80% (Phase 2.3)
    ├── val.jsonl                    # ✅ Validation set - 10%
    ├── test.jsonl                   # ✅ Test set - 10%
    └── split_summary.json           # Split statistics and distributions
```

### Complete Pipeline Outputs

After running the complete pipeline (Phase 1 + Phase 2), the key model-ready files are:

- **For training**: `datasets/processed/train.jsonl`
- **For validation**: `datasets/processed/val.jsonl`
- **For testing**: `datasets/processed/test.jsonl`

Each record includes:
- All unified schema fields (id, language, code, label, etc.)
- Extracted features (LOC, complexity, entropy, etc.)
- Stratified label distribution

## 🔧 Advanced Usage

### Custom Field Mapping

To customize field mappings for a dataset, edit `normalize_all_datasets.py`:

```python
DATASETS = {
    'my_dataset': {
        'path': 'my_dataset/processed/raw_cleaned.jsonl',
        'field_mapping': {
            'code': 'source_code',      # Map 'source_code' -> 'code'
            'is_vulnerable': 'label',   # Map 'label' -> 'is_vulnerable'
            'language': 'lang'          # Map 'lang' -> 'language'
        }
    }
}
```

### Adding a New Dataset

1. Create preprocessing script: `prepare_mydataset.py`
2. Follow the pattern from existing scripts
3. Use utility functions from `utils/`
4. Add to `PREPROCESSING_SCRIPTS` in the master orchestrator (`run_pipeline.py`)
5. Add to `DATASETS` in `normalize_all_datasets.py`

### Deduplication Strategies

The pipeline supports SHA-256 based deduplication:

```python
from utils.schema_utils import deduplicate_by_code_hash

# Deduplicate records
unique_records = deduplicate_by_code_hash(all_records)
```

### Label Noise Filtering

For DiverseVul, filter noisy labels:

```bash
python scripts/prepare_diversevul.py --filter-noisy
```

## 🐛 Troubleshooting

### Common Issues

### 1. Missing Dependencies

```bash
pip install pandas openpyxl tqdm pyyaml
```

### 2. File Not Found Errors

- Ensure raw dataset files are in correct directories
- Check paths: `datasets/<dataset_name>/raw/`

### 3. Memory Issues with Large Datasets

- Use `--max-records` to limit processing
- Process datasets individually instead of all at once

### 4. Encoding Errors

- The pipeline handles multiple encodings automatically
- Check `utils/io_utils.py` for safe_read_text function

### 5. Invalid Records

- Check validation errors in logs
- Review `stats.json` for filtered record counts
- Ensure code length > 10 characters

### Logging

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Testing

Quick test mode processes only 100 records per dataset:

```bash
python scripts/run_pipeline.py --quick-test
```

## 📈 Statistics & Reporting

Each preprocessing script generates:

- **Record counts**: Total, vulnerable, non-vulnerable
- **Language distribution**: Records per language
- **CWE coverage**: Unique CWEs, top CWEs
- **Code metrics**: Average code length

The unified dataset provides:

- **Cross-dataset statistics**: Combined metrics
- **Per-dataset breakdown**: Individual contributions
- **Quality metrics**: Validation results, duplicates removed

## 🔗 Integration with Training

Use the unified dataset with training scripts:

```python
from utils.io_utils import read_jsonl

# Load unified dataset (canonical unified path)
records = list(read_jsonl('datasets/unified/processed_all.jsonl'))

# Filter by language
python_records = [r for r in records if r['language'] == 'Python']

# Filter by CWE
sql_injection = [r for r in records if r.get('cwe_id') == 'CWE-89']

# Split by vulnerability
vulnerable = [r for r in records if r['label'] == 1]
safe = [r for r in records if r['label'] == 0]

# Access function names
functions = [r['func_name'] for r in records if r.get('func_name')]
```

## 📝 Notes

- **MegaVul**: Placeholder implementation - update when dataset becomes available
- **Juliet**: Large dataset - use `--max-records` for testing
- **Language Normalization**: Automatic mapping (e.g., `cpp` → `C++`, `js` → `JavaScript`)
- **CWE/CVE Format**: Automatically normalized to standard formats

## 🎯 Next Steps

After running the pipeline:

1. Review unified dataset: `datasets/unified/processed_all.jsonl`
2. Check statistics: `datasets/unified/stats_summary.csv`
3. Validate schema: `datasets/unified/schema.json`
4. Use for training:
   - `ml/codeBERT/train_codebert_lora.py`
   - `ml/hybrid/train_codet5_qloRA.py`
   - `ml/xgboost/train_xgboost.py`

---
