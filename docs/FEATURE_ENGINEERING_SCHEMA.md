# Feature Engineering Schema - Complete Field Mapping

## 🎯 Key Change (Version 3.3.0)

**BEFORE (v3.2.0):** Only kept 4 fields + computed 32 features = 36 total columns
**NOW (v3.3.0):** Keeps ALL 32 schema fields + computes 32+ features = **64+ total columns**

## ✅ What Changed

### Previous Behavior (WRONG ❌)
```python
enriched = {
    "id": ...,
    "language": ...,
    "is_vulnerable": ...,
    "dataset": ...,
    # 32 computed features added here
}
# ❌ Lost: code, cwe_id, description, vuln_line_start, etc.
```

### New Behavior (CORRECT ✅)
```python
enriched = {
    # ═══ ALL 32 ORIGINAL SCHEMA FIELDS PRESERVED ═══
    "id": ...,
    "language": ...,
    "dataset": ...,
    "code": ...,                    # ✅ PRESERVED
    "is_vulnerable": ...,
    "cwe_id": ...,                  # ✅ PRESERVED
    "cve_id": ...,                  # ✅ PRESERVED
    "description": ...,             # ✅ PRESERVED
    "attack_type": ...,             # ✅ PRESERVED
    "severity": ...,                # ✅ PRESERVED
    "review_status": ...,           # ✅ PRESERVED
    "func_name": ...,               # ✅ PRESERVED
    "file_name": ...,               # ✅ PRESERVED
    "project": ...,                 # ✅ PRESERVED
    "commit_id": ...,               # ✅ PRESERVED
    "source_file": ...,             # ✅ PRESERVED
    "source_row_index": ...,        # ✅ PRESERVED
    "vuln_line_start": ...,         # ✅ PRESERVED
    "vuln_line_end": ...,           # ✅ PRESERVED
    "context_before": ...,          # ✅ PRESERVED
    "context_after": ...,           # ✅ PRESERVED
    "repo_url": ...,                # ✅ PRESERVED
    "commit_url": ...,              # ✅ PRESERVED
    "function_length": ...,         # ✅ PRESERVED
    "num_params": ...,              # ✅ PRESERVED
    "num_calls": ...,               # ✅ PRESERVED
    "imports": ...,                 # ✅ PRESERVED
    "code_sha256": ...,             # ✅ PRESERVED
    "normalized_timestamp": ...,    # ✅ PRESERVED
    "language_stage": ...,          # ✅ PRESERVED
    "verification_source": ...,     # ✅ PRESERVED
    "source_dataset_version": ...,  # ✅ PRESERVED
    "merge_timestamp": ...,         # ✅ PRESERVED
    
    # ═══ PLUS 32+ NEW COMPUTED FEATURES ═══
    "loc": ...,
    "cyclomatic_complexity": ...,
    "shannon_entropy": ...,
    # ... etc (see below for full list)
}
```

## 📊 Complete Output Schema (64+ Fields)

### Group 1: Original Schema Fields (32 fields)
From `validated.jsonl` (UNIFIED_SCHEMA):

| Field | Type | Description |
|-------|------|-------------|
| `id` | str | Unique identifier (UUID) |
| `language` | str | Programming language |
| `dataset` | str | Source dataset name |
| `code` | str | **Source code snippet** |
| `is_vulnerable` | int | Vulnerability label (0/1) |
| `cwe_id` | str | CWE identifier |
| `cve_id` | str | CVE identifier |
| `description` | str | Vulnerability description |
| `attack_type` | str | Attack classification |
| `severity` | str | Risk level |
| `review_status` | str | Quality flag |
| `func_name` | str | Function name |
| `file_name` | str | Source file name |
| `project` | str | Repository name |
| `commit_id` | str | Git commit hash |
| `source_file` | str | Original input file |
| `source_row_index` | int | Row number in source |
| `vuln_line_start` | int | Vulnerability start line |
| `vuln_line_end` | int | Vulnerability end line |
| `context_before` | str | Code before vulnerability |
| `context_after` | str | Code after vulnerability |
| `repo_url` | str | Repository URL |
| `commit_url` | str | Commit URL |
| `function_length` | int | Total function lines |
| `num_params` | int | Function parameters |
| `num_calls` | int | Function calls count |
| `imports` | str | Import statements |
| `code_sha256` | str | Code hash |
| `normalized_timestamp` | str | Normalization timestamp |
| `language_stage` | str | Language version |
| `verification_source` | str | Verification method |
| `source_dataset_version` | str | Dataset version |
| `merge_timestamp` | str | Merge timestamp |

### Group 2: New Computed Features (32+ fields)

#### A. Basic Code Metrics (9 features)
| Feature | Type | Description |
|---------|------|-------------|
| `loc` | int | Lines of code (non-empty) |
| `total_lines` | int | Total lines including empty |
| `num_tokens` | int | Token count |
| `avg_line_len` | float | Average line length |
| `max_line_len` | int | Maximum line length |
| `comment_density` | float | Comment ratio [0-1] |
| `function_length` | int | Function size |
| `total_chars` | int | Character count |
| `whitespace_ratio` | float | Whitespace percentage |

#### B. Lexical Features (7 features)
| Feature | Type | Description |
|---------|------|-------------|
| `keyword_count` | int | Programming keywords |
| `identifier_count` | int | Identifiers (variables) |
| `numeric_count` | int | Numeric literals |
| `string_count` | int | String literals |
| `special_char_count` | int | Special characters |
| `operator_count` | int | Operators (+, -, *, etc.) |
| `security_keyword_count` | int | Security-related keywords |

#### C. Complexity Metrics (5 features)
| Feature | Type | Description |
|---------|------|-------------|
| `cyclomatic_complexity` | int | McCabe complexity |
| `nesting_depth` | int | Maximum nesting level |
| `ast_depth` | int | AST depth estimate |
| `conditional_count` | int | If/else statements |
| `loop_count` | int | Loop statements |

#### D. Diversity & Entropy (3 features)
| Feature | Type | Description |
|---------|------|-------------|
| `token_diversity` | float | Unique tokens / total |
| `shannon_entropy` | float | Information entropy |
| `identifier_entropy` | float | Identifier entropy |

#### E. Ratio Features (5 features)
| Feature | Type | Description |
|---------|------|-------------|
| `comment_code_ratio` | float | Comments / code |
| `identifier_keyword_ratio` | float | Identifiers / keywords |
| `operator_operand_ratio` | float | Operators / operands |
| `token_density` | float | Tokens per line |
| `security_keyword_ratio` | float | Security keywords / total |

#### F. Binary Indicators (3 features)
| Feature | Type | Description |
|---------|------|-------------|
| `has_cwe` | int | Has CWE ID? (0/1) |
| `has_cve` | int | Has CVE ID? (0/1) |
| `has_description` | int | Has description? (0/1) |

## 📁 Output Files

### 1. `features_static.csv`
- **64+ columns** (32 schema + 32+ computed)
- **634,359 rows**
- Size: ~150-200 MB (depending on code length)
- Contains actual source code in `code` column

### 2. `features_static.parquet`
- Same structure as CSV
- Compressed (snappy)
- Faster to load for ML training

### 3. `features_all.jsonl`
- Complete records with all fields
- Human-readable format
- Good for inspection/debugging

### 4. `stats_features.json`
- Statistics for all computed features
- Min/max/mean values
- Dataset distribution

## 🚀 Usage for ML

### For Training Models
```python
import pandas as pd

# Load features with ALL fields
df = pd.read_csv('features_static.csv')

# Original schema fields available
print(df[['code', 'cwe_id', 'description', 'severity']].head())

# Computed features available
print(df[['cyclomatic_complexity', 'shannon_entropy', 'loc']].head())

# Select features for ML model
feature_cols = [
    'loc', 'cyclomatic_complexity', 'nesting_depth',
    'token_diversity', 'shannon_entropy', 'keyword_count',
    # ... add more features
]
X = df[feature_cols]
y = df['is_vulnerable']
```

### For Analysis
```python
# Find specific CWE vulnerabilities
cwe_79 = df[df['cwe_id'] == 'CWE-79']  # XSS vulnerabilities

# Analyze by severity
critical = df[df['severity'] == 'critical']

# Inspect code for specific record
print(df.loc[df['id'] == 'some-id', 'code'].values[0])
```

## ⚙️ How to Re-run

```bash
# On Kaggle, pull latest code
cd /kaggle/working/codeGuardian
git pull origin main

# Run feature engineering with multiprocessing
python scripts/features/feature_engineering.py \
    --input /kaggle/input/merged-dataset/merged_normalized.jsonl \
    --output-csv features_static.csv \
    --multiprocessing
```

**Expected runtime:** ~10 minutes for 634K records

## ✅ Verification

After running, verify the output has all fields:

```python
import pandas as pd

df = pd.read_csv('/kaggle/working/datasets/features/features_static.csv')

print(f"Total columns: {len(df.columns)}")  # Should be 64+
print(f"Total rows: {len(df)}")              # Should be 634,359

# Check schema fields preserved
schema_fields = ['code', 'cwe_id', 'description', 'vuln_line_start']
for field in schema_fields:
    assert field in df.columns, f"Missing schema field: {field}"

# Check computed features added
computed_fields = ['cyclomatic_complexity', 'shannon_entropy', 'loc']
for field in computed_fields:
    assert field in df.columns, f"Missing computed field: {field}"

print("✅ All fields present!")
```

---

**Version:** 3.3.0  
**Date:** 2025-10-12  
**Status:** ✅ Production Ready
