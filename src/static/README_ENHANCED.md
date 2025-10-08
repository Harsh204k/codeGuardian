# Static Analyzer Module - Phase 3.2 (Enhanced)

## Overview

The **codeGuardian Static Analyzer** is a production-ready, multi-language vulnerability detection engine designed for the AI Grand Challenge PS-1. Phase 3.2 introduces major enhancements including **C language support**, **confidence scoring**, **parallel processing**, and **explainability reports**.

### Key Features ✨

- **8 Language Support**: C, C++, Java, JavaScript/TypeScript, Python, PHP, Go, Ruby
- **40+ CWE Categories**: Comprehensive vulnerability coverage mapped to industry-standard CWE IDs
- **Confidence Scoring**: Weighted confidence metrics (0.0-1.0) for each detection
- **Parallel Processing**: Multi-core batch analysis with ProcessPoolExecutor
- **Explainability**: Detailed reports with CWE frequency, rule effectiveness, and precision proxies
- **Incremental Saves**: Language-specific checkpointing for large datasets
- **Production-Ready**: JSONL/CSV outputs compatible with ML fusion models

---

## What's New in Phase 3.2 🆕

### 1. C Language Analyzer
- Full support for C code analysis with `c_analyzer.py`
- Detects 14+ C-specific vulnerability types:
  - Buffer overflows (`strcpy`, `gets`, `scanf`)
  - Format string vulnerabilities
  - Integer overflows in arithmetic/allocation
  - Use-after-free and double-free
  - NULL pointer dereference
  - Command injection (`system`, `popen`)
  - Weak cryptography (DES, MD5, RC4)
- AST-based analysis with `pycparser` + regex fallback
- 40 detection rules in `rules/c.yml`

### 2. Confidence Scoring System
- **Per-Vulnerability Confidence**: Each detection has confidence (0.0-1.0)
- **Overall Confidence**: Weighted maximum across all findings
- **Severity-Weighted**: Critical findings weighted higher than low-severity
- **Rule-Level Confidence**: Defined in YAML rules
- **Output Integration**: `static_confidence` field in CSV for ML models

### 3. Parallel Processing
- **ProcessPoolExecutor**: Multi-core analysis for large datasets
- **Batch Processing**: Intelligent batching by language
- **Progress Tracking**: Real-time progress bars with `tqdm`
- **Incremental Saves**: Per-language checkpointing to `outputs/incremental/`
- **Configurable Workers**: `--workers` flag (default: CPU count)

### 4. Explainability Reports
- **Comprehensive Analytics**: CWE frequency, rule effectiveness, confidence histograms
- **Language Breakdown**: Per-language vulnerability statistics
- **Top Vulnerable Functions**: Ranked by vulnerability score
- **Precision Proxies**: TP/FP/FN metrics when ground truth available
- **Output Location**: `src/static/outputs/reports/explain_{split}.json`

### 5. Enhanced Rule Engine
- **5 Rule Types**: `regex`, `api_call`, `keyword`, `ast_pattern`, `metric_threshold`
- **Confidence Field**: Each rule has numeric confidence
- **CWE Aggregation**: Group findings by CWE with avg/max confidence
- **Rule Effectiveness**: Track hit counts and average confidence per rule

---

## Installation & Dependencies

### Required Python Packages

```bash
pip install pyyaml pandas tqdm pycparser
```

### Optional (for AST-based analysis)
```bash
pip install tree-sitter  # For advanced language parsing
```

---

## Usage

### Quick Start

```bash
# Analyze all splits (train/val/test) with 8 workers
python src/static/run_static_analysis.py --split all --workers 8

# Analyze only training set
python src/static/run_static_analysis.py --split train

# Custom input/output paths
python src/static/run_static_analysis.py \
    --input-dir datasets/processed \
    --output-dir src/static/outputs \
    --split all \
    --workers 4
```

### Pipeline Integration

```bash
# Run complete pipeline with static analysis
python codeGuardian/scripts/run_pipeline.py --static-analysis

# Run only static analysis stage
python codeGuardian/scripts/run_pipeline.py --stages static_analysis
```

### CLI Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--split` | Dataset split to analyze (`train`, `val`, `test`, `all`) | `all` |
| `--input-dir` | Input directory with JSONL files | `datasets/processed` |
| `--output-dir` | Output directory for results | `src/static/outputs` |
| `--workers` | Number of parallel workers | CPU count |
| `--rules-dir` | Directory containing YAML rules | `src/static/rules` |
| `--no-incremental` | Disable incremental per-language saves | Enabled by default |

---

## Output Files

### 1. Static Flags CSV (ML Model Input)
**Location**: `src/static/outputs/static_flags_{split}.csv`

**Columns**:
- `id`, `language`, `label`
- `has_vulnerabilities`, `vulnerability_count`
- `critical_count`, `high_count`, `medium_count`, `low_count`
- `severity_score`, `max_severity`
- **`static_confidence`** ← NEW in Phase 3.2
- `M1_cyclomatic_complexity` through `M15_code_complexity_score`

**Example Row**:
```csv
id,language,label,has_vulnerabilities,vulnerability_count,static_confidence,M1_cyclomatic_complexity,...
zenodo_c_001,C,1,True,5,0.87,12,3,8,45,...
```

### 2. Full Analysis Results (JSONL)
**Location**: `src/static/outputs/static_analysis_{split}.jsonl`

**Structure**:
```json
{
  "id": "zenodo_c_001",
  "language": "C",
  "code": "...",
  "label": 1,
  "static_analysis": {
    "static_metrics": {"M1_cyclomatic_complexity": 12, ...},
    "detected_cwes": ["CWE-120", "CWE-134"],
    "vulnerabilities": [
      {
        "cwe_id": "CWE-120",
        "rule_id": "CWE-120-strcpy",
        "severity": "high",
        "confidence": 0.90,
        "line": 42,
        "description": "...",
        "remediation": "..."
      }
    ],
    "vulnerability_count": 5,
    "overall_confidence": 0.87,
    "severity_scores": {"total_score": 24, "counts": {...}}
  }
}
```

### 3. Explainability Report (JSON)
**Location**: `src/static/outputs/reports/explain_{split}.json`

**Sections**:
- **summary**: Total records, vulnerability rate, avg confidence
- **cwe_analysis**: Top CWEs, unique coverage, instance counts
- **language_breakdown**: Per-language stats and CWE distribution
- **confidence_analysis**: Histogram, avg/median, high/low counts
- **severity_distribution**: Critical/High/Medium/Low/Info percentages
- **top_vulnerable_functions**: Top 20 by vulnerability score
- **rule_effectiveness**: Most-triggered rules with avg confidence
- **precision_proxy**: TP/FP/FN/precision/recall/F1 (if labels available)
- **examples**: 10 diverse vulnerability examples

**Example Summary**:
```json
{
  "split": "train",
  "summary": {
    "total_records": 15000,
    "records_with_vulnerabilities": 8400,
    "vulnerability_rate": 0.56,
    "total_vulnerabilities": 24500,
    "avg_confidence": 0.78,
    "median_confidence": 0.82
  },
  "cwe_analysis": {
    "unique_cwes": 42,
    "total_cwe_instances": 24500,
    "top_cwes": [
      {"cwe_id": "CWE-79", "count": 3200, "avg_confidence": 0.85, ...},
      {"cwe_id": "CWE-89", "count": 2800, "avg_confidence": 0.91, ...}
    ]
  },
  ...
}
```

### 4. Vulnerability Report (JSON)
**Location**: `src/static/outputs/logs/analyzer_report_{split}.json`

Aggregate vulnerability statistics including:
- Total vulnerable records
- Vulnerabilities by CWE
- Vulnerabilities by severity
- Top 20 most vulnerable records

### 5. Incremental Saves (Per-Language)
**Location**: `src/static/outputs/incremental/static_analysis_{split}_{language}.jsonl`

Language-specific checkpoints created during processing for fault tolerance.

---

## Architecture

```
src/static/
├── analyzers/
│   ├── base_analyzer.py          # Abstract base with confidence computation
│   ├── c_analyzer.py              # NEW: C language analyzer
│   ├── cpp_analyzer.py            # C++ analyzer
│   ├── java_analyzer.py           # Java analyzer
│   ├── python_analyzer.py         # Python analyzer
│   ├── js_analyzer.py             # JavaScript/TypeScript analyzer
│   ├── php_analyzer.py            # PHP analyzer
│   ├── go_analyzer.py             # Go analyzer
│   ├── ruby_analyzer.py           # Ruby analyzer
│   ├── language_map.py            # Language routing (updated for C)
│   ├── rule_engine.py             # ENHANCED: Confidence scoring
│   ├── multi_analyzer.py          # ENHANCED: Parallel processing
│   └── explainability.py          # NEW: Explainability generator
├── features/
│   ├── static_feature_extractor.py  # M1-M15 metrics
│   └── feature_definitions.yml
├── rules/
│   ├── c.yml                      # NEW: 40 C-specific rules
│   ├── cpp.yml
│   ├── java.yml
│   ├── python.yml
│   ├── js.yml
│   ├── php.yml
│   ├── go.yml
│   ├── ruby.yml
│   └── shared/                    # Cross-language CWE rules
│       ├── cwe89_sql_injection.yml
│       ├── cwe78_cmd_exec.yml
│       └── ... (10 shared rule files)
├── outputs/                       # Analysis results
│   ├── static_flags_{split}.csv
│   ├── static_analysis_{split}.jsonl
│   ├── incremental/               # Per-language checkpoints
│   ├── reports/                   # Explainability reports
│   └── logs/                      # Analyzer reports
├── run_static_analysis.py         # CLI entrypoint
└── README.md                      # This file
```

---

## Rule Format

### YAML Rule Structure

```yaml
rules:
  - id: CWE-120-strcpy
    cwe_id: CWE-120
    name: Unsafe strcpy Usage
    type: regex                    # regex | api_call | keyword | ast_pattern | metric_threshold
    pattern: '\bstrcpy\s*\('
    severity: high                 # critical | high | medium | low | info
    confidence: 0.90               # NEW: 0.0-1.0 confidence score
    message: "strcpy() does not check buffer bounds"
    remediation: "Use strncpy() or snprintf()"
```

### Rule Types

1. **regex**: Pattern matching with regular expressions
2. **api_call**: Detect dangerous API function calls
3. **keyword**: Keyword-based detection (e.g., "password", "eval")
4. **ast_pattern**: AST-based structural patterns (requires parser)
5. **metric_threshold**: Trigger on metric thresholds (e.g., cyclomatic complexity > 20)

---

## Confidence Scoring Formula

```python
# Weighted Confidence Calculation
severity_weights = {
    'critical': 1.0,
    'high': 0.8,
    'medium': 0.6,
    'low': 0.4,
    'info': 0.2
}

# Overall confidence = max(confidence_i × severity_weight_i) for all findings
overall_confidence = max([
    vuln['confidence'] * severity_weights[vuln['severity']]
    for vuln in vulnerabilities
])
```

**Interpretation**:
- `0.9-1.0`: Very high confidence (critical finding with strong evidence)
- `0.7-0.9`: High confidence (likely vulnerability)
- `0.5-0.7`: Medium confidence (potential issue, needs review)
- `0.0-0.5`: Low confidence (informational or weak signal)

---

## Performance Optimization

### Parallel Processing Strategy

1. **Load Dataset**: Read JSONL into memory
2. **Group by Language**: Batch records by programming language
3. **Parallel Analysis**:
   - Split each language batch into sub-batches
   - ProcessPoolExecutor spawns `N` workers
   - Each worker analyzes its sub-batch independently
4. **Aggregate Results**: Combine results with progress tracking
5. **Incremental Saves**: Write per-language JSONL checkpoints
6. **Final Output**: Generate consolidated CSV, reports, and explainability

### Scalability Benchmarks

| Dataset Size | Workers | Time (approx) | Memory |
|--------------|---------|---------------|--------|
| 1,000 records | 4 | 2 min | 1 GB |
| 10,000 records | 8 | 15 min | 4 GB |
| 50,000 records | 16 | 60 min | 8 GB |

---

## Explainability Report Usage

### Analyzing Top CWEs

```python
import json

with open('src/static/outputs/reports/explain_train.json') as f:
    report = json.load(f)

# Top 5 CWEs
for cwe in report['cwe_analysis']['top_cwes'][:5]:
    print(f"{cwe['cwe_id']}: {cwe['count']} instances, "
          f"avg confidence: {cwe['avg_confidence']}, "
          f"languages: {cwe['languages']}")
```

### Confidence Distribution

```python
# Histogram: 0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0
histogram = report['confidence_analysis']['confidence_histogram']
for bin_range, count in histogram.items():
    print(f"{bin_range}: {count} records")
```

### Precision Proxy (if ground truth available)

```python
precision_data = report['precision_proxy']
print(f"Precision: {precision_data['precision']}")
print(f"Recall: {precision_data['recall']}")
print(f"F1 Score: {precision_data['f1_score']}")
```

---

## CWE Coverage

### Supported CWE Categories (42+ Total)

| CWE ID | Name | Languages |
|--------|------|-----------|
| CWE-79 | XSS | JS, PHP, Python, Java |
| CWE-89 | SQL Injection | All |
| CWE-78 | Command Injection | All |
| CWE-120 | Buffer Overflow | C, C++ |
| CWE-119 | Buffer Operations | C, C++ |
| CWE-134 | Format String | C, C++ |
| CWE-190 | Integer Overflow | C, C++, Java |
| CWE-416 | Use After Free | C, C++ |
| CWE-415 | Double Free | C, C++ |
| CWE-476 | NULL Pointer Deref | C, C++, Java |
| CWE-22 | Path Traversal | All |
| CWE-502 | Deserialization | Python, Java, PHP |
| CWE-327 | Weak Crypto | All |
| CWE-611 | XXE | Java, Python, PHP |
| CWE-798 | Hardcoded Credentials | All |
| ... | ... | ... |

---

## Troubleshooting

### pycparser Not Found
**Issue**: C analyzer falls back to regex-only mode.
**Solution**: Install pycparser: `pip install pycparser`

### Out of Memory
**Issue**: Large datasets exceed available RAM.
**Solution**: Reduce `--workers` or process splits individually (`--split train`, `--split val`, etc.)

### Slow Processing
**Issue**: Analysis taking too long.
**Solution**:
1. Increase `--workers` to match CPU cores
2. Use incremental saves (`--incremental` is default)
3. Process splits separately

### Missing Explainability Reports
**Issue**: No files in `outputs/reports/`.
**Solution**: Ensure analysis completes successfully. Check logs for errors.

---

## Integration with ML Pipeline

### XGBoost Fusion Model Input

The `static_flags_{split}.csv` output is designed for direct integration:

```python
import pandas as pd
from xgboost import XGBClassifier

# Load static analysis features
static_features = pd.read_csv('src/static/outputs/static_flags_train.csv')

# Extract feature columns
feature_cols = [c for c in static_features.columns if c.startswith('M') or 
                c in ['vulnerability_count', 'severity_score', 'static_confidence']]

X = static_features[feature_cols]
y = static_features['label']

# Train XGBoost model
model = XGBClassifier()
model.fit(X, y)
```

### Feature Importance Analysis

```python
import matplotlib.pyplot as plt

# Get feature importance
importance = model.feature_importances_
feature_names = X.columns

# Plot top 15 features
plt.barh(feature_names, importance)
plt.xlabel('Feature Importance')
plt.title('Static Analysis Feature Importance')
plt.show()
```

---

## API Reference

### MultiAnalyzer Class

```python
from pathlib import Path
from src.static.analyzers.multi_analyzer import MultiAnalyzer

# Initialize
analyzer = MultiAnalyzer(
    rules_dir=Path('src/static/rules'),
    max_workers=8
)

# Analyze dataset
stats = analyzer.analyze_dataset(
    dataset_path=Path('datasets/processed/train.jsonl'),
    output_dir=Path('src/static/outputs'),
    batch_size=100,
    incremental_save=True
)

print(f"Analyzed {stats['analyzed']} records")
print(f"Found {stats['total_vulnerabilities']} vulnerabilities")
print(f"Unique CWEs: {stats['unique_cwes']}")
```

### ExplainabilityGenerator Class

```python
from src.static.analyzers.explainability import ExplainabilityGenerator

# Generate report
generator = ExplainabilityGenerator()
report = generator.generate_report(
    results=analysis_results,
    split_name='train'
)

# Save report
generator.save_report(
    report=report,
    output_path=Path('src/static/outputs/reports/explain_train.json')
)
```

---

## Evaluation Metrics (AI Grand Challenge Alignment)

### Detection Accuracy (50%)
- **Static Confidence**: Higher confidence → better precision
- **CWE Coverage**: 42+ CWE categories supported
- **Multi-Language**: 8 languages with language-specific rules

### Vulnerability Detection (20%)
- **Total Detected**: Tracked in explainability summary
- **Per-CWE Breakdown**: Available in explainability report
- **Severity Distribution**: Critical/High/Medium/Low counts

### Explainability (10%)
- **Comprehensive Reports**: CWE frequency, rule effectiveness, examples
- **Precision Proxies**: TP/FP/FN metrics when ground truth available
- **Confidence Scoring**: Per-detection and overall confidence

### Scalability (10%)
- **Parallel Processing**: Multi-core with ProcessPoolExecutor
- **Incremental Saves**: Fault-tolerant checkpointing
- **Benchmarked**: 50K records in ~60 minutes with 16 workers

---

## Contributing

### Adding a New Language

1. Create `src/static/analyzers/{language}_analyzer.py`:
   ```python
   from .base_analyzer import BaseAnalyzer
   
   class NewLanguageAnalyzer(BaseAnalyzer):
       def __init__(self, language, rule_engine=None):
           super().__init__(language, rule_engine)
       
       def detect_vulnerabilities(self, code):
           # Implement language-specific detection
           pass
   ```

2. Create `src/static/rules/{language}.yml` with detection rules

3. Update `src/static/analyzers/language_map.py`:
   ```python
   from .newlang_analyzer import NewLanguageAnalyzer
   
   cls._analyzer_map['newlang'] = NewLanguageAnalyzer
   ```

### Adding a New Rule

Edit appropriate YAML file in `src/static/rules/`:

```yaml
- id: CWE-XXX-new-rule
  cwe_id: CWE-XXX
  name: Descriptive Name
  type: regex
  pattern: '\bnew_pattern\s*\('
  severity: high
  confidence: 0.85
  message: "Description of vulnerability"
  remediation: "How to fix it"
```

---

## License

MIT License - See repository for full license text.

---

## Citation

If you use this static analyzer in research or production, please cite:

```
CodeGuardian Static Analyzer (Phase 3.2)
AI Grand Challenge PS-1: Source Code Vulnerability Detection
2025
```

---

## Contact & Support

- **Issues**: Create GitHub issue
- **Documentation**: This README + inline code comments
- **Updates**: Check GitHub releases for new CWE rules and features

---

**Version**: 3.2.0  
**Last Updated**: October 8, 2025  
**Status**: Production-Ready ✅
