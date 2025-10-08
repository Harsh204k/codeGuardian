# Static Analysis Module - Phase 3

## Overview

The **Static Analyzer Module** is a comprehensive, multi-language vulnerability detection system designed for the codeGuardian project. It analyzes source code using pattern-based and semantic rules to identify security vulnerabilities, extract code metrics, and generate machine-readable flags for the XGBoost fusion model.

### Key Features

- ✅ **Multi-language support**: C, C++, Java, JavaScript, Python, PHP, Go, Ruby
- ✅ **YAML-based rules**: Extensible vulnerability detection patterns
- ✅ **CWE mapping**: Automatic classification to CWE categories
- ✅ **Static metrics (M1-M15)**: Comprehensive code complexity analysis
- ✅ **Scalable architecture**: Batch processing with multiprocessing
- ✅ **ML integration**: Outputs compatible with XGBoost fusion model

---

## Architecture

```
src/static/
├── analyzers/              # Core analysis engine
│   ├── base_analyzer.py    # Abstract base class
│   ├── language_map.py     # Language routing
│   ├── rule_engine.py      # YAML rule executor
│   ├── multi_analyzer.py   # Batch orchestrator
│   ├── cpp_analyzer.py     # C/C++ analyzer
│   ├── java_analyzer.py    # Java analyzer
│   ├── python_analyzer.py  # Python analyzer
│   ├── js_analyzer.py      # JavaScript analyzer
│   ├── php_analyzer.py     # PHP analyzer
│   ├── go_analyzer.py      # Go analyzer
│   └── ruby_analyzer.py    # Ruby analyzer
│
├── rules/                  # Vulnerability detection rules
│   ├── cpp.yml             # C/C++ specific rules
│   ├── java.yml            # Java specific rules
│   ├── python.yml          # Python specific rules
│   ├── php.yml             # PHP specific rules
│   ├── js.yml              # JavaScript specific rules
│   ├── go.yml              # Go specific rules
│   ├── ruby.yml            # Ruby specific rules
│   └── shared/             # Cross-language CWE rules
│       ├── cwe22_path_traversal.yml
│       ├── cwe78_cmd_exec.yml
│       ├── cwe79_xss.yml
│       ├── cwe89_sql_injection.yml
│       ├── cwe120_buffer_overflow.yml
│       ├── cwe327_weak_crypto.yml
│       ├── cwe502_deserialization.yml
│       ├── cwe611_xxe.yml
│       ├── cwe798_hardcoded_creds.yml
│       └── cwe400_dos.yml
│
├── features/               # Static feature extraction
│   ├── static_feature_extractor.py  # M1-M15 metrics
│   └── feature_definitions.yml      # Metric definitions
│
├── outputs/                # Analysis results
│   ├── static_flags_train.csv       # ML model input
│   ├── static_flags_val.csv
│   ├── static_flags_test.csv
│   └── logs/                        # Detailed reports
│       ├── analyzer_report_*.json
│       └── analysis_stats_*.json
│
├── run_static_analysis.py  # Main entrypoint
└── README.md               # This file
```

---

## Installation & Setup

### Prerequisites

```bash
# Install required packages
pip install pyyaml pandas tqdm
```

### Verify Installation

```bash
# Check that the module structure exists
ls src/static/analyzers/
ls src/static/rules/
```

---

## Usage

### Basic Usage

```bash
# Analyze training set
python src/static/run_static_analysis.py --split train

# Analyze all splits (train, val, test)
python src/static/run_static_analysis.py --split all

# Analyze with custom parameters
python src/static/run_static_analysis.py \
    --split all \
    --input-dir datasets/processed \
    --output-dir src/static/outputs \
    --workers 8
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--split` | Dataset split (train/val/test/all) | *required* |
| `--input-dir` | Input JSONL directory | `datasets/processed` |
| `--output-dir` | Output directory | `src/static/outputs` |
| `--rules-dir` | YAML rules directory | `src/static/rules` |
| `--workers` | Parallel workers | `4` |
| `--batch-size` | Batch size | `100` |
| `--export` | Export additional formats | `False` |
| `--verbose` | Verbose logging | `False` |

---

## Static Metrics (M1-M15)

The module extracts 15 comprehensive static code metrics:

| Metric | Name | Description |
|--------|------|-------------|
| M1 | Cyclomatic Complexity | Decision points in code |
| M2 | Nesting Depth | Maximum block nesting level |
| M3 | Function Call Count | Number of function calls |
| M4 | Lines of Code | Non-empty, non-comment LOC |
| M5 | String Literal Count | Potential injection points |
| M6 | Numeric Literal Count | Hard-coded numbers |
| M7 | API Call Count | Security-relevant API usage |
| M8 | Dangerous Function Count | Known unsafe functions |
| M9 | Comment Ratio | Code documentation quality |
| M10 | Import Count | External dependencies |
| M11 | Variable Count | Variable declarations |
| M12 | Conditional Count | If/else/switch statements |
| M13 | Loop Count | For/while/foreach loops |
| M14 | Exception Handling Count | Try/catch blocks |
| M15 | Code Complexity Score | Aggregate complexity (0-100) |

---

## Vulnerability Detection

### Supported CWE Categories

The module detects the following CWE categories:

- **CWE-22**: Path Traversal
- **CWE-78**: OS Command Injection
- **CWE-79**: Cross-Site Scripting (XSS)
- **CWE-89**: SQL Injection
- **CWE-120**: Buffer Overflow (C/C++)
- **CWE-327**: Weak Cryptography
- **CWE-502**: Insecure Deserialization
- **CWE-611**: XML External Entity (XXE)
- **CWE-798**: Hard-coded Credentials
- **CWE-400**: Denial of Service

### Rule Types

1. **regex**: Pattern matching
2. **api_call**: API function detection
3. **keyword**: Keyword matching
4. **ast_pattern**: AST-based patterns
5. **metric_threshold**: Metric-based thresholds

### Example Rule (YAML)

```yaml
rules:
  - id: sql_injection_string_concat
    name: "SQL Injection via String Concatenation"
    cwe_id: "CWE-89"
    severity: HIGH
    confidence: HIGH
    type: regex
    pattern: '(execute|query)\s*\([^)]*[\+&]'
    description: "SQL query with string concatenation"
    remediation: "Use parameterized queries"
    languages: [python, java, php]
```

---

## Output Files

### 1. Static Flags CSV (`static_flags_*.csv`)

Machine-readable feature matrix for ML model:

```csv
id,language,label,has_vulnerabilities,vulnerability_count,M1_cyclomatic_complexity,...
rec_001,python,1,true,3,15,...
rec_002,java,0,false,0,8,...
```

### 2. Full Analysis JSONL (`static_analysis_*.jsonl`)

Complete analysis results with all details:

```json
{
  "id": "rec_001",
  "language": "python",
  "code": "...",
  "label": 1,
  "static_analysis": {
    "static_metrics": {...},
    "detected_cwes": ["CWE-89", "CWE-78"],
    "vulnerabilities": [...],
    "static_flags": {...}
  }
}
```

### 3. Vulnerability Report (`analyzer_report_*.json`)

Aggregated vulnerability statistics:

```json
{
  "total_records": 10000,
  "records_with_vulnerabilities": 4532,
  "vulnerabilities_by_cwe": {
    "CWE-89": 1234,
    "CWE-78": 876
  },
  "top_vulnerable_records": [...]
}
```

---

## Integration with Pipeline

### Option 1: Standalone Execution

```bash
# Run static analysis separately
python src/static/run_static_analysis.py --split all
```

### Option 2: Integrated Pipeline

```bash
# Run complete pipeline with static analysis
python scripts/run_pipeline.py \
    --normalize \
    --feature-engineer \
    --static-analysis \
    --output-dir datasets/processed
```

---

## Performance Considerations

### Scalability

- **Multiprocessing**: Uses `ProcessPoolExecutor` for parallel analysis
- **Batch processing**: Configurable batch sizes
- **Language grouping**: Efficient batching by language

### Benchmarks

| Dataset Size | Workers | Time (approx) |
|--------------|---------|---------------|
| 10,000 records | 4 | ~15 min |
| 50,000 records | 8 | ~45 min |
| 100,000 records | 16 | ~90 min |

---

## Extending the Module

### Adding a New Language Analyzer

1. Create `src/static/analyzers/new_lang_analyzer.py`
2. Extend `BaseAnalyzer`
3. Implement `analyze()`, `extract_metrics()`, `detect_vulnerabilities()`
4. Register in `language_map.py`

```python
from .base_analyzer import BaseAnalyzer

class NewLangAnalyzer(BaseAnalyzer):
    def analyze(self, code, record_id=None):
        # Implementation
        pass
```

### Adding New Vulnerability Rules

Create `src/static/rules/shared/cweXXX_name.yml`:

```yaml
rules:
  - id: new_vulnerability
    cwe_id: "CWE-XXX"
    severity: HIGH
    type: regex
    pattern: 'dangerous_pattern'
    description: "Description"
    remediation: "Fix recommendation"
    languages: [all]
```

---

## PS-1 Evaluation Alignment

| Criterion | Weight | Implementation |
|-----------|--------|----------------|
| **Vulnerabilities Detected + CWE Mapping** | 40% | ✅ Multi-language analyzers + YAML rules |
| **Detection Accuracy (F1 Score)** | 20% | ✅ Static flags + ML fusion |
| **Explainability & Traceability** | 10% | ✅ CWE reports + per-file logs |
| **Scalability & Resource Use** | 10% | ✅ Multiprocessing + batch processing |

---

## Troubleshooting

### Issue: Rules not loading

```bash
# Check rules directory
ls src/static/rules/
# Verify YAML syntax
python -c "import yaml; yaml.safe_load(open('src/static/rules/python.yml'))"
```

### Issue: Out of memory

```bash
# Reduce workers or batch size
python src/static/run_static_analysis.py --split train --workers 2 --batch-size 50
```

### Issue: Missing dependencies

```bash
# Install missing packages
pip install pyyaml pandas tqdm
```

---

## Future Enhancements

- [ ] AST-based analysis (tree-sitter integration)
- [ ] Dataflow analysis for taint tracking
- [ ] Machine learning-based rule generation
- [ ] Real-time incremental analysis
- [ ] IDE plugin integration

---

## References

- **CWE Database**: https://cwe.mitre.org/
- **OWASP Top 10**: https://owasp.org/Top10/
- **SANS Top 25**: https://www.sans.org/top25-software-errors/

---

## License

Part of the codeGuardian project. See main project LICENSE.

---

## Contact & Support

For issues or questions:
- Review logs in `logs/static_analysis.log`
- Check output reports in `src/static/outputs/logs/`
- Refer to main project documentation
