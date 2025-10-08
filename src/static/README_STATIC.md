# CodeGuardian Static Analysis Module

## Overview

The Static Analysis Module is a production-grade, rule-based vulnerability detection system that integrates seamlessly with the CodeGuardian pipeline. It supports **8 programming languages** and provides comprehensive CWE-mapped findings, static metrics (M1-M15), and ML-ready feature flags for downstream XGBoost fusion models.

### Key Features

- ✅ **8 Language Support**: Python, Java, C/C++, JavaScript/TypeScript, PHP, Go, Ruby, C#
- ✅ **Rule-Based Detection**: YAML-configured rules with regex and AST pattern matching
- ✅ **CWE Mapping**: 15+ major CWE categories (XSS, SQLi, Command Injection, etc.)
- ✅ **Static Metrics**: M1-M15 code complexity and security metrics
- ✅ **Parallel Processing**: Multiprocessing support for high-throughput analysis
- ✅ **JSONL Output**: Pipeline-compatible normalized outputs
- ✅ **ML Integration**: Binary flags and risk scores for XGBoost models
- ✅ **SHAP-Ready**: Feature importance analysis support

---

## Architecture

```
src/static/
├── analyzers/
│   ├── base_analyzer.py          # Abstract base class
│   ├── python_analyzer.py        # Language-specific analyzers
│   ├── java_analyzer.py
│   ├── cpp_analyzer.py
│   ├── js_analyzer.py
│   ├── php_analyzer.py
│   ├── go_analyzer.py
│   ├── ruby_analyzer.py
│   ├── csharp_analyzer.py
│   └── multi_analyzer.py         # Orchestrator
├── rules/
│   ├── python.yml                # High-level language rules
│   ├── java.yml
│   ├── cpp.yml
│   ├── ...
│   ├── cwe/                      # Fine-grained CWE rules
│   │   ├── CWE-79.yml            # XSS
│   │   ├── CWE-89.yml            # SQL Injection
│   │   ├── CWE-78.yml            # Command Injection
│   │   ├── CWE-22.yml            # Path Traversal
│   │   ├── CWE-327.yml           # Weak Cryptography
│   │   ├── CWE-502.yml           # Deserialization
│   │   ├── CWE-798.yml           # Hard-coded Credentials
│   │   ├── CWE-400.yml           # Resource Exhaustion
│   │   └── ...
│   └── rule_schema.json          # YAML validation schema
├── utils/
│   ├── rule_loader.py            # Rule loading and validation
│   ├── code_parser.py            # Regex + AST parsing
│   ├── metrics_extractor.py     # M1-M15 metrics
│   └── report_utils.py          # Scoring, CVE mapping
└── pipeline/
    ├── run_static_pipeline.py    # Main entry point
    ├── merge_static_with_features.py
    └── export_static_results.py
```

---

## Quick Start

### 1. Basic Usage

```bash
# Analyze a dataset
python src/static/pipeline/run_static_pipeline.py \
    --input datasets/processed/train.jsonl \
    --output-dir datasets/static_results \
    --workers 8

# Quick test with 100 samples
python src/static/pipeline/run_static_pipeline.py \
    --input datasets/processed/train.jsonl \
    --quick-test
```

### 2. Integration with Main Pipeline

```bash
# Run complete pipeline with static analysis
python scripts/run_pipeline.py --phase static \
    --input datasets/processed/train.jsonl
```

### 3. Merge with Features

```bash
# Merge static results with feature-engineered data
python src/static/pipeline/merge_static_with_features.py \
    --static datasets/static_results/train_static_results.jsonl \
    --features datasets/features/train_features.jsonl \
    --output datasets/fused/train_with_static.jsonl
```

### 4. Export for ML

```bash
# Export ML-ready CSV files
python src/static/pipeline/export_static_results.py \
    --input datasets/fused/train_with_static.jsonl \
    --output-dir datasets/fused
```

---

## Rule Syntax

Rules are defined in YAML format following the `rule_schema.json` specification.

### Rule Types

#### 1. Regex Pattern Matching

```yaml
rules:
  - id: cwe89_sqli_string_concat
    name: "SQL Injection - String Concatenation"
    cwe_id: "CWE-89"
    severity: CRITICAL
    confidence: HIGH
    type: regex
    pattern: '(execute|query|exec)\s*\([^)]*(\+|%|\bconcat\b)'
    language: all
    description: "SQL queries built with string concatenation"
    remediation: "Use parameterized queries"
    owasp: "A03:2021-Injection"
    tags: ["sqli", "injection"]
```

#### 2. API Call Detection

```yaml
rules:
  - id: cwe78_cmd_exec_shell
    name: "Command Injection - Shell Execution"
    cwe_id: "CWE-78"
    severity: CRITICAL
    confidence: HIGH
    type: api_call
    api_names: [system, exec, shell_exec, popen, os.system]
    language: all
    description: "Dangerous shell execution functions"
    remediation: "Use parameterized APIs"
```

#### 3. Keyword Detection

```yaml
rules:
  - id: python_assert_production
    name: "Assert in Production Code"
    cwe_id: "CWE-703"
    severity: LOW
    confidence: MEDIUM
    type: keyword
    keywords: [assert]
    language: python
    description: "Assert statements removed with -O flag"
```

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | ✅ | Unique rule identifier |
| `name` | ✅ | Human-readable name |
| `cwe_id` | ✅ | CWE identifier (e.g., CWE-89) |
| `severity` | ✅ | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `confidence` | ❌ | HIGH, MEDIUM, LOW (default: MEDIUM) |
| `type` | ✅ | regex, api_call, keyword, ast_pattern |
| `language` | ❌ | Target language or "all" |
| `pattern` | ✅* | Regex pattern (for regex type) |
| `api_names` | ✅* | API names (for api_call type) |
| `keywords` | ✅* | Keywords (for keyword type) |
| `description` | ✅ | Detailed description |
| `remediation` | ❌ | How to fix |
| `owasp` | ❌ | OWASP Top 10 mapping |
| `tags` | ❌ | Additional tags |

\* Required for specific rule types

---

## Output Schema

### Static Analysis Results (JSONL)

```json
{
  "id": "record_12345",
  "language": "python",
  "findings": [
    {
      "id": "record_12345:42:cwe89_sqli_string_concat",
      "rule_id": "cwe89_sqli_string_concat",
      "cwe_id": "CWE-89",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "message": "SQL Injection - String Concatenation",
      "line_no": 42,
      "evidence": "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)",
      "file_path": "record_12345",
      "language": "python",
      "remediation": "Use parameterized queries",
      "owasp": "A03:2021-Injection",
      "tags": ["sqli", "injection"]
    }
  ],
  "static_metrics": {
    "M1_cyclomatic_complexity": 8,
    "M2_nesting_depth": 3,
    "M3_function_call_count": 15,
    "M4_lines_of_code": 85,
    "M5_string_literal_count": 12,
    "M6_numeric_literal_count": 5,
    "M7_api_call_count": 3,
    "M8_dangerous_function_count": 1,
    "M9_comment_ratio": 0.15,
    "M10_import_count": 8,
    "M11_variable_count": 12,
    "M12_operator_count": 45,
    "M13_control_flow_count": 10,
    "M14_exception_handling_count": 2,
    "M15_code_complexity_score": 0.42
  },
  "static_flags": {
    "has_cwe_79": 0,
    "has_cwe_89": 1,
    "has_cwe_78": 0,
    "has_critical": 1,
    "has_high": 0,
    "has_high_confidence": 1
  },
  "risk_score": 0.83,
  "detected_cwes": ["CWE-89"],
  "vulnerability_count": 1,
  "severity_distribution": {
    "CRITICAL": 1,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
  }
}
```

### Static Flags CSV (ML Input)

```csv
id,risk_score,has_cwe_79,has_cwe_89,has_cwe_78,has_critical,has_high,has_high_confidence
record_12345,0.83,0,1,0,1,0,1
record_12346,0.42,1,0,0,0,1,1
```

---

## M1-M15 Static Metrics

| Metric | Description | Thresholds |
|--------|-------------|------------|
| **M1** | Cyclomatic Complexity | High: >20 |
| **M2** | Maximum Nesting Depth | High: >6 |
| **M3** | Function Call Count | High: >30 |
| **M4** | Lines of Code (LOC) | High: >200 |
| **M5** | String Literal Count | - |
| **M6** | Numeric Literal Count | - |
| **M7** | API Call Count | High: >10 |
| **M8** | Dangerous Function Count | High: >5 |
| **M9** | Comment Ratio | Low: <0.1 |
| **M10** | Import Count | High: >15 |
| **M11** | Variable Count | High: >20 |
| **M12** | Operator Count | - |
| **M13** | Control Flow Count | High: >20 |
| **M14** | Exception Handling Count | - |
| **M15** | Code Complexity Score | 0.0-1.0 (weighted) |

---

## Supported CWE Categories

| CWE ID | Category | Severity |
|--------|----------|----------|
| CWE-79 | Cross-Site Scripting (XSS) | HIGH |
| CWE-89 | SQL Injection | CRITICAL |
| CWE-78 | Command Injection | CRITICAL |
| CWE-22 | Path Traversal | HIGH |
| CWE-327 | Weak Cryptography | MEDIUM |
| CWE-295 | TLS Validation | HIGH |
| CWE-611 | XXE Injection | HIGH |
| CWE-502 | Deserialization | CRITICAL |
| CWE-798 | Hard-coded Credentials | CRITICAL |
| CWE-400 | Resource Exhaustion | MEDIUM |
| CWE-476 | NULL Pointer Dereference | MEDIUM |
| CWE-190 | Integer Overflow | MEDIUM |
| CWE-120 | Buffer Overflow | HIGH |
| CWE-94 | Code Injection | CRITICAL |
| CWE-416 | Use After Free | HIGH |

---

## Performance

### Benchmarks

- **Throughput**: ~50-100 records/second (8 cores)
- **Target**: 500K functions in <10 minutes
- **Memory**: ~2-4GB for 100K records
- **Parallelization**: ProcessPoolExecutor with configurable workers

### Optimization Tips

```bash
# Use maximum CPU cores
python run_static_pipeline.py --input data.jsonl --workers 16

# Process in batches for very large datasets
split -l 100000 train.jsonl batch_
for batch in batch_*; do
    python run_static_pipeline.py --input $batch --workers 8
done
```

---

## Integration Examples

### Example 1: Standalone Analysis

```python
from src.static.pipeline import StaticAnalysisPipeline

pipeline = StaticAnalysisPipeline(
    input_path="datasets/processed/val.jsonl",
    output_dir="results",
    workers=8
)

summary = pipeline.run(sample_size=1000)
print(f"Found {summary['total_findings']} vulnerabilities")
```

### Example 2: Rule Loading

```python
from src.static.utils import RuleLoader

loader = RuleLoader()
python_rules = loader.load_rules_for_language('python')
sqli_rules = loader.load_rules_by_cwe('CWE-89')
```

### Example 3: Metrics Extraction

```python
from src.static.utils import MetricsExtractor

extractor = MetricsExtractor('python')
metrics = extractor.compute_all_metrics_with_score(code)
print(f"Complexity: {metrics['M1_cyclomatic_complexity']}")
print(f"Risk Score: {metrics['M15_code_complexity_score']}")
```

---

## Troubleshooting

### Issue: No findings detected

**Solution**: Check that rules exist for the target language
```bash
ls src/static/rules/cwe/
ls src/static/rules/python.yml
```

### Issue: Memory errors on large datasets

**Solution**: Reduce workers or process in batches
```bash
python run_static_pipeline.py --input large.jsonl --workers 2
```

### Issue: Slow performance

**Solution**: Enable parallel processing and optimize rules
```bash
# Use all CPU cores
python run_static_pipeline.py --workers $(nproc)
```

---

## Adding New Rules

### Step 1: Create CWE File

Create `src/static/rules/cwe/CWE-XXX.yml`:

```yaml
rules:
  - id: my_new_rule
    name: "My Vulnerability Detection"
    cwe_id: "CWE-XXX"
    severity: HIGH
    confidence: MEDIUM
    type: regex
    pattern: 'dangerous_pattern'
    language: python
    description: "Description of vulnerability"
    remediation: "How to fix it"
```

### Step 2: Validate

```bash
python -c "
from src.static.utils import RuleLoader
loader = RuleLoader()
rules = loader.load_rules_for_language('python')
print(f'Loaded {len(rules)} rules')
"
```

### Step 3: Test

```bash
python src/static/pipeline/run_static_pipeline.py \
    --input test_data.jsonl \
    --quick-test
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Static Analysis

on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run static analysis
        run: |
          python src/static/pipeline/run_static_pipeline.py \
            --input datasets/processed/train.jsonl \
            --output-dir results \
            --workers 4
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: static-analysis-results
          path: results/
```

---

## API Reference

### StaticAnalysisPipeline

```python
class StaticAnalysisPipeline:
    def __init__(self, input_path: Path, output_dir: Path, workers: int = 4)
    def load_dataset(self) -> List[Dict[str, Any]]
    def analyze_record(self, record: Dict[str, Any]) -> Dict[str, Any]
    def run(self, sample_size: Optional[int] = None) -> Dict[str, Any]
```

### RuleLoader

```python
class RuleLoader:
    def load_rules_for_language(self, language: str) -> List[Dict]
    def load_rules_by_cwe(self, cwe_id: str) -> List[Dict]
    def validate_rule(self, rule: Dict) -> bool
```

### MetricsExtractor

```python
class MetricsExtractor:
    def extract_all_metrics(self, code: str) -> Dict[str, Any]
    def compute_all_metrics_with_score(self, code: str) -> Dict[str, Any]
```

---

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add rules or analyzers following existing patterns
4. Submit a pull request

---

## Support

For issues or questions:
- 📧 Email: support@codeguardian.dev
- 🐛 Issues: GitHub Issues
- 📖 Docs: https://docs.codeguardian.dev

---

**Built for DPIIT Hackathon - Production-Grade Vulnerability Detection**
