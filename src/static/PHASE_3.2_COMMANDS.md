# Phase 3.2 - Quick Command Reference
**DPIIT Hackathon - CodeGuardian Enhanced Static Analysis**

---

## ✅ COMPLETION STATUS: 100% (10/10 todos)

---

## 🚀 Quick Start Commands

### Test Everything
```powershell
# Run complete test suite
.\test_phase_3.2.ps1
```

### Run Smoke Tests
```bash
python src/static/tests/run_tests.py
```

### Analyze Single Split (Enhanced)
```bash
# Train split
python src/static/pipeline/run_static_pipeline_enhanced.py \
    --input datasets/processed/train.jsonl \
    --output datasets/static_results/train_static_enhanced.jsonl \
    --reports outputs/reports \
    --split train

# Validation split
python src/static/pipeline/run_static_pipeline_enhanced.py \
    --input datasets/processed/val.jsonl \
    --output datasets/static_results/val_static_enhanced.jsonl \
    --reports outputs/reports \
    --split val

# Test split
python src/static/pipeline/run_static_pipeline_enhanced.py \
    --input datasets/processed/test.jsonl \
    --output datasets/static_results/test_static_enhanced.jsonl \
    --reports outputs/reports \
    --split test
```

### Run Full Pipeline (Enhanced Mode)
```bash
# Complete pipeline with Phase 3.2 enhanced static analysis
python scripts/run_pipeline.py --static-enhanced

# Resume from static analysis stage
python scripts/run_pipeline.py --resume static_analysis --static-enhanced

# With specific config
python scripts/run_pipeline.py --config configs/pipeline_config.yaml --static-enhanced
```

### Run Full Pipeline (Standard Mode)
```bash
# Original Phase 3 static analysis (without C support)
python scripts/run_pipeline.py --static-analysis
```

---

## 📁 Output Files

### Enhanced Static Analysis Results
```
datasets/static_results/
├── train_static_enhanced.jsonl
├── val_static_enhanced.jsonl
└── test_static_enhanced.jsonl
```

### Explainability Reports
```
outputs/reports/
├── explain_train.json   # Machine-readable
├── explain_train.md     # Human-readable
├── explain_val.json
├── explain_val.md
├── explain_test.json
└── explain_test.md
```

---

## 🎯 Key Features

| Feature | Status | Command Flag |
|---------|--------|--------------|
| C Language Support | ✅ | `--static-enhanced` |
| Parallel Processing | ✅ | `--static-enhanced` |
| Explainability Reports | ✅ | `--reports outputs/reports` |
| Confidence Scoring | ✅ | (automatic) |
| 30+ C Vulnerability Patterns | ✅ | (automatic) |
| ProcessPoolExecutor | ✅ | `--max-workers N` |
| Progress Bars | ✅ | (automatic with tqdm) |

---

## 🔧 Flags Reference

### Enhanced Pipeline Flags
```bash
python src/static/pipeline/run_static_pipeline_enhanced.py \
    --input <path>          # Required: Input JSONL file
    --output <path>         # Required: Output JSONL file
    --reports <dir>         # Optional: Reports directory
    --split <name>          # Optional: Split name (train/val/test)
    --max-workers <n>       # Optional: Worker count (default: CPU-1)
```

### Main Pipeline Flags
```bash
python scripts/run_pipeline.py \
    --static-enhanced       # Enable Phase 3.2 enhanced analysis
    --static-analysis       # Enable Phase 3 standard analysis
    --config <yaml>         # Config file path
    --resume <stage>        # Resume from stage
    --dry-run               # Validate without execution
    --skip <stages>         # Skip specific stages
```

---

## 📊 Performance Targets

| Dataset Size | Expected Time | Workers | Memory |
|-------------|---------------|---------|--------|
| 10K | ~1 min | 7 | <1GB |
| 100K | ~5 min | 7 | <2GB |
| 500K | ~10 min | 7 | <4GB |
| 1M | ~20 min | 7 | <8GB |

---

## 🐛 Troubleshooting

### Missing pycparser
```bash
pip install pycparser
```

### Missing tqdm
```bash
pip install tqdm
```

### Check if C rules loaded
```python
from src.static.analyzers.rule_engine import RuleEngine
engine = RuleEngine()
engine.load_all_rules()
print(engine.get_supported_languages())  # Should include 'c'
```

### Verify outputs exist
```bash
ls -lh datasets/static_results/*_static_enhanced.jsonl
ls -lh outputs/reports/explain_*.json
```

---

## 📚 Documentation

- **PHASE_3.2_COMPLETE.md** - Final completion document
- **PHASE_3.2_SUMMARY.md** - Comprehensive overview
- **PHASE_3.2_QUICK_REFERENCE.md** - Detailed quick start
- **PHASE_3.2_PROGRESS.md** - Implementation tracking
- **test_phase_3.2.ps1** - Automated test suite

---

## ✅ Quick Validation

```bash
# 1. Check all files exist
ls src/static/analyzers/c_analyzer.py
ls src/static/rules/c.yml
ls src/static/analyzers/multi_analyzer_enhanced.py
ls src/static/utils/report_generator.py
ls src/static/pipeline/run_static_pipeline_enhanced.py

# 2. Run tests
python src/static/tests/run_tests.py

# 3. Check integration
grep -n "static-enhanced" scripts/run_pipeline.py
```

---

## 🎉 Ready for Hackathon!

**Phase 3.2 is 100% COMPLETE**

All components implemented, tested, integrated, and documented.

Run `.\test_phase_3.2.ps1` to validate everything!

---

**Version:** 3.2.0 Final  
**Date:** October 8, 2025  
**Status:** Production Ready ✅
