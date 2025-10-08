# Quick Reference: Enhanced Pipeline Usage

## 🚀 Running the Enhanced Pipeline

### Full Pipeline Execution
```bash
# Standard run with config
python scripts/run_pipeline_enhanced.py --config configs/pipeline_config.yaml

# Dry run (validate without executing)
python scripts/run_pipeline_enhanced.py --dry-run

# Resume from checkpoint
python scripts/run_pipeline_enhanced.py --resume validation

# Skip stages
python scripts/run_pipeline_enhanced.py --skip preprocessing normalization

# Start fresh (clear checkpoints)
python scripts/run_pipeline_enhanced.py --clear-checkpoints

# Custom log level
python scripts/run_pipeline_enhanced.py --log-level DEBUG
```

## 📝 Individual Module Execution

### Enhanced Validation
```bash
python scripts/validation/validation_enhanced.py \
  --input datasets/unified/processed_all.jsonl \
  --output datasets/unified/validated.jsonl \
  --report datasets/unified/validation_report.json \
  --errors datasets/unified/validation_errors.jsonl \
  --min-code-length 10 \
  --chunk-size 10000
```

### Enhanced Feature Engineering
```bash
python scripts/features/feature_engineering_enhanced.py \
  --input datasets/unified/validated.jsonl \
  --output-csv datasets/features/features_static.csv \
  --stats datasets/features/stats_features.json \
  --chunk-size 10000
```

### Report Generation
```bash
python scripts/utils/report_generator.py \
  --validation-report datasets/unified/validation_report.json \
  --feature-stats datasets/features/stats_features.json \
  --output PIPELINE_REPORT.md
```

## 🛠️ Key Configuration Settings

Edit `configs/pipeline_config.yaml`:

```yaml
# I/O optimization
performance:
  io:
    chunk_size: 10000        # Adjust for your RAM
    use_chunked_reads: true
    compression: "gzip"

# Validation thresholds
validation:
  min_code_length: 10
  auto_repair: true

# Feature engineering
feature_engineering:
  metrics:
    complexity: true
    entropy: true
  embeddings:
    enabled: false  # Set true if CodeBERT available

# Error handling
error_handling:
  retry:
    enabled: true
    max_attempts: 3
```

## 📊 Output Files

After successful run:
- `datasets/unified/validated.jsonl` - Clean validated records
- `datasets/unified/validation_report.json` - Validation statistics
- `datasets/features/features_static.csv` - ML-ready features (35+ columns)
- `datasets/processed/train.jsonl` - Training split
- `datasets/processed/val.jsonl` - Validation split
- `datasets/processed/test.jsonl` - Test split
- `PIPELINE_REPORT.md` - Comprehensive report
- `logs/phase2/phase2_run_*.log` - Execution logs
- `.pipeline_checkpoint.json` - Progress checkpoints

## 🔍 Monitoring & Debugging

### Check Logs
```bash
# Latest log file
cat logs/phase2/phase2_run_$(ls -t logs/phase2/ | head -1)

# Profiling reports
cat logs/profiling/profile_*
```

### View Checkpoints
```bash
cat .pipeline_checkpoint.json
```

### Validate Outputs
```bash
# Count records
wc -l datasets/unified/validated.jsonl

# Check CSV features
head -2 datasets/features/features_static.csv | cut -d',' -f1-10

# View validation report
cat datasets/unified/validation_report.json | jq '.validation_pass_rate'
```

## 💡 Tips & Tricks

### Performance Optimization
- Adjust `chunk_size` based on available RAM (higher = faster but more memory)
- Enable parquet caching for repeated runs (10-100x speedup)
- Use `--skip` to bypass completed stages during debugging

### Data Quality
- Check `validation_report.json` for error patterns
- Review `validation_errors.jsonl` for failed records
- Use `auto_repair: true` to fix common issues automatically

### Debugging
- Use `--dry-run` to validate config
- Start with `--log-level DEBUG` for detailed output
- Check `.pipeline_checkpoint.json` to see which stages completed

## 📦 Dependencies Check

```bash
# Verify installations
python -c "import pyarrow; print('✅ pyarrow')"
python -c "import loguru; print('✅ loguru')"
python -c "from memory_profiler import profile; print('✅ memory_profiler')"
python -c "import yaml; print('✅ pyyaml')"

# Install if missing
pip install pyarrow loguru memory_profiler pyyaml
```

## 🎯 Hackathon Workflow

1. **Initial Run** (full dataset):
   ```bash
   python scripts/run_pipeline_enhanced.py --config configs/pipeline_config.yaml
   ```

2. **Review Results**:
   ```bash
   cat PIPELINE_REPORT.md
   ```

3. **Check Metrics**:
   - Validation pass rate (target: ≥98%)
   - Feature count (35+ features)
   - Dataset balance (check label distribution)

4. **Use for ML Training**:
   - Load `datasets/features/features_static.csv`
   - Use `train.jsonl`, `val.jsonl`, `test.jsonl` for splits
   - Train model with 35+ engineered features

5. **Submit Results**:
   - Include `PIPELINE_REPORT.md` in documentation
   - Highlight performance metrics
   - Show comprehensive feature engineering

## ⚠️ Common Issues & Solutions

**Issue: Out of memory**
- Solution: Reduce `chunk_size` in config (try 5000 or 1000)

**Issue: Slow processing**
- Solution: Enable parquet caching, increase `chunk_size`, use parallel processing

**Issue: Low validation pass rate**
- Solution: Enable `auto_repair`, review `validation_errors.jsonl`, adjust thresholds

**Issue: Missing dependencies**
- Solution: Run `pip install -r requirements.txt`

**Issue: Checkpoint corruption**
- Solution: Run with `--clear-checkpoints` to start fresh

---

**Version:** 3.1.0  
**Status:** ✅ All features complete and ready
