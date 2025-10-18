# CodeGuardian Data Pipeline - Quick Start Guide

Get started with the data processing pipeline in minutes!

## ⚡ Quick Setup

### 1. Install Dependencies

```powershell
# Navigate to the codeGuardian directory
cd codeGuardian

# Install required packages
pip install -r requirements.txt
```

### 2. Verify Dataset Structure

Ensure your raw datasets are organized as follows:

```
datasets/
├── devign/raw/
│   ├── ffmpeg.csv
│   ├── qemu.csv
│   └── function.json
├── zenodo/
│   ├── data_C.csv
│   ├── data_C++.csv
│   ├── data_Python.csv
│   └── ... (other languages)
├── diversevul/raw/
│   ├── diversevul.json
│   └── diversevul_metadata.json
├── github_ppakshad/raw/
│   └── main_dataset.xlsx
├── codexglue_defect/raw/
│   ├── train.txt
│   ├── valid.txt
│   └── test.txt
└── juliet/
    ├── c/testcases/
    └── java/
```

### 3. Run the Pipeline

#### Option A: Quick Test (Recommended First)

Process a small sample to verify everything works:

```powershell
python scripts/run_pipeline.py --quick-test
```

This processes only 100 records per dataset. Takes ~2-5 minutes.

#### Option B: Full Pipeline

Process all datasets completely:

```powershell
python scripts/run_pipeline.py
```

This can take 30-60 minutes depending on dataset sizes.

#### Option C: Specific Datasets

Process only the datasets you need:

```powershell
# Just Devign and Zenodo
python scripts/run_pipeline.py --datasets devign zenodo

# Just CodeXGLUE for validation
python scripts/run_pipeline.py --datasets codexglue
```

## 📊 View Results

### Check Statistics

```powershell
python scripts/inspect_dataset.py --stats
```

### View Samples

```powershell
# Show 10 sample records
python scripts/inspect_dataset.py --samples 10

# Show vulnerable Python records
python scripts/inspect_dataset.py --filter-language Python --vulnerable-only --samples 5
```

### Explore by CWE

```powershell
# Show SQL injection vulnerabilities
python scripts/inspect_dataset.py --filter-cwe CWE-89 --samples 5

# Show XSS vulnerabilities
python scripts/inspect_dataset.py --filter-cwe CWE-79 --samples 5
```

## 📁 Output Files

After running the pipeline, find your processed data:

```
output/unified/                  ← **YOUR MAIN OUTPUT**
├── unified_dataset.jsonl       ← All records, unified format
├── unified_stats.json          ← Comprehensive statistics
├── devign_processed.jsonl      ← Individual dataset outputs
├── zenodo_processed.jsonl
├── diversevul_processed.jsonl
├── codexglue_processed.jsonl
├── juliet_processed.jsonl
├── megavul_processed.jsonl
└── pipeline_log.txt            ← Execution log
```

## 🎯 Use the Data

### Load in Python

```python
from utils.io_utils import read_jsonl

# Load all records
records = list(read_jsonl('datasets/unified/unified_dataset.jsonl'))

print(f"Total records: {len(records)}")

# Filter by language
python_vulns = [r for r in records 
                if r['language'] == 'Python' 
                and r['label'] == 1]

# Filter by CWE
sql_injection = [r for r in records if r.get('cwe_id') == 'CWE-89']

# Get training data
for record in records[:5]:
    code = record['code']
    label = record['label']
    func_name = record['func_name']
    # Your training logic here
```

### Export Filtered Data

```powershell
# Export all Python vulnerabilities
python scripts/inspect_dataset.py --filter-language Python --vulnerable-only --output python_vulns.jsonl

# Export SQL injection samples
python scripts/inspect_dataset.py --filter-cwe CWE-89 --output cwe89_samples.jsonl

# Export Java dataset
python scripts/inspect_dataset.py --filter-language Java --output java_dataset.jsonl
```

## 🐛 Troubleshooting

### Issue: "Dataset file not found"

**Solution**: Check that raw data files are in the correct directories.

```powershell
# List dataset directories
Get-ChildItem -Path datasets -Directory -Recurse -Depth 2
```

### Issue: "Module not found"

**Solution**: Ensure you're running from the correct directory.

```powershell
# Should be in codeGuardian root
cd path/to/codeGuardian
python scripts/run_all_preprocessing.py --quick-test
```

### Issue: Memory errors with large datasets

**Solution**: Process datasets individually or limit records.

```powershell
# Process one at a time
python scripts/prepare_devign.py
python scripts/prepare_zenodo.py --languages Python Java

# Or limit records
python scripts/run_all_preprocessing.py --max-records 1000
```

### Issue: Encoding errors

**Solution**: The pipeline handles this automatically, but if issues persist:

```python
# Scripts use safe_read_text which tries multiple encodings
# Check utils/io_utils.py for details
```

## 🔄 Re-running the Pipeline

The pipeline is idempotent - you can re-run it safely:

```powershell
# Individual dataset (overwrites existing)
python scripts/prepare_devign.py

# Full pipeline (overwrites everything)
python scripts/run_all_preprocessing.py

# Skip normalization if already done
python scripts/run_all_preprocessing.py --skip-normalization
```

## 📈 Next Steps

After processing your data:

1. **Explore the unified dataset**

   ```powershell
   python scripts/inspect_dataset.py --stats
   ```
2. **Train models**

   ```python
   # Use with your training scripts
   from utils.io_utils import read_jsonl
   data = list(read_jsonl('datasets/unified/processed_all.jsonl'))
   ```
3. **Create custom splits**

   ```python
   # Split by language, CWE, or project
   # Filter and export with inspect_dataset.py
   ```

## 💡 Tips

- **Start with `--quick-test`** to verify setup
- **Use `inspect_dataset.py`** to explore data before training
- **Filter by language** if training language-specific models
- **Check CWE distribution** to understand vulnerability types
- **Monitor statistics** to ensure data quality

## 📚 Additional Resources

- **Full Documentation**: `scripts/README.md`
- **Schema Reference**: `datasets/unified/schema.json`
- **Individual Scripts**: Each script has `--help` option

```powershell
python scripts/prepare_devign.py --help
python scripts/normalize_all_datasets.py --help
python scripts/inspect_dataset.py --help
```

## ✅ Verification Checklist

After running the pipeline, verify:

- [ ] `datasets/unified/processed_all.jsonl` exists
- [ ] File size is reasonable (should be MBs to GBs)
- [ ] `inspect_dataset.py --stats` shows expected record counts
- [ ] Multiple languages are present
- [ ] Both vulnerable and non-vulnerable records exist
- [ ] CWE information is populated where available

---

**Need help?** Check the detailed README in `scripts/README.md` or examine the script source code for more options.
