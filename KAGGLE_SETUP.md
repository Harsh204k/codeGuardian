# 🚀 Kaggle Setup Guide for CodeGuardian Preprocessing

This guide explains how to set up and run the preprocessing scripts on Kaggle.

## 📋 Prerequisites

Before running preprocessing on Kaggle, you need to:

1. **Upload datasets to Kaggle** as a Kaggle Dataset
2. **Create a Kaggle Notebook** for preprocessing
3. **Add the datasets as input** to your notebook

---

## 📦 Step 1: Create Kaggle Dataset

You need to upload your raw datasets to Kaggle as a dataset named `codeguardian-datasets`.

### Option A: Upload via Kaggle Web UI

1. Go to https://www.kaggle.com/datasets
2. Click **"New Dataset"**
3. Create a dataset named: `codeguardian-datasets`
4. Upload your dataset folders with this structure:

```
codeguardian-datasets/
├── diversevul/
│   ├── diversevul.json              (330k records, ~700MB)
│   ├── diversevul_metadata.json     (metadata, ~50MB)
│   └── label_noise/                 (optional)
│
├── devign/
│   ├── raw/
│   │   ├── ffmpeg.json
│   │   ├── qemu.json
│   │   └── ... (other project JSONs)
│
└── zenodo/
    ├── raw/
    │   └── balanced_dataset.csv     (10k rows)
```

5. Make the dataset **public** or **private** (your choice)
6. Note your dataset URL: `https://www.kaggle.com/datasets/YOUR_USERNAME/codeguardian-datasets`

### Option B: Upload via Kaggle API (Command Line)

If you have large datasets, use the Kaggle API:

```bash
# Install Kaggle API
pip install kaggle

# Setup API credentials (download kaggle.json from your Kaggle account)
# Place it in: ~/.kaggle/kaggle.json (Linux/Mac) or C:\Users\<user>\.kaggle\kaggle.json (Windows)

# Create dataset metadata
cat > dataset-metadata.json << EOF
{
  "title": "codeguardian-datasets",
  "id": "YOUR_USERNAME/codeguardian-datasets",
  "licenses": [{"name": "CC0-1.0"}]
}
EOF

# Upload dataset (from directory containing your dataset folders)
kaggle datasets create -p /path/to/your/datasets --dir-mode zip
```

---

## 🔧 Step 2: Create Kaggle Notebook

1. Go to https://www.kaggle.com/code
2. Click **"New Notebook"**
3. Choose **Python** notebook
4. Name it: `CodeGuardian Preprocessing`

### Add Input Dataset

In your notebook:
1. Click **"+ Add data"** (right sidebar)
2. Search for: `codeguardian-datasets` (your uploaded dataset)
3. Click **"Add"**

After adding, the dataset will be available at:
```
/kaggle/input/codeguardian-datasets/
```

---

## 💻 Step 3: Setup Notebook Code

Copy this code into your Kaggle notebook:

### Cell 1: Clone Repository

```python
# Clone the codeGuardian repository
!git clone https://github.com/Harsh204k/codeGuardian.git
%cd codeGuardian

# Verify repository structure
!ls -la scripts/preprocessing/
```

### Cell 2: Install Dependencies (if needed)

```python
# Install any missing dependencies
!pip install tqdm jsonschema
```

### Cell 3: Verify Dataset Structure

```python
# Check what datasets are available
import os
from pathlib import Path

print("📦 Available input datasets:")
for item in Path("/kaggle/input").iterdir():
    if item.is_dir():
        print(f"  - {item.name}")

print("\n📁 Contents of codeguardian-datasets:")
base = Path("/kaggle/input/codeguardian-datasets")
if base.exists():
    for item in sorted(base.iterdir()):
        if item.is_dir():
            print(f"\n  📂 {item.name}/")
            for subitem in sorted(item.iterdir())[:10]:  # Show first 10 items
                size = f"({subitem.stat().st_size / 1024 / 1024:.1f} MB)" if subitem.is_file() else "(dir)"
                print(f"     - {subitem.name} {size}")
        else:
            size = item.stat().st_size / 1024 / 1024
            print(f"  📄 {item.name} ({size:.1f} MB)")
else:
    print("❌ Dataset not found! Make sure 'codeguardian-datasets' is added as input.")
```

### Cell 4: Run DiverseVul Preprocessing

```python
# Run DiverseVul preprocessing
!python scripts/preprocessing/prepare_diversevul.py

# Expected processing time: 30-45 minutes
# Expected output: ~310k-320k records after deduplication
```

### Cell 5: Run Devign Preprocessing

```python
# Run Devign preprocessing
!python scripts/preprocessing/prepare_devign.py

# Expected processing time: 3-5 minutes
# Expected output: ~27k records
```

### Cell 6: Run Zenodo Preprocessing

```python
# Run Zenodo preprocessing
!python scripts/preprocessing/prepare_zenodo.py

# Expected processing time: 5-10 minutes
# Expected output: ~4k-5k records after deduplication
```

### Cell 7: Verify Outputs

```python
import json
from pathlib import Path

output_base = Path("/kaggle/working/datasets")

print("="*60)
print("📊 PREPROCESSING RESULTS")
print("="*60)

for dataset_name in ["diversevul", "devign", "zenodo"]:
    dataset_dir = output_base / dataset_name / "processed"
    
    if dataset_dir.exists():
        print(f"\n✅ {dataset_name.upper()}")
        
        # Check stats file
        stats_file = dataset_dir / "stats.json"
        if stats_file.exists():
            stats = json.loads(stats_file.read_text())
            print(f"   Total records: {stats.get('total_records', 'N/A')}")
            print(f"   Vulnerable: {stats.get('vulnerable_records', 'N/A')}")
            print(f"   Languages: {len(stats.get('languages', {}))}")
            print(f"   Unique CWEs: {stats.get('unique_cwes', 'N/A')}")
        
        # Check output file
        output_file = dataset_dir / "raw_cleaned.jsonl"
        if output_file.exists():
            size_mb = output_file.stat().st_size / 1024 / 1024
            print(f"   Output file: {output_file.name} ({size_mb:.1f} MB)")
    else:
        print(f"\n❌ {dataset_name.upper()}: Not processed")

print("\n" + "="*60)
```

### Cell 8: Download Processed Data (Optional)

```python
# Create a zip file of all processed datasets
!cd /kaggle/working && zip -r processed_datasets.zip datasets/

print("✅ Download 'processed_datasets.zip' from the Output section")
```

---

## ⚠️ Common Issues & Solutions

### Issue 1: "Dataset file not found"

**Symptoms:**
```
❌ ERROR: Input directory not found!
Expected path: /kaggle/input/codeguardian-datasets/diversevul
```

**Solution:**
- Make sure you **added the dataset as input** to your notebook
- Check the dataset name is exactly: `codeguardian-datasets` (lowercase, no spaces)
- Verify the folder structure inside your dataset matches the expected layout

### Issue 2: "No module named 'scripts'"

**Symptoms:**
```
ModuleNotFoundError: No module named 'scripts'
```

**Solution:**
```python
# Make sure you're in the repo directory
%cd /kaggle/working/codeGuardian

# Verify you're in the right place
!pwd
!ls scripts/
```

### Issue 3: Out of Memory

**Symptoms:**
```
MemoryError or Kernel crash
```

**Solution:**
- DiverseVul is large (330k records). Enable **GPU/TPU** in notebook settings for more RAM
- Or process in smaller batches using: `--max-records 100000`

```python
!python scripts/preprocessing/prepare_diversevul.py --max-records 100000
```

### Issue 4: Processing Takes Too Long

**Expected Times:**
- **DiverseVul**: 30-45 minutes (large dataset)
- **Devign**: 3-5 minutes
- **Zenodo**: 5-10 minutes

If it's taking much longer:
- Check if the script is stuck (look for tqdm progress bars)
- Verify input file isn't corrupted
- Try with `--max-records` to test on smaller subset first

---

## 🎯 Quick Start Checklist

Before running preprocessing, verify:

- [ ] Dataset uploaded to Kaggle as `codeguardian-datasets`
- [ ] Notebook created with dataset added as input
- [ ] Repository cloned: `git clone https://github.com/Harsh204k/codeGuardian.git`
- [ ] In correct directory: `cd codeGuardian`
- [ ] Can see datasets: `ls /kaggle/input/codeguardian-datasets/`
- [ ] Run preprocessing scripts one by one
- [ ] Verify outputs in `/kaggle/working/datasets/`

---

## 📊 Expected Results

After successful preprocessing:

```
/kaggle/working/datasets/
├── diversevul/
│   └── processed/
│       ├── raw_cleaned.jsonl    (~310k-320k records, ~600MB)
│       └── stats.json
│
├── devign/
│   └── processed/
│       ├── raw_cleaned.jsonl    (~27k records, ~50MB)
│       └── stats.json
│
└── zenodo/
    └── processed/
        ├── raw_cleaned.jsonl    (~4k-5k records, ~8MB)
        └── stats.json
```

**Total:** ~340k-350k vulnerability detection records ready for training!

---

## 🔄 Next Steps

After preprocessing is complete:

1. **Download processed data** (if needed locally)
2. **Run normalization**: `scripts/normalization/normalize_all_datasets.py`
3. **Feature engineering**: Extract features for ML models
4. **Train models**: CodeBERT, XGBoost, Random Forest
5. **Evaluate performance**: Test on holdout sets

---

## 📚 Additional Resources

- **Repository**: https://github.com/Harsh204k/codeGuardian
- **Documentation**: See `DIVERSEVUL_VERIFICATION.md`, `KAGGLE_DEPLOYMENT_GUIDE.md`
- **Issues**: Check `DATASET_VERIFICATION_REPORT.md` for known dataset issues

---

## 🆘 Need Help?

If you encounter issues:

1. Check the **debug output** from the preprocessing scripts
2. Verify **file paths and structure** match expectations
3. Review **PREPROCESSING_FIXES.md** for recent changes
4. Look at **error messages** carefully - they contain helpful diagnostics

The preprocessing scripts now include extensive debugging output to help identify issues quickly!
