# 📦 Installation Guide for CodeGuardian

This guide covers installation for different environments: **Local Development** and **Kaggle Notebooks**.

---

## 🏠 Local Development Installation

### Prerequisites
- Python 3.11 or higher
- pip (Python package installer)
- Git

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/Harsh204k/codeGuardian.git
cd codeGuardian

# Install dependencies
pip install -r requirements.txt
```

**Expected time:** 5-10 minutes

---

## ☁️ Kaggle Installation

### Method 1: Automated Installation (Recommended)

Use the optimized installation script that handles all version conflicts:

```python
# In your Kaggle notebook, after cloning the repo:
!python install_kaggle.py
```

This script will:
- ✅ Install dependencies in the correct order
- ✅ Fix version conflicts automatically (pyarrow, cudf-polars, scikit-learn)
- ✅ Show clear progress with status indicators
- ✅ Verify all packages are installed correctly

**Expected time:** 2-3 minutes

### Method 2: Manual Installation

If the automated script fails, install manually:

```python
# Step 1: Fix critical conflicts first
!pip install --quiet 'pyarrow>=19.0.0,<20.0.0' --force-reinstall
!pip install --quiet cudf-polars-cu12==25.2.2 polars==1.21.0 --force-reinstall

# Step 2: Install core dependencies
!pip install --quiet 'scikit-learn>=1.5.0,<1.6.0' 'rich>=13.0.0,<14.0.0'
!pip install --quiet tqdm jsonschema loguru memory_profiler bandit

# Step 3: Install deep learning libraries (if needed)
!pip install --quiet 'transformers>=4.40.0' 'datasets>=2.19.0' 'accelerate>=0.30.0'
```

### Method 3: Standard pip install

```python
# Basic installation (may show conflicts, but will work)
!pip install -r requirements.txt
```

⚠️ **Note:** You'll see dependency conflict warnings on Kaggle. This is **normal** and expected because Kaggle pre-installs many packages. These warnings won't affect preprocessing functionality.

---

## 🔍 Understanding Dependency Conflicts

### Why do conflicts appear?

Kaggle notebooks come with many pre-installed packages (tensorflow, bigframes, cudf, etc.). When we install our requirements, some version mismatches occur:

**Common conflicts you'll see:**
1. **pyarrow**: datasets needs >=21.0.0, but cudf needs <20.0.0
   - ✅ **Solution**: We pin to 19.0.0 (works with both)

2. **scikit-learn**: category-encoders needs <1.6.0
   - ✅ **Solution**: We pin to <1.6.0

3. **tensorboard**: tensorflow needs <2.19
   - ✅ **Solution**: We pin to >=2.18.0,<2.19.0

4. **rich**: bigframes needs <14
   - ✅ **Solution**: We pin to <14.0.0

### Are these conflicts a problem?

**No!** The preprocessing scripts only use:
- Core Python libraries (json, pathlib, hashlib)
- pandas, numpy (always compatible)
- tqdm, jsonschema (no conflicts)

The conflicts affect packages we **don't use** during preprocessing (bigframes, cesium, sklearn-compat, gradio, etc.).

---

## ✅ Verification

After installation, verify everything works:

```python
# Check key packages
import json
print("✅ Checking installed packages...")

packages = {
    'numpy': 'Data processing',
    'pandas': 'DataFrame operations',
    'tqdm': 'Progress bars',
    'jsonschema': 'Data validation',
    'pyarrow': 'Parquet I/O',
    'transformers': 'CodeBERT models (optional)',
    'datasets': 'HuggingFace datasets (optional)'
}

for pkg, purpose in packages.items():
    try:
        mod = __import__(pkg.replace('-', '_'))
        version = getattr(mod, '__version__', 'unknown')
        print(f"✅ {pkg:15s} {version:10s} - {purpose}")
    except ImportError:
        print(f"❌ {pkg:15s} NOT FOUND  - {purpose}")
```

**Expected output:**
```
✅ numpy          1.26.4     - Data processing
✅ pandas         2.2.3      - DataFrame operations
✅ tqdm           4.67.1     - Progress bars
✅ jsonschema     4.25.0     - Data validation
✅ pyarrow        19.0.0     - Parquet I/O
✅ transformers   4.53.3     - CodeBERT models (optional)
✅ datasets       4.1.1      - HuggingFace datasets (optional)
```

---

## 📝 Minimal Installation

If you only want to run **preprocessing** (not training), you can skip heavy dependencies:

```python
# Minimal installation for preprocessing only
!pip install --quiet tqdm jsonschema loguru \
    'pyarrow>=19.0.0,<20.0.0' \
    'scikit-learn>=1.5.0,<1.6.0' \
    'rich>=13.0.0,<14.0.0'
```

This installs only what's needed for:
- Loading datasets (CSV, JSON, JSONL)
- Data validation (JSON Schema)
- Deduplication (SHA-256 hashing)
- Progress tracking (tqdm)
- Logging (loguru)

**Size:** ~50 MB
**Time:** ~30 seconds

---

## 🐛 Troubleshooting

### Issue: "ERROR: pip's dependency resolver..."

**This is just a warning, not an error!** The packages will still install and work correctly.

### Issue: Scripts not in PATH

```
WARNING: The script X is installed in '/root/.local/bin' which is not on PATH.
```

**Solution:** Add to PATH in your notebook:
```python
import os
import sys
os.environ['PATH'] = '/root/.local/bin:' + os.environ['PATH']
```

### Issue: Out of memory during installation

**Solution:** Install in smaller batches:
```python
!pip install --quiet tqdm jsonschema loguru
!pip install --quiet pyarrow==19.0.0
!pip install --quiet scikit-learn==1.5.2
```

### Issue: Package conflicts prevent installation

**Solution:** Use force-reinstall:
```python
!pip install --quiet --force-reinstall 'pyarrow==19.0.0'
```

---

## 📚 Package Reference

### Required for Preprocessing
- **pyyaml**: YAML config files
- **regex**: Advanced text processing
- **tqdm**: Progress bars
- **jsonschema**: Data validation
- **pandas**: DataFrame operations
- **numpy**: Numerical operations
- **pyarrow**: Parquet I/O (fast caching)
- **loguru**: Enhanced logging

### Required for Training/Inference
- **torch**: PyTorch deep learning
- **transformers**: HuggingFace models (CodeBERT)
- **tokenizers**: Fast tokenization
- **datasets**: Dataset management
- **accelerate**: Distributed training
- **tensorboard**: Training visualization

### Optional Tools
- **bandit**: Security linting
- **memory_profiler**: Memory profiling
- **pytest**: Unit testing
- **xgboost**: Gradient boosting
- **scikit-learn**: Traditional ML

---

## 🚀 Quick Start After Installation

```python
# Verify installation
!python install_kaggle.py  # Shows package versions

# Run preprocessing
!python scripts/preprocessing/prepare_diversevul.py
!python scripts/preprocessing/prepare_devign.py
!python scripts/preprocessing/prepare_zenodo.py

# Expected outputs: ~340k total vulnerability records
```

---

## 📖 Additional Resources

- **Kaggle Setup Guide**: See `KAGGLE_DEPLOYMENT_GUIDE.md` for complete deployment instructions
- **Dataset Verification**: See `DIVERSEVUL_VERIFICATION.md` for dataset structure details
- **Preprocessing Changes**: See `PREPROCESSING_FIXES.md` for recent improvements

---

## 💡 Tips

1. **Use the automated script** (`install_kaggle.py`) - it's tested and handles all edge cases
2. **Ignore conflict warnings** - they don't affect preprocessing
3. **Pin versions** for reproducibility (already done in requirements.txt)
4. **Install minimal packages** if you only need preprocessing
5. **Use GPU runtime** on Kaggle for faster processing (more RAM)

---

## 🆘 Need Help?

If installation fails:
1. Check Python version: `python --version` (should be 3.11+)
2. Update pip: `pip install --upgrade pip`
3. Try manual installation (Method 2 above)
4. Create an issue on GitHub with error logs

**Common error patterns:**
- `Could not find a version that satisfies`: Check Python version
- `ERROR: pip's dependency resolver`: This is just a warning (safe to ignore)
- `MemoryError`: Use smaller batch installation or enable GPU runtime
