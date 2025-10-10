# 📁 Dataset Upload Structure for Kaggle

## Required Folder Structure

When uploading datasets to Kaggle as `codeguardian-datasets`, use this **exact structure**:

```
codeguardian-datasets/           ← Your Kaggle dataset name
│
├── diversevul/
│   └── raw/                      ← Put files in raw/ subdirectory
│       ├── diversevul.json       (330k records, ~700MB)
│       ├── diversevul_metadata.json
│       └── label_noise/          (optional)
│           ├── diversevul-dataset-analysis.csv
│           ├── other_dataset_analysis.csv
│           └── summary.csv
│
├── devign/
│   └── raw/                      ← Put files in raw/ subdirectory
│       ├── ffmpeg.json
│       ├── qemu.json
│       ├── ffmpeg.csv            (or JSON files)
│       └── qemu.csv
│
└── zenodo/
    └── raw/                      ← Put files in raw/ subdirectory
        ├── data_C.csv
        ├── data_C++.csv
        ├── data_Java.csv
        ├── data_JavaScript.csv
        ├── data_Python.csv
        ├── data_PHP.csv
        ├── data_Go.csv
        └── data_Ruby.csv
```

---

## ✅ Correct Upload Method

### Option 1: Upload via Kaggle Web UI

1. Go to https://www.kaggle.com/datasets
2. Click **"New Dataset"**
3. Name it: `codeguardian-datasets`
4. **Upload the entire folder structure** as shown above
5. Make sure each dataset has its files in the `raw/` subdirectory

### Option 2: From Your Local Repository

Since you already have the correct structure locally:

```bash
# From your codeGuardian directory
cd datasets

# Your current structure (already correct!):
# diversevul/raw/  ← Contains diversevul.json, metadata, label_noise/
# devign/raw/      ← Contains ffmpeg.json, qemu.json, etc.
# zenodo/raw/      ← Contains data_C.csv, data_Java.csv, etc.
```

**Upload these three folders to Kaggle:**
1. Upload `diversevul` folder (with its `raw/` subdirectory)
2. Upload `devign` folder (with its `raw/` subdirectory)
3. Upload `zenodo` folder (with its `raw/` subdirectory)

---

## 🔍 What the Scripts Expect

The preprocessing scripts now **automatically detect** if files are in a `raw/` subdirectory:

### For DiverseVul:
```python
# Script will check both:
/kaggle/input/codeguardian-datasets/diversevul/diversevul.json          # Root level
/kaggle/input/codeguardian-datasets/diversevul/raw/diversevul.json      # Raw subdirectory ✅

# If found in raw/, it automatically adjusts the path
```

### For Zenodo:
```python
# Script will check both:
/kaggle/input/codeguardian-datasets/zenodo/data_C.csv                   # Root level
/kaggle/input/codeguardian-datasets/zenodo/raw/data_C.csv               # Raw subdirectory ✅
```

### For Devign:
```python
# Script already looks in raw/ by default:
/kaggle/input/codeguardian-datasets/devign/raw/ffmpeg.json              # ✅
```

---

## ❌ Common Mistakes

### Mistake 1: Uploading files at root level
```
❌ WRONG:
codeguardian-datasets/
├── diversevul.json              ← Files directly in dataset root
├── diversevul_metadata.json
├── data_C.csv
└── ffmpeg.json

✅ CORRECT:
codeguardian-datasets/
├── diversevul/
│   └── raw/
│       ├── diversevul.json      ← Files in dataset/raw/
│       └── diversevul_metadata.json
├── zenodo/
│   └── raw/
│       └── data_C.csv
└── devign/
    └── raw/
        └── ffmpeg.json
```

### Mistake 2: Missing raw/ subdirectory
```
❌ WRONG:
codeguardian-datasets/
└── diversevul/
    ├── diversevul.json          ← No raw/ subdirectory
    └── diversevul_metadata.json

✅ CORRECT:
codeguardian-datasets/
└── diversevul/
    └── raw/                     ← Files inside raw/
        ├── diversevul.json
        └── diversevul_metadata.json
```

### Mistake 3: Nested too deep
```
❌ WRONG:
codeguardian-datasets/
└── datasets/                    ← Extra 'datasets' folder
    └── diversevul/
        └── raw/
            └── diversevul.json

✅ CORRECT:
codeguardian-datasets/
└── diversevul/                  ← Direct child
    └── raw/
        └── diversevul.json
```

---

## 🚀 Quick Verification

After uploading to Kaggle, verify the structure:

```python
# In your Kaggle notebook:
from pathlib import Path

base = Path("/kaggle/input/codeguardian-datasets")

print("📦 Checking dataset structure...")
print()

# Check diversevul
diversevul_dir = base / "diversevul" / "raw"
if diversevul_dir.exists():
    print("✅ diversevul/raw/ found")
    print(f"   Files: {[f.name for f in diversevul_dir.glob('*.json')]}")
else:
    print("❌ diversevul/raw/ NOT FOUND")

# Check zenodo
zenodo_dir = base / "zenodo" / "raw"
if zenodo_dir.exists():
    print("✅ zenodo/raw/ found")
    print(f"   Files: {len(list(zenodo_dir.glob('*.csv')))} CSV files")
else:
    print("❌ zenodo/raw/ NOT FOUND")

# Check devign
devign_dir = base / "devign" / "raw"
if devign_dir.exists():
    print("✅ devign/raw/ found")
    print(f"   Files: {[f.name for f in devign_dir.glob('*.json') or devign_dir.glob('*.csv')]}")
else:
    print("❌ devign/raw/ NOT FOUND")
```

**Expected output:**
```
📦 Checking dataset structure...

✅ diversevul/raw/ found
   Files: ['diversevul.json', 'diversevul_metadata.json']
✅ zenodo/raw/ found
   Files: 8 CSV files
✅ devign/raw/ found
   Files: ['ffmpeg.json', 'qemu.json', ...]
```

---

## 📝 File Size Reference

Make sure your files are uploaded completely:

| Dataset | File | Expected Size |
|---------|------|---------------|
| **DiverseVul** | diversevul.json | ~700 MB |
| **DiverseVul** | diversevul_metadata.json | ~50 MB |
| **Zenodo** | data_C.csv | ~10 MB |
| **Zenodo** | data_Java.csv | ~5 MB |
| **Devign** | ffmpeg.json | ~20 MB |
| **Devign** | qemu.json | ~15 MB |

---

## 🔧 Troubleshooting

### Issue: "Dataset file not found"

**Check:**
1. Is the dataset named exactly `codeguardian-datasets` (lowercase)?
2. Are files in the `raw/` subdirectory?
3. Are file names exactly: `diversevul.json`, `data_C.csv`, etc.?

### Issue: "Input directory exists: False"

**Solution:**
```python
# In Kaggle notebook, check what you actually have:
!ls -la /kaggle/input/
!ls -la /kaggle/input/codeguardian-datasets/
!ls -la /kaggle/input/codeguardian-datasets/diversevul/
```

This will show you the actual structure uploaded.

---

## 💡 Pro Tips

1. **Compress before upload**: Large files upload faster when zipped
   ```bash
   cd datasets
   zip -r diversevul.zip diversevul/
   zip -r zenodo.zip zenodo/
   zip -r devign.zip devign/
   ```

2. **Upload incrementally**: Upload one dataset at a time to verify structure

3. **Use Kaggle API**: For large files (>500MB), use the API:
   ```bash
   kaggle datasets create -p ./datasets --dir-mode zip
   ```

4. **Verify after upload**: Always run the verification script above

---

## ✅ Final Checklist

Before running preprocessing:

- [ ] Dataset named `codeguardian-datasets` on Kaggle
- [ ] Three folders: `diversevul/`, `zenodo/`, `devign/`
- [ ] Each folder has `raw/` subdirectory
- [ ] Files are inside `raw/` subdirectories
- [ ] File sizes match expected values
- [ ] Verification script shows all ✅ checkmarks
- [ ] Dataset is added as input to your Kaggle notebook

Once all checked, you're ready to run:
```python
!python install_kaggle.py
!python scripts/preprocessing/prepare_diversevul.py
!python scripts/preprocessing/prepare_devign.py
!python scripts/preprocessing/prepare_zenodo.py
```

---

**Last Updated:** October 10, 2025
**Commit:** Latest (with raw/ detection)
