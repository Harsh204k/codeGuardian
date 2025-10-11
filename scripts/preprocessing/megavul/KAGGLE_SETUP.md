# 🚀 Kaggle Setup Guide for MegaVul Processing

## 📋 Prerequisites

1. **Dataset Added to Kaggle Notebook**
   - Go to your Kaggle notebook
   - Click "Add Data" → Search for "megavul" or "codeguardian-datasets"
   - Add the MegaVul dataset
   - Note the mounted path (usually `/kaggle/input/<dataset-name>/megavul`)

2. **Clone CodeGuardian Repository**
   ```bash
   cd /kaggle/working
   git clone https://github.com/Harsh204k/codeGuardian.git
   cd codeGuardian
   ```

---

## ⚙️ Configuration Steps

### **Step 1: Find Your Dataset Path**

Run this in your Kaggle notebook to find the exact path:

```bash
# List all input datasets
ls -la /kaggle/input/

# Find MegaVul specifically
find /kaggle/input -name "megavul" -type d
```

**Common paths:**
- `/kaggle/input/codeguardian-datasets/megavul` ← **Your actual path**
- `/kaggle/input/megavul`
- `/kaggle/input/megavul-dataset/megavul`

### **Step 2: Update Configuration**

Edit `scripts/preprocessing/megavul/config_megavul.yaml`:

```yaml
# Update this line with YOUR actual path
raw_dataset_dir: "/kaggle/input/codeguardian-datasets/megavul"
```

### **Step 3: Verify Dataset Structure**

```bash
cd scripts/preprocessing/megavul
python test_discovery.py
```

**Expected output:**
```
✅ Found dataset at: /kaggle/input/codeguardian-datasets/megavul
🔍 Discovering MegaVul files...
   Found 2 date directories: ['2023-11', '2024-04']
   Total JSON files: 8,542
```

---

## 🚀 Processing Options

### **Option 1: Quick Test (Recommended First)**

```bash
cd /kaggle/working/codeGuardian/scripts/preprocessing/megavul
python prepare_megavul_chunked.py --test --no-drive-sync
```

**What this does:**
- Processes only 1,000 records
- No Google Drive upload (faster testing)
- Validates everything works
- Takes ~30-60 seconds

### **Option 2: Small Batch (No Drive)**

```bash
python prepare_megavul_chunked.py --max-records 10000 --no-drive-sync
```

**What this does:**
- Processes 10,000 records
- Saves locally to `/kaggle/working`
- Good for testing full pipeline
- Takes ~2-3 minutes

### **Option 3: Full Processing with Drive Backup**

```bash
# Mount Google Drive first
from google.colab import drive
drive.mount('/content/drive')

# Then run
python prepare_megavul_chunked.py
```

**What this does:**
- Processes all ~340,000 records
- Uploads chunks to Google Drive (recommended!)
- Auto-deletes local files after upload
- Takes ~20-25 minutes

### **Option 4: Specific Language Only**

```bash
# Java only (fastest - ~42k records)
python prepare_megavul_chunked.py --languages Java

# C/C++ only (~298k records)
python prepare_megavul_chunked.py --languages C C++
```

### **Option 5: With Graph Extraction**

```bash
python prepare_megavul_chunked.py --include-graphs
```

**Note:** Graph extraction adds AST/PDG/CFG/DFG metadata but increases processing time by ~30%.

---

## 📊 Monitoring Progress

### **Check Logs**
```bash
# View real-time logs
tail -f /kaggle/working/codeGuardian/scripts/preprocessing/megavul/megavul_preprocessing.log

# Or in Python notebook
!tail -20 megavul_preprocessing.log
```

### **Check Output**
```bash
# List created chunks
ls -lh /kaggle/working/megavul_processed/chunks/

# Check disk usage
df -h /kaggle/working
```

### **Expected Disk Usage (Kaggle Free Tier: 20GB limit)**
- Per chunk: ~1.5 GB (before compression)
- Compressed: ~500 MB per chunk
- Max simultaneous: ~3 GB (2 chunks buffered)
- **Stays well under 20GB limit!** ✅

---

## 🛑 Common Issues & Solutions

### **Issue 1: "Dataset not found"**

**Error:**
```
❌ Test path not found: /kaggle/input/codeguardian-datasets/megavul
```

**Solution:**
```bash
# Find exact path
ls -la /kaggle/input/

# Update config with correct path
# Edit: scripts/preprocessing/megavul/config_megavul.yaml
```

### **Issue 2: "Out of memory"**

**Error:**
```
MemoryError: Unable to allocate array
```

**Solution:**
```bash
# Reduce chunk size in config
# Edit config_megavul.yaml:
chunk_size_records: 25000  # Was 50000
```

Or process by language:
```bash
python prepare_megavul_chunked.py --languages Java  # Smaller dataset
```

### **Issue 3: "Disk quota exceeded"**

**Error:**
```
OSError: [Errno 28] No space left on device
```

**Solution:**
1. **Enable Drive sync** (auto-deletes local files):
   ```bash
   # Don't use --no-drive-sync
   python prepare_megavul_chunked.py
   ```

2. **Or clear working directory:**
   ```bash
   rm -rf /kaggle/working/megavul_processed/chunks/*
   ```

### **Issue 4: "Drive mount failed"**

**Solution:**
```python
# In Kaggle notebook cell
from google.colab import drive
drive.mount('/content/drive', force_remount=True)
```

Then verify:
```bash
ls /content/drive/MyDrive
```

### **Issue 5: Session timeout (Kaggle 9-hour limit)**

**Solution:**
```bash
# Use resume flag
python prepare_megavul_chunked.py --resume
```

This continues from the last completed chunk!

---

## 📁 Output Structure

```
/kaggle/working/megavul_processed/
├── chunks/
│   ├── chunk_0001.jsonl.gz  (50k records, ~500 MB)
│   ├── chunk_0002.jsonl.gz
│   └── ...
├── logs/
│   ├── processing_summary.json
│   └── upload_log.json
└── resume_tracker.json

/content/drive/MyDrive/megavul_backup/  (if Drive enabled)
├── chunks/
│   ├── chunk_0001.jsonl.gz
│   └── ...
└── logs/
```

---

## ⚡ Performance Tips

### **Maximize Speed**

1. **Use Kaggle GPU instances** (if available)
   - More CPU cores = faster processing
   - Settings → Accelerator → GPU/TPU

2. **Process by language**
   ```bash
   # Java first (smallest)
   python prepare_megavul_chunked.py --languages Java
   
   # Then C/C++
   python prepare_megavul_chunked.py --languages C C++
   ```

3. **Skip graph extraction** (unless needed)
   ```bash
   # Faster without --include-graphs
   python prepare_megavul_chunked.py
   ```

4. **Increase chunk size** (if you have extra RAM)
   ```yaml
   # In config_megavul.yaml
   chunk_size_records: 75000  # If you have 32GB+ RAM
   ```

---

## ✅ Success Checklist

After processing completes, verify:

- [ ] All chunks created (check `chunks/` directory)
- [ ] Chunks uploaded to Drive (if enabled)
- [ ] Processing summary generated
- [ ] Expected record count matches estimate
- [ ] No errors in log file
- [ ] Labels balanced (check stats.json)

**Expected Statistics:**
```json
{
  "total_records": 340000,
  "vulnerable_records": 17380,
  "non_vulnerable_records": 322620,
  "vulnerability_ratio": 0.0511,
  "chunks_created": 7
}
```

---

## 📚 Next Steps

After successful preprocessing:

1. **Download chunks from Drive**
   ```bash
   python postprocess_megavul.py --download
   ```

2. **Merge chunks into single dataset**
   ```bash
   python postprocess_megavul.py --merge --format parquet
   ```

3. **Use for model training**
   ```python
   import pandas as pd
   df = pd.read_parquet('merged_dataset.parquet')
   ```

---

## 🆘 Getting Help

If you encounter issues:

1. **Check logs:**
   ```bash
   cat megavul_preprocessing.log
   ```

2. **Run diagnostic:**
   ```bash
   python test_discovery.py
   python test_feature_parity.py
   ```

3. **GitHub Issues:**
   https://github.com/Harsh204k/codeGuardian/issues

---

## 📖 Additional Resources

- **`COMPLETE_UPDATE.md`** - Full feature documentation
- **`OPTIMIZATION_SUMMARY.md`** - Performance optimizations
- **`FEATURE_PARITY.md`** - Feature comparison
- **`config_megavul.yaml`** - All configuration options

---

**Ready to process? Start with:**
```bash
cd /kaggle/working/codeGuardian/scripts/preprocessing/megavul
python test_discovery.py  # Verify dataset
python prepare_megavul_chunked.py --test  # Quick test
```

🚀 **Happy processing!**
