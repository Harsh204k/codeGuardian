# 🎯 MegaVul Quick Reference - Kaggle Edition

## ⚡ TL;DR - Get Started in 3 Steps

```bash
# 1. Update dataset path in config
# Edit: config_megavul.yaml
# Change: raw_dataset_dir: "/kaggle/input/codeguardian-datasets/megavul"

# 2. Test discovery
python test_discovery.py

# 3. Run processing
python prepare_megavul_chunked.py --test
```

---

## 📍 Your Dataset Path

Based on your screenshot: **`/kaggle/input/codeguardian-datasets/megavul`**

Update in `config_megavul.yaml`:
```yaml
raw_dataset_dir: "/kaggle/input/codeguardian-datasets/megavul"
```

---

## 🚀 Common Commands

```bash
# Quick test (1k records, no Drive)
python prepare_megavul_chunked.py --test --no-drive-sync

# Full processing (all 340k records)
python prepare_megavul_chunked.py

# Java only (fastest)
python prepare_megavul_chunked.py --languages Java

# With graphs (AST/PDG/CFG/DFG)
python prepare_megavul_chunked.py --include-graphs

# Resume after interruption
python prepare_megavul_chunked.py --resume
```

---

## 📊 Expected Performance

| Dataset | Records | Time | Output Size |
|---------|---------|------|-------------|
| Test | 1,000 | 30 sec | 50 MB |
| Java | 42,000 | 3 min | 600 MB |
| Full | 340,000 | 20 min | 6.8 GB |

---

## 💾 Kaggle Disk Management

**Free Tier Limit:** 20 GB

**Strategy:**
- Each chunk: ~1.5 GB
- After Drive upload: Auto-deleted
- Max disk usage: ~3 GB (2 chunks buffered)
- ✅ Stays under limit!

---

## 🐛 Quick Fixes

**"Dataset not found"**
```bash
ls /kaggle/input/  # Find exact path
# Update config_megavul.yaml
```

**"Out of memory"**
```yaml
# In config_megavul.yaml
chunk_size_records: 25000  # Reduce from 50000
```

**"Disk full"**
```bash
# Enable Drive sync (auto-cleanup)
python prepare_megavul_chunked.py  # Without --no-drive-sync
```

---

## 📁 Output Location

```
/kaggle/working/megavul_processed/
├── chunks/chunk_0001.jsonl.gz  (~500 MB each)
├── chunks/chunk_0002.jsonl.gz
└── logs/processing_summary.json

/content/drive/MyDrive/megavul_backup/  (if Drive enabled)
└── chunks/  (uploaded automatically)
```

---

## ✅ Verification

```bash
# Check logs
tail -20 megavul_preprocessing.log

# Check output
ls -lh /kaggle/working/megavul_processed/chunks/

# Check stats
cat /kaggle/working/megavul_processed/logs/processing_summary.json
```

---

## 📚 Documentation

- **KAGGLE_SETUP.md** - Detailed Kaggle guide
- **COMPLETE_UPDATE.md** - Full feature docs
- **OPTIMIZATION_SUMMARY.md** - Performance details

---

## 🆘 Help

Issues? Run diagnostics:
```bash
python test_discovery.py
python test_feature_parity.py
```

📖 **Full guide:** `KAGGLE_SETUP.md`
