# 🚀 STEP-BY-STEP: Fix DiverseVul on Kaggle

Follow these steps **exactly** to get preprocessing working.

---

## 📋 Step 1: Clone Latest Code

```python
# Remove old code if exists
%cd /kaggle/working
!rm -rf codeGuardian

# Clone latest version with fixes
!git clone https://github.com/Harsh204k/codeGuardian.git
%cd codeGuardian
```

**Expected output:**
```
Cloning into 'codeGuardian'...
/kaggle/working/codeGuardian
```

---

## 🔍 Step 2: Run Diagnostic Tool

```python
# Run diagnostic to check dataset structure
!python diagnose_dataset.py
```

**This will show you:**
- ✅ Whether dataset files exist
- 📂 Where files are located (root vs raw/)
- 📊 File sizes (to verify complete upload)
- 💡 Recommendations if issues found

**Expected output (if correct):**
```
📦 DIVERSEVUL DATASET DIAGNOSTIC
════════════════════════════════════════

1️⃣ Base directory: /kaggle/input/codeguardian-datasets/diversevul
   Exists: ✅ Yes

2️⃣ Checking for files at root level...
   ❌ diversevul.json: NOT FOUND
   ❌ diversevul_metadata.json: NOT FOUND

3️⃣ Checking for 'raw' subdirectory...
   raw/ exists: ✅ Yes

4️⃣ Checking for files in raw/ subdirectory...
   ✅ diversevul.json: 702.5 MB
   ✅ diversevul_metadata.json: 48.3 MB
   ✅ label_noise/ directory: Found

🎯 RECOMMENDATION:
════════════════════════════════════════
✅ Files found in RAW/ subdirectory
   Script will use: /kaggle/input/codeguardian-datasets/diversevul/raw/
```

---

## ⚠️ Step 3: Fix Issues (If Any)

### If diagnostic shows problems:

#### Problem A: "diversevul directory not found"
**Fix:** Re-upload dataset or check dataset name
```python
# Check what's actually uploaded
!ls -la /kaggle/input/
```

#### Problem B: "raw/ exists: ❌ No"
**Fix:** Your upload structure is wrong. You need to re-upload with correct structure:
```
codeguardian-datasets/
└── diversevul/
    └── raw/              ← This folder is missing!
        ├── diversevul.json
        └── diversevul_metadata.json
```

#### Problem C: "diversevul.json: NOT FOUND" (in both locations)
**Fix:** File wasn't uploaded. Upload diversevul.json (~700MB) to the raw/ directory.

#### Problem D: File size too small (< 500MB)
**Fix:** Upload was incomplete. Re-upload diversevul.json.

---

## ✅ Step 4: Run Preprocessing (Only After Diagnostic Passes)

```python
# Run preprocessing
!python scripts/preprocessing/prepare_diversevul.py
```

**New enhanced output will show:**
```
🔍 Checking for dataset files...
   raw/ subdirectory exists: True
   diversevul.json at root: False
   diversevul.json in raw/: True

✅ Files detected in 'raw' subdirectory!
   Switching input directory to: /kaggle/input/.../diversevul/raw

📂 FINAL INPUT PATH: /kaggle/input/.../diversevul/raw
📂 OUTPUT PATH: /kaggle/working/datasets/diversevul/processed

📁 Files at final input path:
   📄 diversevul.json (702.5 MB)
   📄 diversevul_metadata.json (48.3 MB)
   📂 label_noise/

🔍 Looking for metadata: .../diversevul/raw/diversevul_metadata.json
✓ Metadata exists: True

🔍 Looking for main dataset: .../diversevul/raw/diversevul.json
✓ Dataset file exists: True

Processing DiverseVul: 100%|██████████| 330492/330492 [28:45<00:00, 191.52it/s]
```

---

## 📊 Step 5: Verify Success

```python
# Check output files
!ls -lh /kaggle/working/datasets/diversevul/processed/

# Check stats
import json
with open('/kaggle/working/datasets/diversevul/processed/stats.json') as f:
    stats = json.load(f)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Languages: {len(stats['languages'])}")
```

**Expected output:**
```
-rw-r--r-- 1 root root 585M Oct 10 12:34 raw_cleaned.jsonl
-rw-r--r-- 1 root root 2.1K Oct 10 12:34 stats.json

Total records: 310558
Vulnerable: 155279
Languages: 7
```

---

## 🐛 Troubleshooting Matrix

| Issue | Cause | Fix |
|-------|-------|-----|
| **"diversevul directory not found"** | Dataset not added to notebook | Add `codeguardian-datasets` as input |
| **"raw/ exists: ❌ No"** | Wrong upload structure | Re-upload with raw/ subdirectory |
| **"diversevul.json: NOT FOUND"** (both locations) | File not uploaded | Upload diversevul.json to raw/ |
| **File size < 500MB** | Incomplete upload | Re-upload file completely |
| **"Could not load metadata"** | Metadata file missing/corrupt | Upload diversevul_metadata.json |
| **Script runs but 0 records** | Wrong file content | Verify JSON format |

---

## 💡 Quick Debug Commands

```python
# Check Kaggle input structure
!tree /kaggle/input/codeguardian-datasets/ -L 3

# Check file sizes
!du -sh /kaggle/input/codeguardian-datasets/diversevul/raw/*

# Peek at first line of dataset
!head -c 1000 /kaggle/input/codeguardian-datasets/diversevul/raw/diversevul.json

# Check if it's JSONL (one JSON per line)
!head -n 2 /kaggle/input/codeguardian-datasets/diversevul/raw/diversevul.json | wc -l
```

---

## 🎯 Summary Checklist

Before running preprocessing, verify:

- [ ] **Step 1 done**: Latest code cloned
- [ ] **Step 2 done**: Diagnostic ran and passed ✅
- [ ] **Diagnostic shows**: "Files found in RAW/ subdirectory"
- [ ] **Diagnostic shows**: diversevul.json ~700MB
- [ ] **Diagnostic shows**: diversevul_metadata.json ~50MB
- [ ] **Ready**: Run preprocessing script

If ANY checkbox is ❌, **don't run preprocessing yet** - fix issues first!

---

## 📞 Need Help?

**Share the COMPLETE output of:**
```python
!python diagnose_dataset.py
```

This shows me exactly what structure you have and I can give precise fix instructions.

---

## 🎉 Success Indicators

You'll know it's working when you see:

1. ✅ Diagnostic passes all checks
2. ✅ "Files detected in 'raw' subdirectory!"
3. ✅ "Dataset file exists: True"
4. ✅ Progress bar appears: "Processing DiverseVul: X%"
5. ✅ Final output: "Total records: ~310k"

**Estimated time:** 30-45 minutes for 330k records

---

**Last Updated:** October 10, 2025  
**Version:** Enhanced with diagnostic tool  
**Commit:** 3808745
