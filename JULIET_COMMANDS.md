# Juliet Preprocessing - Command Reference

## 🚀 Quick Start Commands

### Test with small sample (RECOMMENDED FIRST):
```python
import os
os.chdir('/kaggle/working/codeGuardian/scripts/preprocessing')
os.system("python prepare_juliet_parallel.py --max-files 1000 --workers 4")
```

### Process all files (full dataset):
```python
import os
os.chdir('/kaggle/working/codeGuardian/scripts/preprocessing')
os.system("python prepare_juliet_parallel.py --workers 8")
```

---

## 📋 All Command Options

### Basic Usage:
```bash
python prepare_juliet_parallel.py
```
- Processes ALL languages (C, C++, Java, C#)
- Uses all available CPU cores
- Processes all 185,323 files

---

### Control Number of Workers:
```bash
python prepare_juliet_parallel.py --workers 4
```
- Use 4 CPU cores for parallel processing
- Kaggle free tier: Use `--workers 2`
- Kaggle premium: Use `--workers 4` or `--workers 8`

---

### Test with Limited Files:
```bash
python prepare_juliet_parallel.py --max-files 1000
```
- Process only first 1000 files
- Great for testing before full run
- Estimated time: 45 seconds

```bash
python prepare_juliet_parallel.py --max-files 10000 --workers 8
```
- Process 10,000 files with 8 workers
- Estimated time: 4-5 minutes

---

### Filter by Language:

#### Process only C/C++ files:
```bash
python prepare_juliet_parallel.py --languages c cpp
```
- Processes: 61,387 C/C++ files
- Output: ~122,774 records (bad + good functions)
- Time: ~5 minutes with 8 workers

#### Process only Java files:
```bash
python prepare_juliet_parallel.py --languages java
```
- Processes: 88,481 Java files
- Output: ~176,962 records
- Time: ~7 minutes with 8 workers

#### Process only C# files:
```bash
python prepare_juliet_parallel.py --languages csharp
```
- Processes: 35,455 C# files
- Output: ~70,910 records
- Time: ~3 minutes with 8 workers

#### Process C and Java only:
```bash
python prepare_juliet_parallel.py --languages c java --workers 8
```

---

## 🎯 Recommended Workflows

### 1. Quick Test (1-2 minutes):
```python
import os
os.chdir('/kaggle/working/codeGuardian/scripts/preprocessing')

# Test with 500 files
os.system("python prepare_juliet_parallel.py --max-files 500 --workers 2")
```

### 2. Language-Specific Processing:

**C/C++ Only** (for buffer overflow vulnerabilities):
```python
os.system("python prepare_juliet_parallel.py --languages c cpp --workers 8")
```

**Java Only** (for injection vulnerabilities):
```python
os.system("python prepare_juliet_parallel.py --languages java --workers 8")
```

### 3. Full Dataset Processing (~15 minutes):
```python
os.system("python prepare_juliet_parallel.py --workers 8")
```

---

## 📊 Expected Output Sizes

| Configuration | Files | Records | Time (8 workers) | Output Size |
|--------------|-------|---------|------------------|-------------|
| `--max-files 100` | 100 | ~200 | 10 sec | ~200 KB |
| `--max-files 1000` | 1,000 | ~2,000 | 45 sec | ~2 MB |
| `--languages c` | 61,387 | ~122,774 | 5 min | ~150 MB |
| `--languages java` | 88,481 | ~176,962 | 7 min | ~220 MB |
| ALL languages | 185,323 | ~370,646 | 15 min | ~450 MB |

---

## 🔍 Verify Output Files

```python
import json
from pathlib import Path

# Check if files exist
output_dir = Path("/kaggle/working/datasets/juliet/processed")
print(f"Output directory: {output_dir}")
print(f"Exists: {output_dir.exists()}\n")

# Check JSONL file
jsonl_file = output_dir / "raw_cleaned.jsonl"
if jsonl_file.exists():
    with open(jsonl_file, 'r') as f:
        num_records = sum(1 for _ in f)
    print(f"✅ raw_cleaned.jsonl: {num_records} records")
    print(f"   File size: {jsonl_file.stat().st_size / 1024 / 1024:.2f} MB")
else:
    print("❌ raw_cleaned.jsonl not found")

# Check stats file
stats_file = output_dir / "stats.json"
if stats_file.exists():
    with open(stats_file, 'r') as f:
        stats = json.load(f)
    print(f"\n✅ stats.json:")
    print(f"   Total records: {stats['total_records']}")
    print(f"   Vulnerable: {stats['vulnerable_records']}")
    print(f"   Safe: {stats['non_vulnerable_records']}")
    print(f"   Languages: {list(stats['languages'].keys())}")
    print(f"   Unique CWEs: {stats['unique_cwes']}")
    print(f"\n   Top 5 CWEs:")
    for cwe, count in list(stats['top_10_cwes'].items())[:5]:
        print(f"     {cwe}: {count} records")
else:
    print("❌ stats.json not found")
```

---

## 🐛 Troubleshooting

### Error: "No such file or directory"
```python
# Check if input dataset exists
import os
print(os.path.exists("/kaggle/input/codeguardian-datasets/juliet/raw"))

# List available directories
!ls /kaggle/input/codeguardian-datasets/juliet/raw/
```

### Error: "Permission denied"
```python
# Make sure output directory is writable
output_dir = Path("/kaggle/working/datasets/juliet/processed")
output_dir.mkdir(parents=True, exist_ok=True)
```

### Script runs but produces 0 records:
```python
# Check if source files exist
!ls /kaggle/input/codeguardian-datasets/juliet/raw/c/testcases/
!ls /kaggle/input/codeguardian-datasets/juliet/raw/java/src/testcases/

# Try with verbose mode and check logs
os.system("python prepare_juliet_parallel.py --max-files 10 --workers 1")
```

---

## 💡 Pro Tips

1. **Start Small**: Always test with `--max-files 100` first
2. **Monitor Progress**: The script shows real-time progress bars
3. **Check Kaggle Resources**: Monitor CPU/Memory usage in Kaggle
4. **Save Checkpoints**: Kaggle has auto-save, but manually save after big runs
5. **Combine with DiverseVul**: Process both datasets for comprehensive training data

---

## 📈 Performance Optimization

### For Kaggle Free Tier (2 cores):
```bash
python prepare_juliet_parallel.py --workers 2
```

### For Kaggle Premium (4+ cores):
```bash
python prepare_juliet_parallel.py --workers 8
```

### For Testing/Development:
```bash
python prepare_juliet_parallel.py --max-files 100 --workers 2
```

### For Production (full dataset):
```bash
python prepare_juliet_parallel.py --workers 8 --languages all
```

---

## 🎓 Understanding the Output

### raw_cleaned.jsonl structure:
```json
{
  "code": "void bad() { char buffer[10]; strcpy(buffer, input); }",
  "label": 1,
  "language": "C",
  "cwe_id": "CWE-121",
  "file_path": "CWE121_Stack_Based_Buffer_Overflow/s01/...",
  "function_type": "bad",
  "description": "Stack-based buffer overflow via strcpy",
  "testcase_id": "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_01",
  "dataset": "juliet",
  "index": 42
}
```

**Fields:**
- `code`: Extracted function code
- `label`: 1 = vulnerable, 0 = safe
- `language`: C, C++, Java, or C#
- `cwe_id`: Standardized CWE identifier
- `function_type`: "bad" or "good"
- `description`: Vulnerability description (if available)
- `testcase_id`: Unique test case identifier

---

**Ready to test!** 🚀

Run the test script:
```python
exec(open('/kaggle/working/codeGuardian/test_juliet_kaggle.py').read())
```
