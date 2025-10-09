# 🔍 Kaggle CSV Processing Issue - Diagnostic Guide

## Current Problem

The preprocessing scripts on Kaggle show:
- ✅ Reading CSV files (progress bars show thousands of records)
- ❌ Writing **0 records** to output
- ❌ All records are being rejected during processing

## What You Need to Do on Kaggle

### Step 1: Run the Diagnostic Script

Add this cell to your Kaggle notebook **AFTER** cloning the repo:

```python
# Run diagnostic to see actual CSV structure
!python scripts/debug_zenodo_csv.py
```

**This will show you:**
- Actual column names in the CSV files
- Sample data from first row
- Which expected columns are present/missing
- Data types and missing values

### Step 2: Copy the Output and Share It

The diagnostic output will look like this:

```
============================================================
CSV STRUCTURE ANALYSIS
============================================================
File: data_C.csv
Total columns: 8

Column names:
  1. 'func'
  2. 'target'
  3. 'CWE'
  4. 'CVE'
  5. 'project'
  6. 'commit_id'
  7. 'file_path'
  8. 'func_name'

EXPECTED COLUMNS CHECK
============================================================
  code: ❌ MISSING
  Code: ❌ MISSING
  source_code: ❌ MISSING
  label: ❌ MISSING
  ...
```

**Copy this entire output and share it** - this will tell me exactly what column names the CSV files are using.

## Why This Happens

The preprocessing script is looking for columns like:
- `code` or `Code` or `source_code` → for the source code
- `label` or `Label` or `vulnerable` → for the vulnerability label
- `CWE_ID` or `cwe_id` or `CWE` → for CWE identifiers

But the actual CSV files might use **different column names** like:
- `func` instead of `code`
- `target` instead of `label`
- etc.

## Solution

Once you share the diagnostic output, I'll update the preprocessing script to use the **correct column names** that match your actual CSV files.

## Quick Alternative Test (If Diagnostic Doesn't Work)

If the diagnostic script fails, you can manually check the CSV structure:

```python
# In Kaggle notebook
import pandas as pd

# Read first few rows of a CSV
df = pd.read_csv('/kaggle/input/codeguardian-datasets/zenodo/data_C.csv', nrows=3)

# Show column names
print("Columns:", list(df.columns))

# Show first row
print("\nFirst row:")
print(df.iloc[0])
```

Then share the output.

## Expected Next Steps

1. ✅ You run diagnostic script on Kaggle
2. ✅ You share the output here
3. ✅ I fix the column name mappings in the preprocessing scripts
4. ✅ You commit and push the changes
5. ✅ You re-run on Kaggle and see records being processed

---

## Example: If Column Names Are Different

Let's say the diagnostic shows the CSV actually uses:
- `func` for code
- `target` for label  
- `CWE` for CWE ID

Then I would update `prepare_zenodo.py` like this:

```python
# OLD (current)
code = row.get('code', row.get('Code', row.get('source_code', '')))
label = row.get('label', row.get('Label', row.get('vulnerable', '0')))

# NEW (fixed)
code = row.get('func', row.get('code', row.get('Code', row.get('source_code', ''))))
label = row.get('target', row.get('label', row.get('Label', row.get('vulnerable', '0'))))
```

This adds `func` and `target` as the **first fallback options** before trying the others.

---

## Summary

**Your action items:**
1. Run `!python scripts/debug_zenodo_csv.py` on Kaggle
2. Copy the entire output
3. Paste it here

Then I'll fix the column mappings for you immediately.

