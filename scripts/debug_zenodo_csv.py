#!/usr/bin/env python3
"""
Quick diagnostic script to check Zenodo CSV structure.
Run this on Kaggle to see what columns exist in the CSV files.
"""

import sys
from pathlib import Path
import pandas as pd

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.utils.kaggle_paths import get_dataset_path, print_environment_info

def main():
    print_environment_info()
    
    # Get dataset path
    zenodo_dir = get_dataset_path("zenodo")
    print(f"\n[INFO] Zenodo directory: {zenodo_dir}")
    
    # Check for CSV files
    csv_files = list(Path(zenodo_dir).glob("*.csv"))
    print(f"[INFO] Found {len(csv_files)} CSV files")
    
    if not csv_files:
        print("[ERROR] No CSV files found!")
        return
    
    # Analyze first CSV file
    first_csv = csv_files[0]
    print(f"\n[INFO] Analyzing: {first_csv.name}")
    
    # Read with pandas
    df = pd.read_csv(first_csv, nrows=5)
    
    print(f"\n{'='*60}")
    print(f"CSV STRUCTURE ANALYSIS")
    print(f"{'='*60}")
    print(f"File: {first_csv.name}")
    print(f"Total columns: {len(df.columns)}")
    print(f"\nColumn names:")
    for i, col in enumerate(df.columns, 1):
        print(f"  {i}. '{col}'")
    
    print(f"\nFirst row sample:")
    first_row = df.iloc[0]
    for col in df.columns[:8]:  # Show first 8 columns
        value = str(first_row[col])
        if len(value) > 100:
            value = value[:100] + "..."
        print(f"  {col}: {value}")
    
    print(f"\n{'='*60}")
    print(f"DATA TYPES")
    print(f"{'='*60}")
    print(df.dtypes)
    
    print(f"\n{'='*60}")
    print(f"MISSING VALUES")
    print(f"{'='*60}")
    print(df.isnull().sum())
    
    # Check what we're looking for
    print(f"\n{'='*60}")
    print(f"EXPECTED COLUMNS CHECK")
    print(f"{'='*60}")
    expected = ['code', 'Code', 'source_code', 'label', 'Label', 'vulnerable',
                'CWE_ID', 'cwe_id', 'CWE', 'CVE_ID', 'cve_id', 'CVE']
    for exp in expected:
        exists = exp in df.columns
        status = "✅ FOUND" if exists else "❌ MISSING"
        print(f"  {exp}: {status}")
    
    print(f"\n{'='*60}")
    print(f"RECOMMENDATION")
    print(f"{'='*60}")
    if 'code' not in df.columns and 'Code' not in df.columns:
        print("⚠️  WARNING: No 'code' or 'Code' column found!")
        print("The preprocessing script needs to be updated with correct column names.")
        print(f"\nActual columns are: {list(df.columns)}")
    else:
        print("✅ Basic columns found. Check if data is valid.")

if __name__ == "__main__":
    main()
