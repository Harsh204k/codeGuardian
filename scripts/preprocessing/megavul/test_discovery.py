#!/usr/bin/env python3
"""
Quick test of MegaVul file discovery with the actual dataset structure.
"""

import sys
from pathlib import Path
import logging

# Setup
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from megavul_file_discovery import discover_megavul_files, estimate_total_records

# Test with the kaggle path from your screenshots
test_path = Path("c:/Users/urvag/Downloads/Projects/Hackathon/DPIIT/codeGuardian/datasets/megavul")

# If that doesn't exist, try the actual kaggle path
if not test_path.exists():
    test_path = Path("/kaggle/input/megavul")

if not test_path.exists():
    print(f"❌ Test path not found: {test_path}")
    print("Please update the path in this script to point to your MegaVul dataset")
    sys.exit(1)

print(f"🔍 Testing file discovery on: {test_path}\n")

# Run discovery
files_with_labels = discover_megavul_files(test_path, target_languages=['all'])

if files_with_labels:
    print(f"\n✅ Discovery successful!")
    print(f"   Found {len(files_with_labels):,} JSON files")
    
    # Show a few examples
    print(f"\n📄 Sample files:")
    for file_path, label in files_with_labels[:5]:
        rel_path = file_path.relative_to(test_path) if test_path in file_path.parents else file_path
        print(f"   [{label}] {rel_path}")
    
    # Estimate total records
    print(f"\n📊 Estimating record counts...")
    estimate_total_records(files_with_labels, sample_size=20)
    
else:
    print(f"\n❌ No files found!")
    print(f"   Please check the dataset structure matches:")
    print(f"   megavul/raw/YYYY-MM/[c_cpp|java]/megavul_graph/.../[vul|non_vul]/*.json")
