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

# Test with multiple possible paths
possible_paths = [
    Path("/kaggle/input/codeguardian-datasets/megavul"),  # Kaggle dataset
    Path("/kaggle/input/megavul"),  # Alternative Kaggle path
    Path("c:/Users/urvag/Downloads/Projects/Hackathon/DPIIT/codeGuardian/datasets/megavul"),  # Local
    Path("../../../datasets/megavul"),  # Relative path
]

test_path = None
for path in possible_paths:
    if path.exists():
        test_path = path
        print(f"✅ Found dataset at: {test_path}")
        break

if test_path is None:
    print(f"❌ Dataset not found in any of these locations:")
    for path in possible_paths:
        print(f"   - {path}")
    print("\n💡 Based on your Kaggle screenshot, the path should be:")
    print("   /kaggle/input/codeguardian-datasets/megavul")
    print("\nPlease verify the dataset is mounted in your Kaggle notebook.")
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
