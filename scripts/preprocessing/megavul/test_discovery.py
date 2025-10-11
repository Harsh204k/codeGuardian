#!/usr/bin/env python3
"""
Quick test of MegaVul file discovery with the actual dataset structure.
"""

import sys
from pathlib import Path
import logging
import time

# Setup
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from megavul_file_discovery import discover_megavul_files, estimate_total_records

def quick_structure_check(test_path: Path) -> bool:
    """Quick check if the dataset structure looks correct."""
    print("🔍 Quick structure check...")
    
    # Check for raw subdirectory
    raw_dir = test_path / 'raw'
    if not raw_dir.exists():
        print("   ❌ No 'raw' subdirectory found")
        return False
    
    # Check for date directories
    date_dirs = [d for d in raw_dir.iterdir() if d.is_dir() and d.name.startswith('20')]
    if not date_dirs:
        print("   ❌ No date directories (like 2023-11) found")
        return False
    
    # Check first date directory
    first_date_dir = date_dirs[0]
    print(f"   ✅ Found date directory: {first_date_dir.name}")
    
    # Check for language directories
    lang_dirs = [d for d in first_date_dir.iterdir() if d.is_dir() and d.name in ['c_cpp', 'java']]
    if not lang_dirs:
        print("   ❌ No language directories (c_cpp, java) found")
        return False
    
    # Check first language directory
    first_lang_dir = lang_dirs[0]
    print(f"   ✅ Found language directory: {first_lang_dir.name}")
    
    # Check for megavul_graph
    graph_dir = first_lang_dir / 'megavul_graph'
    if not graph_dir.exists():
        print("   ❌ No 'megavul_graph' subdirectory found")
        return False
    
    print("   ✅ Found megavul_graph directory")
    
    # Quick file check - just count files in first few subdirs
    json_count = 0
    dirs_checked = 0
    
    for subdir in graph_dir.rglob('*'):
        if subdir.is_dir() and dirs_checked < 5:  # Check first 5 directories
            json_files = list(subdir.glob('*.json'))
            json_count += len(json_files)
            dirs_checked += 1
            if json_count > 0:
                break
    
    if json_count > 0:
        print("   ✅ Found JSON files in structure")
        return True
    else:
        print("   ❌ No JSON files found in expected structure")
        return False

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
    print("❌ Dataset not found in any of these locations:")
    for path in possible_paths:
        print(f"   - {path}")
    print("\n💡 Based on your Kaggle screenshot, the path should be:")
    print("   /kaggle/input/codeguardian-datasets/megavul")
    print("\nPlease verify the dataset is mounted in your Kaggle notebook.")
    sys.exit(1)

print(f"🔍 Testing file discovery on: {test_path}\n")

# Quick structure check first
if not quick_structure_check(test_path):
    print("\n❌ Dataset structure check failed!")
    print("   Please verify the dataset matches the expected MegaVul structure:")
    print("   megavul/raw/YYYY-MM/[c_cpp|java]/megavul_graph/.../[vul|non_vul]/*.json")
    sys.exit(1)

print("\n✅ Structure check passed!")

# Ask user if they want full count or limited discovery
print("\n⏱️  File discovery options:")
print("   1. Quick test (100 files) - Fast")
print("   2. Full count - May take several minutes")

choice = input("\nChoose (1 or 2) [default: 1]: ").strip()
if choice == "2":
    print("\n🔍 Running full file discovery...")
    files_with_labels = discover_megavul_files(test_path, target_languages=['all'])
else:
    print("\n🔍 Running limited discovery (100 files max)...")
    files_with_labels = discover_megavul_files(test_path, target_languages=['all'], max_files=100)

if files_with_labels:
    print("\n✅ Discovery successful!")
    print(f"   Found {len(files_with_labels):,} JSON files")
    
    # Show a few examples
    print("\n📄 Sample files:")
    for file_path, label in files_with_labels[:5]:
        rel_path = file_path.relative_to(test_path) if test_path in file_path.parents else file_path
        print(f"   [{label}] {rel_path}")
    
    # Estimate total records if we have files
    if len(files_with_labels) >= 5:
        print("\n📊 Estimating record counts...")
        estimate_total_records(files_with_labels, sample_size=min(10, len(files_with_labels)))
    
else:
    print("\n❌ No files found!")
    print("   Please check the dataset structure matches:")
    print("   megavul/raw/YYYY-MM/[c_cpp|java]/megavul_graph/.../[vul|non_vul]/*.json")
