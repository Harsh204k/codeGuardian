#!/usr/bin/env python3
"""
Dataset Structure Diagnostic Tool for Kaggle

Run this script on Kaggle BEFORE preprocessing to verify dataset structure.
This will show you exactly what files exist and where they are located.

Usage:
    !python diagnose_dataset.py
"""

from pathlib import Path
import json


def format_size(bytes_size):
    """Format bytes to human readable size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} TB"


def check_file(filepath, expected_size_mb=None):
    """Check if file exists and verify its size."""
    if filepath.exists():
        size_mb = filepath.stat().st_size / (1024 * 1024)
        status = "✅"
        size_str = f"{size_mb:.1f} MB"
        
        if expected_size_mb:
            if size_mb < expected_size_mb * 0.8:  # Less than 80% of expected
                status = "⚠️"
                size_str += f" (Expected: ~{expected_size_mb} MB)"
        
        return status, True, size_str
    else:
        return "❌", False, "NOT FOUND"


def diagnose_diversevul(base_path):
    """Diagnose DiverseVul dataset structure."""
    print("\n" + "="*70)
    print("📦 DIVERSEVUL DATASET DIAGNOSTIC")
    print("="*70)
    
    diversevul_dir = base_path / "diversevul"
    
    print(f"\n1️⃣ Base directory: {diversevul_dir}")
    print(f"   Exists: {'✅ Yes' if diversevul_dir.exists() else '❌ No'}")
    
    if not diversevul_dir.exists():
        print("   ❌ CRITICAL: diversevul directory not found!")
        return False
    
    print(f"\n2️⃣ Checking for files at root level...")
    main_root = diversevul_dir / "diversevul.json"
    meta_root = diversevul_dir / "diversevul_metadata.json"
    
    status1, exists1, size1 = check_file(main_root, 700)
    status2, exists2, size2 = check_file(meta_root, 50)
    
    print(f"   {status1} diversevul.json: {size1}")
    print(f"   {status2} diversevul_metadata.json: {size2}")
    
    print(f"\n3️⃣ Checking for 'raw' subdirectory...")
    raw_dir = diversevul_dir / "raw"
    print(f"   raw/ exists: {'✅ Yes' if raw_dir.exists() else '❌ No'}")
    
    if raw_dir.exists():
        print(f"\n4️⃣ Checking for files in raw/ subdirectory...")
        main_raw = raw_dir / "diversevul.json"
        meta_raw = raw_dir / "diversevul_metadata.json"
        noise_raw = raw_dir / "label_noise"
        
        status3, exists3, size3 = check_file(main_raw, 700)
        status4, exists4, size4 = check_file(meta_raw, 50)
        
        print(f"   {status3} diversevul.json: {size3}")
        print(f"   {status4} diversevul_metadata.json: {size4}")
        print(f"   {'✅' if noise_raw.exists() else '⚠️ '} label_noise/ directory: {'Found' if noise_raw.exists() else 'Not found (optional)'}")
        
        if exists3:
            print(f"\n5️⃣ Contents of raw/ directory:")
            for item in sorted(raw_dir.iterdir()):
                if item.is_file():
                    size = format_size(item.stat().st_size)
                    print(f"   📄 {item.name} ({size})")
                else:
                    # Count files in subdirectory
                    count = len(list(item.iterdir())) if item.is_dir() else 0
                    print(f"   📂 {item.name}/ ({count} items)")
    
    # Decision summary
    print(f"\n" + "="*70)
    print("🎯 RECOMMENDATION:")
    print("="*70)
    
    if exists1 and exists2:
        print("✅ Files found at ROOT level")
        print("   Script will use: /kaggle/input/codeguardian-datasets/diversevul/")
        return True
    elif raw_dir.exists() and exists3 and exists4:
        print("✅ Files found in RAW/ subdirectory")
        print("   Script will use: /kaggle/input/codeguardian-datasets/diversevul/raw/")
        return True
    else:
        print("❌ PROBLEM: Files not found in expected locations!")
        print("\n💡 SOLUTIONS:")
        if not raw_dir.exists():
            print("   1. Create 'raw' subdirectory in diversevul/")
            print("   2. Move diversevul.json and metadata into raw/")
        elif raw_dir.exists() and not exists3:
            print("   1. Upload diversevul.json to the raw/ directory")
            print("   2. File should be ~700MB")
        elif raw_dir.exists() and not exists4:
            print("   1. Upload diversevul_metadata.json to raw/ directory")
            print("   2. File should be ~50MB")
        return False


def diagnose_all(base_path):
    """Diagnose all datasets."""
    print("\n" + "="*70)
    print("🔍 KAGGLE DATASET STRUCTURE DIAGNOSTIC TOOL")
    print("="*70)
    
    print(f"\n📂 Base path: {base_path}")
    print(f"   Exists: {'✅ Yes' if base_path.exists() else '❌ No'}")
    
    if not base_path.exists():
        print("\n❌ CRITICAL ERROR: Base path not found!")
        print("   Make sure 'codeguardian-datasets' is added as input to your notebook")
        return
    
    print(f"\n📦 Available datasets:")
    for item in sorted(base_path.iterdir()):
        if item.is_dir():
            print(f"   - {item.name}")
    
    # Diagnose each dataset
    diversevul_ok = diagnose_diversevul(base_path)
    
    # Summary
    print("\n" + "="*70)
    print("📊 DIAGNOSTIC SUMMARY")
    print("="*70)
    print(f"DiverseVul: {'✅ Ready' if diversevul_ok else '❌ Needs attention'}")
    
    if diversevul_ok:
        print("\n🎉 All checks passed! Ready to run preprocessing.")
        print("\nNext step:")
        print("   !python scripts/preprocessing/prepare_diversevul.py")
    else:
        print("\n⚠️  Issues detected. Please fix the problems above before preprocessing.")


def main():
    """Main entry point."""
    # Detect environment
    kaggle_path = Path("/kaggle/input/codeguardian-datasets")
    local_path = Path("datasets")
    
    if kaggle_path.exists():
        print("🌍 Environment: Kaggle")
        base_path = kaggle_path
    elif local_path.exists():
        print("🏠 Environment: Local")
        base_path = local_path
    else:
        print("❌ Cannot detect dataset location!")
        print("   Kaggle path: /kaggle/input/codeguardian-datasets (not found)")
        print("   Local path: ./datasets (not found)")
        return
    
    diagnose_all(base_path)


if __name__ == "__main__":
    main()
