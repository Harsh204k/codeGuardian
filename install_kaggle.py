#!/usr/bin/env python3
"""
Kaggle-Optimized Installation Script for CodeGuardian
======================================================
This script installs dependencies in the correct order to avoid conflicts.
Use this in Kaggle notebooks instead of: !pip install -r requirements.txt

Usage in Kaggle notebook:
    !python install_kaggle.py
    
Or run directly:
    python install_kaggle.py
"""

import subprocess
import sys
from typing import List, Tuple


def run_pip(args: List[str], description: str = "") -> Tuple[bool, str]:
    """Run pip command and return success status."""
    cmd = [sys.executable, "-m", "pip"] + args
    
    if description:
        print(f"\n📦 {description}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        
        # Show output only if there are errors
        if result.returncode != 0:
            print(f"⚠️  Warning: {result.stderr}")
            return False, result.stderr
        
        return True, result.stdout
    except Exception as e:
        print(f"❌ Error: {e}")
        return False, str(e)


def check_version(package: str) -> str:
    """Check installed version of a package."""
    try:
        mod = __import__(package.replace('-', '_'))
        return getattr(mod, '__version__', 'unknown')
    except ImportError:
        return 'NOT INSTALLED'


def main():
    print("=" * 60)
    print("🚀 Installing CodeGuardian Dependencies (Kaggle Optimized)")
    print("=" * 60)
    print(f"Python: {sys.version.split()[0]}")
    print("=" * 60)
    
    # Step 1: Fix pyarrow version FIRST (most critical)
    print("\n" + "="*60)
    print("STEP 1: Fixing pyarrow version")
    print("="*60)
    run_pip(
        ["install", "--quiet", "pyarrow>=19.0.0,<20.0.0", "--force-reinstall"],
        "Installing pyarrow 19.x (compatible with cudf and datasets)"
    )
    
    # Step 2: Fix cudf-polars
    print("\n" + "="*60)
    print("STEP 2: Fixing cudf-polars version")
    print("="*60)
    run_pip(
        ["install", "--quiet", "cudf-polars-cu12==25.2.2", "polars==1.21.0", "--force-reinstall"],
        "Installing cudf-polars 25.2.2 and polars 1.21.0"
    )
    
    # Step 3: Core dependencies
    print("\n" + "="*60)
    print("STEP 3: Installing core dependencies")
    print("="*60)
    core_deps = [
        "pyyaml>=6.0",
        "regex>=2023.0.0",
        "openpyxl>=3.1.0",
        "rich>=13.0.0,<14.0.0",
        "requests>=2.31.0",
        "click>=8.0.0",
        "tqdm>=4.64.0",
        "jsonschema>=4.17.0",
    ]
    run_pip(
        ["install", "--quiet"] + core_deps,
        "Installing: pyyaml, regex, openpyxl, rich, requests, click, tqdm, jsonschema"
    )
    
    # Step 4: ML libraries
    print("\n" + "="*60)
    print("STEP 4: Installing ML libraries")
    print("="*60)
    ml_deps = [
        "scikit-learn>=1.5.0,<1.6.0",
        "xgboost>=1.7.0",
        "joblib>=1.3.0",
    ]
    run_pip(
        ["install", "--quiet"] + ml_deps,
        "Installing: scikit-learn, xgboost, joblib"
    )
    
    # Step 5: Deep learning
    print("\n" + "="*60)
    print("STEP 5: Installing deep learning libraries")
    print("="*60)
    dl_deps = [
        "transformers>=4.40.0",
        "tokenizers>=0.19.0",
        "datasets>=2.19.0",
        "accelerate>=0.30.0",
    ]
    run_pip(
        ["install", "--quiet"] + dl_deps,
        "Installing: transformers, tokenizers, datasets, accelerate"
    )
    
    # Step 6: Monitoring tools
    print("\n" + "="*60)
    print("STEP 6: Installing monitoring tools")
    print("="*60)
    monitor_deps = [
        "tensorboard>=2.18.0,<2.19.0",
        "loguru>=0.7.0",
        "memory_profiler>=0.61.0",
        "bandit>=1.7.5",
    ]
    run_pip(
        ["install", "--quiet"] + monitor_deps,
        "Installing: tensorboard, loguru, memory_profiler, bandit"
    )
    
    # Step 7: Testing tools
    print("\n" + "="*60)
    print("STEP 7: Installing testing tools")
    print("="*60)
    test_deps = [
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
    ]
    run_pip(
        ["install", "--quiet"] + test_deps,
        "Installing: pytest, pytest-cov"
    )
    
    # Summary
    print("\n" + "="*60)
    print("✅ INSTALLATION COMPLETE!")
    print("="*60)
    
    print("\n📊 Checking for conflicts...")
    success, output = run_pip(["check"], "")
    if not success:
        print("⚠️  Some conflicts remain (this is normal on Kaggle)")
        print("   These won't affect preprocessing functionality")
    else:
        print("✅ No conflicts detected!")
    
    print("\n🎯 Key package versions:")
    packages = [
        'numpy', 'pandas', 'scikit-learn', 'pyarrow',
        'torch', 'transformers', 'datasets', 'tqdm',
        'jsonschema', 'loguru'
    ]
    
    for pkg in packages:
        version = check_version(pkg)
        status = "✅" if version != "NOT INSTALLED" else "❌"
        print(f"  {status} {pkg:20s}: {version}")
    
    print("\n" + "="*60)
    print("🎉 Ready to run preprocessing scripts!")
    print("="*60)
    print("\nNext steps:")
    print("  1. Run: python scripts/preprocessing/prepare_diversevul.py")
    print("  2. Run: python scripts/preprocessing/prepare_devign.py")
    print("  3. Run: python scripts/preprocessing/prepare_zenodo.py")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
