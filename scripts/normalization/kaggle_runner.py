#!/usr/bin/env python3
"""
🚀 KAGGLE RUNNER FOR CodeGuardian Normalization Pipeline 🚀

This script provides a Kaggle-compatible wrapper for the normalization pipeline.
It handles common Kaggle environment issues and provides better error reporting.

Usage in Kaggle:
    # Install dependencies first
    !pip install tqdm rich

    # Run the pipeline
    !python kaggle_runner.py --quick-test --summary
"""

import os
import sys
import subprocess
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are available."""
    missing = []

    try:
        import tqdm
    except ImportError:
        missing.append("tqdm")

    try:
        import rich
    except ImportError:
        missing.append("rich")

    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        print("Install with: !pip install " + " ".join(missing))
        return False

    print("✅ All dependencies available")
    return True

def check_project_structure():
    """Check if the project structure is correct."""
    required_files = [
        "normalize_and_merge.py",
        "scripts/utils/schema_utils.py",
        "scripts/utils/io_utils.py"
    ]

    for file_path in required_files:
        if not Path(file_path).exists():
            print(f"❌ Missing required file: {file_path}")
            return False

    print("✅ Project structure OK")
    return True

def run_pipeline(args):
    """Run the normalization pipeline with proper error handling."""
    # Change to the correct directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    # Build the command
    cmd = [sys.executable, "scripts/normalization/normalize_and_merge.py"] + args

    print(f"🔄 Running: {' '.join(cmd)}")
    print(f"📂 Working directory: {os.getcwd()}")

    try:
        # Run the command and capture output
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')

        # Print stdout
        if result.stdout:
            print(result.stdout)

        # Print stderr if there was an error
        if result.stderr:
            print("STDERR:", file=sys.stderr)
            print(result.stderr, file=sys.stderr)

        print(f"📊 Exit code: {result.returncode}")

        if result.returncode == 0:
            print("✅ Pipeline completed successfully!")
        else:
            print(f"❌ Pipeline failed with exit code: {result.returncode}")

        return result.returncode

    except Exception as e:
        print(f"❌ Failed to run pipeline: {e}")
        return 1

def main():
    """Main entry point."""
    print("🚀 CodeGuardian Kaggle Runner")
    print("=" * 50)

    # Check dependencies
    if not check_dependencies():
        return 1

    # Check project structure
    if not check_project_structure():
        return 1

    # Get command line arguments (skip the script name)
    args = sys.argv[1:]

    # If no args provided, use quick test
    if not args:
        args = ["--quick-test", "--summary"]
        print("ℹ️  No arguments provided, using: --quick-test --summary")

    # Run the pipeline
    return run_pipeline(args)

if __name__ == "__main__":
    sys.exit(main())
