#!/usr/bin/env python3
"""
Quick runner script for enhanced feature engineering.

Usage:
    python run_enhanced_pipeline.py              # Default settings
    python run_enhanced_pipeline.py --fast       # Fast mode (Kaggle)
    python run_enhanced_pipeline.py --test       # Test mode (sample)
"""

import sys
import argparse
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from scripts.features.feature_engineering_enhanced import main as fe_main


def quick_run(mode="default"):
    """Run pipeline with preset configurations."""

    if mode == "fast":
        # Kaggle-optimized
        sys.argv = [
            "run_enhanced_pipeline.py",
            "--multiprocessing",
            "--chunk-size",
            "3000",
            "--no-validation",
        ]
        print("🚀 Running in FAST mode (Kaggle optimized)")

    elif mode == "test":
        # Test on small sample
        sys.argv = [
            "run_enhanced_pipeline.py",
            "--input",
            "datasets/validated/validated.jsonl",
            "--output-csv",
            "test_output.csv",
            "--chunk-size",
            "100",
        ]
        print("🧪 Running in TEST mode (small sample)")

    elif mode == "phase1":
        # Phase 1 only (original features)
        sys.argv = [
            "run_enhanced_pipeline.py",
            "--disable-phase2",
            "--disable-phase3",
        ]
        print("📊 Running Phase 1 only (original features)")

    else:
        # Default: full pipeline
        sys.argv = [
            "run_enhanced_pipeline.py",
            "--multiprocessing",
        ]
        print("⚙️  Running in DEFAULT mode (full pipeline)")

    fe_main()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Quick runner for enhanced feature engineering"
    )
    parser.add_argument(
        "--fast", action="store_true", help="Fast mode (Kaggle optimized)"
    )
    parser.add_argument("--test", action="store_true", help="Test mode (small sample)")
    parser.add_argument("--phase1", action="store_true", help="Phase 1 only")

    args = parser.parse_args()

    if args.fast:
        quick_run("fast")
    elif args.test:
        quick_run("test")
    elif args.phase1:
        quick_run("phase1")
    else:
        quick_run("default")
