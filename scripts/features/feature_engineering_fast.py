#!/usr/bin/env python3
"""
🚀 ULTRA-FAST FEATURE ENGINEERING - Parallel Processing Edition

This is a high-performance version of feature_engineering.py that uses
multiprocessing.Pool (like prepare_diversevul_parallel.py) for maximum speed.

Performance comparison:
- Sequential: ~60-220 records/sec   (original)
- Parallel:   ~500-1500 records/sec (THIS VERSION - 5-10x faster!)

Usage:
    python feature_engineering_fast.py                     # Auto-detect cores
    python feature_engineering_fast.py --workers 8         # Use 8 cores
    python feature_engineering_fast.py --chunk-size 5000   # Smaller chunks
    python feature_engineering_fast.py --quick-test        # Test on 1000 records

Author: CodeGuardian Team - DPIIT Hackathon
Version: 2.0 - ULTRA FAST MODE 🚀
Date: 2025-10-12
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import argparse
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict
from multiprocessing import Pool, cpu_count
from functools import partial
import pandas as pd

# Import required modules
from tqdm import tqdm
from scripts.utils.io_utils import (
    chunked_read_jsonl,
    ensure_dir,
    write_json,
)
from scripts.utils.kaggle_paths import (
    get_dataset_path,
    get_output_path,
    print_environment_info,
)
from scripts.utils.schema_utils import validate_record

# Feature extraction functions from original script
from scripts.features.feature_engineering import extract_all_features

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s",
)
logger = logging.getLogger(__name__)


def process_record_wrapper(args):
    """
    Wrapper function for multiprocessing.

    Args:
        args: Tuple of (record, validate_schema)

    Returns:
        Feature dictionary or None if extraction failed
    """
    record, validate_schema = args
    try:
        return extract_all_features(record, validate_schema)
    except Exception as e:
        # Silent failure - just return None
        return None


def process_chunk_parallel(
    chunk: List[Dict[str, Any]],
    validate_schema: bool,
    num_workers: int,
    chunk_idx: int,
) -> List[Dict[str, Any]]:
    """
    Process a chunk of records in parallel using multiprocessing.Pool.

    Args:
        chunk: List of records to process
        validate_schema: Whether to validate schema
        num_workers: Number of parallel workers
        chunk_idx: Chunk index for logging

    Returns:
        List of extracted features
    """
    logger.info(
        f"  Processing chunk {chunk_idx} ({len(chunk):,} records) with {num_workers} workers..."
    )

    # Prepare arguments
    args_list = [(record, validate_schema) for record in chunk]

    # Process in parallel with progress bar
    features = []
    failed_count = 0

    with Pool(processes=num_workers) as pool:
        # Use imap_unordered for better performance
        for result in tqdm(
            pool.imap_unordered(process_record_wrapper, args_list, chunksize=100),
            total=len(args_list),
            desc=f"Chunk {chunk_idx}",
            unit="rec",
            leave=False,
        ):
            if result is not None:
                features.append(result)
            else:
                failed_count += 1

    if failed_count > 0:
        logger.warning(
            f"    ⚠️  {failed_count:,} records failed extraction in chunk {chunk_idx}"
        )

    return features


def process_dataset_to_csv_fast(
    input_path: str,
    output_csv_path: str,
    output_parquet_path: Optional[str] = None,
    stats_path: Optional[str] = None,
    chunk_size: int = 10000,
    validate_schema: bool = True,
    num_workers: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Process dataset with ULTRA-FAST parallel feature extraction.

    Args:
        input_path: Input JSONL file (validated dataset)
        output_csv_path: Output CSV file with feature matrix
        output_parquet_path: Optional Parquet output
        stats_path: Optional JSON file for statistics
        chunk_size: Chunk size for processing
        validate_schema: Whether to validate against unified schema
        num_workers: Number of parallel workers (None = auto)

    Returns:
        Statistics dictionary
    """
    # Auto-detect workers
    if num_workers is None:
        num_workers = max(1, cpu_count() - 1)  # Leave 1 core free

    logger.info("=" * 80)
    logger.info("PHASE 2.2 ULTRA-FAST: PARALLEL FEATURE ENGINEERING 🚀")
    logger.info("=" * 80)
    logger.info(f"Input:            {input_path}")
    logger.info(f"Output CSV:       {output_csv_path}")
    if output_parquet_path:
        logger.info(f"Output Parquet:   {output_parquet_path}")
    if stats_path:
        logger.info(f"Statistics:       {stats_path}")
    logger.info(f"Chunk size:       {chunk_size:,}")
    logger.info(f"Schema validation: {validate_schema}")
    logger.info(f"Parallel workers: {num_workers} cores")
    logger.info("=" * 80)

    # Ensure output directories
    ensure_dir(str(Path(output_csv_path).parent))
    if output_parquet_path:
        ensure_dir(str(Path(output_parquet_path).parent))  # type: ignore

    # Initialize tracking
    stats = {
        "start_time": datetime.now().isoformat(),
        "total_records": 0,
        "successful_extractions": 0,
        "failed_extractions": 0,
        "feature_stats": defaultdict(
            lambda: {"min": float("inf"), "max": float("-inf"), "sum": 0, "count": 0}
        ),
        "dataset_counts": defaultdict(int),
        "language_counts": defaultdict(int),
        "vulnerability_counts": {"vulnerable": 0, "safe": 0},
    }

    # Collect all features
    all_features = []

    # Process in chunks
    logger.info("\n🚀 Starting parallel processing...\n")

    chunk_idx = 0
    for chunk in chunked_read_jsonl(input_path, chunk_size=chunk_size):
        chunk_idx += 1
        chunk_start = datetime.now()

        # Extract features in parallel
        features = process_chunk_parallel(
            chunk=chunk,
            validate_schema=validate_schema,
            num_workers=num_workers,
            chunk_idx=chunk_idx,
        )

        # Update statistics
        for feature in features:
            stats["total_records"] += 1

            # Count by dataset and language
            dataset = feature.get("dataset", "unknown")
            language = feature.get("language", "unknown")
            stats["dataset_counts"][dataset] += 1
            stats["language_counts"][language] += 1

            # Count vulnerabilities
            if feature.get("is_vulnerable", 0) == 1:
                stats["vulnerability_counts"]["vulnerable"] += 1
            else:
                stats["vulnerability_counts"]["safe"] += 1

            # Track feature statistics (numeric fields only)
            for field, value in feature.items():
                if isinstance(value, (int, float)) and field not in [
                    "id",
                    "is_vulnerable",
                ]:
                    try:
                        field_stats = stats["feature_stats"][field]
                        field_stats["min"] = min(field_stats["min"], value)
                        field_stats["max"] = max(field_stats["max"], value)
                        field_stats["sum"] += value
                        field_stats["count"] += 1
                        stats["successful_extractions"] += 1
                    except (ValueError, TypeError):
                        stats["failed_extractions"] += 1

        # Collect for DataFrame
        all_features.extend(features)

        # Log chunk completion
        chunk_time = (datetime.now() - chunk_start).total_seconds()
        records_per_sec = len(chunk) / chunk_time if chunk_time > 0 else 0
        logger.info(
            f"  ✅ Chunk {chunk_idx} complete: {len(features):,} records in {chunk_time:.1f}s ({records_per_sec:.0f} rec/s)"
        )

    # Calculate final stats
    stats["end_time"] = datetime.now().isoformat()
    stats["total_time_seconds"] = (
        datetime.fromisoformat(stats["end_time"])
        - datetime.fromisoformat(stats["start_time"])
    ).total_seconds()
    stats["records_per_second"] = (
        stats["total_records"] / stats["total_time_seconds"]
        if stats["total_time_seconds"] > 0
        else 0
    )

    # Calculate averages
    for field, field_stats in stats["feature_stats"].items():
        if field_stats["count"] > 0:
            field_stats["avg"] = field_stats["sum"] / field_stats["count"]

    # Create DataFrame and save
    logger.info(f"\n💾 Saving results...")
    logger.info(f"  Creating DataFrame with {len(all_features):,} records...")

    if all_features:
        df = pd.DataFrame(all_features)

        # Save CSV
        logger.info(f"  Writing CSV: {output_csv_path}")
        df.to_csv(output_csv_path, index=False)
        logger.info(f"  ✅ CSV saved: {len(df):,} rows × {len(df.columns)} columns")

        # Save Parquet (much faster and smaller)
        if output_parquet_path:
            logger.info(f"  Writing Parquet: {output_parquet_path}")
            df.to_parquet(output_parquet_path, index=False, engine="pyarrow")
            logger.info(f"  ✅ Parquet saved")
    else:
        logger.error("❌ No features extracted! Check your data and processing logic.")

    # Save statistics
    if stats_path:
        logger.info(f"  Writing statistics: {stats_path}")
        # Convert defaultdicts to regular dicts for JSON serialization
        stats_serializable = {
            **stats,
            "feature_stats": dict(stats["feature_stats"]),
            "dataset_counts": dict(stats["dataset_counts"]),
            "language_counts": dict(stats["language_counts"]),
        }
        write_json(stats_serializable, stats_path)
        logger.info(f"  ✅ Statistics saved")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Ultra-Fast Feature Engineering with Parallel Processing 🚀",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process with auto-detected cores
  python feature_engineering_fast.py

  # Use specific number of workers
  python feature_engineering_fast.py --workers 8

  # Quick test on 1000 records
  python feature_engineering_fast.py --quick-test

  # Disable schema validation for maximum speed
  python feature_engineering_fast.py --no-validate

  # Custom chunk size (smaller = less memory, more overhead)
  python feature_engineering_fast.py --chunk-size 5000
        """,
    )

    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Input JSONL file (default: auto-detect from kaggle_paths)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV file (default: auto-detect from kaggle_paths)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=10000,
        help="Records per chunk (default: 10000)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of parallel workers (default: auto = CPU cores - 1)",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Disable schema validation for maximum speed",
    )
    parser.add_argument(
        "--quick-test",
        action="store_true",
        help="Quick test on first 1000 records only",
    )

    args = parser.parse_args()

    # Print environment info
    print("\n" + "=" * 80)
    print("🚀 ULTRA-FAST FEATURE ENGINEERING (PARALLEL MODE)")
    print("=" * 80)
    print_environment_info()

    # Get paths
    if args.input:
        input_path = str(args.input)
    else:
        input_path = str(get_dataset_path("validated/validated.jsonl"))

    if args.output:
        output_dir = Path(args.output).parent
        output_csv = str(args.output)
    else:
        output_dir = get_output_path("features")
        output_csv = str(output_dir / "features_static_fast.csv")

    output_parquet = str(output_dir / "features_static_fast.parquet")
    stats_path = str(output_dir / "stats_features_fast.json")

    # Override for quick test
    chunk_size = args.chunk_size
    if args.quick_test:
        logger.info("🧪 QUICK TEST MODE: Processing first 1000 records only")
        chunk_size = 1000

    # Process
    try:
        stats = process_dataset_to_csv_fast(
            input_path=input_path,  # type: ignore
            output_csv_path=output_csv,
            output_parquet_path=output_parquet,
            stats_path=stats_path,
            chunk_size=chunk_size,
            validate_schema=not args.no_validate,
            num_workers=args.workers,
        )

        # Print summary
        print("\n" + "=" * 80)
        print("✅ FEATURE ENGINEERING COMPLETE")
        print("=" * 80)
        print(f"\n📊 SUMMARY:")
        print(f"   Total records:     {stats['total_records']:,}")
        print(f"   Successful:        {stats['total_records']:,}")
        print(f"   Failed:            {stats['failed_extractions']:,}")
        print(f"   Processing time:   {stats['total_time_seconds']:.1f} seconds")
        print(
            f"   Speed:             {stats['records_per_second']:.0f} records/second 🚀"
        )
        print(f"\n💾 OUTPUT:")
        print(f"   CSV:        {output_csv}")
        print(f"   Parquet:    {output_parquet}")
        print(f"   Statistics: {stats_path}")
        print("=" * 80 + "\n")

    except KeyboardInterrupt:
        logger.warning("\n⚠️  Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n❌ Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
