#!/usr/bin/env python3
"""
Phase 2.3: Dataset Splitting Script
====================================

Splits the feature-enriched dataset into stratified train/validation/test sets
for model training and evaluation.

Split ratios:
- Train: 80%
- Validation: 10%
- Test: 10%

Features:
- Stratified splitting (maintains label balance)
- Reproducible (seed=42)
- Language and dataset distribution tracking

Outputs:
- datasets/processed/train.jsonl
- datasets/processed/val.jsonl
- datasets/processed/test.jsonl
- datasets/processed/split_summary.json

Author: CodeGuardian Team
Version: 2.0.0
"""

import argparse
import logging
import random
from pathlib import Path
from typing import Dict, Any, List, Tuple
from collections import defaultdict
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("⚠️  tqdm not available, progress bars disabled")

from scripts.utils.io_utils import read_jsonl, write_jsonl, write_json, ensure_dir
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Default split ratios
DEFAULT_TRAIN_RATIO = 0.8
DEFAULT_VAL_RATIO = 0.1
DEFAULT_TEST_RATIO = 0.1


def stratified_split(
    records: List[Dict[str, Any]],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Perform stratified split of records by label.
    
    Args:
        records: List of records to split
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        test_ratio: Test set ratio
        seed: Random seed for reproducibility
        
    Returns:
        Tuple of (train_records, val_records, test_records)
    """
    # Validate ratios
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, \
        "Split ratios must sum to 1.0"
    
    # Set random seed
    random.seed(seed)
    
    # Separate by label
    vulnerable = [r for r in records if r.get('label') == 1]
    safe = [r for r in records if r.get('label') == 0]
    
    logger.info(f"Vulnerable records: {len(vulnerable):,}")
    logger.info(f"Safe records: {len(safe):,}")
    
    # Shuffle each group
    random.shuffle(vulnerable)
    random.shuffle(safe)
    
    # Calculate split indices for vulnerable
    vuln_train_idx = int(len(vulnerable) * train_ratio)
    vuln_val_idx = vuln_train_idx + int(len(vulnerable) * val_ratio)
    
    vuln_train = vulnerable[:vuln_train_idx]
    vuln_val = vulnerable[vuln_train_idx:vuln_val_idx]
    vuln_test = vulnerable[vuln_val_idx:]
    
    # Calculate split indices for safe
    safe_train_idx = int(len(safe) * train_ratio)
    safe_val_idx = safe_train_idx + int(len(safe) * val_ratio)
    
    safe_train = safe[:safe_train_idx]
    safe_val = safe[safe_train_idx:safe_val_idx]
    safe_test = safe[safe_val_idx:]
    
    # Combine and shuffle
    train_set = vuln_train + safe_train
    val_set = vuln_val + safe_val
    test_set = vuln_test + safe_test
    
    random.shuffle(train_set)
    random.shuffle(val_set)
    random.shuffle(test_set)
    
    logger.info(f"Train set: {len(train_set):,} records")
    logger.info(f"Validation set: {len(val_set):,} records")
    logger.info(f"Test set: {len(test_set):,} records")
    
    return train_set, val_set, test_set


def compute_split_statistics(
    train_set: List[Dict[str, Any]],
    val_set: List[Dict[str, Any]],
    test_set: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Compute comprehensive statistics for dataset splits.
    
    Args:
        train_set: Training records
        val_set: Validation records
        test_set: Test records
        
    Returns:
        Dictionary of split statistics
    """
    def analyze_split(records: List[Dict[str, Any]], split_name: str) -> Dict[str, Any]:
        """Analyze a single split."""
        total = len(records)
        vulnerable = sum(1 for r in records if r.get('label') == 1)
        safe = total - vulnerable
        
        # Language distribution
        lang_dist = defaultdict(int)
        for record in records:
            lang = record.get('language', 'unknown')
            lang_dist[lang] += 1
        
        # Dataset distribution
        dataset_dist = defaultdict(int)
        for record in records:
            ds = record.get('source_dataset', 'unknown')
            dataset_dist[ds] += 1
        
        # CWE coverage
        cwe_count = sum(1 for r in records if r.get('cwe_id'))
        unique_cwes = len(set(r.get('cwe_id') for r in records if r.get('cwe_id')))
        
        return {
            'total_records': total,
            'vulnerable': vulnerable,
            'safe': safe,
            'vulnerability_ratio': round(vulnerable / total * 100, 2) if total > 0 else 0,
            'language_distribution': dict(lang_dist),
            'dataset_distribution': dict(dataset_dist),
            'cwe_coverage': {
                'records_with_cwe': cwe_count,
                'unique_cwes': unique_cwes
            }
        }
    
    stats = {
        'total_records': len(train_set) + len(val_set) + len(test_set),
        'train': analyze_split(train_set, 'train'),
        'val': analyze_split(val_set, 'val'),
        'test': analyze_split(test_set, 'test'),
        'split_ratios': {
            'train': round(len(train_set) / (len(train_set) + len(val_set) + len(test_set)), 3),
            'val': round(len(val_set) / (len(train_set) + len(val_set) + len(test_set)), 3),
            'test': round(len(test_set) / (len(train_set) + len(val_set) + len(test_set)), 3)
        }
    }
    
    return stats


def split_dataset(
    input_file: Path,
    output_dir: Path,
    summary_file: Path,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42
) -> Dict[str, Any]:
    """
    Split dataset into train/val/test sets.
    
    Args:
        input_file: Path to feature-enriched input JSONL
        output_dir: Directory for output split files
        summary_file: Path to split summary JSON
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        test_ratio: Test set ratio
        seed: Random seed
        
    Returns:
        Split statistics dictionary
    """
    logger.info("="*70)
    logger.info("PHASE 2.3: DATASET SPLITTING")
    logger.info("="*70)
    logger.info(f"Input: {input_file}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Summary: {summary_file}")
    logger.info(f"Split ratios - Train: {train_ratio}, Val: {val_ratio}, Test: {test_ratio}")
    logger.info(f"Random seed: {seed}")
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    ensure_dir(str(summary_file.parent))
    
    # Load feature-enriched records
    logger.info("Loading feature-enriched records...")
    records = list(read_jsonl(str(input_file)))
    total_records = len(records)
    logger.info(f"Loaded {total_records:,} records")
    
    # Perform stratified split
    logger.info("Performing stratified split...")
    train_set, val_set, test_set = stratified_split(
        records=records,
        train_ratio=train_ratio,
        val_ratio=val_ratio,
        test_ratio=test_ratio,
        seed=seed
    )
    
    # Save split files
    train_file = output_dir / "train.jsonl"
    val_file = output_dir / "val.jsonl"
    test_file = output_dir / "test.jsonl"
    
    logger.info(f"Saving training set to {train_file}...")
    write_jsonl(train_set, str(train_file), show_progress=False)
    
    logger.info(f"Saving validation set to {val_file}...")
    write_jsonl(val_set, str(val_file), show_progress=False)
    
    logger.info(f"Saving test set to {test_file}...")
    write_jsonl(test_set, str(test_file), show_progress=False)
    
    # Compute statistics
    logger.info("Computing split statistics...")
    stats = compute_split_statistics(train_set, val_set, test_set)
    
    # Add file paths to stats
    stats['output_files'] = {
        'train': str(train_file),
        'val': str(val_file),
        'test': str(test_file)
    }
    
    # Save summary
    logger.info(f"Saving split summary...")
    write_json(stats, str(summary_file))
    
    # Print summary
    print_split_summary(stats)
    
    return stats


def print_split_summary(stats: Dict[str, Any]):
    """
    Print a formatted split summary.
    
    Args:
        stats: Split statistics dictionary
    """
    print(f"\n{Colors.BOLD}{'='*70}")
    print("DATASET SPLITTING SUMMARY")
    print(f"{'='*70}{Colors.END}\n")
    
    print(f"{Colors.BLUE}📊 Overall Statistics:{Colors.END}")
    print(f"  Total records:        {stats['total_records']:,}")
    print(f"  Split ratios:         Train: {stats['split_ratios']['train']:.1%}, "
          f"Val: {stats['split_ratios']['val']:.1%}, Test: {stats['split_ratios']['test']:.1%}")
    
    # Print statistics for each split
    for split_name in ['train', 'val', 'test']:
        split_data = stats[split_name]
        print(f"\n{Colors.BLUE}📁 {split_name.upper()} SET:{Colors.END}")
        print(f"  Total records:        {split_data['total_records']:,}")
        print(f"  Vulnerable:           {split_data['vulnerable']:,} "
              f"({split_data['vulnerability_ratio']:.2f}%)")
        print(f"  Safe:                 {split_data['safe']:,}")
        
        # Top languages
        sorted_langs = sorted(split_data['language_distribution'].items(),
                            key=lambda x: x[1], reverse=True)
        print(f"  Top languages:        ", end='')
        print(', '.join(f"{lang}({count})" for lang, count in sorted_langs[:5]))
        
        # Top datasets
        sorted_datasets = sorted(split_data['dataset_distribution'].items(),
                                key=lambda x: x[1], reverse=True)
        print(f"  Top datasets:         ", end='')
        print(', '.join(f"{ds}({count})" for ds, count in sorted_datasets[:3]))
        
        # CWE coverage
        print(f"  CWE coverage:         {split_data['cwe_coverage']['unique_cwes']} unique CWEs "
              f"({split_data['cwe_coverage']['records_with_cwe']} records)")
    
    # Check label balance
    train_ratio = stats['train']['vulnerability_ratio']
    val_ratio = stats['val']['vulnerability_ratio']
    test_ratio = stats['test']['vulnerability_ratio']
    
    max_diff = max(abs(train_ratio - val_ratio),
                   abs(train_ratio - test_ratio),
                   abs(val_ratio - test_ratio))
    
    print(f"\n{Colors.BLUE}⚖️  Label Balance:{Colors.END}")
    print(f"  Train vulnerable:     {train_ratio:.2f}%")
    print(f"  Val vulnerable:       {val_ratio:.2f}%")
    print(f"  Test vulnerable:      {test_ratio:.2f}%")
    print(f"  Max difference:       {max_diff:.2f}%")
    
    if max_diff < 2.0:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ EXCELLENT LABEL BALANCE (< 2% difference){Colors.END}")
    elif max_diff < 5.0:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ GOOD LABEL BALANCE (< 5% difference){Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  ACCEPTABLE LABEL BALANCE (< 10% difference){Colors.END}")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ DATASET SPLITTING COMPLETED{Colors.END}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Split dataset into train/val/test sets',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--input-file',
        type=str,
        default=None,
        help='Path to feature-enriched input dataset (auto-detected if not provided)'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default=None,
        help='Output directory for split files (auto-detected if not provided)'
    )
    parser.add_argument(
        '--summary-file',
        type=str,
        default=None,
        help='Path to split summary JSON (auto-detected if not provided)'
    )
    parser.add_argument(
        '--train-ratio',
        type=float,
        default=0.8,
        help='Training set ratio (default: 0.8)'
    )
    parser.add_argument(
        '--val-ratio',
        type=float,
        default=0.1,
        help='Validation set ratio (default: 0.1)'
    )
    parser.add_argument(
        '--test-ratio',
        type=float,
        default=0.1,
        help='Test set ratio (default: 0.1)'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Random seed for reproducibility (default: 42)'
    )
    
    args = parser.parse_args()
    
    # Print environment info
    print_environment_info()
    
    # Validate ratios
    total_ratio = args.train_ratio + args.val_ratio + args.test_ratio
    if abs(total_ratio - 1.0) > 1e-6:
        logger.error(f"Split ratios must sum to 1.0, got {total_ratio}")
        sys.exit(1)
    
    # Get paths using Kaggle-compatible helper
    if args.input_file:
        input_file = Path(args.input_file).resolve()
    else:
        # Try features_all.jsonl first, fall back to validated.jsonl
        features_dir = get_output_path("features")
        input_file = features_dir / "features_all.jsonl"
        if not input_file.exists():
            unified_dir = get_output_path("unified")
            input_file = unified_dir / "validated.jsonl"
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("processed")
    
    if args.summary_file:
        summary_file = Path(args.summary_file).resolve()
    else:
        summary_file = output_dir / "split_summary.json"
    
    logger.info(f"[INFO] Reading input from: {input_file}")
    logger.info(f"[INFO] Writing splits to: {output_dir}")
    
    # Check if input exists
    if not input_file.exists():
        logger.error(f"Input file not found: {input_file}")
        logger.error("Please run feature engineering script first.")
        sys.exit(1)
    
    # Run dataset splitting
    try:
        split_dataset(
            input_file=input_file,
            output_dir=output_dir,
            summary_file=summary_file,
            train_ratio=args.train_ratio,
            val_ratio=args.val_ratio,
            test_ratio=args.test_ratio,
            seed=args.seed
        )
        sys.exit(0)
            
    except Exception as e:
        logger.error(f"Dataset splitting failed: {e}", exc_info=True)
        sys.exit(1)


def run(args=None):
    """
    Entry point for dynamic pipeline orchestrator.
    
    Args:
        args: Optional argparse.Namespace object with configuration.
              If None, will parse from sys.argv (CLI mode).
    """
    main()


if __name__ == "__main__":
    main()

