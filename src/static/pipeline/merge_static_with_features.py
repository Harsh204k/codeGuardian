#!/usr/bin/env python3
"""
Enhanced Merge Static Analysis Results with Feature-Engineered Data
Phase 3.2: Robust merging with missing ID handling and imputation
"""

import argparse
import json
import sys
from pathlib import Path
import logging
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def merge_datasets(static_path: Path, features_path: Optional[Path], 
                  base_path: Path, output_path: Path, 
                  impute_missing: bool = True):
    """
    Enhanced merge of static analysis results with feature-engineered dataset.
    
    Args:
        static_path: Path to static analysis JSONL
        features_path: Path to feature-engineered JSONL (optional)
        base_path: Path to base dataset (for IDs)
        output_path: Path to save merged output
        impute_missing: Whether to impute zeros for missing static data
    """
    logger.info(f"Loading static results from {static_path}")
    static_data = {}
    
    try:
        with open(static_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                try:
                    record = json.loads(line)
                    static_data[record['id']] = record
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"Error parsing static line {line_no}: {e}")
    except FileNotFoundError:
        logger.warning(f"Static file not found: {static_path}")
    
    logger.info(f"Loaded {len(static_data)} static analysis records")
    
    # Load features or base dataset
    source_path = features_path if features_path else base_path
    logger.info(f"Loading source data from {source_path}")
    
    merged_records = []
    matched = 0
    unmatched = 0
    imputed = 0
    
    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                try:
                    source_record = json.loads(line)
                    record_id = source_record.get('id')
                    
                    if not record_id:
                        logger.warning(f"Missing ID in line {line_no}")
                        continue
                    
                    # Merge static results if available
                    if record_id in static_data:
                        static_record = static_data[record_id]
                        source_record.update({
                            'static_flags': static_record.get('static_flags', {}),
                            'static_metrics': static_record.get('static_metrics', {}),
                            'static_confidence': static_record.get('static_confidence', 0.0),
                            'risk_score': static_record.get('risk_score', 0.0),
                            'detected_cwes': static_record.get('detected_cwes', []),
                            'vulnerability_count': static_record.get('vulnerability_count', 0),
                            'findings': static_record.get('findings', [])  # Include findings for explainability
                        })
                        matched += 1
                    else:
                        # Impute or skip
                        if impute_missing:
                            source_record.update(_get_empty_static_data())
                            imputed += 1
                        unmatched += 1
                    
                    merged_records.append(source_record)
                    
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(f"Error parsing source line {line_no}: {e}")
    
    except FileNotFoundError:
        logger.error(f"Source file not found: {source_path}")
        return
    
    logger.info(f"Matched: {matched}, Unmatched: {unmatched}, Imputed: {imputed}")
    
    # Save merged data
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for record in merged_records:
            json.dump(record, f, ensure_ascii=False)
            f.write('\n')
    
    logger.info(f"Merged {len(merged_records)} records to {output_path}")
    
    # Generate summary
    summary = {
        'total_records': len(merged_records),
        'matched': matched,
        'unmatched': unmatched,
        'imputed': imputed,
        'match_rate': matched / len(merged_records) * 100 if merged_records else 0
    }
    
    summary_path = output_path.parent / f"{output_path.stem}_merge_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"Merge summary saved to {summary_path}")


def _get_empty_static_data() -> Dict[str, Any]:
    """Get empty/default static data for imputation"""
    return {
        'static_flags': {},
        'static_metrics': {},
        'static_confidence': 0.0,
        'risk_score': 0.0,
        'detected_cwes': [],
        'vulnerability_count': 0,
        'findings': []
    }


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced merge of static analysis results with feature-engineered data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Merge static with features
  python merge_static_with_features.py \\
    --static datasets/static_results/train_static_enhanced.jsonl \\
    --features datasets/features/train_features.jsonl \\
    --output datasets/fused/train_with_static.jsonl
  
  # Merge static with base dataset (no features)
  python merge_static_with_features.py \\
    --static datasets/static_results/train_static_enhanced.jsonl \\
    --base datasets/processed/train.jsonl \\
    --output datasets/fused/train_with_static.jsonl
        """
    )
    
    parser.add_argument(
        '--static',
        type=str,
        required=True,
        help='Path to static analysis JSONL file'
    )
    
    parser.add_argument(
        '--features',
        type=str,
        help='Path to feature-engineered JSONL file (optional)'
    )
    
    parser.add_argument(
        '--base',
        type=str,
        help='Path to base dataset JSONL (used if --features not provided)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Path to save merged JSONL file'
    )
    
    parser.add_argument(
        '--impute',
        action='store_true',
        help='Impute zeros for missing static data'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.features and not args.base:
        parser.error("Either --features or --base must be provided")
    
    merge_datasets(
        static_path=Path(args.static),
        features_path=Path(args.features) if args.features else None,
        base_path=Path(args.base) if args.base else Path(args.features),
        output_path=Path(args.output),
        impute_missing=args.impute
    )


if __name__ == '__main__':
    main()
