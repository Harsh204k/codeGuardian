#!/usr/bin/env python3
"""
Merge Static Analysis Results with Feature-Engineered Data
"""

import argparse
import json
import sys
from pathlib import Path
import logging

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.static.utils.report_utils import ReportUtils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def merge_datasets(static_path: Path, features_path: Path, output_path: Path):
    """
    Merge static analysis results with feature-engineered dataset.
    
    Args:
        static_path: Path to static analysis JSONL
        features_path: Path to feature-engineered JSONL
        output_path: Path to save merged output
    """
    logger.info(f"Loading static results from {static_path}")
    static_data = {}
    
    with open(static_path, 'r', encoding='utf-8') as f:
        for line in f:
            record = json.loads(line)
            static_data[record['id']] = record
    
    logger.info(f"Loaded {len(static_data)} static analysis records")
    
    logger.info(f"Loading features from {features_path}")
    merged_records = []
    matched = 0
    unmatched = 0
    
    with open(features_path, 'r', encoding='utf-8') as f:
        for line in f:
            feature_record = json.loads(line)
            record_id = feature_record['id']
            
            # Merge static results if available
            if record_id in static_data:
                static_record = static_data[record_id]
                feature_record.update({
                    'static_flags': static_record.get('static_flags', {}),
                    'static_metrics': static_record.get('static_metrics', {}),
                    'risk_score': static_record.get('risk_score', 0.0),
                    'detected_cwes': static_record.get('detected_cwes', []),
                    'vulnerability_count': static_record.get('vulnerability_count', 0),
                })
                matched += 1
            else:
                # Add empty static data
                feature_record.update({
                    'static_flags': {},
                    'static_metrics': {},
                    'risk_score': 0.0,
                    'detected_cwes': [],
                    'vulnerability_count': 0,
                })
                unmatched += 1
            
            merged_records.append(feature_record)
    
    logger.info(f"Matched: {matched}, Unmatched: {unmatched}")
    
    # Save merged data
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for record in merged_records:
            json.dump(record, f, ensure_ascii=False)
            f.write('\n')
    
    logger.info(f"Merged {len(merged_records)} records to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Merge static analysis results with feature-engineered data'
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
        required=True,
        help='Path to feature-engineered JSONL file'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Path to save merged JSONL file'
    )
    
    args = parser.parse_args()
    
    merge_datasets(
        static_path=Path(args.static),
        features_path=Path(args.features),
        output_path=Path(args.output)
    )


if __name__ == '__main__':
    main()
