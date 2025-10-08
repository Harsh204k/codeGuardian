#!/usr/bin/env python3
"""
Export Static Analysis Results for ML Training
"""

import argparse
import json
import csv
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def export_for_ml(input_path: Path, output_dir: Path):
    """
    Export static analysis results in ML-ready formats.
    
    Args:
        input_path: Path to merged JSONL file
        output_dir: Directory for output files
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Loading merged data from {input_path}")
    records = []
    
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            records.append(json.loads(line))
    
    logger.info(f"Loaded {len(records)} records")
    
    # Export static flags as CSV
    flags_csv_path = output_dir / f"{input_path.stem}_flags.csv"
    export_flags_csv(records, flags_csv_path)
    
    # Export metrics as CSV
    metrics_csv_path = output_dir / f"{input_path.stem}_metrics.csv"
    export_metrics_csv(records, metrics_csv_path)
    
    # Export labels
    labels_csv_path = output_dir / f"{input_path.stem}_labels.csv"
    export_labels_csv(records, labels_csv_path)
    
    logger.info(f"Export complete to {output_dir}")


def export_flags_csv(records, output_path):
    """Export static flags to CSV."""
    if not records:
        return
    
    # Collect all flag names
    all_flags = set()
    for record in records:
        all_flags.update(record.get('static_flags', {}).keys())
    
    flag_names = sorted(all_flags)
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['id'] + flag_names)
        writer.writeheader()
        
        for record in records:
            row = {'id': record['id']}
            flags = record.get('static_flags', {})
            for flag_name in flag_names:
                row[flag_name] = flags.get(flag_name, 0)
            
            writer.writerow(row)
    
    logger.info(f"Flags exported to {output_path}")


def export_metrics_csv(records, output_path):
    """Export static metrics to CSV."""
    if not records:
        return
    
    # Collect all metric names
    all_metrics = set()
    for record in records:
        all_metrics.update(record.get('static_metrics', {}).keys())
    
    metric_names = sorted(all_metrics)
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'risk_score'] + metric_names)
        writer.writeheader()
        
        for record in records:
            row = {
                'id': record['id'],
                'risk_score': record.get('risk_score', 0.0)
            }
            metrics = record.get('static_metrics', {})
            for metric_name in metric_names:
                row[metric_name] = metrics.get(metric_name, 0)
            
            writer.writerow(row)
    
    logger.info(f"Metrics exported to {output_path}")


def export_labels_csv(records, output_path):
    """Export labels and metadata to CSV."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'id', 'label', 'language', 'vulnerability_count', 
            'risk_score', 'detected_cwes'
        ])
        writer.writeheader()
        
        for record in records:
            writer.writerow({
                'id': record['id'],
                'label': record.get('label', 0),
                'language': record.get('language', ''),
                'vulnerability_count': record.get('vulnerability_count', 0),
                'risk_score': record.get('risk_score', 0.0),
                'detected_cwes': ','.join(record.get('detected_cwes', []))
            })
    
    logger.info(f"Labels exported to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Export static analysis results for ML training'
    )
    
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Path to merged JSONL file'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='datasets/fused',
        help='Output directory (default: datasets/fused)'
    )
    
    args = parser.parse_args()
    
    export_for_ml(
        input_path=Path(args.input),
        output_dir=Path(args.output_dir)
    )


if __name__ == '__main__':
    main()
