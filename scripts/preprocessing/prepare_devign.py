#!/usr/bin/env python3
"""
Preprocessing script for Devign dataset.

The Devign dataset contains function-level vulnerability commits from FFmpeg and Qemu projects.
Files: ffmpeg.csv, qemu.csv, function.json

Expected fields:
- func: function code
- target: vulnerability label (0 or 1)
- project: project name (ffmpeg/qemu)
- commit_id: git commit hash
"""

import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_csv, read_json, write_jsonl, write_json, ensure_dir, ProgressWriter
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import map_to_unified_schema, validate_record, normalize_language, deduplicate_by_code_hash
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def process_csv_file(csv_path: str, project_name: str) -> List[Dict[str, Any]]:
    """
    Process a Devign CSV file (ffmpeg.csv or qemu.csv).
    
    Args:
        csv_path: Path to CSV file
        project_name: Name of the project
        
    Returns:
        List of processed records
    """
    records = []
    csv_data = list(read_csv(csv_path))
    
    logger.info(f"Processing {len(csv_data)} rows from {csv_path}")
    
    for idx, row in enumerate(tqdm(csv_data, desc=f"Processing {project_name}")):
        try:
            # Extract fields
            func = row.get('func', row.get('code', ''))
            target = row.get('target', row.get('label', '0'))
            commit_id = row.get('commit_id', '')
            
            # Sanitize code
            func = sanitize_code(func, language='C', normalize_ws=True)
            
            # Validate code
            if not is_valid_code(func, min_length=10):
                continue
            
            # Create intermediate record with dataset-specific fields
            intermediate_record = {
                "code": func,
                "label": target,  # Will be normalized by map_to_unified_schema
                "language": "C",
                "project": project_name,
                "commit_id": commit_id if commit_id else None,
                "func_name": None,  # Not available in CSV
                "file_name": None,
                "cwe_id": None,
                "cve_id": None,
                "description": None
            }
            
            # Map to unified schema with globally unique ID
            unified_record = map_to_unified_schema(
                record=intermediate_record,
                dataset_name="devign",
                index=idx
            )
            
            # Add source provenance for traceability
            unified_record['source_row_index'] = idx
            unified_record['source_file'] = Path(csv_path).name
            
            # Validate record
            is_valid, errors = validate_record(unified_record, use_jsonschema=True)
            if not is_valid:
                logger.warning(f"Validation failed for record {idx}: {errors}")
                continue
            
            records.append(unified_record)
            
        except Exception as e:
            logger.warning(f"Error processing row {idx} in {csv_path}: {e}")
            continue
    
    return records


def process_function_json(json_path: str) -> List[Dict[str, Any]]:
    """
    Process the function.json file from Devign dataset.
    
    Args:
        json_path: Path to function.json
        
    Returns:
        List of processed records
    """
    records = []
    
    try:
        data = read_json(json_path)
        
        # function.json might be a list or dict
        if isinstance(data, dict):
            data = [data]
        
        logger.info(f"Processing {len(data)} records from function.json")
        
        for idx, item in enumerate(tqdm(data, desc="Processing function.json")):
            try:
                # Extract fields (field names might vary)
                func = item.get('func', item.get('code', item.get('function', '')))
                target = item.get('target', item.get('label', item.get('vulnerable', 0)))
                project = item.get('project', 'unknown')
                commit_id = item.get('commit_id', item.get('commit', ''))
                
                # Sanitize code
                func = sanitize_code(func, language='C', normalize_ws=True)
                
                # Validate code
                if not is_valid_code(func, min_length=10):
                    continue
                
                # Create intermediate record
                intermediate_record = {
                    "code": func,
                    "label": target,
                    "language": "C",
                    "project": project,
                    "commit_id": commit_id if commit_id else None,
                    "func_name": None,
                    "file_name": None,
                    "cwe_id": None,
                    "cve_id": None,
                    "description": None
                }
                
                # Map to unified schema
                unified_record = map_to_unified_schema(
                    record=intermediate_record,
                    dataset_name="devign",
                    index=idx
                )
                
                # Add source provenance for traceability
                unified_record['source_row_index'] = idx
                unified_record['source_file'] = Path(json_path).name
                
                # Validate record
                is_valid, errors = validate_record(unified_record, use_jsonschema=True)
                if not is_valid:
                    logger.warning(f"Validation failed for record {idx}: {errors}")
                    continue
                
                records.append(unified_record)
                
            except Exception as e:
                logger.warning(f"Error processing item {idx} in {json_path}: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error reading {json_path}: {e}")
    
    return records


def generate_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate statistics for the processed dataset.
    
    Args:
        records: List of processed records
        
    Returns:
        Statistics dictionary
    """
    total = len(records)
    vulnerable = sum(1 for r in records if r['label'] == 1)
    non_vulnerable = total - vulnerable
    
    projects = {}
    for record in records:
        proj = record.get('project', 'unknown')
        if proj not in projects:
            projects[proj] = {'total': 0, 'vulnerable': 0}
        projects[proj]['total'] += 1
        if record['label'] == 1:
            projects[proj]['vulnerable'] += 1
    
    return {
        "dataset": "devign",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": {"C": total},
        "projects": projects,
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    parser = argparse.ArgumentParser(description='Preprocess Devign dataset')
    parser.add_argument(
        '--input-dir',
        type=str,
        default=None,
        help='Input directory containing raw Devign files (auto-detected if not provided)'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default=None,
        help='Output directory for processed files (auto-detected if not provided)'
    )
    parser.add_argument(
        '--max-records',
        type=int,
        default=None,
        help='Maximum number of records to process (for testing)'
    )
    
    args = parser.parse_args()
    
    # Print environment info
    print_environment_info()
    
    # Get paths using Kaggle-compatible helper
    if args.input_dir:
        input_dir = Path(args.input_dir).resolve()
    else:
        input_dir = get_dataset_path("devign/raw")
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("devign/processed")
    
    logger.info(f"[INFO] Processing Devign dataset from: {input_dir}")
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    all_records = []
    
    # Process ffmpeg.csv
    ffmpeg_path = input_dir / "ffmpeg.csv"
    if ffmpeg_path.exists():
        logger.info(f"Processing {ffmpeg_path}")
        records = process_csv_file(str(ffmpeg_path), "ffmpeg")
        logger.info(f"Extracted {len(records)} records from ffmpeg.csv")
        all_records.extend(records)
    else:
        logger.warning(f"File not found: {ffmpeg_path}")
    
    # Process qemu.csv
    qemu_path = input_dir / "qemu.csv"
    if qemu_path.exists():
        logger.info(f"Processing {qemu_path}")
        records = process_csv_file(str(qemu_path), "qemu")
        logger.info(f"Extracted {len(records)} records from qemu.csv")
        all_records.extend(records)
    else:
        logger.warning(f"File not found: {qemu_path}")
    
    # Process function.json
    function_path = input_dir / "function.json"
    if function_path.exists():
        logger.info(f"Processing {function_path}")
        records = process_function_json(str(function_path))
        logger.info(f"Extracted {len(records)} records from function.json")
        all_records.extend(records)
    else:
        logger.warning(f"File not found: {function_path}")
    
    # Limit records if specified
    if args.max_records and len(all_records) > args.max_records:
        logger.info(f"Limiting to {args.max_records} records")
        all_records = all_records[:args.max_records]
    
    # Deduplicate using full SHA-256 hash instead of prefix (more accurate)
    logger.info(f"Deduplicating {len(all_records)} records using SHA-256 hash...")
    unique_records = deduplicate_by_code_hash(all_records)
    
    logger.info(f"Removed {len(all_records) - len(unique_records)} duplicate records")
    all_records = unique_records
    
    # Save processed records
    output_file = output_dir / "raw_cleaned.jsonl"
    logger.info(f"[INFO] Saving {len(all_records)} records to: {output_file}")
    write_jsonl(all_records, str(output_file))
    
    # Generate and save statistics
    stats = generate_stats(all_records)
    stats_file = output_dir / "stats.json"
    write_json(stats, str(stats_file))
    logger.info(f"[INFO] Statistics saved to: {stats_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("DEVIGN DATASET PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"Projects: {', '.join(stats['projects'].keys())}")
    print(f"\nOutput saved to: {output_dir}")
    print("="*60 + "\n")


def run(args=None):
    """
    Entry point for dynamic pipeline orchestrator.
    
    Args:
        args: Optional argparse.Namespace object with configuration.
              If None, will parse from sys.argv.
    """
    if args is None:
        main()
    else:
        # If args provided by orchestrator, use them
        import sys
        original_argv = sys.argv.copy()
        
        # Build argv from args
        sys.argv = ['prepare_devign.py']
        if hasattr(args, 'input_dir') and args.input_dir:
            sys.argv.extend(['--input-dir', args.input_dir])
        if hasattr(args, 'output_dir') and args.output_dir:
            sys.argv.extend(['--output-dir', args.output_dir])
        if hasattr(args, 'max_records') and args.max_records:
            sys.argv.extend(['--max-records', str(args.max_records)])
        if hasattr(args, 'quick_test') and args.quick_test:
            sys.argv.extend(['--max-records', '100'])
        
        try:
            main()
        finally:
            sys.argv = original_argv


if __name__ == "__main__":
    main()

