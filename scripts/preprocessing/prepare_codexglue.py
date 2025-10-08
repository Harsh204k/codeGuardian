#!/usr/bin/env python3
"""
Preprocessing script for CodeXGLUE Defect Detection dataset.

CodeXGLUE is derived from Devign and provides binary classification validation data.

Files: train.txt, valid.txt, test.txt

Format: Each line contains: <label> <code>
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import write_jsonl, write_json, ensure_dir, safe_read_text
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import map_to_unified_schema, validate_record

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def process_codexglue_file(file_path: str, split_name: str, global_index_offset: int = 0) -> List[Dict[str, Any]]:
    """
    Process a CodeXGLUE text file.
    
    Args:
        file_path: Path to text file
        split_name: Name of the split (train/valid/test)
        global_index_offset: Starting index for globally unique IDs
        
    Returns:
        List of processed records
    """
    records = []
    
    logger.info(f"Processing {file_path}")
    
    content = safe_read_text(file_path)
    if not content:
        logger.error(f"Could not read file: {file_path}")
        return records
    
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    logger.info(f"Processing {len(lines)} lines from {split_name}")
    
    for idx, line in enumerate(tqdm(lines, desc=f"Processing {split_name}")):
        try:
            # Split into label and code
            # Format: <label> <code>
            parts = line.split(None, 1)  # Split on first whitespace
            
            if len(parts) < 2:
                logger.warning(f"Invalid line format at index {idx}")
                continue
            
            label_str, code = parts
            
            # Parse label
            try:
                label = int(label_str)
            except ValueError:
                logger.warning(f"Invalid label at index {idx}: {label_str}")
                continue
            
            # Sanitize code
            code = sanitize_code(code, language='C', normalize_ws=True)
            
            # Validate code
            if not is_valid_code(code, min_length=10):
                continue
            
            # Create intermediate record
            intermediate_record = {
                "code": code,
                "label": label,
                "language": "C",
                "project": None,
                "commit_id": None,
                "cwe_id": None,
                "cve_id": None,
                "file_name": None,
                "func_name": None,
                "description": None
            }
            
            # Map to unified schema
            unified_record = map_to_unified_schema(
                record=intermediate_record,
                dataset_name="codexglue",
                index=global_index_offset + idx
            )
            
            # Validate record
            is_valid, errors = validate_record(unified_record, use_jsonschema=True)
            if not is_valid:
                logger.warning(f"Validation failed for line {idx}: {errors}")
                continue
            
            records.append(unified_record)
            
        except Exception as e:
            logger.warning(f"Error processing line {idx}: {e}")
            continue
    
    logger.info(f"Extracted {len(records)} valid records from {split_name}")
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
    
    # Split distribution
    splits = {}
    for record in records:
        source_dataset = record.get('source_dataset', 'codexglue')
        # Infer split from ID pattern or source
        record_id = record.get('id', '')
        if 'train' in record_id or record_id.startswith('codexglue_0'):
            split = 'train'
        elif 'valid' in record_id or 'val' in record_id:
            split = 'valid'
        elif 'test' in record_id:
            split = 'test'
        else:
            split = 'unknown'
        
        if split not in splits:
            splits[split] = {'total': 0, 'vulnerable': 0}
        splits[split]['total'] += 1
        if record['label'] == 1:
            splits[split]['vulnerable'] += 1
    
    return {
        "dataset": "codexglue",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": {"C": total},
        "splits": splits,
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    parser = argparse.ArgumentParser(description='Preprocess CodeXGLUE Defect Detection dataset')
    parser.add_argument(
        '--input-dir',
        type=str,
        default='../../datasets/codexglue_defect/raw',
        help='Input directory containing CodeXGLUE text files'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='../../datasets/codexglue_defect/processed',
        help='Output directory for processed files'
    )
    parser.add_argument(
        '--max-records',
        type=int,
        default=None,
        help='Maximum number of records to process (for testing)'
    )
    
    args = parser.parse_args()
    
    # Convert to absolute paths
    script_dir = Path(__file__).parent
    input_dir = (script_dir / args.input_dir).resolve()
    output_dir = (script_dir / args.output_dir).resolve()
    
    logger.info(f"Processing CodeXGLUE dataset from {input_dir}")
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    all_records = []
    global_index = 0  # Track global index for unique IDs
    
    # Process train.txt
    train_path = input_dir / "train.txt"
    if train_path.exists():
        records = process_codexglue_file(str(train_path), "train", global_index)
        global_index += len(records)
        all_records.extend(records)
    else:
        logger.warning(f"File not found: {train_path}")
    
    # Process valid.txt
    valid_path = input_dir / "valid.txt"
    if valid_path.exists():
        records = process_codexglue_file(str(valid_path), "valid", global_index)
        global_index += len(records)
        all_records.extend(records)
    else:
        logger.warning(f"File not found: {valid_path}")
    
    # Process test.txt
    test_path = input_dir / "test.txt"
    if test_path.exists():
        records = process_codexglue_file(str(test_path), "test", global_index)
        global_index += len(records)
        all_records.extend(records)
    else:
        logger.warning(f"File not found: {test_path}")
    
    # Limit records if specified
    if args.max_records and len(all_records) > args.max_records:
        logger.info(f"Limiting to {args.max_records} records")
        all_records = all_records[:args.max_records]
    
    # Remove duplicates based on code content
    unique_codes = set()
    unique_records = []
    for record in all_records:
        code_key = record['code'][:200]  # Use first 200 chars as key
        if code_key not in unique_codes:
            unique_codes.add(code_key)
            unique_records.append(record)
    
    logger.info(f"Removed {len(all_records) - len(unique_records)} duplicate records")
    all_records = unique_records
    
    # Save processed records
    output_file = output_dir / "raw_cleaned.jsonl"
    logger.info(f"Saving {len(all_records)} records to {output_file}")
    write_jsonl(all_records, str(output_file))
    
    # Generate and save statistics
    stats = generate_stats(all_records)
    stats_file = output_dir / "stats.json"
    write_json(stats, str(stats_file))
    logger.info(f"Statistics saved to {stats_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("CODEXGLUE DATASET PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"\nSplit distribution:")
    for split, counts in stats['splits'].items():
        print(f"  {split}: {counts['total']} records ({counts['vulnerable']} vulnerable)")
    print(f"\nOutput saved to: {output_dir}")
    print("="*60 + "\n")


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

