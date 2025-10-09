#!/usr/bin/env python3
"""
Preprocessing script for MegaVul dataset.

MegaVul is a graph-based dataset with commit-level vulnerability information
for C/C++ projects.

NOTE: This is a placeholder implementation as the MegaVul dataset is not yet available.
Update this script when the dataset becomes available.

Expected structure (to be updated):
- Graph data with nodes and edges
- Commit-level vulnerability information
- CWE/CVE mappings
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_json, read_jsonl, write_jsonl, write_json, ensure_dir
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import (
    normalize_language, normalize_cwe_id, normalize_cve_id,
    map_to_unified_schema, validate_record
)
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def process_megavul_record(record: Dict[str, Any], index: int) -> Optional[Dict[str, Any]]:
    """
    Process a single MegaVul record.
    
    Args:
        record: Raw record from MegaVul dataset
        index: Index for unique ID generation
        
    Returns:
        Processed record or None if invalid
    """
    try:
        # TODO: Update field mappings based on actual MegaVul structure
        code = record.get('code', record.get('func', record.get('source', '')))
        label = record.get('label', record.get('vulnerable', record.get('target', 0)))
        language = record.get('language', record.get('lang', 'C'))
        cwe_id = record.get('CWE_ID', record.get('cwe_id', ''))
        cve_id = record.get('CVE_ID', record.get('cve_id', ''))
        commit_id = record.get('commit_id', record.get('commit', ''))
        project = record.get('project', record.get('repo', ''))
        file_name = record.get('file', record.get('filename', ''))
        func_name = record.get('func_name', record.get('function', ''))
        
        # Sanitize code
        code = sanitize_code(code, language=language, normalize_ws=True)
        
        # Validate code
        if not is_valid_code(code, min_length=10):
            return None
        
        # Normalize fields
        language = normalize_language(language)
        cwe_id = normalize_cwe_id(cwe_id)
        cve_id = normalize_cve_id(cve_id)
        
        # Convert label
        if isinstance(label, str):
            is_vulnerable = 1 if label.lower() in ['1', 'true', 'yes', 'vulnerable'] else 0
        else:
            is_vulnerable = int(label) if label else 0
        
        # Create record
        return {
            "code": code,
            "is_vulnerable": is_vulnerable,
            "language": language,
            "project": project if project else None,
            "commit_id": commit_id if commit_id else None,
            "cwe_id": cwe_id,
            "cve_id": cve_id,
            "file_name": file_name if file_name else None,
            "method_name": None,
            "dataset": "megavul",
            "source": "megavul"
        }
        
    except Exception as e:
        logger.warning(f"Error processing MegaVul record: {e}")
        return None


def generate_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate statistics for the processed dataset.
    
    Args:
        records: List of processed records
        
    Returns:
        Statistics dictionary
    """
    total = len(records)
    vulnerable = sum(1 for r in records if r['is_vulnerable'] == 1)
    non_vulnerable = total - vulnerable
    
    # Language distribution
    languages = {}
    for record in records:
        lang = record.get('language', 'unknown')
        if lang not in languages:
            languages[lang] = {'total': 0, 'vulnerable': 0}
        languages[lang]['total'] += 1
        if record['is_vulnerable'] == 1:
            languages[lang]['vulnerable'] += 1
    
    # CWE distribution
    cwes = {}
    for record in records:
        cwe = record.get('cwe_id')
        if cwe:
            cwes[cwe] = cwes.get(cwe, 0) + 1
    
    return {
        "dataset": "megavul",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": languages,
        "unique_cwes": len(cwes),
        "top_cwes": sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:10] if cwes else [],
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    parser = argparse.ArgumentParser(description='Preprocess MegaVul dataset')
    parser.add_argument(
        '--input-dir',
        type=str,
        default=None,
        help='Input directory containing raw MegaVul files (auto-detected if not provided)'
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
        input_dir = get_dataset_path("megavul")
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("megavul/processed")
    
    logger.info(f"[INFO] Processing MegaVul dataset from: {input_dir}")
    
    # Check if dataset exists
    if not input_dir.exists():
        logger.warning("="*60)
        logger.warning("MegaVul dataset not found!")
        logger.warning(f"Expected location: {input_dir}")
        logger.warning("This dataset will be processed when it becomes available.")
        logger.warning("="*60)
        
        # Create placeholder output
        ensure_dir(str(output_dir))
        placeholder_stats = {
            "dataset": "megavul",
            "status": "Dataset not yet available",
            "total_records": 0,
            "note": "Update this script when MegaVul dataset is added"
        }
        write_json(placeholder_stats, str(output_dir / "stats.json"))
        return
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    all_records = []
    
    # TODO: Update file processing logic based on actual MegaVul structure
    # Look for common file patterns
    for json_file in input_dir.glob("*.json"):
        logger.info(f"Processing {json_file}")
        try:
            data = read_json(str(json_file))
            if isinstance(data, list):
                for record in data:
                    processed = process_megavul_record(record)
                    if processed:
                        all_records.append(processed)
            else:
                processed = process_megavul_record(data)
                if processed:
                    all_records.append(processed)
        except Exception as e:
            logger.error(f"Error processing {json_file}: {e}")
    
    for jsonl_file in input_dir.glob("*.jsonl"):
        logger.info(f"Processing {jsonl_file}")
        try:
            for record in read_jsonl(str(jsonl_file)):
                processed = process_megavul_record(record)
                if processed:
                    all_records.append(processed)
        except Exception as e:
            logger.error(f"Error processing {jsonl_file}: {e}")
    
    if not all_records:
        logger.warning("No records found in MegaVul dataset")
        placeholder_stats = {
            "dataset": "megavul",
            "status": "No valid records found",
            "total_records": 0
        }
        write_json(placeholder_stats, str(output_dir / "stats.json"))
        return
    
    # Limit records if specified
    if args.max_records and len(all_records) > args.max_records:
        logger.info(f"Limiting to {args.max_records} records")
        all_records = all_records[:args.max_records]
    
    # Remove duplicates
    unique_codes = set()
    unique_records = []
    for record in all_records:
        code_key = record['code'][:200]
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
    print("MEGAVUL DATASET PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"Languages: {len(stats['languages'])}")
    print(f"Unique CWEs: {stats['unique_cwes']}")
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

