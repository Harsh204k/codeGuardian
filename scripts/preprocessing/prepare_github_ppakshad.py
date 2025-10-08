#!/usr/bin/env python3
"""
Preprocessing script for github_ppakshad dataset (Main_DataSet.xlsx).

This dataset contains function-level training data with static metrics M1-M15.

Expected fields:
- code/function: source code
- label/vulnerable: vulnerability label
- Static metrics M1-M15 (optional)
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_excel, write_jsonl, write_json, ensure_dir
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import (
    normalize_language, map_to_unified_schema, 
    validate_record, infer_language_from_filename
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def process_excel_file(excel_path: str) -> List[Dict[str, Any]]:
    """
    Process the Main_DataSet.xlsx file.
    
    Args:
        excel_path: Path to Excel file
        
    Returns:
        List of processed records
    """
    records = []
    
    logger.info(f"Reading Excel file: {excel_path}")
    rows = list(read_excel(excel_path))
    logger.info(f"Loaded {len(rows)} rows from Excel")
    
    for idx, row in enumerate(tqdm(rows, desc="Processing Excel rows")):
        try:
            # Extract fields - try various possible column names
            code = row.get('code', row.get('Code', row.get('function', row.get('Function', 
                   row.get('source_code', row.get('Source Code', ''))))))
            
            label = row.get('label', row.get('Label', row.get('vulnerable', row.get('Vulnerable',
                    row.get('target', row.get('Target', 0))))))
            
            language = row.get('language', row.get('Language', row.get('lang', 
                       row.get('Lang', 'C'))))  # Default to C if not specified
            
            project = row.get('project', row.get('Project', row.get('repo', row.get('Repo', ''))))
            file_name = row.get('file', row.get('File', row.get('filename', row.get('FileName', ''))))
            func_name = row.get('function_name', row.get('FunctionName', row.get('method', 
                        row.get('Method', row.get('func', row.get('Func', ''))))))
            
            # CWE/CVE if available
            cwe_id = row.get('CWE_ID', row.get('cwe_id', row.get('CWE', row.get('cwe', ''))))
            cve_id = row.get('CVE_ID', row.get('cve_id', row.get('CVE', row.get('cve', ''))))
            
            # Infer language from filename if not specified
            if not language or language.lower() == 'unknown':
                if file_name:
                    inferred_lang = infer_language_from_filename(file_name)
                    if inferred_lang:
                        language = inferred_lang
            
            # Sanitize code
            code = sanitize_code(code, language=language, normalize_ws=True)
            
            # Validate code
            if not is_valid_code(code, min_length=10):
                continue
            
            # Create intermediate record
            intermediate_record = {
                "code": code,
                "label": label,
                "language": language,
                "project": project if project else None,
                "commit_id": None,
                "cwe_id": cwe_id if cwe_id else None,
                "cve_id": cve_id if cve_id else None,
                "file_name": file_name if file_name else None,
                "func_name": func_name if func_name else None,
                "description": None
            }
            
            # Map to unified schema
            unified_record = map_to_unified_schema(
                record=intermediate_record,
                dataset_name="github_ppakshad",
                index=idx
            )
            
            # Validate record
            is_valid, errors = validate_record(unified_record, use_jsonschema=True)
            if not is_valid:
                logger.warning(f"Validation failed for row {idx}: {errors}")
                continue
            
            records.append(unified_record)
            
        except Exception as e:
            logger.warning(f"Error processing row {idx}: {e}")
            continue
    
    logger.info(f"Extracted {len(records)} valid records")
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
    
    # Language distribution
    languages = {}
    for record in records:
        lang = record.get('language', 'unknown')
        if lang not in languages:
            languages[lang] = {'total': 0, 'vulnerable': 0}
        languages[lang]['total'] += 1
        if record['label'] == 1:
            languages[lang]['vulnerable'] += 1
    
    return {
        "dataset": "github_ppakshad",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": languages,
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    parser = argparse.ArgumentParser(description='Preprocess github_ppakshad dataset')
    parser.add_argument(
        '--input-dir',
        type=str,
        default='../../datasets/github_ppakshad/raw',
        help='Input directory containing Main_DataSet.xlsx'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='../../datasets/github_ppakshad/processed',
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
    
    logger.info(f"Processing github_ppakshad dataset from {input_dir}")
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    # Process Excel file
    excel_path = input_dir / "main_dataset.xlsx"
    
    if not excel_path.exists():
        logger.error(f"Excel file not found: {excel_path}")
        return
    
    all_records = process_excel_file(str(excel_path))
    
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
    print("GITHUB_PPAKSHAD DATASET PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"Languages: {', '.join(stats['languages'].keys())}")
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

