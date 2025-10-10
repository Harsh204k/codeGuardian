#!/usr/bin/env python3
"""
Preprocessing script for Zenodo multi-language dataset.

The Zenodo dataset contains vulnerable/patch code across 8 languages with CWE/CVE metadata.
Files: data_C.csv, data_C++.csv, data_Go.csv, data_Java.csv, data_JavaScript.csv, 
       data_PHP.csv, data_Python.csv, data_Ruby.csv

Expected fields:
- code: source code snippet
- label: vulnerability label (0 or 1)
- CWE_ID: CWE identifier
- CVE_ID: CVE identifier (optional)
- language: programming language
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_csv, write_jsonl, write_json, ensure_dir
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import (
    normalize_language, normalize_cwe_id, normalize_cve_id,
    map_to_unified_schema, validate_record, deduplicate_by_code_hash
)
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Language file mapping
LANGUAGE_FILES = {
    "C": "data_C.csv",
    "C++": "data_C++.csv",
    "Go": "data_Go.csv",
    "Java": "data_Java.csv",
    "JavaScript": "data_JavaScript.csv",
    "PHP": "data_PHP.csv",
    "Python": "data_Python.csv",
    "Ruby": "data_Ruby.csv"
}


def process_language_file(csv_path: str, language: str, global_index_offset: int = 0) -> List[Dict[str, Any]]:
    """
    Process a language-specific CSV file from Zenodo dataset.
    
    Args:
        csv_path: Path to CSV file
        language: Programming language name
        global_index_offset: Starting index for globally unique IDs
        
    Returns:
        List of processed records with source_row_index for provenance
    """
    records = []
    csv_data = list(read_csv(csv_path))
    
    logger.info(f"Processing {len(csv_data)} records from {language} file")
    
    # DEBUG: Print first row to see actual column names
    if csv_data and len(csv_data) > 0:
        available_cols = list(csv_data[0].keys())
        print(f"\n{'='*60}")
        print(f"[DEBUG] CSV Column Analysis for {language}")
        print(f"{'='*60}")
        print(f"Total columns: {len(available_cols)}")
        print(f"Available columns: {available_cols}")
        
        # Check which expected columns are present
        code_cols = ['vul_code', 'code', 'Code', 'source_code', 'func', 'function']
        label_cols = ['is_vulnerable', 'label', 'Label', 'vulnerable', 'target']
        cwe_cols = ['cwe_id', 'CWE_ID', 'CWE', 'cwe']
        cve_cols = ['cve_id', 'CVE_ID', 'CVE', 'cve']
        
        print(f"\nColumn mapping check:")
        print(f"  Code columns: {[c for c in code_cols if c in available_cols]}")
        print(f"  Label columns: {[c for c in label_cols if c in available_cols]}")
        print(f"  CWE columns: {[c for c in cwe_cols if c in available_cols]}")
        print(f"  CVE columns: {[c for c in cve_cols if c in available_cols]}")
        
        print(f"\nFirst row sample:")
        sample = dict(list(csv_data[0].items())[:5])
        for k, v in sample.items():
            val_str = str(v)[:100] + "..." if len(str(v)) > 100 else str(v)
            print(f"  {k}: {val_str}")
        print(f"{'='*60}\n")
    
    rejected_reasons = {"code_invalid": 0, "validation_failed": 0, "exception": 0}
    
    for idx, row in enumerate(tqdm(csv_data, desc=f"Processing {language}")):
        try:
            # Extract fields with extended fallback options (vul_code is the actual column name!)
            code = (row.get('vul_code') or row.get('func') or row.get('function') or 
                   row.get('code') or row.get('Code') or row.get('source_code') or '')
            label = (row.get('is_vulnerable') or row.get('target') or row.get('label') or 
                    row.get('Label') or row.get('vulnerable') or '0')
            cwe_id = (row.get('cwe_id') or row.get('CWE') or row.get('cwe') or 
                     row.get('CWE_ID') or '')
            cve_id = (row.get('cve_id') or row.get('CVE') or row.get('cve') or 
                     row.get('CVE_ID') or '')
            project = row.get('repo_owner', row.get('project', row.get('Project', '')))
            file_name = row.get('file_name', row.get('file', row.get('File', row.get('filename', row.get('file_path', '')))))
            func_name = row.get('method_name', row.get('function', row.get('method', row.get('func_name', ''))))
            
            # DEBUG: Print first record details
            if idx == 0:
                print(f"[DEBUG] Extracted - code_len={len(str(code))}, label={label}, cwe={cwe_id}, cve={cve_id}")
            
            # Sanitize code
            code = sanitize_code(code, language=language, normalize_ws=True)
            
            # DEBUG: After sanitization
            if idx == 0:
                print(f"[DEBUG] After sanitize - code_len={len(str(code))}")
            
            # Validate code
            if not is_valid_code(code, min_length=10):
                rejected_reasons["code_invalid"] += 1
                if idx == 0:
                    print(f"[DEBUG] Code validation FAILED - is_valid_code returned False")
                continue
            
            # Create intermediate record
            intermediate_record = {
                "code": code,
                "label": label,
                "language": language,
                "project": project if project else None,
                "commit_id": None,
                "cwe_id": cwe_id,
                "cve_id": cve_id,
                "file_name": file_name if file_name else None,
                "func_name": func_name if func_name else None,
                "description": None
            }
            
            # Map to unified schema
            unified_record = map_to_unified_schema(
                record=intermediate_record,
                dataset_name="zenodo",
                index=global_index_offset + idx
            )
            
            # Add source provenance for traceability
            unified_record['source_row_index'] = idx
            unified_record['source_file'] = Path(csv_path).name
            
            # Validate record
            is_valid, errors = validate_record(unified_record, use_jsonschema=True)
            if not is_valid:
                rejected_reasons["validation_failed"] += 1
                if idx < 3:  # Print first 3 validation failures
                    logger.warning(f"Validation failed for record {idx}: {errors}")
                    logger.debug(f"Failed record: id={unified_record.get('id')}, "
                               f"language={unified_record.get('language')}, "
                               f"label={unified_record.get('label')}, "
                               f"code_len={len(unified_record.get('code', ''))}")
                continue
            
            records.append(unified_record)
            
        except Exception as e:
            rejected_reasons["exception"] += 1
            if idx < 3:  # Print first 3 exceptions
                logger.warning(f"Error processing row {idx} in {csv_path}: {e}")
            continue
    
    # Print rejection summary
    print(f"\n[DEBUG] Rejection summary for {language}:")
    print(f"  - Code invalid: {rejected_reasons['code_invalid']}")
    print(f"  - Validation failed: {rejected_reasons['validation_failed']}")
    print(f"  - Exceptions: {rejected_reasons['exception']}")
    print(f"  - Successfully processed: {len(records)}")
    
    logger.info(f"Extracted {len(records)} valid records from {language}")
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
    
    # CWE distribution
    cwes = {}
    for record in records:
        cwe = record.get('cwe_id')
        if cwe:
            cwes[cwe] = cwes.get(cwe, 0) + 1
    
    # CVE count
    cve_count = sum(1 for r in records if r.get('cve_id'))
    
    return {
        "dataset": "zenodo",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": languages,
        "unique_cwes": len(cwes),
        "top_cwes": sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:10],
        "records_with_cve": cve_count,
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    parser = argparse.ArgumentParser(description='Preprocess Zenodo multi-language dataset')
    parser.add_argument(
        '--input-dir',
        type=str,
        default=None,
        help='Input directory containing raw Zenodo CSV files (auto-detected if not provided)'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default=None,
        help='Output directory for processed files (auto-detected if not provided)'
    )
    parser.add_argument(
        '--languages',
        nargs='+',
        default=None,
        help='Specific languages to process (default: all)'
    )
    parser.add_argument(
        '--max-records-per-lang',
        type=int,
        default=None,
        help='Maximum number of records per language (for testing)'
    )
    
    args = parser.parse_args()
    
    # Print environment info
    print_environment_info()
    
    # Get paths using Kaggle-compatible helper
    if args.input_dir:
        input_dir = Path(args.input_dir).resolve()
    else:
        input_dir = get_dataset_path("zenodo")
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("zenodo/processed")
    
    logger.info(f"[INFO] Processing Zenodo dataset from: {input_dir}")
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    # Determine which languages to process
    languages_to_process = args.languages if args.languages else list(LANGUAGE_FILES.keys())
    
    all_records = []
    global_index = 0  # Track global index for unique IDs across all languages
    
    # Process each language file
    for language in languages_to_process:
        if language not in LANGUAGE_FILES:
            logger.warning(f"Unknown language: {language}")
            continue
        
        file_path = input_dir / LANGUAGE_FILES[language]
        
        if not file_path.exists():
            logger.warning(f"File not found: {file_path}")
            continue
        
        records = process_language_file(str(file_path), language, global_index_offset=global_index)
        global_index += len(records)  # Update global index
        
        # Limit records if specified
        if args.max_records_per_lang and len(records) > args.max_records_per_lang:
            logger.info(f"Limiting {language} to {args.max_records_per_lang} records")
            records = records[:args.max_records_per_lang]
        
        all_records.extend(records)
    
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
    print("ZENODO DATASET PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"Languages processed: {len(stats['languages'])}")
    print(f"Unique CWEs: {stats['unique_cwes']}")
    print(f"Records with CVE: {stats['records_with_cve']}")
    print(f"\nTop 5 CWEs:")
    for cwe, count in stats['top_cwes'][:5]:
        print(f"  {cwe}: {count}")
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

