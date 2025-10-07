#!/usr/bin/env python3
"""
Preprocessing script for Juliet Test Suite dataset.

The Juliet Test Suite is a synthetic NIST benchmark for CWE-type classification
and robustness testing. It contains test cases across multiple languages.

Structure:
- juliet/c/testcases/: C test cases organized by CWE
- juliet/java/: Java test cases
- juliet/csharp/: C# test cases

Each testcase contains "good" (non-vulnerable) and "bad" (vulnerable) examples.
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List
import sys
import re
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import write_jsonl, write_json, ensure_dir, safe_read_text
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import (
    normalize_language, normalize_cwe_id,
    map_to_unified_schema, validate_record
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def extract_cwe_from_path(file_path: Path) -> str:
    """
    Extract CWE ID from file path.
    
    Args:
        file_path: Path to source file
        
    Returns:
        CWE ID or None
    """
    # Look for CWE pattern in path: CWE123, CWE-123, etc.
    path_str = str(file_path)
    match = re.search(r'CWE[-_]?(\d+)', path_str, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return None


def is_vulnerable_testcase(file_path: Path) -> bool:
    """
    Determine if a testcase is vulnerable based on file naming conventions.
    
    Juliet uses patterns like:
    - *_bad.c, *_bad_*.c: vulnerable
    - *_good.c, *_good_*.c: non-vulnerable
    
    Args:
        file_path: Path to source file
        
    Returns:
        True if vulnerable, False otherwise
    """
    filename = file_path.stem.lower()
    
    # Check for "bad" pattern (vulnerable)
    if '_bad' in filename or filename.endswith('bad'):
        return True
    
    # Check for "good" pattern (non-vulnerable)
    if '_good' in filename or filename.endswith('good'):
        return False
    
    # Default to vulnerable if unclear (conservative)
    return True


def process_source_file(file_path: Path, language: str, index: int = 0) -> List[Dict[str, Any]]:
    """
    Process a single source file from Juliet.
    
    Args:
        file_path: Path to source file
        language: Programming language
        index: Index for unique ID generation
        
    Returns:
        List of processed records (typically 1 per file)
    """
    records = []
    
    try:
        # Read source code
        code = safe_read_text(str(file_path))
        if not code:
            return records
        
        # Extract CWE from path
        cwe_id = extract_cwe_from_path(file_path)
        
        # Determine if vulnerable
        is_vuln = is_vulnerable_testcase(file_path)
        
        # Sanitize code
        code = sanitize_code(code, language=language, normalize_ws=True)
        
        # Validate code length
        if not is_valid_code(code, min_length=50):  # Juliet files are typically longer
            return records
        
        # Create intermediate record
        intermediate_record = {
            "code": code,
            "label": 1 if is_vuln else 0,
            "language": language,
            "project": "juliet",
            "commit_id": None,
            "cwe_id": cwe_id,
            "cve_id": None,
            "file_name": file_path.name,
            "func_name": None,
            "description": f"Juliet synthetic test case for {cwe_id}" if cwe_id else "Juliet test case"
        }
        
        # Map to unified schema
        unified_record = map_to_unified_schema(
            record=intermediate_record,
            dataset_name="juliet",
            index=index
        )
        
        # Validate record
        is_valid, errors = validate_record(unified_record, use_jsonschema=True)
        if not is_valid:
            logger.warning(f"Validation failed for {file_path.name}: {errors}")
            return records
        
        records.append(unified_record)
        
    except Exception as e:
        logger.warning(f"Error processing {file_path}: {e}")
    
    return records


def process_language_directory(lang_dir: Path, language: str, file_extensions: List[str]) -> List[Dict[str, Any]]:
    """
    Process all testcases for a specific language.
    
    Args:
        lang_dir: Directory containing language testcases
        language: Programming language name
        file_extensions: List of file extensions to process
        
    Returns:
        List of processed records
    """
    records = []
    
    if not lang_dir.exists():
        logger.warning(f"Language directory not found: {lang_dir}")
        return records
    
    logger.info(f"Processing {language} testcases from {lang_dir}")
    
    # Find testcases directory
    testcases_dir = lang_dir / "testcases"
    if not testcases_dir.exists():
        testcases_dir = lang_dir
    
    # Process all source files
    for ext in file_extensions:
        source_files = list(testcases_dir.rglob(f"*{ext}"))
        logger.info(f"Found {len(source_files)} {ext} files")
        
        for file_path in source_files:
            file_records = process_source_file(file_path, language)
            records.extend(file_records)
    
    logger.info(f"Extracted {len(records)} records from {language}")
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
    
    return {
        "dataset": "juliet",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": languages,
        "unique_cwes": len(cwes),
        "top_cwes": sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:15],
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    parser = argparse.ArgumentParser(description='Preprocess Juliet Test Suite dataset')
    parser.add_argument(
        '--input-dir',
        type=str,
        default='../../datasets/juliet',
        help='Input directory containing Juliet testcases'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='../../datasets/juliet/processed',
        help='Output directory for processed files'
    )
    parser.add_argument(
        '--languages',
        nargs='+',
        default=['c'],
        help='Languages to process (c, java, csharp)'
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
    
    logger.info(f"Processing Juliet dataset from {input_dir}")
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    # Language-specific settings
    language_config = {
        'c': {'dir': 'c', 'extensions': ['.c', '.h']},
        'cpp': {'dir': 'cpp', 'extensions': ['.cpp', '.hpp', '.cc']},
        'java': {'dir': 'java', 'extensions': ['.java']},
        'csharp': {'dir': 'csharp', 'extensions': ['.cs']}
    }
    
    all_records = []
    
    # Process each language
    for lang in args.languages:
        if lang not in language_config:
            logger.warning(f"Unknown language: {lang}")
            continue
        
        config = language_config[lang]
        lang_dir = input_dir / config['dir']
        
        records = process_language_directory(lang_dir, lang, config['extensions'])
        all_records.extend(records)
    
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
    print("JULIET DATASET PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"Languages: {', '.join(stats['languages'].keys())}")
    print(f"Unique CWEs: {stats['unique_cwes']}")
    print(f"\nTop 10 CWEs:")
    for cwe, count in stats['top_cwes'][:10]:
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

