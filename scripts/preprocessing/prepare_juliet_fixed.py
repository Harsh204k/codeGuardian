#!/usr/bin/env python3
"""
FIXED Preprocessing script for Juliet Test Suite dataset.

KEY IMPROVEMENTS:
1. Extracts individual functions (bad() and good()) instead of whole files
2. Creates separate records for vulnerable and safe code
3. Handles multiple function variants (good1, good2, goodG2B, etc.)
4. Accurate labeling based on function type, not filename

Juliet Structure:
- Each file contains BOTH vulnerable (bad) and safe (good) functions
- Files are organized by CWE type
- Supports C, Java, and C# languages
"""

import argparse
import logging
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import write_jsonl, write_json, ensure_dir, safe_read_text
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import (
    normalize_language, normalize_cwe_id,
    map_to_unified_schema, validate_record
)
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

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
    path_str = str(file_path)
    match = re.search(r'CWE[-_]?(\d+)', path_str, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return None


def extract_function(code: str, function_pattern: str, language: str) -> Optional[str]:
    """
    Extract a specific function from source code.
    
    Args:
        code: Full source code
        function_pattern: Regex pattern to match function
        language: Programming language
        
    Returns:
        Extracted function code or None
    """
    try:
        match = re.search(function_pattern, code, re.DOTALL | re.MULTILINE)
        if match:
            # Return the full function including signature
            return match.group(0)
        return None
    except Exception as e:
        logger.debug(f"Error extracting function: {e}")
        return None


def extract_bad_functions_c(code: str) -> List[Tuple[str, str]]:
    """
    Extract all 'bad' functions from C/C++ code.
    
    Returns:
        List of (function_name, function_code) tuples
    """
    functions = []
    
    # Pattern for bad() functions
    # Matches: void CWE_XXX_bad() { ... }
    pattern = r'(void\s+(\w+_bad(?:\w*)?)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    
    matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
    for match in matches:
        func_code = match.group(1)
        func_name = match.group(2)
        functions.append((func_name, func_code))
    
    return functions


def extract_good_functions_c(code: str) -> List[Tuple[str, str]]:
    """
    Extract all 'good' functions from C/C++ code.
    
    Returns:
        List of (function_name, function_code) tuples
    """
    functions = []
    
    # Pattern for good() and good variants
    # Matches: void CWE_XXX_good() { ... }, static void good1() { ... }
    patterns = [
        r'(void\s+(\w+_good(?:\w*)?)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})',
        r'(static\s+void\s+(good\d+|goodG2B|goodB2G)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
        for match in matches:
            func_code = match.group(1)
            func_name = match.group(2)
            functions.append((func_name, func_code))
    
    return functions


def extract_bad_functions_java(code: str) -> List[Tuple[str, str]]:
    """
    Extract all 'bad' functions from Java code.
    
    Returns:
        List of (function_name, function_code) tuples
    """
    functions = []
    
    # Pattern for bad() method
    # Matches: public void bad() throws Throwable { ... }
    pattern = r'(public\s+void\s+(bad)\s*\([^)]*\)(?:\s+throws\s+[\w,\s]+)?\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    
    matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
    for match in matches:
        func_code = match.group(1)
        func_name = match.group(2)
        functions.append((func_name, func_code))
    
    return functions


def extract_good_functions_java(code: str) -> List[Tuple[str, str]]:
    """
    Extract all 'good' functions from Java code.
    
    Returns:
        List of (function_name, function_code) tuples
    """
    functions = []
    
    # Patterns for good() and variants
    patterns = [
        r'(public\s+void\s+(good)\s*\([^)]*\)(?:\s+throws\s+[\w,\s]+)?\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})',
        r'(private\s+void\s+(good[A-Z0-9]\w*|goodG2B|goodB2G)\s*\([^)]*\)(?:\s+throws\s+[\w,\s]+)?\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
        for match in matches:
            func_code = match.group(1)
            func_name = match.group(2)
            functions.append((func_name, func_code))
    
    return functions


def extract_bad_functions_csharp(code: str) -> List[Tuple[str, str]]:
    """
    Extract all 'bad' functions from C# code.
    
    Returns:
        List of (function_name, function_code) tuples
    """
    functions = []
    
    # Pattern for Bad() method (C# uses uppercase)
    pattern = r'(public\s+(?:static\s+)?void\s+(Bad)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    
    matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
    for match in matches:
        func_code = match.group(1)
        func_name = match.group(2)
        functions.append((func_name, func_code))
    
    # Also try lowercase
    pattern = r'(public\s+(?:static\s+)?void\s+(bad)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    
    matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
    for match in matches:
        func_code = match.group(1)
        func_name = match.group(2)
        functions.append((func_name, func_code))
    
    return functions


def extract_good_functions_csharp(code: str) -> List[Tuple[str, str]]:
    """
    Extract all 'good' functions from C# code.
    
    Returns:
        List of (function_name, function_code) tuples
    """
    functions = []
    
    # Patterns for Good() and variants (C# uses uppercase)
    patterns = [
        r'(public\s+(?:static\s+)?void\s+(Good)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})',
        r'(private\s+(?:static\s+)?void\s+(Good[A-Z0-9]\w*|GoodG2B|GoodB2G)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
        for match in matches:
            func_code = match.group(1)
            func_name = match.group(2)
            functions.append((func_name, func_code))
    
    # Also try lowercase
    patterns = [
        r'(public\s+(?:static\s+)?void\s+(good)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})',
        r'(private\s+(?:static\s+)?void\s+(good[A-Z0-9]\w*|goodG2B|goodB2G)\s*\([^)]*\)\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})'
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, code, re.DOTALL | re.MULTILINE)
        for match in matches:
            func_code = match.group(1)
            func_name = match.group(2)
            functions.append((func_name, func_code))
    
    return functions


def extract_functions_from_file(code: str, language: str) -> Dict[str, List[Tuple[str, str]]]:
    """
    Extract all bad and good functions from source code.
    
    Args:
        code: Full source code
        language: Programming language (c, java, csharp)
        
    Returns:
        Dict with 'bad' and 'good' keys containing lists of (func_name, func_code)
    """
    if language.lower() in ['c', 'cpp']:
        bad_funcs = extract_bad_functions_c(code)
        good_funcs = extract_good_functions_c(code)
    elif language.lower() == 'java':
        bad_funcs = extract_bad_functions_java(code)
        good_funcs = extract_good_functions_java(code)
    elif language.lower() in ['csharp', 'cs']:
        bad_funcs = extract_bad_functions_csharp(code)
        good_funcs = extract_good_functions_csharp(code)
    else:
        bad_funcs = []
        good_funcs = []
    
    return {
        'bad': bad_funcs,
        'good': good_funcs
    }


def process_source_file(file_path: Path, language: str, base_index: int = 0) -> List[Dict[str, Any]]:
    """
    Process a single source file from Juliet and extract MULTIPLE records.
    
    This is the KEY FIX: Instead of creating 1 record per file,
    we extract bad() and good() functions separately.
    
    Args:
        file_path: Path to source file
        language: Programming language
        base_index: Base index for unique ID generation
        
    Returns:
        List of processed records (typically 2+ per file)
    """
    records = []
    
    try:
        # Read source code
        code = safe_read_text(str(file_path))
        if not code:
            return records
        
        # Extract CWE from path
        cwe_id = extract_cwe_from_path(file_path)
        
        # Extract all functions
        functions = extract_functions_from_file(code, language)
        
        record_idx = 0
        
        # Process bad (vulnerable) functions
        for func_name, func_code in functions['bad']:
            # Sanitize code
            clean_code = sanitize_code(func_code, language=language, normalize_ws=True)
            
            # Validate code length
            if not is_valid_code(clean_code, min_length=30):
                continue
            
            # Create intermediate record
            intermediate_record = {
                "code": clean_code,
                "label": 1,  # Vulnerable
                "language": language,
                "project": "juliet",
                "commit_id": None,
                "cwe_id": cwe_id,
                "cve_id": None,
                "file_name": file_path.name,
                "func_name": func_name,
                "description": f"Juliet vulnerable test case ({func_name}) for {cwe_id}" if cwe_id else f"Juliet vulnerable test case ({func_name})"
            }
            
            # Map to unified schema
            unified_record = map_to_unified_schema(
                record=intermediate_record,
                dataset_name="juliet",
                index=base_index + record_idx
            )
            
            # Light validation
            if unified_record.get('code') and unified_record.get('label') is not None:
                records.append(unified_record)
                record_idx += 1
        
        # Process good (safe) functions
        for func_name, func_code in functions['good']:
            # Sanitize code
            clean_code = sanitize_code(func_code, language=language, normalize_ws=True)
            
            # Validate code length
            if not is_valid_code(clean_code, min_length=30):
                continue
            
            # Create intermediate record
            intermediate_record = {
                "code": clean_code,
                "label": 0,  # Safe
                "language": language,
                "project": "juliet",
                "commit_id": None,
                "cwe_id": cwe_id,
                "cve_id": None,
                "file_name": file_path.name,
                "func_name": func_name,
                "description": f"Juliet safe test case ({func_name}) for {cwe_id}" if cwe_id else f"Juliet safe test case ({func_name})"
            }
            
            # Map to unified schema
            unified_record = map_to_unified_schema(
                record=intermediate_record,
                dataset_name="juliet",
                index=base_index + record_idx
            )
            
            # Light validation
            if unified_record.get('code') and unified_record.get('label') is not None:
                records.append(unified_record)
                record_idx += 1
        
    except Exception as e:
        logger.warning(f"Error processing {file_path}: {e}")
    
    return records


def process_language_directory(lang_dir: Path, language: str, file_extensions: List[str], max_records: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Process all testcases for a specific language.
    
    Args:
        lang_dir: Directory containing language testcases
        language: Programming language name
        file_extensions: List of file extensions to process
        max_records: Maximum number of records to extract (for testing)
        
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
        testcases_dir = lang_dir / "src" / "testcases"
    
    if not testcases_dir.exists():
        logger.error(f"Testcases directory not found in {lang_dir}")
        return records
    
    # Collect all source files
    source_files = []
    for ext in file_extensions:
        for file_path in testcases_dir.rglob(f"*{ext}"):
            # Skip support/common files
            if 'support' in str(file_path).lower() or 'common' in str(file_path).lower():
                continue
            source_files.append(file_path)
    
    logger.info(f"Found {len(source_files)} {language} files")
    
    # Process all source files with progress bar
    base_index = 0
    for file_path in tqdm(source_files, desc=f"Processing {language}", unit="file"):
        file_records = process_source_file(file_path, language, base_index)
        records.extend(file_records)
        base_index += len(file_records)
        
        # Stop if max_records reached
        if max_records and len(records) >= max_records:
            logger.info(f"Reached max_records limit ({max_records})")
            records = records[:max_records]
            break
    
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
    parser = argparse.ArgumentParser(description='Preprocess Juliet Test Suite dataset (FIXED VERSION)')
    parser.add_argument(
        '--input-dir',
        type=str,
        default=None,
        help='Input directory containing Juliet testcases (auto-detected if not provided)'
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
        default=['c', 'java', 'csharp'],
        help='Languages to process (c, java, csharp)'
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
        input_dir = get_dataset_path("juliet")
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("juliet/processed")
    
    logger.info(f"[INFO] Processing Juliet dataset from: {input_dir}")
    logger.info(f"[INFO] Output directory: {output_dir}")
    
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
        
        records = process_language_directory(
            lang_dir, 
            lang, 
            config['extensions'],
            max_records=args.max_records
        )
        all_records.extend(records)
        
        # Stop if max_records reached
        if args.max_records and len(all_records) >= args.max_records:
            all_records = all_records[:args.max_records]
            break
    
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
