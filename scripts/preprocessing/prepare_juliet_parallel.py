#!/usr/bin/env python3
"""
JULIET TEST SUITE - ADVANCED PARALLEL PREPROCESSING SCRIPT (FIXED)
===================================================================

Processes the NIST Juliet Test Suite vulnerability benchmark dataset across
C, C++, Java, and C# languages with parallel processing and comprehensive
function extraction.

Dataset Structure:
- 185,323 source files across 4 languages
- 118 different CWE vulnerability types
- Each file contains bad() (vulnerable) and good() (safe) functions

FIXES APPLIED:
- ✅ Robust brace matching algorithm (handles nested braces, strings, comments)
- ✅ Language-specific function extraction
- ✅ Proper handling of C vs C++ files
- ✅ Better error logging and debugging
- ✅ Expected output: ~370,646 records (2 per file)

Features:
- ✅ Multi-language support (C, C++, Java, C#)
- ✅ Parallel processing with multiprocessing
- ✅ Robust function extraction via brace matching
- ✅ @description metadata parsing
- ✅ CWE extraction from paths/filenames
- ✅ Comprehensive statistics generation
- ✅ Progress tracking with TQDM
- ✅ Error handling and logging

Output:
- raw_cleaned.jsonl: All extracted records
- stats.json: Comprehensive statistics

Author: CodeGuardian Team
Date: 2025 (Fixed Version)

Usage:
    python prepare_juliet_parallel.py                      # Process all languages
    python prepare_juliet_parallel.py --workers 8          # Use 8 CPU cores
    python prepare_juliet_parallel.py --max-files 1000     # Test with 1000 files
    python prepare_juliet_parallel.py --languages c java   # Process only C and Java
"""

import sys
import json
import re
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count
from functools import partial
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import write_jsonl, write_json, ensure_dir, safe_read_text
from scripts.utils.text_cleaner import sanitize_code
from scripts.utils.schema_utils import normalize_language, normalize_cwe_id
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================
# REGEX PATTERNS FOR METADATA EXTRACTION
# ============================================================

# CWE extraction patterns
CWE_FOLDER_PATTERN = re.compile(r'CWE(\d+)_(.+)')
CWE_FILENAME_PATTERN = re.compile(r'CWE(\d+)_')

# Description parsing pattern
DESCRIPTION_PATTERN = re.compile(
    r'/\*\s*\*\s*@description(.*?)\*/',
    re.MULTILINE | re.DOTALL
)


# ============================================================
# IMPROVED FUNCTION EXTRACTION WITH BRACE MATCHING
# ============================================================

def find_matching_brace(content: str, start_pos: int) -> int:
    """
    Find the position of the matching closing brace.
    
    Args:
        content: The source code string
        start_pos: Position of the opening brace
        
    Returns:
        Position of the matching closing brace, or -1 if not found
    """
    brace_count = 1
    pos = start_pos + 1
    in_string = False
    in_char = False
    in_comment = False
    in_block_comment = False
    
    while pos < len(content) and brace_count > 0:
        # Handle string literals
        if content[pos] == '"' and not in_char and not in_comment and not in_block_comment:
            if pos == 0 or content[pos-1] != '\\':
                in_string = not in_string
        
        # Handle char literals
        elif content[pos] == "'" and not in_string and not in_comment and not in_block_comment:
            if pos == 0 or content[pos-1] != '\\':
                in_char = not in_char
        
        # Handle single-line comments
        elif content[pos:pos+2] == '//' and not in_string and not in_char and not in_block_comment:
            in_comment = True
        elif content[pos] == '\n' and in_comment:
            in_comment = False
        
        # Handle block comments
        elif content[pos:pos+2] == '/*' and not in_string and not in_char and not in_comment:
            in_block_comment = True
            pos += 1
        elif content[pos:pos+2] == '*/' and in_block_comment:
            in_block_comment = False
            pos += 1
        
        # Count braces only if not in string/char/comment
        elif not in_string and not in_char and not in_comment and not in_block_comment:
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
        
        pos += 1
    
    return pos - 1 if brace_count == 0 else -1


def extract_function_with_name(content: str, func_name: str, language: str) -> Optional[str]:
    """
    Extract a function by name using robust brace matching.
    
    Args:
        content: Source code content
        func_name: Name of function to extract (e.g., 'bad', 'good', 'Bad', 'Good')
        language: Programming language
        
    Returns:
        Full function code, or None if not found
    """
    # Build regex pattern based on language
    if language in ('C', 'C++'):
        # Match: [static] [inline] return_type func_name ( params ) {
        pattern = rf'(?:static\s+)?(?:inline\s+)?(?:\w+\s+)+{func_name}\s*\([^)]*\)\s*\{{'
    elif language == 'Java':
        # Match: [public/private/protected] [static] return_type func_name ( params ) [throws ...] {
        pattern = rf'(?:public|private|protected)?\s*(?:static\s+)?(?:\w+\s+)+{func_name}\s*\([^)]*\)(?:\s+throws[^{{]*)?{{'
    elif language == 'C#':
        # Match: [public/private/protected] [override] [static] return_type func_name ( params ) {
        pattern = rf'(?:public|private|protected)?\s*(?:override\s+)?(?:static\s+)?(?:\w+\s+)+{func_name}\s*\([^)]*\)\s*{{'
    else:
        return None
    
    # Find the function signature
    match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
    if not match:
        return None
    
    # Find the opening brace position
    sig_end = match.end() - 1  # Position of '{'
    
    # Find matching closing brace
    close_brace = find_matching_brace(content, sig_end)
    if close_brace == -1:
        return None
    
    # Extract full function including signature and body
    func_code = content[match.start():close_brace + 1]
    return func_code


def extract_functions_robust(content: str, language: str) -> List[Tuple[str, int, str]]:
    """
    Extract bad() and good() functions using robust brace matching.
    
    Args:
        content: Source file content
        language: Programming language (C, C++, Java, C#)
        
    Returns:
        List of (function_code, label, function_name) tuples
    """
    functions = []
    
    # Define function names to search for based on language
    if language == 'C#':
        bad_names = ['Bad']
        good_names = ['Good']
    else:
        bad_names = ['bad']
        good_names = ['good']
    
    # Extract bad functions (vulnerable)
    for bad_name in bad_names:
        func_code = extract_function_with_name(content, bad_name, language)
        if func_code:
            functions.append((func_code, 1, bad_name))
    
    # Extract good functions (safe)
    for good_name in good_names:
        func_code = extract_function_with_name(content, good_name, language)
        if func_code:
            functions.append((func_code, 0, good_name))
    
    return functions


# ============================================================
# METADATA EXTRACTION FUNCTIONS
# ============================================================

def extract_cwe_from_path(file_path: Path) -> Tuple[str, str]:
    """
    Extract CWE ID and name from file path.
    
    Args:
        file_path: Path to source file
        
    Returns:
        Tuple of (cwe_id, cwe_name)
    """
    # Try folder name first
    for part in file_path.parts:
        match = CWE_FOLDER_PATTERN.match(part)
        if match:
            cwe_id = f"CWE-{match.group(1)}"
            cwe_name = match.group(2).replace('_', ' ')
            return cwe_id, cwe_name
    
    # Fallback to filename
    match = CWE_FILENAME_PATTERN.search(file_path.name)
    if match:
        cwe_id = f"CWE-{match.group(1)}"
        return cwe_id, "Unknown"
    
    return "CWE-Unknown", "Unknown"


def extract_variant_from_filename(filename: str) -> str:
    """
    Extract variant information from filename.
    
    Example:
        CWE23_Relative_Path_Traversal__char_environment_ofstream_03.cpp
        Returns: "char_environment_ofstream"
    """
    # Remove extension
    name = filename.rsplit('.', 1)[0]
    
    # Pattern: CWE{ID}_{Name}__{Variant}_{Version}
    parts = name.split('__')
    if len(parts) >= 2:
        variant = parts[1].rsplit('_', 1)[0]  # Remove version number
        return variant
    
    return "unknown"


def parse_description(content: str) -> Dict[str, str]:
    """
    Parse the @description comment block for metadata.
    
    Returns:
        Dict with keys: bad_source, good_source, sink, bad_sink, flow_variant
    """
    match = DESCRIPTION_PATTERN.search(content)
    if not match:
        return {}
    
    desc_text = match.group(1)
    metadata = {}
    
    # Extract fields
    patterns = {
        'bad_source': r'BadSource:\s*(.+?)(?:\n|\*)',
        'good_source': r'GoodSource:\s*(.+?)(?:\n|\*)',
        'sink': r'Sink:\s*(\w+)',
        'bad_sink': r'BadSink\s*:\s*(.+?)(?:\n|\*)',
        'flow_variant': r'Flow Variant:\s*(.+?)(?:\n|\*)',
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, desc_text)
        if match:
            metadata[key] = match.group(1).strip()
    
    return metadata


# ============================================================
# FUNCTION EXTRACTION (USES ROBUST BRACE MATCHING)
# ============================================================

def extract_functions(content: str, language: str) -> List[Tuple[str, int, str]]:
    """
    Extract functions based on language using robust brace matching.
    
    Args:
        content: Source file content
        language: Programming language (C, C++, Java, C#)
        
    Returns:
        List of (function_code, label, function_name) tuples
    """
    return extract_functions_robust(content, language)


# ============================================================
# FILE PROCESSING (SINGLE FILE)
# ============================================================

def process_single_file(file_info: Tuple[Path, Path, str]) -> List[Dict[str, Any]]:
    """
    Process a single source file and extract all records.
    
    Args:
        file_info: Tuple of (file_path, base_path, language)
        
    Returns:
        List of unified records extracted from the file
    """
    file_path, base_path, language = file_info
    records = []
    
    try:
        # Read file content
        content = safe_read_text(file_path)
        if not content:
            return []
        
        # Extract metadata
        cwe_id, cwe_name = extract_cwe_from_path(file_path)
        variant = extract_variant_from_filename(file_path.name)
        description_meta = parse_description(content)
        
        # Get relative path for tracking
        try:
            rel_path = str(file_path.relative_to(base_path))
        except ValueError:
            rel_path = str(file_path)
        
        # Extract functions
        functions = extract_functions(content, language)
        
        if not functions:
            logger.debug(f"No functions extracted from {file_path.name}")
            return []
        
        # Create records for each function
        for func_code, label, func_name in functions:
            # Sanitize code
            clean_code = sanitize_code(func_code)
            
            if not clean_code or len(clean_code) < 10:
                continue
            
            # Build unified record
            record = {
                'code': clean_code,
                'label': label,
                'language': language,
                'cwe_id': cwe_id,
                'cwe_name': cwe_name,
                'variant': variant,
                'function_name': func_name,
                'filename': file_path.name,
                'file_path': rel_path,
                'dataset': 'juliet',
            }
            
            # Add description metadata if available
            if description_meta:
                if label == 1:  # Vulnerable
                    if 'bad_source' in description_meta:
                        record['bad_source'] = description_meta['bad_source']
                    if 'bad_sink' in description_meta:
                        record['bad_sink'] = description_meta['bad_sink']
                else:  # Safe
                    if 'good_source' in description_meta:
                        record['good_source'] = description_meta['good_source']
                
                if 'sink' in description_meta:
                    record['sink'] = description_meta['sink']
                if 'flow_variant' in description_meta:
                    record['flow_variant'] = description_meta['flow_variant']
            
            records.append(record)
        
    except Exception as e:
        logger.error(f"Error processing {file_path}: {e}")
        return []
    
    return records


# ============================================================
# BATCH PROCESSING WITH MULTIPROCESSING
# ============================================================

def collect_files(base_path: Path, language: str, extensions: List[str]) -> List[Tuple[Path, Path, str]]:
    """
    Collect all source files for a specific language.
    
    Args:
        base_path: Base directory for the language (e.g., juliet/raw/c)
        language: Language name (C, C++, Java, C#)
        extensions: List of file extensions to match
        
    Returns:
        List of (file_path, base_path, language) tuples
    """
    testcases_dir = base_path / ('src/testcases' if language in ('Java', 'C#') else 'testcases')
    
    if not testcases_dir.exists():
        logger.warning(f"Testcases directory not found: {testcases_dir}")
        return []
    
    files = []
    for ext in extensions:
        pattern = f"**/*{ext}"
        matched_files = list(testcases_dir.glob(pattern))
        files.extend([(f, base_path, language) for f in matched_files])
    
    logger.info(f"Found {len(files)} {language} files")
    return files


def process_batch_parallel(
    file_infos: List[Tuple[Path, Path, str]],
    workers: int = None
) -> List[Dict[str, Any]]:
    """
    Process multiple files in parallel using multiprocessing.
    
    Args:
        file_infos: List of (file_path, base_path, language) tuples
        workers: Number of worker processes (defaults to CPU count)
        
    Returns:
        List of all extracted records
    """
    if workers is None:
        workers = max(1, cpu_count() - 1)
    
    logger.info(f"Processing {len(file_infos)} files with {workers} workers")
    
    all_records = []
    
    # Process in parallel
    with Pool(processes=workers) as pool:
        # Use imap for progress tracking
        results = list(tqdm(
            pool.imap(process_single_file, file_infos, chunksize=100),
            total=len(file_infos),
            desc="Processing files",
            unit="file"
        ))
    
    # Flatten results
    for file_records in results:
        all_records.extend(file_records)
    
    return all_records


# ============================================================
# STATISTICS GENERATION
# ============================================================

def generate_statistics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate comprehensive statistics from processed records.
    
    Args:
        records: List of all processed records
        
    Returns:
        Dictionary with statistics
    """
    stats = {
        'total_records': len(records),
        'vulnerable_records': sum(1 for r in records if r['label'] == 1),
        'safe_records': sum(1 for r in records if r['label'] == 0),
    }
    
    if stats['total_records'] > 0:
        stats['vulnerability_ratio'] = stats['vulnerable_records'] / stats['total_records']
    else:
        stats['vulnerability_ratio'] = 0.0
    
    # Language distribution
    language_counter = Counter(r['language'] for r in records)
    stats['languages'] = dict(language_counter)
    
    # CWE distribution
    cwe_counter = Counter(r['cwe_id'] for r in records)
    stats['unique_cwes'] = len(cwe_counter)
    stats['cwe_distribution'] = dict(cwe_counter.most_common(20))
    
    # Variant distribution
    variant_counter = Counter(r.get('variant', 'unknown') for r in records)
    stats['unique_variants'] = len(variant_counter)
    stats['top_variants'] = dict(variant_counter.most_common(10))
    
    # Function name distribution
    func_counter = Counter(r['function_name'] for r in records)
    stats['function_distribution'] = dict(func_counter)
    
    # Per-language CWE distribution
    per_lang_cwe = defaultdict(lambda: Counter())
    for r in records:
        per_lang_cwe[r['language']][r['cwe_id']] += 1
    stats['per_language_cwe'] = {lang: dict(cwe_dist) for lang, cwe_dist in per_lang_cwe.items()}
    
    return stats


# ============================================================
# MAIN PROCESSING PIPELINE
# ============================================================

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Preprocess Juliet Test Suite with parallel processing"
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=None,
        help='Number of worker processes (default: CPU count - 1)'
    )
    parser.add_argument(
        '--max-files',
        type=int,
        default=None,
        help='Maximum number of files to process (for testing)'
    )
    parser.add_argument(
        '--languages',
        nargs='+',
        choices=['c', 'cpp', 'java', 'csharp', 'all'],
        default=['all'],
        help='Languages to process (default: all)'
    )
    
    args = parser.parse_args()
    
    # Print environment info
    print_environment_info()
    
    # Get paths (fixed for Kaggle compatibility)
    input_base = get_dataset_path('juliet/raw')
    output_base = get_output_path('juliet/processed')
    ensure_dir(output_base)
    
    logger.info(f"Input directory: {input_base}")
    logger.info(f"Output directory: {output_base}")
    
    # Determine which languages to process
    process_langs = args.languages
    if 'all' in process_langs:
        process_langs = ['c', 'cpp', 'java', 'csharp']
    
    # Language configurations
    lang_configs = {
        'c': {'dir': 'c', 'name': 'C', 'extensions': ['.c']},
        'cpp': {'dir': 'c', 'name': 'C++', 'extensions': ['.cpp']},
        'java': {'dir': 'java', 'name': 'Java', 'extensions': ['.java']},
        'csharp': {'dir': 'csharp', 'name': 'C#', 'extensions': ['.cs']},
    }
    
    # Collect all files
    all_file_infos = []
    for lang_key in process_langs:
        config = lang_configs[lang_key]
        lang_path = input_base / config['dir']
        
        if not lang_path.exists():
            logger.warning(f"Language directory not found: {lang_path}")
            continue
        
        files = collect_files(lang_path, config['name'], config['extensions'])
        all_file_infos.extend(files)
    
    logger.info(f"Total files collected: {len(all_file_infos)}")
    
    # Limit files if specified
    if args.max_files:
        all_file_infos = all_file_infos[:args.max_files]
        logger.info(f"Limited to {args.max_files} files for testing")
    
    # Process files in parallel
    logger.info("Starting parallel processing...")
    all_records = process_batch_parallel(all_file_infos, workers=args.workers)
    
    logger.info(f"Extracted {len(all_records)} records from {len(all_file_infos)} files")
    
    # Check if we got expected number of records
    expected_records = len(all_file_infos) * 2  # Each file should produce 2 records
    extraction_rate = len(all_records) / expected_records if expected_records > 0 else 0
    
    if extraction_rate < 0.8:  # Less than 80% of expected
        logger.warning(f"⚠️  Only extracted {len(all_records)} records from {len(all_file_infos)} files")
        logger.warning(f"⚠️  Expected approximately {expected_records} records (~2 per file)")
        logger.warning(f"⚠️  Extraction rate: {extraction_rate:.1%}")
        logger.warning(f"⚠️  This may indicate issues with function extraction")
    else:
        logger.info(f"✅ Extraction rate: {extraction_rate:.1%} ({len(all_records)}/{expected_records})")
    
    # Generate statistics
    logger.info("Generating statistics...")
    stats = generate_statistics(all_records)
    
    # Write outputs
    output_file = output_base / 'raw_cleaned.jsonl'
    stats_file = output_base / 'stats.json'
    
    logger.info(f"Writing {len(all_records)} records to {output_file}")
    write_jsonl(all_records, output_file)
    
    logger.info(f"Writing statistics to {stats_file}")
    write_json(stats, stats_file)
    
    # Print summary
    print("\n" + "=" * 60)
    print("JULIET DATASET PROCESSING COMPLETE (FIXED VERSION)")
    print("=" * 60)
    print(f"Total records: {stats['total_records']:,}")
    print(f"Vulnerable: {stats['vulnerable_records']:,}")
    print(f"Safe: {stats['safe_records']:,}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"\nLanguages: {', '.join(f'{k}: {v:,}' for k, v in stats['languages'].items())}")
    print(f"Unique CWEs: {stats['unique_cwes']}")
    
    # Show extraction rate
    expected = len(all_file_infos) * 2
    actual = stats['total_records']
    extraction_rate = (actual / expected * 100) if expected > 0 else 0
    print(f"\nExtraction Rate: {extraction_rate:.1f}% ({actual:,} / {expected:,} expected)")
    
    if extraction_rate >= 90:
        print("✅ Excellent extraction rate!")
    elif extraction_rate >= 80:
        print("✅ Good extraction rate")
    elif extraction_rate >= 70:
        print("⚠️  Moderate extraction rate - some functions may have been missed")
    else:
        print("❌ Low extraction rate - function extraction needs improvement")
    
    print(f"\nTop 10 CWEs:")
    for cwe, count in list(stats['cwe_distribution'].items())[:10]:
        print(f"  {cwe}: {count:,}")
    print(f"\nOutput saved to: {output_base}")
    print("=" * 60)


if __name__ == '__main__':
    main()
