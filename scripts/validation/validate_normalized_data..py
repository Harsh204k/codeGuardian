#!/usr/bin/env python3
"""
Phase 2.1 Enhanced: Advanced Data Validation Module
====================================================

Production-grade validation with:
- Strict field type enforcement (id:str, label:int, etc.)
- Auto-repair capabilities (trim whitespace, normalize language, fix nulls)
- Detailed validation reports with per-field statistics
- SHA256 duplicate detection with configurable thresholds
- Comprehensive error categorization and tracking
- Per-dataset validation metrics

Outputs:
- datasets/unified/validated.jsonl: Clean, validated records
- datasets/unified/validation_report.json: Comprehensive stats
- datasets/unified/validation_errors.jsonl: Failed records with error details

Author: CodeGuardian Team
Version: 3.1.0 (Enhanced)
"""

import argparse
import logging
import json
import hashlib
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set, Optional
from collections import defaultdict
from datetime import datetime
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import (
    chunked_read_jsonl, chunked_write_jsonl, 
    write_json, ensure_dir, stream_process
)

# Setup logging (will be replaced by loguru later)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ====================================================================
# SCHEMA DEFINITION
# ====================================================================

# Field type definitions (strict enforcement)
FIELD_TYPES = {
    'id': str,
    'language': str,
    'code': str,
    'label': int,
    'source_dataset': str,
    'func_name': (str, type(None)),      # str or null
    'description': (str, type(None)),
    'cwe_id': (str, type(None)),
    'cve_id': (str, type(None)),
    'project': (str, type(None)),
    'file_name': (str, type(None)),
    'commit_id': (str, type(None))
}

# Required fields (must be non-null, non-empty)
REQUIRED_FIELDS = ['id', 'language', 'code', 'label', 'source_dataset']

# Valid labels (binary classification)
VALID_LABELS = {0, 1}

# Valid programming languages (normalized forms)
VALID_LANGUAGES = {
    'c', 'cpp', 'c++', 'java', 'python', 'javascript', 'js',
    'php', 'go', 'ruby', 'rust', 'kotlin', 'swift', 'csharp', 'c#',
    'typescript', 'ts', 'scala'
}

# Language normalization mapping
LANGUAGE_NORMALIZATION = {
    'c': 'c',
    'cpp': 'cpp',
    'c++': 'cpp',
    'csharp': 'csharp',
    'c#': 'csharp',
    'java': 'java',
    'python': 'python',
    'py': 'python',
    'javascript': 'javascript',
    'js': 'javascript',
    'typescript': 'typescript',
    'ts': 'typescript',
    'php': 'php',
    'go': 'go',
    'golang': 'go',
    'ruby': 'ruby',
    'rb': 'ruby',
    'rust': 'rust',
    'rs': 'rust',
    'kotlin': 'kotlin',
    'kt': 'kotlin',
    'swift': 'swift',
    'scala': 'scala'
}

# Regex patterns for CWE/CVE validation
CWE_PATTERN = re.compile(r'^CWE-\d+$', re.IGNORECASE)
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


# ====================================================================
# VALIDATION FUNCTIONS
# ====================================================================

def compute_code_hash(code: str) -> str:
    """Compute SHA-256 hash for duplicate detection."""
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def validate_field_type(
    record: Dict[str, Any],
    field: str,
    expected_type: type
) -> Tuple[bool, Optional[str]]:
    """
    Validate that a field has the correct type.
    
    Args:
        record: Record to validate
        field: Field name
        expected_type: Expected Python type (or tuple of types)
        
    Returns:
        (is_valid, error_message)
    """
    if field not in record:
        return False, f"Field '{field}' is missing"
    
    value = record[field]
    
    # Handle tuple of types (e.g., (str, type(None)))
    if isinstance(expected_type, tuple):
        if not any(isinstance(value, t) for t in expected_type):
            type_names = ' or '.join(t.__name__ for t in expected_type)
            return False, f"Field '{field}' must be {type_names}, got {type(value).__name__}"
    else:
        if not isinstance(value, expected_type):
            return False, f"Field '{field}' must be {expected_type.__name__}, got {type(value).__name__}"
    
    return True, None


def validate_required_field(
    record: Dict[str, Any],
    field: str
) -> Tuple[bool, Optional[str]]:
    """
    Validate that a required field is non-null and non-empty.
    
    Args:
        record: Record to validate
        field: Field name
        
    Returns:
        (is_valid, error_message)
    """
    if field not in record:
        return False, f"Required field '{field}' is missing"
    
    value = record[field]
    
    if value is None:
        return False, f"Required field '{field}' is null"
    
    # For strings, check non-empty
    if isinstance(value, str) and not value.strip():
        return False, f"Required field '{field}' is empty"
    
    return True, None


def validate_label_value(label: Any) -> Tuple[bool, Optional[str]]:
    """Validate label is 0 or 1."""
    if not isinstance(label, int):
        return False, f"Label must be int, got {type(label).__name__}"
    
    if label not in VALID_LABELS:
        return False, f"Label must be 0 or 1, got {label}"
    
    return True, None


def validate_code_quality(
    code: str,
    min_length: int = 10
) -> Tuple[bool, Optional[str]]:
    """Validate code meets quality standards."""
    if not isinstance(code, str):
        return False, "Code must be a string"
    
    if len(code.strip()) < min_length:
        return False, f"Code too short ({len(code.strip())} chars, min {min_length})"
    
    return True, None


def validate_language_value(language: str) -> Tuple[bool, Optional[str]]:
    """Validate language is in valid set."""
    if not isinstance(language, str):
        return False, "Language must be a string"
    
    normalized = language.lower().strip()
    if normalized not in VALID_LANGUAGES:
        return False, f"Invalid language: '{language}'"
    
    return True, None


def validate_cwe_format(cwe_id: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Validate CWE format (CWE-###)."""
    if cwe_id is None:
        return True, None  # Optional field
    
    if not isinstance(cwe_id, str):
        return False, "CWE ID must be a string"
    
    if not CWE_PATTERN.match(cwe_id):
        return False, f"Invalid CWE format: '{cwe_id}' (expected CWE-###)"
    
    return True, None


def validate_cve_format(cve_id: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Validate CVE format (CVE-YYYY-#####)."""
    if cve_id is None:
        return True, None  # Optional field
    
    if not isinstance(cve_id, str):
        return False, "CVE ID must be a string"
    
    if not CVE_PATTERN.match(cve_id):
        return False, f"Invalid CVE format: '{cve_id}' (expected CVE-YYYY-#####)"
    
    return True, None


# ====================================================================
# AUTO-REPAIR FUNCTIONS
# ====================================================================

def auto_repair_record(
    record: Dict[str, Any],
    config: Dict[str, bool]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Attempt to auto-repair common data quality issues.
    
    Args:
        record: Record to repair
        config: Repair configuration (trim_whitespace, normalize_language, etc.)
        
    Returns:
        (repaired_record, list_of_repairs_applied)
    """
    repaired = record.copy()
    repairs = []
    
    # Trim whitespace from all string fields
    if config.get('trim_whitespace', True):
        for field in ['id', 'language', 'code', 'func_name', 'description', 'project', 'file_name', 'commit_id']:
            if field in repaired and isinstance(repaired[field], str):
                original = repaired[field]
                trimmed = original.strip()
                if original != trimmed:
                    repaired[field] = trimmed
                    repairs.append(f"Trimmed whitespace from '{field}'")
    
    # Normalize language
    if config.get('normalize_language', True):
        if 'language' in repaired and isinstance(repaired['language'], str):
            original = repaired['language']
            normalized = LANGUAGE_NORMALIZATION.get(original.lower().strip(), original)
            if normalized != original:
                repaired['language'] = normalized
                repairs.append(f"Normalized language: '{original}' → '{normalized}'")
    
    # Fix null strings ("null", "None", "NULL" → actual None)
    if config.get('fix_null_strings', True):
        null_strings = {'null', 'none', 'n/a', 'na', 'undefined'}
        for field in ['func_name', 'description', 'cwe_id', 'cve_id', 'project', 'file_name', 'commit_id']:
            if field in repaired and isinstance(repaired[field], str):
                if repaired[field].lower().strip() in null_strings:
                    repaired[field] = None
                    repairs.append(f"Converted '{field}' null string to actual null")
    
    # Fix label type (string "0"/"1" → int)
    if 'label' in repaired and isinstance(repaired['label'], str):
        try:
            label_int = int(repaired['label'])
            if label_int in VALID_LABELS:
                repaired['label'] = label_int
                repairs.append(f"Converted label from string to int")
        except ValueError:
            pass
    
    # Normalize CWE/CVE to uppercase
    for field in ['cwe_id', 'cve_id']:
        if field in repaired and isinstance(repaired[field], str):
            original = repaired[field]
            upper = original.upper().strip()
            if upper != original:
                repaired[field] = upper
                repairs.append(f"Normalized '{field}' to uppercase")
    
    return repaired, repairs


# ====================================================================
# COMPREHENSIVE VALIDATION
# ====================================================================

def validate_record_comprehensive(
    record: Dict[str, Any],
    min_code_length: int = 10,
    auto_repair: bool = True
) -> Tuple[bool, Dict[str, Any], List[str], List[str]]:
    """
    Comprehensive validation with optional auto-repair.
    
    Args:
        record: Record to validate
        min_code_length: Minimum code length threshold
        auto_repair: Whether to attempt auto-repair
        
    Returns:
        (is_valid, repaired_record, errors, repairs_applied)
    """
    errors = []
    repairs = []
    
    # Auto-repair first if enabled
    if auto_repair:
        record, repairs = auto_repair_record(record, {
            'trim_whitespace': True,
            'normalize_language': True,
            'fix_null_strings': True
        })
    
    # Validate all field types
    for field, expected_type in FIELD_TYPES.items():
        if field in record:  # Only validate if field exists
            is_valid, error = validate_field_type(record, field, expected_type)
            if not is_valid:
                errors.append(error)
    
    # Validate required fields (non-null, non-empty)
    for field in REQUIRED_FIELDS:
        is_valid, error = validate_required_field(record, field)
        if not is_valid:
            errors.append(error)
    
    # Validate label
    if 'label' in record:
        is_valid, error = validate_label_value(record['label'])
        if not is_valid:
            errors.append(error)
    
    # Validate code quality
    if 'code' in record:
        is_valid, error = validate_code_quality(record['code'], min_code_length)
        if not is_valid:
            errors.append(error)
    
    # Validate language
    if 'language' in record:
        is_valid, error = validate_language_value(record['language'])
        if not is_valid:
            errors.append(error)
    
    # Validate CWE/CVE formats
    if 'cwe_id' in record:
        is_valid, error = validate_cwe_format(record.get('cwe_id'))
        if not is_valid:
            errors.append(error)
    
    if 'cve_id' in record:
        is_valid, error = validate_cve_format(record.get('cve_id'))
        if not is_valid:
            errors.append(error)
    
    is_valid = len(errors) == 0
    return is_valid, record, errors, repairs


# ====================================================================
# DATASET VALIDATION
# ====================================================================

def validate_dataset_enhanced(
    input_path: str,
    output_path: str,
    report_path: str,
    errors_path: str,
    min_code_length: int = 10,
    auto_repair: bool = True,
    remove_duplicates: bool = True,
    chunk_size: int = 10000
) -> Dict[str, Any]:
    """
    Enhanced dataset validation with chunked processing.
    
    Args:
        input_path: Input JSONL file
        output_path: Output validated JSONL file
        report_path: Validation report JSON
        errors_path: Output JSONL for failed records
        min_code_length: Minimum code length
        auto_repair: Enable auto-repair
        remove_duplicates: Remove duplicate code
        chunk_size: Chunk size for processing
        
    Returns:
        Validation report dictionary
    """
    logger.info("="*80)
    logger.info("PHASE 2.1 ENHANCED: ADVANCED DATA VALIDATION")
    logger.info("="*80)
    logger.info(f"Input:        {input_path}")
    logger.info(f"Output:       {output_path}")
    logger.info(f"Report:       {report_path}")
    logger.info(f"Errors:       {errors_path}")
    logger.info(f"Auto-repair:  {auto_repair}")
    logger.info(f"Duplicates:   {'Remove' if remove_duplicates else 'Keep'}")
    logger.info(f"Chunk size:   {chunk_size:,}")
    logger.info("="*80)
    
    # Ensure output directories exist
    ensure_dir(Path(output_path).parent)
    ensure_dir(Path(errors_path).parent)
    
    # Initialize tracking
    seen_hashes: Set[str] = set()
    stats = {
        'start_time': datetime.now().isoformat(),
        'total_records': 0,
        'valid_records': 0,
        'invalid_records': 0,
        'repaired_records': 0,
        'duplicates_removed': 0,
        'error_counts': defaultdict(int),
        'errors_by_dataset': defaultdict(lambda: defaultdict(int)),
        'field_stats': defaultdict(lambda: {
            'total': 0,
            'null': 0,
            'empty': 0,
            'invalid_type': 0
        }),
        'repairs_applied': defaultdict(int),
        'sample_errors': [],
        'sample_repairs': []
    }
    
    valid_chunks = []
    error_chunks = []
    
    # Process in chunks
    logger.info("Processing chunks...")
    for chunk_idx, chunk in enumerate(chunked_read_jsonl(input_path, chunk_size=chunk_size)):
        valid_chunk = []
        error_chunk = []
        
        for record in chunk:
            stats['total_records'] += 1
            record_id = record.get('id', f'record_{stats["total_records"]}')
            dataset = record.get('source_dataset', 'unknown')
            
            # Comprehensive validation
            is_valid, repaired_record, errors, repairs = validate_record_comprehensive(
                record, min_code_length, auto_repair
            )
            
            # Track field statistics
            for field in FIELD_TYPES.keys():
                stats['field_stats'][field]['total'] += 1
                if field not in record:
                    stats['field_stats'][field]['null'] += 1
                elif record[field] is None:
                    stats['field_stats'][field]['null'] += 1
                elif isinstance(record[field], str) and not record[field].strip():
                    stats['field_stats'][field]['empty'] += 1
            
            # Track repairs
            if repairs:
                stats['repaired_records'] += 1
                for repair in repairs:
                    stats['repairs_applied'][repair] += 1
                
                # Sample repairs (first 10)
                if len(stats['sample_repairs']) < 10:
                    stats['sample_repairs'].append({
                        'record_id': record_id,
                        'dataset': dataset,
                        'repairs': repairs
                    })
            
            if not is_valid:
                stats['invalid_records'] += 1
                
                # Track error counts
                for error in errors:
                    stats['error_counts'][error] += 1
                    stats['errors_by_dataset'][dataset][error] += 1
                
                # Sample errors (first 20)
                if len(stats['sample_errors']) < 20:
                    stats['sample_errors'].append({
                        'record_id': record_id,
                        'dataset': dataset,
                        'errors': errors
                    })
                
                # Add to error output
                error_chunk.append({
                    **record,
                    '_validation_errors': errors,
                    '_validation_timestamp': datetime.now().isoformat()
                })
                
                continue
            
            # Check for duplicates
            if remove_duplicates:
                code_hash = compute_code_hash(repaired_record.get('code', ''))
                if code_hash in seen_hashes:
                    stats['duplicates_removed'] += 1
                    continue
                seen_hashes.add(code_hash)
            
            stats['valid_records'] += 1
            valid_chunk.append(repaired_record)
        
        # Store chunks
        if valid_chunk:
            valid_chunks.append(valid_chunk)
        if error_chunk:
            error_chunks.append(error_chunk)
        
        # Progress
        if (chunk_idx + 1) % 10 == 0:
            logger.info(f"Processed {stats['total_records']:,} records "
                       f"({stats['valid_records']:,} valid, "
                       f"{stats['invalid_records']:,} invalid)")
    
    # Write validated records
    logger.info(f"Writing {stats['valid_records']:,} validated records...")
    chunked_write_jsonl(output_path, iter(valid_chunks), show_progress=False)
    
    # Write error records
    if error_chunks:
        logger.info(f"Writing {stats['invalid_records']:,} error records...")
        chunked_write_jsonl(errors_path, iter(error_chunks), show_progress=False)
    
    # Finalize stats
    stats['end_time'] = datetime.now().isoformat()
    stats['validation_pass_rate'] = (
        stats['valid_records'] / stats['total_records'] 
        if stats['total_records'] > 0 else 0
    )
    
    # Convert defaultdicts to regular dicts for JSON serialization
    stats['error_counts'] = dict(stats['error_counts'])
    stats['errors_by_dataset'] = {k: dict(v) for k, v in stats['errors_by_dataset'].items()}
    stats['field_stats'] = dict(stats['field_stats'])
    stats['repairs_applied'] = dict(stats['repairs_applied'])
    
    # Write report
    logger.info(f"Writing validation report...")
    write_json(stats, report_path, indent=2)
    
    # Print summary
    logger.info("="*80)
    logger.info("VALIDATION SUMMARY")
    logger.info("="*80)
    logger.info(f"Total records:      {stats['total_records']:,}")
    logger.info(f"Valid records:      {stats['valid_records']:,}")
    logger.info(f"Invalid records:    {stats['invalid_records']:,}")
    logger.info(f"Repaired records:   {stats['repaired_records']:,}")
    logger.info(f"Duplicates removed: {stats['duplicates_removed']:,}")
    logger.info(f"Pass rate:          {stats['validation_pass_rate']*100:.2f}%")
    logger.info("="*80)
    
    if stats['validation_pass_rate'] < 0.98:
        logger.warning("⚠️  Validation pass rate < 98%! Review errors in report.")
    else:
        logger.info("✅ Validation pass rate ≥ 98%")
    
    return stats


# ====================================================================
# CLI ENTRY POINT
# ====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Phase 2.1: Advanced Data Validation"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="datasets/unified/processed_all.jsonl",
        help="Input JSONL file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="datasets/unified/validated.jsonl",
        help="Output validated JSONL file"
    )
    parser.add_argument(
        "--report",
        type=str,
        default="datasets/unified/validation_report.json",
        help="Validation report JSON"
    )
    parser.add_argument(
        "--errors",
        type=str,
        default="datasets/unified/validation_errors.jsonl",
        help="Failed records output"
    )
    parser.add_argument(
        "--min-code-length",
        type=int,
        default=10,
        help="Minimum code length"
    )
    parser.add_argument(
        "--no-auto-repair",
        action="store_true",
        help="Disable auto-repair"
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="Keep duplicate records"
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=10000,
        help="Chunk size for processing"
    )
    
    args = parser.parse_args()
    
    validate_dataset_enhanced(
        input_path=args.input,
        output_path=args.output,
        report_path=args.report,
        errors_path=args.errors,
        min_code_length=args.min_code_length,
        auto_repair=not args.no_auto_repair,
        remove_duplicates=not args.keep_duplicates,
        chunk_size=args.chunk_size
    )


def run(args=None):
    """
    Entry point for orchestrator.
    Calls main() to run validation.
    """
    if args is None:
        main()
    else:
        # Build sys.argv from args if provided
        import sys
        original_argv = sys.argv.copy()
        try:
            sys.argv = ['validate_normalized_data.py']
            if hasattr(args, 'input_file'):
                sys.argv.extend(['--input', args.input_file])
            if hasattr(args, 'output_file'):
                sys.argv.extend(['--output', args.output_file])
            if hasattr(args, 'report_file'):
                sys.argv.extend(['--report', args.report_file])
            if hasattr(args, 'min_code_length'):
                sys.argv.extend(['--min-code-length', str(args.min_code_length)])
            if hasattr(args, 'auto_repair') and not args.auto_repair:
                sys.argv.append('--no-auto-repair')
            if hasattr(args, 'keep_duplicates') and args.keep_duplicates:
                sys.argv.append('--keep-duplicates')
            main()
        finally:
            sys.argv = original_argv


if __name__ == '__main__':
    main()
