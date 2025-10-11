#!/usr/bin/env python3
"""
Utility Functions for MegaVul Preprocessing
============================================

Helper functions for record normalization, schema validation, and logging.

Author: CodeGuardian Team
Date: 2025-10-11
"""

import re
import uuid
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from collections import Counter

logger = logging.getLogger(__name__)

# Import schema utilities from parent directory
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    
    from scripts.utils.schema_utils import (
        normalize_language,
        normalize_cwe_id,
        normalize_cve_id,
        map_to_unified_schema,
        validate_record as schema_validate_record
    )
    from scripts.utils.text_cleaner import sanitize_code, is_valid_code
    SCHEMA_UTILS_AVAILABLE = True
except ImportError:
    SCHEMA_UTILS_AVAILABLE = False
    logger.warning("Schema utils not available - using fallback normalization")


# ============================================================================
# NORMALIZATION FUNCTIONS
# ============================================================================

def normalize_record(
    record: Dict[str, Any],
    dataset_name: str = "megavul",
    index: int = 0,
    include_graphs: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Normalize a MegaVul record to the unified schema with FULL feature parity.
    
    MUST maintain identical processing logic as prepare_megavul.py:
    - Extract ALL MegaVul-specific fields (vul_id, severity, patch, etc.)
    - Support graph representations (AST, PDG, CFG, DFG)
    - Apply same validation and sanitization
    - Preserve all metadata fields
    
    Args:
        record: Raw record from MegaVul dataset
        dataset_name: Source dataset name
        index: Record index for traceability
        include_graphs: Whether to extract graph representations
        
    Returns:
        Normalized record or None if invalid
    """
    try:
        # ============================================================
        # EXTRACT CORE FIELDS (same as prepare_megavul.py)
        # ============================================================
        code = (
            record.get('func') or 
            record.get('code') or 
            record.get('function') or 
            record.get('source_code') or 
            ""
        )
        
        label = record.get('label', record.get('vulnerable', record.get('target', 0)))
        language = record.get('language', record.get('lang', 'C'))
        
        # ============================================================
        # EXTRACT MEGAVUL-SPECIFIC METADATA (same as original)
        # ============================================================
        vul_id = record.get('vul_id', record.get('vulnerability_id', ''))
        commit_id = record.get('commit_id', record.get('commit', ''))
        repo = record.get('repo', record.get('repository', record.get('project', '')))
        cwe_id = record.get('cwe_id', record.get('CWE_ID', record.get('cwe', '')))
        cve_id = record.get('cve_id', record.get('CVE_ID', record.get('cve', '')))
        severity = record.get('severity', record.get('risk', ''))
        description = record.get('description', record.get('desc', record.get('bug_info', '')))
        
        # Extract file and function metadata
        file_name = record.get('file', record.get('filename', record.get('file_path', '')))
        func_name = record.get('func_name', record.get('function_name', record.get('method', '')))
        
        # Extract patch/diff information (CRITICAL - was missing!)
        patch = record.get('patch', record.get('diff', ''))
        fixed_code = record.get('fixed_func', record.get('patched_func', ''))
        
        # ============================================================
        # VALIDATE CODE (same as original)
        # ============================================================
        if not code or len(str(code).strip()) < 10:
            return None
        
        # Sanitize code
        if SCHEMA_UTILS_AVAILABLE:
            code = sanitize_code(str(code), language=language, normalize_ws=True)
            
            # Validate sanitized code
            if not is_valid_code(code, min_length=10):
                return None
        else:
            code = sanitize_code_fallback(str(code), language)
            if not is_valid_code_fallback(code):
                return None
        
        # ============================================================
        # NORMALIZE FIELDS (same as original)
        # ============================================================
        if SCHEMA_UTILS_AVAILABLE:
            language = normalize_language(language)
            cwe_id = normalize_cwe_id(cwe_id)
            cve_id = normalize_cve_id(cve_id)
        else:
            language = normalize_language_fallback(language)
            cwe_id = normalize_cwe_id_fallback(cwe_id)
            cve_id = normalize_cve_id_fallback(cve_id)
        
        # Convert label to int (same logic)
        if isinstance(label, str):
            label = 1 if label.lower() in ['1', 'true', 'yes', 'vulnerable'] else 0
        else:
            label = int(label) if label else 0
        
        # ============================================================
        # CREATE BASE RECORD (same structure as original)
        # ============================================================
        processed_record = {
            "code": code,
            "label": label,
            "language": language,
            "project": repo if repo else None,
            "commit_id": commit_id if commit_id else None,
            "cwe_id": cwe_id,
            "cve_id": cve_id,
            "file_name": file_name if file_name else None,
            "func_name": func_name if func_name else None,
            "description": description if description else None,
            "dataset": dataset_name,
            "source": dataset_name,
            "source_row_index": index,
        }
        
        # ============================================================
        # ADD MEGAVUL-SPECIFIC METADATA (CRITICAL - was missing!)
        # ============================================================
        if vul_id:
            processed_record['vulnerability_id'] = vul_id
        
        if severity:
            processed_record['severity'] = severity.upper() if isinstance(severity, str) else severity
        
        if patch:
            processed_record['patch_available'] = True
            if len(patch) < 10000:  # Store small patches inline
                processed_record['patch'] = patch
        
        if fixed_code and len(fixed_code) > 10:
            processed_record['has_fix'] = True
        
        # ============================================================
        # EXTRACT GRAPH REPRESENTATIONS (CRITICAL - was missing!)
        # ============================================================
        if include_graphs:
            if 'ast' in record and record['ast']:
                processed_record['has_ast'] = True
                # Store compact representation
                processed_record['ast_nodes'] = len(record['ast']) if isinstance(record['ast'], (list, dict)) else None
            
            if 'pdg' in record and record['pdg']:
                processed_record['has_pdg'] = True
                processed_record['pdg_nodes'] = len(record['pdg']) if isinstance(record['pdg'], (list, dict)) else None
            
            if 'cfg' in record and record['cfg']:
                processed_record['has_cfg'] = True
                processed_record['cfg_nodes'] = len(record['cfg']) if isinstance(record['cfg'], (list, dict)) else None
            
            if 'dfg' in record and record['dfg']:
                processed_record['has_dfg'] = True
                processed_record['dfg_nodes'] = len(record['dfg']) if isinstance(record['dfg'], (list, dict)) else None
        
        return processed_record
    
    except Exception as e:
        if index < 10:  # Log first few errors
            logger.error(f"Error normalizing record {index}: {e}")
        return None


# ============================================================================
# FALLBACK NORMALIZATION (when schema_utils unavailable)
# ============================================================================

def normalize_language_fallback(lang: Any) -> str:
    """Fallback language normalization."""
    if not lang or not isinstance(lang, str):
        return "unknown"
    
    lang_map = {
        "c": "C", "cpp": "C++", "c++": "C++",
        "java": "Java", "python": "Python",
        "javascript": "JavaScript", "js": "JavaScript"
    }
    
    return lang_map.get(lang.strip().lower(), lang.strip())


def normalize_cwe_id_fallback(cwe: Any) -> Optional[str]:
    """Fallback CWE normalization."""
    if not cwe or str(cwe).lower() in ["none", "null", "n/a", "", "nan"]:
        return None
    
    match = re.search(r'(\d+)', str(cwe))
    if match:
        return f"CWE-{match.group(1)}"
    return None


def normalize_cve_id_fallback(cve: Any) -> Optional[str]:
    """Fallback CVE normalization."""
    if not cve or str(cve).lower() in ["none", "null", "n/a", "", "nan"]:
        return None
    
    match = re.search(r'CVE[-\s]?(\d{4})[-\s]?(\d+)', str(cve), re.IGNORECASE)
    if match:
        return f"CVE-{match.group(1)}-{match.group(2)}"
    return None


def sanitize_code_fallback(code: str, language: str = "C") -> str:
    """Fallback code sanitization."""
    if not code:
        return ""
    
    # Remove null bytes
    code = code.replace('\x00', '')
    
    # Normalize line endings
    code = code.replace('\r\n', '\n').replace('\r', '\n')
    
    # Remove excessive whitespace
    lines = [line.rstrip() for line in code.split('\n')]
    code = '\n'.join(lines)
    
    return code.strip()


def is_valid_code_fallback(code: str, min_length: int = 10) -> bool:
    """Fallback code validation."""
    if not code or len(code) < min_length:
        return False
    
    # Check for minimum non-whitespace characters
    non_ws = len(code.replace(' ', '').replace('\n', '').replace('\t', ''))
    return non_ws >= min_length


# ============================================================================
# HASH AND UUID FUNCTIONS
# ============================================================================

def generate_uuid() -> str:
    """Generate UUID v4 for record identification."""
    return str(uuid.uuid4())


def compute_code_hash(code: str) -> str:
    """
    Compute SHA-256 hash of normalized code for deduplication.
    
    Args:
        code: Source code string
        
    Returns:
        Hexadecimal hash string
    """
    # Normalize code
    normalized = re.sub(r'\s+', '', code.lower())
    normalized = re.sub(r'//.*|/\*.*?\*/', '', normalized)
    
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()


def hash_file(file_path: str) -> str:
    """
    Compute SHA-256 hash of a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        Hexadecimal hash string
    """
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    
    return sha256.hexdigest()


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_record(record: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Validate a normalized record against schema.
    
    Args:
        record: Normalized record
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    if SCHEMA_UTILS_AVAILABLE:
        return schema_validate_record(record)
    
    # Fallback validation
    errors = []
    
    required_fields = ['id', 'code', 'is_vulnerable', 'language', 'dataset']
    
    for field in required_fields:
        if field not in record or not record[field]:
            errors.append(f"Missing required field: {field}")
    
    # Validate types
    if record.get('is_vulnerable') not in [0, 1]:
        errors.append(f"Invalid is_vulnerable value: {record.get('is_vulnerable')}")
    
    if len(str(record.get('code', ''))) < 10:
        errors.append("Code too short")
    
    return (len(errors) == 0, errors)


def validate_schema_consistency(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate schema consistency across a batch of records.
    
    Args:
        records: List of normalized records
        
    Returns:
        Validation report
    """
    if not records:
        return {"status": "empty", "valid_records": 0}
    
    valid_count = 0
    invalid_count = 0
    errors_summary = {}
    
    for idx, record in enumerate(records):
        is_valid, errors = validate_record(record)
        
        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1
            
            for error in errors:
                errors_summary[error] = errors_summary.get(error, 0) + 1
    
    return {
        "status": "valid" if invalid_count == 0 else "partial",
        "total_records": len(records),
        "valid_records": valid_count,
        "invalid_records": invalid_count,
        "validation_rate": valid_count / len(records) if records else 0,
        "errors": errors_summary
    }


# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def log_event(
    event_type: str,
    message: str,
    details: Optional[Dict[str, Any]] = None,
    log_file: Optional[str] = None
):
    """
    Log an event with structured format.
    
    Args:
        event_type: Type of event (INFO, WARNING, ERROR, etc.)
        message: Event message
        details: Additional structured details
        log_file: Optional file to append log
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    log_entry = {
        "timestamp": timestamp,
        "type": event_type,
        "message": message
    }
    
    if details:
        log_entry["details"] = details
    
    # Log to logger
    if event_type == "ERROR":
        logger.error(message)
    elif event_type == "WARNING":
        logger.warning(message)
    else:
        logger.info(message)
    
    # Optionally append to file
    if log_file:
        import json
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')


def create_processing_summary(
    total_records: int,
    valid_records: int,
    processing_time: float,
    chunk_count: int,
    additional_stats: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Create a processing summary report.
    
    Args:
        total_records: Total records processed
        valid_records: Valid records after normalization
        processing_time: Time in seconds
        chunk_count: Number of chunks created
        additional_stats: Additional statistics
        
    Returns:
        Summary dictionary
    """
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": "megavul",
        "total_records": total_records,
        "valid_records": valid_records,
        "invalid_records": total_records - valid_records,
        "success_rate": valid_records / total_records if total_records > 0 else 0,
        "processing_time_seconds": processing_time,
        "records_per_second": total_records / processing_time if processing_time > 0 else 0,
        "chunk_count": chunk_count,
        "avg_records_per_chunk": valid_records / chunk_count if chunk_count > 0 else 0
    }
    
    if additional_stats:
        summary.update(additional_stats)
    
    return summary


# ============================================================================
# DEDUPLICATION
# ============================================================================

def deduplicate_by_code_hash(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate records by code hash.
    
    Args:
        records: List of records
        
    Returns:
        Deduplicated list
    """
    seen_hashes = set()
    deduplicated = []
    
    for record in records:
        code = record.get('code', '')
        code_hash = compute_code_hash(code)
        
        if code_hash not in seen_hashes:
            seen_hashes.add(code_hash)
            deduplicated.append(record)
    
    removed = len(records) - len(deduplicated)
    if removed > 0:
        logger.info(f"Removed {removed:,} duplicate records")
    
    return deduplicated


# ============================================================================
# COMPREHENSIVE STATISTICS (same as prepare_megavul.py)
# ============================================================================

def generate_megavul_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate comprehensive statistics for the processed MegaVul dataset.
    
    MUST match the statistics generation in prepare_megavul.py to ensure
    feature parity regardless of chunking logic.
    
    Args:
        records: List of processed records
        
    Returns:
        Statistics dictionary with same structure as original
    """
    total = len(records)
    vulnerable = sum(1 for r in records if r.get('label') == 1)
    non_vulnerable = total - vulnerable
    
    # Language distribution
    languages = {}
    for record in records:
        lang = record.get('language', 'unknown')
        if lang not in languages:
            languages[lang] = {'total': 0, 'vulnerable': 0}
        languages[lang]['total'] += 1
        if record.get('label') == 1:
            languages[lang]['vulnerable'] += 1
    
    # CWE distribution
    cwes = {}
    for record in records:
        cwe = record.get('cwe_id')
        if cwe:
            cwes[cwe] = cwes.get(cwe, 0) + 1
    
    # CVE count
    cve_count = sum(1 for r in records if r.get('cve_id'))
    
    # Severity distribution (MegaVul-specific)
    severities = Counter(r.get('severity') for r in records if r.get('severity'))
    
    # Project/Repository distribution
    projects = Counter(r.get('project') for r in records if r.get('project'))
    
    # Graph representation availability (MegaVul-specific)
    with_ast = sum(1 for r in records if r.get('has_ast'))
    with_pdg = sum(1 for r in records if r.get('has_pdg'))
    with_cfg = sum(1 for r in records if r.get('has_cfg'))
    with_dfg = sum(1 for r in records if r.get('has_dfg'))
    
    # Patch availability (MegaVul-specific)
    with_patch = sum(1 for r in records if r.get('patch_available'))
    with_fix = sum(1 for r in records if r.get('has_fix'))
    
    # Vulnerability ID tracking (MegaVul-specific)
    with_vul_id = sum(1 for r in records if r.get('vulnerability_id'))
    
    return {
        "dataset": "megavul",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": languages,
        "unique_cwes": len(cwes),
        "top_cwes": sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:20],
        "records_with_cve": cve_count,
        "severity_distribution": dict(severities),
        "unique_projects": len(projects),
        "top_projects": sorted(projects.items(), key=lambda x: x[1], reverse=True)[:10],
        "graph_representations": {
            "ast": with_ast,
            "pdg": with_pdg,
            "cfg": with_cfg,
            "dfg": with_dfg
        },
        "patch_info": {
            "with_patch": with_patch,
            "with_fix": with_fix
        },
        "records_with_vulnerability_id": with_vul_id,
        "avg_code_length": sum(len(r.get('code', '')) for r in records) / total if total > 0 else 0
    }


# ============================================================================
# TESTING
# ============================================================================

def test_utils():
    """Test utility functions."""
    logger.info("=== Testing Normalization ===")
    
    test_record = {
        'func': 'int vulnerable_function(char* input) {\n    strcpy(buffer, input);\n}',
        'label': 1,
        'language': 'c',
        'cwe_id': '119',
        'cve_id': 'CVE-2021-12345',
        'repo': 'test/repo',
        'func_name': 'vulnerable_function'
    }
    
    normalized = normalize_record(test_record, "test", 0)
    logger.info(f"Normalized record: {normalized}")
    
    # Test validation
    is_valid, errors = validate_record(normalized)
    logger.info(f"Valid: {is_valid}, Errors: {errors}")
    
    # Test hashing
    code_hash = compute_code_hash(test_record['func'])
    logger.info(f"Code hash: {code_hash}")
    
    logger.info("\n✅ Utils tests complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    test_utils()
