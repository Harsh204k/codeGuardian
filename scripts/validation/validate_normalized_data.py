#!/usr/bin/env python3
"""
Phase 2.1 Enhanced: Advanced Data Validation Module (Stage III Compatible)
============================================================================

Production-grade validation with Stage III 31-field schema support:
- Strict field type enforcement for all 31 fields (17 base + 14 Stage III)
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
Version: 3.1.0 (Stage III Compatible)
Date: 2025-10-12
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
    chunked_read_jsonl,
    chunked_write_jsonl,
    write_json,
    ensure_dir,
    stream_process,
)
from scripts.utils.kaggle_paths import (
    get_dataset_path,
    get_output_path,
    print_environment_info,
)

# Import schema_utils for Stage III schema definition
try:
    from scripts.utils.schema_utils import UNIFIED_SCHEMA, compute_code_hash

    SCHEMA_UTILS_AVAILABLE = True
except ImportError:
    SCHEMA_UTILS_AVAILABLE = False
    print("⚠️ Warning: schema_utils not available. Using fallback schema.")

# Setup logging (will be replaced by loguru later)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# ====================================================================
# SCHEMA DEFINITION (Stage III - 31 Fields)
# ====================================================================

# Field type definitions (strict enforcement) - Updated for Stage III
FIELD_TYPES = {
    # Core identification (3 fields)
    "id": str,
    "language": str,
    "dataset": str,  # Renamed from source_dataset
    # Code and vulnerability (2 fields)
    "code": str,
    "is_vulnerable": int,  # Renamed from label
    # Vulnerability metadata (3 fields)
    "cwe_id": (str, type(None)),
    "cve_id": (str, type(None)),
    "description": (str, type(None)),
    # CWE-enriched fields (3 fields)
    "attack_type": (str, type(None)),
    "severity": (str, type(None)),
    "review_status": (str, type(None)),
    # Provenance tracking (4 fields)
    "func_name": (str, type(None)),
    "file_name": (str, type(None)),
    "project": (str, type(None)),
    "commit_id": (str, type(None)),
    # Traceability (2 fields)
    "source_file": (str, type(None)),
    "source_row_index": (int, type(None)),
    # Stage III: Granularity fields (4 fields)
    "vuln_line_start": (int, type(None)),
    "vuln_line_end": (int, type(None)),
    "context_before": (str, type(None)),
    "context_after": (str, type(None)),
    # Stage III: Traceability fields (3 fields)
    "repo_url": (str, type(None)),
    "commit_url": (str, type(None)),
    "code_sha256": (str, type(None)),
    # Stage III: Function metadata (4 fields)
    "function_length": (int, type(None)),
    "num_params": (int, type(None)),
    "num_calls": (int, type(None)),
    "imports": (str, type(None)),
    # Stage III: Versioning/Provenance (4 fields)
    "normalized_timestamp": (str, type(None)),
    "language_stage": (str, type(None)),
    "verification_source": (str, type(None)),
    "source_dataset_version": (str, type(None)),
}

# Required fields (must be non-null, non-empty) - Updated for Stage III
REQUIRED_FIELDS = ["id", "language", "dataset", "code", "is_vulnerable"]

# Valid labels (binary classification) - Updated field name
VALID_LABELS = {0, 1}

# Valid programming languages (normalized forms)
VALID_LANGUAGES = {
    "C",
    "C++",
    "Java",
    "JavaScript",
    "Python",
    "TypeScript",
    "PHP",
    "Go",
    "Ruby",
    "Rust",
    "Kotlin",
    "Swift",
    "C#",
    "Scala",
    "Shell",
    "Perl",
    "unknown",  # Allow unknown for graceful degradation
}

# Language normalization mapping (lowercase input -> canonical form)
LANGUAGE_NORMALIZATION = {
    "c": "C",
    "cpp": "C++",
    "c++": "C++",
    "cxx": "C++",
    "cc": "C++",
    "csharp": "C#",
    "c#": "C#",
    "cs": "C#",
    "java": "Java",
    "python": "Python",
    "py": "Python",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "jsx": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "tsx": "TypeScript",
    "php": "PHP",
    "go": "Go",
    "golang": "Go",
    "ruby": "Ruby",
    "rb": "Ruby",
    "rust": "Rust",
    "rs": "Rust",
    "kotlin": "Kotlin",
    "kt": "Kotlin",
    "swift": "Swift",
    "scala": "Scala",
    "shell": "Shell",
    "sh": "Shell",
    "bash": "Shell",
    "perl": "Perl",
    "pl": "Perl",
}

# Regex patterns for CWE/CVE validation
CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ====================================================================
# VALIDATION FUNCTIONS
# ====================================================================

# Use compute_code_hash from schema_utils if available, otherwise define fallback
if not SCHEMA_UTILS_AVAILABLE:

    def compute_code_hash(code: str) -> str:
        """Compute SHA-256 hash for duplicate detection (fallback)."""
        return hashlib.sha256(code.encode("utf-8")).hexdigest()


def validate_field_type(
    record: Dict[str, Any], field: str, expected_type: type
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
            type_names = " or ".join(t.__name__ for t in expected_type)
            return (
                False,
                f"Field '{field}' must be {type_names}, got {type(value).__name__}",
            )
    else:
        if not isinstance(value, expected_type):
            return (
                False,
                f"Field '{field}' must be {expected_type.__name__}, got {type(value).__name__}",
            )

    return True, None


def validate_required_field(
    record: Dict[str, Any], field: str
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


def validate_label_value(is_vulnerable: Any) -> Tuple[bool, Optional[str]]:
    """Validate is_vulnerable is 0 or 1."""
    if not isinstance(is_vulnerable, int):
        return False, f"is_vulnerable must be int, got {type(is_vulnerable).__name__}"

    if is_vulnerable not in VALID_LABELS:
        return False, f"is_vulnerable must be 0 or 1, got {is_vulnerable}"

    return True, None


def validate_code_quality(
    code: str, min_length: int = 10
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
    record: Dict[str, Any], config: Dict[str, bool]
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

    # Migrate old field names to Stage III names
    if "label" in repaired and "is_vulnerable" not in repaired:
        repaired["is_vulnerable"] = repaired.pop("label")
        repairs.append("Migrated 'label' → 'is_vulnerable'")

    if "source_dataset" in repaired and "dataset" not in repaired:
        repaired["dataset"] = repaired.pop("source_dataset")
        repairs.append("Migrated 'source_dataset' → 'dataset'")

    # Trim whitespace from all string fields
    if config.get("trim_whitespace", True):
        string_fields = [
            "id",
            "language",
            "dataset",
            "code",
            "func_name",
            "description",
            "project",
            "file_name",
            "commit_id",
            "cwe_id",
            "cve_id",
            "attack_type",
            "severity",
            "review_status",
            "source_file",
            "context_before",
            "context_after",
            "repo_url",
            "commit_url",
            "code_sha256",
            "imports",
            "normalized_timestamp",
            "language_stage",
            "verification_source",
            "source_dataset_version",
        ]
        for field in string_fields:
            if field in repaired and isinstance(repaired[field], str):
                original = repaired[field]
                trimmed = original.strip()
                if original != trimmed:
                    repaired[field] = trimmed
                    repairs.append(f"Trimmed whitespace from '{field}'")

    # Normalize language
    if config.get("normalize_language", True):
        if "language" in repaired and isinstance(repaired["language"], str):
            original = repaired["language"]
            normalized = LANGUAGE_NORMALIZATION.get(original.lower().strip(), original)
            if normalized != original:
                repaired["language"] = normalized
                repairs.append(f"Normalized language: '{original}' → '{normalized}'")

    # Fix null strings ("null", "None", "NULL" → actual None)
    if config.get("fix_null_strings", True):
        null_strings = {"null", "none", "n/a", "na", "undefined", ""}
        optional_fields = [
            "func_name",
            "description",
            "cwe_id",
            "cve_id",
            "project",
            "file_name",
            "commit_id",
            "attack_type",
            "severity",
            "review_status",
            "source_file",
            "context_before",
            "context_after",
            "repo_url",
            "commit_url",
            "imports",
            "language_stage",
            "verification_source",
            "source_dataset_version",
        ]
        for field in optional_fields:
            if field in repaired and isinstance(repaired[field], str):
                if repaired[field].lower().strip() in null_strings:
                    repaired[field] = None
                    repairs.append(f"Converted '{field}' null string to actual null")

    # Fix is_vulnerable type (string "0"/"1" → int)
    if "is_vulnerable" in repaired and isinstance(repaired["is_vulnerable"], str):
        try:
            vuln_int = int(repaired["is_vulnerable"])
            if vuln_int in VALID_LABELS:
                repaired["is_vulnerable"] = vuln_int
                repairs.append(f"Converted is_vulnerable from string to int")
        except ValueError:
            pass

    # Also handle old 'label' field for backward compatibility
    if "label" in repaired and isinstance(repaired["label"], str):
        try:
            label_int = int(repaired["label"])
            if label_int in VALID_LABELS:
                repaired["is_vulnerable"] = label_int
                repairs.append(
                    f"Converted label from string to int and migrated to is_vulnerable"
                )
                repaired.pop("label", None)
        except ValueError:
            pass

    # Normalize CWE/CVE to uppercase
    for field in ["cwe_id", "cve_id"]:
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
    record: Dict[str, Any], min_code_length: int = 10, auto_repair: bool = True
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
        record, repairs = auto_repair_record(
            record,
            {
                "trim_whitespace": True,
                "normalize_language": True,
                "fix_null_strings": True,
            },
        )

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

    # Validate is_vulnerable (new field name)
    if "is_vulnerable" in record:
        is_valid, error = validate_label_value(record["is_vulnerable"])
        if not is_valid:
            errors.append(error)
    elif "label" in record:  # Backward compatibility
        is_valid, error = validate_label_value(record["label"])
        if not is_valid:
            errors.append(error)

    # Validate code quality
    if "code" in record:
        is_valid, error = validate_code_quality(record["code"], min_code_length)
        if not is_valid:
            errors.append(error)

    # Validate language
    if "language" in record:
        is_valid, error = validate_language_value(record["language"])
        if not is_valid:
            errors.append(error)

    # Validate CWE/CVE formats
    if "cwe_id" in record:
        is_valid, error = validate_cwe_format(record.get("cwe_id"))
        if not is_valid:
            errors.append(error)

    if "cve_id" in record:
        is_valid, error = validate_cve_format(record.get("cve_id"))
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
    chunk_size: int = 10000,
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
    logger.info("=" * 80)
    logger.info("PHASE 2.1 ENHANCED: ADVANCED DATA VALIDATION (Stage III)")
    logger.info("=" * 80)
    logger.info(f"Input:        {input_path}")
    logger.info(f"Output:       {output_path}")
    logger.info(f"Report:       {report_path}")
    logger.info(f"Errors:       {errors_path}")
    logger.info(f"Schema:       31-field unified schema (17 base + 14 Stage III)")
    logger.info(f"Auto-repair:  {auto_repair}")
    logger.info(f"Duplicates:   {'Remove' if remove_duplicates else 'Keep'}")
    logger.info(f"Chunk size:   {chunk_size:,}")
    logger.info("=" * 80)

    # Ensure output directories exist
    ensure_dir(str(Path(output_path).parent))
    ensure_dir(str(Path(errors_path).parent))

    # Initialize tracking
    seen_hashes: Set[str] = set()
    stats = {
        "start_time": datetime.now().isoformat(),
        "total_records": 0,
        "valid_records": 0,
        "invalid_records": 0,
        "repaired_records": 0,
        "duplicates_removed": 0,
        "error_counts": defaultdict(int),
        "errors_by_dataset": defaultdict(lambda: defaultdict(int)),
        "field_stats": defaultdict(
            lambda: {"total": 0, "null": 0, "empty": 0, "invalid_type": 0}
        ),
        "repairs_applied": defaultdict(int),
        "sample_errors": [],
        "sample_repairs": [],
    }

    valid_chunks = []
    error_chunks = []

    # Process in chunks
    logger.info("Processing chunks...")
    for chunk_idx, chunk in enumerate(
        chunked_read_jsonl(input_path, chunk_size=chunk_size)
    ):
        valid_chunk = []
        error_chunk = []

        for record in chunk:
            stats["total_records"] += 1
            record_id = record.get("id", f'record_{stats["total_records"]}')
            # Handle both old and new field names
            dataset = record.get("dataset") or record.get("source_dataset", "unknown")

            # Comprehensive validation
            is_valid, repaired_record, errors, repairs = validate_record_comprehensive(
                record, min_code_length, auto_repair
            )

            # Track field statistics
            for field in FIELD_TYPES.keys():
                stats["field_stats"][field]["total"] += 1
                if field not in record:
                    stats["field_stats"][field]["null"] += 1
                elif record[field] is None:
                    stats["field_stats"][field]["null"] += 1
                elif isinstance(record[field], str) and not record[field].strip():
                    stats["field_stats"][field]["empty"] += 1

            # Track repairs
            if repairs:
                stats["repaired_records"] += 1
                for repair in repairs:
                    stats["repairs_applied"][repair] += 1

                # Sample repairs (first 10)
                if len(stats["sample_repairs"]) < 10:
                    stats["sample_repairs"].append(
                        {"record_id": record_id, "dataset": dataset, "repairs": repairs}
                    )

            if not is_valid:
                stats["invalid_records"] += 1

                # Track error counts
                for error in errors:
                    stats["error_counts"][error] += 1
                    stats["errors_by_dataset"][dataset][error] += 1

                # Sample errors (first 20)
                if len(stats["sample_errors"]) < 20:
                    stats["sample_errors"].append(
                        {"record_id": record_id, "dataset": dataset, "errors": errors}
                    )

                # Add to error output
                error_chunk.append(
                    {
                        **record,
                        "_validation_errors": errors,
                        "_validation_timestamp": datetime.now().isoformat(),
                    }
                )

                continue

            # Check for duplicates
            if remove_duplicates:
                code_hash = compute_code_hash(repaired_record.get("code", ""))
                if code_hash in seen_hashes:
                    stats["duplicates_removed"] += 1
                    continue
                seen_hashes.add(code_hash)

            stats["valid_records"] += 1
            valid_chunk.append(repaired_record)

        # Store chunks
        if valid_chunk:
            valid_chunks.append(valid_chunk)
        if error_chunk:
            error_chunks.append(error_chunk)

        # Progress
        if (chunk_idx + 1) % 10 == 0:
            logger.info(
                f"Processed {stats['total_records']:,} records "
                f"({stats['valid_records']:,} valid, "
                f"{stats['invalid_records']:,} invalid)"
            )

    # Write validated records
    logger.info(f"Writing {stats['valid_records']:,} validated records...")
    chunked_write_jsonl(output_path, iter(valid_chunks), show_progress=False)

    # Write error records
    if error_chunks:
        logger.info(f"Writing {stats['invalid_records']:,} error records...")
        chunked_write_jsonl(errors_path, iter(error_chunks), show_progress=False)

    # Finalize stats
    stats["end_time"] = datetime.now().isoformat()
    stats["validation_pass_rate"] = (
        stats["valid_records"] / stats["total_records"]
        if stats["total_records"] > 0
        else 0
    )

    # Convert defaultdicts to regular dicts for JSON serialization
    stats["error_counts"] = dict(stats["error_counts"])
    stats["errors_by_dataset"] = {
        k: dict(v) for k, v in stats["errors_by_dataset"].items()
    }
    stats["field_stats"] = dict(stats["field_stats"])
    stats["repairs_applied"] = dict(stats["repairs_applied"])

    # Write report
    logger.info(f"Writing validation report...")
    write_json(stats, report_path, indent=2)

    # Print summary
    logger.info("=" * 80)
    logger.info("VALIDATION SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total records:      {stats['total_records']:,}")
    logger.info(f"Valid records:      {stats['valid_records']:,}")
    logger.info(f"Invalid records:    {stats['invalid_records']:,}")
    logger.info(f"Repaired records:   {stats['repaired_records']:,}")
    logger.info(f"Duplicates removed: {stats['duplicates_removed']:,}")
    logger.info(f"Pass rate:          {stats['validation_pass_rate']*100:.2f}%")
    logger.info("=" * 80)

    if stats["validation_pass_rate"] < 0.98:
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
        default=None,
        help="Input JSONL file (auto-detected if not provided)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output validated JSONL file (auto-detected if not provided)",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Validation report JSON (auto-detected if not provided)",
    )
    parser.add_argument(
        "--errors",
        type=str,
        default=None,
        help="Failed records output (auto-detected if not provided)",
    )
    parser.add_argument(
        "--min-code-length", type=int, default=10, help="Minimum code length"
    )
    parser.add_argument(
        "--no-auto-repair", action="store_true", help="Disable auto-repair"
    )
    parser.add_argument(
        "--keep-duplicates", action="store_true", help="Keep duplicate records"
    )
    parser.add_argument(
        "--chunk-size", type=int, default=10000, help="Chunk size for processing"
    )

    args = parser.parse_args()

    # Print environment info
    print_environment_info()

    # Get paths using Kaggle-compatible helper
    if args.input:
        input_path = args.input
    else:
        unified_dir = get_output_path("unified")
        input_path = str(unified_dir / "processed_all.jsonl")

    # If user provided a directory (common in Kaggle), try to auto-detect merged file
    input_path_obj = Path(input_path)
    if input_path_obj.is_dir():
        # Look for common merged filenames
        candidates = [
            input_path_obj / "merged_normalized.jsonl",
            input_path_obj / "merged_normalized.json",
            input_path_obj / "merged.jsonl",
            input_path_obj / "merged.json",
        ]
        found = None
        for c in candidates:
            if c.exists():
                found = c
                break
        if not found:
            logger.error(f"No merged file found in directory: {input_path_obj}")
            logger.error(f"Checked: {', '.join(str(p.name) for p in candidates)}")
            sys.exit(1)
        input_path = str(found)

    # If the input path does not exist (user passed a non-existent dir), try scanning /kaggle/input
    input_path_obj = Path(input_path)
    if not input_path_obj.exists() and Path("/kaggle/input").exists():
        logger.info(
            f"Input path {input_path} not found — scanning /kaggle/input for merged files..."
        )
        scan_candidates = [
            "merged_normalized.jsonl",
            "merged_normalized.json",
            "merged.jsonl",
            "merged.json",
        ]
        found = None
        for entry in Path("/kaggle/input").iterdir():
            # check merged/ inside each mounted dataset
            final_dir = entry / "merged"
            if final_dir.exists() and final_dir.is_dir():
                for name in scan_candidates:
                    cand = final_dir / name
                    if cand.exists():
                        found = cand
                        logger.info(f"Auto-detected merged file at: {found}")
                        break
            if found:
                break
        if not found:
            logger.error(
                "Could not auto-detect merged file under /kaggle/input. Please pass --input pointing to the merged file or its directory."
            )
            sys.exit(1)
        input_path = str(found)

    # If input is a .json array file (not newline-delimited), convert to JSONL in /kaggle/working
    input_path_obj = Path(input_path)
    if input_path_obj.exists() and input_path_obj.suffix.lower() == ".json":
        # create working destination
        working_dst = Path("/kaggle/working/datasets/merged/merged_normalized.jsonl")
        working_dst.parent.mkdir(parents=True, exist_ok=True)
        # Only convert if destination doesn't exist or is older
        try:
            convert_required = True
            if working_dst.exists():
                # if dst newer than src, skip
                if working_dst.stat().st_mtime >= input_path_obj.stat().st_mtime:
                    convert_required = False
            if convert_required:
                import json as _json

                with (
                    input_path_obj.open("rt", encoding="utf-8") as inf,
                    working_dst.open("wt", encoding="utf-8") as outf,
                ):
                    data = _json.load(inf)
                    if isinstance(data, dict):
                        outf.write(_json.dumps(data, ensure_ascii=False) + "\n")
                    else:
                        for obj in data:
                            outf.write(_json.dumps(obj, ensure_ascii=False) + "\n")
                logger.info(f"Converted JSON -> JSONL: {working_dst}")
        except Exception as e:
            logger.error(f"Failed to convert JSON to JSONL: {e}")
            sys.exit(1)
        # point input_path to working dst
        input_path = str(working_dst)

    if args.output:
        output_path = args.output
    else:
        unified_dir = get_output_path("unified")
        output_path = str(unified_dir / "validated.jsonl")

    if args.report:
        report_path = args.report
    else:
        unified_dir = get_output_path("unified")
        report_path = str(unified_dir / "validation_report.json")

    if args.errors:
        errors_path = args.errors
    else:
        unified_dir = get_output_path("unified")
        errors_path = str(unified_dir / "validation_errors.jsonl")

    logger.info(f"[INFO] Reading input from: {input_path}")
    logger.info(f"[INFO] Writing validated data to: {output_path}")
    logger.info(f"[INFO] Writing report to: {report_path}")

    validate_dataset_enhanced(
        input_path=input_path,
        output_path=output_path,
        report_path=report_path,
        errors_path=errors_path,
        min_code_length=args.min_code_length,
        auto_repair=not args.no_auto_repair,
        remove_duplicates=not args.keep_duplicates,
        chunk_size=args.chunk_size,
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
            sys.argv = ["validate_normalized_data.py"]
            if hasattr(args, "input_file"):
                sys.argv.extend(["--input", args.input_file])
            if hasattr(args, "output_file"):
                sys.argv.extend(["--output", args.output_file])
            if hasattr(args, "report_file"):
                sys.argv.extend(["--report", args.report_file])
            if hasattr(args, "min_code_length"):
                sys.argv.extend(["--min-code-length", str(args.min_code_length)])
            if hasattr(args, "auto_repair") and not args.auto_repair:
                sys.argv.append("--no-auto-repair")
            if hasattr(args, "keep_duplicates") and args.keep_duplicates:
                sys.argv.append("--keep-duplicates")
            main()
        finally:
            sys.argv = original_argv


if __name__ == "__main__":
    main()
