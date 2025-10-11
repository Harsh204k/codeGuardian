"""
🎯 CANONICAL SCHEMA ENFORCER - Single Source of Truth
CodeGuardian Unified Schema Management & Field Mapping

This module is the authoritative schema definition for the entire CodeGuardian project.
It ensures 100% consistency between dataset normalization, merging, and ML feature engineering.

Core Features:
✅ Unified 17-field schema (aligned with normalize_and_merge_all.py)
✅ Automatic CWE → attack_type/severity enrichment
✅ Field normalization (language, CWE, CVE, labels)
✅ Provenance tracking (source_file, source_row_index)
✅ Deduplication by code hash (SHA-256)
✅ Validation (manual + jsonschema)
✅ CLI test mode for compliance verification

Schema Alignment:
- This module defines the schema used by normalize_and_merge_all.py
- All preprocessing scripts (prepare_*.py) output to this schema
- CWE mapper integration for attack type classification
- Full traceability for competition scoring

Author: CodeGuardian Team
Version: 2.0.0 - Competition Ready
Date: 2025-10-11
"""

import sys
import uuid
import hashlib
import logging
import json
from typing import Dict, Any, Optional, List, Tuple
import re
from pathlib import Path
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Import CWE mapper for attack type enrichment
try:
    from scripts.utils.cwe_mapper import map_cwe_to_attack

    CWE_MAPPER_AVAILABLE = True
    logger.info("✅ CWE Mapper integrated successfully")
except ImportError:
    CWE_MAPPER_AVAILABLE = False
    logger.warning("⚠️ CWE Mapper unavailable - enrichment disabled")


# ═══════════════════════════════════════════════════════════════════════════
# 🎯 FINAL UNIFIED SCHEMA (100% Aligned with normalize_and_merge_all.py)
# ═══════════════════════════════════════════════════════════════════════════

UNIFIED_SCHEMA = {
    # Core identification
    "id": str,  # UUID or dataset-prefixed unique ID
    "language": str,  # Normalized language name
    "dataset": str,  # Source dataset name (renamed from source_dataset)
    # Code and vulnerability
    "code": str,  # Source code snippet
    "is_vulnerable": int,  # Binary: 0 (safe) or 1 (vulnerable) - renamed from label
    # Vulnerability metadata
    "cwe_id": Optional[str],  # CWE identifier
    "cve_id": Optional[str],  # CVE identifier
    "description": Optional[str],  # Vulnerability description
    # CWE-enriched fields (auto-populated via cwe_mapper)
    "attack_type": Optional[str],  # Attack classification (e.g., "SQL Injection")
    "severity": Optional[str],  # Risk level (low/medium/high/critical)
    "review_status": Optional[
        str
    ],  # Quality flag (auto_verified/pending_review/needs_review)
    # Provenance tracking
    "func_name": Optional[str],  # Function/method name
    "file_name": Optional[str],  # Source file name
    "project": Optional[str],  # Repository/project name
    "commit_id": Optional[str],  # Git commit hash
    # Traceability (for debugging and audit)
    "source_file": Optional[str],  # Original input file path
    "source_row_index": Optional[int],  # Row number in source file
}


# ═══════════════════════════════════════════════════════════════════════════
# 📋 JSONSCHEMA VALIDATION DEFINITION
# ═══════════════════════════════════════════════════════════════════════════

JSONSCHEMA_DEFINITION = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "language": {"type": "string"},
        "dataset": {"type": "string"},
        "code": {"type": "string"},
        "is_vulnerable": {"type": "integer", "enum": [0, 1]},
        "cwe_id": {"type": ["string", "null"]},
        "cve_id": {"type": ["string", "null"]},
        "description": {"type": ["string", "null"]},
        "attack_type": {"type": ["string", "null"]},
        "severity": {
            "type": ["string", "null"],
            "enum": ["low", "medium", "high", "critical", None],
        },
        "review_status": {
            "type": ["string", "null"],
            "enum": ["auto_verified", "pending_review", "needs_review", None],
        },
        "func_name": {"type": ["string", "null"]},
        "file_name": {"type": ["string", "null"]},
        "project": {"type": ["string", "null"]},
        "commit_id": {"type": ["string", "null"]},
        "source_file": {"type": ["string", "null"]},
        "source_row_index": {"type": ["integer", "null"]},
    },
    "required": ["id", "language", "dataset", "code", "is_vulnerable"],
    "additionalProperties": False,
}


# ═══════════════════════════════════════════════════════════════════════════
# 🗺️ LANGUAGE NORMALIZATION MAPPINGS
# ═══════════════════════════════════════════════════════════════════════════

LANGUAGE_MAPPING = {
    "c": "C",
    "cpp": "C++",
    "c++": "C++",
    "cxx": "C++",
    "cc": "C++",
    "h": "C",
    "hpp": "C++",
    "hxx": "C++",
    "java": "Java",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "jsx": "JavaScript",
    "ts": "TypeScript",
    "tsx": "TypeScript",
    "typescript": "TypeScript",
    "python": "Python",
    "py": "Python",
    "php": "PHP",
    "go": "Go",
    "golang": "Go",
    "ruby": "Ruby",
    "rb": "Ruby",
    "csharp": "C#",
    "cs": "C#",
    "c#": "C#",
    "swift": "Swift",
    "kotlin": "Kotlin",
    "kt": "Kotlin",
    "rust": "Rust",
    "rs": "Rust",
    "scala": "Scala",
    "perl": "Perl",
    "pl": "Perl",
    "shell": "Shell",
    "sh": "Shell",
    "bash": "Shell",
}

EXTENSION_TO_LANGUAGE = {
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hxx": "C++",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".py": "Python",
    ".php": "PHP",
    ".go": "Go",
    ".rb": "Ruby",
    ".cs": "C#",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".rs": "Rust",
    ".scala": "Scala",
    ".pl": "Perl",
    ".sh": "Shell",
}


# ═══════════════════════════════════════════════════════════════════════════
# 🔧 NORMALIZATION UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def normalize_language(lang: str) -> str:
    """
    Normalize language names to standard format.

    Args:
        lang: Raw language name

    Returns:
        Normalized language name or "unknown"
    """
    if not lang or not isinstance(lang, str):
        return "unknown"

    lang_lower = lang.strip().lower()
    return LANGUAGE_MAPPING.get(lang_lower, lang.strip())


def infer_language_from_filename(file_name: str) -> Optional[str]:
    """
    Infer programming language from file extension.

    Args:
        file_name: Name or path of source file

    Returns:
        Inferred language name or None
    """
    if not file_name:
        return None

    ext = Path(file_name).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(ext)


def normalize_cwe_id(cwe: Any) -> Optional[str]:
    """
    Normalize CWE ID to standard format (CWE-XXX).

    Args:
        cwe: CWE identifier in various formats

    Returns:
        Normalized CWE ID or None
    """
    if not cwe or str(cwe).lower() in ["none", "null", "n/a", "", "nan"]:
        return None

    cwe_str = str(cwe).strip()

    # Extract numeric part
    match = re.search(r"(\d+)", cwe_str)
    if match:
        cwe_num = match.group(1)
        return f"CWE-{cwe_num}"

    return None


def normalize_cve_id(cve: Any) -> Optional[str]:
    """
    Normalize CVE ID to standard format (CVE-YYYY-XXXXX).

    Args:
        cve: CVE identifier in various formats

    Returns:
        Normalized CVE ID or None
    """
    if not cve or str(cve).lower() in ["none", "null", "n/a", "", "nan"]:
        return None

    cve_str = str(cve).strip()

    # CVE pattern: CVE-YYYY-XXXXX
    match = re.search(r"CVE[-\s]?(\d{4})[-\s]?(\d+)", cve_str, re.IGNORECASE)
    if match:
        year, num = match.groups()
        return f"CVE-{year}-{num}"

    return None


def normalize_vulnerability_label(label: Any) -> int:
    """
    Normalize vulnerability label to binary 0/1.

    Args:
        label: Various representations of vulnerability status

    Returns:
        0 for non-vulnerable, 1 for vulnerable
    """
    if isinstance(label, bool):
        return 1 if label else 0

    if isinstance(label, (int, float)):
        return 1 if label > 0 else 0

    if isinstance(label, str):
        label_lower = label.strip().lower()
        if label_lower in ["1", "true", "yes", "vulnerable", "vuln", "positive"]:
            return 1
        if label_lower in ["0", "false", "no", "safe", "clean", "negative"]:
            return 0

    # Default to 0 if unclear
    return 0


def generate_unique_id(dataset: str, index: int, additional_info: str = "") -> str:
    """
    Generate a globally unique ID with dataset prefix.

    Format: <dataset>_<zero-padded-index>_<hash>
    Example: devign_00001_a3f2

    Args:
        dataset: Dataset name
        index: Record index
        additional_info: Additional information for uniqueness

    Returns:
        Globally unique identifier with dataset prefix
    """
    # Create base identifier with zero-padded index
    base = f"{dataset}_{index:05d}"

    # Add hash for additional uniqueness if provided
    if additional_info:
        hash_obj = hashlib.md5(f"{base}_{additional_info}".encode())
        hash_suffix = hash_obj.hexdigest()[:8]
        return f"{base}_{hash_suffix}"

    return base


# ═══════════════════════════════════════════════════════════════════════════
# 🎯 CORE SCHEMA MAPPING FUNCTION
# ═══════════════════════════════════════════════════════════════════════════


def map_to_unified_schema(
    record: Dict[str, Any],
    dataset_name: str,
    index: int,
    field_mapping: Optional[Dict[str, str]] = None,
    source_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Map a dataset-specific record to the unified schema with CWE enrichment.

    This is the canonical mapping function that ensures 100% consistency
    with normalize_and_merge_all.py.

    Args:
        record: Original record from dataset
        dataset_name: Name of the source dataset
        index: Record index for ID generation
        field_mapping: Optional mapping of dataset fields to unified fields (None = auto-detect)
        source_file: Original file path for traceability

    Returns:
        Record conforming to unified schema (17 fields)
    """
    if field_mapping is None:
        field_mapping = {}

    # Helper function to get field value with mapping
    def get_field(unified_field: str, default=None):
        # Check if there's a custom mapping
        dataset_field = field_mapping.get(unified_field, unified_field)
        return record.get(dataset_field, default)

    # Get core fields with multiple fallback names
    code = (
        get_field("code")
        or get_field("func")
        or get_field("source_code")
        or get_field("function")
        or ""
    )

    # Get label with various naming conventions (map to is_vulnerable)
    label = get_field("label")
    if label is None:
        label = (
            get_field("target")
            or get_field("is_vulnerable")
            or get_field("vulnerable")
            or 0
        )

    # Get language field
    language = (
        get_field("language")
        or get_field("lang")
        or get_field("program_language")
        or ""
    )

    # Infer language from file_name if not provided
    if not language or language == "unknown":
        file_name = get_field("file_name") or get_field("file") or get_field("filename")
        if file_name:
            inferred_lang = infer_language_from_filename(file_name)
            if inferred_lang:
                language = inferred_lang

    # Normalize language
    language = normalize_language(language)

    # Get function name with fallbacks
    func_name = (
        get_field("func_name")
        or get_field("method_name")
        or get_field("function_name")
        or None
    )

    # Get commit ID
    commit_id = (
        get_field("commit_id")
        or get_field("commit")
        or get_field("commit_hash")
        or None
    )

    # Generate globally unique ID with dataset prefix
    unique_id = generate_unique_id(
        dataset_name, index, commit_id[:8] if commit_id else ""
    )

    # Normalize CWE and CVE
    cwe_id = normalize_cwe_id(get_field("cwe_id") or get_field("cwe"))
    cve_id = normalize_cve_id(get_field("cve_id") or get_field("cve"))

    # Get description
    description = (
        get_field("description")
        or get_field("desc")
        or get_field("commit_message")
        or None
    )

    # Build unified record matching exact schema (NEW FIELD NAMES)
    unified_record = {
        "id": unique_id,
        "language": language,
        "dataset": dataset_name,  # RENAMED from source_dataset
        "code": str(code).strip(),
        "is_vulnerable": normalize_vulnerability_label(label),  # RENAMED from label
        "cwe_id": cwe_id,
        "cve_id": cve_id,
        "description": description,
        "attack_type": None,  # Will be enriched if CWE mapper available
        "severity": None,  # Will be enriched if CWE mapper available
        "review_status": None,  # Will be enriched if CWE mapper available
        "func_name": func_name,
        "file_name": get_field("file_name")
        or get_field("file")
        or get_field("filename")
        or None,
        "project": get_field("project")
        or get_field("repo")
        or get_field("repository")
        or None,
        "commit_id": commit_id,
        "source_file": source_file,  # NEW: traceability
        "source_row_index": index,  # NEW: traceability
    }

    # CWE Enrichment (automatic if CWE mapper available)
    if CWE_MAPPER_AVAILABLE and unified_record.get("cwe_id"):
        try:
            attack_info = map_cwe_to_attack(
                cwe_id=unified_record["cwe_id"],
                cwe_description=unified_record.get("description"),
            )
            unified_record["attack_type"] = attack_info.get("attack_type")
            unified_record["severity"] = attack_info.get("severity")
            unified_record["review_status"] = attack_info.get("review_status")
        except Exception as e:
            logger.debug(f"CWE enrichment failed for {unified_record['cwe_id']}: {e}")

    return unified_record


# ═══════════════════════════════════════════════════════════════════════════
# ✅ VALIDATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def validate_record(
    record: Dict[str, Any], use_jsonschema: bool = False
) -> Tuple[bool, List[str]]:
    """
    Validate that a record conforms to the unified schema.

    Args:
        record: Record to validate
        use_jsonschema: If True, use jsonschema validation (more strict)

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors = []

    # Option 1: Use jsonschema for strict validation
    if use_jsonschema:
        try:
            from jsonschema import validate, ValidationError

            validate(instance=record, schema=JSONSCHEMA_DEFINITION)
        except ValidationError as e:
            errors.append(f"Schema validation error: {e.message}")
            return False, errors
        except ImportError:
            logger.warning("jsonschema not available, using manual validation")
            use_jsonschema = False

    # Option 2: Manual validation (fallback or default)
    if not use_jsonschema:
        # Check required fields (UPDATED FOR NEW SCHEMA)
        required_fields = ["id", "language", "dataset", "code", "is_vulnerable"]
        for field in required_fields:
            if field not in record:
                errors.append(f"Missing required field: {field}")
            elif field == "is_vulnerable":
                # Special check for is_vulnerable
                if record[field] not in [0, 1]:
                    errors.append(
                        f"Invalid is_vulnerable value: {record[field]} (must be 0 or 1)"
                    )
            elif not record[field] and field not in ["is_vulnerable"]:
                errors.append(f"Empty required field: {field}")

        # Check code length
        if "code" in record:
            code_len = len(record.get("code", "").strip())
            if code_len < 10:
                errors.append(
                    f"Code snippet too short ({code_len} characters, minimum 10)"
                )

        # Validate language is not empty
        if "language" in record:
            lang = record.get("language", "").strip()
            if not lang:
                errors.append("Language field is empty")

        # Validate CWE format if present
        if record.get("cwe_id"):
            cwe = record["cwe_id"]
            if not isinstance(cwe, str) or not cwe.startswith("CWE-"):
                errors.append(f"Invalid CWE format: {cwe} (expected CWE-XXX)")

        # Validate CVE format if present
        if record.get("cve_id"):
            cve = record["cve_id"]
            if not isinstance(cve, str) or not cve.startswith("CVE-"):
                errors.append(f"Invalid CVE format: {cve} (expected CVE-YYYY-XXXX)")

    return len(errors) == 0, errors


def get_schema_template() -> Dict[str, Any]:
    """
    Get an empty template following the unified schema (NEW FIELD NAMES).

    Returns:
        Empty record with all fields initialized to defaults
    """
    return {
        "id": "",
        "language": "unknown",
        "dataset": "",
        "code": "",
        "is_vulnerable": 0,
        "cwe_id": None,
        "cve_id": None,
        "description": None,
        "attack_type": None,
        "severity": None,
        "review_status": None,
        "func_name": None,
        "file_name": None,
        "project": None,
        "commit_id": None,
        "source_file": None,
        "source_row_index": None,
    }


def deduplicate_by_code_hash(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate records based on code content hash.

    Args:
        records: List of records to deduplicate

    Returns:
        Deduplicated list of records
    """
    seen_hashes = set()
    deduplicated = []

    for record in records:
        code = record.get("code", "")
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

        if code_hash not in seen_hashes:
            seen_hashes.add(code_hash)
            deduplicated.append(record)

    return deduplicated


# ═══════════════════════════════════════════════════════════════════════════
# 📊 STATISTICS AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════


def get_schema_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get statistics about schema compliance and enrichment status.

    Args:
        records: List of unified schema records

    Returns:
        Dictionary with schema statistics
    """
    from collections import Counter

    stats = {
        "total_records": len(records),
        "field_completeness": {},
        "language_distribution": Counter(),
        "dataset_distribution": Counter(),
        "vulnerability_ratio": 0.0,
        "cwe_coverage": 0.0,
        "attack_type_coverage": 0.0,
        "severity_distribution": Counter(),
        "review_status_distribution": Counter(),
    }

    # Field completeness
    for field in UNIFIED_SCHEMA.keys():
        non_null_count = sum(
            1 for r in records if r.get(field) is not None and r.get(field) != ""
        )
        stats["field_completeness"][field] = (
            (non_null_count / len(records)) * 100 if records else 0
        )

    # Distributions
    for record in records:
        stats["language_distribution"][record.get("language", "unknown")] += 1
        stats["dataset_distribution"][record.get("dataset", "unknown")] += 1
        if record.get("severity"):
            stats["severity_distribution"][record["severity"]] += 1
        if record.get("review_status"):
            stats["review_status_distribution"][record["review_status"]] += 1

    # Coverage metrics
    vuln_count = sum(1 for r in records if r.get("is_vulnerable") == 1)
    cwe_count = sum(1 for r in records if r.get("cwe_id"))
    attack_count = sum(1 for r in records if r.get("attack_type"))

    stats["vulnerability_ratio"] = (vuln_count / len(records)) * 100 if records else 0
    stats["cwe_coverage"] = (cwe_count / len(records)) * 100 if records else 0
    stats["attack_type_coverage"] = (
        (attack_count / len(records)) * 100 if records else 0
    )

    return stats


# ═══════════════════════════════════════════════════════════════════════════
# 🧪 CLI TEST MODE
# ═══════════════════════════════════════════════════════════════════════════


def run_compliance_test(test_data_dir: Optional[Path] = None):
    """
    Run schema compliance tests on sample data.

    Args:
        test_data_dir: Directory containing test JSONL files
    """
    print("\n" + "=" * 80)
    print("🧪 SCHEMA COMPLIANCE TEST SUITE")
    print("=" * 80)

    # Print schema information
    print(f"\n📋 UNIFIED SCHEMA ({len(UNIFIED_SCHEMA)} fields):")
    for field, field_type in UNIFIED_SCHEMA.items():
        required = field in JSONSCHEMA_DEFINITION["required"]
        req_marker = "✅ REQUIRED" if required else "⚪ OPTIONAL"
        print(f"   {req_marker:15s} {field:20s} : {field_type}")

    # Test CWE mapper integration
    print(f"\n🧠 CWE MAPPER STATUS:")
    if CWE_MAPPER_AVAILABLE:
        print("   ✅ Available - automatic enrichment enabled")
    else:
        print("   ❌ Unavailable - enrichment disabled")

    # Test record mapping if test data available
    if test_data_dir and test_data_dir.exists():
        print(f"\n📁 TESTING WITH DATA FROM: {test_data_dir}")

        test_files = list(test_data_dir.glob("**/*cleaned.jsonl"))[:3]

        for test_file in test_files:
            print(f"\n   Testing: {test_file.name}")

            try:
                # Use existing io_utils.read_jsonl instead of jsonlines
                from scripts.utils.io_utils import read_jsonl

                records = list(
                    read_jsonl(str(test_file), max_records=10)
                )  # Test first 10 records

                # Map to unified schema
                dataset_name = test_file.parent.parent.name
                mapped = [
                    map_to_unified_schema(
                        r, dataset_name, i, source_file=str(test_file)
                    )
                    for i, r in enumerate(records)
                ]

                # Validate
                valid_count = sum(1 for r in mapped if validate_record(r)[0])

                # Get stats
                stats = get_schema_stats(mapped)

                print(f"      Records: {len(mapped)}")
                print(f"      Valid: {valid_count}/{len(mapped)}")
                print(f"      CWE Coverage: {stats['cwe_coverage']:.1f}%")
                print(
                    f"      Attack Type Coverage: {stats['attack_type_coverage']:.1f}%"
                )

            except Exception as e:
                print(f"      ❌ Error: {e}")
    else:
        print(f"\n⚠️  No test data directory specified or found")
        print(f"   Usage: python schema_utils_v2.py --test --data-dir <path>")

    # Test template generation
    print(f"\n🎯 SCHEMA TEMPLATE TEST:")
    template = get_schema_template()
    is_valid, errors = validate_record(template)
    if not is_valid:
        print(f"   ⚠️  Empty template has expected validation errors:")
        for error in errors[:3]:
            print(f"      - {error}")
    else:
        print(f"   ✅ Template structure valid")

    print("\n" + "=" * 80)
    print("✅ COMPLIANCE TEST COMPLETE")
    print("=" * 80 + "\n")


# ═══════════════════════════════════════════════════════════════════════════
# 🎬 CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════


def main():
    """CLI entry point for schema compliance testing."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeGuardian Schema Utilities v2")
    parser.add_argument("--test", action="store_true", help="Run compliance test suite")
    parser.add_argument("--data-dir", type=Path, help="Test data directory")
    parser.add_argument(
        "--export-schema", type=Path, help="Export schema definition to JSON file"
    )

    args = parser.parse_args()

    if args.export_schema:
        schema_doc = {
            "name": "CodeGuardian Unified Schema v2.0",
            "fields": {k: str(v) for k, v in UNIFIED_SCHEMA.items()},
            "required_fields": JSONSCHEMA_DEFINITION["required"],
            "cwe_mapper_available": CWE_MAPPER_AVAILABLE,
        }
        with open(args.export_schema, "w") as f:
            json.dump(schema_doc, f, indent=2)
        print(f"✅ Schema exported to: {args.export_schema}")

    if args.test:
        run_compliance_test(args.data_dir)

    if not args.test and not args.export_schema:
        parser.print_help()


if __name__ == "__main__":
    main()
