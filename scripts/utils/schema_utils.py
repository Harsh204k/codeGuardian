"""
Utility module for unified schema management and field mapping.

This module provides functions to:
- Map dataset-specific records to the unified schema
- Fill missing fields with default values
- Validate schema compliance with jsonschema
- Normalize field values
- Infer language from file extensions
- Generate globally unique IDs
"""

import uuid
import hashlib
from typing import Dict, Any, Optional, List, Tuple
import re
from pathlib import Path


# Unified schema definition (matches hackathon requirements exactly)
UNIFIED_SCHEMA = {
    "id": str,                    # Globally unique ID with dataset prefix
    "language": str,              # Programming language (normalized)
    "code": str,                  # Source code snippet
    "label": int,                 # Binary: 0 (safe) or 1 (vulnerable)
    "cwe_id": Optional[str],      # CWE identifier or None
    "cve_id": Optional[str],      # CVE identifier or None
    "func_name": Optional[str],   # Function/method name or None
    "file_name": Optional[str],   # Source file name or None
    "project": Optional[str],     # Repository/project name or None
    "commit_id": Optional[str],   # Git commit hash or None
    "description": Optional[str], # Vulnerability description or None
    "source_dataset": str         # Dataset name (e.g., "devign", "zenodo")
}

# JSONSchema for validation
JSONSCHEMA_DEFINITION = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "language": {"type": "string"},
        "code": {"type": "string"},
        "label": {"type": "integer", "enum": [0, 1]},
        "cwe_id": {"type": ["string", "null"]},
        "cve_id": {"type": ["string", "null"]},
        "func_name": {"type": ["string", "null"]},
        "file_name": {"type": ["string", "null"]},
        "project": {"type": ["string", "null"]},
        "commit_id": {"type": ["string", "null"]},
        "description": {"type": ["string", "null"]},
        "source_dataset": {"type": "string"},
        # Optional provenance fields for traceability
        "source_row_index": {"type": "integer"},
        "source_file": {"type": "string"}
    },
    "required": ["id", "language", "code", "label", "source_dataset"],
    "additionalProperties": False
}


# Language normalization mappings (comprehensive)
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
    "bash": "Shell"
}

# File extension to language mapping (for inference)
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
    ".sh": "Shell"
}


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
    if not cwe or cwe in ["None", "null", "N/A", ""]:
        return None
    
    cwe_str = str(cwe).strip()
    
    # Extract numeric part
    match = re.search(r'(\d+)', cwe_str)
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
    if not cve or cve in ["None", "null", "N/A", ""]:
        return None
    
    cve_str = str(cve).strip()
    
    # CVE pattern: CVE-YYYY-XXXXX
    match = re.search(r'CVE[-\s]?(\d{4})[-\s]?(\d+)', cve_str, re.IGNORECASE)
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


def map_to_unified_schema(
    record: Dict[str, Any],
    dataset_name: str,
    index: int,
    field_mapping: Dict[str, str] = None
) -> Dict[str, Any]:
    """
    Map a dataset-specific record to the unified schema.
    
    Args:
        record: Original record from dataset
        dataset_name: Name of the source dataset
        index: Record index for ID generation
        field_mapping: Optional mapping of dataset fields to unified fields
        
    Returns:
        Record conforming to unified schema with exact field names
    """
    if field_mapping is None:
        field_mapping = {}
    
    # Helper function to get field value with mapping
    def get_field(unified_field: str, default=None):
        # Check if there's a custom mapping
        dataset_field = field_mapping.get(unified_field, unified_field)
        return record.get(dataset_field, default)
    
    # Get core fields with multiple fallback names
    code = (get_field("code") or get_field("func") or 
            get_field("source_code") or get_field("function") or "")
    
    # Get label with various naming conventions
    label = get_field("label")
    if label is None:
        label = get_field("target") or get_field("is_vulnerable") or get_field("vulnerable") or 0
    
    # Get language field
    language = get_field("language") or get_field("lang") or ""
    
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
    func_name = (get_field("func_name") or get_field("method_name") or 
                 get_field("function_name") or None)
    
    # Get commit ID
    commit_id = get_field("commit_id") or get_field("commit") or None
    
    # Generate globally unique ID with dataset prefix
    unique_id = generate_unique_id(dataset_name, index, commit_id[:8] if commit_id else "")
    
    # Build unified record matching exact schema
    unified_record = {
        "id": unique_id,
        "language": language,
        "code": str(code).strip(),
        "label": normalize_vulnerability_label(label),
        "cwe_id": normalize_cwe_id(get_field("cwe_id")),
        "cve_id": normalize_cve_id(get_field("cve_id")),
        "func_name": func_name,
        "file_name": get_field("file_name") or get_field("file") or get_field("filename") or None,
        "project": get_field("project") or get_field("repo") or None,
        "commit_id": commit_id,
        "description": get_field("description") or get_field("desc") or None,
        "source_dataset": dataset_name
    }
    
    return unified_record


def validate_record(record: Dict[str, Any], use_jsonschema: bool = True) -> tuple[bool, List[str]]:
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
            # Fallback to manual validation if jsonschema not available
            use_jsonschema = False
    
    # Option 2: Manual validation (fallback or if use_jsonschema=False)
    if not use_jsonschema:
        # Check required fields with new schema
        required_fields = ["id", "language", "code", "label", "source_dataset"]
        for field in required_fields:
            if field not in record:
                errors.append(f"Missing required field: {field}")
            elif not record[field] and field != "label":
                errors.append(f"Empty required field: {field}")
        
        # Validate label type
        if "label" in record and record["label"] not in [0, 1]:
            errors.append(f"Invalid label value: {record['label']} (must be 0 or 1)")
        
        # Check code length
        if "code" in record:
            code_len = len(record.get("code", "").strip())
            if code_len < 10:
                errors.append(f"Code snippet too short ({code_len} characters, minimum 10)")
        
        # Validate language is not empty (allow "unknown" as fallback)
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
    Get an empty template following the unified schema with new field names.
    
    Returns:
        Empty record with all fields initialized to defaults
    """
    return {
        "id": "",
        "language": "unknown",
        "code": "",
        "label": 0,
        "cwe_id": None,
        "cve_id": None,
        "func_name": None,
        "file_name": None,
        "project": None,
        "commit_id": None,
        "description": None,
        "source_dataset": ""
    }


def deduplicate_by_code_hash(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate records based on code content hash.
    
    Args:
        records: List of records to deduplicate
        
    Returns:
        Deduplicated list of records
    """
    import hashlib
    
    seen_hashes = set()
    deduplicated = []
    
    for record in records:
        code = record.get("code", "")
        code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
        
        if code_hash not in seen_hashes:
            seen_hashes.add(code_hash)
            deduplicated.append(record)
    
    return deduplicated


def save_schema_definition(output_path: str):
    """
    Save the unified schema definition to a JSON file.
    
    Args:
        output_path: Path to save schema definition
    """
    import json
    
    schema_doc = {
        "name": "CodeGuardian Unified Vulnerability Dataset Schema",
        "version": "2.0.0",
        "description": "Standardized schema for vulnerability detection across multiple datasets",
        "fields": {
            "id": {
                "type": "string",
                "required": True,
                "description": "Globally unique identifier with dataset prefix (e.g., devign_00001_a3f2)"
            },
            "language": {
                "type": "string",
                "required": True,
                "description": "Programming language (normalized)",
                "allowed_values": list(set(LANGUAGE_MAPPING.values())) + ["unknown"]
            },
            "code": {
                "type": "string",
                "required": True,
                "description": "Source code snippet or function body"
            },
            "label": {
                "type": "integer",
                "required": True,
                "description": "Binary vulnerability label (0=safe, 1=vulnerable)",
                "allowed_values": [0, 1]
            },
            "cwe_id": {
                "type": "string",
                "required": False,
                "description": "CWE identifier (format: CWE-XXX)",
                "nullable": True
            },
            "cve_id": {
                "type": "string",
                "required": False,
                "description": "CVE identifier (format: CVE-YYYY-XXXXX)",
                "nullable": True
            },
            "func_name": {
                "type": "string",
                "required": False,
                "description": "Function or method name",
                "nullable": True
            },
            "file_name": {
                "type": "string",
                "required": False,
                "description": "Source file name",
                "nullable": True
            },
            "project": {
                "type": "string",
                "required": False,
                "description": "Project or repository name",
                "nullable": True
            },
            "commit_id": {
                "type": "string",
                "required": False,
                "description": "Git commit hash",
                "nullable": True
            },
            "description": {
                "type": "string",
                "required": False,
                "description": "Vulnerability description or metadata",
                "nullable": True
            },
            "source_dataset": {
                "type": "string",
                "required": True,
                "description": "Name of the source dataset"
            }
        }
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(schema_doc, f, indent=2, ensure_ascii=False)
