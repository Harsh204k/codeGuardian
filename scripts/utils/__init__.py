"""
Utility module initialization.
"""

from .schema_utils import (
    normalize_language,
    normalize_cwe_id,
    normalize_cve_id,
    normalize_vulnerability_label,
    map_to_unified_schema,
    validate_record,
    get_schema_template,
    deduplicate_by_code_hash,
    UNIFIED_SCHEMA,
    LANGUAGE_MAPPING,
)

from .io_utils import (
    ensure_dir,
    read_json,
    read_jsonl,
    read_csv,
    read_excel,
    write_jsonl,
    write_json,
    write_csv,
    count_lines,
    get_file_info,
    ProgressWriter,
)

from .text_cleaner import (
    remove_comments,
    normalize_whitespace,
    sanitize_code,
    is_valid_code,
    extract_function_name,
    clean_special_chars,
    get_code_statistics,
)

__all__ = [
    # Schema utilities
    "normalize_language",
    "normalize_cwe_id",
    "normalize_cve_id",
    "normalize_vulnerability_label",
    "map_to_unified_schema",
    "validate_record",
    "get_schema_template",
    "deduplicate_by_code_hash",
    "UNIFIED_SCHEMA",
    "LANGUAGE_MAPPING",
    # I/O utilities
    "ensure_dir",
    "read_json",
    "read_jsonl",
    "read_csv",
    "read_excel",
    "write_jsonl",
    "write_json",
    "write_csv",
    "count_lines",
    "get_file_info",
    "ProgressWriter",
    # Text cleaning utilities
    "remove_comments",
    "normalize_whitespace",
    "sanitize_code",
    "is_valid_code",
    "extract_function_name",
    "clean_special_chars",
    "get_code_statistics",
]
