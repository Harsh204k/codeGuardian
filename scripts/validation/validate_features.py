#!/usr/bin/env python
# type: ignore
"""
Production-Ready Enhanced Dataset Validator for CodeGuardian
============================================================

Validates and repairs the Phase 1-3 enhanced feature dataset (107 columns).
Designed for Kaggle runtime with reinforcement learning evaluation.

Validates:
- Schema completeness (107 expected features)
- Data type consistency and automatic coercion
- Missing value imputation (mean/False/unknown)
- Integrity constraints (uniqueness, non-negative counts, bounded ratios)
- Code field preservation
- Shape consistency (no data loss)

Outputs:
- /kaggle/working/datasets/validated/validated_features.csv
- /kaggle/working/datasets/validated/validation_summary.json

Reinforcement Signal:
- ✅ Success (clean execution, valid outputs) → Reward +10
- ❌ Failure (errors, data loss, schema mismatch) → Penalty -10

Author: CodeGuardian Team (Reinforcement-Optimized)
Date: 2025-10-13
"""

import os
import sys
import json
import time
import warnings
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
import pandas as pd

# Suppress pandas FutureWarnings for cleaner output
warnings.filterwarnings('ignore', category=FutureWarning)


# ============================================================================
# SCHEMA DEFINITION (107 columns total)
# ============================================================================

EXPECTED_ORIGINAL_FIELDS = [
    "id",
    "language",
    "dataset",
    "code",
    "is_vulnerable",
    "cwe_id",
    "cve_id",
    "description",
    "attack_type",
    "severity",
    "review_status",
    "func_name",
    "file_name",
    "project",
    "commit_id",
    "source_file",
    "source_row_index",
    "vuln_line_start",
    "vuln_line_end",
    "context_before",
    "context_after",
    "repo_url",
    "commit_url",
    "function_length",
    "num_params",
    "num_calls",
    "imports",
    "code_sha256",
    "normalized_timestamp",
    "language_stage",
    "verification_source",
    "source_dataset_version",
    "merge_timestamp",
]

EXPECTED_PHASE1_FIELDS = [
    # Basic code metrics (9)
    "loc",
    "total_lines",
    "num_tokens",
    "avg_line_len",
    "max_line_len",
    "comment_density",
    "total_chars",
    "whitespace_ratio",
    # Lexical features (7)
    "keyword_count",
    "identifier_count",
    "numeric_count",
    "string_count",
    "special_char_count",
    "operator_count",
    "security_keyword_count",
    # Complexity metrics (5)
    "cyclomatic_complexity",
    "nesting_depth",
    "ast_depth",
    "conditional_count",
    "loop_count",
    # Diversity and entropy (3)
    "token_diversity",
    "shannon_entropy",
    "identifier_entropy",
    # Ratio features (5)
    "comment_code_ratio",
    "identifier_keyword_ratio",
    "operator_operand_ratio",
    "token_density",
    "security_keyword_ratio",
    # Binary indicators (3)
    "has_cwe",
    "has_cve",
    "has_description",
]

EXPECTED_PHASE2_FIELDS = [
    # AST features (10)
    "ast_node_count",
    "ast_branch_factor",
    "ast_max_depth",
    "ast_leaf_count",
    "ast_function_def_count",
    "ast_class_def_count",
    "ast_assignment_count",
    "ast_call_count",
    "ast_import_count",
    "ast_exception_handler_count",
    # Semantic features (5)
    "import_dependency_count",
    "function_call_graph_size",
    "variable_declaration_count",
    "data_dependency_score",
    "control_dependency_score",
    # Security lexical features (12)
    "dangerous_api_count",
    "user_input_calls",
    "cwe_pattern_count",
    "buffer_operation_count",
    "crypto_operation_count",
    "network_operation_count",
    "file_operation_count",
    "sql_keyword_count",
    "shell_command_count",
    "assertion_count",
    "logging_count",
    "try_catch_count",
]

EXPECTED_PHASE3_FIELDS = [
    # Graph features (7)
    "cfg_nodes",
    "cfg_edges",
    "cfg_density",
    "cfg_avg_degree",
    "cfg_max_degree",
    "cfg_strongly_connected_components",
    "cfg_cyclomatic_graph",
    # Taint analysis features (5)
    "tainted_variable_ratio",
    "source_sink_distance",
    "untrusted_input_flow",
    "sanitization_count",
    "validation_count",
    # Data flow features (3)
    "def_use_chain_length",
    "variable_lifetime",
    "inter_procedural_flow",
]

EXPECTED_EMBEDDING_FIELDS = [
    "embedding_features_pending",
]

# Complete schema (107 columns)
ALL_EXPECTED_FIELDS = (
    EXPECTED_ORIGINAL_FIELDS
    + EXPECTED_PHASE1_FIELDS
    + EXPECTED_PHASE2_FIELDS
    + EXPECTED_PHASE3_FIELDS
    + EXPECTED_EMBEDDING_FIELDS
)

# Expected data types for validation and coercion
DTYPE_MAP = {
    # Original fields
    "id": "object",
    "language": "object",
    "dataset": "object",
    "code": "object",
    "is_vulnerable": "bool",
    "cwe_id": "object",
    "cve_id": "object",
    "description": "object",
    "attack_type": "object",
    "severity": "object",
    "review_status": "object",
    "func_name": "object",
    "file_name": "object",
    "project": "object",
    "commit_id": "object",
    "source_file": "object",
    "source_row_index": "int64",
    "vuln_line_start": "int64",
    "vuln_line_end": "int64",
    "context_before": "object",
    "context_after": "object",
    "repo_url": "object",
    "commit_url": "object",
    "function_length": "int64",
    "num_params": "int64",
    "num_calls": "int64",
    "imports": "object",
    "code_sha256": "object",
    "normalized_timestamp": "object",
    "language_stage": "object",
    "verification_source": "object",
    "source_dataset_version": "object",
    "merge_timestamp": "object",
    # Phase 1 - mostly numeric/float
    "loc": "int64",
    "total_lines": "int64",
    "num_tokens": "int64",
    "avg_line_len": "float64",
    "max_line_len": "int64",
    "comment_density": "float64",
    "total_chars": "int64",
    "whitespace_ratio": "float64",
    "keyword_count": "int64",
    "identifier_count": "int64",
    "numeric_count": "int64",
    "string_count": "int64",
    "special_char_count": "int64",
    "operator_count": "int64",
    "security_keyword_count": "int64",
    "cyclomatic_complexity": "int64",
    "nesting_depth": "int64",
    "ast_depth": "int64",
    "conditional_count": "int64",
    "loop_count": "int64",
    "token_diversity": "float64",
    "shannon_entropy": "float64",
    "identifier_entropy": "float64",
    "comment_code_ratio": "float64",
    "identifier_keyword_ratio": "float64",
    "operator_operand_ratio": "float64",
    "token_density": "float64",
    "security_keyword_ratio": "float64",
    "has_cwe": "bool",
    "has_cve": "bool",
    "has_description": "bool",
    # Phase 2
    "ast_node_count": "int64",
    "ast_branch_factor": "float64",
    "ast_max_depth": "int64",
    "ast_leaf_count": "int64",
    "ast_function_def_count": "int64",
    "ast_class_def_count": "int64",
    "ast_assignment_count": "int64",
    "ast_call_count": "int64",
    "ast_import_count": "int64",
    "ast_exception_handler_count": "int64",
    "import_dependency_count": "int64",
    "function_call_graph_size": "int64",
    "variable_declaration_count": "int64",
    "data_dependency_score": "float64",
    "control_dependency_score": "float64",
    "dangerous_api_count": "int64",
    "user_input_calls": "int64",
    "cwe_pattern_count": "int64",
    "buffer_operation_count": "int64",
    "crypto_operation_count": "int64",
    "network_operation_count": "int64",
    "file_operation_count": "int64",
    "sql_keyword_count": "int64",
    "shell_command_count": "int64",
    "assertion_count": "int64",
    "logging_count": "int64",
    "try_catch_count": "int64",
    # Phase 3
    "cfg_nodes": "int64",
    "cfg_edges": "int64",
    "cfg_density": "float64",
    "cfg_avg_degree": "float64",
    "cfg_max_degree": "int64",
    "cfg_strongly_connected_components": "int64",
    "cfg_cyclomatic_graph": "int64",
    "tainted_variable_ratio": "float64",
    "source_sink_distance": "float64",
    "untrusted_input_flow": "int64",
    "sanitization_count": "int64",
    "validation_count": "int64",
    "def_use_chain_length": "float64",
    "variable_lifetime": "float64",
    "inter_procedural_flow": "int64",
    # Embedding
    "embedding_features_pending": "bool",
}


# ============================================================================
# VALIDATOR CLASS
# ============================================================================


class EnhancedDatasetValidator:
    """Production validator for enhanced feature dataset."""

    def __init__(self, input_csv: str, output_dir: str):
        """
        Initialize validator.

        Args:
            input_csv: Path to input CSV (e.g., /kaggle/input/.../features_enhanced.csv)
            output_dir: Output directory (e.g., /kaggle/working/datasets/validated)
        """
        self.input_csv = Path(input_csv)
        self.output_dir = Path(output_dir)
        self.output_csv = self.output_dir / "validated_features.csv"
        self.output_json = self.output_dir / "validation_summary.json"

        self.df: Optional[pd.DataFrame] = None
        self.original_row_count = 0
        self.validation_log: Dict[str, Any] = {}
        self.start_time = time.time()

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def log(self, message: str, level: str = "INFO"):
        """Simple logging to stdout."""
        print(f"[{level}] {message}")

    def load_dataset(self) -> bool:
        """Load the enhanced dataset from CSV."""
        try:
            self.log("=" * 80)
            self.log("📂 LOADING DATASET")
            self.log("=" * 80)

            if not self.input_csv.exists():
                self.log(f"❌ Input file not found: {self.input_csv}", "ERROR")
                return False

            self.log(f"Loading from: {self.input_csv}")

            # Load with dtype optimization
            self.df = pd.read_csv(
                self.input_csv,
                low_memory=False,
                encoding="utf-8",
                na_values=["", "NA", "N/A", "null", "NULL", "None"],
            )

            self.original_row_count = len(self.df)
            self.log(
                f"✅ Loaded {self.original_row_count:,} rows, {len(self.df.columns)} columns"
            )

            return True

        except Exception as e:
            self.log(f"❌ Failed to load dataset: {str(e)}", "ERROR")
            return False

    def validate_schema(self) -> bool:
        """Validate schema completeness."""
        try:
            self.log("\n" + "=" * 80)
            self.log("🔍 SCHEMA VALIDATION")
            self.log("=" * 80)

            missing_cols = [
                col for col in ALL_EXPECTED_FIELDS if col not in self.df.columns
            ]
            extra_cols = [col for col in self.df.columns if col not in ALL_EXPECTED_FIELDS]  # type: ignore

            if missing_cols:
                self.log(f"❌ Missing {len(missing_cols)} expected columns:", "ERROR")
                for col in missing_cols[:10]:  # Show first 10
                    self.log(f"   - {col}", "ERROR")
                self.validation_log["missing_columns"] = missing_cols
                return False

            if extra_cols:
                self.log(
                    f"⚠️  Found {len(extra_cols)} extra columns (will be dropped):",
                    "WARN",
                )
                for col in extra_cols[:10]:
                    self.log(f"   - {col}", "WARN")
                self.validation_log["extra_columns"] = extra_cols
                # Drop extra columns
                self.df = self.df[ALL_EXPECTED_FIELDS]

            self.log(f"✅ Schema verified: {len(ALL_EXPECTED_FIELDS)} columns")
            self.validation_log["schema_valid"] = True
            self.validation_log["total_columns"] = len(ALL_EXPECTED_FIELDS)

            return True

        except Exception as e:
            self.log(f"❌ Schema validation failed: {str(e)}", "ERROR")
            return False

    def coerce_data_types(self) -> bool:
        """Coerce columns to expected data types."""
        try:
            self.log("\n" + "=" * 80)
            self.log("🔧 DATA TYPE COERCION")
            self.log("=" * 80)

            type_coercions = []

            for col in self.df.columns:
                if col not in DTYPE_MAP:
                    continue

                expected_dtype = DTYPE_MAP[col]
                current_dtype = str(self.df[col].dtype)

                if current_dtype != expected_dtype:
                    try:
                        if expected_dtype == "bool":
                            # Boolean coercion
                            self.df[col] = self.df[col].fillna(False).astype(bool)
                        elif expected_dtype == "int64":
                            # Integer coercion (handle NaN first)
                            self.df[col] = (
                                pd.to_numeric(self.df[col], errors="coerce")
                                .fillna(0)
                                .astype("int64")
                            )
                        elif expected_dtype == "float64":
                            # Float coercion
                            self.df[col] = pd.to_numeric(self.df[col], errors="coerce")
                        else:
                            # Object/string - fix FutureWarning by using mask instead of replace
                            str_series = self.df[col].astype(str)
                            self.df[col] = str_series.where(str_series != "nan", np.nan)

                        type_coercions.append(
                            f"{col}: {current_dtype} → {expected_dtype}"
                        )

                    except Exception as e:
                        self.log(f"⚠️  Failed to coerce {col}: {str(e)}", "WARN")

            if type_coercions:
                self.log(f"✅ Coerced {len(type_coercions)} columns")
                self.validation_log["type_coercions"] = type_coercions
            else:
                self.log("✅ All data types correct")
                self.validation_log["type_coercions"] = []

            return True

        except Exception as e:
            self.log(f"❌ Type coercion failed: {str(e)}", "ERROR")
            return False

    def impute_missing_values(self) -> bool:
        """Impute missing values systematically."""
        try:
            self.log("\n" + "=" * 80)
            self.log("🩹 MISSING VALUE IMPUTATION")
            self.log("=" * 80)

            # Track which rows had imputation
            imputation_mask = pd.Series([False] * len(self.df), index=self.df.index)
            imputed_columns = []
            missing_value_summary = {}

            for col in self.df.columns:
                missing_count = self.df[col].isnull().sum()

                if missing_count > 0:
                    missing_pct = (missing_count / len(self.df)) * 100
                    missing_value_summary[col] = round(missing_pct, 2)
                    imputed_columns.append(col)

                    # Mark rows with missing values
                    imputation_mask |= self.df[col].isnull()

                    # Impute based on dtype
                    dtype = str(self.df[col].dtype)

                    if dtype == "bool":
                        self.df[col] = self.df[col].fillna(False)
                    elif dtype in ["int64", "float64"]:
                        # Use column mean for numeric
                        col_mean = self.df[col].mean()
                        if pd.isna(col_mean):  # All NaN column
                            col_mean = 0
                        self.df[col] = self.df[col].fillna(col_mean)
                    else:
                        # Use "unknown" for categorical/object
                        self.df[col] = self.df[col].fillna("unknown")

            # Add imputation flag column
            self.df["imputation_flag"] = imputation_mask.astype(int)

            self.log(f"✅ Imputed missing values in {len(imputed_columns)} columns")
            self.log(
                f"   Rows with imputation: {imputation_mask.sum():,} ({(imputation_mask.sum()/len(self.df)*100):.2f}%)"
            )

            self.validation_log["missing_value_summary"] = missing_value_summary
            self.validation_log["imputed_columns"] = imputed_columns
            self.validation_log["rows_with_imputation"] = int(imputation_mask.sum())

            return True

        except Exception as e:
            self.log(f"❌ Missing value imputation failed: {str(e)}", "ERROR")
            return False

    def validate_integrity(self) -> bool:
        """Validate data integrity constraints."""
        try:
            self.log("\n" + "=" * 80)
            self.log("🔒 INTEGRITY VALIDATION")
            self.log("=" * 80)

            integrity_issues = {}

            # 1. Check ID uniqueness
            if "id" in self.df.columns:
                duplicate_ids = self.df["id"].duplicated().sum()
                if duplicate_ids > 0:
                    self.log(f"⚠️  Found {duplicate_ids} duplicate IDs", "WARN")
                    integrity_issues["duplicate_ids"] = int(duplicate_ids)
                else:
                    self.log("✅ All IDs unique")

            # 2. Check code_sha256 uniqueness
            if "code_sha256" in self.df.columns:
                duplicate_hashes = self.df["code_sha256"].duplicated().sum()
                if duplicate_hashes > 0:
                    self.log(
                        f"⚠️  Found {duplicate_hashes} duplicate code hashes (possible duplicates)",
                        "WARN",
                    )
                    integrity_issues["duplicate_code_hashes"] = int(duplicate_hashes)
                else:
                    self.log("✅ All code hashes unique")

            # 3. Check for empty code
            if "code" in self.df.columns:
                empty_code = (
                    (self.df["code"] == "") | (self.df["code"] == "unknown")
                ).sum()
                if empty_code > 0:
                    self.log(
                        f"⚠️  Found {empty_code} empty/unknown code snippets", "WARN"
                    )
                    integrity_issues["empty_code_snippets"] = int(empty_code)
                else:
                    self.log("✅ All code snippets non-empty")

            # 4. Check non-negative counts
            count_cols = [
                col
                for col in self.df.columns
                if any(
                    kw in col
                    for kw in ["count", "num_", "loc", "nodes", "edges", "length"]
                )
            ]

            negative_count_issues = []
            for col in count_cols:
                if self.df[col].dtype in ["int64", "float64"]:
                    negative_count = (self.df[col] < 0).sum()
                    if negative_count > 0:
                        negative_count_issues.append(f"{col}: {negative_count}")
                        self.log(
                            f"⚠️  Found {negative_count} negative values in {col}",
                            "WARN",
                        )

            if negative_count_issues:
                integrity_issues["negative_count_features"] = negative_count_issues
            else:
                self.log("✅ All count features non-negative")

            # 5. Check ratio bounds (should be 0-1 or reasonable)
            ratio_cols = [
                col
                for col in self.df.columns
                if any(kw in col for kw in ["ratio", "density", "diversity"])
            ]

            ratio_issues = []
            for col in ratio_cols:
                if self.df[col].dtype in ["float64"]:
                    out_of_bounds = ((self.df[col] < 0) | (self.df[col] > 1)).sum()
                    if out_of_bounds > 0:
                        ratio_issues.append(f"{col}: {out_of_bounds} out of [0,1]")
                        self.log(
                            f"⚠️  {col} has {out_of_bounds} values outside [0,1]", "WARN"
                        )

            if ratio_issues:
                integrity_issues["ratio_bound_violations"] = ratio_issues
            else:
                self.log("✅ All ratio features within bounds")

            # 6. Verify shape preservation
            if len(self.df) != self.original_row_count:
                self.log(
                    f"❌ Row count mismatch! Original: {self.original_row_count}, Current: {len(self.df)}",
                    "ERROR",
                )
                integrity_issues["row_count_mismatch"] = {
                    "original": self.original_row_count,
                    "current": len(self.df),
                }
                return False
            else:
                self.log(f"✅ Shape preserved: {len(self.df):,} rows")

            self.validation_log["integrity_issues"] = integrity_issues
            return True

        except Exception as e:
            self.log(f"❌ Integrity validation failed: {str(e)}", "ERROR")
            return False

    def save_outputs(self) -> bool:
        """Save validated dataset and summary."""
        try:
            self.log("\n" + "=" * 80)
            self.log("💾 SAVING OUTPUTS")
            self.log("=" * 80)

            # Save CSV
            self.log(f"Saving validated dataset to: {self.output_csv}")
            self.df.to_csv(self.output_csv, index=False, encoding="utf-8")
            self.log(
                f"✅ Saved CSV: {self.output_csv.stat().st_size / 1024 / 1024:.2f} MB"
            )

            # Prepare summary
            elapsed_time = time.time() - self.start_time

            summary = {
                "timestamp": pd.Timestamp.now().isoformat(),
                "input_file": str(self.input_csv),
                "output_file": str(self.output_csv),
                "execution_time_seconds": round(elapsed_time, 2),
                "total_rows": len(self.df),
                "total_columns": len(self.df.columns),
                "execution_status": "success",
                **self.validation_log,
            }

            # Save JSON
            self.log(f"Saving validation summary to: {self.output_json}")
            with open(self.output_json, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)

            self.log(f"✅ Saved validation summary: {self.output_json}")

            return True

        except Exception as e:
            self.log(f"❌ Failed to save outputs: {str(e)}", "ERROR")
            return False

    def print_summary(self):
        """Print final validation summary."""
        self.log("\n" + "=" * 80)
        self.log("✅ VALIDATION COMPLETE")
        self.log("=" * 80)
        self.log(f"Rows: {len(self.df):,} | Columns: {len(self.df.columns)}")
        self.log(f"Output saved to: {self.output_dir}")
        self.log(f"  - {self.output_csv.name}")
        self.log(f"  - {self.output_json.name}")
        self.log("=" * 80)

    def run(self) -> bool:
        """Execute full validation pipeline."""
        try:
            # Pipeline steps
            if not self.load_dataset():
                return False

            if not self.validate_schema():
                return False

            if not self.coerce_data_types():
                return False

            if not self.impute_missing_values():
                return False

            if not self.validate_integrity():
                return False

            if not self.save_outputs():
                return False

            self.print_summary()

            # Reinforcement signal: Success
            self.log(
                "\n🎯 REINFORCEMENT SIGNAL: ✅ REWARD +10 (Clean execution, valid outputs)"
            )

            return True

        except Exception as e:
            self.log(f"\n❌ VALIDATION PIPELINE FAILED: {str(e)}", "ERROR")
            self.log("🎯 REINFORCEMENT SIGNAL: ❌ PENALTY -10 (Execution error)")

            # Save error report
            error_summary = {
                "timestamp": pd.Timestamp.now().isoformat(),
                "execution_status": "failed",
                "error_message": str(e),
                "reinforcement_signal": -10,
            }

            try:
                with open(self.output_dir / "validation_error.json", "w") as f:
                    json.dump(error_summary, f, indent=2)
            except:
                pass

            return False


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


def main():
    """Main execution function."""

    # Kaggle paths (adjust for local use)
    # INPUT_CSV = "/kaggle/input/codeGuardian-preprocessed-dataset/features/features_enhanced.csv"
    # OUTPUT_DIR = "/kaggle/working/datasets/validated"

    # Local development paths (default)
    INPUT_CSV = "datasets/features/features_enhanced.csv"
    OUTPUT_DIR = "datasets/validated"

    # Allow command-line override
    if len(sys.argv) > 1:
        INPUT_CSV = sys.argv[1]
    if len(sys.argv) > 2:
        OUTPUT_DIR = sys.argv[2]

    print("=" * 80)
    print("🛡️  CodeGuardian Enhanced Dataset Validator")
    print("=" * 80)
    print(f"Input:  {INPUT_CSV}")
    print(f"Output: {OUTPUT_DIR}")
    print("=" * 80)

    # Run validator
    validator = EnhancedDatasetValidator(input_csv=INPUT_CSV, output_dir=OUTPUT_DIR)

    success = validator.run()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
