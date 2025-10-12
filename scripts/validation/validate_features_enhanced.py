#!/usr/bin/env python
# type: ignore
"""
Enhanced Dataset Validation Script for Phase 2+3 Feature-Engineered Dataset
===========================================================================

Validates the enhanced feature dataset with ~100+ features.

Validates:
- Schema completeness (100+ expected features)
- All original 32 schema fields preserved
- Phase 1 (32), Phase 2 (~27), Phase 3 (~15) features present
- Data types and consistency
- Missing values and data quality
- Statistical sanity checks
- Code field integrity
- Label distribution
- Feature value ranges

Author: CodeGuardian Team (Enhanced)
Date: 2025-10-12
"""

import sys
from pathlib import Path
import json
import warnings

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import pandas as pd
    import numpy as np

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("❌ ERROR: pandas is required for validation")
    sys.exit(1)

from scripts.utils.logging_utils import get_logger

logger = get_logger(__name__)

# Expected schema: 32 original + 32 Phase 1 + ~27 Phase 2 + ~15 Phase 3 = ~106 features
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


class EnhancedDatasetValidator:
    """Comprehensive enhanced dataset validation."""

    def __init__(
        self, csv_path: str, stats_path: str = None, sample_size: int = 100000
    ):
        """
        Initialize validator.

        Args:
            csv_path: Path to enhanced features CSV
            stats_path: Path to stats JSON (optional)
            sample_size: Number of rows to load for validation
        """
        self.csv_path = Path(csv_path)
        self.stats_path = Path(stats_path) if stats_path else None
        self.sample_size = sample_size
        self.df = None
        self.stats = None
        self.issues = []
        self.warnings = []

    def load_data(self):
        """Load enhanced dataset and stats."""
        logger.info("=" * 80)
        logger.info("LOADING ENHANCED DATASET")
        logger.info("=" * 80)

        if not self.csv_path.exists():
            self.issues.append(f"CSV file not found: {self.csv_path}")
            return False

        try:
            # Load CSV (sample if too large)
            logger.info(f"Loading CSV: {self.csv_path}")
            self.df = pd.read_csv(self.csv_path, nrows=self.sample_size)
            logger.info(
                f"✅ Loaded {len(self.df):,} records with {len(self.df.columns)} columns"
            )

            # Load stats if available
            if self.stats_path and self.stats_path.exists():
                with open(self.stats_path, "r") as f:
                    self.stats = json.load(f)
                logger.info(f"✅ Loaded statistics from: {self.stats_path}")

            return True

        except Exception as e:
            self.issues.append(f"Failed to load data: {e}")
            return False

    def validate_schema(self):
        """Validate that all expected fields are present."""
        logger.info("\n" + "=" * 80)
        logger.info("SCHEMA VALIDATION")
        logger.info("=" * 80)

        all_expected_fields = (
            EXPECTED_ORIGINAL_FIELDS
            + EXPECTED_PHASE1_FIELDS
            + EXPECTED_PHASE2_FIELDS
            + EXPECTED_PHASE3_FIELDS
            + EXPECTED_EMBEDDING_FIELDS
        )

        missing_fields = [f for f in all_expected_fields if f not in self.df.columns]
        extra_fields = [f for f in self.df.columns if f not in all_expected_fields]

        # Check original schema fields
        missing_original = [
            f for f in EXPECTED_ORIGINAL_FIELDS if f not in self.df.columns
        ]
        if missing_original:
            self.issues.append(
                f"❌ CRITICAL: Missing original schema fields: {missing_original}"
            )
            logger.error(f"Missing original schema fields: {missing_original}")
        else:
            logger.info(
                f"✅ All {len(EXPECTED_ORIGINAL_FIELDS)} original schema fields present"
            )

        # Check Phase 1 fields
        missing_phase1 = [f for f in EXPECTED_PHASE1_FIELDS if f not in self.df.columns]
        if missing_phase1:
            self.issues.append(f"Missing Phase 1 fields: {missing_phase1}")
            logger.warning(f"Missing Phase 1 fields: {missing_phase1}")
        else:
            logger.info(f"✅ All {len(EXPECTED_PHASE1_FIELDS)} Phase 1 fields present")

        # Check Phase 2 fields
        missing_phase2 = [f for f in EXPECTED_PHASE2_FIELDS if f not in self.df.columns]
        if missing_phase2:
            self.warnings.append(f"Missing Phase 2 fields: {missing_phase2}")
            logger.warning(f"⚠️  Missing Phase 2 fields: {missing_phase2}")
        else:
            logger.info(f"✅ All {len(EXPECTED_PHASE2_FIELDS)} Phase 2 fields present")

        # Check Phase 3 fields
        missing_phase3 = [f for f in EXPECTED_PHASE3_FIELDS if f not in self.df.columns]
        if missing_phase3:
            self.warnings.append(f"Missing Phase 3 fields: {missing_phase3}")
            logger.warning(f"⚠️  Missing Phase 3 fields: {missing_phase3}")
        else:
            logger.info(f"✅ All {len(EXPECTED_PHASE3_FIELDS)} Phase 3 fields present")

        # Extra fields (informational)
        if extra_fields:
            logger.info(f"ℹ️  Extra fields found: {extra_fields}")

        # Summary
        logger.info(f"\nTotal fields: {len(self.df.columns)}")
        logger.info(f"Expected fields: {len(all_expected_fields)}")
        logger.info(f"Missing fields: {len(missing_fields)}")
        logger.info(f"Extra fields: {len(extra_fields)}")

        return len(missing_original) == 0  # Only fail on missing original fields

    def validate_code_integrity(self):
        """Validate that code field is preserved."""
        logger.info("\n" + "=" * 80)
        logger.info("CODE INTEGRITY VALIDATION")
        logger.info("=" * 80)

        if "code" not in self.df.columns:
            self.issues.append("❌ CRITICAL: 'code' field missing!")
            return False

        # Check for null/empty code
        null_code = self.df["code"].isnull().sum()
        empty_code = (self.df["code"] == "").sum()

        if null_code > 0:
            self.warnings.append(f"Found {null_code} records with null code")
            logger.warning(f"⚠️  {null_code} records have null code")

        if empty_code > 0:
            self.warnings.append(f"Found {empty_code} records with empty code")
            logger.warning(f"⚠️  {empty_code} records have empty code")

        # Check code length distribution
        code_lengths = self.df["code"].str.len()
        logger.info(f"Code length stats:")
        logger.info(f"  Min: {code_lengths.min()}")
        logger.info(f"  Max: {code_lengths.max()}")
        logger.info(f"  Mean: {code_lengths.mean():.2f}")
        logger.info(f"  Median: {code_lengths.median():.2f}")

        logger.info("✅ Code field integrity check complete")
        return True

    def validate_feature_ranges(self):
        """Validate feature value ranges."""
        logger.info("\n" + "=" * 80)
        logger.info("FEATURE RANGE VALIDATION")
        logger.info("=" * 80)

        numeric_features = self.df.select_dtypes(include=[np.number]).columns

        # Check for negative values in count features
        count_features = [
            f
            for f in numeric_features
            if any(kw in f for kw in ["count", "num_", "loc", "nodes", "edges"])
        ]

        for feature in count_features:
            negative_count = (self.df[feature] < 0).sum()
            if negative_count > 0:
                self.issues.append(
                    f"Feature {feature} has {negative_count} negative values"
                )
                logger.error(f"❌ {feature}: {negative_count} negative values")

        # Check for ratio features (should be in [0, 1] or reasonable ranges)
        ratio_features = [
            f
            for f in numeric_features
            if any(kw in f for kw in ["ratio", "density", "diversity"])
        ]

        for feature in ratio_features:
            out_of_range = ((self.df[feature] < 0) | (self.df[feature] > 1)).sum()
            if out_of_range > 0:
                self.warnings.append(
                    f"Feature {feature} has {out_of_range} values outside [0, 1]"
                )
                logger.warning(f"⚠️  {feature}: {out_of_range} values outside [0, 1]")

        # Check for infinite values
        for feature in numeric_features:
            inf_count = np.isinf(self.df[feature]).sum()
            if inf_count > 0:
                self.issues.append(f"Feature {feature} has {inf_count} infinite values")
                logger.error(f"❌ {feature}: {inf_count} infinite values")

        logger.info("✅ Feature range validation complete")

    def validate_label_distribution(self):
        """Validate vulnerability label distribution."""
        logger.info("\n" + "=" * 80)
        logger.info("LABEL DISTRIBUTION VALIDATION")
        logger.info("=" * 80)

        if "is_vulnerable" not in self.df.columns:
            self.issues.append("❌ CRITICAL: 'is_vulnerable' label missing!")
            return False

        label_counts = self.df["is_vulnerable"].value_counts()
        logger.info("Label distribution:")
        for label, count in label_counts.items():
            pct = count / len(self.df) * 100
            logger.info(f"  {label}: {count:,} ({pct:.2f}%)")

        # Check for class imbalance
        if len(label_counts) > 1:
            min_class = label_counts.min()
            max_class = label_counts.max()
            imbalance_ratio = max_class / min_class

            if imbalance_ratio > 10:
                self.warnings.append(
                    f"Severe class imbalance: {imbalance_ratio:.2f}:1 ratio"
                )
                logger.warning(f"⚠️  Class imbalance ratio: {imbalance_ratio:.2f}:1")

        logger.info("✅ Label distribution validation complete")
        return True

    def validate_missing_values(self):
        """Check for missing values in features."""
        logger.info("\n" + "=" * 80)
        logger.info("MISSING VALUES VALIDATION")
        logger.info("=" * 80)

        # Critical fields that should never be null
        critical_fields = ["id", "code", "is_vulnerable"]

        for field in critical_fields:
            if field in self.df.columns:
                null_count = self.df[field].isnull().sum()
                if null_count > 0:
                    self.issues.append(
                        f"❌ CRITICAL: {field} has {null_count} null values"
                    )
                    logger.error(f"❌ {field}: {null_count} null values")

        # Optional fields - just log warnings
        for col in self.df.columns:
            if col not in critical_fields:
                null_count = self.df[col].isnull().sum()
                if null_count > 0:
                    null_pct = null_count / len(self.df) * 100
                    if null_pct > 50:
                        self.warnings.append(
                            f"{col} has {null_pct:.2f}% missing values"
                        )
                        logger.warning(f"⚠️  {col}: {null_pct:.2f}% missing")

        logger.info("✅ Missing values validation complete")

    def validate_phase2_features(self):
        """Validate Phase 2 specific features."""
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 2 FEATURES VALIDATION")
        logger.info("=" * 80)

        phase2_present = sum(1 for f in EXPECTED_PHASE2_FIELDS if f in self.df.columns)
        logger.info(
            f"Phase 2 features present: {phase2_present}/{len(EXPECTED_PHASE2_FIELDS)}"
        )

        # AST features sanity checks
        if "ast_node_count" in self.df.columns:
            logger.info(
                f"AST node count range: {self.df['ast_node_count'].min()} - {self.df['ast_node_count'].max()}"
            )

        if "dangerous_api_count" in self.df.columns:
            dangerous_records = (self.df["dangerous_api_count"] > 0).sum()
            logger.info(
                f"Records with dangerous APIs: {dangerous_records:,} ({dangerous_records/len(self.df)*100:.2f}%)"
            )

        if "user_input_calls" in self.df.columns:
            user_input_records = (self.df["user_input_calls"] > 0).sum()
            logger.info(
                f"Records with user input: {user_input_records:,} ({user_input_records/len(self.df)*100:.2f}%)"
            )

        logger.info("✅ Phase 2 features validation complete")

    def validate_phase3_features(self):
        """Validate Phase 3 specific features."""
        logger.info("\n" + "=" * 80)
        logger.info("PHASE 3 FEATURES VALIDATION")
        logger.info("=" * 80)

        phase3_present = sum(1 for f in EXPECTED_PHASE3_FIELDS if f in self.df.columns)
        logger.info(
            f"Phase 3 features present: {phase3_present}/{len(EXPECTED_PHASE3_FIELDS)}"
        )

        # CFG features sanity checks
        if "cfg_nodes" in self.df.columns:
            logger.info(
                f"CFG nodes range: {self.df['cfg_nodes'].min()} - {self.df['cfg_nodes'].max()}"
            )

        if "tainted_variable_ratio" in self.df.columns:
            tainted_records = (self.df["tainted_variable_ratio"] > 0).sum()
            logger.info(
                f"Records with tainted variables: {tainted_records:,} ({tainted_records/len(self.df)*100:.2f}%)"
            )

        logger.info("✅ Phase 3 features validation complete")

    def generate_report(self, output_path: str = None):
        """Generate validation report."""
        logger.info("\n" + "=" * 80)
        logger.info("VALIDATION REPORT")
        logger.info("=" * 80)

        report = {
            "timestamp": pd.Timestamp.now().isoformat(),
            "csv_path": str(self.csv_path),
            "total_records": len(self.df) if self.df is not None else 0,
            "total_features": len(self.df.columns) if self.df is not None else 0,
            "original_fields_count": len(EXPECTED_ORIGINAL_FIELDS),
            "phase1_fields_count": len(EXPECTED_PHASE1_FIELDS),
            "phase2_fields_count": len(EXPECTED_PHASE2_FIELDS),
            "phase3_fields_count": len(EXPECTED_PHASE3_FIELDS),
            "issues": self.issues,
            "warnings": self.warnings,
            "validation_passed": len(self.issues) == 0,
        }

        # Print summary
        logger.info(
            f"\nValidation Status: {'✅ PASSED' if report['validation_passed'] else '❌ FAILED'}"
        )
        logger.info(f"Total records: {report['total_records']:,}")
        logger.info(f"Total features: {report['total_features']}")
        logger.info(f"Issues found: {len(self.issues)}")
        logger.info(f"Warnings: {len(self.warnings)}")

        if self.issues:
            logger.error("\n🚨 CRITICAL ISSUES:")
            for issue in self.issues:
                logger.error(f"  - {issue}")

        if self.warnings:
            logger.warning("\n⚠️  WARNINGS:")
            for warning in self.warnings:
                logger.warning(f"  - {warning}")

        # Save report
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"\n✅ Report saved: {output_path}")

        return report

    def run_all_validations(self, output_report_path: str = None):
        """Run all validation checks."""
        logger.info("\n" + "=" * 80)
        logger.info("ENHANCED DATASET VALIDATION")
        logger.info("=" * 80)

        # Load data
        if not self.load_data():
            logger.error("❌ Failed to load data. Aborting validation.")
            return False

        # Run validations
        self.validate_schema()
        self.validate_code_integrity()
        self.validate_label_distribution()
        self.validate_missing_values()
        self.validate_feature_ranges()
        self.validate_phase2_features()
        self.validate_phase3_features()

        # Generate report
        report = self.generate_report(output_report_path)

        return report["validation_passed"]


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate enhanced feature-engineered dataset"
    )
    parser.add_argument(
        "--csv",
        type=str,
        required=True,
        help="Path to enhanced features CSV file",
    )
    parser.add_argument(
        "--stats",
        type=str,
        default=None,
        help="Path to statistics JSON file (optional)",
    )
    parser.add_argument(
        "--output-report",
        type=str,
        default=None,
        help="Path to save validation report JSON",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=100000,
        help="Number of rows to validate (default: 100k)",
    )

    args = parser.parse_args()

    # Run validation
    validator = EnhancedDatasetValidator(
        csv_path=args.csv,
        stats_path=args.stats,
        sample_size=args.sample_size,
    )

    success = validator.run_all_validations(args.output_report)

    if success:
        logger.info("\n✅ All validations passed!")
        sys.exit(0)
    else:
        logger.error("\n❌ Validation failed. See issues above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
