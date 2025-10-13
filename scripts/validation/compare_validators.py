#!/usr/bin/env python
#type: ignore
"""
Compare single-threaded vs multiprocessing validator performance
"""

import sys
import time
import tempfile
from pathlib import Path
import pandas as pd
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.validation.validate_features import EnhancedDatasetValidator as ValidatorV1
from scripts.validation.validate_features_v2 import (
    EnhancedDatasetValidator as ValidatorV2,
    ALL_EXPECTED_FIELDS,
)


def create_sample_dataset(num_rows=1000):
    """Create a sample dataset for testing."""
    print(f"\n📊 Creating sample dataset with {num_rows} rows...")

    np.random.seed(42)

    data = {
        # Original fields
        "id": [f"sample_{i}" for i in range(num_rows)],
        "language": np.random.choice(["python", "java", "c"], num_rows),
        "dataset": ["test_dataset"] * num_rows,
        "code": [f"def func_{i}():\n    return {i}" for i in range(num_rows)],
        "is_vulnerable": np.random.choice([True, False], num_rows),
        "cwe_id": [
            f"CWE-{np.random.randint(1, 1000)}" if np.random.random() > 0.3 else None
            for _ in range(num_rows)
        ],
        "cve_id": [
            (
                f"CVE-2023-{np.random.randint(1000, 9999)}"
                if np.random.random() > 0.5
                else None
            )
            for _ in range(num_rows)
        ],
        "description": [
            f"Test description {i}" if np.random.random() > 0.2 else None
            for i in range(num_rows)
        ],
        "attack_type": np.random.choice(["injection", "overflow", "xss"], num_rows),
        "severity": np.random.choice(["high", "medium", "low"], num_rows),
        "review_status": ["pending"] * num_rows,
        "func_name": [f"func_{i}" for i in range(num_rows)],
        "file_name": [f"file_{i % 100}.py" for i in range(num_rows)],
        "project": ["test_project"] * num_rows,
        "commit_id": [f"commit_{i % 50}" for i in range(num_rows)],
        "source_file": [f"source_{i}.py" for i in range(num_rows)],
        "source_row_index": list(range(num_rows)),
        "vuln_line_start": np.random.randint(1, 100, num_rows),
        "vuln_line_end": np.random.randint(1, 100, num_rows),
        "context_before": [f"context_before_{i}" for i in range(num_rows)],
        "context_after": [f"context_after_{i}" for i in range(num_rows)],
        "repo_url": ["https://github.com/test/repo"] * num_rows,
        "commit_url": [
            f"https://github.com/test/repo/commit/{i}" for i in range(num_rows)
        ],
        "function_length": np.random.randint(10, 200, num_rows),
        "num_params": np.random.randint(0, 10, num_rows),
        "num_calls": np.random.randint(0, 50, num_rows),
        "imports": [f"import module_{i % 20}" for i in range(num_rows)],
        "code_sha256": [f"sha256_{i}" for i in range(num_rows)],
        "normalized_timestamp": ["2023-01-01T00:00:00Z"] * num_rows,
        "language_stage": ["production"] * num_rows,
        "verification_source": ["manual"] * num_rows,
        "source_dataset_version": ["1.0"] * num_rows,
        "merge_timestamp": ["2023-01-01T00:00:00Z"] * num_rows,
    }

    # Phase 1 features
    for field in [
        "loc",
        "total_lines",
        "num_tokens",
        "max_line_len",
        "total_chars",
        "keyword_count",
        "identifier_count",
        "numeric_count",
        "string_count",
        "special_char_count",
        "operator_count",
        "security_keyword_count",
        "cyclomatic_complexity",
        "nesting_depth",
        "ast_depth",
        "conditional_count",
        "loop_count",
    ]:
        data[field] = np.random.randint(1, 100, num_rows)

    for field in [
        "avg_line_len",
        "comment_density",
        "whitespace_ratio",
        "token_diversity",
        "shannon_entropy",
        "identifier_entropy",
        "comment_code_ratio",
        "identifier_keyword_ratio",
        "operator_operand_ratio",
        "token_density",
        "security_keyword_ratio",
    ]:
        data[field] = np.random.random(num_rows)

    for field in ["has_cwe", "has_cve", "has_description"]:
        data[field] = np.random.choice([True, False], num_rows)

    # Phase 2 features
    for field in [
        "ast_node_count",
        "ast_max_depth",
        "ast_leaf_count",
        "ast_function_def_count",
        "ast_class_def_count",
        "ast_assignment_count",
        "ast_call_count",
        "ast_import_count",
        "ast_exception_handler_count",
        "import_dependency_count",
        "function_call_graph_size",
        "variable_declaration_count",
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
    ]:
        data[field] = np.random.randint(0, 50, num_rows)

    for field in [
        "ast_branch_factor",
        "data_dependency_score",
        "control_dependency_score",
    ]:
        data[field] = np.random.random(num_rows)

    # Phase 3 features
    for field in [
        "cfg_nodes",
        "cfg_edges",
        "cfg_max_degree",
        "cfg_strongly_connected_components",
        "cfg_cyclomatic_graph",
        "untrusted_input_flow",
        "sanitization_count",
        "validation_count",
        "inter_procedural_flow",
    ]:
        data[field] = np.random.randint(0, 30, num_rows)

    for field in [
        "cfg_density",
        "cfg_avg_degree",
        "tainted_variable_ratio",
        "source_sink_distance",
        "def_use_chain_length",
        "variable_lifetime",
    ]:
        data[field] = np.random.random(num_rows)

    # Embedding field
    data["embedding_features_pending"] = [True] * num_rows

    df = pd.DataFrame(data)
    print(f"✅ Created dataset with {len(df)} rows, {len(df.columns)} columns")

    return df


def test_validator(
    validator_class, version_name, input_csv, output_dir, supports_sampling=True
):
    """Test a validator and return execution time."""
    print(f"\n{'='*80}")
    print(f"🧪 Testing {version_name}")
    print(f"{'='*80}")

    start_time = time.time()

    if supports_sampling:
        validator = validator_class(
            input_csv=str(input_csv), output_dir=str(output_dir), sample_size=None
        )
    else:
        validator = validator_class(
            input_csv=str(input_csv), output_dir=str(output_dir)
        )

    success = validator.run()

    elapsed_time = time.time() - start_time

    print(f"\n{'='*80}")
    print(f"⏱️  {version_name} Results")
    print(f"{'='*80}")
    print(f"Status: {'✅ SUCCESS' if success else '❌ FAILED'}")
    print(f"Execution Time: {elapsed_time:.2f} seconds")
    print(f"Output: {output_dir}")
    print(f"{'='*80}")

    return success, elapsed_time


def main():
    """Main test function."""
    print("\n" + "=" * 80)
    print("🔬 VALIDATOR COMPARISON TEST")
    print("=" * 80)

    # Create sample dataset
    df = create_sample_dataset(num_rows=1000)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Save sample dataset
        input_csv = tmpdir / "sample_data.csv"
        df.to_csv(input_csv, index=False)
        print(f"✅ Saved sample data to: {input_csv}")

        # Test V1 (single-threaded)
        output_v1 = tmpdir / "output_v1"
        output_v1.mkdir()
        success_v1, time_v1 = test_validator(
            ValidatorV1,
            "Version 1 (Single-threaded)",
            input_csv,
            output_v1,
            supports_sampling=False,
        )

        # Test V2 (multiprocessing)
        output_v2 = tmpdir / "output_v2"
        output_v2.mkdir()
        success_v2, time_v2 = test_validator(
            ValidatorV2,
            "Version 2 (Multiprocessing)",
            input_csv,
            output_v2,
            supports_sampling=True,
        )

        # Compare results
        print("\n" + "=" * 80)
        print("📊 COMPARISON RESULTS")
        print("=" * 80)
        print(
            f"Version 1 (Single-threaded): {time_v1:.2f}s - {'✅ PASSED' if success_v1 else '❌ FAILED'}"
        )
        print(
            f"Version 2 (Multiprocessing):  {time_v2:.2f}s - {'✅ PASSED' if success_v2 else '❌ FAILED'}"
        )

        if success_v1 and success_v2:
            speedup = time_v1 / time_v2
            print(f"\n⚡ Speedup: {speedup:.2f}x")
            if speedup > 1:
                print(f"✅ Multiprocessing version is {speedup:.2f}x FASTER")
            elif speedup < 1:
                print(f"⚠️  Multiprocessing version is {1/speedup:.2f}x SLOWER")
            else:
                print("⚠️  Both versions have similar performance")

        print("=" * 80)

        # Final verdict
        if success_v1 and success_v2:
            print("\n✅ ALL TESTS PASSED")
            print("\n💡 RECOMMENDATION:")
            if time_v2 < time_v1:
                print(
                    "   Use validate_features_v2.py for better performance on Kaggle (multiprocessing)"
                )
            else:
                print("   Use validate_features.py for simplicity (both work the same)")
        else:
            print("\n❌ SOME TESTS FAILED")
            if not success_v1:
                print("   ❌ Version 1 failed")
            if not success_v2:
                print("   ❌ Version 2 failed")


if __name__ == "__main__":
    main()
