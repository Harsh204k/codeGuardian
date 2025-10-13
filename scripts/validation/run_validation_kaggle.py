#!/usr/bin/env python
"""
Kaggle Validation Runner Script
================================
Runs the enhanced dataset validator on Kaggle with proper error handling
and warning suppression.

Usage in Kaggle Notebook:
    !python /kaggle/working/codeGuardian/scripts/validation/run_validation_kaggle.py
"""

import os
import sys
import json
import glob
import warnings

# Suppress pandas FutureWarnings for cleaner output
warnings.filterwarnings("ignore", category=FutureWarning)


def find_input_csv():
    """Auto-discover the features_enhanced.csv file in Kaggle input."""
    patterns = [
        "/kaggle/input/codeguardian-pre-processed-datasets/features/features_enhanced.csv",
        "/kaggle/input/*/features/features_enhanced.csv",
        "/kaggle/input/*/*/features_enhanced.csv",
    ]

    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]

    return None


def main():
    """Main execution function."""
    print("=" * 80)
    print("🛡️  CodeGuardian Dataset Validator (Kaggle Edition)")
    print("=" * 80)

    # Configuration
    script_path = "/kaggle/working/codeGuardian/scripts/validation/validate_features.py"
    output_dir = "/kaggle/working/datasets/validated"

    # Step 1: Check if validation script exists
    if not os.path.exists(script_path):
        print(f"❌ Validation script not found at: {script_path}")
        print("   Make sure to upload the codeGuardian repository to /kaggle/working/")
        sys.exit(1)

    print(f"✅ Found validation script at: {script_path}")

    # Step 2: Find input CSV
    input_csv = find_input_csv()

    if not input_csv:
        print("❌ No features_enhanced.csv found in /kaggle/input/")
        print("\nAvailable datasets in /kaggle/input/:")
        try:
            for dataset in os.listdir("/kaggle/input/"):
                print(f"  - {dataset}")
        except:
            print("  (Unable to list datasets)")
        sys.exit(1)

    print(f"✅ Found input dataset: {input_csv}")

    # Step 3: Create output directory
    os.makedirs(output_dir, exist_ok=True)
    print(f"✅ Output directory ready: {output_dir}")

    # Step 4: Run validation
    print("\n" + "=" * 80)
    print("🚀 STARTING VALIDATION")
    print("=" * 80)

    exit_code = os.system(f'python "{script_path}" "{input_csv}" "{output_dir}"')

    # Step 5: Check results
    print("\n" + "=" * 80)
    print("📊 VALIDATION RESULTS")
    print("=" * 80)

    output_csv = f"{output_dir}/validated_features.csv"
    output_json = f"{output_dir}/validation_summary.json"

    if exit_code == 0:
        print("✅ Validation completed successfully!")
        print("\n📁 Output Files:")

        # Check and display file info
        for fpath, fname in [
            (output_csv, "Validated CSV"),
            (output_json, "Validation Summary"),
        ]:
            if os.path.isfile(fpath):
                size_mb = os.path.getsize(fpath) / (1024**2)
                print(f"  ✅ {fname}: {size_mb:.2f} MB")
                print(f"     Path: {fpath}")
            else:
                print(f"  ⚠️  {fname}: Not found")

        # Display summary stats
        if os.path.isfile(output_json):
            try:
                with open(output_json, "r") as f:
                    summary = json.load(f)

                print("\n📈 Validation Summary:")
                print(f"  • Total Rows: {summary.get('total_rows', 'N/A'):,}")
                print(f"  • Total Columns: {summary.get('total_columns', 'N/A')}")
                print(
                    f"  • Execution Time: {summary.get('execution_time_seconds', 'N/A')}s"
                )
                print(f"  • Imputed Columns: {len(summary.get('imputed_columns', []))}")
                print(
                    f"  • Rows with Imputation: {summary.get('rows_with_imputation', 'N/A'):,}"
                )

                # Show integrity issues if any
                integrity = summary.get("integrity_issues", {})
                if integrity:
                    print(f"\n⚠️  Integrity Issues Detected:")
                    for issue, details in integrity.items():
                        print(f"  • {issue}: {details}")

                print(
                    f"\n🎯 Reinforcement Signal: {summary.get('reinforcement_signal', '+10 (Success)')}"
                )

            except Exception as e:
                print(f"⚠️  Could not parse summary JSON: {e}")

        print("\n" + "=" * 80)
        print("✅ VALIDATION PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print(f"\nValidated dataset ready at: {output_csv}")
        print("You can now use this dataset for ML model training!")

    else:
        print(f"❌ Validation failed with exit code: {exit_code}")
        print("\n🔍 Troubleshooting:")
        print("  1. Check the Kaggle kernel logs above for detailed error messages")
        print("  2. Verify the input CSV has the correct 107-column schema")
        print("  3. Ensure sufficient Kaggle disk space (validated output is ~1.2GB)")
        print("  4. Check for any dataset-specific issues in the error logs")

        if os.path.isfile(f"{output_dir}/validation_error.json"):
            print(f"\n📄 Error report saved to: {output_dir}/validation_error.json")

        sys.exit(1)


if __name__ == "__main__":
    main()
