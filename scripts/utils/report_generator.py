#!/usr/bin/env python3
"""
Pipeline Report Generator
==========================

Automatically generates comprehensive PIPELINE_REPORT.md with:
- Summary statistics
- Dataset breakdown
- Validation results
- Feature coverage
- Performance metrics
- Visualizations (ASCII charts for terminal compatibility)
- Recommendations

Usage:
    from scripts.utils.report_generator import generate_pipeline_report

    generate_pipeline_report(
        validation_stats=validation_stats,
        feature_stats=feature_stats,
        output_path="PIPELINE_REPORT.md"
    )

Author: CodeGuardian Team
Version: 3.1.0
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict


# ====================================================================
# ASCII VISUALIZATION UTILITIES
# ====================================================================

def create_bar_chart(data: Dict[str, int], max_width: int = 50, title: str = "") -> str:
    """
    Create an ASCII bar chart.

    Args:
        data: Dictionary of labels to values
        max_width: Maximum bar width in characters
        title: Chart title

    Returns:
        ASCII bar chart string
    """
    if not data:
        return "No data available\n"

    chart = []
    if title:
        chart.append(f"\n{title}")
        chart.append("=" * len(title))

    # Find max value for scaling
    max_value = max(data.values()) if data else 1

    # Sort by value (descending)
    sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)

    for label, value in sorted_data:
        # Calculate bar length
        bar_length = int((value / max_value) * max_width) if max_value > 0 else 0
        bar = "█" * bar_length

        # Format with padding
        chart.append(f"{label:<25} {bar} {value:,}")

    return "\n".join(chart) + "\n"


def create_pie_chart_ascii(data: Dict[str, int], title: str = "") -> str:
    """
    Create an ASCII pie chart representation.

    Args:
        data: Dictionary of labels to values
        title: Chart title

    Returns:
        ASCII pie chart string
    """
    if not data:
        return "No data available\n"

    chart = []
    if title:
        chart.append(f"\n{title}")
        chart.append("=" * len(title))

    total = sum(data.values())

    # Sort by value (descending)
    sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)

    for label, value in sorted_data:
        percentage = (value / total * 100) if total > 0 else 0
        bar_length = int(percentage / 2)  # 50 chars = 100%
        bar = "●" * bar_length

        chart.append(f"{label:<25} {bar} {percentage:>5.1f}% ({value:,})")

    return "\n".join(chart) + "\n"


# ====================================================================
# REPORT SECTIONS
# ====================================================================

def generate_summary_section(stats: Dict[str, Any]) -> str:
    """Generate summary section."""
    section = []
    section.append("## 📊 Summary\n")

    section.append("### Pipeline Execution")
    section.append(f"- **Start Time:** {stats.get('start_time', 'N/A')}")
    section.append(f"- **End Time:** {stats.get('end_time', 'N/A')}")
    section.append(f"- **Total Records Processed:** {stats.get('total_records', 0):,}")
    section.append(f"- **Valid Records:** {stats.get('valid_records', 0):,}")
    section.append(f"- **Invalid Records:** {stats.get('invalid_records', 0):,}")

    # Overall pass rate
    pass_rate = stats.get('validation_pass_rate', 0) * 100
    pass_emoji = "✅" if pass_rate >= 98 else "⚠️"
    section.append(f"- **Validation Pass Rate:** {pass_emoji} {pass_rate:.2f}%\n")

    return "\n".join(section) + "\n"


def generate_dataset_section(stats: Dict[str, Any]) -> str:
    """Generate dataset statistics section."""
    section = []
    section.append("## 📁 Dataset Statistics\n")

    # Dataset distribution
    if 'dataset_counts' in stats or 'errors_by_dataset' in stats:
        dataset_data = stats.get('dataset_counts', stats.get('errors_by_dataset', {}))

        if isinstance(dataset_data, dict):
            # Handle nested structure (errors_by_dataset)
            if dataset_data and isinstance(list(dataset_data.values())[0], dict):
                dataset_data = {k: sum(v.values()) if isinstance(v, dict) else v
                               for k, v in dataset_data.items()}

            section.append(create_bar_chart(
                dataset_data,
                title="Dataset Distribution"
            ))

    # Language distribution
    if 'language_counts' in stats:
        section.append(create_bar_chart(
            stats['language_counts'],
            title="Language Distribution"
        ))

    return "\n".join(section) + "\n"


def generate_validation_section(stats: Dict[str, Any]) -> str:
    """Generate validation results section."""
    section = []
    section.append("## ✅ Validation Results\n")

    # Overall stats
    section.append("### Overall Validation")
    section.append(f"- **Total Records:** {stats.get('total_records', 0):,}")
    section.append(f"- **Valid Records:** {stats.get('valid_records', 0):,}")
    section.append(f"- **Invalid Records:** {stats.get('invalid_records', 0):,}")
    section.append(f"- **Duplicates Removed:** {stats.get('duplicates_removed', 0):,}")

    if 'repaired_records' in stats:
        section.append(f"- **Auto-Repaired:** {stats['repaired_records']:,}")

    section.append("")

    # Error categories
    if 'error_counts' in stats or 'error_categories' in stats:
        error_data = stats.get('error_counts', stats.get('error_categories', {}))
        if error_data:
            section.append("### Error Categories")
            section.append(create_bar_chart(
                error_data,
                title="Top Validation Errors"
            ))

    # Field statistics
    if 'field_stats' in stats:
        section.append("### Field Statistics")
        section.append("\n| Field | Total | Null | Empty | Invalid Type |")
        section.append("|-------|-------|------|-------|--------------|")

        for field, field_stats in sorted(stats['field_stats'].items()):
            total = field_stats.get('total', 0)
            null = field_stats.get('null', 0)
            empty = field_stats.get('empty', 0)
            invalid = field_stats.get('invalid_type', 0)

            section.append(f"| {field} | {total:,} | {null:,} | {empty:,} | {invalid:,} |")

        section.append("")

    # Sample errors
    if 'sample_errors' in stats and stats['sample_errors']:
        section.append("### Sample Validation Errors (First 5)")
        for i, error in enumerate(stats['sample_errors'][:5], 1):
            section.append(f"\n**Error {i}:**")
            section.append(f"- Record ID: `{error.get('record_id')}`")
            section.append(f"- Dataset: `{error.get('dataset')}`")
            section.append(f"- Errors: {', '.join(error.get('errors', []))}")
        section.append("")

    return "\n".join(section) + "\n"


def generate_feature_section(stats: Dict[str, Any]) -> str:
    """Generate feature coverage section."""
    section = []
    section.append("## 🔧 Feature Engineering\n")

    section.append("### Extraction Summary")
    section.append(f"- **Total Records:** {stats.get('total_records', 0):,}")
    section.append(f"- **Successful Extractions:** {stats.get('successful_extractions', 0):,}")
    section.append(f"- **Failed Extractions:** {stats.get('failed_extractions', 0):,}")

    success_rate = stats.get('success_rate', 0) * 100
    section.append(f"- **Success Rate:** {success_rate:.2f}%\n")

    # Feature statistics
    if 'feature_stats' in stats:
        section.append("### Feature Statistics (Top 10)\n")
        section.append("| Feature | Min | Max | Avg |")
        section.append("|---------|-----|-----|-----|")

        # Sort by average value and take top 10
        sorted_features = sorted(
            stats['feature_stats'].items(),
            key=lambda x: x[1].get('avg', 0),
            reverse=True
        )[:10]

        for feature, feature_stats in sorted_features:
            min_val = feature_stats.get('min', 0)
            max_val = feature_stats.get('max', 0)
            avg_val = feature_stats.get('avg', 0)

            section.append(f"| {feature} | {min_val:.2f} | {max_val:.2f} | {avg_val:.2f} |")

        section.append("")

    return "\n".join(section) + "\n"


def generate_performance_section(stats: Dict[str, Any]) -> str:
    """Generate performance metrics section."""
    section = []
    section.append("## ⚡ Performance Metrics\n")

    # Calculate duration
    start_time = stats.get('start_time')
    end_time = stats.get('end_time')

    if start_time and end_time:
        try:
            start_dt = datetime.fromisoformat(start_time)
            end_dt = datetime.fromisoformat(end_time)
            duration = (end_dt - start_dt).total_seconds()

            section.append(f"- **Total Duration:** {duration:.2f}s")

            # Throughput
            total_records = stats.get('total_records', 0)
            if total_records > 0 and duration > 0:
                throughput = total_records / duration
                section.append(f"- **Throughput:** {throughput:.2f} records/sec")
                section.append(f"- **Average Time per Record:** {(duration/total_records)*1000:.2f}ms")
        except:
            pass

    section.append("")

    return "\n".join(section) + "\n"


def generate_recommendations_section(stats: Dict[str, Any]) -> str:
    """Generate recommendations section."""
    section = []
    section.append("## 💡 Recommendations\n")

    recommendations = []

    # Check validation pass rate
    pass_rate = stats.get('validation_pass_rate', 1.0)
    if pass_rate < 0.98:
        recommendations.append(
            "⚠️  **Low Validation Pass Rate:** Review validation errors and improve data quality. "
            f"Current: {pass_rate*100:.2f}%, Target: ≥98%"
        )

    # Check for duplicates
    duplicates = stats.get('duplicates_removed', 0)
    total = stats.get('total_records', 1)
    dup_rate = duplicates / total if total > 0 else 0
    if dup_rate > 0.05:
        recommendations.append(
            f"⚠️  **High Duplicate Rate:** {dup_rate*100:.2f}% duplicates detected. "
            "Consider improving upstream data collection."
        )

    # Check for failed feature extractions
    failed = stats.get('failed_extractions', 0)
    if failed > 0:
        recommendations.append(
            f"⚠️  **Feature Extraction Failures:** {failed:,} records failed feature extraction. "
            "Review code quality or add error handling."
        )

    # Check for imbalanced datasets
    if 'dataset_counts' in stats:
        dataset_counts = stats['dataset_counts']
        if len(dataset_counts) > 1:
            min_count = min(dataset_counts.values())
            max_count = max(dataset_counts.values())
            if max_count > min_count * 10:
                recommendations.append(
                    "⚠️  **Dataset Imbalance:** Some datasets are significantly larger than others. "
                    "Consider balanced sampling for model training."
                )

    # Check label balance
    if 'label_counts' in stats:
        label_counts = stats['label_counts']
        if len(label_counts) == 2:
            counts = list(label_counts.values())
            imbalance_ratio = max(counts) / min(counts) if min(counts) > 0 else float('inf')
            if imbalance_ratio > 4:
                recommendations.append(
                    f"⚠️  **Label Imbalance:** Class imbalance ratio is {imbalance_ratio:.2f}:1. "
                    "Consider using weighted loss or SMOTE for training."
                )

    # Success cases
    if not recommendations:
        recommendations.append("✅ **All Checks Passed:** Pipeline is healthy and ready for model training!")

    for rec in recommendations:
        section.append(f"- {rec}")

    section.append("")

    return "\n".join(section) + "\n"


# ====================================================================
# MAIN REPORT GENERATOR
# ====================================================================

def generate_pipeline_report(
    validation_stats: Optional[Dict[str, Any]] = None,
    feature_stats: Optional[Dict[str, Any]] = None,
    output_path: str = "PIPELINE_REPORT.md",
    additional_stats: Optional[Dict[str, Any]] = None
) -> None:
    """
    Generate comprehensive pipeline report.

    Args:
        validation_stats: Statistics from validation phase
        feature_stats: Statistics from feature engineering phase
        output_path: Output markdown file path
        additional_stats: Any additional statistics to include
    """
    # Merge all stats
    combined_stats = {}
    if validation_stats:
        combined_stats.update(validation_stats)
    if feature_stats:
        combined_stats.update(feature_stats)
    if additional_stats:
        combined_stats.update(additional_stats)

    # Generate report
    report = []

    # Header
    report.append("# CodeGuardian Phase 2 Pipeline Report\n")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report.append(f"**Version:** 3.1.0 (Production-Grade Enhanced)\n")
    report.append("---\n")

    # Sections
    report.append(generate_summary_section(combined_stats))
    report.append(generate_dataset_section(combined_stats))

    if validation_stats:
        report.append(generate_validation_section(combined_stats))

    if feature_stats:
        report.append(generate_feature_section(combined_stats))

    report.append(generate_performance_section(combined_stats))
    report.append(generate_recommendations_section(combined_stats))

    # Footer
    report.append("---\n")
    report.append("## 📚 Resources\n")
    report.append("- **Documentation:** See `docs/` directory for detailed guides")
    report.append("- **Configuration:** `configs/pipeline_config.yaml`")
    report.append("- **Logs:** `logs/phase2/` for execution logs")
    report.append("- **Profiling:** `logs/profiling/` for performance analysis\n")

    # Write to file
    output_path = Path(output_path) # type: ignore
    output_path.parent.mkdir(parents=True, exist_ok=True) # type: ignore

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(report))

    print(f"✅ Pipeline report generated: {output_path}")


def generate_report_from_files(
    validation_report: str = "datasets/unified/validation_report.json",
    feature_stats: str = "datasets/features/stats_features.json",
    output_path: str = "PIPELINE_REPORT.md"
) -> None:
    """
    Generate report by reading statistics from JSON files.

    Args:
        validation_report: Path to validation report JSON
        feature_stats: Path to feature statistics JSON
        output_path: Output markdown file path
    """
    validation_data = None
    feature_data = None

    # Load validation stats
    if Path(validation_report).exists():
        with open(validation_report, 'r') as f:
            validation_data = json.load(f)

    # Load feature stats
    if Path(feature_stats).exists():
        with open(feature_stats, 'r') as f:
            feature_data = json.load(f)

    generate_pipeline_report(
        validation_stats=validation_data,
        feature_stats=feature_data,
        output_path=output_path
    )


# ====================================================================
# CLI
# ====================================================================

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Generate pipeline report")
    parser.add_argument(
        "--validation-report",
        type=str,
        default="datasets/unified/validation_report.json",
        help="Path to validation report JSON"
    )
    parser.add_argument(
        "--feature-stats",
        type=str,
        default="datasets/features/stats_features.json",
        help="Path to feature statistics JSON"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="PIPELINE_REPORT.md",
        help="Output markdown file path"
    )

    args = parser.parse_args()

    generate_report_from_files(
        validation_report=args.validation_report,
        feature_stats=args.feature_stats,
        output_path=args.output
    )
