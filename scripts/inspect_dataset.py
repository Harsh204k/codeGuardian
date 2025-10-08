#!/usr/bin/env python3
"""
Dataset inspection and query tool.

This utility script helps inspect and query the processed datasets.
Useful for exploring data characteristics, filtering records, and debugging.

Examples:
    # Show dataset statistics
    python inspect_dataset.py --stats

    # Show sample records
    python inspect_dataset.py --samples 10

    # Filter by language
    python inspect_dataset.py --filter-language Python --samples 5

    # Filter by CWE
    python inspect_dataset.py --filter-cwe CWE-79 --samples 5

    # Show vulnerable records only
    python inspect_dataset.py --vulnerable-only --samples 10

    # Export filtered results
    python inspect_dataset.py --filter-language Java --output filtered_java.jsonl

    # Filter by dataset (new schema field: source_dataset)
    python inspect_dataset.py --filter-dataset devign --samples 5
"""

import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.io_utils import read_jsonl, write_jsonl, write_json


def load_dataset(dataset_path: str) -> List[Dict[str, Any]]:
    """Load dataset from JSONL file."""
    print(f"Loading dataset from {dataset_path}...")
    records = list(read_jsonl(dataset_path))
    print(f"Loaded {len(records)} records")
    return records


def show_statistics(records: List[Dict[str, Any]]):
    """Display comprehensive statistics about the dataset."""
    total = len(records)
    
    if total == 0:
        print("No records to analyze")
        return
    
    # Basic counts
    vulnerable = sum(1 for r in records if r.get('label') == 1)
    non_vulnerable = total - vulnerable
    
    # Language distribution
    languages = Counter(r.get('language', 'unknown') for r in records)
    
    # Dataset distribution
    datasets = Counter(r.get('source_dataset', 'unknown') for r in records)
    
    # CWE distribution
    cwes = Counter(r.get('cwe_id') for r in records if r.get('cwe_id'))
    cwe_count = sum(1 for r in records if r.get('cwe_id'))
    
    # CVE count
    cve_count = sum(1 for r in records if r.get('cve_id'))
    
    # Code length statistics
    code_lengths = [len(r.get('code', '')) for r in records]
    avg_length = sum(code_lengths) / len(code_lengths)
    min_length = min(code_lengths)
    max_length = max(code_lengths)
    
    # Project distribution
    projects = Counter(r.get('project') for r in records if r.get('project'))
    
    # Print statistics
    print("\n" + "="*60)
    print("DATASET STATISTICS")
    print("="*60)
    
    print(f"\n📊 OVERALL:")
    print(f"  Total records: {total:,}")
    print(f"  Vulnerable: {vulnerable:,} ({vulnerable/total*100:.1f}%)")
    print(f"  Non-vulnerable: {non_vulnerable:,} ({non_vulnerable/total*100:.1f}%)")
    
    print(f"\n🗂️  DATASETS ({len(datasets)} unique):")
    for dataset, count in datasets.most_common(10):
        print(f"  {dataset:20s}: {count:6,} records ({count/total*100:.1f}%)")
    
    print(f"\n🌐 LANGUAGES ({len(languages)} unique):")
    for lang, count in languages.most_common(10):
        print(f"  {lang:20s}: {count:6,} records ({count/total*100:.1f}%)")
    
    print(f"\n🔒 CWEs ({len(cwes)} unique, {cwe_count} records with CWE):")
    for cwe, count in cwes.most_common(10):
        print(f"  {cwe:20s}: {count:6,} occurrences")
    
    print(f"\n🏷️  CVE COVERAGE:")
    print(f"  Records with CVE: {cve_count:,} ({cve_count/total*100:.1f}%)")
    
    print(f"\n📝 CODE LENGTH:")
    print(f"  Average: {avg_length:.0f} characters")
    print(f"  Min: {min_length} characters")
    print(f"  Max: {max_length:,} characters")
    
    if projects:
        print(f"\n🔧 TOP PROJECTS ({len(projects)} unique):")
        for project, count in projects.most_common(5):
            print(f"  {project:30s}: {count:6,} records")
    
    print("="*60 + "\n")


def show_samples(records: List[Dict[str, Any]], count: int = 5):
    """Display sample records."""
    print(f"\n{'='*60}")
    print(f"SAMPLE RECORDS (showing {min(count, len(records))} of {len(records)})")
    print("="*60)
    
    for i, record in enumerate(records[:count], 1):
        print(f"\n--- Record {i} ---")
        print(f"ID: {record.get('id', 'N/A')}")
        print(f"Dataset: {record.get('source_dataset', 'N/A')}")
        print(f"Language: {record.get('language', 'N/A')}")
        print(f"Vulnerable: {'Yes' if record.get('label') == 1 else 'No'}")
        print(f"CWE: {record.get('cwe_id', 'N/A')}")
        print(f"CVE: {record.get('cve_id', 'N/A')}")
        print(f"Project: {record.get('project', 'N/A')}")
        print(f"File: {record.get('file_name', 'N/A')}")
        print(f"Function: {record.get('func_name', 'N/A')}")
        print(f"Code length: {len(record.get('code', ''))} characters")
        
        code = record.get('code', '')
        if len(code) > 200:
            print(f"Code preview:\n{code[:200]}...")
        else:
            print(f"Code:\n{code}")
    
    print("="*60 + "\n")


def filter_records(
    records: List[Dict[str, Any]],
    language: Optional[str] = None,
    dataset: Optional[str] = None,
    cwe: Optional[str] = None,
    vulnerable_only: bool = False,
    non_vulnerable_only: bool = False,
    has_cwe: bool = False,
    has_cve: bool = False
) -> List[Dict[str, Any]]:
    """Filter records based on criteria."""
    filtered = records
    
    if language:
        filtered = [r for r in filtered if r.get('language', '').lower() == language.lower()]
        print(f"Filtered by language '{language}': {len(filtered)} records")
    
    if dataset:
        filtered = [r for r in filtered if r.get('source_dataset', '').lower() == dataset.lower()]
        print(f"Filtered by dataset '{dataset}': {len(filtered)} records")
    
    if cwe:
        filtered = [r for r in filtered if r.get('cwe_id') == cwe]
        print(f"Filtered by CWE '{cwe}': {len(filtered)} records")
    
    if vulnerable_only:
        filtered = [r for r in filtered if r.get('label') == 1]
        print(f"Filtered to vulnerable only: {len(filtered)} records")
    
    if non_vulnerable_only:
        filtered = [r for r in filtered if r.get('label') == 0]
        print(f"Filtered to non-vulnerable only: {len(filtered)} records")
    
    if has_cwe:
        filtered = [r for r in filtered if r.get('cwe_id')]
        print(f"Filtered to records with CWE: {len(filtered)} records")
    
    if has_cve:
        filtered = [r for r in filtered if r.get('cve_id')]
        print(f"Filtered to records with CVE: {len(filtered)} records")
    
    return filtered


def main():
    parser = argparse.ArgumentParser(
        description='Inspect and query processed datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--dataset',
        type=str,
        default='../../datasets/unified/processed_all.jsonl',
        help='Path to dataset JSONL file'
    )
    
    # Display options
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show dataset statistics'
    )
    parser.add_argument(
        '--samples',
        type=int,
        default=None,
        help='Number of sample records to display'
    )
    
    # Filter options
    parser.add_argument(
        '--filter-language',
        type=str,
        help='Filter by programming language'
    )
    parser.add_argument(
        '--filter-dataset',
        type=str,
        help='Filter by dataset name'
    )
    parser.add_argument(
        '--filter-cwe',
        type=str,
        help='Filter by CWE ID (e.g., CWE-79)'
    )
    parser.add_argument(
        '--vulnerable-only',
        action='store_true',
        help='Show only vulnerable records'
    )
    parser.add_argument(
        '--non-vulnerable-only',
        action='store_true',
        help='Show only non-vulnerable records'
    )
    parser.add_argument(
        '--has-cwe',
        action='store_true',
        help='Show only records with CWE information'
    )
    parser.add_argument(
        '--has-cve',
        action='store_true',
        help='Show only records with CVE information'
    )
    
    # Output options
    parser.add_argument(
        '--output',
        type=str,
        help='Export filtered results to file'
    )
    parser.add_argument(
        '--output-stats',
        type=str,
        help='Export statistics to JSON file'
    )
    
    args = parser.parse_args()
    
    # Resolve dataset path
    script_dir = Path(__file__).parent
    dataset_path = (script_dir / args.dataset).resolve()
    
    if not dataset_path.exists():
        print(f"Error: Dataset file not found: {dataset_path}")
        sys.exit(1)
    
    # Load dataset
    records = load_dataset(str(dataset_path))
    
    if not records:
        print("No records found in dataset")
        sys.exit(1)
    
    # Apply filters
    filtered_records = filter_records(
        records,
        language=args.filter_language,
        dataset=args.filter_dataset,
        cwe=args.filter_cwe,
        vulnerable_only=args.vulnerable_only,
        non_vulnerable_only=args.non_vulnerable_only,
        has_cwe=args.has_cwe,
        has_cve=args.has_cve
    )
    
    # Show statistics
    if args.stats or (not args.samples and not args.output):
        show_statistics(filtered_records)
    
    # Show samples
    if args.samples:
        show_samples(filtered_records, args.samples)
    
    # Export filtered results
    if args.output:
        output_path = Path(args.output)
        print(f"\nExporting {len(filtered_records)} filtered records to {output_path}")
        write_jsonl(filtered_records, str(output_path))
        print("✅ Export complete")
    
    # Export statistics
    if args.output_stats:
        # Generate statistics as JSON
        stats = {
            "total_records": len(filtered_records),
            "vulnerable": sum(1 for r in filtered_records if r.get('label') == 1),
            "languages": dict(Counter(r.get('language', 'unknown') for r in filtered_records)),
            "datasets": dict(Counter(r.get('source_dataset', 'unknown') for r in filtered_records)),
            "cwes": dict(Counter(r.get('cwe_id') for r in filtered_records if r.get('cwe_id')))
        }
        write_json(stats, args.output_stats)
        print(f"✅ Statistics exported to {args.output_stats}")


if __name__ == "__main__":
    main()
