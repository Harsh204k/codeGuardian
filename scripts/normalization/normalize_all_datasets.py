#!/usr/bin/env python3
"""
Universal normalization script for all datasets.

This script:
1. Loads all processed JSONL files from individual datasets
2. Maps them into a standard unified schema
3. Fills missing fields with None or "unknown"
4. Harmonizes data types and formats
5. Optionally deduplicates records
6. Saves the unified dataset with statistics and schema documentation

Output:
- datasets/unified/processed_all.jsonl: All records in unified format
- datasets/unified/stats_summary.csv: Per-dataset statistics
- datasets/unified/schema.json: Schema documentation
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import (
    read_jsonl, write_jsonl, write_json, write_csv, 
    ensure_dir, ProgressWriter
)
from scripts.utils.schema_utils import (
    map_to_unified_schema, validate_record, 
    deduplicate_by_code_hash, save_schema_definition
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Dataset configurations
DATASETS = {
    'devign': {
        'path': 'devign/processed/raw_cleaned.jsonl',
        'field_mapping': {}  # Already in correct format from preprocessing
    },
    'zenodo': {
        'path': 'zenodo/processed/raw_cleaned.jsonl',
        'field_mapping': {}
    },
    'diversevul': {
        'path': 'diversevul/processed/raw_cleaned.jsonl',
        'field_mapping': {}
    },
    'github_ppakshad': {
        'path': 'github_ppakshad/processed/raw_cleaned.jsonl',
        'field_mapping': {}
    },
    'codexglue': {
        'path': 'codexglue_defect/processed/raw_cleaned.jsonl',
        'field_mapping': {}
    },
    'megavul': {
        'path': 'megavul/processed/raw_cleaned.jsonl',
        'field_mapping': {}
    },
    'juliet': {
        'path': 'juliet/processed/raw_cleaned.jsonl',
        'field_mapping': {}
    }
}


def load_dataset(dataset_name: str, dataset_path: Path, field_mapping: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Load and normalize records from a dataset.
    
    Args:
        dataset_name: Name of the dataset
        dataset_path: Path to processed JSONL file
        field_mapping: Field mapping for this dataset
        
    Returns:
        List of normalized records
    """
    logger.info(f"Loading {dataset_name} from {dataset_path}")
    
    if not dataset_path.exists():
        logger.warning(f"Dataset file not found: {dataset_path}")
        return []
    
    records = []
    errors = []
    
    for idx, record in enumerate(read_jsonl(str(dataset_path))):
        # Map to unified schema
        unified_record = map_to_unified_schema(
            record=record,
            dataset_name=dataset_name,
            index=idx,
            field_mapping=field_mapping
        )
        
        # Validate record
        is_valid, validation_errors = validate_record(unified_record)
        
        if is_valid:
            records.append(unified_record)
        else:
            errors.append({
                'dataset': dataset_name,
                'index': idx,
                'errors': validation_errors
            })
    
    logger.info(f"Loaded {len(records)} valid records from {dataset_name}")
    
    if errors:
        logger.warning(f"Skipped {len(errors)} invalid records from {dataset_name}")
        # Log first few errors for debugging
        for error in errors[:5]:
            logger.debug(f"Validation error: {error}")
    
    return records


def generate_dataset_stats(records: List[Dict[str, Any]], dataset_name: str) -> Dict[str, Any]:
    """
    Generate statistics for a single dataset.
    
    Args:
        records: List of records
        dataset_name: Name of the dataset
        
    Returns:
        Statistics dictionary
    """
    total = len(records)
    vulnerable = sum(1 for r in records if r['label'] == 1)
    
    # Language distribution
    languages = {}
    for record in records:
        lang = record.get('language', 'unknown')
        languages[lang] = languages.get(lang, 0) + 1
    
    # CWE coverage
    cwe_count = sum(1 for r in records if r.get('cwe_id'))
    unique_cwes = len(set(r['cwe_id'] for r in records if r.get('cwe_id')))
    
    # CVE coverage
    cve_count = sum(1 for r in records if r.get('cve_id'))
    
    return {
        'dataset': dataset_name,
        'total_records': total,
        'vulnerable': vulnerable,
        'non_vulnerable': total - vulnerable,
        'vulnerability_ratio': round(vulnerable / total, 4) if total > 0 else 0,
        'languages': len(languages),
        'top_language': max(languages.items(), key=lambda x: x[1])[0] if languages else 'unknown',
        'records_with_cwe': cwe_count,
        'unique_cwes': unique_cwes,
        'records_with_cve': cve_count,
        'avg_code_length': round(sum(len(r['code']) for r in records) / total) if total > 0 else 0
    }


def generate_unified_stats(all_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate overall statistics for the unified dataset.
    
    Args:
        all_records: All records from all datasets
        
    Returns:
        Overall statistics dictionary
    """
    total = len(all_records)
    vulnerable = sum(1 for r in all_records if r['label'] == 1)
    
    # Dataset distribution
    datasets = {}
    for record in all_records:
        ds = record.get('source_dataset', 'unknown')
        if ds not in datasets:
            datasets[ds] = {'total': 0, 'vulnerable': 0}
        datasets[ds]['total'] += 1
        if record['label'] == 1:
            datasets[ds]['vulnerable'] += 1
    
    # Language distribution
    languages = {}
    for record in all_records:
        lang = record.get('language', 'unknown')
        if lang not in languages:
            languages[lang] = {'total': 0, 'vulnerable': 0}
        languages[lang]['total'] += 1
        if record['label'] == 1:
            languages[lang]['vulnerable'] += 1
    
    # CWE distribution
    cwes = {}
    for record in all_records:
        cwe = record.get('cwe_id')
        if cwe:
            cwes[cwe] = cwes.get(cwe, 0) + 1
    
    # CVE count
    cve_count = sum(1 for r in all_records if r.get('cve_id'))
    
    # Project distribution
    projects = {}
    for record in all_records:
        proj = record.get('project')
        if proj:
            projects[proj] = projects.get(proj, 0) + 1
    
    return {
        'total_records': total,
        'vulnerable_records': vulnerable,
        'non_vulnerable_records': total - vulnerable,
        'vulnerability_ratio': round(vulnerable / total, 4) if total > 0 else 0,
        'datasets': datasets,
        'languages': languages,
        'unique_cwes': len(cwes),
        'top_cwes': sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:20],
        'records_with_cve': cve_count,
        'unique_projects': len(projects),
        'top_projects': sorted(projects.items(), key=lambda x: x[1], reverse=True)[:20],
        'avg_code_length': round(sum(len(r['code']) for r in all_records) / total) if total > 0 else 0
    }


def main():
    parser = argparse.ArgumentParser(description='Normalize all datasets into unified format')
    parser.add_argument(
        '--datasets-dir',
        type=str,
        default='../../datasets',
        help='Root directory containing all datasets'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='../../datasets/unified',
        help='Output directory for unified dataset'
    )
    parser.add_argument(
        '--datasets',
        nargs='+',
        default=None,
        help='Specific datasets to include (default: all available)'
    )
    parser.add_argument(
        '--deduplicate',
        action='store_true',
        help='Deduplicate records based on code hash'
    )
    parser.add_argument(
        '--max-records-per-dataset',
        type=int,
        default=None,
        help='Maximum records per dataset (for testing)'
    )
    
    args = parser.parse_args()
    
    # Convert to absolute paths
    script_dir = Path(__file__).parent
    datasets_dir = (script_dir / args.datasets_dir).resolve()
    output_dir = (script_dir / args.output_dir).resolve()
    
    logger.info("="*60)
    logger.info("STARTING UNIFIED DATASET NORMALIZATION")
    logger.info("="*60)
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    # Determine which datasets to process
    datasets_to_process = args.datasets if args.datasets else list(DATASETS.keys())
    
    logger.info(f"Processing {len(datasets_to_process)} datasets: {', '.join(datasets_to_process)}")
    
    all_records = []
    dataset_stats_list = []
    
    # Load each dataset
    for dataset_name in datasets_to_process:
        if dataset_name not in DATASETS:
            logger.warning(f"Unknown dataset: {dataset_name}")
            continue
        
        config = DATASETS[dataset_name]
        dataset_path = datasets_dir / config['path']
        
        # Load and normalize records
        records = load_dataset(
            dataset_name=dataset_name,
            dataset_path=dataset_path,
            field_mapping=config['field_mapping']
        )
        
        # Limit records if specified
        if args.max_records_per_dataset and len(records) > args.max_records_per_dataset:
            logger.info(f"Limiting {dataset_name} to {args.max_records_per_dataset} records")
            records = records[:args.max_records_per_dataset]
        
        if records:
            # Generate dataset-specific stats
            stats = generate_dataset_stats(records, dataset_name)
            dataset_stats_list.append(stats)
            
            all_records.extend(records)
        else:
            logger.warning(f"No records loaded from {dataset_name}")
    
    logger.info(f"\nLoaded {len(all_records)} total records from {len(dataset_stats_list)} datasets")
    
    # Deduplicate if requested
    if args.deduplicate:
        logger.info("Deduplicating records...")
        original_count = len(all_records)
        all_records = deduplicate_by_code_hash(all_records)
        logger.info(f"Removed {original_count - len(all_records)} duplicate records")
    
    # Save unified dataset
    output_file = output_dir / "processed_all.jsonl"
    logger.info(f"\nSaving {len(all_records)} records to {output_file}")
    write_jsonl(all_records, str(output_file))
    
    # Generate and save overall statistics
    unified_stats = generate_unified_stats(all_records)
    stats_file = output_dir / "stats_overall.json"
    write_json(unified_stats, str(stats_file))
    logger.info(f"Overall statistics saved to {stats_file}")
    
    # Save per-dataset statistics as CSV
    if dataset_stats_list:
        stats_csv_file = output_dir / "stats_summary.csv"
        write_csv(dataset_stats_list, str(stats_csv_file))
        logger.info(f"Per-dataset statistics saved to {stats_csv_file}")
    
    # Save schema definition
    schema_file = output_dir / "schema.json"
    save_schema_definition(str(schema_file))
    logger.info(f"Schema definition saved to {schema_file}")
    
    # Print summary report
    print("\n" + "="*60)
    print("UNIFIED DATASET NORMALIZATION COMPLETE")
    print("="*60)
    print(f"\n📊 OVERALL STATISTICS:")
    print(f"  Total records: {unified_stats['total_records']:,}")
    print(f"  Vulnerable: {unified_stats['vulnerable_records']:,} ({unified_stats['vulnerability_ratio']:.2%})")
    print(f"  Non-vulnerable: {unified_stats['non_vulnerable_records']:,}")
    print(f"  Datasets included: {len(unified_stats['datasets'])}")
    print(f"  Languages: {len(unified_stats['languages'])}")
    print(f"  Unique CWEs: {unified_stats['unique_cwes']}")
    print(f"  Records with CVE: {unified_stats['records_with_cve']:,}")
    print(f"  Unique projects: {unified_stats['unique_projects']}")
    
    print(f"\n📁 PER-DATASET BREAKDOWN:")
    for ds_stats in sorted(dataset_stats_list, key=lambda x: x['total_records'], reverse=True):
        print(f"  {ds_stats['dataset']:20s}: {ds_stats['total_records']:6,} records " +
              f"({ds_stats['vulnerability_ratio']:.2%} vulnerable, " +
              f"{ds_stats['languages']} lang(s))")
    
    print(f"\n🔝 TOP 10 LANGUAGES:")
    for lang, counts in sorted(unified_stats['languages'].items(), 
                               key=lambda x: x[1]['total'], reverse=True)[:10]:
        print(f"  {lang:15s}: {counts['total']:6,} records ({counts['vulnerable']:,} vulnerable)")
    
    print(f"\n🔝 TOP 10 CWEs:")
    for cwe, count in unified_stats['top_cwes'][:10]:
        print(f"  {cwe:15s}: {count:,} occurrences")
    
    print(f"\n💾 OUTPUT FILES:")
    print(f"  {output_file}")
    print(f"  {stats_file}")
    print(f"  {stats_csv_file}")
    print(f"  {schema_file}")
    
    print("\n" + "="*60)
    print("✅ Pipeline ready for downstream training!")
    print("="*60 + "\n")


def run(args=None):
    """
    Entry point for dynamic pipeline orchestrator.
    
    Args:
        args: Optional argparse.Namespace object with configuration.
              If None, will parse from sys.argv (CLI mode).
    """
    main()


if __name__ == "__main__":
    main()

