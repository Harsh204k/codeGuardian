#!/usr/bin/env python3
"""
Fast parallel preprocessing for DiverseVul dataset.

Uses multiprocessing to process records in parallel across CPU cores.
This is much faster than GPU for text/JSON processing tasks.

Usage:
    python prepare_diversevul_fast.py
    
Speed improvement: 3-5x faster on multi-core CPUs (Kaggle has 4 cores)
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import sys
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
from functools import partial

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_jsonl, write_jsonl, write_json, ensure_dir
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import (
    normalize_language, normalize_cwe_id, normalize_cve_id,
    map_to_unified_schema, validate_record, deduplicate_by_code_hash
)
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global metadata dictionary (shared across processes)
METADATA_DICT = {}


def load_metadata(metadata_path: str) -> Dict[str, Any]:
    """Load metadata from diversevul_metadata.json (JSONL format)."""
    try:
        metadata_dict = {}
        for record in read_jsonl(metadata_path):
            commit_id = record.get('commit_id', '')
            if commit_id:
                metadata_dict[commit_id] = record
        
        logger.info(f"Loaded metadata for {len(metadata_dict)} records")
        return metadata_dict
    except Exception as e:
        logger.warning(f"Could not load metadata: {e}")
        return {}


def process_single_record(args):
    """Process a single record (for parallel execution)."""
    record, idx = args
    
    try:
        # Extract fields
        code = record.get('func', record.get('code', record.get('source_code', '')))
        label = record.get('target', record.get('label', record.get('vulnerable', 0)))
        commit_id = record.get('commit_id', '')
        project = record.get('project', '')
        
        # CWE is a LIST in DiverseVul
        cwe_list = record.get('cwe', [])
        cwe_id = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else ''
        
        # Get metadata if available
        meta = METADATA_DICT.get(commit_id, {})
        cve_id = meta.get('CVE', '') if meta else ''
        
        if not cwe_id and 'CWE' in meta:
            cwe_id = meta['CWE']
        description = meta.get('bug_info', '') if meta else record.get('message', '')
        
        # Language inference
        language = 'C'
        if project:
            project_lower = project.lower()
            if any(x in project_lower for x in ['java', 'jdk', 'tomcat', 'spring']):
                language = 'Java'
            elif any(x in project_lower for x in ['node', 'javascript', 'js', 'npm']):
                language = 'JavaScript'
            elif any(x in project_lower for x in ['python', 'py', 'django', 'flask']):
                language = 'Python'
            elif any(x in project_lower for x in ['php']):
                language = 'PHP'
            elif any(x in project_lower for x in ['go', 'golang']):
                language = 'Go'
            elif any(x in project_lower for x in ['ruby', 'rails']):
                language = 'Ruby'
        
        # Sanitize code
        code = sanitize_code(code, language=language, normalize_ws=True)
        
        # Validate code
        if not is_valid_code(code, min_length=10):
            return None
        
        # Create intermediate record
        intermediate_record = {
            "code": code,
            "label": label,
            "language": language,
            "project": project if project else None,
            "commit_id": commit_id if commit_id else None,
            "cwe_id": cwe_id,
            "cve_id": cve_id,
            "file_name": None,
            "func_name": None,
            "description": description if description else None
        }
        
        # Map to unified schema
        unified_record = map_to_unified_schema(
            record=intermediate_record,
            dataset_name="diversevul",
            index=idx
        )
        
        # Add provenance
        unified_record['source_row_index'] = idx
        unified_record['source_file'] = 'diversevul.json'
        
        # Validate
        is_valid, errors = validate_record(unified_record, use_jsonschema=True)
        if not is_valid:
            return None
        
        return unified_record
        
    except Exception as e:
        return None


def process_batch_parallel(data: List[Dict], num_workers: int = None) -> List[Dict]:
    """Process records in parallel using multiprocessing."""
    if num_workers is None:
        num_workers = max(1, cpu_count() - 1)  # Leave 1 core free
    
    logger.info(f"🚀 Using {num_workers} parallel workers")
    
    # Prepare arguments for parallel processing
    args_list = [(record, idx) for idx, record in enumerate(data)]
    
    # Process in parallel with progress bar
    results = []
    with Pool(processes=num_workers) as pool:
        # Use imap_unordered for better performance with progress bar
        for result in tqdm(
            pool.imap_unordered(process_single_record, args_list, chunksize=100),
            total=len(args_list),
            desc="Processing DiverseVul (Parallel)",
            unit="records"
        ):
            if result is not None:
                results.append(result)
    
    return results


def generate_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate statistics for the processed dataset."""
    total = len(records)
    vulnerable = sum(1 for r in records if r['label'] == 1)
    non_vulnerable = total - vulnerable
    
    # Language distribution
    languages = {}
    for record in records:
        lang = record.get('language', 'unknown')
        if lang not in languages:
            languages[lang] = {'total': 0, 'vulnerable': 0}
        languages[lang]['total'] += 1
        if record['label'] == 1:
            languages[lang]['vulnerable'] += 1
    
    # CWE distribution
    cwes = {}
    for record in records:
        cwe = record.get('cwe_id')
        if cwe:
            cwes[cwe] = cwes.get(cwe, 0) + 1
    
    # CVE count
    cve_count = sum(1 for r in records if r.get('cve_id'))
    
    # Project distribution
    projects = {}
    for record in records:
        proj = record.get('project')
        if proj:
            projects[proj] = projects.get(proj, 0) + 1
    
    return {
        "dataset": "diversevul",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": languages,
        "unique_cwes": len(cwes),
        "top_cwes": sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:10],
        "records_with_cve": cve_count,
        "unique_projects": len(projects),
        "top_projects": sorted(projects.items(), key=lambda x: x[1], reverse=True)[:10],
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    global METADATA_DICT
    
    parser = argparse.ArgumentParser(description='Fast parallel preprocessing for DiverseVul')
    parser.add_argument('--input-dir', type=str, default=None)
    parser.add_argument('--output-dir', type=str, default=None)
    parser.add_argument('--max-records', type=int, default=None)
    parser.add_argument('--workers', type=int, default=None,
                       help='Number of parallel workers (default: CPU cores - 1)')
    
    args = parser.parse_args()
    
    # Print environment info
    print_environment_info()
    
    # Get paths
    if args.input_dir:
        input_dir = Path(args.input_dir).resolve()
    else:
        input_dir = get_dataset_path("diversevul")
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("diversevul/processed")
    
    if not input_dir.exists():
        logger.error(f"❌ Input directory not found: {input_dir}")
        return
    
    # Check for raw subdirectory
    raw_dir = input_dir / "raw"
    main_file_at_root = input_dir / "diversevul.json"
    main_file_in_raw = raw_dir / "diversevul.json"
    
    print(f"\n🔍 Checking for dataset files...")
    print(f"   raw/ subdirectory exists: {raw_dir.exists()}")
    print(f"   diversevul.json at root: {main_file_at_root.exists()}")
    print(f"   diversevul.json in raw/: {main_file_in_raw.exists()}")
    
    if raw_dir.exists() and not main_file_at_root.exists() and main_file_in_raw.exists():
        print(f"\n✅ Files detected in 'raw' subdirectory!")
        print(f"   Switching input directory to: {raw_dir}")
        input_dir = raw_dir
    
    print(f"\n📂 FINAL INPUT PATH: {input_dir}")
    print(f"📂 OUTPUT PATH: {output_dir}")
    
    ensure_dir(str(output_dir))
    
    # Load metadata (shared across all workers)
    metadata_path = input_dir / "diversevul_metadata.json"
    if metadata_path.exists():
        METADATA_DICT = load_metadata(str(metadata_path))
    
    # Load dataset
    dataset_path = input_dir / "diversevul.json"
    if not dataset_path.exists():
        logger.error(f"❌ Dataset file not found: {dataset_path}")
        return
    
    logger.info(f"📖 Loading dataset from {dataset_path}")
    data = list(read_jsonl(str(dataset_path), max_records=args.max_records))
    logger.info(f"✅ Loaded {len(data)} records")
    
    # Process in parallel
    logger.info(f"🚀 Starting parallel processing...")
    all_records = process_batch_parallel(data, num_workers=args.workers)
    logger.info(f"✅ Processed {len(all_records)} valid records")
    
    # Deduplicate
    logger.info(f"🔄 Deduplicating using SHA-256 hash...")
    unique_records = deduplicate_by_code_hash(all_records)
    logger.info(f"✅ Removed {len(all_records) - len(unique_records)} duplicates")
    
    # Save
    output_file = output_dir / "raw_cleaned.jsonl"
    logger.info(f"💾 Saving {len(unique_records)} records to {output_file}")
    write_jsonl(unique_records, str(output_file))
    
    # Generate stats
    stats = generate_stats(unique_records)
    stats_file = output_dir / "stats.json"
    write_json(stats, str(stats_file))
    
    # Print summary
    print("\n" + "="*60)
    print("DIVERSEVUL DATASET PROCESSING COMPLETE (FAST MODE)")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"Languages: {len(stats['languages'])}")
    print(f"Unique CWEs: {stats['unique_cwes']}")
    print(f"Records with CVE: {stats['records_with_cve']}")
    print(f"Unique projects: {stats['unique_projects']}")
    print(f"\nOutput saved to: {output_dir}")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
