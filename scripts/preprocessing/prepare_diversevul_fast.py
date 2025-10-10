#!/usr/bin/env python3
"""
Fast parallel preprocessing for DiverseVul dataset - ENHANCED VERSION.

Uses multiprocessing to process records in parallel across CPU cores.
This is much faster than GPU for text/JSON processing tasks.

NEW FEATURES:
- Label noise filtering for cleaner data
- Train/test/valid split information preservation
- Enhanced metadata enrichment
- Comprehensive statistics

Usage:
    python prepare_diversevul_fast.py                    # Process all records
    python prepare_diversevul_fast.py --filter-noisy     # Remove noisy labels
    python prepare_diversevul_fast.py --preserve-splits  # Keep original splits
    python prepare_diversevul_fast.py --workers 8        # Use 8 CPU cores
    
Speed improvement: 3-5x faster on multi-core CPUs (Kaggle has 4 cores)
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
import sys
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
from functools import partial

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_jsonl, write_jsonl, write_json, ensure_dir, read_csv
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

# Global dictionaries (shared across processes)
METADATA_DICT = {}
LABEL_NOISE_DICT = {}
SPLIT_INFO = {'train': set(), 'test': set(), 'valid': set()}
DATASET_PROVENANCE = {}  # Maps idx -> source_dataset (bigvul, crossvul, etc.)


def init_worker(metadata, noise, splits, provenance):
    """Initialize worker process with shared data."""
    global METADATA_DICT, LABEL_NOISE_DICT, SPLIT_INFO, DATASET_PROVENANCE
    METADATA_DICT = metadata
    LABEL_NOISE_DICT = noise
    SPLIT_INFO = splits
    DATASET_PROVENANCE = provenance


def load_metadata(metadata_path: str) -> Dict[str, Any]:
    """Load metadata from diversevul_metadata.json (JSONL format)."""
    try:
        metadata_dict = {}
        for record in read_jsonl(metadata_path):
            commit_id = record.get('commit_id', '')
            if commit_id:
                metadata_dict[commit_id] = record
        
        logger.info(f"✅ Loaded metadata for {len(metadata_dict)} records")
        return metadata_dict
    except Exception as e:
        logger.warning(f"⚠️  Could not load metadata: {e}")
        return {}


def load_label_noise_info(label_noise_dir: Path) -> Dict[str, bool]:
    """
    Load label noise information from ALL CSV files in label_noise directory.
    
    Args:
        label_noise_dir: Path to label_noise directory
        
    Returns:
        Dictionary mapping commit_id to is_noisy boolean
    """
    noisy_records = {}
    
    if not label_noise_dir.exists():
        logger.info("📊 No label noise directory found")
        return noisy_records
    
    try:
        # Load ALL CSV files in label_noise directory
        csv_files = list(label_noise_dir.glob("*.csv"))
        if not csv_files:
            logger.info("📊 No CSV files found in label_noise directory")
            return noisy_records
        
        logger.info(f"📊 Found {len(csv_files)} CSV files in label_noise directory")
        
        for file_path in csv_files:
            logger.info(f"   Loading {file_path.name}...")
            try:
                csv_content = read_csv(str(file_path))
                processed_count = 0
                
                for row in csv_content:
                    # Try multiple possible column names for record ID
                    record_id = row.get('Commit id / URL', 
                                      row.get('commit_id', 
                                      row.get('id', 
                                      row.get('record_id', 
                                      row.get('CVE_ID', '')))))
                    
                    # Check if record is marked as incorrect/noisy
                    # Look for markers in various columns
                    wrong_label = row.get('Wrong Label', row.get('wrong_label', ''))
                    irrelevant = row.get('Irrelevant', row.get('irrelevant', ''))
                    correct_label = row.get('Correct Label', row.get('correct_label', ''))
                    
                    if record_id and str(record_id).strip():
                        # Mark as noisy if:
                        # 1. "Wrong Label" column is marked (X or non-empty)
                        # 2. "Irrelevant" column is marked
                        # 3. "Correct Label" is explicitly empty/false
                        is_noisy = (
                            str(wrong_label).strip().upper() in ['X', 'TRUE', '1', 'YES'] or
                            str(irrelevant).strip().upper() in ['X', 'TRUE', '1', 'YES'] or
                            (correct_label and str(correct_label).strip().upper() in ['FALSE', '0', 'NO', ''])
                        )
                        
                        # Clean the record_id (remove URL parts if present)
                        clean_id = str(record_id).split('/')[-1].strip()
                        if clean_id:
                            noisy_records[clean_id] = is_noisy
                            processed_count += 1
                
                logger.info(f"      Processed {processed_count} records from {file_path.name}")
                
            except Exception as e:
                logger.warning(f"⚠️  Error reading {file_path.name}: {e}")
        
        noisy_count = sum(1 for v in noisy_records.values() if v)
        logger.info(f"✅ Loaded noise info for {len(noisy_records)} records ({noisy_count} marked as noisy)")
        
    except Exception as e:
        logger.warning(f"⚠️  Error loading label noise info: {e}")
    
    return noisy_records


def load_split_info(merged_splits_dir: Path) -> Dict[str, Set[int]]:
    """
    Load train/test/valid split information.
    
    Args:
        merged_splits_dir: Path to merged_splits directory
        
    Returns:
        Dictionary with 'train', 'test', 'valid' sets of indices
    """
    split_info = {'train': set(), 'test': set(), 'valid': set()}
    
    if not merged_splits_dir.exists():
        logger.info("📊 No merged_splits directory found")
        return split_info
    
    try:
        for split_name in ['train', 'test', 'valid']:
            split_file = merged_splits_dir / f"{split_name}.jsonl"
            if split_file.exists():
                indices = set()
                for record in read_jsonl(str(split_file)):
                    idx = record.get('idx')
                    if idx is not None:
                        indices.add(idx)
                split_info[split_name] = indices
                logger.info(f"✅ Loaded {len(indices)} indices for {split_name} split")
        
        total_in_splits = sum(len(v) for v in split_info.values())
        logger.info(f"📊 Total records in splits: {total_in_splits}")
        
    except Exception as e:
        logger.warning(f"⚠️  Error loading split info: {e}")
    
    return split_info


def load_dataset_provenance(merged_splits_dir: Path) -> Dict[int, str]:
    """
    Load dataset provenance information from dataset-specific split files.
    Identifies which original dataset (BigVul, CrossVul, etc.) each record came from.
    
    Args:
        merged_splits_dir: Path to merged_splits directory
        
    Returns:
        Dictionary mapping idx -> source_dataset name
    """
    provenance = {}
    
    if not merged_splits_dir.exists():
        logger.info("📊 No merged_splits directory found")
        return provenance
    
    # Dataset names to check
    datasets = ['bigvul', 'crossvul', 'cvefixes', 'devign', 'our', 'reveal']
    
    try:
        for dataset_name in datasets:
            total_indices = 0
            # Check train, test, and valid splits for each dataset
            for split_type in ['train', 'test', 'valid']:
                split_file = merged_splits_dir / f"{split_type}_{dataset_name}.jsonl"
                if split_file.exists():
                    for record in read_jsonl(str(split_file)):
                        idx = record.get('idx')
                        if idx is not None:
                            provenance[idx] = dataset_name
                            total_indices += 1
            
            if total_indices > 0:
                logger.info(f"✅ Loaded {total_indices} indices for '{dataset_name}' dataset")
        
        logger.info(f"📊 Total provenance mapping: {len(provenance)} records")
        
    except Exception as e:
        logger.warning(f"⚠️  Error loading dataset provenance: {e}")
    
    return provenance


def process_single_record(args):
    """Process a single record (for parallel execution)."""
    record, idx, filter_noisy = args
    
    try:
        # Extract fields
        code = record.get('func', record.get('code', record.get('source_code', '')))
        label = record.get('target', record.get('label', record.get('vulnerable', 0)))
        commit_id = record.get('commit_id', '')
        project = record.get('project', '')
        
        # Check for label noise and filter if requested
        if filter_noisy:
            record_key = commit_id or str(idx)
            is_noisy = LABEL_NOISE_DICT.get(record_key, False)
            if is_noisy:
                return None  # Skip noisy records
        
        # CWE is a LIST in DiverseVul
        cwe_list = record.get('cwe', [])
        cwe_id = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else ''
        
        # Get metadata if available
        meta = METADATA_DICT.get(commit_id, {})
        cve_id = meta.get('CVE', '') if meta else ''
        
        if not cwe_id and 'CWE' in meta:
            cwe_id = meta['CWE']
        description = meta.get('bug_info', '') if meta else record.get('message', '')
        
        # Get additional metadata fields
        commit_url = meta.get('commit_url', '') if meta else ''
        repo_url = meta.get('repo_url', '') if meta else ''
        
        # Determine split (train/test/valid) if split info is available
        split = None
        if SPLIT_INFO['train'] or SPLIT_INFO['test'] or SPLIT_INFO['valid']:
            if idx in SPLIT_INFO['train']:
                split = 'train'
            elif idx in SPLIT_INFO['test']:
                split = 'test'
            elif idx in SPLIT_INFO['valid']:
                split = 'valid'
        
        # Determine dataset provenance if available
        source_dataset = DATASET_PROVENANCE.get(idx, None)
        
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
        
        # Add enhanced provenance
        unified_record['source_row_index'] = idx
        unified_record['source_file'] = 'diversevul.json'
        unified_record['commit_url'] = commit_url if commit_url else None
        unified_record['repo_url'] = repo_url if repo_url else None
        
        # Add split information if available
        if split:
            unified_record['original_split'] = split
        
        # Add dataset provenance if available
        if source_dataset:
            unified_record['source_dataset'] = source_dataset
        
        # Validate
        is_valid, errors = validate_record(unified_record, use_jsonschema=True)
        if not is_valid:
            return None
        
        return unified_record
        
    except Exception as e:
        logger.debug(f"Error processing record {idx}: {str(e)}")
        return None


def process_batch_parallel(data: List[Dict], num_workers: int = None, filter_noisy: bool = False) -> List[Dict]:
    """Process records in parallel using multiprocessing."""
    if num_workers is None:
        num_workers = max(1, cpu_count() - 1)  # Leave 1 core free
    
    logger.info(f"🚀 Using {num_workers} parallel workers")
    if filter_noisy:
        logger.info(f"🔍 Label noise filtering: ENABLED")
    
    logger.info(f"📝 Total input records to process: {len(data)}")
    
    # Prepare arguments for parallel processing
    args_list = [(record, idx, filter_noisy) for idx, record in enumerate(data)]
    
    # Process in parallel with progress bar
    results = []
    none_count = 0
    
    # Initialize worker processes with shared data
    with Pool(
        processes=num_workers,
        initializer=init_worker,
        initargs=(METADATA_DICT, LABEL_NOISE_DICT, SPLIT_INFO, DATASET_PROVENANCE)
    ) as pool:
        # Use imap_unordered for better performance with progress bar
        for result in tqdm(
            pool.imap_unordered(process_single_record, args_list, chunksize=100),
            total=len(args_list),
            desc="Processing DiverseVul (Parallel)",
            unit="records"
        ):
            if result is not None:
                results.append(result)
            else:
                none_count += 1
    
    logger.info(f"✅ Successfully processed: {len(results)} records")
    logger.info(f"⚠️  Filtered/Failed: {none_count} records")
    
    return results


def generate_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate comprehensive statistics for the processed dataset."""
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
    
    # Split distribution
    splits = {}
    for record in records:
        split = record.get('original_split')
        if split:
            splits[split] = splits.get(split, 0) + 1
    
    # Dataset provenance distribution
    provenance = {}
    for record in records:
        source = record.get('source_dataset')
        if source:
            provenance[source] = provenance.get(source, 0) + 1
    
    # Records with enhanced metadata
    with_commit_url = sum(1 for r in records if r.get('commit_url'))
    with_repo_url = sum(1 for r in records if r.get('repo_url'))
    with_description = sum(1 for r in records if r.get('description'))
    
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
        "records_with_commit_url": with_commit_url,
        "records_with_repo_url": with_repo_url,
        "records_with_description": with_description,
        "unique_projects": len(projects),
        "top_projects": sorted(projects.items(), key=lambda x: x[1], reverse=True)[:10],
        "split_distribution": splits,
        "provenance_distribution": provenance,
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


def main():
    global METADATA_DICT, LABEL_NOISE_DICT, SPLIT_INFO, DATASET_PROVENANCE
    
    parser = argparse.ArgumentParser(
        description='Fast parallel preprocessing for DiverseVul - ENHANCED VERSION',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all records with default settings
  python prepare_diversevul_fast.py
  
  # Filter out noisy labels for cleaner data
  python prepare_diversevul_fast.py --filter-noisy
  
  # Preserve original train/test/valid split information
  python prepare_diversevul_fast.py --preserve-splits
  
  # Track dataset provenance (bigvul, crossvul, cvefixes, devign, our, reveal)
  python prepare_diversevul_fast.py --track-provenance
  
  # Use all enhancements together for MAXIMUM POWER
  python prepare_diversevul_fast.py --filter-noisy --preserve-splits --track-provenance --workers 8
        """
    )
    parser.add_argument('--input-dir', type=str, default=None,
                       help='Input directory containing raw DiverseVul files')
    parser.add_argument('--output-dir', type=str, default=None,
                       help='Output directory for processed files')
    parser.add_argument('--max-records', type=int, default=None,
                       help='Maximum number of records to process (for testing)')
    parser.add_argument('--workers', type=int, default=None,
                       help='Number of parallel workers (default: CPU cores - 1)')
    parser.add_argument('--filter-noisy', action='store_true',
                       help='Filter out records with label noise (improves quality)')
    parser.add_argument('--preserve-splits', action='store_true',
                       help='Preserve original train/test/valid split information')
    parser.add_argument('--track-provenance', action='store_true',
                       help='Track dataset provenance (bigvul, crossvul, cvefixes, devign, our, reveal)')
    
    args = parser.parse_args()
    
    # Print environment info
    print("\n" + "="*70)
    print("🚀 DIVERSEVUL ENHANCED PREPROCESSING (FAST MODE)")
    print("="*70)
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
    print(f"\n📊 Loading enrichment data...")
    metadata_path = input_dir / "diversevul_metadata.json"
    if metadata_path.exists():
        METADATA_DICT = load_metadata(str(metadata_path))
    else:
        logger.warning("⚠️  Metadata file not found - CVE/CWE enrichment unavailable")
    
    # Load label noise info if filtering is enabled
    if args.filter_noisy:
        label_noise_dir = input_dir / "label_noise"
        if label_noise_dir.exists():
            LABEL_NOISE_DICT = load_label_noise_info(label_noise_dir)
            if LABEL_NOISE_DICT:
                logger.info(f"✅ Label noise filtering ENABLED ({len(LABEL_NOISE_DICT)} records marked)")
            else:
                logger.warning("⚠️  No label noise data found - filtering disabled")
        else:
            logger.warning("⚠️  label_noise/ directory not found - filtering disabled")
    
    # Load split information if preservation is enabled
    if args.preserve_splits:
        merged_splits_dir = input_dir / "merged_splits"
        if merged_splits_dir.exists():
            SPLIT_INFO = load_split_info(merged_splits_dir)
            total_in_splits = sum(len(v) for v in SPLIT_INFO.values())
            if total_in_splits > 0:
                logger.info(f"✅ Split preservation ENABLED (train: {len(SPLIT_INFO['train'])}, "
                          f"test: {len(SPLIT_INFO['test'])}, valid: {len(SPLIT_INFO['valid'])})")
            else:
                logger.warning("⚠️  No split data found - preservation disabled")
        else:
            logger.warning("⚠️  merged_splits/ directory not found - preservation disabled")
    
    # Load dataset provenance if tracking is enabled
    if args.track_provenance:
        merged_splits_dir = input_dir / "merged_splits"
        if merged_splits_dir.exists():
            DATASET_PROVENANCE = load_dataset_provenance(merged_splits_dir)
            if DATASET_PROVENANCE:
                logger.info(f"✅ Dataset provenance tracking ENABLED ({len(DATASET_PROVENANCE)} records tracked)")
            else:
                logger.warning("⚠️  No provenance data found - tracking disabled")
        else:
            logger.warning("⚠️  merged_splits/ directory not found - tracking disabled")
    
    # Load dataset
    dataset_path = input_dir / "diversevul.json"
    if not dataset_path.exists():
        logger.error(f"❌ Dataset file not found: {dataset_path}")
        return
    
    logger.info(f"\n📖 Loading dataset from {dataset_path}")
    data = list(read_jsonl(str(dataset_path), max_records=args.max_records))
    logger.info(f"✅ Loaded {len(data)} records")
    
    if len(data) == 0:
        logger.error(f"❌ No data loaded from {dataset_path}! File might be empty or corrupted.")
        logger.info(f"🔍 Checking file size: {dataset_path.stat().st_size} bytes")
        return
    
    # Show sample of first record for debugging
    logger.info(f"📋 Sample record keys: {list(data[0].keys())}")
    
    # Process in parallel
    logger.info(f"\n🚀 Starting parallel processing...")
    all_records = process_batch_parallel(data, num_workers=args.workers, filter_noisy=args.filter_noisy)
    logger.info(f"✅ Processed {len(all_records)} valid records")
    
    if args.filter_noisy and LABEL_NOISE_DICT:
        filtered_count = len(data) - len(all_records)
        logger.info(f"🔍 Filtered out {filtered_count} records due to noise/validation")
    
    # Deduplicate
    logger.info(f"\n🔄 Deduplicating using SHA-256 hash...")
    unique_records = deduplicate_by_code_hash(all_records)
    duplicates_removed = len(all_records) - len(unique_records)
    logger.info(f"✅ Removed {duplicates_removed} duplicates")
    
    # Save
    output_file = output_dir / "raw_cleaned.jsonl"
    logger.info(f"\n💾 Saving {len(unique_records)} records to {output_file}")
    write_jsonl(unique_records, str(output_file))
    
    # Generate comprehensive stats
    logger.info(f"📊 Generating statistics...")
    stats = generate_stats(unique_records)
    stats_file = output_dir / "stats.json"
    write_json(stats, str(stats_file))
    
    # Print summary
    print("\n" + "="*70)
    print("✅ DIVERSEVUL DATASET PROCESSING COMPLETE (ENHANCED FAST MODE)")
    print("="*70)
    print(f"\n📊 DATASET STATISTICS:")
    print(f"   Total records: {stats['total_records']:,}")
    print(f"   Vulnerable: {stats['vulnerable_records']:,} ({stats['vulnerability_ratio']:.2%})")
    print(f"   Non-vulnerable: {stats['non_vulnerable_records']:,}")
    print(f"\n🏷️  METADATA ENRICHMENT:")
    print(f"   Records with CWE: {stats['unique_cwes']:,} unique CWEs")
    print(f"   Records with CVE: {stats['records_with_cve']:,}")
    print(f"   Records with descriptions: {stats['records_with_description']:,}")
    print(f"   Records with commit URLs: {stats['records_with_commit_url']:,}")
    print(f"\n💻 LANGUAGE DISTRIBUTION:")
    for lang, counts in sorted(stats['languages'].items(), key=lambda x: x[1]['total'], reverse=True)[:5]:
        print(f"   {lang}: {counts['total']:,} ({counts['vulnerable']:,} vulnerable)")
    print(f"\n🎯 DATA QUALITY:")
    print(f"   Unique projects: {stats['unique_projects']:,}")
    print(f"   Duplicates removed: {duplicates_removed:,}")
    if args.filter_noisy and LABEL_NOISE_DICT:
        print(f"   Noisy records filtered: ~{filtered_count:,}")
    print(f"\n📁 SPLIT PRESERVATION:")
    if stats.get('split_distribution'):
        for split_name, count in sorted(stats['split_distribution'].items()):
            print(f"   {split_name}: {count:,} records")
    else:
        print(f"   Not preserved (use --preserve-splits to enable)")
    print(f"\n� DATASET PROVENANCE:")
    if stats.get('provenance_distribution'):
        for dataset_name, count in sorted(stats['provenance_distribution'].items(), key=lambda x: x[1], reverse=True):
            print(f"   {dataset_name}: {count:,} records")
    else:
        print(f"   Not tracked (use --track-provenance to enable)")
    print(f"\n�💾 OUTPUT:")
    print(f"   Data: {output_file}")
    print(f"   Stats: {stats_file}")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
