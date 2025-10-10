#!/usr/bin/env python3
"""
Preprocessing script for DiverseVul dataset.

The DiverseVul dataset is a multi-language, CWE-tagged dataset with metadata 
and label noise information.

Files:
- diversevul.json: main dataset
- diversevul_metadata.json: additional metadata
- label_noise/: directory with label noise information
"""

import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import sys
from tqdm import tqdm

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_json, read_jsonl, write_jsonl, write_json, ensure_dir
from scripts.utils.text_cleaner import sanitize_code, is_valid_code
from scripts.utils.schema_utils import (
    normalize_language, normalize_cwe_id, normalize_cve_id,
    map_to_unified_schema, validate_record, infer_language_from_filename, deduplicate_by_code_hash
)
from scripts.utils.kaggle_paths import get_dataset_path, get_output_path, print_environment_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_metadata(metadata_path: str) -> Dict[str, Any]:
    """
    Load metadata from diversevul_metadata.json (JSONL format).
    
    Args:
        metadata_path: Path to metadata JSONL file
        
    Returns:
        Dictionary mapping commit_ids to metadata
    """
    try:
        metadata_dict = {}
        # Metadata is in JSONL format (one JSON per line)
        for record in read_jsonl(metadata_path):
            commit_id = record.get('commit_id', '')
            if commit_id:
                metadata_dict[commit_id] = record
        
        logger.info(f"Loaded metadata for {len(metadata_dict)} records")
        return metadata_dict
    except Exception as e:
        logger.warning(f"Could not load metadata: {e}")
        return {}


def load_label_noise_info(label_noise_dir: Path) -> Dict[str, bool]:
    """
    Load label noise information if available.
    
    Args:
        label_noise_dir: Path to label_noise directory
        
    Returns:
        Dictionary mapping record IDs to noise status
    """
    noisy_records = {}
    
    if not label_noise_dir.exists():
        logger.info("No label noise directory found")
        return noisy_records
    
    try:
        # Look for CSV or JSON files in label_noise directory
        for file_path in label_noise_dir.glob("*.csv"):
            logger.info(f"Loading label noise info from {file_path}")
            from scripts.utils.io_utils import read_csv
            for row in read_csv(str(file_path)):
                record_id = row.get('id', row.get('record_id', row.get('CVE_ID', '')))
                is_noisy = row.get('is_noisy', row.get('noisy', 'False'))
                if record_id:
                    noisy_records[str(record_id)] = str(is_noisy).lower() in ['true', '1', 'yes']
        
        for file_path in label_noise_dir.glob("*.json"):
            logger.info(f"Loading label noise info from {file_path}")
            data = read_json(str(file_path))
            if isinstance(data, dict):
                noisy_records.update(data)
            elif isinstance(data, list):
                for item in data:
                    record_id = item.get('id', item.get('record_id', ''))
                    is_noisy = item.get('is_noisy', item.get('noisy', False))
                    if record_id:
                        noisy_records[str(record_id)] = is_noisy
        
        logger.info(f"Loaded noise info for {len(noisy_records)} records")
    except Exception as e:
        logger.warning(f"Error loading label noise info: {e}")
    
    return noisy_records


def process_diversevul_record(
    record: Dict[str, Any], 
    metadata: Dict[str, Any],
    label_noise: Dict[str, bool],
    index: int
) -> Optional[Dict[str, Any]]:
    """
    Process a single DiverseVul record.
    
    Args:
        record: Raw record from diversevul.json
        metadata: Metadata dictionary (keyed by commit_id)
        label_noise: Label noise dictionary
        index: Record index for unique ID generation
        
    Returns:
        Processed record or None if invalid
    """
    try:
        # Extract fields - DiverseVul actual structure:
        # Main dataset: func, target, cwe (list), project, commit_id, hash, size, message
        code = record.get('func', record.get('code', record.get('source_code', '')))
        label = record.get('target', record.get('label', record.get('vulnerable', 0)))
        commit_id = record.get('commit_id', '')
        project = record.get('project', '')
        
        # CWE is a LIST in DiverseVul, take first one if available
        cwe_list = record.get('cwe', [])
        cwe_id = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else ''
        
        # Get metadata if available (keyed by commit_id)
        meta = metadata.get(commit_id, {})
        
        # CVE from metadata (field is 'CVE' not 'CVE_ID')
        cve_id = meta.get('CVE', '') if meta else ''
        
        # Get additional info from metadata
        if not cwe_id and 'CWE' in meta:
            cwe_id = meta['CWE']
        description = meta.get('bug_info', '') if meta else record.get('message', '')
        
        # Language inference - DiverseVul doesn't have language field in main dataset
        # Infer from project name or set based on common patterns
        language = 'C'  # Most projects are C/C++
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
        
        # Check if record has label noise
        record_key = commit_id or str(index)
        is_noisy = label_noise.get(record_key, False)
        
        # Skip noisy records if filtering is desired (optional)
        # if is_noisy:
        #     return None
        
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
            "file_name": None,  # Not in DiverseVul
            "func_name": None,  # Not in DiverseVul
            "description": description if description else None
        }
        
        # Map to unified schema
        unified_record = map_to_unified_schema(
            record=intermediate_record,
            dataset_name="diversevul",
            index=index
        )
        
        # Add source provenance for traceability
        unified_record['source_row_index'] = index
        unified_record['source_file'] = 'diversevul.json'
        
        # Validate record
        is_valid, errors = validate_record(unified_record, use_jsonschema=True)
        if not is_valid:
            logger.warning(f"Validation failed for record {index}: {errors}")
            return None
        
        return unified_record
        
    except Exception as e:
        logger.warning(f"Error processing DiverseVul record {index}: {e}")
        return None


def generate_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate statistics for the processed dataset.
    
    Args:
        records: List of processed records
        
    Returns:
        Statistics dictionary
    """
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
    parser = argparse.ArgumentParser(description='Preprocess DiverseVul dataset')
    parser.add_argument(
        '--input-dir',
        type=str,
        default=None,
        help='Input directory containing raw DiverseVul files (auto-detected if not provided)'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default=None,
        help='Output directory for processed files (auto-detected if not provided)'
    )
    parser.add_argument(
        '--max-records',
        type=int,
        default=None,
        help='Maximum number of records to process (for testing)'
    )
    parser.add_argument(
        '--filter-noisy',
        action='store_true',
        help='Filter out records with label noise'
    )
    
    args = parser.parse_args()
    
    # Print environment info
    print_environment_info()
    
    # Get paths using Kaggle-compatible helper
    if args.input_dir:
        input_dir = Path(args.input_dir).resolve()
    else:
        input_dir = get_dataset_path("diversevul")
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("diversevul/processed")
    
    logger.info(f"[INFO] Processing DiverseVul dataset from: {input_dir}")
    
    # Ensure output directory exists
    ensure_dir(str(output_dir))
    
    # Load metadata
    metadata_path = input_dir / "diversevul_metadata.json"
    metadata = load_metadata(str(metadata_path)) if metadata_path.exists() else {}
    
    # Load label noise info
    label_noise_dir = input_dir / "label_noise"
    label_noise = load_label_noise_info(label_noise_dir)
    
    # Process main dataset
    dataset_path = input_dir / "diversevul.json"
    
    if not dataset_path.exists():
        logger.error(f"Dataset file not found: {dataset_path}")
        return
    
    all_records = []
    
    logger.info(f"Processing {dataset_path}")
    
    try:
        # Try reading as JSONL first
        data = list(read_jsonl(str(dataset_path), max_records=args.max_records))
        logger.info(f"Loaded {len(data)} records from JSONL")
        
        for idx, record in enumerate(tqdm(data, desc="Processing DiverseVul")):
            processed = process_diversevul_record(record, metadata, label_noise, idx)
            if processed:
                all_records.append(processed)
    except:
        # Try reading as JSON array
        try:
            data = read_json(str(dataset_path))
            if isinstance(data, list):
                logger.info(f"Loaded {len(data)} records from JSON array")
                limited_data = data[:args.max_records] if args.max_records else data
                for idx, record in enumerate(tqdm(limited_data, desc="Processing DiverseVul")):
                    processed = process_diversevul_record(record, metadata, label_noise, idx)
                    if processed:
                        all_records.append(processed)
            else:
                logger.error("Unexpected JSON format")
        except Exception as e:
            logger.error(f"Error reading dataset: {e}")
            return
    
    logger.info(f"Extracted {len(all_records)} valid records")
    
    # Deduplicate using full SHA-256 hash instead of prefix (more accurate)
    logger.info(f"Deduplicating {len(all_records)} records using SHA-256 hash...")
    unique_records = deduplicate_by_code_hash(all_records)
    
    logger.info(f"Removed {len(all_records) - len(unique_records)} duplicate records")
    all_records = unique_records
    
    # Save processed records
    output_file = output_dir / "raw_cleaned.jsonl"
    logger.info(f"Saving {len(all_records)} records to {output_file}")
    write_jsonl(all_records, str(output_file))
    
    # Generate and save statistics
    stats = generate_stats(all_records)
    stats_file = output_dir / "stats.json"
    write_json(stats, str(stats_file))
    logger.info(f"Statistics saved to {stats_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("DIVERSEVUL DATASET PROCESSING COMPLETE")
    print("="*60)
    print(f"Total records: {stats['total_records']}")
    print(f"Vulnerable: {stats['vulnerable_records']}")
    print(f"Non-vulnerable: {stats['non_vulnerable_records']}")
    print(f"Vulnerability ratio: {stats['vulnerability_ratio']:.2%}")
    print(f"Languages: {len(stats['languages'])}")
    print(f"Unique CWEs: {stats['unique_cwes']}")
    print(f"Records with CVE: {stats['records_with_cve']}")
    print(f"Unique projects: {stats['unique_projects']}")
    print(f"\nTop 5 CWEs:")
    for cwe, count in stats['top_cwes'][:5]:
        print(f"  {cwe}: {count}")
    print(f"\nOutput saved to: {output_dir}")
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

