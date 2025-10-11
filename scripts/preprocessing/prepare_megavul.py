#!/usr/bin/env python3
"""
MEGAVUL DATASET - ULTRA-FAST PARALLEL PREPROCESSING
====================================================

MegaVul is the LARGEST high-quality vulnerability dataset with comprehensive code representations.

DATASET OVERVIEW:
- Languages: C, C++, Java
- Size: 18-20 GB (JSON format)
- Vulnerabilities: 17,380 vulnerable functions + 322,168 non-vulnerable functions
- Total: ~340,000 functions
- Commit Data: 9,000+ vulnerability fix commits
- Repositories: 992 open-source projects
- Vulnerability Types: 169 different CWE types
- Time Span: January 2006 - October 2023
- Code Representations: AST, PDG, Control Flow, Data Flow

JAVA SUPPORT (Added April 2024):
- Vulnerable: 2,433 functions
- Non-vulnerable: 39,541 functions
- Total Java: ~42,000 functions

EXPECTED STRUCTURE:
{
    "vul_id": "CVE-2021-12345",
    "func": "vulnerable_function_code",
    "label": 1,  // 1=vulnerable, 0=safe
    "language": "C",
    "commit_id": "abc123...",
    "repo": "owner/project",
    "cwe_id": "CWE-119",
    "cve_id": "CVE-2021-12345",
    "severity": "HIGH",
    "description": "Buffer overflow in...",
    "ast": {...},  // Abstract Syntax Tree
    "pdg": {...},  // Program Dependency Graph
    "cfg": {...},  // Control Flow Graph
    "dfg": {...}   // Data Flow Graph
}

PREPROCESSING OPTIMIZATIONS:
- Ultra-fast parallel processing (DiverseVul-level speed)
- Multi-core CPU utilization
- Batch processing for memory efficiency
- Optional graph representation extraction
- Comprehensive metadata enrichment
- Language-specific handling (C/C++/Java)

Author: CodeGuardian Team - Competition-Ready
Date: 2025

Usage:
    python prepare_megavul.py --workers 8                  # Full speed
    python prepare_megavul.py --test                       # Test mode (1000 records)
    python prepare_megavul.py --include-graphs             # Extract AST/PDG/CFG/DFG
    python prepare_megavul.py --languages c cpp java       # Specific languages only
"""

import argparse
import logging
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter
import sys
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.io_utils import read_json, read_jsonl, write_jsonl, write_json, ensure_dir
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

# Global configuration (shared across workers)
INCLUDE_GRAPHS = False


# ============================================================
# WORKER INITIALIZATION
# ============================================================

def init_worker(include_graphs: bool):
    """Initialize worker process with shared configuration."""
    global INCLUDE_GRAPHS
    INCLUDE_GRAPHS = include_graphs


# ============================================================
# RECORD PROCESSING (OPTIMIZED)
# ============================================================

def process_megavul_record(args: Tuple[Dict[str, Any], int, List[str]]) -> Optional[Dict[str, Any]]:
    """
    Process a single MegaVul record with ultra-fast parsing.
    
    MegaVul Structure:
    - vul_id: Unique vulnerability identifier
    - func: Function source code
    - label: 1 (vulnerable) or 0 (safe)
    - language: C, C++, or Java
    - commit_id: Git commit hash
    - repo: Repository name
    - cwe_id: CWE identifier
    - cve_id: CVE identifier (if available)
    - severity: Vulnerability severity (LOW/MEDIUM/HIGH/CRITICAL)
    - description: Vulnerability description
    - ast, pdg, cfg, dfg: Graph representations (optional)
    
    Args:
        args: Tuple of (record, index, target_languages)
        
    Returns:
        Processed record or None if invalid/filtered
    """
    record, index, target_languages = args
    
    try:
        # Extract core fields
        code = record.get('func', record.get('code', record.get('function', '')))
        label = record.get('label', record.get('vulnerable', record.get('target', 0)))
        language = record.get('language', record.get('lang', 'C'))
        
        # Language filtering
        if target_languages and language not in target_languages:
            return None
        
        # Extract metadata
        vul_id = record.get('vul_id', record.get('vulnerability_id', ''))
        commit_id = record.get('commit_id', record.get('commit', ''))
        repo = record.get('repo', record.get('repository', record.get('project', '')))
        cwe_id = record.get('cwe_id', record.get('CWE_ID', record.get('cwe', '')))
        cve_id = record.get('cve_id', record.get('CVE_ID', record.get('cve', '')))
        severity = record.get('severity', record.get('risk', ''))
        description = record.get('description', record.get('desc', record.get('bug_info', '')))
        
        # Extract file and function metadata
        file_name = record.get('file', record.get('filename', record.get('file_path', '')))
        func_name = record.get('func_name', record.get('function_name', record.get('method', '')))
        
        # Extract patch/diff information if available
        patch = record.get('patch', record.get('diff', ''))
        fixed_code = record.get('fixed_func', record.get('patched_func', ''))
        
        # Validate code
        if not code or len(str(code).strip()) < 10:
            return None
        
        # Sanitize code
        code = sanitize_code(str(code), language=language, normalize_ws=True)
        
        # Validate sanitized code
        if not is_valid_code(code, min_length=10):
            return None
        
        # Normalize fields
        language = normalize_language(language)
        cwe_id = normalize_cwe_id(cwe_id)
        cve_id = normalize_cve_id(cve_id)
        
        # Convert label to int
        if isinstance(label, str):
            label = 1 if label.lower() in ['1', 'true', 'yes', 'vulnerable'] else 0
        else:
            label = int(label) if label else 0
        
        # Create base record
        processed_record = {
            "code": code,
            "label": label,
            "language": language,
            "project": repo if repo else None,
            "commit_id": commit_id if commit_id else None,
            "cwe_id": cwe_id,
            "cve_id": cve_id,
            "file_name": file_name if file_name else None,
            "func_name": func_name if func_name else None,
            "description": description if description else None,
            "dataset": "megavul",
            "source": "megavul",
            "source_row_index": index,
        }
        
        # Add MegaVul-specific metadata
        if vul_id:
            processed_record['vulnerability_id'] = vul_id
        
        if severity:
            processed_record['severity'] = severity.upper() if isinstance(severity, str) else severity
        
        if patch:
            processed_record['patch_available'] = True
            if len(patch) < 10000:  # Store small patches inline
                processed_record['patch'] = patch
        
        if fixed_code and len(fixed_code) > 10:
            processed_record['has_fix'] = True
        
        # Extract graph representations if enabled
        if INCLUDE_GRAPHS:
            if 'ast' in record and record['ast']:
                processed_record['has_ast'] = True
                # Store compact representation
                processed_record['ast_nodes'] = len(record['ast']) if isinstance(record['ast'], (list, dict)) else None
            
            if 'pdg' in record and record['pdg']:
                processed_record['has_pdg'] = True
                processed_record['pdg_nodes'] = len(record['pdg']) if isinstance(record['pdg'], (list, dict)) else None
            
            if 'cfg' in record and record['cfg']:
                processed_record['has_cfg'] = True
                processed_record['cfg_nodes'] = len(record['cfg']) if isinstance(record['cfg'], (list, dict)) else None
            
            if 'dfg' in record and record['dfg']:
                processed_record['has_dfg'] = True
                processed_record['dfg_nodes'] = len(record['dfg']) if isinstance(record['dfg'], (list, dict)) else None
        
        return processed_record
        
    except Exception as e:
        if index < 10:  # Log first few errors
            logger.error(f"Error processing record {index}: {type(e).__name__}: {str(e)}")
        return None


# ============================================================
# PARALLEL PROCESSING ENGINE
# ============================================================

def process_batch_parallel(
    data: List[Dict[str, Any]],
    num_workers: int = None,
    target_languages: List[str] = None,
    include_graphs: bool = False
) -> List[Dict[str, Any]]:
    """
    Process MegaVul records in parallel using multiprocessing.
    
    Args:
        data: List of raw records
        num_workers: Number of parallel workers (default: CPU cores - 1)
        target_languages: Filter to specific languages (e.g., ['C', 'C++'])
        include_graphs: Whether to extract graph representations
        
    Returns:
        List of processed records
    """
    if num_workers is None:
        num_workers = max(1, cpu_count() - 1)
    
    logger.info(f"🚀 Using {num_workers} parallel workers")
    logger.info(f"📝 Total input records: {len(data):,}")
    
    if target_languages:
        logger.info(f"🔍 Language filter: {', '.join(target_languages)}")
    
    if include_graphs:
        logger.info(f"📊 Graph extraction: ENABLED (AST, PDG, CFG, DFG)")
    
    # Prepare arguments
    args_list = [(record, idx, target_languages) for idx, record in enumerate(data)]
    
    results = []
    none_count = 0
    
    # Initialize workers with shared configuration
    with Pool(
        processes=num_workers,
        initializer=init_worker,
        initargs=(include_graphs,)
    ) as pool:
        # Process with progress bar
        for result in tqdm(
            pool.imap_unordered(process_megavul_record, args_list, chunksize=100),
            total=len(args_list),
            desc="Processing MegaVul (Parallel)",
            unit="records"
        ):
            if result is not None:
                results.append(result)
            else:
                none_count += 1
    
    logger.info(f"✅ Successfully processed: {len(results):,} records")
    logger.info(f"⚠️  Filtered/Failed: {none_count:,} records")
    
    if len(results) == 0 and len(data) > 0:
        logger.error(f"🚨 CRITICAL: ALL {len(data):,} records were filtered out!")
    
    return results


# ============================================================
# STATISTICS GENERATION
# ============================================================

def generate_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate comprehensive statistics for the processed MegaVul dataset.
    
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
    
    # Severity distribution
    severities = Counter(r.get('severity') for r in records if r.get('severity'))
    
    # Project/Repository distribution
    projects = Counter(r.get('project') for r in records if r.get('project'))
    
    # Graph representation availability
    with_ast = sum(1 for r in records if r.get('has_ast'))
    with_pdg = sum(1 for r in records if r.get('has_pdg'))
    with_cfg = sum(1 for r in records if r.get('has_cfg'))
    with_dfg = sum(1 for r in records if r.get('has_dfg'))
    
    # Patch availability
    with_patch = sum(1 for r in records if r.get('patch_available'))
    with_fix = sum(1 for r in records if r.get('has_fix'))
    
    return {
        "dataset": "megavul",
        "total_records": total,
        "vulnerable_records": vulnerable,
        "non_vulnerable_records": non_vulnerable,
        "vulnerability_ratio": round(vulnerable / total, 4) if total > 0 else 0,
        "languages": languages,
        "unique_cwes": len(cwes),
        "top_cwes": sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:20],
        "records_with_cve": cve_count,
        "severity_distribution": dict(severities),
        "unique_projects": len(projects),
        "top_projects": sorted(projects.items(), key=lambda x: x[1], reverse=True)[:10],
        "graph_representations": {
            "ast": with_ast,
            "pdg": with_pdg,
            "cfg": with_cfg,
            "dfg": with_dfg
        },
        "patch_info": {
            "with_patch": with_patch,
            "with_fix": with_fix
        },
        "avg_code_length": sum(len(r['code']) for r in records) / total if total > 0 else 0
    }


# ============================================================
# FILE DISCOVERY & LOADING
# ============================================================

def discover_megavul_files(input_dir: Path) -> Dict[str, List[Path]]:
    """
    Auto-discover MegaVul dataset files.
    
    Expected Kaggle structure:
    megavul/raw/
    ├── 2023-11/c_cpp/  (C/C++ files - 8.99 GB)
    └── 2024-04/
        ├── c_cpp/      (C/C++ files - 9.2 GB)
        └── java/       (Java files - 811 MB)
    
    Args:
        input_dir: Input directory path (should be megavul/raw)
        
    Returns:
        Dictionary mapping language to list of file paths
    """
    files_by_lang = {'C/C++': [], 'Java': [], 'all': []}
    
    logger.info(f"   Scanning directory structure...")
    
    # Check for raw subdirectory (Kaggle structure)
    if (input_dir / 'raw').exists():
        logger.info(f"   Found 'raw' subdirectory, using Kaggle structure")
        input_dir = input_dir / 'raw'
    
    # Scan for dated release directories (2023-11, 2024-04, etc.)
    date_dirs = sorted([d for d in input_dir.iterdir() if d.is_dir() and d.name.startswith('20')])
    
    if date_dirs:
        logger.info(f"   Found {len(date_dirs)} release directories: {[d.name for d in date_dirs]}")
        
        for date_dir in date_dirs:
            logger.info(f"   Scanning {date_dir.name}/...")
            
            # Look for c_cpp directory
            c_cpp_dir = date_dir / 'c_cpp'
            if c_cpp_dir.exists():
                c_cpp_files = list(c_cpp_dir.glob('*.json')) + list(c_cpp_dir.glob('*.jsonl'))
                if c_cpp_files:
                    files_by_lang['C/C++'].extend(c_cpp_files)
                    logger.info(f"      c_cpp/: {len(c_cpp_files)} file(s)")
            
            # Look for java directory
            java_dir = date_dir / 'java'
            if java_dir.exists():
                java_files = list(java_dir.glob('*.json')) + list(java_dir.glob('*.jsonl'))
                if java_files:
                    files_by_lang['Java'].extend(java_files)
                    logger.info(f"      java/: {len(java_files)} file(s)")
    
    # Fallback: Look for direct file patterns (backwards compatibility)
    if not any(files_by_lang.values()):
        logger.info(f"   No dated directories found, checking for direct files...")
        
        patterns = {
            'C/C++': ['*_c.json', '*_cpp.json', '*_c.jsonl', '*_cpp.jsonl', 
                      'c_cpp*.json', 'c_cpp*.jsonl'],
            'Java': ['*_java.json', '*_java.jsonl', 'java*.json', 'java*.jsonl']
        }
        
        for lang, pattern_list in patterns.items():
            for pattern in pattern_list:
                found_files = list(input_dir.glob(pattern))
                if found_files:
                    files_by_lang[lang].extend(found_files)
        
        # Check for combined files
        for pattern in ['megavul.json', 'megavul.jsonl', 'dataset.json', 'dataset.jsonl']:
            combined_file = input_dir / pattern
            if combined_file.exists():
                files_by_lang['all'].append(combined_file)
    
    # Summary
    total_files = sum(len(files) for files in files_by_lang.values())
    logger.info(f"   ✅ Discovered {total_files} total file(s)")
    for lang, files in files_by_lang.items():
        if files:
            logger.info(f"      {lang}: {len(files)} file(s)")
    
    return files_by_lang


def load_megavul_data(
    input_dir: Path,
    max_records: Optional[int] = None,
    target_languages: List[str] = None
) -> List[Dict[str, Any]]:
    """
    Load MegaVul dataset from discovered files.
    
    Kaggle Structure:
    megavul/raw/
    ├── 2023-11/c_cpp/  (4 files, C/C++ data)
    └── 2024-04/
        ├── c_cpp/      (4 files, C/C++ data)
        └── java/       (4 files, Java data)
    
    Args:
        input_dir: Input directory (will auto-detect raw/ subdirectory)
        max_records: Maximum records to load (for testing)
        target_languages: Filter to specific languages (None = all)
        
    Returns:
        List of raw records
    """
    logger.info(f"\n🔍 Discovering MegaVul files in {input_dir}")
    files_by_lang = discover_megavul_files(input_dir)
    
    all_data = []
    total_files = sum(len(files) for files in files_by_lang.values())
    
    if total_files == 0:
        logger.warning("⚠️  No MegaVul files found!")
        return []
    
    # Map target languages to file categories
    # Users specify: C, C++, Java
    # Files are categorized as: C/C++ (combined), Java
    process_cpp = False
    process_java = False
    
    if not target_languages or 'all' in target_languages:
        process_cpp = True
        process_java = True
    else:
        if 'C' in target_languages or 'C++' in target_languages:
            process_cpp = True
        if 'Java' in target_languages:
            process_java = True
    
    # Process files
    for lang, file_list in files_by_lang.items():
        if not file_list:
            continue
        
        # Skip based on language filter
        if lang == 'C/C++' and not process_cpp:
            logger.info(f"   Skipping C/C++ (not in target languages)")
            continue
        if lang == 'Java' and not process_java:
            logger.info(f"   Skipping Java (not in target languages)")
            continue
        
        for file_path in file_list:
            logger.info(f"\n📖 Loading {file_path.parent.parent.name}/{file_path.parent.name}/{file_path.name}...")
            
            try:
                # Detect format
                if file_path.suffix == '.jsonl':
                    # JSONL format (one record per line)
                    records = list(read_jsonl(str(file_path)))
                else:
                    # JSON format (array or single object)
                    data = read_json(str(file_path))
                    if isinstance(data, list):
                        records = data
                    elif isinstance(data, dict):
                        # Check if it's wrapped in a key
                        if 'data' in data:
                            records = data['data']
                        elif 'functions' in data:
                            records = data['functions']
                        elif 'vulnerabilities' in data:
                            records = data['vulnerabilities']
                        else:
                            records = [data]
                    else:
                        logger.warning(f"   Unknown JSON structure in {file_path.name}")
                        continue
                
                logger.info(f"   Loaded {len(records):,} records")
                all_data.extend(records)
                
                # Check max records
                if max_records and len(all_data) >= max_records:
                    logger.info(f"   Reached max records limit ({max_records:,})")
                    break
                    
            except Exception as e:
                logger.error(f"   Error loading {file_path.name}: {e}")
        
        # Break if max reached
        if max_records and len(all_data) >= max_records:
            break
    
    # Limit to max_records if specified
    if max_records and len(all_data) > max_records:
        logger.info(f"🔪 Limiting to first {max_records:,} records")
        all_data = all_data[:max_records]
    
    logger.info(f"\n✅ Total records loaded: {len(all_data):,}")
    return all_data


# ============================================================
# MAIN PIPELINE (ULTRA-FAST)
# ============================================================

def main():
    """Main execution - ultra-fast parallel processing."""
    parser = argparse.ArgumentParser(
        description='Ultra-fast parallel preprocessing for MegaVul dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MegaVul Dataset Information:
  - Total: ~340,000 functions (17,380 vulnerable + 322,168 safe)
  - Languages: C, C++, Java
  - Size: 18-20 GB
  - Repositories: 992 open-source projects
  - CWE Types: 169 different vulnerabilities
  - Time Span: 2006-2023

Examples:
  # Process all languages with full speed
  python prepare_megavul.py --workers 8
  
  # Test mode (1000 records)
  python prepare_megavul.py --test
  
  # C/C++ only
  python prepare_megavul.py --languages C C++
  
  # Extract graph representations (AST, PDG, CFG, DFG)
  python prepare_megavul.py --include-graphs --workers 8
        """
    )
    parser.add_argument('--input-dir', type=str, default=None,
                       help='Input directory containing MegaVul files')
    parser.add_argument('--output-dir', type=str, default=None,
                       help='Output directory for processed files')
    parser.add_argument('--max-records', type=int, default=None,
                       help='Maximum number of records to process (for testing)')
    parser.add_argument('--workers', type=int, default=None,
                       help='Number of parallel workers (default: CPU cores - 1)')
    parser.add_argument('--test', action='store_true',
                       help='Test mode: process 1000 records')
    parser.add_argument('--languages', nargs='+',
                       choices=['C', 'C++', 'Java', 'all'],
                       default=['all'],
                       help='Languages to process')
    parser.add_argument('--include-graphs', action='store_true',
                       help='Extract graph representations (AST, PDG, CFG, DFG)')
    
    args = parser.parse_args()
    
    # Test mode configuration
    if args.test:
        args.max_records = 1000
        logger.info("\n⚡ TEST MODE: Processing 1000 records")
    
    # Print environment
    print("\n" + "="*70)
    print("⚡ MEGAVUL ULTRA-FAST PREPROCESSING (COMPETITION OPTIMIZED)")
    print("="*70)
    print_environment_info()
    
    # Get paths
    if args.input_dir:
        input_dir = Path(args.input_dir).resolve()
    else:
        input_dir = get_dataset_path("megavul")
    
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = get_output_path("megavul/processed")
    
    print(f"\n📂 Input: {input_dir}")
    print(f"📂 Output: {output_dir}")
    
    # Check if dataset exists
    if not input_dir.exists():
        logger.warning("="*70)
        logger.warning("⚠️  MegaVul dataset not found!")
        logger.warning(f"Expected location: {input_dir}")
        logger.warning("\nExpected Kaggle structure:")
        logger.warning("  /kaggle/input/megavul/")
        logger.warning("  └── raw/")
        logger.warning("      ├── 2023-11/c_cpp/  (8.99 GB, 4 files)")
        logger.warning("      └── 2024-04/")
        logger.warning("          ├── c_cpp/      (9.2 GB, 4 files)")
        logger.warning("          └── java/       (811 MB, 4 files)")
        logger.warning("\nThis dataset will be processed when it becomes available.")
        logger.warning("="*70)
        
        # Create placeholder output
        ensure_dir(str(output_dir))
        placeholder_stats = {
            "dataset": "megavul",
            "status": "Dataset not yet available",
            "total_records": 0,
            "expected_records": 340000,
            "expected_structure": {
                "2023-11": {"c_cpp": "8.99 GB, 4 files"},
                "2024-04": {"c_cpp": "9.2 GB, 4 files", "java": "811 MB, 4 files"}
            },
            "note": "MegaVul dataset (19 GB total) will be processed when downloaded"
        }
        write_json(placeholder_stats, str(output_dir / "stats.json"))
        return
    
    ensure_dir(str(output_dir))
    
    # Determine target languages
    target_languages = args.languages if 'all' not in args.languages else None
    
    # Start timer
    start_time = time.time()
    
    # Load data
    logger.info(f"\n📊 Loading MegaVul dataset...")
    all_data = load_megavul_data(input_dir, args.max_records, target_languages)
    
    if not all_data:
        logger.error("❌ No data loaded from MegaVul dataset!")
        return
    
    load_time = time.time() - start_time
    logger.info(f"⏱️  Load time: {load_time:.2f}s")
    
    # Process in parallel
    process_start = time.time()
    logger.info(f"\n🚀 Starting parallel processing...")
    all_records = process_batch_parallel(
        all_data,
        num_workers=args.workers,
        target_languages=target_languages,
        include_graphs=args.include_graphs
    )
    process_time = time.time() - process_start
    
    logger.info(f"\n✅ Processed {len(all_records):,} valid records")
    logger.info(f"⏱️  Processing time: {process_time:.2f}s")
    logger.info(f"🚀 Processing speed: {len(all_data) / process_time:.0f} records/sec")
    
    if len(all_records) == 0:
        logger.error("❌ No valid records after processing!")
        return
    
    # Deduplicate
    logger.info(f"\n🔄 Deduplicating using SHA-256 hash...")
    unique_records = deduplicate_by_code_hash(all_records)
    duplicates_removed = len(all_records) - len(unique_records)
    logger.info(f"✅ Removed {duplicates_removed:,} duplicates")
    
    # Save
    write_start = time.time()
    output_file = output_dir / "raw_cleaned.jsonl"
    logger.info(f"\n💾 Saving {len(unique_records):,} records to {output_file}")
    write_jsonl(unique_records, str(output_file))
    write_time = time.time() - write_start
    logger.info(f"⏱️  Write time: {write_time:.2f}s")
    logger.info(f"🚀 Write speed: {len(unique_records) / write_time:.0f} records/sec")
    
    # Generate stats
    stats_start = time.time()
    logger.info(f"\n📊 Generating statistics...")
    stats = generate_stats(unique_records)
    stats_file = output_dir / "stats.json"
    write_json(stats, str(stats_file))
    stats_time = time.time() - stats_start
    
    # Total time
    total_time = time.time() - start_time
    
    # Print summary
    print("\n" + "="*70)
    print("✅ MEGAVUL PREPROCESSING COMPLETE (ULTRA-FAST MODE)")
    print("="*70)
    print(f"\n📊 RESULTS:")
    print(f"   Total records: {stats['total_records']:,}")
    print(f"   Vulnerable: {stats['vulnerable_records']:,} ({stats['vulnerability_ratio']:.2%})")
    print(f"   Safe: {stats['non_vulnerable_records']:,}")
    
    print(f"\n🏷️  LANGUAGES:")
    for lang, counts in sorted(stats['languages'].items(), key=lambda x: x[1]['total'], reverse=True):
        print(f"   {lang}: {counts['total']:,} ({counts['vulnerable']:,} vulnerable)")
    
    print(f"\n🏷️  CWES:")
    print(f"   Unique CWEs: {stats['unique_cwes']}")
    print(f"   Top 5 CWEs:")
    for cwe, count in list(stats['top_cwes'])[:5]:
        print(f"     {cwe}: {count:,}")
    
    print(f"\n🔬 METADATA:")
    print(f"   Records with CVE: {stats['records_with_cve']:,}")
    if stats.get('severity_distribution'):
        print(f"   Severity distribution:")
        for sev, count in sorted(stats['severity_distribution'].items()):
            print(f"     {sev}: {count:,}")
    
    if args.include_graphs:
        print(f"\n📊 GRAPH REPRESENTATIONS:")
        graph_stats = stats['graph_representations']
        print(f"   AST: {graph_stats['ast']:,} records")
        print(f"   PDG: {graph_stats['pdg']:,} records")
        print(f"   CFG: {graph_stats['cfg']:,} records")
        print(f"   DFG: {graph_stats['dfg']:,} records")
    
    patch_stats = stats['patch_info']
    print(f"\n🔧 PATCH INFO:")
    print(f"   With patch: {patch_stats['with_patch']:,}")
    print(f"   With fix: {patch_stats['with_fix']:,}")
    
    print(f"\n⏱️  PERFORMANCE:")
    print(f"   Total time: {total_time:.2f}s")
    print(f"   Load: {load_time:.2f}s")
    print(f"   Processing: {process_time:.2f}s ({len(all_data) / process_time:.0f} records/sec)")
    print(f"   Writing: {write_time:.2f}s ({len(unique_records) / write_time:.0f} records/sec)")
    print(f"   Statistics: {stats_time:.2f}s")
    print(f"   Duplicates removed: {duplicates_removed:,}")
    
    print(f"\n📁 Output: {output_dir}")
    print("="*70)
    
    # Performance comparison
    if not args.test:
        diversevul_speed = 33458  # records/sec from DiverseVul
        megavul_speed = len(all_data) / process_time
        
        print(f"\n🏆 SPEED COMPARISON:")
        print(f"   DiverseVul: {diversevul_speed:,.0f} records/sec")
        print(f"   MegaVul: {megavul_speed:,.0f} records/sec")
        
        if megavul_speed >= diversevul_speed * 0.8:
            print("   ✅ EXCELLENT - Matching DiverseVul speed!")
        elif megavul_speed >= 10000:
            print("   ✅ GOOD - Fast preprocessing")
        else:
            print("   ⚠️  Moderate speed")


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

