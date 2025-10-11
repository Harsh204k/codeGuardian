#!/usr/bin/env python3
"""
MegaVul Dataset File Discovery
===============================

Handles the deeply nested MegaVul dataset structure on Kaggle.

Structure:
megavul/raw/
├── 2023-11/c_cpp/megavul_graph/
│   └── <project>/<commit>/<file>/
│       ├── non_vul/*.json (label=0)
│       └── vul/
│           ├── after/*.json (label=1)
│           └── before/*.json (label=1)
└── 2024-04/
    ├── c_cpp/megavul_graph/...
    └── java/megavul_graph/...

Author: CodeGuardian Team
Date: 2025-10-11
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


def discover_megavul_files(
    base_dir: Path,
    target_languages: List[str] = None
) -> List[Tuple[Path, int]]:
    """
    Discover ALL JSON files in the deeply nested MegaVul structure.
    
    Returns list of (file_path, label) tuples where:
    - label = 1 if in 'vul/' directory
    - label = 0 if in 'non_vul/' directory
    
    Args:
        base_dir: Root directory (e.g., /kaggle/input/megavul or megavul/raw)
        target_languages: Filter languages (e.g., ['C', 'C++', 'Java'])
        
    Returns:
        List of (file_path, label) tuples
    """
    logger.info(f"\n🔍 Discovering MegaVul files in {base_dir}")
    
    # Check for raw subdirectory (Kaggle structure)
    if (base_dir / 'raw').exists():
        base_dir = base_dir / 'raw'
        logger.info(f"   Using raw subdirectory: {base_dir}")
    
    if not base_dir.exists():
        logger.error(f"❌ Base directory not found: {base_dir}")
        return []
    
    # Map user-friendly language names to directory names
    lang_map = {
        'C': 'c_cpp',
        'C++': 'c_cpp',
        'Java': 'java'
    }
    
    # Determine which language directories to search
    if target_languages and 'all' not in target_languages:
        search_dirs = set()
        for lang in target_languages:
            mapped = lang_map.get(lang)
            if mapped:
                search_dirs.add(mapped)
    else:
        search_dirs = {'c_cpp', 'java'}
    
    logger.info(f"   Searching language directories: {search_dirs}")
    
    # Collect files
    files_with_labels = []
    stats = defaultdict(int)
    
    # Search date directories (2023-11, 2024-04, etc.)
    date_dirs = sorted([d for d in base_dir.iterdir() if d.is_dir() and d.name.startswith('20')])
    
    if not date_dirs:
        logger.warning(f"⚠️  No date directories found in {base_dir}")
        return []
    
    logger.info(f"   Found {len(date_dirs)} date directories: {[d.name for d in date_dirs]}")
    
    for date_dir in date_dirs:
        logger.info(f"\n   📅 Scanning {date_dir.name}/")
        
        # Search language directories
        for lang_dir_name in search_dirs:
            lang_dir = date_dir / lang_dir_name
            
            if not lang_dir.exists():
                logger.debug(f"      Skipping {lang_dir_name} (not found)")
                continue
            
            logger.info(f"      📂 {lang_dir_name}/")
            
            # MegaVul data is under megavul_graph/
            graph_dir = lang_dir / 'megavul_graph'
            
            if not graph_dir.exists():
                logger.warning(f"         ⚠️  megavul_graph/ not found in {lang_dir}")
                continue
            
            # Recursively find all JSON files
            json_files = list(graph_dir.rglob('*.json'))
            logger.info(f"         Found {len(json_files)} JSON files")
            
            # Classify by directory (vul vs non_vul)
            for json_file in json_files:
                path_parts = json_file.parts
                
                # Determine label from directory structure
                if 'vul' in path_parts:
                    label = 1  # Vulnerable
                    stats[f'{date_dir.name}/{lang_dir_name}/vul'] += 1
                elif 'non_vul' in path_parts:
                    label = 0  # Safe
                    stats[f'{date_dir.name}/{lang_dir_name}/non_vul'] += 1
                else:
                    # Unknown - skip
                    logger.debug(f"         ⚠️  Unknown label for {json_file.relative_to(base_dir)}")
                    continue
                
                files_with_labels.append((json_file, label))
    
    # Print statistics
    logger.info(f"\n📊 File Discovery Statistics:")
    logger.info(f"   Total JSON files: {len(files_with_labels):,}")
    
    for key, count in sorted(stats.items()):
        logger.info(f"   {key}: {count:,} files")
    
    # Calculate totals
    total_vul = sum(count for key, count in stats.items() if '/vul' in key)
    total_non_vul = sum(count for key, count in stats.items() if '/non_vul' in key)
    
    logger.info(f"\n   Vulnerable: {total_vul:,} files")
    logger.info(f"   Safe: {total_non_vul:,} files")
    logger.info(f"   Total: {len(files_with_labels):,} files\n")
    
    return files_with_labels


def estimate_total_records(files_with_labels: List[Tuple[Path, int]], sample_size: int = 10) -> int:
    """
    Estimate total records by sampling a few files.
    
    Args:
        files_with_labels: List of (file_path, label) tuples
        sample_size: Number of files to sample
        
    Returns:
        Estimated total record count
    """
    import json
    
    if not files_with_labels:
        return 0
    
    sample_size = min(sample_size, len(files_with_labels))
    sample_files = files_with_labels[:sample_size]
    
    record_counts = []
    
    for file_path, _ in sample_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                record_counts.append(len(data))
            elif isinstance(data, dict):
                record_counts.append(1)
        except Exception as e:
            logger.debug(f"Error reading {file_path}: {e}")
            continue
    
    if not record_counts:
        return 0
    
    avg_records_per_file = sum(record_counts) / len(record_counts)
    estimated_total = int(avg_records_per_file * len(files_with_labels))
    
    logger.info(f"📊 Estimation: {avg_records_per_file:.1f} avg records/file")
    logger.info(f"   Estimated total: ~{estimated_total:,} records")
    
    return estimated_total


def group_files_by_size(
    files_with_labels: List[Tuple[Path, int]],
    chunk_size_bytes: int = 100 * 1024 * 1024  # 100MB
) -> List[List[Tuple[Path, int]]]:
    """
    Group files into chunks of approximately equal size.
    
    This optimizes processing by batching small files together.
    
    Args:
        files_with_labels: List of (file_path, label) tuples
        chunk_size_bytes: Target chunk size in bytes
        
    Returns:
        List of file groups
    """
    groups = []
    current_group = []
    current_size = 0
    
    for file_path, label in files_with_labels:
        file_size = file_path.stat().st_size
        
        if current_size + file_size > chunk_size_bytes and current_group:
            # Start new group
            groups.append(current_group)
            current_group = []
            current_size = 0
        
        current_group.append((file_path, label))
        current_size += file_size
    
    # Add final group
    if current_group:
        groups.append(current_group)
    
    logger.info(f"📦 Grouped {len(files_with_labels)} files into {len(groups)} chunks")
    logger.info(f"   Avg {len(files_with_labels) / len(groups):.1f} files per chunk")
    
    return groups


# Testing
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test with local dataset path
    test_path = Path("/kaggle/input/megavul")
    
    if not test_path.exists():
        test_path = Path("../../../datasets/megavul")
    
    files = discover_megavul_files(test_path)
    
    if files:
        estimate_total_records(files, sample_size=20)
        groups = group_files_by_size(files, chunk_size_bytes=50 * 1024 * 1024)
        
        print(f"\n✅ Discovery test complete")
        print(f"   Files: {len(files):,}")
        print(f"   Groups: {len(groups)}")
