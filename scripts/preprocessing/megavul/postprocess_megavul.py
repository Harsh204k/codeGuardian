#!/usr/bin/env python3
"""
MegaVul Post-Processing & Merging Module
=========================================

Downloads processed chunks from Google Drive and merges them into a final
unified dataset ready for model training.

Features:
    - Download chunks from Drive
    - Merge multiple chunks into single dataset
    - Generate JSONL and Parquet formats
    - Schema validation across chunks
    - Deduplication across entire dataset
    - Statistics generation

Author: CodeGuardian Team
Date: 2025-10-11

Usage:
    # Download and merge all chunks
    python postprocess_megavul.py --download --merge
    
    # Merge local chunks only
    python postprocess_megavul.py --merge-local
    
    # Generate Parquet format
    python postprocess_megavul.py --merge --format parquet
    
    # With metadata enrichment
    python postprocess_megavul.py --merge --enrich-metadata
"""

import argparse
import logging
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from chunk_manager import ChunkManager
from drive_sync import DriveSync
from utils_megavul import (
    validate_schema_consistency,
    deduplicate_by_code_hash,
    create_processing_summary
)

# Try to import merge_metadata
try:
    from merge_metadata import MetadataEnricher
    METADATA_AVAILABLE = True
except ImportError:
    METADATA_AVAILABLE = False
    logging.warning("merge_metadata not available - enrichment disabled")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import tqdm
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class PostProcessor:
    """
    Post-processes MegaVul chunks into final unified dataset.
    
    Handles downloading chunks from Drive, merging, deduplication,
    and format conversion.
    """
    
    def __init__(
        self,
        drive_root: str = "/content/drive/MyDrive/codeGuardian/MegaVulProcessed",
        output_dir: str = "/kaggle/working/merged",
        local_chunks_dir: Optional[str] = None
    ):
        """
        Initialize post-processor.
        
        Args:
            drive_root: Google Drive root directory
            output_dir: Local output directory for merged data
            local_chunks_dir: Optional local chunks directory
        """
        self.drive_root = Path(drive_root)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.local_chunks_dir = Path(local_chunks_dir) if local_chunks_dir else self.output_dir / "chunks"
        self.local_chunks_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Drive sync
        self.drive_sync = DriveSync(
            drive_root=str(self.drive_root),
            verify_checksum=True,
            delete_after_upload=False  # Don't delete during download
        )
        
        # Initialize chunk manager
        self.chunk_manager = ChunkManager(
            output_dir=self.output_dir
        )
        
        logger.info("✅ PostProcessor initialized")
        logger.info(f"   Drive root: {self.drive_root}")
        logger.info(f"   Output dir: {self.output_dir}")
    
    def download_all_chunks(self) -> List[Path]:
        """
        Download all chunks from Google Drive.
        
        Returns:
            List of downloaded chunk paths
        """
        logger.info("\n" + "="*70)
        logger.info("☁️  Downloading chunks from Google Drive")
        logger.info("="*70)
        
        # Mount Drive
        if not self.drive_sync.mount_drive():
            logger.error("❌ Failed to mount Drive")
            return []
        
        # List remote chunks
        remote_chunks = self.drive_sync.list_remote_files(
            subdir="chunks",
            pattern="chunk_*.jsonl*"
        )
        
        if not remote_chunks:
            logger.warning("⚠️  No chunks found in Drive")
            return []
        
        logger.info(f"📦 Found {len(remote_chunks)} chunks in Drive")
        
        # Download chunks
        downloaded_paths = []
        
        iterator = tqdm(remote_chunks, desc="Downloading chunks") if TQDM_AVAILABLE else remote_chunks
        
        for remote_path in iterator:
            local_path = self.drive_sync.download_file(
                remote_path,
                self.local_chunks_dir,
                verify=True
            )
            
            if local_path:
                downloaded_paths.append(local_path)
            else:
                logger.warning(f"⚠️  Failed to download {remote_path.name}")
        
        logger.info(f"✅ Downloaded {len(downloaded_paths)} chunks")
        return downloaded_paths
    
    def download_chunk_range(self, start: int, end: int) -> List[Path]:
        """
        Download a specific range of chunks.
        
        Args:
            start: Starting chunk number
            end: Ending chunk number (inclusive)
            
        Returns:
            List of downloaded chunk paths
        """
        if not self.drive_sync.mount_drive():
            logger.error("❌ Failed to mount Drive")
            return []
        
        downloaded_paths = []
        
        for chunk_num in range(start, end + 1):
            chunk_id = self.chunk_manager.get_chunk_id(chunk_num)
            remote_path = self.drive_root / "chunks" / f"{chunk_id}.jsonl.gz"
            
            if not remote_path.exists():
                logger.warning(f"⚠️  Chunk not found: {chunk_id}")
                continue
            
            local_path = self.drive_sync.download_file(
                remote_path,
                self.local_chunks_dir,
                verify=True
            )
            
            if local_path:
                downloaded_paths.append(local_path)
        
        logger.info(f"✅ Downloaded {len(downloaded_paths)} chunks")
        return downloaded_paths
    
    def merge_chunks(
        self,
        chunk_paths: List[Path],
        output_path: Path,
        deduplicate: bool = True,
        validate: bool = True,
        batch_size: int = 100000
    ) -> int:
        """
        Merge multiple chunks into a single dataset.
        
        Args:
            chunk_paths: List of chunk file paths
            output_path: Output file path
            deduplicate: Remove duplicates across chunks
            validate: Validate schema consistency
            batch_size: Records to accumulate before writing
            
        Returns:
            Total records in merged dataset
        """
        logger.info("\n" + "="*70)
        logger.info(f"🔄 Merging {len(chunk_paths)} chunks")
        logger.info("="*70)
        
        start_time = time.time()
        
        # Collect all records
        all_records = []
        
        iterator = tqdm(chunk_paths, desc="Reading chunks") if TQDM_AVAILABLE else chunk_paths
        
        for chunk_path in iterator:
            records = self.chunk_manager.read_chunk(chunk_path)
            all_records.extend(records)
            logger.info(f"   Read {chunk_path.name}: {len(records):,} records (total: {len(all_records):,})")
        
        logger.info(f"\n✅ Loaded {len(all_records):,} total records")
        
        # Validate if enabled
        if validate:
            logger.info("\n🔍 Validating schema consistency...")
            validation_report = validate_schema_consistency(all_records)
            logger.info(f"✅ Validation: {validation_report['valid_records']}/{validation_report['total_records']} valid")
            
            if validation_report.get('errors'):
                logger.warning(f"⚠️  Validation errors: {validation_report['errors']}")
        
        # Deduplicate if enabled
        if deduplicate:
            logger.info("\n🔄 Deduplicating across all chunks...")
            original_count = len(all_records)
            all_records = deduplicate_by_code_hash(all_records)
            removed = original_count - len(all_records)
            logger.info(f"✅ Removed {removed:,} duplicates ({removed/original_count:.2%})")
        
        # Write merged dataset
        logger.info(f"\n💾 Writing merged dataset to {output_path}...")
        
        # Use chunk manager's merge function
        total_records = self.chunk_manager.merge_chunks(
            chunk_paths=[],  # We already have records in memory
            output_path=output_path,
            batch_size=batch_size
        )
        
        # Actually write the records we collected
        if output_path.suffix == '.parquet':
            try:
                import pyarrow as pa
                import pyarrow.parquet as pq
                
                table = pa.Table.from_pylist(all_records)
                pq.write_table(table, output_path, compression='snappy')
                logger.info(f"✅ Wrote Parquet: {output_path}")
            except ImportError:
                logger.error("❌ PyArrow not available - cannot write Parquet")
                return 0
        else:
            # Write JSONL
            import gzip
            
            is_gzipped = output_path.suffix == '.gz'
            open_func = gzip.open if is_gzipped else open
            mode = 'wt' if is_gzipped else 'w'
            
            with open_func(output_path, mode, encoding='utf-8') as f:
                for record in all_records:
                    f.write(json.dumps(record) + '\n')
            
            logger.info(f"✅ Wrote JSONL: {output_path}")
        
        total_records = len(all_records)
        
        # Calculate stats
        merge_time = time.time() - start_time
        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        
        logger.info(f"\n✅ Merge complete!")
        logger.info(f"   Total records: {total_records:,}")
        logger.info(f"   Output size: {file_size_mb:.2f} MB")
        logger.info(f"   Merge time: {merge_time:.2f}s ({total_records/merge_time:.0f} records/sec)")
        
        return total_records
    
    def generate_statistics(self, merged_file: Path) -> Dict[str, Any]:
        """
        Generate comprehensive statistics for merged dataset.
        
        Args:
            merged_file: Path to merged dataset
            
        Returns:
            Statistics dictionary
        """
        logger.info("\n📊 Generating statistics...")
        
        # Read merged dataset
        records = self.chunk_manager.read_chunk(merged_file)
        
        # Calculate statistics
        stats = {
            "dataset": "megavul_merged",
            "total_records": len(records),
            "vulnerable": sum(1 for r in records if r.get('is_vulnerable') == 1),
            "safe": sum(1 for r in records if r.get('is_vulnerable') == 0),
            "languages": {},
            "cwes": {},
            "cves": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        # Language distribution
        for record in records:
            lang = record.get('language', 'unknown')
            if lang not in stats['languages']:
                stats['languages'][lang] = {'total': 0, 'vulnerable': 0}
            stats['languages'][lang]['total'] += 1
            if record.get('is_vulnerable') == 1:
                stats['languages'][lang]['vulnerable'] += 1
        
        # CWE distribution
        for record in records:
            cwe = record.get('cwe_id')
            if cwe:
                stats['cwes'][cwe] = stats['cwes'].get(cwe, 0) + 1
        
        # CVE count
        stats['cves'] = sum(1 for r in records if r.get('cve_id'))
        
        # Sort and limit top CWEs
        stats['top_cwes'] = dict(sorted(stats['cwes'].items(), key=lambda x: x[1], reverse=True)[:20])
        stats['unique_cwes'] = len(stats['cwes'])
        del stats['cwes']  # Remove full CWE list to save space
        
        logger.info(f"✅ Statistics generated")
        return stats
    
    def upload_to_drive(self, local_path: Path, remote_subdir: str = "merged"):
        """
        Upload merged dataset to Drive.
        
        Args:
            local_path: Path to local file
            remote_subdir: Drive subdirectory
        """
        logger.info(f"\n☁️  Uploading {local_path.name} to Drive...")
        
        remote_path = self.drive_sync.upload_file(
            local_path,
            remote_subdir=remote_subdir
        )
        
        if remote_path:
            logger.info(f"✅ Uploaded to: {remote_path}")
        else:
            logger.error(f"❌ Upload failed")


def main():
    """Main entry point with CLI."""
    parser = argparse.ArgumentParser(
        description='Post-process MegaVul chunks into final dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download and merge all chunks
  python postprocess_megavul.py --download --merge
  
  # Merge local chunks only
  python postprocess_megavul.py --merge-local
  
  # Generate both JSONL and Parquet
  python postprocess_megavul.py --merge --format both
  
  # With deduplication
  python postprocess_megavul.py --merge --deduplicate
  
  # Upload to Drive
  python postprocess_megavul.py --merge --upload
        """
    )
    
    parser.add_argument(
        '--download',
        action='store_true',
        help='Download chunks from Google Drive'
    )
    parser.add_argument(
        '--merge',
        action='store_true',
        help='Merge chunks into final dataset'
    )
    parser.add_argument(
        '--merge-local',
        action='store_true',
        help='Merge local chunks without downloading'
    )
    parser.add_argument(
        '--deduplicate',
        action='store_true',
        help='Remove duplicates across chunks'
    )
    parser.add_argument(
        '--format',
        choices=['jsonl', 'parquet', 'both'],
        default='jsonl',
        help='Output format'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='merged_dataset.jsonl',
        help='Output filename'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Generate statistics report'
    )
    parser.add_argument(
        '--upload',
        action='store_true',
        help='Upload merged dataset to Drive'
    )
    parser.add_argument(
        '--chunk-range',
        nargs=2,
        type=int,
        metavar=('START', 'END'),
        help='Download specific chunk range (e.g., --chunk-range 1 10)'
    )
    
    args = parser.parse_args()
    
    # Initialize processor
    processor = PostProcessor()
    
    # Download chunks if requested
    chunk_paths = []
    
    if args.download:
        if args.chunk_range:
            start, end = args.chunk_range
            chunk_paths = processor.download_chunk_range(start, end)
        else:
            chunk_paths = processor.download_all_chunks()
    
    # Merge chunks
    if args.merge or args.merge_local:
        if not chunk_paths:
            # Use local chunks
            chunk_paths = sorted(processor.local_chunks_dir.glob("chunk_*.jsonl*"))
            logger.info(f"📂 Found {len(chunk_paths)} local chunks")
        
        if not chunk_paths:
            logger.error("❌ No chunks found to merge!")
            return
        
        # Merge to JSONL
        if args.format in ['jsonl', 'both']:
            output_path = processor.output_dir / args.output
            total = processor.merge_chunks(
                chunk_paths,
                output_path,
                deduplicate=args.deduplicate
            )
            
            if args.upload:
                processor.upload_to_drive(output_path)
            
            if args.stats:
                stats = processor.generate_statistics(output_path)
                stats_file = processor.output_dir / "stats.json"
                with open(stats_file, 'w') as f:
                    json.dump(stats, f, indent=2)
                logger.info(f"📊 Statistics saved: {stats_file}")
        
        # Merge to Parquet
        if args.format in ['parquet', 'both']:
            output_path = processor.output_dir / args.output.replace('.jsonl', '.parquet')
            total = processor.merge_chunks(
                chunk_paths,
                output_path,
                deduplicate=args.deduplicate
            )
            
            if args.upload:
                processor.upload_to_drive(output_path)
    
    print("\n" + "="*70)
    print("✅ POST-PROCESSING COMPLETE!")
    print("="*70)
    logger.info("🎉 Post-processing complete!")


if __name__ == "__main__":
    main()
