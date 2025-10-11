#!/usr/bin/env python3
"""
MegaVul Chunked Preprocessing Orchestrator
===========================================

Main entry point for processing the 100GB MegaVul dataset within Kaggle's
20GB disk limit using chunked processing and Google Drive persistence.

Features:
    - Automatic chunking (50k records per chunk)
    - Google Drive sync with checksum verification
    - Resume support via checkpoint tracker
    - Memory-efficient streaming (< 8GB peak usage)
    - Progress tracking and logging

Author: CodeGuardian Team
Date: 2025-10-11

Usage:
    # Full preprocessing
    python prepare_megavul_chunked.py --config config_megavul.yaml
    
    # Test mode (1000 records)
    python prepare_megavul_chunked.py --test
    
    # Resume from checkpoint
    python prepare_megavul_chunked.py --resume
    
    # Specific languages only
    python prepare_megavul_chunked.py --languages C C++
"""

import argparse
import logging
import json
import time
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import local modules
from chunk_manager import ChunkManager
from drive_sync import DriveSync
from megavul_file_discovery import discover_megavul_files, estimate_total_records
from utils_megavul import (
    normalize_record,
    validate_record,
    validate_schema_consistency,
    log_event,
    create_processing_summary,
    deduplicate_by_code_hash,
    generate_megavul_stats
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('megavul_preprocessing.log')
    ]
)
logger = logging.getLogger(__name__)

# Try to import tqdm for progress bars
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    logger.warning("tqdm not available - progress bars disabled")


class MegaVulPreprocessor:
    """
    Orchestrates the entire MegaVul preprocessing pipeline.
    
    Coordinates chunking, normalization, Drive sync, and checkpointing
    to process the 100GB dataset within Kaggle's memory constraints.
    """
    
    def __init__(self, config_path: str = "config_megavul.yaml", include_graphs: bool = False):
        """
        Initialize preprocessor with configuration.
        
        Args:
            config_path: Path to YAML configuration file
            include_graphs: Whether to extract graph representations (AST/PDG/CFG/DFG)
        """
        self.config = self.load_config(config_path)
        self.include_graphs = include_graphs  # Store for use in processing
        self.stats = {
            'total_records_processed': 0,
            'valid_records': 0,
            'invalid_records': 0,
            'chunks_created': 0,
            'chunks_uploaded': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Initialize components
        self.chunk_manager = ChunkManager(
            chunk_size_records=self.config['chunk_size_records'],
            output_dir=Path(self.config['output_dir']),
            compression=self.config.get('compression', 'gzip')
        )
        
        self.drive_sync = None
        if self.config.get('drive_enabled', True):
            self.drive_sync = DriveSync(
                drive_root=self.config['drive_mount_dir'],
                verify_checksum=self.config.get('verify_checksum', True),
                max_retries=self.config.get('max_retries', 3),
                retry_delay=self.config.get('retry_delay_seconds', 5),
                delete_after_upload=self.config.get('delete_after_upload', True)
            )
        
        self.resume_tracker = self.load_resume_tracker()
        
        logger.info("✅ MegaVulPreprocessor initialized")
        logger.info(f"   Chunk size: {self.config['chunk_size_records']:,} records")
        logger.info(f"   Drive sync: {'ENABLED' if self.drive_sync else 'DISABLED'}")
    
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        config_path = Path(config_path)
        
        if not config_path.exists():
            logger.error(f"Config file not found: {config_path}")
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        logger.info(f"✅ Loaded config: {config_path}")
        return config
    
    def load_resume_tracker(self) -> Dict[str, Any]:
        """Load or create resume tracker."""
        tracker_file = Path(self.config.get('resume_tracker_file', 'resume_tracker.json'))
        
        if tracker_file.exists():
            with open(tracker_file) as f:
                tracker = json.load(f)
            logger.info(f"✅ Loaded resume tracker: {len(tracker.get('completed_chunks', []))} chunks completed")
            return tracker
        else:
            tracker = {
                'completed_chunks': [],
                'last_updated': None,
                'total_records_processed': 0,
                'session_id': datetime.now().strftime("%Y%m%d_%H%M%S"),
                'status': 'not_started'
            }
            logger.info("📝 Created new resume tracker")
            return tracker
    
    def save_resume_tracker(self):
        """Save resume tracker to disk and Drive."""
        tracker_file = Path(self.config.get('resume_tracker_file', 'resume_tracker.json'))
        
        self.resume_tracker['last_updated'] = datetime.now(timezone.utc).isoformat()
        self.resume_tracker['status'] = 'in_progress'
        
        with open(tracker_file, 'w') as f:
            json.dump(self.resume_tracker, f, indent=2)
        
        # Also upload to Drive
        if self.drive_sync and self.drive_sync.drive_mounted:
            self.drive_sync.upload_file(
                tracker_file,
                remote_subdir="",
                remote_name="resume_tracker.json"
            )
        
        logger.debug(f"💾 Saved resume tracker: {len(self.resume_tracker['completed_chunks'])} chunks")
    
    def discover_input_files(self) -> List[Tuple[Path, int]]:
        """
        Discover all MegaVul input files in the deeply nested structure.
        
        Returns:
            List of (file_path, label) tuples
        """
        input_dir = Path(self.config['raw_dataset_dir'])
        
        if not input_dir.exists():
            logger.error(f"Input directory not found: {input_dir}")
            return []
        
        # Use optimized file discovery
        target_languages = self.config.get('target_languages', ['all'])
        
        files_with_labels = discover_megavul_files(
            base_dir=input_dir,
            target_languages=target_languages
        )
        
        if files_with_labels:
            # Estimate total records
            estimate_total_records(files_with_labels, sample_size=20)
        
        return files_with_labels
    
    def process_chunk(
        self,
        chunk_id: str,
        raw_records: List[Dict[str, Any]],
        default_label: Optional[int] = None
    ) -> Optional[Path]:
        """
        Process a single chunk: normalize, validate, write, upload.
        
        Args:
            chunk_id: Chunk identifier (e.g., "chunk_001")
            raw_records: List of raw records from dataset
            default_label: Default label for records (from file path)
            
        Returns:
            Path to processed chunk file, or None if failed
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"Processing {chunk_id}: {len(raw_records):,} records")
        if default_label is not None:
            logger.info(f"Label from path: {default_label} ({'vulnerable' if default_label == 1 else 'safe'})")
        logger.info(f"{'='*70}")
        
        # Normalize records
        normalized_records = []
        
        iterator = tqdm(raw_records, desc=f"Normalizing {chunk_id}") if TQDM_AVAILABLE else raw_records
        
        for idx, raw_record in enumerate(iterator):
            # Apply default label if not present in record
            if default_label is not None and 'label' not in raw_record:
                raw_record['label'] = default_label
            
            normalized = normalize_record(
                raw_record,
                dataset_name="megavul",
                index=self.stats['total_records_processed'] + idx,
                include_graphs=self.include_graphs  # Pass graph extraction flag
            )
            
            if normalized:
                normalized_records.append(normalized)
        
        self.stats['total_records_processed'] += len(raw_records)
        self.stats['valid_records'] += len(normalized_records)
        self.stats['invalid_records'] += (len(raw_records) - len(normalized_records))
        
        logger.info(f"✅ Normalized: {len(normalized_records):,}/{len(raw_records):,} records")
        
        if not normalized_records:
            logger.warning(f"⚠️  No valid records in {chunk_id}")
            return None
        
        # Validate schema consistency
        if self.config.get('schema_validation', True):
            validation_report = validate_schema_consistency(normalized_records)
            logger.info(f"✅ Validation: {validation_report['valid_records']}/{validation_report['total_records']} valid")
            
            if validation_report.get('errors'):
                logger.warning(f"⚠️  Validation errors: {validation_report['errors']}")
        
        # Deduplicate if enabled
        if self.config.get('deduplicate', True):
            original_count = len(normalized_records)
            normalized_records = deduplicate_by_code_hash(normalized_records)
            removed = original_count - len(normalized_records)
            if removed > 0:
                logger.info(f"🔄 Deduplicated: removed {removed:,} duplicates")
        
        # Write chunk to disk
        output_format = self.config.get('output_format', 'jsonl')
        chunk_path = self.chunk_manager.write_chunk(
            normalized_records,
            chunk_id,
            output_format=output_format
        )
        
        if not chunk_path:
            logger.error(f"❌ Failed to write {chunk_id}")
            return None
        
        self.stats['chunks_created'] += 1
        
        # Upload to Drive if enabled
        if self.drive_sync:
            logger.info(f"☁️  Uploading {chunk_id} to Google Drive...")
            remote_path = self.drive_sync.upload_file(
                chunk_path,
                remote_subdir="chunks"
            )
            
            if remote_path:
                logger.info(f"✅ Uploaded to Drive: {remote_path.name}")
                self.stats['chunks_uploaded'] += 1
            else:
                logger.error(f"❌ Upload failed for {chunk_id}")
                # Don't return None - local file still exists
        
        # Update resume tracker
        self.resume_tracker['completed_chunks'].append(chunk_id)
        self.resume_tracker['total_records_processed'] = self.stats['total_records_processed']
        self.save_resume_tracker()
        
        return chunk_path
    
    def run(
        self,
        max_records: Optional[int] = None,
        target_languages: Optional[List[str]] = None,
        resume: bool = False
    ):
        """
        Run the complete preprocessing pipeline.
        
        Args:
            max_records: Maximum records to process (for testing)
            target_languages: Filter to specific languages
            resume: Resume from checkpoint
        """
        self.stats['start_time'] = time.time()
        
        print("\n" + "="*70)
        print("🚀 MEGAVUL CHUNKED PREPROCESSING PIPELINE")
        print("   Optimized for Kaggle Free Tier (20GB limit)")
        print("="*70 + "\n")
        
        # Mount Drive if enabled
        if self.drive_sync:
            logger.info("☁️  Mounting Google Drive...")
            if self.drive_sync.mount_drive():
                logger.info("✅ Google Drive mounted successfully")
            else:
                logger.warning("⚠️  Drive mount failed - continuing without Drive sync")
                self.drive_sync = None
        
        # Discover input files with labels
        files_with_labels = self.discover_input_files()
        
        if not files_with_labels:
            logger.error("❌ No input files found!")
            return
        
        # Process each input file
        total_chunks_processed = 0
        all_records = []  # Collect records from all files for final merging
        
        for file_idx, (file_path, file_label) in enumerate(files_with_labels, 1):
            logger.info(f"\n{'='*70}")
            logger.info(f"📖 Processing file {file_idx}/{len(files_with_labels)}: {file_path.name}")
            logger.info(f"   Label: {file_label} ({'vulnerable' if file_label == 1 else 'safe'})")
            logger.info(f"{'='*70}")
            
            # Check max_records limit
            if max_records and self.stats['total_records_processed'] >= max_records:
                logger.info(f"⏹️  Reached max_records limit ({max_records:,})")
                break
            
            # Read file and collect records
            try:
                import json
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_data = json.load(f)
                
                # Handle both list and dict formats
                if isinstance(file_data, list):
                    raw_records = file_data
                elif isinstance(file_data, dict):
                    raw_records = [file_data]
                else:
                    logger.warning(f"⚠️  Unknown format in {file_path}, skipping")
                    continue
                
                # Add to collection
                for record in raw_records:
                    if 'label' not in record:
                        record['label'] = file_label
                    all_records.append(record)
                
                logger.info(f"   Loaded {len(raw_records):,} records (total: {len(all_records):,})")
                
                # Process in chunks when we have enough records
                while len(all_records) >= self.config['chunk_size_records']:
                    chunk_records = all_records[:self.config['chunk_size_records']]
                    all_records = all_records[self.config['chunk_size_records']:]
                    
                    total_chunks_processed += 1
                    chunk_id = f"chunk_{total_chunks_processed:04d}"
                    
                    # Process chunk
                    chunk_path = self.process_chunk(chunk_id, chunk_records)
                    
                    if chunk_path:
                        logger.info(f"✅ {chunk_id} complete")
                    else:
                        logger.warning(f"⚠️  {chunk_id} failed")
                    
                    # Check max_records limit
                    if max_records and self.stats['total_records_processed'] >= max_records:
                        break
                
            except Exception as e:
                logger.error(f"❌ Error processing {file_path}: {e}")
                continue
        
        # Process remaining records
        if all_records and (not max_records or self.stats['total_records_processed'] < max_records):
            total_chunks_processed += 1
            chunk_id = f"chunk_{total_chunks_processed:04d}"
            logger.info(f"\n📦 Processing final chunk with {len(all_records):,} records")
            self.process_chunk(chunk_id, all_records)
        
        # Finalize
        self.stats['end_time'] = time.time()
        self.finalize()
    
    def finalize(self):
        """Finalize processing and generate summary."""
        processing_time = self.stats['end_time'] - self.stats['start_time']
        
        # Update resume tracker
        self.resume_tracker['status'] = 'completed'
        self.save_resume_tracker()
        
        # Generate summary
        summary = create_processing_summary(
            total_records=self.stats['total_records_processed'],
            valid_records=self.stats['valid_records'],
            processing_time=processing_time,
            chunk_count=self.stats['chunks_created'],
            additional_stats={
                'chunks_uploaded': self.stats['chunks_uploaded'],
                'invalid_records': self.stats['invalid_records']
            }
        )
        
        # Save summary
        summary_file = Path(self.config['output_dir']) / "processing_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Upload summary to Drive
        if self.drive_sync and self.drive_sync.drive_mounted:
            self.drive_sync.upload_file(summary_file, remote_subdir="logs")
            self.drive_sync.save_upload_log()
        
        # Print final report
        print("\n" + "="*70)
        print("✅ PREPROCESSING COMPLETE!")
        print("="*70)
        print(f"\n📊 RESULTS:")
        print(f"   Total records processed: {self.stats['total_records_processed']:,}")
        print(f"   Valid records: {self.stats['valid_records']:,} ({summary['success_rate']:.2%})")
        print(f"   Invalid records: {self.stats['invalid_records']:,}")
        print(f"   Chunks created: {self.stats['chunks_created']}")
        print(f"   Chunks uploaded: {self.stats['chunks_uploaded']}")
        
        print(f"\n⏱️  PERFORMANCE:")
        print(f"   Total time: {processing_time/3600:.2f} hours")
        print(f"   Processing speed: {summary['records_per_second']:.0f} records/sec")
        print(f"   Avg records/chunk: {summary['avg_records_per_chunk']:.0f}")
        
        if self.drive_sync:
            usage = self.drive_sync.get_disk_usage()
            print(f"\n☁️  GOOGLE DRIVE:")
            print(f"   Files uploaded: {usage.get('file_count', 0)}")
            print(f"   Total size: {usage.get('total_size_gb', 0):.2f} GB")
        
        print(f"\n📁 OUTPUT:")
        print(f"   Local: {self.config['output_dir']}")
        if self.drive_sync:
            print(f"   Drive: {self.config['drive_mount_dir']}")
        
        print("\n" + "="*70)
        
        logger.info("🎉 Preprocessing pipeline complete!")


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description='MegaVul Chunked Preprocessing for Kaggle (20GB limit)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full preprocessing
  python prepare_megavul_chunked.py --config config_megavul.yaml
  
  # Test mode (1000 records)
  python prepare_megavul_chunked.py --test
  
  # Resume from checkpoint
  python prepare_megavul_chunked.py --resume
  
  # Specific languages only
  python prepare_megavul_chunked.py --languages C C++ Java
  
  # Extract graph representations (AST, PDG, CFG, DFG)
  python prepare_megavul_chunked.py --include-graphs
  
  # Disable Drive sync (local only)
  python prepare_megavul_chunked.py --no-drive-sync
        """
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config_megavul.yaml',
        help='Path to configuration YAML file'
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test mode: process 1000 records only'
    )
    parser.add_argument(
        '--max-records',
        type=int,
        default=None,
        help='Maximum records to process'
    )
    parser.add_argument(
        '--resume',
        action='store_true',
        help='Resume from last checkpoint'
    )
    parser.add_argument(
        '--languages',
        nargs='+',
        default=None,
        help='Target languages (C, C++, Java)'
    )
    parser.add_argument(
        '--no-drive-sync',
        action='store_true',
        help='Disable Google Drive synchronization'
    )
    parser.add_argument(
        '--include-graphs',
        action='store_true',
        help='Extract graph representations (AST, PDG, CFG, DFG) - same as original'
    )
    
    args = parser.parse_args()
    
    # Test mode
    if args.test:
        args.max_records = 1000
        logger.info("⚡ TEST MODE: Processing 1000 records")
    
    # Load and modify config if needed
    config_path = args.config
    
    if args.no_drive_sync:
        # Temporarily modify config
        with open(config_path) as f:
            config = yaml.safe_load(f)
        config['drive_enabled'] = False
        
        # Write temporary config
        temp_config = Path("config_temp.yaml")
        with open(temp_config, 'w') as f:
            yaml.dump(config, f)
        
        config_path = temp_config
        logger.info("🔌 Drive sync DISABLED")
    
    # Initialize and run preprocessor
    try:
        preprocessor = MegaVulPreprocessor(config_path, include_graphs=args.include_graphs)
        
        if args.include_graphs:
            logger.info("📊 Graph extraction ENABLED (AST, PDG, CFG, DFG)")
        
        preprocessor.run(
            max_records=args.max_records,
            target_languages=args.languages,
            resume=args.resume
        )
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Processing interrupted by user")
        logger.info("💾 Progress saved - use --resume to continue")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}", exc_info=True)
        raise
    finally:
        # Cleanup temp config
        if args.no_drive_sync and Path("config_temp.yaml").exists():
            Path("config_temp.yaml").unlink()


if __name__ == "__main__":
    main()
