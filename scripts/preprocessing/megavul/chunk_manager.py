#!/usr/bin/env python3
"""
Chunk Manager for MegaVul Dataset
==================================

Handles chunked reading and writing of large JSON/JSONL files for the 100GB
MegaVul dataset. Optimized for Kaggle's 20GB disk limit.

Features:
    - Streaming JSON parsing using ijson (memory-efficient)
    - Automatic chunk size management
    - Resume support with checkpoint tracking
    - Multiple output formats (JSONL, Parquet)
    - Progress tracking and logging

Author: CodeGuardian Team
Date: 2025-10-11
"""

import json
import gzip
import logging
from pathlib import Path
from typing import Generator, Dict, Any, List, Optional, Tuple
from collections import defaultdict
import sys

# Try to import optional dependencies
try:
    import ijson
    IJSON_AVAILABLE = True
except ImportError:
    IJSON_AVAILABLE = False
    logging.warning("ijson not available - falling back to standard JSON")

try:
    import jsonlines
    JSONLINES_AVAILABLE = True
except ImportError:
    JSONLINES_AVAILABLE = False

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    PARQUET_AVAILABLE = True
except ImportError:
    PARQUET_AVAILABLE = False

logger = logging.getLogger(__name__)


class ChunkManager:
    """
    Manages chunked reading and writing of large dataset files.
    
    Optimized for streaming large JSON files without loading entire dataset
    into memory. Critical for Kaggle's 20GB disk limit.
    """
    
    def __init__(
        self,
        chunk_size_records: int = 50000,
        output_dir: Path = None,
        compression: str = "gzip"
    ):
        """
        Initialize chunk manager.
        
        Args:
            chunk_size_records: Number of records per chunk
            output_dir: Directory for output chunks
            compression: Compression type (none, gzip, bz2)
        """
        self.chunk_size_records = chunk_size_records
        self.output_dir = Path(output_dir) if output_dir else Path("./chunks")
        self.compression = compression
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"ChunkManager initialized: {chunk_size_records} records/chunk")
        logger.info(f"Output directory: {self.output_dir}")
    
    def stream_json_file(
        self,
        file_path: Path,
        start_index: int = 0,
        max_records: Optional[int] = None
    ) -> Generator[Tuple[int, Dict[str, Any]], None, None]:
        """
        Stream records from a large JSON file using ijson for memory efficiency.
        
        Supports both JSON arrays and JSONL format.
        
        Args:
            file_path: Path to input JSON file
            start_index: Skip to this record index (for resume)
            max_records: Maximum records to read (None = all)
            
        Yields:
            Tuple of (record_index, record_dict)
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return
        
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        logger.info(f"Streaming {file_path.name} ({file_size_mb:.2f} MB)")
        
        # Detect file format
        is_gzipped = file_path.suffix == '.gz'
        is_jsonl = '.jsonl' in file_path.name
        
        try:
            # Open file with appropriate handler
            if is_gzipped:
                file_handle = gzip.open(file_path, 'rb')
            else:
                file_handle = open(file_path, 'rb')
            
            records_yielded = 0
            
            if is_jsonl:
                # JSONL format - one JSON object per line
                logger.info("Detected JSONL format")
                
                if JSONLINES_AVAILABLE and not is_gzipped:
                    # Use jsonlines library for efficiency
                    with jsonlines.open(file_path) as reader:
                        for idx, record in enumerate(reader):
                            if idx < start_index:
                                continue
                            
                            yield (idx, record)
                            records_yielded += 1
                            
                            if max_records and records_yielded >= max_records:
                                break
                else:
                    # Manual JSONL parsing
                    for idx, line in enumerate(file_handle):
                        if idx < start_index:
                            continue
                        
                        try:
                            record = json.loads(line)
                            yield (idx, record)
                            records_yielded += 1
                            
                            if max_records and records_yielded >= max_records:
                                break
                        except json.JSONDecodeError as e:
                            logger.warning(f"Invalid JSON at line {idx}: {e}")
                            continue
            
            else:
                # Standard JSON array format - use ijson for streaming
                logger.info("Detected JSON array format")
                
                if IJSON_AVAILABLE:
                    # Use ijson for memory-efficient streaming
                    parser = ijson.items(file_handle, 'item')
                    
                    for idx, record in enumerate(parser):
                        if idx < start_index:
                            continue
                        
                        yield (idx, record)
                        records_yielded += 1
                        
                        if max_records and records_yielded >= max_records:
                            break
                else:
                    # Fallback: Load entire file (NOT RECOMMENDED for large files)
                    logger.warning("ijson not available - loading entire file into memory")
                    data = json.load(file_handle)
                    
                    if isinstance(data, dict):
                        # Check for common wrapper keys
                        for key in ['data', 'functions', 'records', 'vulnerabilities']:
                            if key in data and isinstance(data[key], list):
                                data = data[key]
                                break
                    
                    if not isinstance(data, list):
                        logger.error(f"Unexpected JSON structure: {type(data)}")
                        return
                    
                    for idx, record in enumerate(data):
                        if idx < start_index:
                            continue
                        
                        yield (idx, record)
                        records_yielded += 1
                        
                        if max_records and records_yielded >= max_records:
                            break
            
            file_handle.close()
            logger.info(f"Streamed {records_yielded:,} records from {file_path.name}")
            
        except Exception as e:
            logger.error(f"Error streaming {file_path}: {e}")
            if 'file_handle' in locals():
                file_handle.close()
    
    def write_chunk(
        self,
        records: List[Dict[str, Any]],
        chunk_id: str,
        output_format: str = "jsonl"
    ) -> Path:
        """
        Write a chunk of records to disk.
        
        Args:
            records: List of processed records
            chunk_id: Unique chunk identifier (e.g., "chunk_001")
            output_format: Output format (jsonl, parquet, both)
            
        Returns:
            Path to written file
        """
        if not records:
            logger.warning(f"No records to write for {chunk_id}")
            return None
        
        output_paths = []
        
        # Write JSONL format
        if output_format in ["jsonl", "both"]:
            if self.compression == "gzip":
                output_file = self.output_dir / f"{chunk_id}.jsonl.gz"
                with gzip.open(output_file, 'wt', encoding='utf-8') as f:
                    for record in records:
                        f.write(json.dumps(record) + '\n')
            else:
                output_file = self.output_dir / f"{chunk_id}.jsonl"
                with open(output_file, 'w', encoding='utf-8') as f:
                    for record in records:
                        f.write(json.dumps(record) + '\n')
            
            file_size_mb = output_file.stat().st_size / (1024 * 1024)
            logger.info(f"Wrote {len(records):,} records to {output_file.name} ({file_size_mb:.2f} MB)")
            output_paths.append(output_file)
        
        # Write Parquet format
        if output_format in ["parquet", "both"] and PARQUET_AVAILABLE:
            output_file = self.output_dir / f"{chunk_id}.parquet"
            
            try:
                # Convert to PyArrow table
                table = pa.Table.from_pylist(records)
                pq.write_table(table, output_file, compression='snappy')
                
                file_size_mb = output_file.stat().st_size / (1024 * 1024)
                logger.info(f"Wrote Parquet: {output_file.name} ({file_size_mb:.2f} MB)")
                output_paths.append(output_file)
            except Exception as e:
                logger.error(f"Failed to write Parquet: {e}")
        
        return output_paths[0] if output_paths else None
    
    def get_chunk_id(self, chunk_number: int, total_chunks: Optional[int] = None) -> str:
        """
        Generate standardized chunk ID.
        
        Args:
            chunk_number: Current chunk number (1-indexed)
            total_chunks: Total number of chunks (for padding)
            
        Returns:
            Chunk ID string (e.g., "chunk_001")
        """
        if total_chunks and total_chunks > 0:
            padding = len(str(total_chunks))
        else:
            padding = 4  # Default to 4 digits (supports up to 9999 chunks)
        
        return f"chunk_{chunk_number:0{padding}d}"
    
    def estimate_chunks(self, file_path: Path) -> int:
        """
        Estimate number of chunks needed for a file.
        
        Args:
            file_path: Path to input file
            
        Returns:
            Estimated chunk count
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return 0
        
        # Rough estimation based on file size
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        
        # Assume ~1-2 KB per record on average
        estimated_records = file_size_mb * 500  # 500 records per MB
        estimated_chunks = max(1, int(estimated_records / self.chunk_size_records))
        
        logger.info(f"Estimated {estimated_chunks} chunks for {file_path.name}")
        return estimated_chunks
    
    def chunk_generator(
        self,
        file_path: Path,
        start_chunk: int = 1,
        processed_chunks: List[str] = None
    ) -> Generator[Tuple[str, List[Dict[str, Any]]], None, None]:
        """
        Generate chunks from a large file with resume support.
        
        Args:
            file_path: Path to input file
            start_chunk: Starting chunk number (for resume)
            processed_chunks: List of already-processed chunk IDs
            
        Yields:
            Tuple of (chunk_id, records_list)
        """
        processed_chunks = processed_chunks or []
        total_chunks = self.estimate_chunks(file_path)
        
        chunk_number = start_chunk
        current_chunk = []
        start_index = (start_chunk - 1) * self.chunk_size_records
        
        logger.info(f"Starting chunk generation from chunk {start_chunk}")
        
        for idx, record in self.stream_json_file(file_path, start_index=start_index):
            current_chunk.append(record)
            
            # Yield chunk when size reached
            if len(current_chunk) >= self.chunk_size_records:
                chunk_id = self.get_chunk_id(chunk_number, total_chunks)
                
                # Skip if already processed
                if chunk_id in processed_chunks:
                    logger.info(f"Skipping already-processed {chunk_id}")
                    chunk_number += 1
                    current_chunk = []
                    continue
                
                yield (chunk_id, current_chunk)
                
                chunk_number += 1
                current_chunk = []
        
        # Yield remaining records as final chunk
        if current_chunk:
            chunk_id = self.get_chunk_id(chunk_number, total_chunks)
            
            if chunk_id not in processed_chunks:
                yield (chunk_id, current_chunk)
    
    def read_chunk(self, chunk_path: Path) -> List[Dict[str, Any]]:
        """
        Read a previously written chunk.
        
        Args:
            chunk_path: Path to chunk file
            
        Returns:
            List of records
        """
        chunk_path = Path(chunk_path)
        
        if not chunk_path.exists():
            logger.error(f"Chunk not found: {chunk_path}")
            return []
        
        records = []
        
        try:
            if chunk_path.suffix == '.parquet' and PARQUET_AVAILABLE:
                # Read Parquet
                table = pq.read_table(chunk_path)
                records = table.to_pylist()
            
            elif '.jsonl' in chunk_path.name:
                # Read JSONL
                if chunk_path.suffix == '.gz':
                    with gzip.open(chunk_path, 'rt', encoding='utf-8') as f:
                        for line in f:
                            records.append(json.loads(line))
                else:
                    with open(chunk_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            records.append(json.loads(line))
            
            logger.info(f"Read {len(records):,} records from {chunk_path.name}")
            
        except Exception as e:
            logger.error(f"Error reading chunk {chunk_path}: {e}")
        
        return records
    
    def merge_chunks(
        self,
        chunk_paths: List[Path],
        output_path: Path,
        batch_size: int = 100000
    ) -> int:
        """
        Merge multiple chunks into a single output file.
        
        Args:
            chunk_paths: List of chunk file paths
            output_path: Output file path
            batch_size: Records to accumulate before writing
            
        Returns:
            Total records merged
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        total_records = 0
        batch = []
        
        logger.info(f"Merging {len(chunk_paths)} chunks into {output_path}")
        
        # Determine output format
        is_parquet = output_path.suffix == '.parquet'
        is_gzipped = output_path.suffix == '.gz'
        
        if is_parquet and PARQUET_AVAILABLE:
            # Merge to Parquet
            writer = None
            schema = None
            
            for chunk_path in chunk_paths:
                records = self.read_chunk(chunk_path)
                
                if not records:
                    continue
                
                table = pa.Table.from_pylist(records)
                
                if writer is None:
                    schema = table.schema
                    writer = pq.ParquetWriter(output_path, schema, compression='snappy')
                
                writer.write_table(table)
                total_records += len(records)
                
                logger.info(f"Merged {chunk_path.name}: {total_records:,} total records")
            
            if writer:
                writer.close()
        
        else:
            # Merge to JSONL
            open_func = gzip.open if is_gzipped else open
            mode = 'wt' if is_gzipped else 'w'
            
            with open_func(output_path, mode, encoding='utf-8') as f:
                for chunk_path in chunk_paths:
                    records = self.read_chunk(chunk_path)
                    
                    for record in records:
                        f.write(json.dumps(record) + '\n')
                        total_records += 1
                    
                    logger.info(f"Merged {chunk_path.name}: {total_records:,} total records")
        
        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        logger.info(f"✅ Merged {total_records:,} records into {output_path.name} ({file_size_mb:.2f} MB)")
        
        return total_records


def test_chunk_manager():
    """Test chunk manager with sample data."""
    import tempfile
    
    # Create test data
    test_dir = Path(tempfile.mkdtemp())
    logger.info(f"Test directory: {test_dir}")
    
    # Write test JSON
    test_file = test_dir / "test_data.json"
    test_records = [{"id": i, "code": f"function_{i}", "label": i % 2} for i in range(1000)]
    
    with open(test_file, 'w') as f:
        json.dump(test_records, f)
    
    # Initialize chunk manager
    cm = ChunkManager(chunk_size_records=250, output_dir=test_dir / "chunks")
    
    # Test streaming
    logger.info("\n=== Testing Streaming ===")
    count = 0
    for idx, record in cm.stream_json_file(test_file):
        count += 1
        if count <= 3:
            logger.info(f"Record {idx}: {record}")
    
    logger.info(f"Streamed {count} records")
    
    # Test chunking
    logger.info("\n=== Testing Chunking ===")
    for chunk_id, records in cm.chunk_generator(test_file):
        logger.info(f"Chunk {chunk_id}: {len(records)} records")
        cm.write_chunk(records, chunk_id)
    
    # Test merging
    logger.info("\n=== Testing Merging ===")
    chunk_files = sorted(cm.output_dir.glob("chunk_*.jsonl"))
    merged_file = test_dir / "merged.jsonl"
    total = cm.merge_chunks(chunk_files, merged_file)
    logger.info(f"Merged total: {total} records")
    
    logger.info("\n✅ Chunk manager tests complete")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    test_chunk_manager()
