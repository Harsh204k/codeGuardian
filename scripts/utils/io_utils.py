"""
I/O utility module for safe reading and writing of dataset files.

Provides functions for:
- Reading various file formats (JSON, JSONL, CSV, Excel, Parquet)
- Writing to JSONL/Parquet format
- Safe file handling with error recovery
- Progress tracking
- Chunked I/O for memory efficiency
- Parquet caching for faster repeated reads
- Parallel processing support

Version: 3.1.0 - Production-Grade Enhanced
"""

import json
import csv
import os
import gzip
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Iterator, Optional, Union, Callable
import logging
from tqdm import tqdm  # type: ignore
import pickle

# Optional imports for advanced features
try:
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore

    PARQUET_AVAILABLE = True
except ImportError:
    PARQUET_AVAILABLE = False

try:
    from joblib import Parallel, delayed  # type: ignore

    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

logger = logging.getLogger(__name__)


def ensure_dir(directory: str):
    """
    Ensure that a directory exists, create if it doesn't.

    Args:
        directory: Path to directory
    """
    Path(directory).mkdir(parents=True, exist_ok=True)


def read_json(file_path: str) -> Any:
    """
    Read a JSON file safely.

    Args:
        file_path: Path to JSON file

    Returns:
        Parsed JSON data

    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    logger.info(f"Reading JSON file: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(
    file_path: str, max_records: Optional[int] = None
) -> Iterator[Dict[str, Any]]:
    """
    Read JSONL file line by line.

    Args:
        file_path: Path to JSONL file
        max_records: Maximum number of records to read (None for all)

    Yields:
        Parsed JSON objects
    """
    logger.info(f"Reading JSONL file: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if max_records and i >= max_records:
                break

            line = line.strip()
            if not line:
                continue

            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping invalid JSON at line {i + 1}: {e}")
                continue


def read_csv(
    file_path: str, max_records: Optional[int] = None
) -> Iterator[Dict[str, Any]]:
    """
    Read CSV file row by row.

    Args:
        file_path: Path to CSV file
        max_records: Maximum number of records to read (None for all)

    Yields:
        Dictionary for each row
    """
    logger.info(f"Reading CSV file: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_records and i >= max_records:
                break
            yield row


def read_excel(
    file_path: str, sheet_name: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Read Excel file.

    Args:
        file_path: Path to Excel file
        sheet_name: Sheet name to read (None for first sheet)

    Returns:
        List of dictionaries for each row
    """
    logger.info(f"Reading Excel file: {file_path}")

    try:
        import pandas as pd

        df = pd.read_excel(file_path, sheet_name=sheet_name or 0)
        # Replace NaN with None
        df = df.where(pd.notna(df), None)
        return df.to_dict("records")  # type: ignore
    except ImportError:
        logger.error("pandas and openpyxl are required to read Excel files")
        raise
    except Exception as e:
        logger.error(f"Error reading Excel file: {e}")
        raise


def write_jsonl(
    records: List[Dict[str, Any]], output_path: str, show_progress: bool = True
):
    """
    Write records to JSONL file.

    Args:
        records: List of dictionaries to write
        output_path: Path to output JSONL file
        show_progress: Whether to show progress bar
    """
    logger.info(f"Writing {len(records)} records to {output_path}")

    # Ensure output directory exists
    ensure_dir(os.path.dirname(output_path))

    with open(output_path, "w", encoding="utf-8") as f:
        iterator = tqdm(records, desc="Writing records") if show_progress else records
        for record in iterator:
            json.dump(record, f, ensure_ascii=False)
            f.write("\n")

    logger.info(f"Successfully wrote {len(records)} records")


def append_jsonl(record: Dict[str, Any], output_path: str):
    """
    Append a single record to JSONL file.

    Args:
        record: Dictionary to append
        output_path: Path to output JSONL file
    """
    # Ensure output directory exists
    ensure_dir(os.path.dirname(output_path))

    with open(output_path, "a", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False)
        f.write("\n")


def write_json(data: Any, output_path: str, indent: int = 2):
    """
    Write data to JSON file.

    Args:
        data: Data to write
        output_path: Path to output JSON file
        indent: Indentation level
    """
    logger.info(f"Writing JSON to {output_path}")

    # Ensure output directory exists
    ensure_dir(os.path.dirname(output_path))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)

    logger.info(f"Successfully wrote JSON file")


def write_csv(
    records: List[Dict[str, Any]],
    output_path: str,
    fieldnames: Optional[List[str]] = None,
):
    """
    Write records to CSV file.

    Args:
        records: List of dictionaries to write
        output_path: Path to output CSV file
        fieldnames: List of field names (None to infer from first record)
    """
    logger.info(f"Writing {len(records)} records to CSV: {output_path}")

    if not records:
        logger.warning("No records to write")
        return

    # Ensure output directory exists
    ensure_dir(os.path.dirname(output_path))

    if fieldnames is None:
        fieldnames = list(records[0].keys())

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    logger.info(f"Successfully wrote CSV file")


def write_parquet(
    records: List[Dict[str, Any]],
    output_path: str,
    compression: str = "snappy",
):
    """
    Write records to Parquet file.

    Args:
        records: List of dictionaries to write
        output_path: Path to output Parquet file
        compression: Compression algorithm (snappy, gzip, brotli, none)
    """
    if not PARQUET_AVAILABLE:
        logger.error("pyarrow not available, cannot write parquet file")
        raise ImportError("pyarrow is required for parquet support")

    logger.info(f"Writing {len(records)} records to Parquet: {output_path}")

    if not records:
        logger.warning("No records to write")
        return

    # Ensure output directory exists
    ensure_dir(os.path.dirname(output_path))

    try:
        table = pa.Table.from_pylist(records)
        pq.write_table(table, output_path, compression=compression)
        logger.info(f"Successfully wrote Parquet file")
    except Exception as e:
        logger.error(f"Failed to write Parquet file: {e}")
        raise


def count_lines(file_path: str) -> int:
    """
    Count the number of lines in a file.

    Args:
        file_path: Path to file

    Returns:
        Number of lines
    """
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)


def batch_process(
    input_iterator: Iterator[Dict[str, Any]],
    process_func: Callable,
    batch_size: int = 1000,
    show_progress: bool = True,
    total: Optional[int] = None,
) -> Iterator[List[Any]]:
    """
    Process records in batches.

    Args:
        input_iterator: Iterator of input records
        process_func: Function to process each record
        batch_size: Number of records per batch
        show_progress: Whether to show progress bar
        total: Total number of records (for progress bar)

    Yields:
        Lists of processed records
    """
    batch = []
    iterator = (
        tqdm(input_iterator, total=total, desc="Processing")
        if show_progress
        else input_iterator
    )

    for record in iterator:
        try:
            processed = process_func(record)
            if processed is not None:
                batch.append(processed)

            if len(batch) >= batch_size:
                yield batch
                batch = []
        except Exception as e:
            logger.warning(f"Error processing record: {e}")
            continue

    # Yield remaining records
    if batch:
        yield batch


def safe_read_text(file_path: str, encoding: str = "utf-8") -> Optional[str]:
    """
    Safely read text file with fallback encodings.

    Args:
        file_path: Path to text file
        encoding: Primary encoding to try

    Returns:
        File content or None if failed
    """
    encodings = [encoding, "utf-8", "latin-1", "cp1252"]

    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue

    logger.error(f"Failed to read file with any encoding: {file_path}")
    return None


def get_file_info(file_path: str) -> Dict[str, Any]:
    """
    Get information about a file.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with file information
    """
    path = Path(file_path)

    if not path.exists():
        return {"exists": False}

    stat = path.stat()

    return {
        "exists": True,
        "size_bytes": stat.st_size,
        "size_mb": round(stat.st_size / (1024 * 1024), 2),
        "modified": stat.st_mtime,
        "is_file": path.is_file(),
        "is_dir": path.is_dir(),
        "extension": path.suffix,
    }


class ProgressWriter:
    """
    Context manager for writing records with progress tracking.
    """

    def __init__(self, output_path: str, total: Optional[int] = None):
        self.output_path = output_path
        self.total = total
        self.count = 0
        self.file = None
        self.pbar = None

    def __enter__(self):
        ensure_dir(os.path.dirname(self.output_path))
        self.file = open(self.output_path, "w", encoding="utf-8")
        self.pbar = tqdm(total=self.total, desc="Writing records")
        return self

    def write(self, record: Dict[str, Any]):
        """Write a single record."""
        json.dump(record, self.file, ensure_ascii=False)  # type: ignore
        self.file.write("\n")  # type: ignore
        self.count += 1
        self.pbar.update(1)  # type: ignore

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
        if self.pbar:
            self.pbar.close()

        if exc_type is None:
            logger.info(
                f"Successfully wrote {self.count} records to {self.output_path}"
            )


# ====================================================================
# CHUNKED I/O FUNCTIONS (Performance Optimized)
# ====================================================================


def chunked_read_jsonl(
    file_path: str,
    chunk_size: int = 10000,
    max_records: Optional[int] = None,
    show_progress: bool = True,
) -> Iterator[List[Dict[str, Any]]]:
    """
    Read JSONL file in chunks for memory-efficient processing.

    Args:
        file_path: Path to JSONL file
        chunk_size: Number of records per chunk
        max_records: Maximum total records to read (None for all)
        show_progress: Whether to show progress bar

    Yields:
        Lists of parsed JSON objects (chunks)

    Example:
        >>> for chunk in chunked_read_jsonl("data.jsonl", chunk_size=1000):
        >>>     # Process chunk of 1000 records
        >>>     processed = [process_record(r) for r in chunk]
    """
    logger.info(f"Reading JSONL in chunks: {file_path} (chunk_size={chunk_size})")

    # Count total lines for progress bar
    total_lines = None
    if show_progress:
        try:
            total_lines = count_lines(file_path)
            if max_records:
                total_lines = min(total_lines, max_records)
        except:
            pass

    chunk = []
    records_read = 0

    # Determine if file is gzipped
    is_gzipped = file_path.endswith(".gz")
    open_func = gzip.open if is_gzipped else open

    with open_func(file_path, "rt", encoding="utf-8") as f:
        iterator = tqdm(f, total=total_lines, desc="Reading") if show_progress else f

        for line in iterator:
            if max_records and records_read >= max_records:
                break

            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
                chunk.append(record)
                records_read += 1

                if len(chunk) >= chunk_size:
                    yield chunk
                    chunk = []
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping invalid JSON at record {records_read}: {e}")
                continue

    # Yield remaining records
    if chunk:
        yield chunk

    logger.info(f"Finished reading {records_read} records in chunks")


def chunked_write_jsonl(
    output_path: str,
    chunk_iterator: Iterator[List[Dict[str, Any]]],
    show_progress: bool = True,
    compress: bool = False,
):
    """
    Write records to JSONL file from chunk iterator.

    Args:
        output_path: Path to output JSONL file
        chunk_iterator: Iterator yielding chunks of records
        show_progress: Whether to show progress bar
        compress: Whether to gzip compress the output

    Example:
        >>> chunks = chunked_read_jsonl("input.jsonl")
        >>> processed_chunks = ([process(r) for r in chunk] for chunk in chunks)
        >>> chunked_write_jsonl("output.jsonl", processed_chunks)
    """
    logger.info(f"Writing JSONL in chunks to {output_path}")

    # Ensure output directory exists
    ensure_dir(os.path.dirname(output_path))

    # Add .gz extension if compressing
    if compress and not output_path.endswith(".gz"):
        output_path += ".gz"

    open_func = gzip.open if compress else open
    total_records = 0

    with open_func(output_path, "wt", encoding="utf-8") as f:
        for chunk in (
            tqdm(chunk_iterator, desc="Writing chunks")
            if show_progress
            else chunk_iterator
        ):
            for record in chunk:
                json.dump(record, f, ensure_ascii=False)
                f.write("\n")
                total_records += 1

    logger.info(f"Successfully wrote {total_records} records to {output_path}")


def stream_process(
    input_path: str,
    output_path: str,
    process_func: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]],
    chunk_size: int = 10000,
    show_progress: bool = True,
    compress_output: bool = False,
):
    """
    Stream-process JSONL file in chunks (input → process → output).
    Memory-efficient for large files.

    Args:
        input_path: Path to input JSONL file
        output_path: Path to output JSONL file
        process_func: Function to process each record (returns None to skip)
        chunk_size: Number of records per chunk
        show_progress: Whether to show progress bar
        compress_output: Whether to gzip compress output

    Example:
        >>> def clean_code(record):
        >>>     record['code'] = record['code'].strip()
        >>>     return record
        >>> stream_process("input.jsonl", "output.jsonl", clean_code)
    """

    def process_chunk_iterator():
        for chunk in chunked_read_jsonl(
            input_path, chunk_size, show_progress=show_progress
        ):
            processed = []
            for record in chunk:
                try:
                    result = process_func(record)
                    if result is not None:
                        processed.append(result)
                except Exception as e:
                    logger.warning(f"Error processing record: {e}")
                    continue
            if processed:
                yield processed

    chunked_write_jsonl(
        output_path,
        process_chunk_iterator(),
        show_progress=False,
        compress=compress_output,
    )


# ====================================================================
# PARQUET CACHING (Fast Reads for Repeated Access)
# ====================================================================


def _get_cache_path(cache_key: str, cache_dir: str = "datasets/cache") -> str:
    """Generate cache file path from cache key."""
    ensure_dir(cache_dir)
    safe_key = hashlib.md5(cache_key.encode()).hexdigest()[:16]
    return os.path.join(cache_dir, f"{safe_key}.parquet")


def read_parquet_cached(
    cache_key: str, cache_dir: str = "datasets/cache"
) -> Optional[List[Dict[str, Any]]]:
    """
    Read dataset from parquet cache if available.

    Args:
        cache_key: Unique identifier for cached data
        cache_dir: Directory to store cache files

    Returns:
        List of records if cache exists, None otherwise
    """
    if not PARQUET_AVAILABLE:
        logger.warning("pyarrow not available, parquet caching disabled")
        return None

    cache_path = _get_cache_path(cache_key, cache_dir)

    if not os.path.exists(cache_path):
        logger.debug(f"Cache miss: {cache_key}")
        return None

    try:
        logger.info(f"Cache hit: Loading from {cache_path}")
        table = pq.read_table(cache_path)
        records = table.to_pylist()
        logger.info(f"Loaded {len(records)} records from cache")
        return records
    except Exception as e:
        logger.warning(f"Failed to read cache: {e}")
        return None


def write_parquet_cached(
    records: List[Dict[str, Any]],
    cache_key: str,
    cache_dir: str = "datasets/cache",
    compression: str = "snappy",
):
    """
    Write dataset to parquet cache for fast future reads.

    Args:
        records: List of records to cache
        cache_key: Unique identifier for cached data
        cache_dir: Directory to store cache files
        compression: Compression algorithm (snappy, gzip, brotli, none)
    """
    if not PARQUET_AVAILABLE:
        logger.warning("pyarrow not available, skipping parquet caching")
        return

    cache_path = _get_cache_path(cache_key, cache_dir)

    try:
        logger.info(f"Writing {len(records)} records to cache: {cache_path}")
        table = pa.Table.from_pylist(records)
        pq.write_table(table, cache_path, compression=compression)
        logger.info(f"Successfully cached to {cache_path}")
    except Exception as e:
        logger.error(f"Failed to write cache: {e}")


def read_with_cache(
    source_path: str,
    cache_key: Optional[str] = None,
    cache_dir: str = "datasets/cache",
    use_cache: bool = True,
) -> List[Dict[str, Any]]:
    """
    Read JSONL with automatic parquet caching.

    Args:
        source_path: Path to source JSONL file
        cache_key: Cache identifier (defaults to source_path)
        cache_dir: Cache directory
        use_cache: Whether to use caching

    Returns:
        List of records

    Example:
        >>> # First call: reads JSONL, caches to parquet
        >>> data = read_with_cache("data.jsonl")
        >>> # Second call: reads from parquet cache (much faster!)
        >>> data = read_with_cache("data.jsonl")
    """
    if cache_key is None:
        cache_key = source_path

    # Try reading from cache
    if use_cache:
        cached = read_parquet_cached(cache_key, cache_dir)
        if cached is not None:
            return cached

    # Cache miss: read from source
    logger.info(f"Reading from source: {source_path}")
    records = list(read_jsonl(source_path))

    # Write to cache for next time
    if use_cache and records:
        write_parquet_cached(records, cache_key, cache_dir)

    return records


# ====================================================================
# PICKLE CACHING (For Complex Python Objects)
# ====================================================================


def write_pickle_cached(data: Any, cache_key: str, cache_dir: str = "datasets/cache"):
    """
    Write Python object to pickle cache.

    Args:
        data: Python object to cache
        cache_key: Unique identifier
        cache_dir: Cache directory
    """
    ensure_dir(cache_dir)
    safe_key = hashlib.md5(cache_key.encode()).hexdigest()[:16]
    cache_path = os.path.join(cache_dir, f"{safe_key}.pkl")

    try:
        with open(cache_path, "wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        logger.info(f"Cached to pickle: {cache_path}")
    except Exception as e:
        logger.error(f"Failed to pickle cache: {e}")


def read_pickle_cached(
    cache_key: str, cache_dir: str = "datasets/cache"
) -> Optional[Any]:
    """
    Read Python object from pickle cache.

    Args:
        cache_key: Unique identifier
        cache_dir: Cache directory

    Returns:
        Cached object or None
    """
    safe_key = hashlib.md5(cache_key.encode()).hexdigest()[:16]
    cache_path = os.path.join(cache_dir, f"{safe_key}.pkl")

    if not os.path.exists(cache_path):
        return None

    try:
        with open(cache_path, "rb") as f:
            data = pickle.load(f)
        logger.info(f"Loaded from pickle cache: {cache_path}")
        return data
    except Exception as e:
        logger.warning(f"Failed to read pickle cache: {e}")
        return None


# ====================================================================
# PARALLEL PROCESSING UTILITIES
# ====================================================================


def parallel_process_files(
    file_paths: List[str],
    process_func: Callable[[str], Any],
    n_jobs: int = -1,
    backend: str = "threading",
    show_progress: bool = True,
) -> List[Any]:
    """
    Process multiple files in parallel.

    Args:
        file_paths: List of file paths to process
        process_func: Function to process each file (takes file_path, returns result)
        n_jobs: Number of parallel jobs (-1 = all CPUs)
        backend: "threading" or "multiprocessing"
        show_progress: Show progress bar

    Returns:
        List of results from process_func

    Example:
        >>> def process_dataset(path):
        >>>     return list(read_jsonl(path))
        >>> results = parallel_process_files(
        >>>     ["data1.jsonl", "data2.jsonl"],
        >>>     process_dataset,
        >>>     n_jobs=2
        >>> )
    """
    if not JOBLIB_AVAILABLE:
        logger.warning("joblib not available, falling back to sequential processing")
        results = []
        iterator = (
            tqdm(file_paths, desc="Processing files") if show_progress else file_paths
        )
        for path in iterator:
            results.append(process_func(path))
        return results

    logger.info(f"Processing {len(file_paths)} files in parallel (n_jobs={n_jobs})")

    results = Parallel(n_jobs=n_jobs, backend=backend)(
        delayed(process_func)(path)
        for path in tqdm(file_paths, desc="Processing")
        if show_progress
    )

    return results # type: ignore
