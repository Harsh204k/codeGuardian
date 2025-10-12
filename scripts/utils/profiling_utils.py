"""
Profiling and Performance Optimization Utilities
=================================================

Production-grade profiling utilities for CodeGuardian Phase 2 pipeline:
✅ cProfile integration for function-level profiling
✅ Memory profiling with memory_profiler
✅ Execution time tracking
✅ Memory usage monitoring
✅ Cache management for intermediate results
✅ Performance report generation

Author: CodeGuardian Team
Version: 1.0.0
Date: 2025-10-12
"""

import cProfile
import pstats
import io
import time
import gc
import psutil
import os
import pickle
import functools
from pathlib import Path
from typing import Callable, Any, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

try:
    from memory_profiler import profile as memory_profile # type: ignore

    MEMORY_PROFILER_AVAILABLE = True
except ImportError:
    MEMORY_PROFILER_AVAILABLE = False
    logger.warning("memory_profiler not available - memory profiling disabled")


# ====================================================================
# EXECUTION PROFILING
# ====================================================================


class ProfileContext:
    """Context manager for profiling code blocks."""

    def __init__(self, name: str, output_path: Optional[str] = None):
        self.name = name
        self.output_path = output_path
        self.profiler = cProfile.Profile()
        self.start_time = None
        self.end_time = None
        self.start_memory = None
        self.end_memory = None

    def __enter__(self):
        logger.info(f"Starting profiler: {self.name}")
        self.start_time = time.time()
        self.start_memory = self._get_memory_usage()
        self.profiler.enable()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.profiler.disable()
        self.end_time = time.time()
        self.end_memory = self._get_memory_usage()

        duration = self.end_time - self.start_time # type: ignore
        memory_delta = self.end_memory - self.start_memory # type: ignore

        logger.info(f"Profiler '{self.name}' completed:")
        logger.info(f"  Duration: {duration:.2f}s")
        logger.info(f"  Memory delta: {memory_delta:.2f} MB")

        if self.output_path:
            self._save_profile()

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024  # MB
        except Exception:
            return 0.0

    def _save_profile(self):
        """Save profiling results to file."""
        try:
            Path(self.output_path).parent.mkdir(parents=True, exist_ok=True) # type: ignore

            with open(self.output_path, "w") as f: # type: ignore
                f.write(f"Profile Report: {self.name}\n")
                f.write(f"{'='*80}\n\n")
                f.write(f"Execution Time: {self.end_time - self.start_time:.2f}s\n") # type: ignore
                f.write(
                    f"Memory Usage: {self.start_memory:.2f} MB → {self.end_memory:.2f} MB "
                    f"(Δ {self.end_memory - self.start_memory:+.2f} MB)\n" # type: ignore
                )
                f.write(f"\n{'='*80}\n")
                f.write("Function Call Statistics:\n")
                f.write(f"{'='*80}\n\n")

                # Get profiling statistics
                stats = pstats.Stats(self.profiler, stream=f)
                stats.strip_dirs()
                stats.sort_stats("cumulative")
                stats.print_stats(50)  # Top 50 functions

            logger.info(f"Profile saved to: {self.output_path}")
        except Exception as e:
            logger.error(f"Failed to save profile: {e}")


def profile_function(output_dir: str = "logs/profiling"):
    """
    Decorator to profile a function.

    Usage:
        @profile_function(output_dir="logs/profiling")
        def my_function():
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(output_dir) / f"{func.__name__}_{timestamp}.txt"

            with ProfileContext(func.__name__, str(output_path)):
                result = func(*args, **kwargs)

            return result

        return wrapper

    return decorator


# ====================================================================
# MEMORY MONITORING
# ====================================================================


class MemoryMonitor:
    """Monitor memory usage during execution."""

    def __init__(self, name: str = "MemoryMonitor"):
        self.name = name
        self.snapshots = []
        self.start_memory = None

    def start(self):
        """Start memory monitoring."""
        self.start_memory = self._get_memory_usage()
        self.snapshots = [(time.time(), self.start_memory, "start")]
        logger.info(f"{self.name} started - Initial memory: {self.start_memory:.2f} MB")

    def snapshot(self, label: str = ""):
        """Take a memory snapshot."""
        current_memory = self._get_memory_usage()
        delta = current_memory - self.start_memory # type: ignore
        self.snapshots.append((time.time(), current_memory, label))
        logger.info(
            f"{self.name} snapshot '{label}': {current_memory:.2f} MB (Δ {delta:+.2f} MB)"
        )

    def report(self) -> Dict[str, Any]:
        """Generate memory usage report."""
        if not self.snapshots:
            return {}

        peak_memory = max(snap[1] for snap in self.snapshots)
        final_memory = self.snapshots[-1][1]
        total_delta = final_memory - self.start_memory # type: ignore

        report = {
            "start_memory_mb": round(self.start_memory, 2), # type: ignore
            "peak_memory_mb": round(peak_memory, 2),
            "final_memory_mb": round(final_memory, 2),
            "total_delta_mb": round(total_delta, 2),
            "snapshots": [
                {"timestamp": snap[0], "memory_mb": round(snap[1], 2), "label": snap[2]}
                for snap in self.snapshots
            ],
        }

        logger.info(f"{self.name} Report:")
        logger.info(f"  Start:  {report['start_memory_mb']:.2f} MB")
        logger.info(f"  Peak:   {report['peak_memory_mb']:.2f} MB")
        logger.info(f"  Final:  {report['final_memory_mb']:.2f} MB")
        logger.info(f"  Delta:  {report['total_delta_mb']:+.2f} MB")

        return report

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024
        except Exception:
            return 0.0


# ====================================================================
# CACHE MANAGEMENT
# ====================================================================


class CacheManager:
    """Manage intermediate result caching for performance optimization."""

    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def cache_exists(self, key: str, format: str = "pkl") -> bool:
        """Check if cached result exists."""
        cache_file = self.cache_dir / f"{key}.{format}"
        return cache_file.exists()

    def load(self, key: str, format: str = "pkl") -> Any:
        """Load cached result."""
        cache_file = self.cache_dir / f"{key}.{format}"

        if not cache_file.exists():
            raise FileNotFoundError(f"Cache not found: {cache_file}")

        logger.info(f"Loading cache: {cache_file}")
        start_time = time.time()

        if format == "pkl":
            with open(cache_file, "rb") as f:
                result = pickle.load(f)
        else:
            raise ValueError(f"Unsupported cache format: {format}")

        duration = time.time() - start_time
        logger.info(f"Cache loaded in {duration:.2f}s")

        return result

    def save(self, key: str, data: Any, format: str = "pkl"):
        """Save result to cache."""
        cache_file = self.cache_dir / f"{key}.{format}"

        logger.info(f"Saving cache: {cache_file}")
        start_time = time.time()

        if format == "pkl":
            with open(cache_file, "wb") as f:
                pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        else:
            raise ValueError(f"Unsupported cache format: {format}")

        duration = time.time() - start_time
        file_size = cache_file.stat().st_size / 1024 / 1024  # MB
        logger.info(f"Cache saved in {duration:.2f}s ({file_size:.2f} MB)")

    def clear(self, key: Optional[str] = None):
        """Clear cache (specific key or all)."""
        if key:
            cache_files = list(self.cache_dir.glob(f"{key}.*"))
        else:
            cache_files = list(self.cache_dir.glob("*"))

        for cache_file in cache_files:
            try:
                cache_file.unlink()
                logger.info(f"Deleted cache: {cache_file}")
            except Exception as e:
                logger.error(f"Failed to delete cache {cache_file}: {e}")

    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache directory information."""
        cache_files = list(self.cache_dir.glob("*"))
        total_size = sum(f.stat().st_size for f in cache_files if f.is_file())

        return {
            "cache_dir": str(self.cache_dir),
            "num_files": len(cache_files),
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "files": [
                {
                    "name": f.name,
                    "size_mb": round(f.stat().st_size / 1024 / 1024, 2),
                    "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                }
                for f in cache_files
                if f.is_file()
            ],
        }


# ====================================================================
# GARBAGE COLLECTION UTILITIES
# ====================================================================


def force_gc():
    """Force garbage collection to free memory."""
    logger.info("Running garbage collection...")
    start_memory = _get_memory_usage()
    gc.collect()
    end_memory = _get_memory_usage()
    freed = start_memory - end_memory
    logger.info(f"Garbage collection freed {freed:.2f} MB")


def _get_memory_usage() -> float:
    """Get current memory usage in MB."""
    try:
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    except Exception:
        return 0.0


# ====================================================================
# PERFORMANCE REPORT GENERATION
# ====================================================================


def generate_performance_report(
    profile_path: str, memory_report: Dict[str, Any], output_path: str
):
    """
    Generate comprehensive performance report.

    Args:
        profile_path: Path to cProfile output
        memory_report: Memory monitoring report
        output_path: Output path for report
    """
    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write("CodeGuardian Phase 2 Performance Report\n")
            f.write("=" * 80 + "\n\n")

            # Memory section
            f.write("Memory Usage Summary\n")
            f.write("-" * 80 + "\n")
            f.write(
                f"Start Memory:  {memory_report.get('start_memory_mb', 0):.2f} MB\n"
            )
            f.write(f"Peak Memory:   {memory_report.get('peak_memory_mb', 0):.2f} MB\n")
            f.write(
                f"Final Memory:  {memory_report.get('final_memory_mb', 0):.2f} MB\n"
            )
            f.write(
                f"Total Delta:   {memory_report.get('total_delta_mb', 0):+.2f} MB\n\n"
            )

            # Execution profile
            if Path(profile_path).exists():
                f.write("\nExecution Profile\n")
                f.write("-" * 80 + "\n")
                with open(profile_path, "r") as pf:
                    f.write(pf.read())

        logger.info(f"Performance report saved to: {output_path}")
    except Exception as e:
        logger.error(f"Failed to generate performance report: {e}")


# ====================================================================
# UTILITY FUNCTIONS
# ====================================================================


def time_function(func: Callable) -> Callable:
    """Simple decorator to time function execution."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        logger.info(f"{func.__name__} completed in {duration:.2f}s")
        return result

    return wrapper
