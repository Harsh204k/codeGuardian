#!/usr/bin/env python3
"""
Logging and Profiling Utilities
=================================

Production-grade logging and profiling infrastructure:
- Structured logging with loguru (timestamps, module names, rotation)
- Per-function timing decorators
- Memory profiling decorators
- cProfile integration
- Performance report generation

Usage:
    from scripts.utils.logging_utils import get_logger, timed, profile_memory
    
    logger = get_logger(__name__)
    
    @timed
    @profile_memory
    def my_function():
        logger.info("Processing data")
        ...

Author: CodeGuardian Team
Version: 3.1.0
"""

import time
import functools
import cProfile
import pstats
import io
from pathlib import Path
from typing import Callable, Any, Dict
from datetime import datetime
import sys

# Try to import loguru (structured logging)
try:
    from loguru import logger as loguru_logger
    HAS_LOGURU = True
except ImportError:
    HAS_LOGURU = False
    import logging
    loguru_logger = logging.getLogger(__name__)

# Try to import memory_profiler
try:
    from memory_profiler import profile as memory_profile_decorator
    HAS_MEMORY_PROFILER = True
except ImportError:
    HAS_MEMORY_PROFILER = False


# ====================================================================
# LOGGER CONFIGURATION
# ====================================================================

_LOGGERS = {}
_LOG_DIR = Path("logs/phase2")
_PROFILING_DIR = Path("logs/profiling")


def setup_logging(
    log_level: str = "INFO",
    log_dir: str = "logs/phase2",
    rotation: str = "100 MB",
    retention: str = "7 days",
    compression: str = "zip"
):
    """
    Configure global logging settings.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_dir: Directory for log files
        rotation: Log rotation size/time
        retention: How long to keep old logs
        compression: Compression format for rotated logs
    """
    global _LOG_DIR
    _LOG_DIR = Path(log_dir)
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    if HAS_LOGURU:
        # Remove default handler
        loguru_logger.remove()
        
        # Add console handler with colors
        loguru_logger.add(
            sys.stderr,
            format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
            level=log_level,
            colorize=True
        )
        
        # Add file handler with rotation
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = _LOG_DIR / f"phase2_run_{timestamp}.log"
        
        loguru_logger.add(
            str(log_file),
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level=log_level,
            rotation=rotation,
            retention=retention,
            compression=compression
        )
        
        loguru_logger.info(f"Logging configured: {log_file}")
    else:
        # Fallback to standard logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format='%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stderr),
                logging.FileHandler(_LOG_DIR / f"phase2_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            ]
        )


def get_logger(name: str):
    """
    Get a logger instance for a module.
    
    Args:
        name: Module name (typically __name__)
        
    Returns:
        Logger instance
    """
    if name not in _LOGGERS:
        if HAS_LOGURU:
            _LOGGERS[name] = loguru_logger.bind(name=name)
        else:
            _LOGGERS[name] = logging.getLogger(name)
    
    return _LOGGERS[name]


# ====================================================================
# TIMING DECORATORS
# ====================================================================

def timed(func: Callable) -> Callable:
    """
    Decorator to measure function execution time.
    
    Usage:
        @timed
        def my_function():
            ...
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        
        start_time = time.time()
        logger.info(f"⏱️  Starting {func.__name__}")
        
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            
            # Format time nicely
            if elapsed < 1:
                time_str = f"{elapsed*1000:.2f}ms"
            elif elapsed < 60:
                time_str = f"{elapsed:.2f}s"
            else:
                minutes = int(elapsed // 60)
                seconds = elapsed % 60
                time_str = f"{minutes}m {seconds:.2f}s"
            
            logger.info(f"✅ Completed {func.__name__} in {time_str}")
            return result
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"❌ Failed {func.__name__} after {elapsed:.2f}s: {e}")
            raise
    
    return wrapper


def timed_with_stats(func: Callable) -> Callable:
    """
    Decorator to measure and collect timing statistics.
    
    Stores timing data in function.__timing_stats__
    """
    if not hasattr(func, '__timing_stats__'):
        func.__timing_stats__ = {
            'calls': 0,
            'total_time': 0,
            'min_time': float('inf'),
            'max_time': 0
        }
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            
            # Update stats
            func.__timing_stats__['calls'] += 1
            func.__timing_stats__['total_time'] += elapsed
            func.__timing_stats__['min_time'] = min(func.__timing_stats__['min_time'], elapsed)
            func.__timing_stats__['max_time'] = max(func.__timing_stats__['max_time'], elapsed)
            
            return result
            
        except Exception as e:
            elapsed = time.time() - start_time
            func.__timing_stats__['calls'] += 1
            func.__timing_stats__['total_time'] += elapsed
            raise
    
    return wrapper


def get_timing_stats(func: Callable) -> Dict[str, Any]:
    """Get timing statistics for a decorated function."""
    if hasattr(func, '__timing_stats__'):
        stats = func.__timing_stats__.copy()
        if stats['calls'] > 0:
            stats['avg_time'] = stats['total_time'] / stats['calls']
        return stats
    return {}


# ====================================================================
# MEMORY PROFILING
# ====================================================================

def profile_memory(func: Callable) -> Callable:
    """
    Decorator to profile memory usage.
    
    Requires memory_profiler package.
    
    Usage:
        @profile_memory
        def my_function():
            ...
    """
    if HAS_MEMORY_PROFILER:
        # Use memory_profiler's decorator
        return memory_profile_decorator(func)
    else:
        # No-op if memory_profiler not available
        logger = get_logger(__name__)
        logger.warning(f"memory_profiler not available, skipping profiling for {func.__name__}")
        return func


# ====================================================================
# CPU PROFILING (cProfile)
# ====================================================================

def profile_cpu(output_dir: str = "logs/profiling"):
    """
    Decorator to profile CPU usage with cProfile.
    
    Usage:
        @profile_cpu()
        def my_function():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            profiler = cProfile.Profile()
            profiler.enable()
            
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                profiler.disable()
                
                # Save profile to file
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                profile_file = output_path / f"profile_{func.__name__}_{timestamp}.txt"
                
                # Write stats to file
                with open(profile_file, 'w') as f:
                    ps = pstats.Stats(profiler, stream=f)
                    ps.strip_dirs()
                    ps.sort_stats('cumulative')
                    f.write(f"Profile for {func.__name__}\n")
                    f.write("="*80 + "\n")
                    ps.print_stats(50)  # Top 50 functions
                
                logger = get_logger(func.__module__)
                logger.info(f"CPU profile saved to {profile_file}")
        
        return wrapper
    return decorator


# ====================================================================
# PROGRESS BANNER
# ====================================================================

def print_banner(title: str, width: int = 80, char: str = "="):
    """
    Print a formatted banner.
    
    Args:
        title: Banner title
        width: Banner width
        char: Border character
    """
    logger = get_logger("banner")
    
    logger.info(char * width)
    logger.info(title.center(width))
    logger.info(char * width)


def print_summary(stats: Dict[str, Any], title: str = "SUMMARY"):
    """
    Print a formatted summary of statistics.
    
    Args:
        stats: Dictionary of statistics
        title: Summary title
    """
    logger = get_logger("summary")
    
    logger.info("="*80)
    logger.info(title.center(80))
    logger.info("="*80)
    
    for key, value in stats.items():
        if isinstance(value, float):
            logger.info(f"{key:<30} {value:>15.4f}")
        elif isinstance(value, int):
            logger.info(f"{key:<30} {value:>15,}")
        else:
            logger.info(f"{key:<30} {str(value):>15}")
    
    logger.info("="*80)


# ====================================================================
# DATASET-SPECIFIC LOGGING
# ====================================================================

class DatasetLogger:
    """Logger for tracking per-dataset metrics."""
    
    def __init__(self, dataset_name: str):
        self.dataset_name = dataset_name
        self.logger = get_logger(f"dataset.{dataset_name}")
        self.start_time = None
        self.metrics = {}
    
    def start(self):
        """Start timing the dataset processing."""
        self.start_time = time.time()
        self.logger.info(f"📊 Processing dataset: {self.dataset_name}")
    
    def log_progress(self, records_processed: int, total_records: int):
        """Log processing progress."""
        percentage = (records_processed / total_records * 100) if total_records > 0 else 0
        self.logger.info(f"Progress: {records_processed:,}/{total_records:,} ({percentage:.1f}%)")
    
    def log_metric(self, metric_name: str, value: Any):
        """Log a metric."""
        self.metrics[metric_name] = value
        self.logger.info(f"{metric_name}: {value}")
    
    def finish(self, records_processed: int):
        """Finish and summarize dataset processing."""
        if self.start_time:
            elapsed = time.time() - self.start_time
            records_per_sec = records_processed / elapsed if elapsed > 0 else 0
            
            self.logger.info(f"✅ Completed {self.dataset_name}")
            self.logger.info(f"   Records: {records_processed:,}")
            self.logger.info(f"   Time: {elapsed:.2f}s")
            self.logger.info(f"   Throughput: {records_per_sec:.2f} records/sec")
            
            # Log all metrics
            if self.metrics:
                self.logger.info(f"   Metrics: {self.metrics}")


# ====================================================================
# PERFORMANCE REPORT GENERATION
# ====================================================================

def generate_performance_report(
    timing_data: Dict[str, Dict[str, Any]],
    output_path: str = "logs/profiling/performance_report.md"
):
    """
    Generate a comprehensive performance report.
    
    Args:
        timing_data: Dictionary of function names to timing stats
        output_path: Output markdown file path
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write("# Performance Report\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Function Timing Statistics\n\n")
        f.write("| Function | Calls | Total Time | Avg Time | Min Time | Max Time |\n")
        f.write("|----------|-------|------------|----------|----------|----------|\n")
        
        for func_name, stats in sorted(timing_data.items(), key=lambda x: x[1].get('total_time', 0), reverse=True):
            calls = stats.get('calls', 0)
            total = stats.get('total_time', 0)
            avg = stats.get('avg_time', 0)
            min_t = stats.get('min_time', 0)
            max_t = stats.get('max_time', 0)
            
            f.write(f"| {func_name} | {calls} | {total:.3f}s | {avg:.3f}s | {min_t:.3f}s | {max_t:.3f}s |\n")
        
        f.write("\n## Performance Summary\n\n")
        total_time = sum(stats.get('total_time', 0) for stats in timing_data.values())
        total_calls = sum(stats.get('calls', 0) for stats in timing_data.values())
        
        f.write(f"- **Total execution time:** {total_time:.2f}s\n")
        f.write(f"- **Total function calls:** {total_calls:,}\n")
        f.write(f"- **Functions profiled:** {len(timing_data)}\n")
    
    logger = get_logger(__name__)
    logger.info(f"Performance report saved to {output_path}")


# ====================================================================
# INITIALIZATION
# ====================================================================

# Auto-configure logging on import
if not _LOGGERS:
    setup_logging()
