"""
Kaggle-compatible path management utility.

Automatically detects Kaggle environment and provides correct paths for:
- Input datasets (local vs /kaggle/input)
- Output processed data (local cache vs /kaggle/working)
- Logging and temporary files
"""

from pathlib import Path
import os
from typing import Optional


def in_kaggle() -> bool:
    """
    Detect if code is running in Kaggle environment.

    Returns:
        True if running in Kaggle, False otherwise
    """
    return os.path.exists("/kaggle/input")


def get_dataset_path(dataset_name: str) -> Path:
    """
    Get input dataset path (works locally and in Kaggle).

    Args:
        dataset_name: Relative path to dataset (e.g., "devign/raw/ffmpeg.csv")

    Returns:
        Absolute Path object to dataset location

    Examples:
        >>> get_dataset_path("devign/raw")
        # Local: C:/Users/.../codeGuardian/datasets/devign/raw
        # Kaggle: /kaggle/input/codeguardian-pre-processed-datasets/devign/raw
    """
    if in_kaggle():
        base = Path("/kaggle/input/codeguardian-pre-processed-datasets")
    else:
        # Navigate from scripts/utils/ to root, then to datasets/
        base = Path(__file__).resolve().parents[2] / "datasets"

    return base / dataset_name


def get_output_path(subdir: str = "processed", create: bool = True) -> Path:
    """
    Get output directory path for processed datasets.

    Args:
        subdir: Subdirectory name (e.g., "devign_processed", "normalized")
        create: Whether to create directory if it doesn't exist

    Returns:
        Absolute Path object to output location

    Examples:
        >>> get_output_path("devign_processed")
        # Local: C:/Users/.../codeGuardian/cache/processed_datasets_unified/devign_processed
        # Kaggle: /kaggle/working/datasets/devign_processed
    """
    if in_kaggle():
        base = Path("/kaggle/working/datasets")
    else:
        # Navigate from scripts/utils/ to root, then to cache/
        base = (
            Path(__file__).resolve().parents[2] / "cache" / "processed_datasets_unified"
        )

    output_dir = base / subdir

    if create:
        output_dir.mkdir(parents=True, exist_ok=True)

    return output_dir


def get_cache_path(cache_type: str = "temp") -> Path:
    """
    Get cache directory for temporary files, logs, etc.

    Args:
        cache_type: Type of cache ("temp", "logs", "checkpoints")

    Returns:
        Absolute Path object to cache location
    """
    if in_kaggle():
        base = Path("/kaggle/working/cache")
    else:
        base = Path(__file__).resolve().parents[2] / "cache"

    cache_dir = base / cache_type
    cache_dir.mkdir(parents=True, exist_ok=True)

    return cache_dir


def get_config_path(config_name: str = "pipeline_config.yaml") -> Path:
    """
    Get configuration file path.

    Args:
        config_name: Config file name

    Returns:
        Absolute Path object to config file
    """
    if in_kaggle():
        # Assume repo is cloned to /kaggle/working/codeGuardian
        base = Path("/kaggle/working/codeGuardian/configs")
    else:
        base = Path(__file__).resolve().parents[2] / "configs"

    return base / config_name


def print_environment_info():
    """
    Print current execution environment information.
    Useful for debugging path issues.
    """
    env = "Kaggle" if in_kaggle() else "Local"
    print(f"\n{'='*60}")
    print(f"🌍 Environment: {env}")
    print(f"{'='*60}")

    if in_kaggle():
        print(f"📁 Input Base:  /kaggle/input/codeguardian-pre-processed-datasets")
        print(f"💾 Output Base: /kaggle/working/datasets")
        print(f"🗂️  Cache Base:  /kaggle/working/cache")
    else:
        root = Path(__file__).resolve().parents[2]
        print(f"📁 Input Base:  {root / 'datasets'}")
        print(f"💾 Output Base: {root / 'cache' / 'processed_datasets_unified'}")
        print(f"🗂️  Cache Base:  {root / 'cache'}")

    print(f"{'='*60}\n")


def setup_paths():
    """
    Initialize path management and print environment info.
    Call this at the start of each preprocessing script.

    Returns:
        Tuple of (get_dataset_path, get_output_path) functions
    """
    print_environment_info()
    return get_dataset_path, get_output_path
