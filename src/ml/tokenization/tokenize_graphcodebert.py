#! /usr/bin/env python
# type: ignore

"""
GraphCodeBERT Tokenization Pipeline for Vulnerability Detection with Multimodal Features
====================================================================================
Production-ready tokenization script with engineered numeric features support.

Features:
✅ JSONL input with code + ~107 numeric features
✅ Tokenization with GraphCodeBERT
✅ Feature extraction and normalization
✅ Multimodal output: input_ids + attention_mask + labels + features

Output:
.pt files containing: input_ids, attention_mask, labels, features
"""

import os
import json
import torch
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import Counter
import logging
from tqdm.auto import tqdm
from transformers import AutoTokenizer
from torch.utils.data import Dataset, DataLoader
import multiprocessing as mp
from functools import partial
import hashlib
import random
import numpy as np
from sklearn.preprocessing import StandardScaler

# ============================================================================
# CONFIGURATION
# ============================================================================


@dataclass
class TokenizationConfig:
    """Configuration for tokenization pipeline"""

    # Model configuration
    model_name: str = "microsoft/graphcodebert-base"
    max_seq_length: int = 512
    dynamic_padding: bool = True  # Enable dynamic padding per batch

    # Input paths (Kaggle)
    input_base: str = (
        "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted"
    )
    train_path: str = f"{input_base}/train.jsonl"
    val_path: str = f"{input_base}/val.jsonl"
    test_path: str = f"{input_base}/test.jsonl"

    # Output paths
    output_base: str = "/kaggle/working/datasets/tokenized/graphcodebert"
    cache_dir: str = f"{output_base}/.cache"  # Cache directory
    train_output: str = f"{output_base}/train_tokenized_graphcodebert.pt"
    val_output: str = f"{output_base}/val_tokenized_graphcodebert.pt"
    test_output: str = f"{output_base}/test_tokenized_graphcodebert.pt"
    error_log: str = f"{output_base}/tokenization_errors.jsonl"

    # Processing configuration
    batch_size: int = 128  # Increased for faster processing (was 32)
    num_workers: int = (
        0  # Single process is faster for tokenization (multiprocessing overhead)
    )
    padding: str = "max_length"  # Will be overridden if dynamic_padding=True
    truncation: bool = True
    return_attention_mask: bool = True
    shuffle_train: bool = True  # Shuffle training data for better generalization
    random_seed: int = 42  # Reproducibility seed

    # Caching configuration
    use_cache: bool = True  # Enable caching
    force_retokenize: bool = False  # Force retokenization even if cache exists

    # Error handling
    skip_on_error: bool = True  # Skip problematic rows instead of failing
    max_errors_per_split: int = 100  # Max errors before stopping

    # Label validation
    strict_binary_labels: bool = True  # Enforce 0/1 labels only
    support_multiclass: bool = False  # Future extension for CWE multi-class

    # Validation thresholds
    min_samples: int = 100
    max_label_imbalance: float = 0.95  # Max 95% of one class

    # Feature engineering configuration
    normalize_features: bool = True  # Apply StandardScaler to numeric features
    feature_columns_exclude: List[str] = None  # Columns to exclude from features

    def __post_init__(self):
        if self.feature_columns_exclude is None:
            self.feature_columns_exclude = ["code", "is_vulnerable", "id", "language", "dataset"]


# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/kaggle/working/tokenization.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


# ============================================================================
# ERROR TRACKING
# ============================================================================


class ErrorTracker:
    """Track and log tokenization errors per row (multiprocessing-safe)"""

    def __init__(self, config: TokenizationConfig):
        self.config = config
        self.errors = []
        self.error_log_path = config.error_log
        # Don't keep file handle open - open/close for each write to be pickle-safe

    def log_error(
        self,
        row_id: str,
        split_name: str,
        error_type: str,
        error_msg: str,
        row_data: Optional[Dict] = None,
    ):
        """Log error for a specific row"""
        error_entry: Dict = {
            "row_id": row_id,
            "split": split_name,
            "error_type": error_type,
            "error_message": str(error_msg),
            "timestamp": (
                str(torch.cuda.Event(enable_timing=False))
                if torch.cuda.is_available()
                else "N/A"
            ),
        }

        if row_data:
            error_entry["row_preview"] = {
                "code_length": len(str(row_data.get("code", ""))),
                "label": row_data.get("is_vulnerable", "N/A"),
            }

        self.errors.append(error_entry)

        # Open, write, and close immediately for multiprocessing safety
        try:
            with open(self.error_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(error_entry) + "\n")
        except Exception as e:
            logger.warning(f"Failed to write error log: {e}")

        logger.warning(
            f"⚠️ Row error [{split_name}]: ID={row_id}, Type={error_type}, Msg={error_msg}"
        )

    def get_error_count(self, split_name: Optional[str] = None) -> int:
        """Get error count for a specific split or all"""
        if split_name:
            return sum(1 for e in self.errors if e["split"] == split_name)
        return len(self.errors)

    def should_stop(self, split_name: str) -> bool:
        """Check if error threshold exceeded"""
        count = self.get_error_count(split_name)
        if count >= self.config.max_errors_per_split:
            logger.error(
                f"❌ PENALTY: Too many errors in {split_name}: {count}/{self.config.max_errors_per_split}"
            )
            return True
        return False

    def close(self):
        """Close error log file (no-op since we don't keep file open)"""
        pass

    def __del__(self):
        """Cleanup (no-op since we don't keep file open)"""
        pass


# ============================================================================
# CACHE MANAGEMENT
# ============================================================================


def get_cache_path(split_name: str, config: TokenizationConfig) -> str:
    """Generate cache file path"""
    cache_filename = (
        f"{split_name}_cache_seed{config.random_seed}_len{config.max_seq_length}.pt"
    )
    return os.path.join(config.cache_dir, cache_filename)


def load_from_cache(
    split_name: str, config: TokenizationConfig
) -> Optional[Dict[str, torch.Tensor]]:
    """Load tokenized data from cache if available"""
    if not config.use_cache or config.force_retokenize:
        return None

    cache_path = get_cache_path(split_name, config)

    if os.path.exists(cache_path):
        try:
            logger.info(f"📦 Loading {split_name} from cache: {cache_path}")
            cached_data = torch.load(cache_path)
            logger.info(
                f"✅ Cache hit! Loaded {cached_data['input_ids'].shape[0]} samples"
            )
            return cached_data
        except Exception as e:
            logger.warning(
                f"⚠️ Cache load failed for {split_name}: {e}. Retokenizing..."
            )
            return None

    logger.info(f"📭 No cache found for {split_name}. Will tokenize and cache.")
    return None


def save_to_cache(
    tokenized_data: Dict[str, torch.Tensor], split_name: str, config: TokenizationConfig
):
    """Save tokenized data to cache"""
    if not config.use_cache:
        return

    try:
        os.makedirs(config.cache_dir, exist_ok=True)
        cache_path = get_cache_path(split_name, config)
        torch.save(tokenized_data, cache_path)
        logger.info(f"💾 Cached {split_name} to: {cache_path}")
    except Exception as e:
        logger.warning(f"⚠️ Cache save failed for {split_name}: {e}")


# ============================================================================
# DATA LOADING
# ============================================================================


def set_seed(seed: int):
    """Set random seed for reproducibility"""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    logger.info(f"🎲 Random seed set to: {seed}")


def load_jsonl(file_path: str) -> pd.DataFrame:
    """
    Load JSONL file with pandas for efficient feature extraction.

    Returns: DataFrame with all columns (code, is_vulnerable, features)
    """
    try:
        logger.info(f"📂 Loading JSONL file: {file_path}")
        df = pd.read_json(file_path, lines=True)

        # Fill NaN values in numeric columns with 0.0
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0.0)

        logger.info(f"✅ Loaded {len(df)} samples from {file_path}")
        logger.info(f"   Columns: {len(df.columns)} total")

        return df

    except FileNotFoundError:
        logger.error(f"❌ PENALTY: File not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"❌ PENALTY: Error loading {file_path}: {e}")
        raise


def validate_data(
    df: pd.DataFrame, split_name: str, config: TokenizationConfig
) -> None:
    """
    Validate loaded DataFrame for required fields and label balance.

    Args:
        df: DataFrame with code, is_vulnerable, and feature columns
        split_name: Name of the split (train/val/test)
        config: Configuration object
    """
    if len(df) < config.min_samples:
        logger.error(
            f"❌ PENALTY: {split_name} has only {len(df)} samples (min: {config.min_samples})"
        )
        raise ValueError(f"Insufficient samples in {split_name}")

    # Check required fields
    required_fields = ["code", "is_vulnerable"]
    missing_fields = [f for f in required_fields if f not in df.columns]

    if missing_fields:
        logger.error(
            f"❌ PENALTY: Missing fields in {split_name}: {missing_fields}"
        )
        raise ValueError(f"Missing required fields in {split_name}")

    # Normalize labels to 0/1
    df["is_vulnerable"] = df["is_vulnerable"].astype(int)

    # Check label balance
    label_counts = df["is_vulnerable"].value_counts().to_dict()
    total = len(df)

    if total == 0:
        logger.error(f"❌ PENALTY: No valid labels in {split_name}")
        raise ValueError("No valid labels found")

    vulnerable_ratio = label_counts.get(1, 0) / total
    non_vulnerable_ratio = label_counts.get(0, 0) / total

    logger.info(f"📊 {split_name} label distribution:")
    logger.info(f"   Vulnerable (1): {label_counts.get(1, 0)} ({vulnerable_ratio:.2%})")
    logger.info(
        f"   Non-vulnerable (0): {label_counts.get(0, 0)} ({non_vulnerable_ratio:.2%})"
    )

    if max(vulnerable_ratio, non_vulnerable_ratio) > config.max_label_imbalance:
        logger.warning(f"⚠️ WARNING: Extreme label imbalance in {split_name}")
    else:
        logger.info(f"✅ Label balance acceptable in {split_name}")


def extract_numeric_features(
    df: pd.DataFrame, config: TokenizationConfig
) -> Tuple[np.ndarray, List[str]]:
    """
    Extract numeric feature columns from DataFrame.

    Args:
        df: Input DataFrame
        config: Configuration object

    Returns:
        features: NumPy array of shape [num_samples, num_features]
        feature_names: List of feature column names
    """
    # Identify feature columns (exclude code, labels, and metadata)
    all_cols = set(df.columns)
    exclude_cols = set(config.feature_columns_exclude)
    feature_cols = sorted(list(all_cols - exclude_cols))

    # Select only numeric columns
    numeric_feature_cols = []
    for col in feature_cols:
        if df[col].dtype in [np.float32, np.float64, np.int32, np.int64, np.int8, np.int16]:
            numeric_feature_cols.append(col)

    if len(numeric_feature_cols) == 0:
        logger.warning("⚠️ No numeric features found. Using code-only mode.")
        return np.zeros((len(df), 0), dtype=np.float32), []

    logger.info(f"📊 Extracted {len(numeric_feature_cols)} numeric feature columns")

    # Extract features as NumPy array
    features = df[numeric_feature_cols].values.astype(np.float32)

    return features, numeric_feature_cols


def normalize_features(
    features: np.ndarray, scaler: Optional[StandardScaler] = None, fit: bool = False
) -> Tuple[np.ndarray, StandardScaler]:
    """
    Normalize features using StandardScaler.

    Args:
        features: NumPy array of shape [num_samples, num_features]
        scaler: Pre-fitted scaler (for val/test)
        fit: Whether to fit the scaler (True for train, False for val/test)

    Returns:
        normalized_features: Normalized features
        scaler: Fitted scaler
    """
    if features.shape[1] == 0:
        return features, None

    if fit:
        scaler = StandardScaler()
        normalized = scaler.fit_transform(features)
        logger.info(f"✅ Fitted StandardScaler on {features.shape[0]} samples")
    else:
        if scaler is None:
            logger.warning("⚠️ No scaler provided for normalization. Skipping.")
            return features, None
        normalized = scaler.transform(features)
        logger.info(f"✅ Transformed features using existing scaler")

    return normalized.astype(np.float32), scaler


# ============================================================================
# TOKENIZATION
# ============================================================================


class VulnerabilityDataset(Dataset):
    """
    Custom dataset for vulnerability detection with error handling.

    Rewards: ✅ Proper tensor shapes and types
    Penalties: ❌ Shape mismatches, ❌ Type errors
    """

    def __init__(
        self,
        data: List[Dict],
        tokenizer,
        config: TokenizationConfig,
        error_tracker: ErrorTracker,
        split_name: str,
    ):
        self.data = data
        self.tokenizer = tokenizer
        self.config = config
        self.error_tracker = error_tracker
        self.split_name = split_name
        self.failed_indices = set()

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        sample = self.data[idx]
        row_id = sample.get("id", f"row_{idx}")

        try:
            # Extract code and label
            code = str(sample.get("code", ""))

            if not code or code.strip() == "":
                raise ValueError("Empty code field")

            label = int(sample.get("is_vulnerable", False))

            # Strict binary label check
            if self.config.strict_binary_labels and label not in [0, 1]:
                raise ValueError(f"Invalid label value: {label}")

            # Tokenize with dynamic or fixed padding
            padding_strategy = (
                "do_not_pad" if self.config.dynamic_padding else self.config.padding
            )

            encoding = self.tokenizer(
                code,
                max_length=self.config.max_seq_length,
                padding=padding_strategy,
                truncation=self.config.truncation,
                return_attention_mask=self.config.return_attention_mask,
                return_tensors="pt",
            )

            return {
                "input_ids": encoding["input_ids"].squeeze(0),
                "attention_mask": encoding["attention_mask"].squeeze(0),
                "labels": torch.tensor(label, dtype=torch.long),
                "row_id": row_id,
                "success": True,
            }

        except Exception as e:
            # Log error
            self.error_tracker.log_error(
                row_id, self.split_name, type(e).__name__, str(e), sample
            )
            self.failed_indices.add(idx)

            if not self.config.skip_on_error:
                raise

            # Return dummy data to continue processing
            return {
                "input_ids": torch.zeros(self.config.max_seq_length, dtype=torch.long),
                "attention_mask": torch.zeros(
                    self.config.max_seq_length, dtype=torch.long
                ),
                "labels": torch.tensor(0, dtype=torch.long),
                "row_id": row_id,
                "success": False,
            }


def collate_fn_dynamic(
    batch: List[Dict], config: TokenizationConfig
) -> Dict[str, torch.Tensor]:
    """
    Custom collate function for dynamic padding per batch.
    Only pads to the longest sequence in the batch, not max_seq_length.

    Rewards: ✅ Memory efficiency
    """
    # Filter out failed samples
    valid_batch = [item for item in batch if item["success"]]

    if not valid_batch:
        # All samples failed, return dummy batch
        return {
            "input_ids": torch.zeros((1, config.max_seq_length), dtype=torch.long),
            "attention_mask": torch.zeros((1, config.max_seq_length), dtype=torch.long),
            "labels": torch.tensor([0], dtype=torch.long),
        }

    # Find max length in this batch (dynamic)
    if config.dynamic_padding:
        max_len = max(item["input_ids"].size(0) for item in valid_batch)
        max_len = min(max_len, config.max_seq_length)  # Cap at max_seq_length
    else:
        max_len = config.max_seq_length

    # Pad to max_len
    input_ids_list = []
    attention_mask_list = []
    labels_list = []

    for item in valid_batch:
        input_ids = item["input_ids"]
        attention_mask = item["attention_mask"]

        # Pad if needed
        current_len = input_ids.size(0)
        if current_len < max_len:
            padding_len = max_len - current_len
            input_ids = torch.cat(
                [input_ids, torch.zeros(padding_len, dtype=torch.long)]
            )
            attention_mask = torch.cat(
                [attention_mask, torch.zeros(padding_len, dtype=torch.long)]
            )
        elif current_len > max_len:
            input_ids = input_ids[:max_len]
            attention_mask = attention_mask[:max_len]

        input_ids_list.append(input_ids)
        attention_mask_list.append(attention_mask)
        labels_list.append(item["labels"])

    return {
        "input_ids": torch.stack(input_ids_list),
        "attention_mask": torch.stack(attention_mask_list),
        "labels": torch.stack(labels_list),
    }


def tokenize_dataset_batch(
    df: pd.DataFrame,
    features: np.ndarray,
    tokenizer,
    config: TokenizationConfig,
    split_name: str,
) -> Dict[str, torch.Tensor]:
    """
    Tokenize dataset with FAST batch processing and include numeric features.

    Args:
        df: DataFrame with code and is_vulnerable columns
        features: NumPy array of numeric features [num_samples, num_features]
        tokenizer: HuggingFace tokenizer
        config: Configuration object
        split_name: Name of the split

    Returns:
        Dict with input_ids, attention_mask, labels, features tensors
    """
    logger.info(f"🔄 Fast batch tokenizing {split_name} split ({len(df)} samples)...")

    # Shuffle training data for better generalization
    if split_name == "train" and config.shuffle_train:
        logger.info(f"🔀 Shuffling training data (seed={config.random_seed})...")
        indices = np.arange(len(df))
        np.random.shuffle(indices)
        df = df.iloc[indices].reset_index(drop=True)
        features = features[indices]

    # Extract code and labels
    all_code = df["code"].astype(str).tolist()
    all_labels = df["is_vulnerable"].astype(int).tolist()

    # CHUNKED BATCH TOKENIZATION - process in chunks to avoid OOM
    chunk_size = 5000  # Reduced to 5k samples at a time for GraphCodeBERT
    num_chunks = (len(all_code) + chunk_size - 1) // chunk_size

    logger.info(f"⚡ Batch tokenizing in {num_chunks} chunks of {chunk_size} samples...")

    all_input_ids = []
    all_attention_masks = []

    try:
        padding_strategy = "max_length"  # Always use max_length for consistent shapes

        for i in tqdm(range(0, len(all_code), chunk_size), desc=f"Tokenizing {split_name}"):
            chunk_code = all_code[i:i + chunk_size]

            # Tokenize chunk
            encoded = tokenizer(
                chunk_code,
                max_length=config.max_seq_length,
                padding=padding_strategy,
                truncation=config.truncation,
                return_tensors="pt",
                return_attention_mask=config.return_attention_mask,
            )

            all_input_ids.append(encoded["input_ids"])
            all_attention_masks.append(encoded["attention_mask"])
            
            # Clear memory after each chunk
            del encoded
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

        # Concatenate all chunks
        logger.info(f"🔗 Concatenating {len(all_input_ids)} chunks...")
        
        # Free up memory before concatenation
        import gc
        gc.collect()
        
        tokenized_data = {
            "input_ids": torch.cat(all_input_ids, dim=0),
            "attention_mask": torch.cat(all_attention_masks, dim=0),
            "labels": torch.tensor(all_labels, dtype=torch.long),
            "features": torch.from_numpy(features).float(),
        }

        # Log statistics
        logger.info(f"✅ {split_name} tokenization complete:")
        logger.info(f"   Input IDs shape: {tokenized_data['input_ids'].shape}")
        logger.info(f"   Attention mask shape: {tokenized_data['attention_mask'].shape}")
        logger.info(f"   Labels shape: {tokenized_data['labels'].shape}")
        logger.info(f"   Features shape: {tokenized_data['features'].shape}")

        # Memory usage info
        input_ids_size_mb = tokenized_data["input_ids"].element_size() * tokenized_data["input_ids"].nelement() / (1024 * 1024)
        features_size_mb = tokenized_data["features"].element_size() * tokenized_data["features"].nelement() / (1024 * 1024)
        logger.info(f"   Memory usage: ~{input_ids_size_mb * 2 + features_size_mb:.1f} MB")

        return tokenized_data

    except Exception as e:
        logger.error(f"❌ PENALTY: Tokenization failed for {split_name}: {e}")
        raise


# ============================================================================
# VALIDATION
# ============================================================================


def validate_tokenized_data(
    tokenized_data: Dict[str, torch.Tensor],
    split_name: str,
    expected_samples: int,
    config: TokenizationConfig,
) -> None:
    """
    Validate tokenized data shapes and content (including features).

    Args:
        tokenized_data: Dict with input_ids, attention_mask, labels, features
        split_name: Name of the split
        expected_samples: Expected number of samples
        config: Configuration object
    """
    logger.info(f"🔍 Validating {split_name} tokenized data...")

    # Check keys
    required_keys = ["input_ids", "attention_mask", "labels", "features"]
    missing_keys = [key for key in required_keys if key not in tokenized_data]
    if missing_keys:
        logger.error(f"❌ PENALTY: Missing keys in {split_name}: {missing_keys}")
        raise ValueError(f"Missing keys: {missing_keys}")

    # Check shapes
    input_ids = tokenized_data["input_ids"]
    attention_mask = tokenized_data["attention_mask"]
    labels = tokenized_data["labels"]
    features = tokenized_data["features"]

    if input_ids.shape[0] != expected_samples:
        logger.error(
            f"❌ PENALTY: Sample count mismatch in {split_name}: "
            f"expected {expected_samples}, got {input_ids.shape[0]}"
        )
        raise ValueError(f"Sample count mismatch")

    if input_ids.shape[1] != config.max_seq_length:
        logger.error(
            f"❌ PENALTY: Sequence length mismatch in {split_name}: "
            f"expected {config.max_seq_length}, got {input_ids.shape[1]}"
        )
        raise ValueError(f"Sequence length mismatch")

    if input_ids.shape != attention_mask.shape:
        logger.error(f"❌ PENALTY: Shape mismatch between input_ids and attention_mask")
        raise ValueError(f"Shape mismatch")

    if labels.shape[0] != expected_samples:
        logger.error(f"❌ PENALTY: Label count mismatch in {split_name}")
        raise ValueError(f"Label count mismatch")

    if features.shape[0] != expected_samples:
        logger.error(f"❌ PENALTY: Feature count mismatch in {split_name}")
        raise ValueError(f"Feature count mismatch")

    # Check label values
    unique_labels = labels.unique().tolist()
    if not all(label in [0, 1] for label in unique_labels):
        logger.error(
            f"❌ PENALTY: Invalid label values in {split_name}: {unique_labels}"
        )
        raise ValueError(f"Invalid label values")

    # Check data types
    if input_ids.dtype != torch.long or attention_mask.dtype != torch.long:
        logger.error(f"❌ PENALTY: Invalid dtype for input_ids or attention_mask")
        raise ValueError(f"Invalid dtype")

    if labels.dtype != torch.long:
        logger.error(f"❌ PENALTY: Invalid dtype for labels")
        raise ValueError(f"Invalid dtype")

    if features.dtype != torch.float32:
        logger.error(f"❌ PENALTY: Invalid dtype for features (expected float32, got {features.dtype})")
        raise ValueError(f"Invalid dtype")

    logger.info(f"✅ {split_name} validation passed!")
    logger.info(f"   Input shape: {input_ids.shape}")
    logger.info(f"   Feature shape: {features.shape}")
    logger.info(f"   Label distribution: {Counter(labels.tolist())}")


# ============================================================================
# SAVE/LOAD
# ============================================================================


def save_tokenized_dataset(
    tokenized_data: Dict[str, torch.Tensor], output_path: str, split_name: str
) -> None:
    """
    Save tokenized dataset with error handling.

    Rewards: ✅ Successful save
    Penalties: ❌ I/O errors
    """
    try:
        # Create output directory
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Save
        torch.save(tokenized_data, output_path)

        # Verify save
        file_size = os.path.getsize(output_path) / (1024 * 1024)  # MB
        logger.info(f"✅ Saved {split_name} to {output_path} ({file_size:.2f} MB)")

    except Exception as e:
        logger.error(f"❌ PENALTY: Failed to save {split_name}: {e}")
        raise


def sanity_check(output_path: str, split_name: str) -> None:
    """
    Perform sanity check by loading saved data.

    Args:
        output_path: Path to saved .pt file
        split_name: Name of the split
    """
    try:
        logger.info(f"🔍 Sanity check: Loading {split_name}...")
        data = torch.load(output_path)

        logger.info(f"✅ {split_name} sanity check passed!")
        logger.info(f"   Keys: {list(data.keys())}")
        logger.info(f"   Input IDs shape: {data['input_ids'].shape}")
        logger.info(f"   Features shape: {data['features'].shape}")
        logger.info(
            f"   First batch: input_ids={data['input_ids'][:4].shape}, "
            f"labels={data['labels'][:4].tolist()}, features={data['features'][:4].shape}"
        )

    except Exception as e:
        logger.error(f"❌ PENALTY: Sanity check failed for {split_name}: {e}")
        raise


# ============================================================================
# ROBUST SPLIT PROCESSING HELPERS
# ============================================================================


def process_and_persist_split(
    split_name: str,
    df: pd.DataFrame,
    features: np.ndarray,
    tokenizer,
    config: TokenizationConfig,
    scaler: Optional[StandardScaler] = None,
) -> Tuple[Dict[str, torch.Tensor], StandardScaler]:
    """
    End-to-end handling for a single split with multimodal features:
      - tokenizes code (chunked)
      - includes numeric features
      - validates shapes & labels
      - saves to final output
      - performs sanity check

    Args:
        split_name: Name of the split
        df: DataFrame with code and labels
        features: NumPy array of numeric features
        tokenizer: HuggingFace tokenizer
        config: Configuration object
        scaler: Pre-fitted scaler (for val/test)

    Returns:
        tokenized_data: Dict with all tensors
        scaler: Fitted scaler (for train) or input scaler (for val/test)
    """
    logger.info(f"\n[PROCESS] Starting processing for split: {split_name}")

    # Normalize features
    if config.normalize_features and features.shape[1] > 0:
        if split_name == "train":
            features, scaler = normalize_features(features, scaler=None, fit=True)
        else:
            features, _ = normalize_features(features, scaler=scaler, fit=False)

    # Tokenize
    tokenized = tokenize_dataset_batch(
        df, features, tokenizer, config, split_name
    )

    # Validate tokenized data
    validate_tokenized_data(
        tokenized, split_name, tokenized["input_ids"].shape[0], config
    )

    # Persist final dataset to configured output path
    output_map = {
        "train": config.train_output,
        "val": config.val_output,
        "test": config.test_output,
    }
    out_path = output_map.get(split_name)
    if out_path is None:
        # Fallback: create file under output_base
        out_path = os.path.join(config.output_base, f"{split_name}_tokenized.pt")

    save_tokenized_dataset(tokenized, out_path, split_name)

    # Sanity check saved file
    sanity_check(out_path, split_name)

    return tokenized, scaler


def assert_outputs_exist(config: TokenizationConfig):
    """
    Assert that all final tokenized output files exist.

    Rewards: ✅ All outputs present
    Penalties: ❌ Missing outputs
    """
    expected = [config.train_output, config.val_output, config.test_output]
    missing = [p for p in expected if not os.path.exists(p)]
    if missing:
        logger.error(f"❌ PENALTY: Missing final outputs: {missing}")
        raise FileNotFoundError(f"Missing outputs: {missing}")
    logger.info("✅ All final tokenized output files are present.")


# ============================================================================
# MAIN PIPELINE
# ============================================================================


def main():
    """
    Main tokenization pipeline with multimodal features (code + numeric features).
    """
    config = TokenizationConfig()

    logger.info("=" * 80)
    logger.info("🚀 GraphCodeBERT Multimodal Tokenization Pipeline")
    logger.info("=" * 80)
    logger.info(f"📋 Configuration:")
    logger.info(f"   Model: {config.model_name}")
    logger.info(f"   Max sequence length: {config.max_seq_length}")
    logger.info(f"   Normalize features: {config.normalize_features}")
    logger.info(f"   Random seed: {config.random_seed}")
    logger.info(f"   Shuffle training: {config.shuffle_train}")

    try:
        # ====================================================================
        # STEP 1: Set Random Seed
        # ====================================================================
        logger.info("\n[STEP 1/6] Setting random seed for reproducibility...")
        set_seed(config.random_seed)
        logger.info(f"✅ Seed set for reproducibility")

        # ====================================================================
        # STEP 2: Initialize Output Directory
        # ====================================================================
        logger.info("\n[STEP 2/6] Creating output directory...")
        os.makedirs(config.output_base, exist_ok=True)
        logger.info(f"✅ Output directory ready: {config.output_base}")

        # ====================================================================
        # STEP 3: Load Tokenizer
        # ====================================================================
        logger.info("\n[STEP 3/6] Loading tokenizer...")
        # Disable chat template fetching to avoid 404 errors
        os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"

        try:
            tokenizer = AutoTokenizer.from_pretrained(
                config.model_name,
                trust_remote_code=False,
                use_fast=True,
                chat_template=None
            )
        except Exception as e:
            logger.warning(f"⚠️ Fast tokenizer failed, trying basic tokenizer: {e}")
            try:
                tokenizer = AutoTokenizer.from_pretrained(
                    config.model_name,
                    trust_remote_code=False,
                    use_fast=False,
                    chat_template=None
                )
            except Exception as e2:
                logger.warning(f"⚠️ Basic tokenizer also failed, trying with local files only: {e2}")
                # Last resort - try to load from local cache only
                tokenizer = AutoTokenizer.from_pretrained(
                    config.model_name,
                    trust_remote_code=False,
                    use_fast=False,
                    chat_template=None,
                    local_files_only=True
                )
        logger.info(f"✅ Tokenizer loaded successfully")

        # ====================================================================
        # STEP 4: Load and Validate Data
        # ====================================================================
        logger.info("\n[STEP 4/6] Loading datasets...")
        train_df = load_jsonl(config.train_path)
        val_df = load_jsonl(config.val_path)
        test_df = load_jsonl(config.test_path)
        logger.info(f"✅ All datasets loaded successfully")

        logger.info("\n[STEP 4/6] Validating datasets...")
        validate_data(train_df, "train", config)
        validate_data(val_df, "val", config)
        validate_data(test_df, "test", config)
        logger.info(f"✅ All datasets validated successfully")

        # ====================================================================
        # STEP 5: Extract Features
        # ====================================================================
        logger.info("\n[STEP 5/6] Extracting numeric features...")
        train_features, feature_names = extract_numeric_features(train_df, config)
        val_features, _ = extract_numeric_features(val_df, config)
        test_features, _ = extract_numeric_features(test_df, config)

        logger.info(f"✅ Extracted features:")
        logger.info(f"   Feature count: {len(feature_names)}")
        logger.info(f"   Train features shape: {train_features.shape}")
        logger.info(f"   Val features shape: {val_features.shape}")
        logger.info(f"   Test features shape: {test_features.shape}")
        if len(feature_names) > 0:
            logger.info(f"   Sample features: {feature_names[:5]}")

        # ====================================================================
        # STEP 6: Tokenize and Persist All Splits
        # ====================================================================
        logger.info("\n[STEP 6/6] Tokenizing and persisting all splits...")

        # Process train (fit scaler)
        logger.info("\n--- Processing TRAIN split ---")
        train_tokenized, scaler = process_and_persist_split(
            "train", train_df, train_features, tokenizer, config, scaler=None
        )
        logger.info(f"✅ Train tokenization & persist complete")
        
        # Clear memory after train
        import gc
        gc.collect()

        # Process val (use fitted scaler)
        logger.info("\n--- Processing VAL split ---")
        val_tokenized, _ = process_and_persist_split(
            "val", val_df, val_features, tokenizer, config, scaler=scaler
        )
        logger.info(f"✅ Validation tokenization & persist complete")
        
        # Clear memory after val
        gc.collect()

        # Process test (use fitted scaler)
        logger.info("\n--- Processing TEST split ---")
        test_tokenized, _ = process_and_persist_split(
            "test", test_df, test_features, tokenizer, config, scaler=scaler
        )
        logger.info(f"✅ Test tokenization & persist complete")

        # ====================================================================
        # STEP 7: Final Verification
        # ====================================================================
        logger.info("\n[STEP 7/7] Verifying all output files exist...")
        assert_outputs_exist(config)
        logger.info(f"✅ All output files verified")

        # ====================================================================
        # FINAL SUMMARY
        # ====================================================================
        logger.info("\n" + "=" * 80)
        logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY!")
        logger.info("=" * 80)
        logger.info(f"\n📁 Output Directory: {config.output_base}")
        logger.info(f"   ├── train_tokenized_graphcodebert.pt ({len(train_df)} samples)")
        logger.info(f"   ├── val_tokenized_graphcodebert.pt ({len(val_df)} samples)")
        logger.info(f"   └── test_tokenized_graphcodebert.pt ({len(test_df)} samples)")
        logger.info(f"\n📊 Output Structure (per .pt file):")
        logger.info(f"   ├── input_ids: {train_tokenized['input_ids'].shape}")
        logger.info(f"   ├── attention_mask: {train_tokenized['attention_mask'].shape}")
        logger.info(f"   ├── labels: {train_tokenized['labels'].shape}")
        logger.info(f"   └── features: {train_tokenized['features'].shape}")
        logger.info(f"\n✅ Ready for multimodal fine-tuning with use_features=True!")

    except Exception as e:
        logger.error("\n" + "=" * 80)
        logger.error("❌ PIPELINE FAILED!")
        logger.error("=" * 80)
        logger.error(f"Error: {type(e).__name__}: {e}")
        logger.error("\n💡 Troubleshooting:")
        logger.error("   1. Check input paths exist")
        logger.error("   2. Verify JSONL format is valid")
        logger.error("   3. Ensure sufficient memory")
        logger.error("   4. Check log file for details")
        raise


if __name__ == "__main__":
    # Set multiprocessing start method for compatibility
    try:
        if mp.get_start_method(allow_none=True) != "spawn":
            mp.set_start_method("spawn", force=True)
    except RuntimeError:
        # Already set, ignore
        pass

    main()
