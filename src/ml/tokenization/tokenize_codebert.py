#! /usr/bin/env python
#type: ignore

"""
CodeBERT Tokenization Pipeline for Vulnerability Detection
===========================================================
Production-ready tokenization script with multiprocessing and validation.

Rewards:
✅ Successful tokenization with proper shapes
✅ Correct label conversion and balance check
✅ Efficient batch processing with multiprocessing
✅ Validation checks for data integrity

Penalties:
❌ Tokenization errors or shape mismatches
❌ Missing fields or incorrect labels
❌ File I/O failures
❌ Memory inefficiency
"""

import os
import json
import torch
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

# ============================================================================
# CONFIGURATION
# ============================================================================


@dataclass
class TokenizationConfig:
    """Configuration for tokenization pipeline"""

    # Model configuration
    model_name: str = "microsoft/codebert-base"
    max_seq_length: int = 512
    dynamic_padding: bool = True  # Enable dynamic padding per batch

    # Input paths (Kaggle)
    input_base: str = (
        "/kaggle/input/codeguardian-pre-processed-datasets/random_splitted"
    )
    train_path: str = f"{input_base}/train.jsonl"
    val_path: str = f"{input_base}/val.jsonl"
    test_path: str = f"{input_base}/test.jsonl"

    # Output paths
    output_base: str = "/kaggle/working/datasets/tokenized/codebert"
    cache_dir: str = f"{output_base}/.cache"  # Cache directory
    train_output: str = f"{output_base}/train_tokenized_codebert.pt"
    val_output: str = f"{output_base}/val_tokenized_codebert.pt"
    test_output: str = f"{output_base}/test_tokenized_codebert.pt"
    error_log: str = f"{output_base}/tokenization_errors.jsonl"

    # Processing configuration
    batch_size: int = 32
    num_workers: int = 8  # Leverage CPU cores
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
    """Track and log tokenization errors per row"""

    def __init__(self, config: TokenizationConfig):
        self.config = config
        self.errors = []
        self.error_file = open(config.error_log, "w", encoding="utf-8")

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
        self.error_file.write(json.dumps(error_entry) + "\n")
        self.error_file.flush()

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
        """Close error log file"""
        self.error_file.close()

    def __del__(self):
        """Cleanup"""
        if hasattr(self, "error_file") and not self.error_file.closed:
            self.error_file.close()


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


def load_jsonl(file_path: str) -> List[Dict]:
    """
    Load JSONL file with error handling.

    Rewards: ✅ Successful loading
    Penalties: ❌ File not found, ❌ JSON parse errors
    """
    try:
        data = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    data.append(json.loads(line.strip()))
                except json.JSONDecodeError as e:
                    logger.warning(f"⚠️ Skipping line {line_num} in {file_path}: {e}")

        logger.info(f"✅ Loaded {len(data)} samples from {file_path}")
        return data

    except FileNotFoundError:
        logger.error(f"❌ PENALTY: File not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"❌ PENALTY: Error loading {file_path}: {e}")
        raise


def validate_data(
    data: List[Dict], split_name: str, config: TokenizationConfig
) -> None:
    """
    Validate loaded data for required fields and label balance.

    Rewards: ✅ Valid data structure and balance
    Penalties: ❌ Missing fields, ❌ Extreme imbalance, ❌ Too few samples
    """
    if len(data) < config.min_samples:
        logger.error(
            f"❌ PENALTY: {split_name} has only {len(data)} samples (min: {config.min_samples})"
        )
        raise ValueError(f"Insufficient samples in {split_name}")

    # Check required fields
    required_fields = ["code", "is_vulnerable"]
    missing_fields = []

    for idx, sample in enumerate(data[:10]):  # Check first 10 samples
        for field in required_fields:
            if field not in sample:
                missing_fields.append((idx, field))

    if missing_fields:
        logger.error(
            f"❌ PENALTY: Missing fields in {split_name}: {missing_fields[:5]}"
        )
        raise ValueError(f"Missing required fields in {split_name}")

    # Check and normalize label values
    labels = []
    label_issues = []

    for idx, sample in enumerate(data):
        label = sample.get("is_vulnerable")

        # Normalize label to 0/1
        if isinstance(label, bool):
            normalized_label = int(label)
        elif isinstance(label, (int, float)):
            normalized_label = int(label)
        else:
            label_issues.append((idx, label))
            continue

        # Strict binary check
        if config.strict_binary_labels and normalized_label not in [0, 1]:
            label_issues.append((idx, label))
            continue

        labels.append(normalized_label)
        # Update sample with normalized label
        sample["is_vulnerable"] = normalized_label

    if label_issues:
        logger.warning(
            f"⚠️ Found {len(label_issues)} label issues in {split_name} (first 5): {label_issues[:5]}"
        )
        if (
            config.strict_binary_labels and len(label_issues) > len(data) * 0.01
        ):  # More than 1%
            logger.error(f"❌ PENALTY: Too many invalid labels in {split_name}")
            raise ValueError(f"Invalid label values exceed threshold")

    # Check label balance
    label_counts = Counter(labels)
    total = len(labels)

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

    if config.support_multiclass:
        unique_labels = list(label_counts.keys())
        logger.info(f"   Unique labels (multiclass): {unique_labels}")

    if max(vulnerable_ratio, non_vulnerable_ratio) > config.max_label_imbalance:
        logger.warning(f"⚠️ WARNING: Extreme label imbalance in {split_name}")
    else:
        logger.info(f"✅ Label balance acceptable in {split_name}")


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
    data: List[Dict],
    tokenizer,
    config: TokenizationConfig,
    split_name: str,
    error_tracker: ErrorTracker,
) -> Dict[str, torch.Tensor]:
    """
    Tokenize dataset in batches with progress bar and error handling.

    Rewards: ✅ Efficient batch processing, ✅ Correct shapes, ✅ Error resilience
    Penalties: ❌ Memory errors, ❌ Shape mismatches
    """
    logger.info(f"🔄 Tokenizing {split_name} split with batch processing...")

    # Shuffle training data for better generalization
    if split_name == "train" and config.shuffle_train:
        logger.info(f"🔀 Shuffling training data (seed={config.random_seed})...")
        random.shuffle(data)

    dataset = VulnerabilityDataset(data, tokenizer, config, error_tracker, split_name)

    # Use custom collate function if dynamic padding
    collate_function = (
        partial(collate_fn_dynamic, config=config) if config.dynamic_padding else None
    )

    dataloader = DataLoader(
        dataset,
        batch_size=config.batch_size,
        num_workers=config.num_workers,
        shuffle=False,  # Already shuffled if needed
        pin_memory=True,
        collate_fn=collate_function,
    )

    all_input_ids = []
    all_attention_masks = []
    all_labels = []

    try:
        for batch in tqdm(dataloader, desc=f"Tokenizing {split_name}"):
            all_input_ids.append(batch["input_ids"])
            all_attention_masks.append(batch["attention_mask"])
            all_labels.append(batch["labels"])

            # Check if error threshold exceeded
            if error_tracker.should_stop(split_name):
                logger.error(
                    f"❌ PENALTY: Stopping {split_name} due to too many errors"
                )
                raise RuntimeError(f"Error threshold exceeded for {split_name}")

        # Concatenate all batches
        tokenized_data = {
            "input_ids": torch.cat(all_input_ids, dim=0),
            "attention_mask": torch.cat(all_attention_masks, dim=0),
            "labels": torch.cat(all_labels, dim=0),
        }

        # Log statistics
        error_count = error_tracker.get_error_count(split_name)
        success_count = tokenized_data["input_ids"].shape[0]

        logger.info(f"✅ {split_name} tokenization complete:")
        logger.info(f"   Successful samples: {success_count}")
        logger.info(f"   Failed samples: {error_count}")
        logger.info(
            f"   Success rate: {success_count / (success_count + error_count) * 100:.2f}%"
        )
        logger.info(f"   Input IDs shape: {tokenized_data['input_ids'].shape}")
        logger.info(
            f"   Attention mask shape: {tokenized_data['attention_mask'].shape}"
        )
        logger.info(f"   Labels shape: {tokenized_data['labels'].shape}")

        # Dynamic padding stats
        if config.dynamic_padding:
            actual_lengths = (tokenized_data["attention_mask"].sum(dim=1)).tolist()
            avg_length = sum(actual_lengths) / len(actual_lengths)
            logger.info(
                f"   Avg sequence length: {avg_length:.1f} (dynamic padding saved {(1 - avg_length / config.max_seq_length) * 100:.1f}% space)"
            )

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
    Validate tokenized data shapes and content.

    Rewards: ✅ Correct shapes and types
    Penalties: ❌ Shape mismatches, ❌ Invalid labels
    """
    logger.info(f"🔍 Validating {split_name} tokenized data...")

    # Check keys
    required_keys = ["input_ids", "attention_mask", "labels"]
    missing_keys = [key for key in required_keys if key not in tokenized_data]
    if missing_keys:
        logger.error(f"❌ PENALTY: Missing keys in {split_name}: {missing_keys}")
        raise ValueError(f"Missing keys: {missing_keys}")

    # Check shapes
    input_ids = tokenized_data["input_ids"]
    attention_mask = tokenized_data["attention_mask"]
    labels = tokenized_data["labels"]

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

    logger.info(f"✅ {split_name} validation passed!")
    logger.info(f"   Shape: {input_ids.shape}")
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

    Rewards: ✅ Successful load and shape verification
    Penalties: ❌ Load errors
    """
    try:
        logger.info(f"🔍 Sanity check: Loading {split_name}...")
        data = torch.load(output_path)

        logger.info(f"✅ {split_name} sanity check passed!")
        logger.info(f"   Keys: {list(data.keys())}")
        logger.info(f"   Input IDs shape: {data['input_ids'].shape}")
        logger.info(
            f"   First batch (shape): input_ids={data['input_ids'][:4].shape}, "
            f"labels={data['labels'][:4].tolist()}"
        )

    except Exception as e:
        logger.error(f"❌ PENALTY: Sanity check failed for {split_name}: {e}")
        raise


# ============================================================================
# MAIN PIPELINE
# ============================================================================


def main():
    """
    Main tokenization pipeline with reinforcement logic and enhanced features.

    Rewards accumulate for each successful step.
    Penalties trigger on any failure.
    """
    config = TokenizationConfig()
    reward_score = 0
    error_tracker = None

    logger.info("=" * 80)
    logger.info("🚀 CodeBERT Tokenization Pipeline - Enhanced Production Mode")
    logger.info("=" * 80)
    logger.info(f"📋 Configuration:")
    logger.info(f"   Model: {config.model_name}")
    logger.info(f"   Max sequence length: {config.max_seq_length}")
    logger.info(f"   Dynamic padding: {config.dynamic_padding}")
    logger.info(f"   Batch size: {config.batch_size}")
    logger.info(f"   Num workers: {config.num_workers}")
    logger.info(f"   Random seed: {config.random_seed}")
    logger.info(f"   Shuffle training: {config.shuffle_train}")
    logger.info(f"   Use cache: {config.use_cache}")
    logger.info(f"   Skip on error: {config.skip_on_error}")
    logger.info(f"   Strict binary labels: {config.strict_binary_labels}")

    try:
        # ====================================================================
        # STEP 0: Set Random Seed
        # ====================================================================
        logger.info("\n[STEP 0/7] Setting random seed for reproducibility...")
        set_seed(config.random_seed)
        logger.info(f"✅ REWARD +5: Seed set for reproducibility")
        reward_score += 5

        # ====================================================================
        # STEP 1: Initialize Error Tracker
        # ====================================================================
        logger.info("\n[STEP 1/7] Initializing error tracker...")
        os.makedirs(config.output_base, exist_ok=True)
        error_tracker = ErrorTracker(config)
        logger.info(f"✅ REWARD +5: Error tracker initialized")
        reward_score += 5

        # ====================================================================
        # STEP 2: Load Tokenizer
        # ====================================================================
        logger.info("\n[STEP 2/7] Loading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(config.model_name)
        logger.info(f"✅ REWARD +10: Tokenizer loaded successfully")
        reward_score += 10

        # ====================================================================
        # STEP 3: Load Data
        # ====================================================================
        logger.info("\n[STEP 3/7] Loading datasets...")
        train_data = load_jsonl(config.train_path)
        val_data = load_jsonl(config.val_path)
        test_data = load_jsonl(config.test_path)
        logger.info(f"✅ REWARD +10: All datasets loaded successfully")
        reward_score += 10

        # ====================================================================
        # STEP 4: Validate Data
        # ====================================================================
        logger.info("\n[STEP 4/7] Validating datasets...")
        validate_data(train_data, "train", config)
        validate_data(val_data, "val", config)
        validate_data(test_data, "test", config)
        logger.info(f"✅ REWARD +10: All datasets validated successfully")
        reward_score += 10

        # ====================================================================
        # STEP 5: Tokenize (with caching)
        # ====================================================================
        logger.info("\n[STEP 5/7] Tokenizing datasets...")

        # Try cache for train
        train_tokenized = load_from_cache("train", config)
        if train_tokenized is None:
            train_tokenized = tokenize_dataset_batch(
                train_data, tokenizer, config, "train", error_tracker
            )
            save_to_cache(train_tokenized, "train", config)
        logger.info(f"✅ REWARD +20: Train tokenization complete")
        reward_score += 20

        # Try cache for val
        val_tokenized = load_from_cache("val", config)
        if val_tokenized is None:
            val_tokenized = tokenize_dataset_batch(
                val_data, tokenizer, config, "val", error_tracker
            )
            save_to_cache(val_tokenized, "val", config)
        logger.info(f"✅ REWARD +20: Validation tokenization complete")
        reward_score += 20

        # Try cache for test
        test_tokenized = load_from_cache("test", config)
        if test_tokenized is None:
            test_tokenized = tokenize_dataset_batch(
                test_data, tokenizer, config, "test", error_tracker
            )
            save_to_cache(test_tokenized, "test", config)
        logger.info(f"✅ REWARD +20: Test tokenization complete")
        reward_score += 20

        # ====================================================================
        # STEP 6: Validate Tokenized Data
        # ====================================================================
        logger.info("\n[STEP 6/7] Validating tokenized datasets...")

        validate_tokenized_data(train_tokenized, "train", len(train_data), config)
        validate_tokenized_data(val_tokenized, "val", len(val_data), config)
        validate_tokenized_data(test_tokenized, "test", len(test_data), config)

        logger.info(f"✅ REWARD +20: All tokenized datasets validated successfully")
        reward_score += 20

        # ====================================================================
        # STEP 7: Save
        # ====================================================================
        logger.info("\n[STEP 7/7] Saving tokenized datasets...")

        save_tokenized_dataset(train_tokenized, config.train_output, "train")
        save_tokenized_dataset(val_tokenized, config.val_output, "val")
        save_tokenized_dataset(test_tokenized, config.test_output, "test")

        logger.info(f"✅ REWARD +20: All datasets saved successfully")
        reward_score += 20

        # ====================================================================
        # STEP 8: Sanity Checks
        # ====================================================================
        logger.info("\n[BONUS] Running sanity checks...")

        sanity_check(config.train_output, "train")
        sanity_check(config.val_output, "val")
        sanity_check(config.test_output, "test")

        logger.info(f"✅ REWARD +30: All sanity checks passed")
        reward_score += 30

        # ====================================================================
        # Error Summary
        # ====================================================================
        logger.info("\n[ERROR SUMMARY]")
        total_errors = error_tracker.get_error_count()
        train_errors = error_tracker.get_error_count("train")
        val_errors = error_tracker.get_error_count("val")
        test_errors = error_tracker.get_error_count("test")

        logger.info(f"📊 Error Statistics:")
        logger.info(f"   Total errors: {total_errors}")
        logger.info(f"   Train errors: {train_errors}")
        logger.info(f"   Val errors: {val_errors}")
        logger.info(f"   Test errors: {test_errors}")
        logger.info(f"   Error log: {config.error_log}")

        if total_errors > 0:
            logger.info(
                f"⚠️ WARNING: {total_errors} samples failed tokenization but were handled gracefully"
            )
            reward_score -= min(total_errors, 10)  # Small penalty for errors

        # ====================================================================
        # FINAL SUMMARY
        # ====================================================================
        logger.info("\n" + "=" * 80)
        logger.info("🎉 PIPELINE COMPLETED SUCCESSFULLY!")
        logger.info("=" * 80)
        logger.info(f"🏆 FINAL REWARD SCORE: {reward_score}/170 (adjusted for errors)")
        logger.info(f"\n📁 Output Directory: {config.output_base}")
        logger.info(f"   ├── train_tokenized.pt ({len(train_data)} samples)")
        logger.info(f"   ├── val_tokenized.pt ({len(val_data)} samples)")
        logger.info(f"   ├── test_tokenized.pt ({len(test_data)} samples)")
        if config.use_cache:
            logger.info(f"   └── .cache/ (cached tokenized data)")
        logger.info(f"\n📝 Logs:")
        logger.info(f"   ├── /kaggle/working/tokenization.log")
        logger.info(f"   └── {config.error_log}")
        logger.info("\n✅ Ready for fine-tuning!")
        logger.info("\n🎁 Enhanced Features:")
        logger.info(
            f"   ✅ Dynamic padding: {'ON' if config.dynamic_padding else 'OFF'}"
        )
        logger.info(f"   ✅ Caching: {'ON' if config.use_cache else 'OFF'}")
        logger.info(
            f"   ✅ Error resilience: {'ON' if config.skip_on_error else 'OFF'}"
        )
        logger.info(f"   ✅ Reproducible (seed={config.random_seed})")
        logger.info(f"   ✅ Train shuffling: {'ON' if config.shuffle_train else 'OFF'}")
        logger.info("=" * 80)

        return reward_score

    except Exception as e:
        logger.error("\n" + "=" * 80)
        logger.error("❌ PIPELINE FAILED!")
        logger.error("=" * 80)
        logger.error(f"💔 PENALTY: {e}")
        logger.error(f"📉 Final Score: {reward_score}/170 (FAILED)")

        if error_tracker:
            total_errors = error_tracker.get_error_count()
            logger.error(f"📊 Errors encountered: {total_errors}")
            logger.error(f"   Error log: {config.error_log}")

        logger.error("=" * 80)
        raise

    finally:
        # Cleanup
        if error_tracker:
            error_tracker.close()
            logger.info("🧹 Error tracker closed")


if __name__ == "__main__":
    # Set multiprocessing start method for compatibility
    try:
        if mp.get_start_method(allow_none=True) != "spawn":
            mp.set_start_method("spawn", force=True)
    except RuntimeError:
        # Already set, ignore
        pass

    final_score = main()

    if final_score >= 160:
        print(
            "\n🎊 EXCELLENT SCORE! Pipeline executed successfully with minimal errors! 🎊"
        )
    elif final_score >= 140:
        print("\n✅ GOOD SCORE! Pipeline completed with some warnings. ✅")
    else:
        print("\n⚠️ COMPLETED WITH ISSUES. Check logs for details. ⚠️")
