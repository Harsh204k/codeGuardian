# type: ignore

"""
Enhanced CodeBERT Fine-Tuning with LoRA for Vulnerability Detection
===============================================================================
Production-ready LoRA fine-tuning script optimized for Kaggle Free GPU.
Supports pre-tokenized .pt datasets with optional engineered features.

Key Features:
- LoRA r=8, α=16, dropout=0.1 on attention projections
- Mixed precision (BF16 on A100, FP16 on T4/P100)
- Weighted cross-entropy loss with class balancing
- Early stopping on validation F1
- Gradient accumulation & checkpointing
- Auto-detection of feature dimensions
- Comprehensive logging and metrics

Hardware Support:
- Kaggle T4/P100: 16GB VRAM, FP16
- A100/V100: BF16 support

Author: CodeGuardian Team - IIT Delhi Hackathon
Date: November 2025
"""

import sys
import subprocess


def fix_kaggle_dependencies():
    """Fix transformers/httpx compatibility on Kaggle"""
    try:
        print("🔧 Checking dependencies...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-q", "--upgrade",
             "httpx>=0.24.0", "huggingface-hub>=0.19.0", "transformers>=4.36.0"]
        )
        print("✓ Dependencies updated successfully")
    except Exception as e:
        print(f"⚠️ Warning: Could not update dependencies: {e}")
        print("Continuing with existing versions...")


fix_kaggle_dependencies()

import os
import gc
import json
import time
import logging
import csv
import argparse
from typing import Dict, List, Tuple, Optional, Any
import warnings

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset, TensorDataset
from torch.cuda.amp import autocast, GradScaler
from transformers import (
    AutoModel,
    AutoConfig,
    RobertaModel,
    RobertaConfig,
    get_linear_schedule_with_warmup,
)
from peft import LoraConfig, get_peft_model, TaskType, PeftModel
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    classification_report,
    confusion_matrix,
)
from tqdm import tqdm

warnings.filterwarnings("ignore")

# Reproducibility
torch.manual_seed(42)
np.random.seed(42)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(42)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

torch.backends.cuda.matmul.allow_tf32 = True


def check_bf16_support() -> bool:
    """Check if current GPU supports BFloat16 (compute capability >= 8.0)"""
    if not torch.cuda.is_available():
        return False
    try:
        capability = torch.cuda.get_device_capability()
        return capability[0] >= 8
    except Exception:
        return False


BF16_SUPPORTED = check_bf16_support()


# ============================================================================
# CONFIGURATION
# ============================================================================


class Config:
    """Configuration for CodeBERT LoRA fine-tuning"""

    # Model
    MODEL_NAME = "microsoft/codebert-base"
    NUM_LABELS = 2

    # LoRA
    LORA_R = 8
    LORA_ALPHA = 16
    LORA_DROPOUT = 0.1
    LORA_TARGET_MODULES = ["query", "key", "value"]
    ENABLE_LAYER_NORM_TUNING = True

    # Training
    EPOCHS = 3
    TRAIN_BATCH_SIZE = 4
    EVAL_BATCH_SIZE = 8
    LEARNING_RATE = 3e-5
    WEIGHT_DECAY = 1e-2
    MAX_GRAD_NORM = 1.0
    WARMUP_RATIO = 0.05
    GRADIENT_ACCUMULATION_STEPS = 4

    # Early stopping
    EARLY_STOPPING_PATIENCE = 3
    EARLY_STOPPING_MIN_DELTA = 0.001

    # Loss
    USE_WEIGHTED_LOSS = True
    USE_FOCAL_LOSS = False
    FOCAL_GAMMA = 2.0

    # Feature fusion (auto-detected)
    USE_ENGINEERED_FEATURES = True
    FEATURE_DIM = None
    FUSION_HIDDEN_DIM = 128

    # Paths
    if os.path.exists("/kaggle/input"):
        DATA_PATH = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/codebert"
        OUTPUT_DIR = "/kaggle/working"
    else:
        DATA_PATH = "datasets/tokenized/codebert"
        OUTPUT_DIR = "outputs"

    CHECKPOINT_DIR = f"{OUTPUT_DIR}/checkpoints"
    METRICS_DIR = f"{OUTPUT_DIR}/metrics"
    LOG_DIR = f"{OUTPUT_DIR}/logs"
    FINAL_MODEL_DIR = f"{OUTPUT_DIR}/codebert_lora_final"

    TRAIN_FILE = "train_tokenized_codebert.pt"
    VAL_FILE = "val_tokenized_codebert.pt"
    TEST_FILE = "test_tokenized_codebert.pt"

    # Device
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    USE_MIXED_PRECISION = True
    PRECISION_DTYPE = torch.bfloat16 if BF16_SUPPORTED else torch.float16
    GRADIENT_CHECKPOINTING = True

    # Monitoring
    LOG_INTERVAL = 50
    SAVE_BEST_MODEL = True
    NUM_WORKERS = 2
    AUTO_REDUCE_BATCH_SIZE = True
    MIN_BATCH_SIZE = 1


# ============================================================================
# LOGGING
# ============================================================================


def setup_logging(log_dir: str) -> logging.Logger:
    """Setup logging to file and console"""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "train_log.txt")

    logger = logging.getLogger("CodeBERT_LoRA")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(log_file, mode="a")
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


# ============================================================================
# LOSS FUNCTIONS
# ============================================================================


class FocalLoss(nn.Module):
    """Focal Loss for handling class imbalance"""

    def __init__(self, gamma: float = 2.0, alpha: Optional[torch.Tensor] = None):
        super().__init__()
        self.gamma = gamma
        self.alpha = alpha

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        bce_loss = nn.functional.cross_entropy(inputs, targets, reduction="none")
        pt = torch.exp(-bce_loss)
        focal_loss = ((1 - pt) ** self.gamma) * bce_loss
        if self.alpha is not None:
            focal_loss = self.alpha[targets] * focal_loss
        return focal_loss.mean()


# ============================================================================
# DATASET
# ============================================================================


class PreTokenizedDataset(Dataset):
    """Dataset wrapper for pre-tokenized .pt files with optional features"""

    def __init__(self, data: Dict[str, torch.Tensor], use_features: bool = False):
        self.input_ids = data["input_ids"]
        self.attention_mask = data["attention_mask"]
        self.labels = data["labels"]
        self.features = data.get("features", None) if use_features else None
        self.languages = data.get("language", None)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        item = {
            "input_ids": self.input_ids[idx],
            "attention_mask": self.attention_mask[idx],
            "labels": self.labels[idx],
        }
        if self.features is not None:
            item["features"] = self.features[idx]
        if self.languages is not None:
            item["language"] = self.languages[idx]
        return item


def load_tokenized_dataset(
    file_path: str, config: Config, logger: logging.Logger
) -> Dict[str, torch.Tensor]:
    """Load pre-tokenized dataset from .pt file"""
    logger.info(f"Loading dataset from: {file_path}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    try:
        data = torch.load(file_path, map_location="cpu", weights_only=False)
    except Exception as e:
        logger.error(f"Failed to load {file_path}: {e}")
        raise

    # Handle both dict and TensorDataset formats
    if isinstance(data, TensorDataset):
        data = {
            "input_ids": data.tensors[0],
            "attention_mask": data.tensors[1],
            "labels": data.tensors[2],
        }
    elif not isinstance(data, dict):
        raise ValueError(f"Unknown dataset format: {type(data)}")

    labels = data["labels"]
    logger.info(f"✓ Loaded {len(labels)} samples")
    logger.info(f"  - Input shape: {data['input_ids'].shape}")
    logger.info(f"  - Labels distribution: {torch.bincount(labels).tolist()}")

    if "features" in data:
        logger.info(f"  - Features shape: {data['features'].shape}")
    if "language" in data:
        logger.info(f"  - Languages present: {len(torch.unique(data['language']))}")

    return data


def create_dataloaders(
    config: Config, logger: logging.Logger
) -> Tuple[DataLoader, DataLoader, DataLoader, Optional[int]]:
    """Create dataloaders and return detected feature dimension"""
    logger.info("=" * 70)
    logger.info("LOADING DATASETS")
    logger.info("=" * 70)

    train_data = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, config.TRAIN_FILE), config, logger
    )
    val_data = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, config.VAL_FILE), config, logger
    )
    test_data = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, config.TEST_FILE), config, logger
    )

    # Auto-detect feature dimension
    use_features = config.USE_ENGINEERED_FEATURES and "features" in train_data
    feature_dim = None

    if use_features:
        feature_dim = train_data["features"].shape[1]
        logger.info(f"✓ Detected feature dimension: {feature_dim}")
        config.FEATURE_DIM = feature_dim

    train_dataset = PreTokenizedDataset(train_data, use_features=use_features)
    val_dataset = PreTokenizedDataset(val_data, use_features=use_features)
    test_dataset = PreTokenizedDataset(test_data, use_features=use_features)

    train_loader = DataLoader(
        train_dataset,
        batch_size=config.TRAIN_BATCH_SIZE,
        shuffle=True,
        num_workers=config.NUM_WORKERS,
        pin_memory=torch.cuda.is_available(),
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=config.EVAL_BATCH_SIZE,
        shuffle=False,
        num_workers=config.NUM_WORKERS,
        pin_memory=torch.cuda.is_available(),
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=config.EVAL_BATCH_SIZE,
        shuffle=False,
        num_workers=config.NUM_WORKERS,
        pin_memory=torch.cuda.is_available(),
    )

    logger.info(f"\n✓ DataLoaders created successfully")
    logger.info(f"  - Train batches: {len(train_loader)}")
    logger.info(f"  - Val batches: {len(val_loader)}")
    logger.info(f"  - Test batches: {len(test_loader)}")
    logger.info(f"  - Using engineered features: {use_features}")
    if use_features:
        logger.info(f"  - Feature dimension: {feature_dim}")

    return train_loader, val_loader, test_loader, feature_dim


# ============================================================================
# MODEL
# ============================================================================


class CodeBERTForVulnerabilityDetection(nn.Module):
    """CodeBERT with optional feature fusion for vulnerability detection"""

    def __init__(
        self,
        model_name: str,
        num_labels: int = 2,
        use_features: bool = False,
        feature_dim: int = 107,
        fusion_hidden_dim: int = 128,
    ):
        super().__init__()
        self.use_features = use_features

        # Load pretrained model
        print(f"Loading model: {model_name}")
        try:
            self.config = AutoConfig.from_pretrained(model_name, force_download=False)
            self.roberta = AutoModel.from_pretrained(
                model_name, config=self.config, force_download=False
            )
            print("✓ Loaded successfully using AutoModel")
        except Exception as e:
            print(f"⚠️ AutoModel failed: {str(e)[:100]}")
            try:
                self.config = RobertaConfig.from_pretrained(model_name)
                self.roberta = RobertaModel.from_pretrained(model_name)
                print("✓ Loaded successfully using legacy method")
            except Exception as e2:
                raise RuntimeError(f"Failed to load '{model_name}': {str(e2)}") from e2

        # Freeze backbone
        for param in self.roberta.parameters():
            param.requires_grad = False

        # Classification head with optional feature fusion
        classifier_input_dim = self.config.hidden_size

        if self.use_features:
            self.feature_projection = nn.Sequential(
                nn.Linear(feature_dim, fusion_hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
            )
            classifier_input_dim += fusion_hidden_dim

        self.classifier = nn.Sequential(
            nn.Dropout(0.1), nn.Linear(classifier_input_dim, num_labels)
        )

    def forward(
        self,
        input_ids: Optional[torch.Tensor] = None,
        attention_mask: Optional[torch.Tensor] = None,
        features: Optional[torch.Tensor] = None,
        **kwargs,
    ) -> torch.Tensor:
        """Forward pass with optional feature fusion"""
        if input_ids is None and "inputs_embeds" in kwargs:
            outputs = self.roberta(
                inputs_embeds=kwargs["inputs_embeds"], attention_mask=attention_mask
            )
        else:
            outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)

        pooled_output = outputs.pooler_output

        if self.use_features and features is not None:
            projected_features = self.feature_projection(features)
            pooled_output = torch.cat([pooled_output, projected_features], dim=1)

        logits = self.classifier(pooled_output)
        return logits


def compute_class_weights(labels: torch.Tensor, device: torch.device) -> torch.Tensor:
    """Compute class weights for imbalanced datasets"""
    class_counts = torch.bincount(labels)
    total = len(labels)
    weights = total / (len(class_counts) * class_counts.float())
    return weights.to(device)


def initialize_model(
    config: Config,
    logger: logging.Logger,
    use_features: bool = False,
    feature_dim: Optional[int] = None,
) -> nn.Module:
    """Initialize model with LoRA on attention projections"""
    logger.info("=" * 70)
    logger.info("INITIALIZING MODEL")
    logger.info("=" * 70)

    actual_feature_dim = feature_dim if feature_dim is not None else config.FEATURE_DIM

    if use_features and actual_feature_dim is None:
        raise ValueError("Feature dimension must be specified when use_features=True")

    model = CodeBERTForVulnerabilityDetection(
        model_name=config.MODEL_NAME,
        num_labels=config.NUM_LABELS,
        use_features=use_features,
        feature_dim=actual_feature_dim if use_features else 107,
        fusion_hidden_dim=config.FUSION_HIDDEN_DIM,
    )

    logger.info(f"✓ Base model loaded: {config.MODEL_NAME}")
    if use_features:
        logger.info(f"✓ Feature fusion enabled with dim={actual_feature_dim}")

    total_params = sum(p.numel() for p in model.parameters())
    trainable_params_before = sum(
        p.numel() for p in model.parameters() if p.requires_grad
    )

    logger.info(f"\n📊 Parameters before LoRA:")
    logger.info(f"  - Total: {total_params:,}")
    logger.info(
        f"  - Trainable: {trainable_params_before:,} "
        f"({100*trainable_params_before/total_params:.2f}%)"
    )

    # Apply LoRA
    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=config.LORA_R,
        lora_alpha=config.LORA_ALPHA,
        lora_dropout=config.LORA_DROPOUT,
        target_modules=config.LORA_TARGET_MODULES,
        bias="none",
        inference_mode=False,
    )

    model = get_peft_model(model, lora_config)

    if config.GRADIENT_CHECKPOINTING:
        model.base_model.model.roberta.gradient_checkpointing_enable()
        logger.info("✓ Gradient checkpointing enabled")

    if config.ENABLE_LAYER_NORM_TUNING:
        try:
            for param in model.base_model.model.roberta.encoder.layer[
                11
            ].output.LayerNorm.parameters():
                param.requires_grad = True
            logger.info("✓ LayerNorm tuning enabled")
        except Exception as e:
            logger.warning(f"Could not enable LayerNorm tuning: {e}")

    trainable_params_after = sum(
        p.numel() for p in model.parameters() if p.requires_grad
    )

    logger.info(f"\n✓ LoRA applied to attention projections")
    logger.info(f"  - LoRA rank (r): {config.LORA_R}")
    logger.info(f"  - LoRA alpha: {config.LORA_ALPHA}")
    logger.info(f"  - LoRA dropout: {config.LORA_DROPOUT}")
    logger.info(f"  - Target modules: {config.LORA_TARGET_MODULES}")

    logger.info(f"\n📊 Parameters after LoRA:")
    logger.info(
        f"  - Trainable: {trainable_params_after:,} "
        f"({100*trainable_params_after/total_params:.2f}%)"
    )
    logger.info(
        f"  - Memory reduction: "
        f"{100*(1-trainable_params_after/total_params):.2f}%"
    )

    model = model.to(config.DEVICE)
    return model


# ============================================================================
# TRAINING & EVALUATION
# ============================================================================


def calculate_metrics(predictions: np.ndarray, labels: np.ndarray) -> Dict[str, float]:
    """Calculate evaluation metrics"""
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1": f1_score(labels, predictions, average="binary", zero_division=0),
        "precision": precision_score(
            labels, predictions, average="binary", zero_division=0
        ),
        "recall": recall_score(labels, predictions, average="binary", zero_division=0),
    }


def train_epoch(
    model: nn.Module,
    train_loader: DataLoader,
    optimizer: torch.optim.Optimizer,
    scheduler: Any,
    scaler: Optional[GradScaler],
    criterion: nn.Module,
    config: Config,
    logger: logging.Logger,
    epoch: int,
) -> Dict[str, float]:
    """Train for one epoch with gradient accumulation"""
    model.train()
    total_loss = 0
    all_predictions = []
    all_labels = []

    progress_bar = tqdm(
        train_loader, desc=f"Epoch {epoch}/{config.EPOCHS} [TRAIN]", ncols=100
    )

    accumulation_steps = config.GRADIENT_ACCUMULATION_STEPS
    optimizer.zero_grad()

    for batch_idx, batch in enumerate(progress_bar):
        try:
            input_ids = batch["input_ids"].to(config.DEVICE)
            attention_mask = batch["attention_mask"].to(config.DEVICE)
            labels = batch["labels"].to(config.DEVICE)
            features = batch.get("features", None)
            if features is not None:
                features = features.to(config.DEVICE)

            if config.USE_MIXED_PRECISION:
                with autocast(enabled=True, dtype=config.PRECISION_DTYPE):
                    logits = model(
                        input_ids=input_ids,
                        attention_mask=attention_mask,
                        features=features,
                    )
                    loss = criterion(logits, labels) / accumulation_steps

                scaler.scale(loss).backward()

                if (batch_idx + 1) % accumulation_steps == 0:
                    scaler.unscale_(optimizer)
                    torch.nn.utils.clip_grad_norm_(
                        model.parameters(), config.MAX_GRAD_NORM
                    )
                    scaler.step(optimizer)
                    scaler.update()
                    scheduler.step()
                    optimizer.zero_grad()
            else:
                logits = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    features=features,
                )
                loss = criterion(logits, labels) / accumulation_steps
                loss.backward()

                if (batch_idx + 1) % accumulation_steps == 0:
                    torch.nn.utils.clip_grad_norm_(
                        model.parameters(), config.MAX_GRAD_NORM
                    )
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad()

            total_loss += loss.item() * accumulation_steps
            predictions = torch.argmax(logits, dim=1).cpu().numpy()
            all_predictions.extend(predictions)
            all_labels.extend(labels.cpu().numpy())

            if (batch_idx + 1) % config.LOG_INTERVAL == 0:
                avg_loss = total_loss / (batch_idx + 1)
                progress_bar.set_postfix(
                    {"loss": f"{avg_loss:.4f}", "lr": f"{scheduler.get_last_lr()[0]:.2e}"}
                )

        except RuntimeError as e:
            if "out of memory" in str(e):
                logger.error(f"OOM error at batch {batch_idx}")
                torch.cuda.empty_cache()
                gc.collect()
                if config.AUTO_REDUCE_BATCH_SIZE:
                    logger.warning("Consider reducing batch size")
                raise
            else:
                raise

    avg_loss = total_loss / len(train_loader)
    metrics = calculate_metrics(np.array(all_predictions), np.array(all_labels))
    metrics["loss"] = avg_loss
    return metrics


def evaluate(
    model: nn.Module,
    data_loader: DataLoader,
    criterion: nn.Module,
    config: Config,
    logger: logging.Logger,
    split_name: str,
) -> Tuple[Dict[str, float], Dict[str, Any]]:
    """Evaluate model on validation or test set"""
    model.eval()
    total_loss = 0
    all_predictions = []
    all_labels = []
    all_languages = []

    progress_bar = tqdm(data_loader, desc=f"{split_name.upper()}", ncols=100)

    with torch.no_grad():
        for batch in progress_bar:
            try:
                input_ids = batch["input_ids"].to(config.DEVICE)
                attention_mask = batch["attention_mask"].to(config.DEVICE)
                labels = batch["labels"].to(config.DEVICE)
                features = batch.get("features", None)
                if features is not None:
                    features = features.to(config.DEVICE)

                if config.USE_MIXED_PRECISION:
                    with autocast(enabled=True, dtype=config.PRECISION_DTYPE):
                        logits = model(
                            input_ids=input_ids,
                            attention_mask=attention_mask,
                            features=features,
                        )
                        loss = criterion(logits, labels)
                else:
                    logits = model(
                        input_ids=input_ids,
                        attention_mask=attention_mask,
                        features=features,
                    )
                    loss = criterion(logits, labels)

                total_loss += loss.item()
                predictions = torch.argmax(logits, dim=1).cpu().numpy()
                all_predictions.extend(predictions)
                all_labels.extend(labels.cpu().numpy())

                if "language" in batch:
                    all_languages.extend(batch["language"].cpu().numpy())

            except RuntimeError as e:
                if "out of memory" in str(e):
                    logger.error(f"OOM error during evaluation")
                    torch.cuda.empty_cache()
                    gc.collect()
                    raise
                else:
                    raise

    avg_loss = total_loss / len(data_loader)
    metrics = calculate_metrics(np.array(all_predictions), np.array(all_labels))
    metrics["loss"] = avg_loss

    info = {
        "predictions": np.array(all_predictions),
        "labels": np.array(all_labels),
        "languages": np.array(all_languages) if all_languages else None,
    }

    return metrics, info


# ============================================================================
# SAVING UTILITIES
# ============================================================================


def save_model(
    model: nn.Module, config: Config, logger: logging.Logger, name: str = "final"
) -> None:
    """Save model and config"""
    save_dir = config.FINAL_MODEL_DIR if name == "final" else config.CHECKPOINT_DIR
    os.makedirs(save_dir, exist_ok=True)

    model.save_pretrained(save_dir)
    logger.info(f"✓ Model saved to: {save_dir}")

    config_dict = {
        k: v
        for k, v in config.__dict__.items()
        if not k.startswith("__") and not callable(v)
    }
    for k, v in config_dict.items():
        if isinstance(v, (torch.device, torch.dtype)):
            config_dict[k] = str(v)

    config_path = os.path.join(config.OUTPUT_DIR, "model_config.json")
    with open(config_path, "w") as f:
        json.dump(config_dict, f, indent=2)
    logger.info(f"✓ Config saved to: {config_path}")


def save_metrics(
    metrics: Dict[str, Any], config: Config, logger: logging.Logger
) -> None:
    """Save metrics to JSON"""
    os.makedirs(config.METRICS_DIR, exist_ok=True)
    metrics_path = os.path.join(config.OUTPUT_DIR, "results.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"✓ Metrics saved to: {metrics_path}")


def save_classification_report(
    predictions: np.ndarray,
    labels: np.ndarray,
    config: Config,
    logger: logging.Logger,
) -> None:
    """Save detailed classification report"""
    os.makedirs(config.METRICS_DIR, exist_ok=True)

    report = classification_report(
        labels, predictions, target_names=["Secure", "Vulnerable"], output_dict=True
    )

    report_path = os.path.join(config.METRICS_DIR, "classification_report.csv")
    with open(report_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Class", "Precision", "Recall", "F1-Score", "Support"])
        for cls, metrics in report.items():
            if cls not in ["accuracy", "macro avg", "weighted avg"]:
                writer.writerow(
                    [
                        cls,
                        metrics["precision"],
                        metrics["recall"],
                        metrics["f1-score"],
                        metrics["support"],
                    ]
                )

    logger.info(f"✓ Classification report saved to: {report_path}")

    cm = confusion_matrix(labels, predictions)
    logger.info("\nConfusion Matrix:")
    logger.info(f"  TN: {cm[0][0]}, FP: {cm[0][1]}")
    logger.info(f"  FN: {cm[1][0]}, TP: {cm[1][1]}")


def save_training_log(
    epoch: int, train_metrics: Dict, val_metrics: Dict, config: Config
) -> None:
    """Append epoch metrics to CSV log"""
    os.makedirs(config.LOG_DIR, exist_ok=True)
    log_path = os.path.join(config.LOG_DIR, "train_log.csv")

    if not os.path.exists(log_path):
        with open(log_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "epoch",
                    "train_loss",
                    "train_acc",
                    "train_f1",
                    "train_precision",
                    "train_recall",
                    "val_loss",
                    "val_acc",
                    "val_f1",
                    "val_precision",
                    "val_recall",
                ]
            )

    with open(log_path, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                epoch,
                train_metrics["loss"],
                train_metrics["accuracy"],
                train_metrics["f1"],
                train_metrics["precision"],
                train_metrics["recall"],
                val_metrics["loss"],
                val_metrics["accuracy"],
                val_metrics["f1"],
                val_metrics["precision"],
                val_metrics["recall"],
            ]
        )


# ============================================================================
# MAIN TRAINING LOOP
# ============================================================================


def train(config: Config) -> None:
    """Main training function"""
    start_time = time.time()
    logger = setup_logging(config.LOG_DIR)

    logger.info("=" * 70)
    logger.info("CODEGUARDIAN - CODEBERT FINE-TUNING WITH LORA (ENHANCED)")
    logger.info("=" * 70)
    logger.info(f"Device: {config.DEVICE}")

    if config.USE_MIXED_PRECISION:
        precision_name = (
            "BFloat16" if config.PRECISION_DTYPE == torch.bfloat16 else "Float16"
        )
        logger.info(f"Precision: {precision_name} (Mixed Precision)")
    else:
        logger.info(f"Precision: Float32")

    logger.info(f"Train Batch Size: {config.TRAIN_BATCH_SIZE}")
    logger.info(f"Eval Batch Size: {config.EVAL_BATCH_SIZE}")
    logger.info(f"Gradient Accumulation: {config.GRADIENT_ACCUMULATION_STEPS}x")
    logger.info(
        f"Effective Batch Size: "
        f"{config.TRAIN_BATCH_SIZE * config.GRADIENT_ACCUMULATION_STEPS}"
    )
    logger.info(f"Learning Rate: {config.LEARNING_RATE}")
    logger.info(f"Epochs: {config.EPOCHS}")

    if torch.cuda.is_available():
        logger.info(f"\n🎮 GPU Info:")
        logger.info(f"  - Name: {torch.cuda.get_device_name(0)}")
        logger.info(
            f"  - Memory: "
            f"{torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB"
        )
        capability = torch.cuda.get_device_capability()
        logger.info(f"  - Compute Capability: {capability[0]}.{capability[1]}")
        logger.info(
            f"  - BFloat16 Support: "
            f"{'Yes' if BF16_SUPPORTED else 'No (using FP16)'}"
        )

    os.makedirs(config.CHECKPOINT_DIR, exist_ok=True)
    os.makedirs(config.METRICS_DIR, exist_ok=True)
    os.makedirs(config.LOG_DIR, exist_ok=True)

    train_loader, val_loader, test_loader, feature_dim = create_dataloaders(
        config, logger
    )

    first_batch = next(iter(train_loader))
    use_features = "features" in first_batch

    logger.info("\n📊 Computing class weights...")
    train_data = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, config.TRAIN_FILE), config, logger
    )
    train_labels = train_data["labels"]
    class_weights = compute_class_weights(train_labels, config.DEVICE)

    logger.info(f"\n📊 Class Distribution:")
    logger.info(f"  - Class 0 (Secure): {(train_labels == 0).sum().item()}")
    logger.info(f"  - Class 1 (Vulnerable): {(train_labels == 1).sum().item()}")
    logger.info(f"  - Class weights: {class_weights.tolist()}")

    model = initialize_model(
        config, logger, use_features=use_features, feature_dim=feature_dim
    )

    if config.USE_FOCAL_LOSS:
        criterion = FocalLoss(gamma=config.FOCAL_GAMMA, alpha=class_weights)
        logger.info(f"\n✓ Using Focal Loss (γ={config.FOCAL_GAMMA})")
    elif config.USE_WEIGHTED_LOSS:
        criterion = nn.CrossEntropyLoss(weight=class_weights)
        logger.info("\n✓ Using Weighted Cross Entropy Loss")
    else:
        criterion = nn.CrossEntropyLoss()
        logger.info("\n✓ Using Cross Entropy Loss")

    optimizer = torch.optim.AdamW(
        model.parameters(), lr=config.LEARNING_RATE, weight_decay=config.WEIGHT_DECAY
    )

    num_training_steps = (
        len(train_loader) * config.EPOCHS // config.GRADIENT_ACCUMULATION_STEPS
    )
    warmup_steps = int(num_training_steps * config.WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_steps, num_training_steps=num_training_steps
    )

    logger.info(f"\n📊 Training Schedule:")
    logger.info(f"  - Total steps: {num_training_steps}")
    logger.info(f"  - Warmup steps: {warmup_steps}")

    scaler = GradScaler() if config.USE_MIXED_PRECISION else None

    best_f1 = 0.0
    patience_counter = 0
    training_history = {"train": [], "val": [], "test": None}

    logger.info("\n" + "=" * 70)
    logger.info("STARTING TRAINING")
    logger.info("=" * 70)

    for epoch in range(1, config.EPOCHS + 1):
        epoch_start = time.time()

        logger.info(f"\n{'='*70}")
        logger.info(f"EPOCH {epoch}/{config.EPOCHS}")
        logger.info(f"{'='*70}")

        try:
            train_metrics = train_epoch(
                model,
                train_loader,
                optimizer,
                scheduler,
                scaler,
                criterion,
                config,
                logger,
                epoch,
            )
            training_history["train"].append(train_metrics)

            epoch_time = time.time() - epoch_start

            logger.info(f"\n📊 Train Metrics:")
            logger.info(f"  - Loss: {train_metrics['loss']:.4f}")
            logger.info(f"  - Accuracy: {train_metrics['accuracy']:.4f}")
            logger.info(f"  - F1-Score: {train_metrics['f1']:.4f}")
            logger.info(f"  - Precision: {train_metrics['precision']:.4f}")
            logger.info(f"  - Recall: {train_metrics['recall']:.4f}")
            logger.info(f"  - Time: {epoch_time:.2f}s")

            val_metrics, val_info = evaluate(
                model, val_loader, criterion, config, logger, "validation"
            )
            training_history["val"].append(val_metrics)

            logger.info(f"\n📊 Validation Metrics:")
            logger.info(f"  - Loss: {val_metrics['loss']:.4f}")
            logger.info(f"  - Accuracy: {val_metrics['accuracy']:.4f}")
            logger.info(f"  - F1-Score: {val_metrics['f1']:.4f}")
            logger.info(f"  - Precision: {val_metrics['precision']:.4f}")
            logger.info(f"  - Recall: {val_metrics['recall']:.4f}")

            save_training_log(epoch, train_metrics, val_metrics, config)

            if val_metrics["f1"] > best_f1 + config.EARLY_STOPPING_MIN_DELTA:
                best_f1 = val_metrics["f1"]
                patience_counter = 0
                if config.SAVE_BEST_MODEL:
                    save_model(model, config, logger, name="best")
                    logger.info(f"\n✓ Best model saved! (F1: {best_f1:.4f})")
            else:
                patience_counter += 1
                logger.info(
                    f"\n⚠️ No improvement. Patience: "
                    f"{patience_counter}/{config.EARLY_STOPPING_PATIENCE}"
                )

            if patience_counter >= config.EARLY_STOPPING_PATIENCE:
                logger.info(
                    f"\n⏸️  Early stopping triggered after {epoch} epochs "
                    f"(best F1: {best_f1:.4f})"
                )
                break

            if torch.cuda.is_available():
                memory_allocated = torch.cuda.memory_allocated(0) / 1e9
                memory_reserved = torch.cuda.memory_reserved(0) / 1e9
                logger.info(f"\n💾 GPU Memory:")
                logger.info(f"  - Allocated: {memory_allocated:.2f} GB")
                logger.info(f"  - Reserved: {memory_reserved:.2f} GB")

        except RuntimeError as e:
            if "out of memory" in str(e):
                logger.error(f"\n❌ OOM Error at epoch {epoch}")
                logger.error(
                    "Consider reducing batch size or gradient accumulation steps"
                )
                torch.cuda.empty_cache()
                gc.collect()
                raise
            else:
                raise

    if config.SAVE_BEST_MODEL:
        logger.info(f"\n{'='*70}")
        logger.info("LOADING BEST MODEL FOR FINAL EVALUATION")
        logger.info(f"{'='*70}")
        try:
            model = PeftModel.from_pretrained(
                model.base_model.model, config.CHECKPOINT_DIR
            )
            model = model.to(config.DEVICE)
            logger.info(f"✓ Loaded best model (F1: {best_f1:.4f})")
        except Exception as e:
            logger.warning(f"Could not load best model: {e}. Using current model.")

    logger.info(f"\n{'='*70}")
    logger.info("FINAL TEST EVALUATION")
    logger.info(f"{'='*70}")

    test_metrics, test_info = evaluate(
        model, test_loader, criterion, config, logger, "test"
    )
    training_history["test"] = test_metrics

    logger.info(f"\n📊 Test Metrics:")
    logger.info(f"  - Loss: {test_metrics['loss']:.4f}")
    logger.info(f"  - Accuracy: {test_metrics['accuracy']:.4f}")
    logger.info(f"  - F1-Score: {test_metrics['f1']:.4f}")
    logger.info(f"  - Precision: {test_metrics['precision']:.4f}")
    logger.info(f"  - Recall: {test_metrics['recall']:.4f}")

    save_model(model, config, logger, name="final")
    save_metrics(training_history, config, logger)
    save_classification_report(
        test_info["predictions"], test_info["labels"], config, logger
    )

    # ============================================================
    # MERGE LORA ADAPTERS INTO BASE MODEL (for standalone export)
    # ============================================================
    logger.info(f"\n{'='*70}")
    logger.info("MERGING LORA ADAPTERS INTO BASE MODEL")
    logger.info(f"{'='*70}")

    try:
        from transformers import AutoModelForSequenceClassification

        # Load the original frozen CodeBERT base
        logger.info("Loading base CodeBERT model...")
        base = AutoModelForSequenceClassification.from_pretrained(
            "microsoft/codebert-base", num_labels=config.NUM_LABELS
        )

        # Load the best fine-tuned LoRA adapters (from final model directory)
        logger.info(f"Loading LoRA adapters from: {config.FINAL_MODEL_DIR}")
        merged_model = PeftModel.from_pretrained(base, config.FINAL_MODEL_DIR)

        # Merge the LoRA deltas into the base weights
        logger.info("Merging LoRA weights into base model...")
        merged_model = merged_model.merge_and_unload()

        # Save the fully merged, standalone model
        merged_dir = os.path.join(config.OUTPUT_DIR, "codebert_lora_merged")
        os.makedirs(merged_dir, exist_ok=True)
        merged_model.save_pretrained(merged_dir)

        # Also save tokenizer for convenience
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(config.MODEL_NAME)
        tokenizer.save_pretrained(merged_dir)

        # Calculate and log size
        merged_size = sum(
            os.path.getsize(os.path.join(merged_dir, f))
            for f in os.listdir(merged_dir)
            if os.path.isfile(os.path.join(merged_dir, f))
        ) / (1024 * 1024)

        logger.info(f"✓ LoRA adapters successfully merged and saved!")
        logger.info(f"  - Path: {merged_dir}")
        logger.info(f"  - Size: {merged_size:.2f} MB")
        logger.info(f"  - Status: Ready for standalone deployment")
        logger.info(f"  - Usage: Load with AutoModelForSequenceClassification.from_pretrained()")

        # Cleanup merged model
        del merged_model
        del base
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

    except Exception as e:
        logger.warning(f"⚠️ Merge step failed: {e}")
        logger.warning("Continuing with LoRA adapter-only checkpoint")
        import traceback
        traceback.print_exc()

    logger.info(f"\n{'='*70}")
    logger.info("CLEANING UP")
    logger.info(f"{'='*70}")
    del model
    del optimizer
    if scaler:
        del scaler
    torch.cuda.empty_cache()
    gc.collect()
    logger.info("✓ GPU memory cleaned")

    total_time = time.time() - start_time

    logger.info(f"\n{'='*70}")
    logger.info("TRAINING COMPLETE!")
    logger.info(f"{'='*70}")
    logger.info(f"✓ Best Validation F1: {best_f1:.4f}")
    logger.info(f"✓ Test F1: {test_metrics['f1']:.4f}")
    logger.info(f"✓ Total Runtime: {total_time/60:.2f} minutes")
    logger.info(f"✓ Model saved: {config.FINAL_MODEL_DIR}")
    logger.info(f"✓ Results saved: {config.OUTPUT_DIR}/results.json")


# ============================================================================
# ENTRY POINT
# ============================================================================


def main():
    """Entry point with CLI argument parsing"""
    parser = argparse.ArgumentParser(
        description="Fine-tune CodeBERT with LoRA for vulnerability detection"
    )
    parser.add_argument(
        "--data_path", type=str, help="Path to tokenized dataset directory"
    )
    parser.add_argument("--output_dir", type=str, help="Output directory")
    parser.add_argument("--epochs", type=int, default=3, help="Number of epochs")
    parser.add_argument("--batch_size", type=int, default=4, help="Training batch size")
    parser.add_argument("--lr", type=float, default=3e-5, help="Learning rate")
    parser.add_argument(
        "--use_focal_loss", action="store_true", help="Use Focal Loss instead of CE"
    )

    args = parser.parse_args()

    config = Config()

    if args.data_path:
        config.DATA_PATH = args.data_path
    if args.output_dir:
        config.OUTPUT_DIR = args.output_dir
        config.CHECKPOINT_DIR = f"{args.output_dir}/checkpoints"
        config.METRICS_DIR = f"{args.output_dir}/metrics"
        config.LOG_DIR = f"{args.output_dir}/logs"
        config.FINAL_MODEL_DIR = f"{args.output_dir}/codebert_lora_final"
    if args.epochs:
        config.EPOCHS = args.epochs
    if args.batch_size:
        config.TRAIN_BATCH_SIZE = args.batch_size
    if args.lr:
        config.LEARNING_RATE = args.lr
    if args.use_focal_loss:
        config.USE_FOCAL_LOSS = True

    try:
        train(config)
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback

        traceback.print_exc()

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()
        raise


if __name__ == "__main__":
    main()
