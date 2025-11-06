#!/usr/bin/env python3
# =============================================================
# codeGuardian LoRA Fine-tuning Pipeline (Pure-code version)
# Model: microsoft/graphcodebert-base
# Author: Urva Gandhi
# =============================================================
"""
Fine-tunes GraphCodeBERT using LoRA for vulnerability detection.
Optimized for Kaggle Free GPU (T4/P100) with mixed precision and early stopping.

Features:
- Pure-code training (no engineered features)
- LoRA r=8, α=16, dropout=0.1
- Mixed precision (BF16/FP16 auto-detect)
- Weighted cross-entropy + optional Focal Loss
- Early stopping on F1 score
- Gradient accumulation & checkpointing
- Automatic LoRA adapter merging
"""

import os
import sys
import gc
import json
import time
import logging
import argparse
import hashlib
from typing import Dict, Tuple, Optional
from pathlib import Path
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from torch import amp
from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup
from peft import LoraConfig, get_peft_model, PeftModel
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, classification_report, confusion_matrix
from tqdm import tqdm

# Reproducibility
SEED = 42
torch.manual_seed(SEED)
np.random.seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

# ============================================================================
# GPU DETECTION
# ============================================================================

def check_bf16_support() -> bool:
    """Check if GPU supports BFloat16 (compute capability >= 8.0)"""
    if not torch.cuda.is_available():
        return False
    capability = torch.cuda.get_device_capability()
    return capability[0] >= 8

BF16_SUPPORTED = check_bf16_support()

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Training configuration"""

    # Model
    MODEL_NAME = "microsoft/graphcodebert-base"
    NUM_LABELS = 2

    # LoRA
    LORA_R = 8
    LORA_ALPHA = 16
    LORA_DROPOUT = 0.1
    LORA_TARGET_MODULES = ["query", "value"]

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
    EARLY_STOPPING_PATIENCE = 2
    EARLY_STOPPING_MIN_DELTA = 0.001

    # Loss
    USE_WEIGHTED_LOSS = True
    USE_FOCAL_LOSS = False
    FOCAL_GAMMA = 2.0

    # Paths
    if os.path.exists("/kaggle/input"):
        DATA_PATH = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/graphcodebert-base"
        OUTPUT_DIR = "/kaggle/working"
    else:
        DATA_PATH = "datasets/tokenized/graphcodebert"
        OUTPUT_DIR = "outputs"

    CHECKPOINT_DIR = f"{OUTPUT_DIR}/checkpoints_graphcodebert"
    METRICS_DIR = f"{OUTPUT_DIR}/metrics_graphcodebert"
    LOG_DIR = f"{OUTPUT_DIR}/logs"
    FINAL_MODEL_DIR = f"{OUTPUT_DIR}/graphcodebert_lora_final"
    MERGED_MODEL_DIR = f"{OUTPUT_DIR}/graphcodebert_lora_merged"

    # Device
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    USE_MIXED_PRECISION = True
    PRECISION_DTYPE = torch.bfloat16 if BF16_SUPPORTED else torch.float16
    GRADIENT_CHECKPOINTING = True

# ============================================================================
# LOGGING
# ============================================================================

def generate_run_hash(config: 'Config') -> str:
    """Generate reproducibility hash from training configuration"""
    config_str = f"{config.MODEL_NAME}_{config.LORA_R}_{config.LORA_ALPHA}_" \
                 f"{config.LEARNING_RATE}_{config.TRAIN_BATCH_SIZE}_{config.EPOCHS}_" \
                 f"{SEED}_{config.USE_WEIGHTED_LOSS}_{config.USE_FOCAL_LOSS}"
    return hashlib.md5(config_str.encode()).hexdigest()[:8]

def setup_logging(log_dir: str) -> logging.Logger:
    """Setup logging to file and console"""
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("GraphCodeBERT_LoRA")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    fh = logging.FileHandler(os.path.join(log_dir, "train_log.txt"), mode="a")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
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
# DATA LOADING
# ============================================================================

def load_tokenized_dataset(file_path: str, logger: logging.Logger) -> TensorDataset:
    """Load pre-tokenized dataset from .pt file"""
    logger.info(f"Loading: {file_path}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    data = torch.load(file_path, map_location="cpu")

    # Extract tensors
    input_ids = data["input_ids"]
    attention_mask = data["attention_mask"]
    labels = data["labels"]

    logger.info(f"  Samples: {len(labels):,}")
    logger.info(f"  Shape: {input_ids.shape}")
    logger.info(f"  Labels: {torch.bincount(labels).tolist()}")

    return TensorDataset(input_ids, attention_mask, labels)

def create_dataloaders(config: Config, logger: logging.Logger) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """Create train, validation, and test dataloaders"""
    logger.info("=" * 70)
    logger.info("LOADING DATASETS")
    logger.info("=" * 70)

    train_dataset = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, "train_tokenized_graphcodebert-base.pt"), logger
    )
    val_dataset = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, "val_tokenized_graphcodebert-base.pt"), logger
    )
    test_dataset = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, "test_tokenized_graphcodebert-base.pt"), logger
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=config.TRAIN_BATCH_SIZE,
        shuffle=True,
        num_workers=2,
        pin_memory=True
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=config.EVAL_BATCH_SIZE,
        shuffle=False,
        num_workers=2,
        pin_memory=True
    )
    test_loader = DataLoader(
        test_dataset,
        batch_size=config.EVAL_BATCH_SIZE,
        shuffle=False,
        num_workers=2,
        pin_memory=True
    )

    logger.info(f"Train batches: {len(train_loader)}")
    logger.info(f"Val batches: {len(val_loader)}")
    logger.info(f"Test batches: {len(test_loader)}")

    return train_loader, val_loader, test_loader

# ============================================================================
# MODEL
# ============================================================================

class GraphCodeBERTClassifier(nn.Module):
    """GraphCodeBERT with classification head"""

    def __init__(self, model_name: str, num_labels: int = 2):
        super().__init__()
        self.roberta = AutoModel.from_pretrained(model_name)
        self.config = self.roberta.config  # Expose config for PEFT compatibility
        self.classifier = nn.Sequential(
            nn.Dropout(0.1),
            nn.Linear(self.roberta.config.hidden_size, num_labels)
        )

        # Freeze backbone
        for param in self.roberta.parameters():
            param.requires_grad = False

    def forward(self, input_ids, attention_mask, **kwargs):
        outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)
        pooled = outputs.pooler_output
        logits = self.classifier(pooled)
        return logits

def compute_class_weights(labels: torch.Tensor, device: torch.device) -> torch.Tensor:
    """Compute class weights for imbalanced datasets"""
    class_counts = torch.bincount(labels)
    total = len(labels)
    weights = total / (len(class_counts) * class_counts.float())
    return weights.to(device)

def initialize_model(config: Config, logger: logging.Logger) -> nn.Module:
    """Initialize model with LoRA"""
    logger.info("=" * 70)
    logger.info("INITIALIZING MODEL")
    logger.info("=" * 70)

    model = GraphCodeBERTClassifier(config.MODEL_NAME, config.NUM_LABELS)
    logger.info(f"Base model: {config.MODEL_NAME}")

    total_params = sum(p.numel() for p in model.parameters())
    trainable_before = sum(p.numel() for p in model.parameters() if p.requires_grad)

    logger.info(f"Total params: {total_params:,}")
    logger.info(f"Trainable before LoRA: {trainable_before:,} ({100*trainable_before/total_params:.2f}%)")

    # Apply LoRA
    lora_config = LoraConfig(
        task_type="SEQ_CLS",
        r=config.LORA_R,
        lora_alpha=config.LORA_ALPHA,
        lora_dropout=config.LORA_DROPOUT,
        target_modules=config.LORA_TARGET_MODULES,
        bias="none",
        inference_mode=False
    )

    model = get_peft_model(model, lora_config)

    if config.GRADIENT_CHECKPOINTING:
        try:
            if hasattr(model.base_model, "roberta"):
                model.base_model.roberta.gradient_checkpointing_enable()
            elif hasattr(model.base_model, "model") and hasattr(model.base_model.model, "roberta"):
                model.base_model.model.roberta.gradient_checkpointing_enable()
            logger.info("✓ Gradient checkpointing enabled")
        except Exception as e:
            logger.warning(f"Could not enable gradient checkpointing: {e}")

    trainable_after = sum(p.numel() for p in model.parameters() if p.requires_grad)

    logger.info(f"LoRA config: r={config.LORA_R}, α={config.LORA_ALPHA}, dropout={config.LORA_DROPOUT}")
    logger.info(f"Target modules: {config.LORA_TARGET_MODULES}")
    logger.info(f"Trainable after LoRA: {trainable_after:,} ({100*trainable_after/total_params:.2f}%)")
    logger.info(f"Memory reduction: {100*(1-trainable_after/total_params):.1f}%")

    return model.to(config.DEVICE)

# ============================================================================
# TRAINING
# ============================================================================

def calculate_metrics(predictions: np.ndarray, labels: np.ndarray) -> Dict[str, float]:
    """Calculate evaluation metrics"""
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1": f1_score(labels, predictions, average="binary", zero_division=0),
        "precision": precision_score(labels, predictions, average="binary", zero_division=0),
        "recall": recall_score(labels, predictions, average="binary", zero_division=0)
    }

def train_epoch(
    model, train_loader, optimizer, scheduler, scaler, criterion,
    config: Config, logger: logging.Logger, epoch: int
) -> Dict[str, float]:
    """Train for one epoch"""
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []

    progress_bar = tqdm(train_loader, desc=f"Epoch {epoch}/{config.EPOCHS} [TRAIN]")
    optimizer.zero_grad()

    for batch_idx, batch in enumerate(progress_bar):
        input_ids = batch[0].to(config.DEVICE)
        attention_mask = batch[1].to(config.DEVICE)
        labels = batch[2].to(config.DEVICE)

        if config.USE_MIXED_PRECISION:
            with amp.autocast("cuda", dtype=config.PRECISION_DTYPE):
                logits = model(input_ids=input_ids, attention_mask=attention_mask)
                loss = criterion(logits, labels) / config.GRADIENT_ACCUMULATION_STEPS

            scaler.scale(loss).backward()

            if (batch_idx + 1) % config.GRADIENT_ACCUMULATION_STEPS == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.MAX_GRAD_NORM)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()
                optimizer.zero_grad()
        else:
            logits = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = criterion(logits, labels) / config.GRADIENT_ACCUMULATION_STEPS
            loss.backward()

            if (batch_idx + 1) % config.GRADIENT_ACCUMULATION_STEPS == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.MAX_GRAD_NORM)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

        total_loss += loss.item() * config.GRADIENT_ACCUMULATION_STEPS
        preds = torch.argmax(logits, dim=1).cpu().numpy()
        all_preds.extend(preds)
        all_labels.extend(labels.cpu().numpy())

        progress_bar.set_postfix({"loss": f"{total_loss/(batch_idx+1):.4f}"})

        # Live progress logging every 5% of epoch
        if (batch_idx + 1) % max(1, len(train_loader) // 20) == 0:
            step_loss = total_loss / (batch_idx + 1)
            step_preds = np.array(all_preds)
            step_labels = np.array(all_labels)
            acc = accuracy_score(step_labels, step_preds)
            f1 = f1_score(step_labels, step_preds, average="binary", zero_division=0)
            progress_pct = 100 * (batch_idx + 1) / len(train_loader)
            logger.info(f"  [Epoch {epoch}] Progress {progress_pct:.1f}% | Loss={step_loss:.4f} | Acc={acc:.4f} | F1={f1:.4f}")

    metrics = calculate_metrics(np.array(all_preds), np.array(all_labels))
    metrics["loss"] = total_loss / len(train_loader)
    return metrics

def evaluate(
    model, data_loader, criterion, config: Config, logger: logging.Logger, split_name: str
) -> Dict[str, float]:
    """Evaluate model"""
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for batch in tqdm(data_loader, desc=f"{split_name.upper()}"):
            input_ids = batch[0].to(config.DEVICE)
            attention_mask = batch[1].to(config.DEVICE)
            labels = batch[2].to(config.DEVICE)

            if config.USE_MIXED_PRECISION:
                with amp.autocast("cuda", dtype=config.PRECISION_DTYPE):
                    logits = model(input_ids=input_ids, attention_mask=attention_mask)
                    loss = criterion(logits, labels)
            else:
                logits = model(input_ids=input_ids, attention_mask=attention_mask)
                loss = criterion(logits, labels)

            total_loss += loss.item()
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(labels.cpu().numpy())

    metrics = calculate_metrics(np.array(all_preds), np.array(all_labels))
    metrics["loss"] = total_loss / len(data_loader)
    metrics["predictions"] = np.array(all_preds)
    metrics["labels"] = np.array(all_labels)
    return metrics

# ============================================================================
# MAIN TRAINING LOOP
# ============================================================================

def train(config: Config, logger: logging.Logger):
    """Main training function"""
    start_time = time.time()

    # Generate reproducibility hash
    run_hash = generate_run_hash(config)
    run_id = f"graphcodebert_lora_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{run_hash}"

    logger.info("=" * 70)
    logger.info("GRAPHCODEBERT LORA FINE-TUNING (PURE-CODE)")
    logger.info("=" * 70)
    logger.info(f"Run ID: {run_id}")
    logger.info(f"Reproducibility Hash: {run_hash}")
    logger.info(f"Random Seed: {SEED}")
    logger.info(f"Device: {config.DEVICE}")
    logger.info(f"Precision: {'BFloat16' if config.PRECISION_DTYPE == torch.bfloat16 else 'Float16'}")
    logger.info(f"Batch size: {config.TRAIN_BATCH_SIZE} (effective: {config.TRAIN_BATCH_SIZE * config.GRADIENT_ACCUMULATION_STEPS})")
    logger.info(f"Learning rate: {config.LEARNING_RATE}")
    logger.info(f"Epochs: {config.EPOCHS}")

    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_memory / 1e9
        logger.info(f"\n🎮 GPU: {gpu_name} ({gpu_mem:.1f} GB)")
        capability = torch.cuda.get_device_capability()
        logger.info(f"  Compute Capability: {capability[0]}.{capability[1]}")
        logger.info(f"  BFloat16 Support: {'Yes' if BF16_SUPPORTED else 'No (using FP16)'}")

    # Create directories
    for dir_path in [config.CHECKPOINT_DIR, config.METRICS_DIR, config.LOG_DIR]:
        os.makedirs(dir_path, exist_ok=True)

    # Load data
    train_loader, val_loader, test_loader = create_dataloaders(config, logger)

    # Compute class weights
    logger.info("\nComputing class weights...")
    train_data = torch.load(os.path.join(config.DATA_PATH, "train_tokenized_graphcodebert-base.pt"))
    class_weights = compute_class_weights(train_data["labels"], config.DEVICE)
    logger.info(f"Class weights: {class_weights.tolist()}")

    # Initialize model
    model = initialize_model(config, logger)

    # Setup loss
    if config.USE_FOCAL_LOSS:
        criterion = FocalLoss(gamma=config.FOCAL_GAMMA, alpha=class_weights)
        logger.info(f"Loss: Focal Loss (γ={config.FOCAL_GAMMA})")
    elif config.USE_WEIGHTED_LOSS:
        criterion = nn.CrossEntropyLoss(weight=class_weights)
        logger.info("Loss: Weighted Cross Entropy")
    else:
        criterion = nn.CrossEntropyLoss()
        logger.info("Loss: Cross Entropy")

    # Setup optimizer & scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.LEARNING_RATE, weight_decay=config.WEIGHT_DECAY)

    num_training_steps = len(train_loader) * config.EPOCHS // config.GRADIENT_ACCUMULATION_STEPS
    warmup_steps = int(num_training_steps * config.WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, num_training_steps)

    scaler = amp.GradScaler("cuda") if config.USE_MIXED_PRECISION else None

    logger.info(f"\nTraining steps: {num_training_steps}")
    logger.info(f"Warmup steps: {warmup_steps}")

    # Training loop
    best_f1 = 0.0
    patience = 0
    history = {"train": [], "val": [], "test": None}

    logger.info("\n" + "=" * 70)
    logger.info("STARTING TRAINING")
    logger.info("=" * 70)

    for epoch in range(1, config.EPOCHS + 1):
        epoch_start = time.time()

        # Train
        train_metrics = train_epoch(model, train_loader, optimizer, scheduler, scaler, criterion, config, logger, epoch)
        history["train"].append(train_metrics)

        logger.info(f"\nTrain - Loss: {train_metrics['loss']:.4f}, F1: {train_metrics['f1']:.4f}, Acc: {train_metrics['accuracy']:.4f}")

        # Validate
        val_metrics = evaluate(model, val_loader, criterion, config, logger, "val")
        history["val"].append(val_metrics)

        logger.info(f"Val - Loss: {val_metrics['loss']:.4f}, F1: {val_metrics['f1']:.4f}, Acc: {val_metrics['accuracy']:.4f}")
        logger.info(f"Epoch time: {time.time() - epoch_start:.1f}s")

        # Early stopping
        if (val_metrics["f1"] - best_f1) > config.EARLY_STOPPING_MIN_DELTA:
            best_f1 = val_metrics["f1"]
            patience = 0
            model.save_pretrained(config.CHECKPOINT_DIR)
            logger.info(f"✓ Best model saved (F1: {best_f1:.4f})")
        else:
            patience += 1
            logger.info(f"Patience: {patience}/{config.EARLY_STOPPING_PATIENCE}")

        if patience >= config.EARLY_STOPPING_PATIENCE:
            logger.info("\nEarly stopping triggered")
            break

    # Load best model
    logger.info("\n" + "=" * 70)
    logger.info("LOADING BEST MODEL")
    logger.info("=" * 70)
    model = PeftModel.from_pretrained(model.base_model.model, config.CHECKPOINT_DIR).to(config.DEVICE)

    # Test evaluation
    logger.info("\n" + "=" * 70)
    logger.info("TEST EVALUATION")
    logger.info("=" * 70)
    test_metrics = evaluate(model, test_loader, criterion, config, logger, "test")
    preds, labels = test_metrics["predictions"], test_metrics["labels"]
    history["test"] = {k: v for k, v in test_metrics.items() if k not in ["predictions", "labels"]}

    logger.info(f"\nTest - Loss: {test_metrics['loss']:.4f}")
    logger.info(f"Test - Accuracy: {test_metrics['accuracy']:.4f}")
    logger.info(f"Test - F1: {test_metrics['f1']:.4f}")
    logger.info(f"Test - Precision: {test_metrics['precision']:.4f}")
    logger.info(f"Test - Recall: {test_metrics['recall']:.4f}")

    # Language-wise F1 analysis
    try:
        test_data = torch.load(os.path.join(config.DATA_PATH, "test_tokenized_graphcodebert-base.pt"), map_location="cpu")
        if "language" in test_data:
            import pandas as pd
            languages = test_data["language"].tolist()
            df = pd.DataFrame({"lang": languages, "pred": preds, "label": labels})
            per_lang = []
            for lang, group in df.groupby("lang"):
                f1 = f1_score(group["label"], group["pred"], average="binary", zero_division=0)
                acc = accuracy_score(group["label"], group["pred"])
                per_lang.append({"language": lang, "f1": f1, "accuracy": acc, "count": len(group)})
            logger.info("\n📊 Language-wise F1 Scores:")
            for row in per_lang:
                logger.info(f"  {row['language']:<10s} → F1={row['f1']:.4f}, Acc={row['accuracy']:.4f}, N={row['count']}")
            with open(os.path.join(config.METRICS_DIR, "language_wise_f1.json"), "w") as f:
                json.dump(per_lang, f, indent=2)
            logger.info("✓ Saved language-wise metrics to metrics_graphcodebert/language_wise_f1.json")
        else:
            logger.info("Language field not found — skipping per-language metrics.")
    except Exception as e:
        logger.warning(f"Language-wise F1 logging skipped: {e}")

    # Save final model
    model.save_pretrained(config.FINAL_MODEL_DIR)
    logger.info(f"\n✓ Final model: {config.FINAL_MODEL_DIR}")

    # Merge LoRA adapters
    logger.info("\n" + "=" * 70)
    logger.info("MERGING LORA ADAPTERS")
    logger.info("=" * 70)
    try:
        from transformers import AutoModelForSequenceClassification
        base_model = AutoModelForSequenceClassification.from_pretrained(config.MODEL_NAME, num_labels=config.NUM_LABELS)
        merged_model = PeftModel.from_pretrained(base_model, config.FINAL_MODEL_DIR)
        merged_model = merged_model.merge_and_unload()

        os.makedirs(config.MERGED_MODEL_DIR, exist_ok=True)
        merged_model.save_pretrained(config.MERGED_MODEL_DIR)

        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(config.MODEL_NAME)
        tokenizer.save_pretrained(config.MERGED_MODEL_DIR)

        logger.info(f"✓ Merged model: {config.MERGED_MODEL_DIR}")
    except Exception as e:
        logger.warning(f"Merge failed: {e}")

    # Save metrics
    metrics_path = os.path.join(config.METRICS_DIR, "results.json")
    with open(metrics_path, "w") as f:
        json.dump(history, f, indent=2, default=str)
    logger.info(f"✓ Metrics: {metrics_path}")

    # Save run metadata with reproducibility info
    metadata = {
        "run_id": run_id,
        "run_hash": run_hash,
        "seed": SEED,
        "timestamp": datetime.now().isoformat(),
        "model": config.MODEL_NAME,
        "lora_config": {
            "r": config.LORA_R,
            "alpha": config.LORA_ALPHA,
            "dropout": config.LORA_DROPOUT,
            "target_modules": config.LORA_TARGET_MODULES
        },
        "training": {
            "epochs": config.EPOCHS,
            "batch_size": config.TRAIN_BATCH_SIZE,
            "learning_rate": config.LEARNING_RATE,
            "weight_decay": config.WEIGHT_DECAY,
            "gradient_accumulation": config.GRADIENT_ACCUMULATION_STEPS
        },
        "results": {
            "best_val_f1": float(best_f1),
            "test_f1": float(test_metrics['f1']),
            "test_accuracy": float(test_metrics['accuracy']),
            "test_precision": float(test_metrics['precision']),
            "test_recall": float(test_metrics['recall'])
        },
        "device": str(config.DEVICE),
        "precision": "BFloat16" if config.PRECISION_DTYPE == torch.bfloat16 else "Float16"
    }

    metadata_path = os.path.join(config.METRICS_DIR, "run_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"✓ Run metadata: {metadata_path}")

    # Optional: Upload to W&B or MLflow
    try:
        # Try Weights & Biases
        import wandb
        if wandb.run is not None:
            wandb.log(metadata["results"])
            wandb.log({"run_hash": run_hash})
            logger.info("✓ Metrics logged to Weights & Biases")
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"W&B logging skipped: {e}")

    try:
        # Try MLflow
        import mlflow
        if mlflow.active_run():
            mlflow.log_metrics(metadata["results"])
            mlflow.log_params({
                "run_hash": run_hash,
                "model": config.MODEL_NAME,
                "lora_r": config.LORA_R
            })
            logger.info("✓ Metrics logged to MLflow")
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"MLflow logging skipped: {e}")

    # Classification report
    cm = confusion_matrix(labels, preds)
    logger.info("\nConfusion Matrix:")
    logger.info(f"  TN={cm[0][0]}, FP={cm[0][1]}")
    logger.info(f"  FN={cm[1][0]}, TP={cm[1][1]}")

    report = classification_report(labels, preds, target_names=["Secure", "Vulnerable"])
    logger.info("\n" + report)

    # Make results visible in Kaggle Outputs
    os.system("cp -r /kaggle/working/metrics_graphcodebert /kaggle/working/metrics_output_graphcodebert || true")
    os.system("cp -r /kaggle/working/checkpoints_graphcodebert /kaggle/working/checkpoints_output_graphcodebert || true")
    os.system("cp -r /kaggle/working/graphcodebert_lora_merged /kaggle/working/graphcodebert_lora_merged || true")
    logger.info("✓ Copied outputs to visible Kaggle directories")

    # Export Trainer-compatible format for HuggingFace integration
    try:
        from transformers import TrainingArguments, AutoModelForSequenceClassification

        trainer_export_dir = f"{config.OUTPUT_DIR}/graphcodebert_trainer_export"
        os.makedirs(trainer_export_dir, exist_ok=True)

        # Save model in Trainer format
        merged_model = AutoModelForSequenceClassification.from_pretrained(config.MERGED_MODEL_DIR)
        merged_model.save_pretrained(trainer_export_dir)

        # Save tokenizer
        tokenizer = AutoTokenizer.from_pretrained(config.MODEL_NAME)
        tokenizer.save_pretrained(trainer_export_dir)

        # Save training arguments template
        training_args_dict = {
            "output_dir": trainer_export_dir,
            "num_train_epochs": config.EPOCHS,
            "per_device_train_batch_size": config.TRAIN_BATCH_SIZE,
            "per_device_eval_batch_size": config.EVAL_BATCH_SIZE,
            "learning_rate": config.LEARNING_RATE,
            "weight_decay": config.WEIGHT_DECAY,
            "warmup_ratio": config.WARMUP_RATIO,
            "fp16": not BF16_SUPPORTED,
            "bf16": BF16_SUPPORTED,
            "gradient_accumulation_steps": config.GRADIENT_ACCUMULATION_STEPS,
            "max_grad_norm": config.MAX_GRAD_NORM,
            "save_strategy": "epoch",
            "evaluation_strategy": "epoch",
            "load_best_model_at_end": True,
            "metric_for_best_model": "f1",
            "run_name": run_id
        }

        with open(os.path.join(trainer_export_dir, "training_args.json"), "w") as f:
            json.dump(training_args_dict, f, indent=2)

        logger.info(f"✓ Trainer-compatible export: {trainer_export_dir}")
        logger.info("  → Use with: from transformers import Trainer, AutoModelForSequenceClassification")
    except Exception as e:
        logger.warning(f"Trainer export skipped: {e}")

    # Hugging Face Hub Upload (Optional)
    try:
        from huggingface_hub import login
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        # Authenticate using environment variable (secure)
        HF_TOKEN = os.getenv("HF_TOKEN", None)
        if not HF_TOKEN:
            logger.warning("⚠️ HF_TOKEN not found — skipping Hugging Face upload.")
            raise ValueError("HF_TOKEN environment variable not set")

        login(token=HF_TOKEN)
        logger.info("✓ Logged into Hugging Face Hub via environment variable.")

        repo_id = "urva-gandhi/codeGuardian-GraphCodeBERT"
        model_dir = config.MERGED_MODEL_DIR

        logger.info(f"\n🚀 Uploading merged model to Hugging Face Hub → {repo_id}")
        model_hf = AutoModelForSequenceClassification.from_pretrained(model_dir)
        tokenizer_hf = AutoTokenizer.from_pretrained(model_dir)

        model_hf.push_to_hub(repo_id, commit_message="Upload CodeGuardian GraphCodeBERT-LoRA v1")
        tokenizer_hf.push_to_hub(repo_id)

        logger.info("✅ Model successfully pushed to Hugging Face Hub!")
        logger.info("🔗 https://huggingface.co/urva-gandhi/codeGuardian-GraphCodeBERT")
    except Exception as e:
        logger.warning(f"HF Hub upload skipped: {e}")

    # Cleanup
    del model
    torch.cuda.empty_cache()
    gc.collect()

    total_time = time.time() - start_time
    logger.info("\n" + "=" * 70)
    logger.info("TRAINING COMPLETE")
    logger.info("=" * 70)
    logger.info(f"✓ Best Val F1: {best_f1:.4f}")
    logger.info(f"✓ Test F1: {test_metrics['f1']:.4f}")
    logger.info(f"✓ Total runtime: {total_time/60:.2f} mins")

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Fine-tune GraphCodeBERT with LoRA")
    parser.add_argument("--epochs", type=int, default=3, help="Number of epochs")
    parser.add_argument("--batch_size", type=int, default=4, help="Training batch size")
    parser.add_argument("--lr", type=float, default=3e-5, help="Learning rate")
    args = parser.parse_args()

    config = Config()
    config.EPOCHS = args.epochs
    config.TRAIN_BATCH_SIZE = args.batch_size
    config.LEARNING_RATE = args.lr

    logger = setup_logging(config.LOG_DIR)

    try:
        train(config, logger)
    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()
