#!/usr/bin/env python3
# =============================================================
# codeGuardian LoRA Fine-tuning Pipeline (Production v3)
# Model: microsoft/graphcodebert-base
# Author: Urva Gandhi
# =============================================================
"""
Production-grade LoRA fine-tuning for GraphCodeBERT vulnerability detection.
Optimized for Kaggle Free GPU (T4/P100) with mixed precision and checkpoint resume.

Features:
- ✅ Automatic checkpoint resume (restartable training)
- ✅ Proper LoRA merge with base model
- ✅ HuggingFace Hub upload via CLI
- ✅ Full state persistence (optimizer, scheduler, epoch, best F1)
- ✅ PyTorch 2.0+ AMP API
- ✅ Mixed precision (BF16/FP16 auto-detect)
- ✅ Weighted cross-entropy + optional Focal Loss
- ✅ Early stopping on F1 score
- ✅ Gradient accumulation & checkpointing
- ✅ Live progress logging every 5%
- ✅ Enhanced LoRA (r=16, α=32, query+key+value)
"""

import os
import sys
import gc
import json
import time
import logging
import argparse
import hashlib
import subprocess
from typing import Dict, Tuple, Optional
from pathlib import Path
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from torch import amp
from transformers import AutoModel, AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
from peft import LoraConfig, get_peft_model, PeftModel, PeftConfig
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

    # LoRA (Enhanced for GraphCodeBERT)
    LORA_R = 16
    LORA_ALPHA = 32
    LORA_DROPOUT = 0.1
    LORA_TARGET_MODULES = ["query", "key", "value"]

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

    # HuggingFace
    HF_REPO_ID = "urva-gandhi/codeGuardian-GraphCodeBERT"

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

    logger = logging.getLogger("GraphCodeBERT_LoRA_v3")
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
# CHECKPOINT MANAGEMENT
# ============================================================================

def save_checkpoint(
    epoch: int, model, optimizer, scheduler, best_f1: float, 
    checkpoint_dir: str, logger: logging.Logger
) -> None:
    """Save training checkpoint"""
    os.makedirs(checkpoint_dir, exist_ok=True)
    
    checkpoint_path = os.path.join(checkpoint_dir, f"checkpoint_epoch_{epoch}.pt")
    
    checkpoint = {
        "epoch": epoch,
        "best_f1": best_f1,
        "optimizer_state": optimizer.state_dict(),
        "scheduler_state": scheduler.state_dict(),
    }
    
    # Save PEFT model separately
    model.save_pretrained(checkpoint_dir)
    
    # Save training state
    torch.save(checkpoint, checkpoint_path)
    logger.info(f"✓ Checkpoint saved: epoch {epoch}, F1={best_f1:.4f}")

def load_checkpoint(
    checkpoint_dir: str, model, optimizer, scheduler, config: Config, logger: logging.Logger
) -> Tuple[int, float]:
    """Load training checkpoint if exists"""
    
    if not os.path.exists(checkpoint_dir):
        logger.info("No checkpoint found - starting from scratch")
        return 0, 0.0
    
    # Find latest checkpoint
    checkpoints = [f for f in os.listdir(checkpoint_dir) if f.startswith("checkpoint_epoch_")]
    if not checkpoints:
        logger.info("No checkpoint found - starting from scratch")
        return 0, 0.0
    
    # Get latest epoch
    epochs = [int(f.split("_")[-1].replace(".pt", "")) for f in checkpoints]
    latest_epoch = max(epochs)
    checkpoint_path = os.path.join(checkpoint_dir, f"checkpoint_epoch_{latest_epoch}.pt")
    
    try:
        # Load PEFT model
        model = PeftModel.from_pretrained(model.base_model.model, checkpoint_dir).to(config.DEVICE)
        
        # Load training state
        checkpoint = torch.load(checkpoint_path, map_location=config.DEVICE)
        optimizer.load_state_dict(checkpoint["optimizer_state"])
        scheduler.load_state_dict(checkpoint["scheduler_state"])
        best_f1 = checkpoint["best_f1"]
        
        logger.info("=" * 70)
        logger.info("🔁 RESUMING FROM CHECKPOINT")
        logger.info("=" * 70)
        logger.info(f"✓ Loaded checkpoint: epoch {latest_epoch}, best F1={best_f1:.4f}")
        
        return latest_epoch, best_f1
    
    except Exception as e:
        logger.warning(f"Failed to load checkpoint: {e}")
        logger.info("Starting from scratch")
        return 0, 0.0

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

    # Clear memory after epoch
    torch.cuda.empty_cache()
    gc.collect()

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
# MODEL MERGING & UPLOAD
# ============================================================================

def merge_lora_model(config: Config, logger: logging.Logger) -> bool:
    """Merge LoRA adapters with base model properly"""
    logger.info("\n" + "=" * 70)
    logger.info("MERGING LORA ADAPTERS")
    logger.info("=" * 70)
    
    try:
        # Load PEFT config to get base model name
        peft_config = PeftConfig.from_pretrained(config.FINAL_MODEL_DIR)
        base_model_name = peft_config.base_model_name_or_path
        
        logger.info(f"Base model: {base_model_name}")
        logger.info(f"Loading adapters from: {config.FINAL_MODEL_DIR}")
        
        # Load base model (use custom classifier)
        base_model = GraphCodeBERTClassifier(base_model_name, config.NUM_LABELS)
        
        # Load and merge LoRA weights
        model_with_adapters = PeftModel.from_pretrained(base_model, config.FINAL_MODEL_DIR)
        merged_model = model_with_adapters.merge_and_unload()
        
        # Save merged model
        os.makedirs(config.MERGED_MODEL_DIR, exist_ok=True)
        
        # Save model state dict directly
        torch.save(merged_model.state_dict(), os.path.join(config.MERGED_MODEL_DIR, "pytorch_model.bin"))
        
        # Save config
        merged_model.roberta.config.save_pretrained(config.MERGED_MODEL_DIR)
        
        # Save tokenizer
        tokenizer = AutoTokenizer.from_pretrained(base_model_name)
        tokenizer.save_pretrained(config.MERGED_MODEL_DIR)
        
        # Save model config for HF compatibility
        model_config = {
            "architectures": ["GraphCodeBERTClassifier"],
            "model_type": "roberta",
            "num_labels": config.NUM_LABELS,
            "base_model": base_model_name,
        }
        with open(os.path.join(config.MERGED_MODEL_DIR, "config.json"), "w") as f:
            json.dump(model_config, f, indent=2)
        
        logger.info(f"✓ Merged model saved: {config.MERGED_MODEL_DIR}")
        logger.info(f"✓ Tokenizer saved: {config.MERGED_MODEL_DIR}")
        
        # Verify saved files
        required_files = ["pytorch_model.bin", "config.json", "tokenizer.json", "tokenizer_config.json"]
        missing_files = [f for f in required_files if not os.path.exists(os.path.join(config.MERGED_MODEL_DIR, f))]
        
        if missing_files:
            logger.warning(f"⚠️ Missing files: {missing_files}")
            return False
        
        logger.info("✓ All required files present")
        return True
        
    except Exception as e:
        logger.error(f"❌ Merge failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def upload_to_huggingface(config: Config, logger: logging.Logger, metadata: Dict) -> bool:
    """Upload merged model to HuggingFace Hub using CLI"""
    logger.info("\n" + "=" * 70)
    logger.info("UPLOADING TO HUGGINGFACE HUB")
    logger.info("=" * 70)
    
    try:
        # Check if HF_TOKEN is set
        hf_token = os.getenv("HF_TOKEN")
        if not hf_token:
            logger.warning("⚠️ HF_TOKEN not found - skipping upload")
            return False
        
        # Create README.md with model card
        readme_content = f"""---
language: code
tags:
- code
- vulnerability-detection
- graphcodebert
- lora
license: mit
datasets:
- custom
metrics:
- f1
- accuracy
---

# CodeGuardian - GraphCodeBERT LoRA

Fine-tuned GraphCodeBERT model for vulnerability detection using LoRA adapters.

## Model Details

- **Base Model**: {config.MODEL_NAME}
- **Task**: Binary Classification (Secure vs Vulnerable)
- **LoRA Config**: r={config.LORA_R}, α={config.LORA_ALPHA}, dropout={config.LORA_DROPOUT}
- **Target Modules**: {config.LORA_TARGET_MODULES}

## Performance

- **Test F1 Score**: {metadata['results']['test_f1']:.4f}
- **Test Accuracy**: {metadata['results']['test_accuracy']:.4f}
- **Test Precision**: {metadata['results']['test_precision']:.4f}
- **Test Recall**: {metadata['results']['test_recall']:.4f}

## Training Details

- **Epochs**: {config.EPOCHS}
- **Batch Size**: {config.TRAIN_BATCH_SIZE} (effective: {config.TRAIN_BATCH_SIZE * config.GRADIENT_ACCUMULATION_STEPS})
- **Learning Rate**: {config.LEARNING_RATE}
- **Weight Decay**: {config.WEIGHT_DECAY}
- **Precision**: {metadata['precision']}
- **Random Seed**: {SEED}
- **Run Hash**: {metadata['run_hash']}

## Usage

```python
from transformers import AutoTokenizer, AutoModel
import torch

tokenizer = AutoTokenizer.from_pretrained("{config.HF_REPO_ID}")
model = AutoModel.from_pretrained("{config.HF_REPO_ID}")

# Your code here
```

## Citation

```bibtex
@software{{codeguardian_graphcodebert,
  author = {{Urva Gandhi}},
  title = {{CodeGuardian - GraphCodeBERT Vulnerability Detection}},
  year = {{2025}},
  url = {{https://huggingface.co/{config.HF_REPO_ID}}}
}}
```
"""
        
        readme_path = os.path.join(config.MERGED_MODEL_DIR, "README.md")
        with open(readme_path, "w") as f:
            f.write(readme_content)
        
        logger.info("✓ Created model card (README.md)")
        
        # Upload using HuggingFace CLI
        logger.info(f"🚀 Uploading to {config.HF_REPO_ID}...")
        
        upload_cmd = [
            "huggingface-cli", "upload",
            config.HF_REPO_ID,
            config.MERGED_MODEL_DIR,
            "--repo-type", "model",
            "--commit-message", f"Upload GraphCodeBERT-LoRA model (F1: {metadata['results']['test_f1']:.4f})"
        ]
        
        result = subprocess.run(upload_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✅ Model successfully uploaded to HuggingFace Hub!")
            logger.info(f"🔗 https://huggingface.co/{config.HF_REPO_ID}")
            return True
        else:
            logger.error(f"❌ Upload failed: {result.stderr}")
            return False
            
    except FileNotFoundError:
        logger.error("❌ huggingface-cli not found. Install with: pip install huggingface_hub[cli]")
        return False
    except Exception as e:
        logger.error(f"❌ Upload failed: {e}")
        import traceback
        traceback.print_exc()
        return False

# ============================================================================
# MAIN TRAINING LOOP
# ============================================================================

def train(config: Config, logger: logging.Logger):
    """Main training function with checkpoint resume"""
    start_time = time.time()

    # Generate reproducibility hash
    run_hash = generate_run_hash(config)
    run_id = f"graphcodebert_lora_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{run_hash}"

    logger.info("=" * 70)
    logger.info("GRAPHCODEBERT LORA FINE-TUNING (PRODUCTION V3)")
    logger.info("=" * 70)
    logger.info(f"Run ID: {run_id}")
    logger.info(f"Reproducibility Hash: {run_hash}")
    logger.info(f"Random Seed: {SEED}")
    logger.info(f"Device: {config.DEVICE}")
    logger.info(f"Precision: {'BFloat16' if config.PRECISION_DTYPE == torch.bfloat16 else 'Float16'}")
    logger.info(f"Batch size: {config.TRAIN_BATCH_SIZE} (effective: {config.TRAIN_BATCH_SIZE * config.GRADIENT_ACCUMULATION_STEPS})")
    logger.info(f"Learning rate: {config.LEARNING_RATE}")
    logger.info(f"Epochs: {config.EPOCHS}")
    logger.info(f"LoRA: r={config.LORA_R}, α={config.LORA_ALPHA} (Enhanced)")

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

    # Try to resume from checkpoint
    start_epoch, best_f1 = load_checkpoint(config.CHECKPOINT_DIR, model, optimizer, scheduler, config, logger)

    logger.info(f"\nTraining steps: {num_training_steps}")
    logger.info(f"Warmup steps: {warmup_steps}")

    # Training loop
    patience = 0
    history = {"train": [], "val": [], "test": None}

    logger.info("\n" + "=" * 70)
    logger.info("STARTING TRAINING")
    logger.info("=" * 70)

    for epoch in range(start_epoch + 1, config.EPOCHS + 1):
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

        # Early stopping & checkpoint
        if (val_metrics["f1"] - best_f1) > config.EARLY_STOPPING_MIN_DELTA:
            best_f1 = val_metrics["f1"]
            patience = 0
            
            # Save checkpoint
            save_checkpoint(epoch, model, optimizer, scheduler, best_f1, config.CHECKPOINT_DIR, logger)
            
            # Also save as final model
            model.save_pretrained(config.FINAL_MODEL_DIR)
            logger.info(f"✓ Best model saved (F1: {best_f1:.4f})")
        else:
            patience += 1
            logger.info(f"Patience: {patience}/{config.EARLY_STOPPING_PATIENCE}")

        if patience >= config.EARLY_STOPPING_PATIENCE:
            logger.info("\nEarly stopping triggered")
            break

    # Load best model for testing
    logger.info("\n" + "=" * 70)
    logger.info("LOADING BEST MODEL")
    logger.info("=" * 70)
    model = PeftModel.from_pretrained(model.base_model.model, config.FINAL_MODEL_DIR).to(config.DEVICE)

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

    # Classification report
    cm = confusion_matrix(labels, preds)
    logger.info("\nConfusion Matrix:")
    logger.info(f"  TN={cm[0][0]}, FP={cm[0][1]}")
    logger.info(f"  FN={cm[1][0]}, TP={cm[1][1]}")

    report = classification_report(labels, preds, target_names=["Secure", "Vulnerable"])
    logger.info("\n" + report)

    # Language-wise F1 analysis
    try:
        test_data = torch.load(os.path.join(config.DATA_PATH, "test_tokenized_graphcodebert-base.pt"), map_location="cpu")
        if "language" in test_data:
            import pandas as pd
            languages = test_data["language"].tolist()
            df = pd.DataFrame({"lang": languages, "pred": preds, "label": labels})
            per_lang = []
            for lang, group in df.groupby("lang"):
                f1_lang = f1_score(group["label"], group["pred"], average="binary", zero_division=0)
                acc = accuracy_score(group["label"], group["pred"])
                per_lang.append({"language": lang, "f1": f1_lang, "accuracy": acc, "count": len(group)})
            logger.info("\n📊 Language-wise F1 Scores:")
            for row in per_lang:
                logger.info(f"  {row['language']:<10s} → F1={row['f1']:.4f}, Acc={row['accuracy']:.4f}, N={row['count']}")
            with open(os.path.join(config.METRICS_DIR, "language_wise_f1.json"), "w") as f:
                json.dump(per_lang, f, indent=2)
            logger.info("✓ Saved language-wise metrics")
    except Exception as e:
        logger.warning(f"Language-wise F1 logging skipped: {e}")

    # Save metrics
    metrics_path = os.path.join(config.METRICS_DIR, "results.json")
    with open(metrics_path, "w") as f:
        json.dump(history, f, indent=2, default=str)
    logger.info(f"✓ Metrics: {metrics_path}")

    # Save run metadata
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

    # Merge LoRA adapters
    merge_success = merge_lora_model(config, logger)
    
    if merge_success:
        # Upload to HuggingFace Hub
        upload_to_huggingface(config, logger, metadata)
    else:
        logger.warning("⚠️ Skipping HuggingFace upload due to merge failure")

    # Make results visible in Kaggle Outputs
    os.system("cp -r /kaggle/working/metrics_graphcodebert /kaggle/working/metrics_output_graphcodebert || true")
    os.system("cp -r /kaggle/working/checkpoints_graphcodebert /kaggle/working/checkpoints_output_graphcodebert || true")
    os.system("cp -r /kaggle/working/graphcodebert_lora_merged /kaggle/working/graphcodebert_lora_merged_output || true")
    logger.info("✓ Copied outputs to visible Kaggle directories")

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
    parser = argparse.ArgumentParser(description="Fine-tune GraphCodeBERT with LoRA (Production v3)")
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
