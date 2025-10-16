# type: ignore

"""
Kaggle-Ready GraphCodeBERT Fine-Tuning Script with LoRA (Optimized)
====================================================================

This script fine-tunes ONLY the final classification layer of GraphCodeBERT for
code vulnerability detection using LoRA/PEFT on Kaggle's free GPU (T4).

Optimizations:
- BF16 mixed precision for better numerical stability
- torch.compile for faster execution
- Gradient accumulation for effective larger batch size
- Linear warmup scheduler
- Persistent workers and prefetch in DataLoader
- Expanded LoRA targets (classifier + last encoder layer)
- TF32 and cuDNN benchmarking enabled

Author: CodeGuardian Team
Date: October 2025
"""

import os
import gc
import json
import time
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from torch.cuda.amp import autocast, GradScaler
from transformers import RobertaModel, RobertaConfig, get_linear_schedule_with_warmup
from peft import LoraConfig, get_peft_model, TaskType
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from tqdm import tqdm
import warnings

warnings.filterwarnings("ignore")

# Enable TF32 for faster matmul on Ampere GPUs (T4 compatible)
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.benchmark = True

# ============================================================================
# CONFIGURATION
# ============================================================================


class Config:
    """Configuration for GraphCodeBERT fine-tuning"""

    # Model settings
    MODEL_NAME = "microsoft/graphcodebert-base"
    MODEL_CHOICE = "graphcodebert"
    NUM_LABELS = 2

    # Kaggle paths
    DATA_PATH = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/graphcodebert"
    TRAIN_FILE = "train_tokenized_graphcodebert.pt"
    VAL_FILE = "val_tokenized_graphcodebert.pt"
    TEST_FILE = "test_tokenized_graphcodebert.pt"

    # Output paths
    CHECKPOINT_DIR = "/kaggle/working/checkpoints"
    MODEL_SAVE_PATH = f"{CHECKPOINT_DIR}/graphcodebert_final_layer.pt"
    METRICS_SAVE_PATH = f"{CHECKPOINT_DIR}/graphcodebert_eval_metrics.json"

    # Training hyperparameters
    EPOCHS = 3
    TRAIN_BATCH_SIZE = 64
    EVAL_BATCH_SIZE = 128
    LEARNING_RATE = 2e-3
    WEIGHT_DECAY = 0.01
    MAX_GRAD_NORM = 1.0
    WARMUP_STEPS = 100
    GRADIENT_ACCUMULATION_STEPS = 2

    # LoRA configuration (classifier + last encoder layer)
    LORA_R = 8
    LORA_ALPHA = 16
    LORA_DROPOUT = 0.1
    ENABLE_LAYER_NORM_TUNING = False

    # Device and precision
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    USE_BF16 = True  # BFloat16 for better stability

    # Monitoring
    LOG_INTERVAL = 50
    SAVE_BEST_MODEL = True


# ============================================================================
# MODEL DEFINITION
# ============================================================================


class GraphCodeBERTForVulnerabilityDetection(nn.Module):
    """GraphCodeBERT model with classification head for vulnerability detection"""

    def __init__(self, model_name: str, num_labels: int = 2):
        super().__init__()
        self.config = RobertaConfig.from_pretrained(model_name)
        self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)

        # Classification head (this is what we'll train)
        self.classifier = nn.Sequential(
            nn.Dropout(0.1), nn.Linear(self.config.hidden_size, num_labels)
        )

        # Freeze the backbone (RoBERTa encoder)
        for param in self.roberta.parameters():
            param.requires_grad = False

    def forward(self, input_ids, attention_mask):
        outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs.pooler_output  # [CLS] token representation
        logits = self.classifier(pooled_output)
        return logits


# ============================================================================
# DATA LOADING
# ============================================================================


def load_tokenized_dataset(file_path: str, config: Config):
    """Load pre-tokenized dataset from .pt file"""
    print(f"Loading dataset from: {file_path}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    data = torch.load(file_path, map_location="cpu")

    # Extract tensors
    input_ids = data["input_ids"]
    attention_mask = data["attention_mask"]
    labels = data["labels"]

    print(f"✓ Loaded {len(input_ids)} samples")
    print(f"  - Input shape: {input_ids.shape}")
    print(f"  - Labels distribution: {torch.bincount(labels)}")

    # Create TensorDataset
    dataset = TensorDataset(input_ids, attention_mask, labels)
    return dataset


def create_dataloaders(config: Config):
    """Create train, validation, and test dataloaders"""
    print("\n" + "=" * 70)
    print("LOADING DATASETS")
    print("=" * 70)

    # Load datasets
    train_dataset = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, config.TRAIN_FILE), config
    )
    val_dataset = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, config.VAL_FILE), config
    )
    test_dataset = load_tokenized_dataset(
        os.path.join(config.DATA_PATH, config.TEST_FILE), config
    )

    # Create dataloaders with persistent workers and prefetch
    train_loader = DataLoader(
        train_dataset,
        batch_size=config.TRAIN_BATCH_SIZE,
        shuffle=True,
        num_workers=2,
        pin_memory=True,
        persistent_workers=True,
        prefetch_factor=2,
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=config.EVAL_BATCH_SIZE,
        shuffle=False,
        num_workers=2,
        pin_memory=True,
        persistent_workers=True,
        prefetch_factor=2,
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=config.EVAL_BATCH_SIZE,
        shuffle=False,
        num_workers=2,
        pin_memory=True,
        persistent_workers=True,
        prefetch_factor=2,
    )

    print(f"\n✓ DataLoaders created successfully")
    print(f"  - Train batches: {len(train_loader)}")
    print(f"  - Val batches: {len(val_loader)}")
    print(f"  - Test batches: {len(test_loader)}")

    return train_loader, val_loader, test_loader


# ============================================================================
# MODEL INITIALIZATION
# ============================================================================


def initialize_model(config: Config):
    """Initialize model with LoRA on final classification layer only"""
    print("\n" + "=" * 70)
    print("INITIALIZING MODEL")
    print("=" * 70)

    # Create base model
    model = GraphCodeBERTForVulnerabilityDetection(
        model_name=config.MODEL_NAME, num_labels=config.NUM_LABELS
    )

    print(f"✓ Base model loaded: {config.MODEL_NAME}")

    # Count parameters before LoRA
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params_before = sum(
        p.numel() for p in model.parameters() if p.requires_grad
    )

    print(f"\n📊 Parameters before LoRA:")
    print(f"  - Total: {total_params:,}")
    print(
        f"  - Trainable: {trainable_params_before:,} ({100*trainable_params_before/total_params:.2f}%)"
    )

    # Apply LoRA to classifier and last encoder layer for better expressiveness
    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=config.LORA_R,
        lora_alpha=config.LORA_ALPHA,
        lora_dropout=config.LORA_DROPOUT,
        target_modules=["classifier.1", "roberta.encoder.layer.11.output.dense"],
        bias="none",
        inference_mode=False,
    )

    # Wrap model with PEFT
    model = get_peft_model(model, lora_config)

    # Optionally unfreeze LayerNorm in last encoder block
    if config.ENABLE_LAYER_NORM_TUNING:
        for param in model.base_model.model.roberta.encoder.layer[
            11
        ].output.LayerNorm.parameters():
            param.requires_grad = True

    # Count parameters after LoRA
    trainable_params_after = sum(
        p.numel() for p in model.parameters() if p.requires_grad
    )

    print(f"\n✓ LoRA applied to final classification layer")
    print(f"  - LoRA rank (r): {config.LORA_R}")
    print(f"  - LoRA alpha: {config.LORA_ALPHA}")
    print(f"  - LoRA dropout: {config.LORA_DROPOUT}")

    print(f"\n📊 Parameters after LoRA:")
    print(
        f"  - Trainable: {trainable_params_after:,} ({100*trainable_params_after/total_params:.2f}%)"
    )
    print(f"  - Memory reduction: {100*(1-trainable_params_after/total_params):.2f}%")

    model = model.to(config.DEVICE)

    # Compile model for faster execution (PyTorch 2.0+)
    try:
        model = torch.compile(model)
        print("\n✓ Model compiled with torch.compile()")
    except Exception as e:
        print(f"\n⚠ torch.compile() not available: {e}")

    return model


# ============================================================================
# TRAINING UTILITIES
# ============================================================================


def calculate_metrics(predictions, labels):
    """Calculate evaluation metrics"""
    accuracy = accuracy_score(labels, predictions)
    f1 = f1_score(labels, predictions, average="binary", zero_division=0)
    precision = precision_score(labels, predictions, average="binary", zero_division=0)
    recall = recall_score(labels, predictions, average="binary", zero_division=0)

    return {"accuracy": accuracy, "f1": f1, "precision": precision, "recall": recall}


def train_epoch(
    model, train_loader, optimizer, scheduler, scaler, config: Config, epoch: int
):
    """Train for one epoch with gradient accumulation"""
    model.train()
    total_loss = 0
    all_predictions = []
    all_labels = []

    progress_bar = tqdm(
        train_loader, desc=f"Epoch {epoch}/{config.EPOCHS} [TRAIN]", ncols=100
    )

    criterion = nn.CrossEntropyLoss()
    accumulation_steps = config.GRADIENT_ACCUMULATION_STEPS

    for batch_idx, batch in enumerate(progress_bar):
        input_ids = batch[0].to(config.DEVICE)
        attention_mask = batch[1].to(config.DEVICE)
        labels = batch[2].to(config.DEVICE)

        # Forward pass with BF16
        if config.USE_BF16:
            with autocast(device_type="cuda", dtype=torch.bfloat16):
                logits = model(input_ids, attention_mask)
                loss = criterion(logits, labels)
                loss = loss / accumulation_steps  # Scale loss for accumulation

            # Backward pass with gradient scaling
            scaler.scale(loss).backward()

            # Update weights every accumulation_steps
            if (batch_idx + 1) % accumulation_steps == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.MAX_GRAD_NORM)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()
                optimizer.zero_grad()
        else:
            logits = model(input_ids, attention_mask)
            loss = criterion(logits, labels)
            loss = loss / accumulation_steps
            loss.backward()

            if (batch_idx + 1) % accumulation_steps == 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.MAX_GRAD_NORM)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

        # Track metrics
        total_loss += loss.item() * accumulation_steps
        predictions = torch.argmax(logits, dim=1).cpu().numpy()
        all_predictions.extend(predictions)
        all_labels.extend(labels.cpu().numpy())

        # Update progress bar
        if (batch_idx + 1) % config.LOG_INTERVAL == 0:
            avg_loss = total_loss / (batch_idx + 1)
            progress_bar.set_postfix(
                {"loss": f"{avg_loss:.4f}", "lr": f"{scheduler.get_last_lr()[0]:.2e}"}
            )

    # Calculate epoch metrics
    avg_loss = total_loss / len(train_loader)
    metrics = calculate_metrics(all_predictions, all_labels)
    metrics["loss"] = avg_loss

    return metrics


def evaluate(model, data_loader, config: Config, split_name: str):
    """Evaluate model on validation or test set"""
    model.eval()
    total_loss = 0
    all_predictions = []
    all_labels = []

    criterion = nn.CrossEntropyLoss()

    progress_bar = tqdm(data_loader, desc=f"{split_name.upper()}", ncols=100)

    with torch.no_grad():
        for batch in progress_bar:
            input_ids = batch[0].to(config.DEVICE)
            attention_mask = batch[1].to(config.DEVICE)
            labels = batch[2].to(config.DEVICE)

            # Forward pass with BF16
            if config.USE_BF16:
                with autocast(device_type="cuda", dtype=torch.bfloat16):
                    logits = model(input_ids, attention_mask)
                    loss = criterion(logits, labels)
            else:
                logits = model(input_ids, attention_mask)
                loss = criterion(logits, labels)

            # Track metrics
            total_loss += loss.item()
            predictions = torch.argmax(logits, dim=1).cpu().numpy()
            all_predictions.extend(predictions)
            all_labels.extend(labels.cpu().numpy())

    # Calculate metrics
    avg_loss = total_loss / len(data_loader)
    metrics = calculate_metrics(all_predictions, all_labels)
    metrics["loss"] = avg_loss

    return metrics


# ============================================================================
# MAIN TRAINING LOOP
# ============================================================================


def train(config: Config):
    """Main training function"""
    start_time = time.time()

    print("\n" + "=" * 70)
    print("CODEGUARDIAN - GRAPHCODEBERT FINE-TUNING WITH LORA (OPTIMIZED)")
    print("=" * 70)
    print(f"Device: {config.DEVICE}")
    print(f"Precision: BF16" if config.USE_BF16 else "FP32")
    print(f"Train Batch Size: {config.TRAIN_BATCH_SIZE}")
    print(f"Eval Batch Size: {config.EVAL_BATCH_SIZE}")
    print(f"Gradient Accumulation: {config.GRADIENT_ACCUMULATION_STEPS}x")
    print(
        f"Effective Batch Size: {config.TRAIN_BATCH_SIZE * config.GRADIENT_ACCUMULATION_STEPS}"
    )
    print(f"Learning Rate: {config.LEARNING_RATE}")
    print(f"Epochs: {config.EPOCHS}")

    if torch.cuda.is_available():
        print(f"\n🎮 GPU Info:")
        print(f"  - Name: {torch.cuda.get_device_name(0)}")
        print(
            f"  - Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB"
        )

    # Create checkpoint directory
    os.makedirs(config.CHECKPOINT_DIR, exist_ok=True)

    # Load data
    train_loader, val_loader, test_loader = create_dataloaders(config)

    # Initialize model
    model = initialize_model(config)

    # Setup optimizer
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=config.LEARNING_RATE, weight_decay=config.WEIGHT_DECAY
    )

    # Setup learning rate scheduler with warmup
    num_training_steps = (
        len(train_loader) * config.EPOCHS // config.GRADIENT_ACCUMULATION_STEPS
    )
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=config.WARMUP_STEPS,
        num_training_steps=num_training_steps,
    )

    # Setup gradient scaler for BF16
    scaler = GradScaler() if config.USE_BF16 else None

    # Training tracking
    best_f1 = 0.0
    training_history = {"train": [], "val": [], "test": None}

    print("\n" + "=" * 70)
    print("STARTING TRAINING")
    print("=" * 70)

    # Training loop
    epoch_times = []
    for epoch in range(1, config.EPOCHS + 1):
        epoch_start = time.time()

        print(f"\n{'='*70}")
        print(f"EPOCH {epoch}/{config.EPOCHS}")
        print(f"{'='*70}")

        # Train
        train_metrics = train_epoch(
            model, train_loader, optimizer, scheduler, scaler, config, epoch
        )
        training_history["train"].append(train_metrics)

        epoch_time = time.time() - epoch_start
        epoch_times.append(epoch_time)

        print(f"\n📊 Train Metrics:")
        print(f"  - Loss: {train_metrics['loss']:.4f}")
        print(f"  - Accuracy: {train_metrics['accuracy']:.4f}")
        print(f"  - F1-Score: {train_metrics['f1']:.4f}")
        print(f"  - Precision: {train_metrics['precision']:.4f}")
        print(f"  - Recall: {train_metrics['recall']:.4f}")

        # Validate
        val_metrics = evaluate(model, val_loader, config, "validation")
        training_history["val"].append(val_metrics)

        print(f"\n📊 Validation Metrics:")
        print(f"  - Loss: {val_metrics['loss']:.4f}")
        print(f"  - Accuracy: {val_metrics['accuracy']:.4f}")
        print(f"  - F1-Score: {val_metrics['f1']:.4f}")
        print(f"  - Precision: {val_metrics['precision']:.4f}")
        print(f"  - Recall: {val_metrics['recall']:.4f}")

        # Save best model
        if config.SAVE_BEST_MODEL and val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "best_f1": best_f1,
                    "config": config.__dict__,
                },
                config.MODEL_SAVE_PATH,
            )
            print(f"\n✓ Best model saved! (F1: {best_f1:.4f})")

    # Load best model for final evaluation
    if config.SAVE_BEST_MODEL:
        print(f"\n{'='*70}")
        print("LOADING BEST MODEL FOR FINAL EVALUATION")
        print(f"{'='*70}")
        checkpoint = torch.load(config.MODEL_SAVE_PATH)
        model.load_state_dict(checkpoint["model_state_dict"])
        print(
            f"✓ Loaded model from epoch {checkpoint['epoch']} (F1: {checkpoint['best_f1']:.4f})"
        )

    # Final test evaluation
    print(f"\n{'='*70}")
    print("FINAL TEST EVALUATION")
    print(f"{'='*70}")
    test_metrics = evaluate(model, test_loader, config, "test")
    training_history["test"] = test_metrics

    print(f"\n📊 Test Metrics:")
    print(f"  - Loss: {test_metrics['loss']:.4f}")
    print(f"  - Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"  - F1-Score: {test_metrics['f1']:.4f}")
    print(f"  - Precision: {test_metrics['precision']:.4f}")
    print(f"  - Recall: {test_metrics['recall']:.4f}")

    # Save metrics
    with open(config.METRICS_SAVE_PATH, "w") as f:
        json.dump(training_history, f, indent=2)
    print(f"\n✓ Metrics saved to: {config.METRICS_SAVE_PATH}")

    # Cleanup
    print(f"\n{'='*70}")
    print("CLEANING UP GPU MEMORY")
    print(f"{'='*70}")
    del model
    del optimizer
    if scaler:
        del scaler
    torch.cuda.empty_cache()
    gc.collect()
    print("✓ GPU memory cleaned")

    print(f"\n{'='*70}")
    print("TRAINING COMPLETE!")
    print(f"{'='*70}")
    print(f"✓ Best Validation F1: {best_f1:.4f}")
    print(f"✓ Test F1: {test_metrics['f1']:.4f}")
    print(f"✓ Model saved: {config.MODEL_SAVE_PATH}")
    print(f"✓ Metrics saved: {config.METRICS_SAVE_PATH}")

    # Training summary
    total_time = time.time() - start_time
    avg_epoch_time = sum(epoch_times) / len(epoch_times) if epoch_times else 0

    print(f"\n{'='*70}")
    print("TRAINING SUMMARY")
    print(f"{'='*70}")
    print(f"⏱  Total Runtime: {total_time/60:.2f} minutes ({total_time:.1f} seconds)")
    print(
        f"⏱  Avg Time per Epoch: {avg_epoch_time/60:.2f} minutes ({avg_epoch_time:.1f} seconds)"
    )

    if torch.cuda.is_available():
        memory_allocated = torch.cuda.memory_allocated(0) / 1e9
        memory_reserved = torch.cuda.memory_reserved(0) / 1e9
        print(f"💾 GPU Memory:")
        print(f"  - Allocated: {memory_allocated:.2f} GB")
        print(f"  - Reserved: {memory_reserved:.2f} GB")

    print(f"\n📊 Final Performance:")
    print(f"  - Best Val F1: {best_f1:.4f}")
    print(f"  - Test Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"  - Test F1: {test_metrics['f1']:.4f}")
    print(f"  - Test Precision: {test_metrics['precision']:.4f}")
    print(f"  - Test Recall: {test_metrics['recall']:.4f}")


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Initialize configuration
    config = Config()

    try:
        # Run training
        train(config)

    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback

        traceback.print_exc()

        # Cleanup on error
        torch.cuda.empty_cache()
        gc.collect()

        raise
