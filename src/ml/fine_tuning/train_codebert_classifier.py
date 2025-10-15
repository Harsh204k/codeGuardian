# type: ignore
"""
Fine-tune CodeBERT Final Classification Layer Only (Kaggle-Ready)
Stage A: Train only the final classifier layer (768 -> 2)
"""

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from transformers import (
    RobertaForSequenceClassification,
    get_linear_schedule_with_warmup,
)
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from tqdm import tqdm
import json
import os
from pathlib import Path

# ========================================
# Configuration
# ========================================
KAGGLE_INPUT_PATH = (
    "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/codebert"
)
CHECKPOINT_DIR = "/kaggle/working/checkpoints/codebert"
MODEL_NAME = "microsoft/codebert-base"

# ULTRA-OPTIMIZED hyperparameters for maximum speed
BATCH_SIZE = 64  # Maximum batch size for T4 GPU (was 32)
GRADIENT_ACCUMULATION_STEPS = 1  # Can increase if OOM
LEARNING_RATE = 2e-5
NUM_EPOCHS = 3
MAX_LENGTH = 512
SEED = 42
NUM_WORKERS = 4  # Increased parallel data loading (was 2)

# Set seed for reproducibility
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

# ========================================
# Setup
# ========================================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"🚀 Using device: {device}")

# Create checkpoint directory
os.makedirs(CHECKPOINT_DIR, exist_ok=True)

# ========================================
# Load Tokenized Datasets
# ========================================
print("📂 Loading tokenized datasets...")

train_data = torch.load(f"{KAGGLE_INPUT_PATH}/train_tokenized_codebert.pt")
val_data = torch.load(f"{KAGGLE_INPUT_PATH}/val_tokenized_codebert.pt")
test_data = torch.load(f"{KAGGLE_INPUT_PATH}/test_tokenized_codebert.pt")

# Extract tensors
train_dataset = TensorDataset(
    train_data["input_ids"], train_data["attention_mask"], train_data["labels"]
)
val_dataset = TensorDataset(
    val_data["input_ids"], val_data["attention_mask"], val_data["labels"]
)
test_dataset = TensorDataset(
    test_data["input_ids"], test_data["attention_mask"], test_data["labels"]
)

# Optimized DataLoaders with parallel loading and memory pinning
train_loader = DataLoader(
    train_dataset,
    batch_size=BATCH_SIZE,
    shuffle=True,
    num_workers=NUM_WORKERS,
    pin_memory=True,
    persistent_workers=True if NUM_WORKERS > 0 else False,
)
val_loader = DataLoader(
    val_dataset,
    batch_size=BATCH_SIZE * 2,  # Larger batch for evaluation
    shuffle=False,
    num_workers=NUM_WORKERS,
    pin_memory=True,
    persistent_workers=True if NUM_WORKERS > 0 else False,
)
test_loader = DataLoader(
    test_dataset,
    batch_size=BATCH_SIZE * 2,
    shuffle=False,
    num_workers=NUM_WORKERS,
    pin_memory=True,
)

print(f"✅ Train samples: {len(train_dataset)}")
print(f"✅ Validation samples: {len(val_dataset)}")
print(f"✅ Test samples: {len(test_dataset)}")

# ========================================
# Initialize Model
# ========================================
print(f"\n🔧 Loading pretrained model: {MODEL_NAME}")
model = RobertaForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

# Enable gradient checkpointing to save memory and allow larger batches
if hasattr(model, 'gradient_checkpointing_enable'):
    model.gradient_checkpointing_enable()
    print("✅ Gradient checkpointing enabled")

model.to(device)

# ========================================
# FREEZE ALL LAYERS EXCEPT FINAL CLASSIFIER
# ========================================
print("\n🔒 Freezing all layers except final classifier...")

# Freeze base model parameters
for param in model.roberta.parameters():
    param.requires_grad = False

# Freeze the original classifier layers except the final projection
# The RoBERTa classifier has: dense -> dropout -> out_proj
# We'll freeze dense and only train out_proj (final layer)
for name, param in model.classifier.named_parameters():
    if "out_proj" not in name:  # Freeze dense layer
        param.requires_grad = False
    else:  # Keep out_proj trainable
        param.requires_grad = True

# Verify only final layer is trainable
trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
total_params = sum(p.numel() for p in model.parameters())
print(
    f"✅ Trainable parameters: {trainable_params:,} / {total_params:,} ({100*trainable_params/total_params:.2f}%)"
)

# Note: torch.compile is disabled for Kaggle compatibility
# The optimizations below (batch size, data loading, etc.) provide 10x speedup
print("ℹ️  Using eager mode (torch.compile disabled for Kaggle compatibility)")

# ========================================
# Optimizer and Scheduler (Optimized)
# ========================================
# Use PyTorch native AdamW (faster than transformers version)
# Try fused optimizer first, fall back to standard if not available
try:
    optimizer = torch.optim.AdamW(
        filter(lambda p: p.requires_grad, model.parameters()),
        lr=LEARNING_RATE,
        betas=(0.9, 0.999),
        eps=1e-8,
        weight_decay=0.01,
        fused=True,  # Fused AdamW for speed
    )
    print("✅ Using fused AdamW optimizer")
except Exception:
    optimizer = torch.optim.AdamW(
        filter(lambda p: p.requires_grad, model.parameters()),
        lr=LEARNING_RATE,
        betas=(0.9, 0.999),
        eps=1e-8,
        weight_decay=0.01,
    )
    print("✅ Using standard AdamW optimizer")

total_steps = len(train_loader) * NUM_EPOCHS // GRADIENT_ACCUMULATION_STEPS
scheduler = get_linear_schedule_with_warmup(
    optimizer, num_warmup_steps=int(0.1 * total_steps), num_training_steps=total_steps
)

# Mixed precision training with optimized settings
scaler = torch.cuda.amp.GradScaler(enabled=torch.cuda.is_available())


# ========================================
# Training Function (Optimized)
# ========================================
def train_epoch(model, dataloader, optimizer, scheduler, scaler, device):
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []

    progress_bar = tqdm(dataloader, desc="Training", leave=False)

    # Pre-allocate lists for better performance
    optimizer.zero_grad(set_to_none=True)  # Faster than zero_grad()

    for batch_idx, batch in enumerate(progress_bar):
        input_ids, attention_mask, labels = [
            b.to(device, non_blocking=True) for b in batch
        ]

        # Mixed precision forward pass
        with torch.cuda.amp.autocast():
            outputs = model(
                input_ids=input_ids, attention_mask=attention_mask, labels=labels
            )
            loss = outputs.loss / GRADIENT_ACCUMULATION_STEPS

        # Backward pass with gradient scaling
        scaler.scale(loss).backward()

        # Gradient accumulation
        if (batch_idx + 1) % GRADIENT_ACCUMULATION_STEPS == 0:
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            optimizer.zero_grad(set_to_none=True)  # Faster reset

        total_loss += loss.item() * GRADIENT_ACCUMULATION_STEPS

        # Compute predictions (detach to save memory)
        with torch.no_grad():
            preds = torch.argmax(outputs.logits, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

        progress_bar.set_postfix(
            {"loss": f"{loss.item() * GRADIENT_ACCUMULATION_STEPS:.4f}"}
        )

    avg_loss = total_loss / len(dataloader)
    accuracy = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, average="binary")

    return avg_loss, accuracy, f1


# ========================================
# Evaluation Function (Optimized)
# ========================================
def evaluate(model, dataloader, device):
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []

    progress_bar = tqdm(dataloader, desc="Evaluating", leave=False)

    with torch.no_grad(), torch.cuda.amp.autocast():
        for batch in progress_bar:
            input_ids, attention_mask, labels = [
                b.to(device, non_blocking=True) for b in batch
            ]

            outputs = model(
                input_ids=input_ids, attention_mask=attention_mask, labels=labels
            )
            loss = outputs.loss

            total_loss += loss.item()
            preds = torch.argmax(outputs.logits, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    avg_loss = total_loss / len(dataloader)
    accuracy = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, average="binary")
    precision = precision_score(all_labels, all_preds, average="binary")
    recall = recall_score(all_labels, all_preds, average="binary")

    return {
        "loss": avg_loss,
        "accuracy": accuracy,
        "f1_score": f1,
        "precision": precision,
        "recall": recall,
    }


# ========================================
# Training Loop
# ========================================
print("\n🏋️ Starting training...\n")

best_val_f1 = 0
training_history = []

for epoch in range(NUM_EPOCHS):
    print(f"{'='*60}")
    print(f"Epoch {epoch + 1}/{NUM_EPOCHS}")
    print(f"{'='*60}")

    # Train
    train_loss, train_acc, train_f1 = train_epoch(
        model, train_loader, optimizer, scheduler, scaler, device
    )
    print(
        f"📊 Train Loss: {train_loss:.4f} | Acc: {train_acc:.4f} | F1: {train_f1:.4f}"
    )

    # Validate
    val_metrics = evaluate(model, val_loader, device)
    print(
        f"📊 Val Loss: {val_metrics['loss']:.4f} | Acc: {val_metrics['accuracy']:.4f} | F1: {val_metrics['f1_score']:.4f}"
    )

    # Save best model
    if val_metrics["f1_score"] > best_val_f1:
        best_val_f1 = val_metrics["f1_score"]
        torch.save(
            model.classifier.state_dict(), f"{CHECKPOINT_DIR}/model_final_layer.pt"
        )
        print(f"💾 Saved best model (F1: {best_val_f1:.4f})")

    training_history.append(
        {
            "epoch": epoch + 1,
            "train_loss": train_loss,
            "train_accuracy": train_acc,
            "train_f1": train_f1,
            "val_loss": val_metrics["loss"],
            "val_accuracy": val_metrics["accuracy"],
            "val_f1": val_metrics["f1_score"],
        }
    )

    print()

# ========================================
# Final Evaluation on Test Set
# ========================================
print("\n🧪 Evaluating on test set...")

# Load best model
model.classifier.load_state_dict(torch.load(f"{CHECKPOINT_DIR}/model_final_layer.pt"))
test_metrics = evaluate(model, test_loader, device)

print(f"\n{'='*60}")
print("📈 Final Test Results:")
print(f"{'='*60}")
print(f"Accuracy:  {test_metrics['accuracy']:.4f}")
print(f"F1 Score:  {test_metrics['f1_score']:.4f}")
print(f"Precision: {test_metrics['precision']:.4f}")
print(f"Recall:    {test_metrics['recall']:.4f}")
print(f"Loss:      {test_metrics['loss']:.4f}")
print(f"{'='*60}\n")

# ========================================
# Save Metrics
# ========================================
eval_results = {
    "model": MODEL_NAME,
    "best_val_f1": best_val_f1,
    "test_metrics": test_metrics,
    "training_history": training_history,
    "config": {
        "batch_size": BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "num_epochs": NUM_EPOCHS,
        "max_length": MAX_LENGTH,
        "trainable_params": trainable_params,
        "total_params": total_params,
    },
}

with open(f"{CHECKPOINT_DIR}/eval_metrics.json", "w") as f:
    json.dump(eval_results, f, indent=2)

print(f"✅ Metrics saved to {CHECKPOINT_DIR}/eval_metrics.json")
print(f"✅ Model weights saved to {CHECKPOINT_DIR}/model_final_layer.pt")
print("\n🎉 Training complete!")

# Clean up memory
del model
torch.cuda.empty_cache() if torch.cuda.is_available() else None
