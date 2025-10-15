# type: ignore
"""
Fine-tune GraphCodeBERT Final Classification Layer Only (Kaggle-Ready)
Stage A: Train only the final classifier layer (768 -> 2)
"""

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from transformers import (
    RobertaForSequenceClassification,
    AdamW,
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
    "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/graphcodebert"
)
CHECKPOINT_DIR = "/kaggle/working/checkpoints/graphcodebert"
MODEL_NAME = "microsoft/graphcodebert-base"

BATCH_SIZE = 8
LEARNING_RATE = 2e-5
NUM_EPOCHS = 3
MAX_LENGTH = 512
SEED = 42

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

train_data = torch.load(f"{KAGGLE_INPUT_PATH}/train.pt")
val_data = torch.load(f"{KAGGLE_INPUT_PATH}/val.pt")
test_data = torch.load(f"{KAGGLE_INPUT_PATH}/test.pt")

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

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

print(f"✅ Train samples: {len(train_dataset)}")
print(f"✅ Validation samples: {len(val_dataset)}")
print(f"✅ Test samples: {len(test_dataset)}")

# ========================================
# Initialize Model
# ========================================
print(f"\n🔧 Loading pretrained model: {MODEL_NAME}")
model = RobertaForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
model.to(device)

# ========================================
# FREEZE ALL LAYERS EXCEPT FINAL CLASSIFIER
# ========================================
print("\n🔒 Freezing all layers except final classifier...")

# Freeze base model parameters
for param in model.roberta.parameters():
    param.requires_grad = False

# Replace and ensure classifier is trainable
model.classifier = nn.Linear(768, 2)
model.classifier.to(device)

# Verify only classifier is trainable
trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
total_params = sum(p.numel() for p in model.parameters())
print(
    f"✅ Trainable parameters: {trainable_params:,} / {total_params:,} ({100*trainable_params/total_params:.2f}%)"
)

# ========================================
# Optimizer and Scheduler
# ========================================
optimizer = AdamW(
    filter(lambda p: p.requires_grad, model.parameters()), lr=LEARNING_RATE
)
total_steps = len(train_loader) * NUM_EPOCHS
scheduler = get_linear_schedule_with_warmup(
    optimizer, num_warmup_steps=int(0.1 * total_steps), num_training_steps=total_steps
)

# Mixed precision training
scaler = torch.cuda.amp.GradScaler() if torch.cuda.is_available() else None


# ========================================
# Training Function
# ========================================
def train_epoch(model, dataloader, optimizer, scheduler, scaler, device):
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []

    progress_bar = tqdm(dataloader, desc="Training", leave=False)

    for batch in progress_bar:
        input_ids, attention_mask, labels = [b.to(device) for b in batch]

        optimizer.zero_grad()

        if scaler:
            with torch.cuda.amp.autocast():
                outputs = model(
                    input_ids=input_ids, attention_mask=attention_mask, labels=labels
                )
                loss = outputs.loss
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
        else:
            outputs = model(
                input_ids=input_ids, attention_mask=attention_mask, labels=labels
            )
            loss = outputs.loss
            loss.backward()
            optimizer.step()

        scheduler.step()

        total_loss += loss.item()
        preds = torch.argmax(outputs.logits, dim=1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

        progress_bar.set_postfix({"loss": loss.item()})

    avg_loss = total_loss / len(dataloader)
    accuracy = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, average="binary")

    return avg_loss, accuracy, f1


# ========================================
# Evaluation Function
# ========================================
def evaluate(model, dataloader, device):
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []

    progress_bar = tqdm(dataloader, desc="Evaluating", leave=False)

    with torch.no_grad():
        for batch in progress_bar:
            input_ids, attention_mask, labels = [b.to(device) for b in batch]

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
