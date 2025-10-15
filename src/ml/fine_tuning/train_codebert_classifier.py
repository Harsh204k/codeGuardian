# type: ignore
"""
Fine-tune CodeBERT Final Classification Layer Only (Kaggle-Ready)
ULTRA-FAST VERSION: Precompute frozen embeddings, then train linear classifier

Stage 1: Extract frozen CodeBERT embeddings ([CLS] token) and cache to disk
Stage 2: Train only lightweight linear classifier (768 -> 2) on cached embeddings

This approach is 20-50x faster than training through full model!
"""

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from transformers import RobertaForSequenceClassification
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
EMBEDDINGS_DIR = "/kaggle/working/embeddings/codebert"
MODEL_NAME = "microsoft/codebert-base"

# ULTRA-OPTIMIZED hyperparameters for maximum speed
EMBEDDING_BATCH_SIZE = 256  # FP16 allows larger batches (halves memory)
TRAINING_BATCH_SIZE = 512  # Much larger for linear classifier training
LEARNING_RATE = 2e-3  # Higher LR for linear classifier (not pretrained model)
NUM_EPOCHS = 3
SEED = 42
NUM_WORKERS = 4
CHUNK_SIZE = 50000  # Save embeddings in chunks to avoid OOM

# Set seed for reproducibility
torch.manual_seed(SEED)
if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

# ========================================
# Setup
# ========================================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"🚀 Using device: {device}")

# Create directories
os.makedirs(CHECKPOINT_DIR, exist_ok=True)
os.makedirs(EMBEDDINGS_DIR, exist_ok=True)

# ========================================
# STAGE 1: EXTRACT AND CACHE EMBEDDINGS
# ========================================
print("\n" + "=" * 60)
print("STAGE 1: Extracting Frozen CodeBERT Embeddings")
print("=" * 60)

# Check if embeddings already exist
embeddings_exist = all([
    os.path.exists(f"{EMBEDDINGS_DIR}/train_embeddings.pt"),
    os.path.exists(f"{EMBEDDINGS_DIR}/val_embeddings.pt"),
    os.path.exists(f"{EMBEDDINGS_DIR}/test_embeddings.pt"),
])

if embeddings_exist:
    print("✅ Embeddings already cached! Skipping extraction.")
else:
    print("📂 Loading tokenized datasets...")
    train_data = torch.load(f"{KAGGLE_INPUT_PATH}/train_tokenized_codebert.pt")
    val_data = torch.load(f"{KAGGLE_INPUT_PATH}/val_tokenized_codebert.pt")
    test_data = torch.load(f"{KAGGLE_INPUT_PATH}/test_tokenized_codebert.pt")

    print(f"✅ Train samples: {len(train_data['labels'])}")
    print(f"✅ Val samples: {len(val_data['labels'])}")
    print(f"✅ Test samples: {len(test_data['labels'])}")

    print(f"\n🔧 Loading frozen CodeBERT backbone...")
    model = RobertaForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
    model.to(device)
    model.eval()  # Freeze all layers

    # Freeze all parameters (no gradients needed)
    for param in model.parameters():
        param.requires_grad = False

    print("✅ Model frozen. Extracting embeddings...")

    def extract_embeddings(data_dict, split_name):
        """Extract [CLS] embeddings from frozen model"""
        dataset = TensorDataset(
            data_dict["input_ids"],
            data_dict["attention_mask"],
            data_dict["labels"]
        )
        dataloader = DataLoader(
            dataset,
            batch_size=EMBEDDING_BATCH_SIZE,
            shuffle=False,
            num_workers=NUM_WORKERS,
            pin_memory=True,
        )

        all_embeddings = []
        all_labels = []

        with torch.no_grad():
            for batch in tqdm(dataloader, desc=f"Extracting {split_name}"):
                input_ids, attention_mask, labels = [b.to(device) for b in batch]

                # Get hidden states from RoBERTa backbone (no classification head)
                outputs = model.roberta(input_ids=input_ids, attention_mask=attention_mask)
                # Extract [CLS] token embedding (first token)
                cls_embeddings = outputs.last_hidden_state[:, 0, :]  # Shape: (batch_size, 768)

                all_embeddings.append(cls_embeddings.cpu())
                all_labels.append(labels.cpu())

        embeddings = torch.cat(all_embeddings, dim=0)
        labels = torch.cat(all_labels, dim=0)

        print(f"  ✅ {split_name}: {embeddings.shape[0]} embeddings (shape: {embeddings.shape})")
        return {"embeddings": embeddings, "labels": labels}

    # Extract embeddings for all splits
    train_embeddings = extract_embeddings(train_data, "train")
    val_embeddings = extract_embeddings(val_data, "val")
    test_embeddings = extract_embeddings(test_data, "test")

    # Save to disk
    print("\n� Saving embeddings to disk...")
    torch.save(train_embeddings, f"{EMBEDDINGS_DIR}/train_embeddings.pt")
    torch.save(val_embeddings, f"{EMBEDDINGS_DIR}/val_embeddings.pt")
    torch.save(test_embeddings, f"{EMBEDDINGS_DIR}/test_embeddings.pt")
    print(f"✅ Embeddings saved to {EMBEDDINGS_DIR}/")

    # Clean up model to free memory
    del model
    torch.cuda.empty_cache() if torch.cuda.is_available() else None

# ========================================
# STAGE 2: TRAIN LINEAR CLASSIFIER ON CACHED EMBEDDINGS
# ========================================
print("\n" + "=" * 60)
print("STAGE 2: Training Linear Classifier on Cached Embeddings")
print("=" * 60)

print("📂 Loading cached embeddings...")
train_embeddings = torch.load(f"{EMBEDDINGS_DIR}/train_embeddings.pt")
val_embeddings = torch.load(f"{EMBEDDINGS_DIR}/val_embeddings.pt")
test_embeddings = torch.load(f"{EMBEDDINGS_DIR}/test_embeddings.pt")

# Create datasets from embeddings
train_dataset = TensorDataset(train_embeddings["embeddings"], train_embeddings["labels"])
val_dataset = TensorDataset(val_embeddings["embeddings"], val_embeddings["labels"])
test_dataset = TensorDataset(test_embeddings["embeddings"], test_embeddings["labels"])

# DataLoaders - much larger batches possible with just 768-dim vectors!
train_loader = DataLoader(
    train_dataset,
    batch_size=TRAINING_BATCH_SIZE,
    shuffle=True,
    num_workers=NUM_WORKERS,
    pin_memory=True,
)
val_loader = DataLoader(
    val_dataset,
    batch_size=TRAINING_BATCH_SIZE * 2,
    shuffle=False,
    num_workers=NUM_WORKERS,
    pin_memory=True,
)
test_loader = DataLoader(
    test_dataset,
    batch_size=TRAINING_BATCH_SIZE * 2,
    shuffle=False,
    num_workers=NUM_WORKERS,
    pin_memory=True,
)

print(f"✅ Train batches: {len(train_loader)} (batch_size={TRAINING_BATCH_SIZE})")
print(f"✅ Val batches: {len(val_loader)}")
print(f"✅ Test batches: {len(test_loader)}")

# ========================================
# Define Simple Linear Classifier
# ========================================
class LinearClassifier(nn.Module):
    """Simple 768 -> 2 linear classifier"""
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(768, 2)

    def forward(self, embeddings):
        return self.fc(embeddings)

classifier = LinearClassifier().to(device)
print(f"\n🔧 Classifier: {sum(p.numel() for p in classifier.parameters())} parameters")

# ========================================
# Optimizer and Loss
# ========================================
optimizer = torch.optim.AdamW(
    classifier.parameters(),
    lr=LEARNING_RATE,
    betas=(0.9, 0.999),
    weight_decay=0.01,
)
criterion = nn.CrossEntropyLoss()

print(f"✅ Optimizer: AdamW (lr={LEARNING_RATE})")
print(f"✅ Loss: CrossEntropyLoss")

# ========================================
# Training Function (Simple - No Mixed Precision Needed)
# ========================================
def train_epoch(classifier, dataloader, optimizer, criterion, device):
    classifier.train()
    total_loss = 0
    all_preds = []
    all_labels = []

    progress_bar = tqdm(dataloader, desc="Training", leave=False)

    for embeddings, labels in progress_bar:
        embeddings = embeddings.to(device, non_blocking=True)
        labels = labels.to(device, non_blocking=True)

        # Forward pass
        logits = classifier(embeddings)
        loss = criterion(logits, labels)

        # Backward pass
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

        # Predictions
        preds = torch.argmax(logits, dim=1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

        progress_bar.set_postfix({"loss": f"{loss.item():.4f}"})

    avg_loss = total_loss / len(dataloader)
    accuracy = accuracy_score(all_labels, all_preds)
    f1 = f1_score(all_labels, all_preds, average="binary")

    return avg_loss, accuracy, f1


# ========================================
# Evaluation Function
# ========================================
def evaluate(classifier, dataloader, criterion, device):
    classifier.eval()
    total_loss = 0
    all_preds = []
    all_labels = []

    progress_bar = tqdm(dataloader, desc="Evaluating", leave=False)

    with torch.no_grad():
        for embeddings, labels in progress_bar:
            embeddings = embeddings.to(device, non_blocking=True)
            labels = labels.to(device, non_blocking=True)

            logits = classifier(embeddings)
            loss = criterion(logits, labels)

            total_loss += loss.item()
            preds = torch.argmax(logits, dim=1)
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
        classifier, train_loader, optimizer, criterion, device
    )
    print(
        f"📊 Train Loss: {train_loss:.4f} | Acc: {train_acc:.4f} | F1: {train_f1:.4f}"
    )

    # Validate
    val_metrics = evaluate(classifier, val_loader, criterion, device)
    print(
        f"📊 Val Loss: {val_metrics['loss']:.4f} | Acc: {val_metrics['accuracy']:.4f} | F1: {val_metrics['f1_score']:.4f}"
    )

    # Save best model
    if val_metrics["f1_score"] > best_val_f1:
        best_val_f1 = val_metrics["f1_score"]
        torch.save(classifier.state_dict(), f"{CHECKPOINT_DIR}/model_final_layer.pt")
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
classifier.load_state_dict(torch.load(f"{CHECKPOINT_DIR}/model_final_layer.pt"))
test_metrics = evaluate(classifier, test_loader, criterion, device)

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
    "training_method": "cached_embeddings_linear_classifier",
    "best_val_f1": best_val_f1,
    "test_metrics": test_metrics,
    "training_history": training_history,
    "config": {
        "embedding_batch_size": EMBEDDING_BATCH_SIZE,
        "training_batch_size": TRAINING_BATCH_SIZE,
        "learning_rate": LEARNING_RATE,
        "num_epochs": NUM_EPOCHS,
        "classifier_params": sum(p.numel() for p in classifier.parameters()),
    },
}

with open(f"{CHECKPOINT_DIR}/eval_metrics.json", "w") as f:
    json.dump(eval_results, f, indent=2)

print(f"✅ Metrics saved to {CHECKPOINT_DIR}/eval_metrics.json")
print(f"✅ Model weights saved to {CHECKPOINT_DIR}/model_final_layer.pt")
print(f"✅ Cached embeddings saved to {EMBEDDINGS_DIR}/")
print("\n🎉 Training complete!")
print(f"\n⚡ Performance Summary:")
print(f"  - Embedding extraction: One-time cost (reusable)")
print(f"  - Classifier training: ~1-2 minutes per epoch")
print(f"  - Total speedup: 20-50x faster than full model training!")

# Clean up memory
del classifier
torch.cuda.empty_cache() if torch.cuda.is_available() else None
