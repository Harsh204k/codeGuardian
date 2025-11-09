#!/usr/bin/env python3
# =============================
# codeGuardian LoRA Fine-tuning Script - FINAL VERSION
# Author: Urva Gandhi
# Model: CodeBERT (microsoft/codebert-base)
# Purpose: Binary vulnerability detection with LoRA parameter-efficient fine-tuning
# Standard: CodeGuardian Training Standard v1.0
# =============================

"""
CodeGuardian LoRA Fine-tuning Pipeline - Production Standard v1.0
===================================================================
Production-ready LoRA fine-tuning script optimized for Kaggle Free GPU (T4/P100 16GB).
Implements parameter-efficient fine-tuning for vulnerability detection across 9 languages.

Features:
✅ PEFT LoRA configuration (r=8, α=16, dropout=0.1)
✅ Weighted CrossEntropyLoss for class imbalance
✅ AdamW optimizer with cosine learning rate scheduling
✅ Early stopping with patience mechanism
✅ Mixed precision training (fp16) for memory efficiency
✅ Gradient accumulation for effective larger batch sizes
✅ Batch-level progress logging (every 5% of steps)
✅ Comprehensive epoch summaries (train/val metrics)
✅ Language-wise test evaluation with per-language F1/Accuracy
✅ Full reproducibility (seed=42, deterministic operations)
✅ Structured output with checkpoints, and metrics
✅ Memory-efficient validation and test loops

Training Configuration:
- Model: microsoft/codebert-base
- Task: Binary classification (vulnerable vs. secure code)
- Languages: C, C#, C++, Go, Java, JavaScript, PHP, Python, Ruby
- LoRA rank (r): 8
- LoRA alpha (α): 16
- LoRA dropout: 0.1
- Target modules: ["query", "value"]
- Learning rate: 1e-4
- Weight decay: 0.01
- Epochs: 2
- Batch size: 4 (effective: 16 with grad accumulation)
- Gradient accumulation steps: 4
- Warmup ratio: 0.05
- Early stopping patience: 2
- Mixed precision: fp16
- Random seed: 42

Expected Performance:
- Test F1: ~0.60 ± 0.05 (aligned with CodeBERT paper)
- Test Accuracy: ~0.60 ± 0.05
- Training time: ~45-60 minutes on Kaggle T4

Input Structure:
Pre-tokenized .pt files from tokenization pipeline:
{
  "input_ids": Tensor[N, 512],
  "attention_mask": Tensor[N, 512],
  "labels": Tensor[N],
  "language_ids": Tensor[N],
  "language_vocab": List[str],
  "meta": {...}
}

Input Path:
/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/codebert-base/{split}_tokenized_codebert-base.pt

Output Structure:
/kaggle/working/lora_output_codebert/
├── adapter_config_codebert.json       # LoRA adapter configuration
├── adapter_model_codebert.bin         # Trained LoRA weights
├── README_codebert.md                 # Model documentation
├── checkpoints_codebert/              # Epoch checkpoints
│   └── epoch_codebert_{n}.pt
└── metrics_codebert/                  # Evaluation metrics
    ├── results_codebert.json          # Full results
    ├── language_wise_f1_codebert.json # Per-language metrics
    └── confusion_matrix_codebert.json # Confusion matrix

Console Output Format:
================================================================================
EPOCH 1/2
================================================================================
Train → Loss=0.2167 | Acc=0.9432 | Prec=0.8861 | Rec=0.8264 | F1=0.8552
Val   → Loss=0.1907 | Acc=0.9495 | Prec=0.8871 | Rec=0.8605 | F1=0.8736
✓ Saved best checkpoint (val_F1=0.8736)
--------------------------------------------------------------------------------

🎯 FINAL TEST PERFORMANCE
Acc=0.6058 | Prec=0.6121 | Rec=0.5859 | F1=0.5987

## 📊 Language-wise F1 Scores
Language       F1      Acc      Samples
C              0.59    0.60    39,404
Java           0.63    0.62     7,975
...

Usage:
1. Upload to Kaggle notebook
2. Ensure tokenized dataset is available as Kaggle Dataset
3. Run: python train_codebert_lora_vFinalStable.py
4. Monitor training progress in console output
5. Collect artifacts from /kaggle/working/lora_output_codebert/

Dependencies:
- torch>=2.0.0
- transformers>=4.30.0
- peft>=0.4.0
- scikit-learn>=1.0.0
- tqdm
- numpy
"""

import os
import json
import time
import random
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import (
    RobertaTokenizer,
    RobertaForSequenceClassification,
    get_cosine_schedule_with_warmup
)
from peft import LoraConfig, get_peft_model, TaskType
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)
from tqdm import tqdm
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

SEED = 42
MODEL_NAME = "microsoft/codebert-base"
BASE_DIR = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/codebert-base"
OUTPUT_DIR = "/kaggle/working/lora_output_codebert"

# Training hyperparameters
EPOCHS = 2
BATCH_SIZE = 4
GRAD_ACCUM_STEPS = 4
LEARNING_RATE = 1e-4
WEIGHT_DECAY = 0.01
WARMUP_RATIO = 0.05
FP16 = True

# LoRA configuration
LORA_R = 8
LORA_ALPHA = 16
LORA_DROPOUT = 0.1
LORA_TARGET_MODULES = ["query", "value"]

# Early stopping
EARLY_STOP_PATIENCE = 2
EARLY_STOP_MIN_DELTA = 0.001

# Logging
LOG_STEPS_RATIO = 0.05  # Log every 5% of steps

LANGUAGES = ["C", "C#", "C++", "Go", "Java", "JavaScript", "PHP", "Python", "Ruby"]

# ═══════════════════════════════════════════════════════════════════════════
# REPRODUCIBILITY
# ═══════════════════════════════════════════════════════════════════════════

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

set_seed(SEED)

# ═══════════════════════════════════════════════════════════════════════════
# DATASET
# ═══════════════════════════════════════════════════════════════════════════

class PreTokenizedDataset(Dataset):
    def __init__(self, pt_file):
        if not os.path.exists(pt_file):
            raise FileNotFoundError(f"Dataset not found: {pt_file}")
        self.data = torch.load(pt_file)

    def __len__(self):
        return len(self.data['input_ids'])

    def __getitem__(self, idx):
        return {
            'input_ids': self.data['input_ids'][idx],
            'attention_mask': self.data['attention_mask'][idx],
            'labels': self.data['labels'][idx],
            'language_ids': self.data.get('language_ids', [0] * len(self.data['labels']))[idx],
        }

# ═══════════════════════════════════════════════════════════════════════════
# WEIGHTED LOSS CALCULATION
# ═══════════════════════════════════════════════════════════════════════════

def compute_class_weights(dataset):
    labels = dataset.data['labels'].numpy()
    pos_count = np.sum(labels == 1)
    neg_count = np.sum(labels == 0)
    total = len(labels)

    weight_pos = total / (2 * pos_count) if pos_count > 0 else 1.0
    weight_neg = total / (2 * neg_count) if neg_count > 0 else 1.0

    return torch.tensor([weight_neg, weight_pos], dtype=torch.float32)

# ═══════════════════════════════════════════════════════════════════════════
# METRICS COMPUTATION
# ═══════════════════════════════════════════════════════════════════════════

def compute_metrics(preds, labels):
    preds = np.array(preds)
    labels = np.array(labels)

    acc = accuracy_score(labels, preds)
    prec, rec, f1, _ = precision_recall_fscore_support(
        labels, preds, average='binary', zero_division=0
    )

    return {
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1
    }

# ═══════════════════════════════════════════════════════════════════════════
# TRAINING LOOP
# ═══════════════════════════════════════════════════════════════════════════

def train_epoch(model, dataloader, optimizer, scheduler, criterion, scaler, device, epoch, total_epochs):
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []

    log_interval = max(1, int(len(dataloader) * LOG_STEPS_RATIO))

    progress_bar = tqdm(dataloader, desc=f"Epoch {epoch}/{total_epochs} [Train]")

    for step, batch in enumerate(progress_bar):
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)

        # Mixed precision forward pass
        with torch.amp.autocast('cuda', enabled=FP16):
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            loss = criterion(logits, labels) / GRAD_ACCUM_STEPS

        # Backward pass with gradient scaling
        if FP16:
            scaler.scale(loss).backward()
        else:
            loss.backward()

        if (step + 1) % GRAD_ACCUM_STEPS == 0:
            if FP16:
                scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            if FP16:
                scaler.step(optimizer)
                scaler.update()
            else:
                optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

        total_loss += loss.item() * GRAD_ACCUM_STEPS

        preds = torch.argmax(logits, dim=-1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

        # Log progress
        if (step + 1) % log_interval == 0:
            metrics = compute_metrics(all_preds[-log_interval*BATCH_SIZE:],
                                     all_labels[-log_interval*BATCH_SIZE:])
            progress_bar.set_postfix({
                'loss': f"{loss.item() * GRAD_ACCUM_STEPS:.4f}",
                'acc': f"{metrics['accuracy']:.4f}",
                'f1': f"{metrics['f1']:.4f}"
            })

    avg_loss = total_loss / len(dataloader)
    metrics = compute_metrics(all_preds, all_labels)

    return avg_loss, metrics

# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION LOOP
# ═══════════════════════════════════════════════════════════════════════════

def validate(model, dataloader, criterion, device):
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for batch in tqdm(dataloader, desc="Validating"):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits

            loss = criterion(logits, labels)
            total_loss += loss.item()

            preds = torch.argmax(logits, dim=-1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    avg_loss = total_loss / len(dataloader)
    metrics = compute_metrics(all_preds, all_labels)

    return avg_loss, metrics

# ═══════════════════════════════════════════════════════════════════════════
# LANGUAGE-WISE EVALUATION
# ═══════════════════════════════════════════════════════════════════════════

def evaluate_per_language(model, dataloader, device):
    model.eval()
    language_data = defaultdict(lambda: {'preds': [], 'labels': []})

    with torch.no_grad():
        for batch in tqdm(dataloader, desc="Test Evaluation"):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].cpu().numpy()
            language_ids = batch['language_ids'].cpu().numpy()

            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            preds = torch.argmax(logits, dim=-1).cpu().numpy()

            for pred, label, lang_id in zip(preds, labels, language_ids):
                lang_name = LANGUAGES[lang_id] if lang_id < len(LANGUAGES) else f"Unknown_{lang_id}"
                language_data[lang_name]['preds'].append(pred)
                language_data[lang_name]['labels'].append(label)

    # Compute metrics per language
    results = {}
    all_preds = []
    all_labels = []

    for lang, data in language_data.items():
        metrics = compute_metrics(data['preds'], data['labels'])
        results[lang] = {
            'f1': metrics['f1'],
            'accuracy': metrics['accuracy'],
            'precision': metrics['precision'],
            'recall': metrics['recall'],
            'samples': len(data['labels'])
        }
        all_preds.extend(data['preds'])
        all_labels.extend(data['labels'])

    # Global metrics
    global_metrics = compute_metrics(all_preds, all_labels)

    # Compute confusion matrix
    cm = confusion_matrix(all_labels, all_preds)
    global_metrics['confusion_matrix'] = cm.tolist()

    return global_metrics, results

# ═══════════════════════════════════════════════════════════════════════════
# MAIN TRAINING FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def main():
    start_time = time.time()

    # Create output directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(f"{OUTPUT_DIR}/checkpoints_codebert", exist_ok=True)
    os.makedirs(f"{OUTPUT_DIR}/metrics_codebert", exist_ok=True)

    print("=" * 80)
    print("🚀 codeGuardian - CodeBERT LoRA Fine-tuning")
    print("=" * 80)
    print(f"Model: {MODEL_NAME}")
    print(f"LoRA Config: r={LORA_R}, α={LORA_ALPHA}, dropout={LORA_DROPOUT}")
    print(f"Training: {EPOCHS} epochs, BS={BATCH_SIZE}, LR={LEARNING_RATE}")
    print(f"Device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}")
    print("=" * 80)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # Load datasets
    print("\n📂 Loading tokenized datasets...")
    train_dataset = PreTokenizedDataset(f"{BASE_DIR}/train_tokenized_codebert-base.pt")
    val_dataset = PreTokenizedDataset(f"{BASE_DIR}/val_tokenized_codebert-base.pt")
    test_dataset = PreTokenizedDataset(f"{BASE_DIR}/test_tokenized_codebert-base.pt")

    # # ⚠️ TESTING MODE: Subset datasets for faster iteration
    # subset_size = 50000
    # print(f"\n⚠️  TESTING MODE: Using subset of {subset_size:,} samples")
    # train_dataset.data['input_ids'] = train_dataset.data['input_ids'][:subset_size]
    # train_dataset.data['attention_mask'] = train_dataset.data['attention_mask'][:subset_size]
    # train_dataset.data['labels'] = train_dataset.data['labels'][:subset_size]
    # train_dataset.data['language_ids'] = train_dataset.data['language_ids'][:subset_size]

    print(f"   Train: {len(train_dataset):,} samples")
    print(f"   Val:   {len(val_dataset):,} samples")
    print(f"   Test:  {len(test_dataset):,} samples")

    # Compute class weights
    class_weights = compute_class_weights(train_dataset).to(device)
    print(f"\n⚖️  Class weights: [Neg: {class_weights[0]:.4f}, Pos: {class_weights[1]:.4f}]")

    # Create dataloaders with pin_memory for faster GPU transfer
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, num_workers=2, pin_memory=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False, num_workers=2, pin_memory=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, num_workers=2, pin_memory=True)

    # Load model
    print(f"\n🤖 Loading {MODEL_NAME}...")
    model = RobertaForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    # Apply LoRA
    print("🔧 Applying LoRA configuration...")
    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=LORA_R,
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        target_modules=LORA_TARGET_MODULES,
        bias="none"
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    model.to(device)

    # Loss function
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    # Optimizer and scheduler
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)

    total_steps = len(train_loader) // GRAD_ACCUM_STEPS * EPOCHS
    warmup_steps = int(total_steps * WARMUP_RATIO)
    scheduler = get_cosine_schedule_with_warmup(optimizer, warmup_steps, total_steps)

    print(f"\n📊 Training steps: {total_steps:,} | Warmup: {warmup_steps:,}")

    # Enable mixed precision
    scaler = torch.amp.GradScaler('cuda') if FP16 else None

    # Training loop
    best_val_f1 = 0
    patience_counter = 0
    training_log = []

    print("\n" + "=" * 80)
    print("🏋️  TRAINING START")
    print("=" * 80)

    for epoch in range(1, EPOCHS + 1):
        train_loss, train_metrics = train_epoch(
            model, train_loader, optimizer, scheduler, criterion, scaler, device, epoch, EPOCHS
        )

        val_loss, val_metrics = validate(model, val_loader, criterion, device)

        # Print epoch summary
        print("\n" + "=" * 80)
        print(f"EPOCH {epoch}/{EPOCHS}")
        print("=" * 80)
        print(f"Train → Loss={train_loss:.4f} | Acc={train_metrics['accuracy']:.4f} | "
              f"Prec={train_metrics['precision']:.4f} | Rec={train_metrics['recall']:.4f} | "
              f"F1={train_metrics['f1']:.4f}")
        print(f"Val   → Loss={val_loss:.4f} | Acc={val_metrics['accuracy']:.4f} | "
              f"Prec={val_metrics['precision']:.4f} | Rec={val_metrics['recall']:.4f} | "
              f"F1={val_metrics['f1']:.4f}")

        # Save checkpoint if best
        if val_metrics['f1'] > best_val_f1 + EARLY_STOP_MIN_DELTA:
            best_val_f1 = val_metrics['f1']
            patience_counter = 0

            checkpoint_path = f"{OUTPUT_DIR}/checkpoints_codebert/epoch_codebert_{epoch}.pt"
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_f1': val_metrics['f1'],
            }, checkpoint_path)

            # Save LoRA adapter
            model.save_pretrained(OUTPUT_DIR)

            print(f"✓ Saved best checkpoint (val_F1={val_metrics['f1']:.4f})")
        else:
            patience_counter += 1
            print(f"⚠ No improvement (patience {patience_counter}/{EARLY_STOP_PATIENCE})")

        print("-" * 80)

        training_log.append({
            'epoch': epoch,
            'train_loss': train_loss,
            'train_metrics': train_metrics,
            'val_loss': val_loss,
            'val_metrics': val_metrics
        })

        # Early stopping
        if patience_counter >= EARLY_STOP_PATIENCE:
            print(f"\n⏹️  Early stopping triggered at epoch {epoch}")
            break

    # Load best model
    print("\n" + "=" * 80)
    print("📥 Loading best checkpoint for test evaluation...")
    best_checkpoint = torch.load(
        f"{OUTPUT_DIR}/checkpoints_codebert/epoch_codebert_{epoch - patience_counter}.pt"
    )
    model.load_state_dict(best_checkpoint['model_state_dict'])

    # Final test evaluation
    print("\n🎯 Evaluating on Test Set...")
    global_metrics, language_results = evaluate_per_language(model, test_loader, device)

    print("\n" + "=" * 80)
    print("🎯 FINAL TEST PERFORMANCE")
    print("=" * 80)
    print(f"Acc={global_metrics['accuracy']:.4f} | Prec={global_metrics['precision']:.4f} | "
          f"Rec={global_metrics['recall']:.4f} | F1={global_metrics['f1']:.4f}")

    print("\n## 📊 Language-wise F1 Scores\n")
    print(f"{'Language':<15} {'F1':<8} {'Acc':<8} {'Samples':<10}")
    print("-" * 45)

    sorted_langs = sorted(language_results.items(), key=lambda x: x[1]['samples'], reverse=True)
    for lang, metrics in sorted_langs:
        print(f"{lang:<15} {metrics['f1']:<8.2f} {metrics['accuracy']:<8.2f} {metrics['samples']:<10,}")

    print("-" * 45)

    # Save results
    results = {
        'global_metrics': global_metrics,
        'language_wise': language_results,
        'training_log': training_log,
        'best_val_f1': best_val_f1,
        'total_epochs': epoch
    }

    with open(f"{OUTPUT_DIR}/metrics_codebert/results_codebert.json", 'w') as f:
        json.dump(results, f, indent=2)

    with open(f"{OUTPUT_DIR}/metrics_codebert/language_wise_f1_codebert.json", 'w') as f:
        json.dump(language_results, f, indent=2)

    # Save confusion matrix
    cm_data = {
        'confusion_matrix': global_metrics.get('confusion_matrix', []),
        'labels': ['Secure (0)', 'Vulnerable (1)']
    }
    with open(f"{OUTPUT_DIR}/metrics_codebert/confusion_matrix_codebert.json", 'w') as f:
        json.dump(cm_data, f, indent=2)

    print(f"\n💾 Saved to metrics_codebert/language_wise_f1_codebert.json")
    print(f"💾 Saved confusion matrix to metrics_codebert/confusion_matrix_codebert.json")

    # Save README
    readme_content = f"""# codeGuardian - CodeBERT LoRA Adapter

## Model Info
- Base Model: {MODEL_NAME}
- Task: Binary vulnerability detection
- Languages: {', '.join(LANGUAGES)}
- Training Date: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Training Configuration
- LoRA r: {LORA_R}
- LoRA α: {LORA_ALPHA}
- LoRA dropout: {LORA_DROPOUT}
- Learning rate: {LEARNING_RATE}
- Epochs: {epoch}
- Batch size: {BATCH_SIZE}
- Gradient accumulation: {GRAD_ACCUM_STEPS}

## Performance
- Test F1: {global_metrics['f1']:.4f}
- Test Accuracy: {global_metrics['accuracy']:.4f}
- Best Val F1: {best_val_f1:.4f}

## Usage
```python
from peft import PeftModel
from transformers import RobertaForSequenceClassification

base_model = RobertaForSequenceClassification.from_pretrained("{MODEL_NAME}")
model = PeftModel.from_pretrained(base_model, "{OUTPUT_DIR}")
```
"""

    with open(f"{OUTPUT_DIR}/README_codebert.md", 'w') as f:
        f.write(readme_content)

    total_time = time.time() - start_time
    print(f"\n✅ Training completed | Total runtime ≈ {total_time/60:.0f} min")
    print("=" * 80)

if __name__ == "__main__":
    main()
