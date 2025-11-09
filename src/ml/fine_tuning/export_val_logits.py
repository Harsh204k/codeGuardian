#!/usr/bin/env python3
# =============================
# codeGuardian Validation Logits Export Script
# Author: Urva Gandhi
# Purpose: Export raw logits from fine-tuned CodeBERT and GraphCodeBERT models
# Standard: CodeGuardian Post-Training Standard v1.0
# =============================

"""
CodeGuardian Validation Logits Export Pipeline
================================================
Exports raw logits from fine-tuned LoRA models for post-training calibration.

This script performs inference on the validation dataset using both:
- CodeBERT-LoRA
- GraphCodeBERT-LoRA

And exports their raw logits (pre-sigmoid outputs) for use in:
1. Temperature scaling (probability calibration)
2. Threshold optimization (per-language)
3. Model ensembling (weighted combination)

Features:
✅ Loads LoRA adapters and checkpoints automatically
✅ Batched inference with progress tracking
✅ CUDA acceleration with automatic device detection
✅ Memory-efficient processing
✅ Comprehensive logging and validation
✅ CSV export for downstream optimization

Input:
- Validation dataset: /kaggle/input/.../random_splitted/val.jsonl
- CodeBERT LoRA adapter: /kaggle/working/lora_output_codebert/
- GraphCodeBERT LoRA adapter: /kaggle/working/lora_output_graphcodebert/

Output:
- /kaggle/working/val_logits.csv with columns:
  [language, logits_codebert, logits_graphcodebert, y_true]

Usage:
1. Ensure both models are fine-tuned and adapters are saved
2. Run: python export_val_logits.py
3. Use output CSV for threshold_optimizer.py

Dependencies:
- torch>=2.0.0
- transformers>=4.30.0
- peft>=0.4.0
- pandas
- tqdm
"""

import os
import json
import logging
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from peft import PeftModel
from tqdm import tqdm

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Kaggle paths
VAL_DATA_PATH = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted/val.jsonl"
OUTPUT_CSV_PATH = "/kaggle/working/val_logits.csv"

# Model paths
CODEBERT_BASE = "microsoft/codebert-base"
GRAPHCODEBERT_BASE = "microsoft/graphcodebert-base"

CODEBERT_ADAPTER_DIR = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_codebert"
GRAPHCODEBERT_ADAPTER_DIR = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_graphcodebert"

CODEBERT_CHECKPOINT = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_codebert/checkpoints_codebert/epoch_codebert_1.pt"
GRAPHCODEBERT_CHECKPOINT = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_graphcodebert/checkpoints_graphcodebert/epoch_graphcodebert_1.pt"

# Inference settings
BATCH_SIZE = 16
MAX_LENGTH = 512
NUM_WORKERS = 2

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# CUSTOM DATASET
# ═══════════════════════════════════════════════════════════════════════════

class ValidationDataset(Dataset):
    """
    Dataset for loading validation samples from JSONL format.

    Each sample contains:
    - code: source code snippet
    - language: programming language
    - is_vulnerable: ground truth label
    """

    def __init__(self, jsonl_path, tokenizer, max_length=512):
        """
        Args:
            jsonl_path: Path to val.jsonl file
            tokenizer: Hugging Face tokenizer
            max_length: Maximum sequence length
        """
        self.tokenizer = tokenizer
        self.max_length = max_length

        # Load JSONL data
        logger.info(f"Loading validation data from {jsonl_path}")
        self.df = pd.read_json(jsonl_path, lines=True)

        # Validate required columns
        required_cols = ['code', 'language', 'is_vulnerable']
        missing_cols = set(required_cols) - set(self.df.columns)
        if missing_cols:
            raise ValueError(f"Missing required columns: {missing_cols}")

        # Convert boolean to int labels
        self.df['label'] = self.df['is_vulnerable'].astype(int)

        logger.info(f"Loaded {len(self.df):,} validation samples")
        logger.info(f"Label distribution: {self.df['label'].value_counts().to_dict()}")

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx):
        row = self.df.iloc[idx]

        # Tokenize code
        encoding = self.tokenizer(
            row['code'],
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )

        return {
            'input_ids': encoding['input_ids'].squeeze(0),
            'attention_mask': encoding['attention_mask'].squeeze(0),
            'label': torch.tensor(row['label'], dtype=torch.long),
            'language': row['language']
        }

# ═══════════════════════════════════════════════════════════════════════════
# MODEL LOADING
# ═══════════════════════════════════════════════════════════════════════════

def load_lora_model(base_model_name, adapter_dir, checkpoint_path, device):
    """
    Load a fine-tuned LoRA model with checkpoint weights.

    Args:
        base_model_name: Hugging Face model identifier
        adapter_dir: Directory containing LoRA adapter
        checkpoint_path: Path to model checkpoint (.pt file)
        device: Target device (cuda/cpu)

    Returns:
        model: Loaded model in eval mode
        tokenizer: Corresponding tokenizer
    """
    logger.info(f"Loading base model: {base_model_name}")

    # Load base model
    base_model = RobertaForSequenceClassification.from_pretrained(
        base_model_name,
        num_labels=2
    )

    # Load LoRA adapter
    logger.info(f"Loading LoRA adapter from: {adapter_dir}")
    model = PeftModel.from_pretrained(base_model, adapter_dir)

    # Load checkpoint weights if available
    if os.path.exists(checkpoint_path):
        logger.info(f"Loading checkpoint: {checkpoint_path}")
        checkpoint = torch.load(checkpoint_path, map_location=device)
        model.load_state_dict(checkpoint['model_state_dict'])
        logger.info(f"Checkpoint loaded (epoch {checkpoint.get('epoch', 'N/A')})")
    else:
        logger.warning(f"Checkpoint not found: {checkpoint_path}, using adapter weights only")

    # Load tokenizer
    tokenizer = RobertaTokenizer.from_pretrained(base_model_name)

    model.to(device)
    model.eval()

    return model, tokenizer

# ═══════════════════════════════════════════════════════════════════════════
# INFERENCE
# ═══════════════════════════════════════════════════════════════════════════

def extract_logits(model, dataloader, device, model_name):
    """
    Run inference and extract raw logits from model.

    Args:
        model: Fine-tuned model
        dataloader: DataLoader for validation data
        device: CUDA device
        model_name: Name for logging

    Returns:
        logits_list: List of raw logit values (for vulnerable class)
        labels_list: Ground truth labels
        languages_list: Programming languages
    """
    logger.info(f"Running inference with {model_name}...")

    logits_list = []
    labels_list = []
    languages_list = []

    with torch.no_grad():
        for batch in tqdm(dataloader, desc=f"Extracting {model_name} logits"):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['label']
            languages = batch['language']

            # Forward pass
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)

            # Extract logits for class 1 (vulnerable)
            # Shape: [batch_size, 2] -> take column 1
            batch_logits = outputs.logits[:, 1].cpu().tolist()

            logits_list.extend(batch_logits)
            labels_list.extend(labels.tolist())
            languages_list.extend(languages)

    logger.info(f"Extracted {len(logits_list):,} logits from {model_name}")
    logger.info(f"Logit range: [{min(logits_list):.4f}, {max(logits_list):.4f}]")
    logger.info(f"Mean logit: {sum(logits_list)/len(logits_list):.4f}")

    return logits_list, labels_list, languages_list

# ═══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """
    Main execution pipeline:
    1. Load both LoRA models
    2. Load validation dataset
    3. Run inference with both models
    4. Merge results and export CSV
    """

    logger.info("=" * 80)
    logger.info("🚀 codeGuardian - Validation Logits Export")
    logger.info("=" * 80)

    # Device setup
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info(f"Device: {device}")
    if torch.cuda.is_available():
        logger.info(f"GPU: {torch.cuda.get_device_name(0)}")
        logger.info(f"CUDA Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

    # -------------------------------------------------------------------------
    # Step 1: Load Models
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("📦 LOADING MODELS")
    logger.info("=" * 80)

    # Load CodeBERT
    codebert_model, codebert_tokenizer = load_lora_model(
        CODEBERT_BASE,
        CODEBERT_ADAPTER_DIR,
        CODEBERT_CHECKPOINT,
        device
    )

    logger.info("")

    # Load GraphCodeBERT
    graphcodebert_model, graphcodebert_tokenizer = load_lora_model(
        GRAPHCODEBERT_BASE,
        GRAPHCODEBERT_ADAPTER_DIR,
        GRAPHCODEBERT_CHECKPOINT,
        device
    )

    # -------------------------------------------------------------------------
    # Step 2: Load Validation Dataset
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("📂 LOADING VALIDATION DATASET")
    logger.info("=" * 80)

    # Use CodeBERT tokenizer (both models use same RoBERTa tokenizer)
    val_dataset = ValidationDataset(VAL_DATA_PATH, codebert_tokenizer, MAX_LENGTH)

    val_loader = DataLoader(
        val_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
        num_workers=NUM_WORKERS,
        pin_memory=True if torch.cuda.is_available() else False
    )

    logger.info(f"Batch size: {BATCH_SIZE}")
    logger.info(f"Total batches: {len(val_loader):,}")

    # -------------------------------------------------------------------------
    # Step 3: Extract Logits from Both Models
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("🔍 EXTRACTING LOGITS")
    logger.info("=" * 80)

    # CodeBERT logits
    codebert_logits, labels, languages = extract_logits(
        codebert_model, val_loader, device, "CodeBERT-LoRA"
    )

    logger.info("")

    # GraphCodeBERT logits (reuse labels and languages from first pass)
    graphcodebert_logits, _, _ = extract_logits(
        graphcodebert_model, val_loader, device, "GraphCodeBERT-LoRA"
    )

    # -------------------------------------------------------------------------
    # Step 4: Merge and Export Results
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("💾 EXPORTING RESULTS")
    logger.info("=" * 80)

    # Create DataFrame
    results_df = pd.DataFrame({
        'language': languages,
        'logits_codebert': codebert_logits,
        'logits_graphcodebert': graphcodebert_logits,
        'y_true': labels
    })

    # Save to CSV
    os.makedirs(os.path.dirname(OUTPUT_CSV_PATH), exist_ok=True)
    results_df.to_csv(OUTPUT_CSV_PATH, index=False)

    logger.info(f"✅ Exported {len(results_df):,} samples to: {OUTPUT_CSV_PATH}")

    # -------------------------------------------------------------------------
    # Step 5: Validation Summary
    # -------------------------------------------------------------------------

    logger.info("\n" + "=" * 80)
    logger.info("📊 EXPORT SUMMARY")
    logger.info("=" * 80)

    logger.info(f"Total samples: {len(results_df):,}")
    logger.info(f"Output file: {OUTPUT_CSV_PATH}")
    logger.info(f"File size: {os.path.getsize(OUTPUT_CSV_PATH) / 1e6:.2f} MB")

    logger.info("\n## Sample Rows:")
    print(results_df.head(10).to_string(index=False))

    logger.info("\n## Statistics:")
    print(results_df.describe())

    logger.info("\n## Language Distribution:")
    print(results_df['language'].value_counts().to_string())

    logger.info("\n## Label Distribution:")
    print(results_df['y_true'].value_counts().to_string())

    # Correlation check
    correlation = results_df[['logits_codebert', 'logits_graphcodebert']].corr().iloc[0, 1]
    logger.info(f"\n## Model Correlation:")
    logger.info(f"CodeBERT ↔ GraphCodeBERT logits: {correlation:.4f}")

    logger.info("\n" + "=" * 80)
    logger.info("✅ LOGIT EXPORT COMPLETE")
    logger.info("=" * 80)
    logger.info("\nNext step: Run threshold_optimizer.py with this CSV file")
    logger.info(f"Command: python threshold_optimizer.py --input {OUTPUT_CSV_PATH}")
    logger.info("=" * 80)

if __name__ == "__main__":
    main()
