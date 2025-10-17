"""
Emergency Evaluation Script - Load Saved Checkpoint and Generate Test Metrics
=============================================================================
This script loads a saved checkpoint from training and runs final test evaluation.
Use this to salvage training results after the PyTorch 2.6 weights_only bug.

Usage:
    python eval_saved_checkpoint.py --model codebert --checkpoint /kaggle/working/checkpoints/codebert_best_model.pt
    python eval_saved_checkpoint.py --model graphcodebert --checkpoint /kaggle/working/checkpoints/graphcodebert_best_model.pt
"""

import argparse
import os
import sys
import gc
import torch
from torch.utils.data import DataLoader, TensorDataset
from transformers import RobertaForSequenceClassification
from peft import LoraConfig, get_peft_model
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

# =============================================================================
# CONFIGURATION
# =============================================================================


class CodeBERTConfig:
    """Configuration for CodeBERT emergency evaluation"""

    # Model settings
    MODEL_NAME = "microsoft/codebert-base"
    MAX_LENGTH = 512
    NUM_LABELS = 2

    # Dataset paths (CHANGE THESE IF NEEDED)
    TEST_DATA_PATH = "/kaggle/input/datasets-codebert/test_data.pt"

    # Checkpoint path (CHANGE THIS IF NEEDED)
    CHECKPOINT_PATH = "/kaggle/working/checkpoints/codebert_best_model.pt"

    # Training settings (for model setup)
    BATCH_SIZE = 128
    LORA_R = 8
    LORA_ALPHA = 16
    LORA_DROPOUT = 0.05


class GraphCodeBERTConfig:
    """Configuration for GraphCodeBERT emergency evaluation"""

    # Model settings
    MODEL_NAME = "microsoft/graphcodebert-base"
    MAX_LENGTH = 512
    NUM_LABELS = 2

    # Dataset paths (CHANGE THESE IF NEEDED)
    TEST_DATA_PATH = "/kaggle/input/datasets-graphcodebert/test_data.pt"

    # Checkpoint path (CHANGE THIS IF NEEDED)
    CHECKPOINT_PATH = "/kaggle/working/checkpoints/graphcodebert_best_model.pt"

    # Training settings (for model setup)
    BATCH_SIZE = 128
    LORA_R = 8
    LORA_ALPHA = 16
    LORA_DROPOUT = 0.05


# =============================================================================
# DATA LOADING
# =============================================================================


def load_test_dataset(file_path):
    """
    Load test dataset from .pt file

    Args:
        file_path: Path to test_data.pt file

    Returns:
        DataLoader with test data
    """
    print(f"\n{'='*70}")
    print("LOADING TEST DATASET")
    print(f"{'='*70}")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Test dataset not found: {file_path}")

    # Load with weights_only=False to allow numpy objects
    data = torch.load(file_path, map_location="cpu", weights_only=False)

    # Extract tensors
    input_ids = data["input_ids"]
    attention_mask = data["attention_mask"]
    labels = data["labels"]

    print(f"✓ Loaded test data:")
    print(f"  - Samples: {len(input_ids):,}")
    print(f"  - Input IDs shape: {input_ids.shape}")
    print(f"  - Attention mask shape: {attention_mask.shape}")
    print(f"  - Labels shape: {labels.shape}")

    # Create dataset and dataloader
    dataset = TensorDataset(input_ids, attention_mask, labels)
    dataloader = DataLoader(
        dataset, batch_size=CodeBERTConfig.BATCH_SIZE, shuffle=False, pin_memory=True
    )

    return dataloader


# =============================================================================
# MODEL SETUP
# =============================================================================


def setup_model(config):
    """
    Setup model with LoRA configuration

    Args:
        config: Configuration object (CodeBERTConfig or GraphCodeBERTConfig)

    Returns:
        PEFT model with LoRA
    """
    print(f"\n{'='*70}")
    print("SETTING UP MODEL")
    print(f"{'='*70}")

    # Load base model
    print(f"Loading base model: {config.MODEL_NAME}")
    base_model = RobertaForSequenceClassification.from_pretrained(
        config.MODEL_NAME,
        num_labels=config.NUM_LABELS,
        problem_type="single_label_classification",
    )

    # LoRA configuration
    lora_config = LoraConfig(
        r=config.LORA_R,
        lora_alpha=config.LORA_ALPHA,
        lora_dropout=config.LORA_DROPOUT,
        bias="none",
        task_type="SEQ_CLS",
        target_modules=["query", "value"],
        modules_to_save=["classifier"],
    )

    # Apply LoRA
    model = get_peft_model(base_model, lora_config)

    print("✓ Model setup complete")
    model.print_trainable_parameters()

    return model


# =============================================================================
# CHECKPOINT LOADING
# =============================================================================


def load_checkpoint(model, checkpoint_path):
    """
    Load saved checkpoint into model

    Args:
        model: PEFT model
        checkpoint_path: Path to checkpoint file

    Returns:
        Dictionary with checkpoint info
    """
    print(f"\n{'='*70}")
    print("LOADING CHECKPOINT")
    print(f"{'='*70}")

    if not os.path.exists(checkpoint_path):
        raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")

    # Load with weights_only=False to allow numpy objects
    checkpoint = torch.load(checkpoint_path, weights_only=False, map_location="cpu")

    # Load state dict
    model.load_state_dict(checkpoint["model_state_dict"])

    print(f"✓ Loaded checkpoint from: {checkpoint_path}")
    print(f"  - Epoch: {checkpoint['epoch']}")
    print(f"  - Best F1: {checkpoint['best_f1']:.4f}")

    return checkpoint


# =============================================================================
# EVALUATION
# =============================================================================


@torch.no_grad()
def evaluate(model, dataloader, device):
    """
    Evaluate model on test set

    Args:
        model: PEFT model
        dataloader: Test dataloader
        device: Device to use

    Returns:
        Dictionary with metrics
    """
    print(f"\n{'='*70}")
    print("RUNNING TEST EVALUATION")
    print(f"{'='*70}")

    model.eval()
    model.to(device)

    all_preds = []
    all_labels = []
    total_loss = 0
    num_batches = 0

    # Progress tracking
    total_batches = len(dataloader)

    for batch_idx, batch in enumerate(dataloader):
        input_ids, attention_mask, labels = [b.to(device) for b in batch]

        # Forward pass
        outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)

        # Collect predictions
        preds = torch.argmax(outputs.logits, dim=1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

        # Accumulate loss
        total_loss += outputs.loss.item()
        num_batches += 1

        # Progress
        if (batch_idx + 1) % 50 == 0 or (batch_idx + 1) == total_batches:
            progress = (batch_idx + 1) / total_batches * 100
            print(
                f"  Progress: {batch_idx+1}/{total_batches} batches ({progress:.1f}%)",
                end="\r",
            )

    print()  # New line after progress

    # Calculate metrics
    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)

    accuracy = accuracy_score(all_labels, all_preds)
    precision = precision_score(all_labels, all_preds, zero_division=0)
    recall = recall_score(all_labels, all_preds, zero_division=0)
    f1 = f1_score(all_labels, all_preds, zero_division=0)
    avg_loss = total_loss / num_batches

    # Confusion matrix
    cm = confusion_matrix(all_labels, all_preds)

    metrics = {
        "loss": avg_loss,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": cm,
    }

    return metrics


# =============================================================================
# MAIN FUNCTION
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Emergency evaluation of saved checkpoint"
    )
    parser.add_argument(
        "--model",
        type=str,
        choices=["codebert", "graphcodebert"],
        required=True,
        help="Model type: codebert or graphcodebert",
    )
    parser.add_argument(
        "--checkpoint",
        type=str,
        help="Path to checkpoint file (optional, uses config default if not provided)",
    )
    parser.add_argument(
        "--test-data",
        type=str,
        help="Path to test data file (optional, uses config default if not provided)",
    )

    args = parser.parse_args()

    # Select config
    if args.model == "codebert":
        config = CodeBERTConfig()
    else:
        config = GraphCodeBERTConfig()

    # Override paths if provided
    if args.checkpoint:
        config.CHECKPOINT_PATH = args.checkpoint
    if args.test_data:
        config.TEST_DATA_PATH = args.test_data

    print(f"\n{'='*70}")
    print(f"EMERGENCY EVALUATION - {args.model.upper()}")
    print(f"{'='*70}")
    print(f"Checkpoint: {config.CHECKPOINT_PATH}")
    print(f"Test data: {config.TEST_DATA_PATH}")

    # Setup device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\nUsing device: {device}")

    if torch.cuda.is_available():
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

    try:
        # Load test dataset
        test_loader = load_test_dataset(config.TEST_DATA_PATH)

        # Setup model
        model = setup_model(config)

        # Load checkpoint
        checkpoint_info = load_checkpoint(model, config.CHECKPOINT_PATH)

        # Evaluate
        test_metrics = evaluate(model, test_loader, device)

        # Print results
        print(f"\n{'='*70}")
        print("TEST EVALUATION RESULTS")
        print(f"{'='*70}")
        print(f"\n📊 Checkpoint Info:")
        print(f"  - Training Epoch: {checkpoint_info['epoch']}")
        print(f"  - Best Validation F1: {checkpoint_info['best_f1']:.4f}")

        print(f"\n📊 Test Metrics:")
        print(f"  - Loss: {test_metrics['loss']:.4f}")
        print(f"  - Accuracy: {test_metrics['accuracy']:.4f}")
        print(f"  - Precision: {test_metrics['precision']:.4f}")
        print(f"  - Recall: {test_metrics['recall']:.4f}")
        print(f"  - F1 Score: {test_metrics['f1']:.4f}")

        print(f"\n📊 Confusion Matrix:")
        cm = test_metrics["confusion_matrix"]
        print(f"  [[TN={cm[0,0]:>6}  FP={cm[0,1]:>6}]")
        print(f"   [FN={cm[1,0]:>6}  TP={cm[1,1]:>6}]]")

        print(f"\n{'='*70}")
        print("✅ EVALUATION COMPLETE!")
        print(f"{'='*70}")

        # Cleanup
        del model
        torch.cuda.empty_cache()
        gc.collect()

    except Exception as e:
        print(f"\n{'='*70}")
        print("❌ EVALUATION FAILED")
        print(f"{'='*70}")
        print(f"Error: {str(e)}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
