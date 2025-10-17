"""
Emergency Evaluation Script - Load Saved Checkpoint and Generate Test Metrics
=============================================================================
This script loads a saved checkpoint from training and runs final test evaluation.
Use this to salvage training results after the PyTorch 2.6 weights_only bug.

Usage:
    # First, find available checkpoints
    python eval_saved_checkpoint.py --find-checkpoints
    
    # Then use the checkpoint path shown
    python eval_saved_checkpoint.py --model codebert --checkpoint <path_from_above>
    
    # Or let it auto-find the latest checkpoint
    python eval_saved_checkpoint.py --model codebert --auto
"""

import argparse
import os
import sys
import gc
import torch
from pathlib import Path
import glob
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
# CHECKPOINT FINDER
# =============================================================================


def find_all_checkpoints():
    """
    Search for all checkpoint files in common locations
    
    Returns:
        List of tuples: (checkpoint_path, file_size_mb, modified_time)
    """
    print(f"\n{'='*70}")
    print("SEARCHING FOR CHECKPOINT FILES")
    print(f"{'='*70}")
    
    search_patterns = [
        "/kaggle/working/**/*.pt",
        "/kaggle/working/**/*.pth",
        "/kaggle/working/checkpoints/**/*",
        "/kaggle/input/**/*.pt",
        "/kaggle/input/**/*.pth",
        "./**/*.pt",
        "./**/*.pth",
    ]
    
    found_checkpoints = []
    
    for pattern in search_patterns:
        try:
            for file_path in glob.glob(pattern, recursive=True):
                if os.path.isfile(file_path):
                    size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    modified_time = os.path.getmtime(file_path)
                    found_checkpoints.append((file_path, size_mb, modified_time))
        except:
            pass
    
    # Remove duplicates and sort by modified time (newest first)
    seen = set()
    unique_checkpoints = []
    for cp in found_checkpoints:
        if cp[0] not in seen:
            seen.add(cp[0])
            unique_checkpoints.append(cp)
    
    unique_checkpoints.sort(key=lambda x: x[2], reverse=True)
    
    if unique_checkpoints:
        print(f"\n✓ Found {len(unique_checkpoints)} checkpoint file(s):\n")
        for i, (path, size_mb, mtime) in enumerate(unique_checkpoints, 1):
            from datetime import datetime
            mod_time_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{i}. {path}")
            print(f"   Size: {size_mb:.2f} MB | Modified: {mod_time_str}")
            print()
    else:
        print("\n❌ No checkpoint files found!")
        print("\nSearched in:")
        print("  - /kaggle/working/")
        print("  - /kaggle/input/")
        print("  - Current directory")
    
    return unique_checkpoints


def auto_find_checkpoint(model_type):
    """
    Automatically find the best checkpoint for the given model type
    
    Args:
        model_type: 'codebert' or 'graphcodebert'
    
    Returns:
        Path to checkpoint or None
    """
    print(f"\n{'='*70}")
    print(f"AUTO-FINDING {model_type.upper()} CHECKPOINT")
    print(f"{'='*70}")
    
    all_checkpoints = find_all_checkpoints()
    
    if not all_checkpoints:
        return None
    
    # Filter by model type
    model_checkpoints = [
        cp for cp in all_checkpoints 
        if model_type.lower() in cp[0].lower() or 'best' in cp[0].lower()
    ]
    
    if model_checkpoints:
        best_checkpoint = model_checkpoints[0][0]  # First one (newest)
        print(f"\n✓ Auto-selected: {best_checkpoint}")
        return best_checkpoint
    
    # Fallback: use the largest checkpoint
    if all_checkpoints:
        largest_checkpoint = max(all_checkpoints, key=lambda x: x[1])[0]
        print(f"\n✓ Auto-selected (largest): {largest_checkpoint}")
        return largest_checkpoint
    
    return None


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
        # Try to find checkpoint files
        print(f"❌ Checkpoint not found at: {checkpoint_path}")
        print("\n🔍 Searching for available checkpoints...")
        
        # Search in common locations
        search_dirs = [
            "/kaggle/working/checkpoints",
            "/kaggle/working",
            os.path.dirname(checkpoint_path) if checkpoint_path else None
        ]
        
        found_checkpoints = []
        for search_dir in search_dirs:
            if search_dir and os.path.exists(search_dir):
                print(f"\nSearching in: {search_dir}")
                for file in os.listdir(search_dir):
                    if file.endswith('.pt') or file.endswith('.pth'):
                        full_path = os.path.join(search_dir, file)
                        size_mb = os.path.getsize(full_path) / (1024 * 1024)
                        found_checkpoints.append((full_path, size_mb))
                        print(f"  ✓ Found: {file} ({size_mb:.2f} MB)")
        
        if found_checkpoints:
            print(f"\n💡 Found {len(found_checkpoints)} checkpoint file(s)")
            print("\nTo use a checkpoint, run:")
            for cp_path, size_mb in found_checkpoints:
                print(f"  python eval_saved_checkpoint.py --model codebert --checkpoint {cp_path}")
        else:
            print("\n❌ No checkpoint files found!")
            print("Expected locations checked:")
            for search_dir in search_dirs:
                if search_dir:
                    print(f"  - {search_dir}")
        
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
        outputs = model(
            input_ids=input_ids, attention_mask=attention_mask, labels=labels
        )

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
        description="Emergency evaluation of saved checkpoint",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find all available checkpoints
  python eval_saved_checkpoint.py --find-checkpoints
  
  # Auto-find and use latest checkpoint
  python eval_saved_checkpoint.py --model codebert --auto
  
  # Use specific checkpoint
  python eval_saved_checkpoint.py --model codebert --checkpoint /path/to/checkpoint.pt
        """
    )
    parser.add_argument(
        "--find-checkpoints",
        action="store_true",
        help="Search for all available checkpoint files and exit",
    )
    parser.add_argument(
        "--model",
        type=str,
        choices=["codebert", "graphcodebert"],
        help="Model type: codebert or graphcodebert",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Automatically find and use the latest checkpoint",
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
    
    # Handle find-checkpoints mode
    if args.find_checkpoints:
        find_all_checkpoints()
        print(f"\n{'='*70}")
        print("💡 USAGE")
        print(f"{'='*70}")
        print("\nTo evaluate a checkpoint, run:")
        print("  python eval_saved_checkpoint.py --model <codebert|graphcodebert> --checkpoint <path>")
        print("\nOr auto-find the latest checkpoint:")
        print("  python eval_saved_checkpoint.py --model <codebert|graphcodebert> --auto")
        return
    
    # Require model for evaluation
    if not args.model:
        parser.error("--model is required (unless using --find-checkpoints)")

    # Select config
    if args.model == "codebert":
        config = CodeBERTConfig()
    else:
        config = GraphCodeBERTConfig()
    
    # Auto-find checkpoint if requested
    if args.auto:
        auto_checkpoint = auto_find_checkpoint(args.model)
        if auto_checkpoint:
            config.CHECKPOINT_PATH = auto_checkpoint
        else:
            print("\n❌ Could not auto-find checkpoint!")
            print("Run with --find-checkpoints to see available checkpoints")
            sys.exit(1)

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
        print(
            f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB"
        )

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
