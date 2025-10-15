"""
Kaggle Notebook Cell Commands - Copy/Paste Ready
Run these cells in order in your Kaggle notebook
"""

# =========================================
# CELL 1: Clone Project Repository
# =========================================
"""
!git clone https://github.com/Harsh204k/codeGuardian.git /kaggle/working/codeGuardian
!ls -lh /kaggle/working/codeGuardian/src/ml/fine_tuning/
"""

# =========================================
# CELL 2: Install Dependencies
# =========================================
"""
!pip install -q transformers==4.36.0 torch==2.1.0 torchvision torchaudio
!pip install -q scikit-learn==1.3.2 tqdm==4.66.1
"""

# =========================================
# CELL 3: Verify Dataset Paths
# =========================================
"""
# Check that tokenized datasets exist
!ls -lh /kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/codebert/
!ls -lh /kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/graphcodebert/

# Verify .pt files
import torch
print("Checking CodeBERT train.pt...")
data = torch.load('/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/codebert/train.pt')
print(f"Keys: {data.keys()}")
print(f"Input IDs shape: {data['input_ids'].shape}")
print(f"Labels shape: {data['labels'].shape}")
"""

# =========================================
# CELL 4: Train CodeBERT (Final Layer Only)
# =========================================
"""
!python /kaggle/working/codeGuardian/src/ml/fine_tuning/train_codebert_classifier.py
"""

# =========================================
# CELL 5: Train GraphCodeBERT (Final Layer Only)
# =========================================
"""
!python /kaggle/working/codeGuardian/src/ml/fine_tuning/train_graphcodebert_classifier.py
"""

# =========================================
# CELL 6: View Results
# =========================================
"""
import json
import pandas as pd

# Load CodeBERT metrics
with open('/kaggle/working/checkpoints/codebert/eval_metrics.json') as f:
    codebert = json.load(f)

# Load GraphCodeBERT metrics
with open('/kaggle/working/checkpoints/graphcodebert/eval_metrics.json') as f:
    graphcodebert = json.load(f)

# Create comparison table
results = pd.DataFrame({
    'Model': ['CodeBERT', 'GraphCodeBERT'],
    'Test Accuracy': [
        codebert['test_metrics']['accuracy'],
        graphcodebert['test_metrics']['accuracy']
    ],
    'Test F1': [
        codebert['test_metrics']['f1_score'],
        graphcodebert['test_metrics']['f1_score']
    ],
    'Test Precision': [
        codebert['test_metrics']['precision'],
        graphcodebert['test_metrics']['precision']
    ],
    'Test Recall': [
        codebert['test_metrics']['recall'],
        graphcodebert['test_metrics']['recall']
    ],
    'Trainable Params': [
        codebert['config']['trainable_params'],
        graphcodebert['config']['trainable_params']
    ]
})

print("\\n" + "="*80)
print("STAGE A: FINAL LAYER TRAINING RESULTS")
print("="*80)
print(results.to_string(index=False))
print("="*80)

# Plot training history
import matplotlib.pyplot as plt

fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# CodeBERT Loss
epochs = [h['epoch'] for h in codebert['training_history']]
axes[0, 0].plot(epochs, [h['train_loss'] for h in codebert['training_history']], label='Train', marker='o')
axes[0, 0].plot(epochs, [h['val_loss'] for h in codebert['training_history']], label='Val', marker='s')
axes[0, 0].set_title('CodeBERT - Loss')
axes[0, 0].set_xlabel('Epoch')
axes[0, 0].set_ylabel('Loss')
axes[0, 0].legend()
axes[0, 0].grid(True)

# CodeBERT F1
axes[0, 1].plot(epochs, [h['train_f1'] for h in codebert['training_history']], label='Train', marker='o')
axes[0, 1].plot(epochs, [h['val_f1'] for h in codebert['training_history']], label='Val', marker='s')
axes[0, 1].set_title('CodeBERT - F1 Score')
axes[0, 1].set_xlabel('Epoch')
axes[0, 1].set_ylabel('F1 Score')
axes[0, 1].legend()
axes[0, 1].grid(True)

# GraphCodeBERT Loss
epochs_gcb = [h['epoch'] for h in graphcodebert['training_history']]
axes[1, 0].plot(epochs_gcb, [h['train_loss'] for h in graphcodebert['training_history']], label='Train', marker='o')
axes[1, 0].plot(epochs_gcb, [h['val_loss'] for h in graphcodebert['training_history']], label='Val', marker='s')
axes[1, 0].set_title('GraphCodeBERT - Loss')
axes[1, 0].set_xlabel('Epoch')
axes[1, 0].set_ylabel('Loss')
axes[1, 0].legend()
axes[1, 0].grid(True)

# GraphCodeBERT F1
axes[1, 1].plot(epochs_gcb, [h['train_f1'] for h in graphcodebert['training_history']], label='Train', marker='o')
axes[1, 1].plot(epochs_gcb, [h['val_f1'] for h in graphcodebert['training_history']], label='Val', marker='s')
axes[1, 1].set_title('GraphCodeBERT - F1 Score')
axes[1, 1].set_xlabel('Epoch')
axes[1, 1].set_ylabel('F1 Score')
axes[1, 1].legend()
axes[1, 1].grid(True)

plt.tight_layout()
plt.savefig('/kaggle/working/training_comparison.png', dpi=150, bbox_inches='tight')
plt.show()

print("\\n✅ Visualization saved to: /kaggle/working/training_comparison.png")
"""

# =========================================
# CELL 7: Download Checkpoints (Optional)
# =========================================
"""
# Create zip file for download
!cd /kaggle/working && zip -r stage_a_checkpoints.zip checkpoints/
!ls -lh /kaggle/working/stage_a_checkpoints.zip

# This will be available in Kaggle output section
"""

# =========================================
# CELL 8: Memory Check
# =========================================
"""
import torch

if torch.cuda.is_available():
    print(f"GPU Device: {torch.cuda.get_device_name(0)}")
    print(f"Memory Allocated: {torch.cuda.memory_allocated(0) / 1e9:.2f} GB")
    print(f"Memory Cached: {torch.cuda.memory_reserved(0) / 1e9:.2f} GB")
    print(f"Max Memory Allocated: {torch.cuda.max_memory_allocated(0) / 1e9:.2f} GB")
else:
    print("⚠️ No GPU available - training will be slow!")
"""
