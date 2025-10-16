#type: ignore

"""
KAGGLE QUICK REFERENCE - Copy and paste this into Kaggle Notebook
====================================================================

This is a complete, ready-to-run Kaggle notebook cell that you can copy
and paste directly into Kaggle to run the fine-tuning scripts.
"""

# ============================================================================
# CELL 1: Install Dependencies
# ============================================================================
print("Uninstalling conflicting packages...")
!pip uninstall -y sentence-transformers datasets featuretools umap-learn libcugraph-cu12 pydantic pylibraft-cu12 rmm-cu12

print("\nInstalling dependencies...")
!pip install -q transformers==4.36.0 peft==0.7.1 scikit-learn tqdm

# Install CUDA-specific packages (if needed)
print("\nInstalling CUDA packages...")
!pip install -q "pydantic>=2.0,<2.12"

print("\n✓ All dependencies installed successfully!")

# ============================================================================
# CELL 2: Verify Dataset
# ============================================================================
import os

print("\nVerifying dataset...")

# Check CodeBERT dataset
codebert_path = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/codebert"
if os.path.exists(codebert_path):
    print(f"✓ CodeBERT dataset found: {codebert_path}")
    print(f"  Files: {os.listdir(codebert_path)}")
else:
    print(f"❌ CodeBERT dataset not found: {codebert_path}")

# Check GraphCodeBERT dataset
graphcodebert_path = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/tokenized/graphcodebert"
if os.path.exists(graphcodebert_path):
    print(f"✓ GraphCodeBERT dataset found: {graphcodebert_path}")
    print(f"  Files: {os.listdir(graphcodebert_path)}")
else:
    print(f"❌ GraphCodeBERT dataset not found: {graphcodebert_path}")

# ============================================================================
# CELL 3: Check GPU
# ============================================================================
import torch

print("\nChecking GPU...")
print(f"CUDA Available: {torch.cuda.is_available()}")
if torch.cuda.is_available():
    print(f"Device: {torch.cuda.get_device_name(0)}")
    print(f"Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")
else:
    print("⚠️  No GPU detected! Enable GPU in Settings → Accelerator")

# ============================================================================
# CELL 4A: Run CodeBERT Training
# ============================================================================
# Upload train_codebert_lora.py to your Kaggle notebook first, then run:
print("\n" + "="*70)
print("STARTING CODEBERT TRAINING")
print("="*70 + "\n")

!python /kaggle/working/train_codebert_lora.py

# ============================================================================
# CELL 4B: OR Run GraphCodeBERT Training
# ============================================================================
# Upload train_graphcodebert_lora.py to your Kaggle notebook first, then run:
print("\n" + "="*70)
print("STARTING GRAPHCODEBERT TRAINING")
print("="*70 + "\n")

!python /kaggle/working/train_graphcodebert_lora.py

# ============================================================================
# CELL 5: Check Results
# ============================================================================
import json

print("\n" + "="*70)
print("TRAINING RESULTS")
print("="*70 + "\n")

# Check for CodeBERT results
codebert_metrics = "/kaggle/working/checkpoints/codebert_eval_metrics.json"
if os.path.exists(codebert_metrics):
    print("✓ CodeBERT Training Complete!")
    with open(codebert_metrics, 'r') as f:
        metrics = json.load(f)

    print("\nCodeBERT Test Results:")
    print(f"  - Accuracy:  {metrics['test']['accuracy']:.4f}")
    print(f"  - F1-Score:  {metrics['test']['f1']:.4f}")
    print(f"  - Precision: {metrics['test']['precision']:.4f}")
    print(f"  - Recall:    {metrics['test']['recall']:.4f}")
    print(f"  - Loss:      {metrics['test']['loss']:.4f}")

# Check for GraphCodeBERT results
graphcodebert_metrics = "/kaggle/working/checkpoints/graphcodebert_eval_metrics.json"
if os.path.exists(graphcodebert_metrics):
    print("\n✓ GraphCodeBERT Training Complete!")
    with open(graphcodebert_metrics, 'r') as f:
        metrics = json.load(f)

    print("\nGraphCodeBERT Test Results:")
    print(f"  - Accuracy:  {metrics['test']['accuracy']:.4f}")
    print(f"  - F1-Score:  {metrics['test']['f1']:.4f}")
    print(f"  - Precision: {metrics['test']['precision']:.4f}")
    print(f"  - Recall:    {metrics['test']['recall']:.4f}")
    print(f"  - Loss:      {metrics['test']['loss']:.4f}")

# List saved models
print("\n" + "="*70)
print("SAVED MODELS")
print("="*70 + "\n")

checkpoint_dir = "/kaggle/working/checkpoints"
if os.path.exists(checkpoint_dir):
    files = os.listdir(checkpoint_dir)
    for file in files:
        file_path = os.path.join(checkpoint_dir, file)
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        print(f"✓ {file} ({size_mb:.2f} MB)")
else:
    print("❌ No checkpoints found")

# ============================================================================
# CELL 6: Load and Test Model (Optional)
# ============================================================================
import torch
import torch.nn as nn
from transformers import RobertaModel, RobertaConfig, RobertaTokenizer

# Define model class (must match training script)
class CodeBERTForVulnerabilityDetection(nn.Module):
    def __init__(self, model_name: str, num_labels: int = 2):
        super().__init__()
        self.config = RobertaConfig.from_pretrained(model_name)
        self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)
        self.classifier = nn.Sequential(
            nn.Dropout(0.1),
            nn.Linear(self.config.hidden_size, num_labels)
        )
        for param in self.roberta.parameters():
            param.requires_grad = False

    def forward(self, input_ids, attention_mask):
        outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = outputs.pooler_output
        logits = self.classifier(pooled_output)
        return logits

# Load model
print("\nLoading trained model...")
model = CodeBERTForVulnerabilityDetection('microsoft/codebert-base', num_labels=2)
checkpoint = torch.load('/kaggle/working/checkpoints/codebert_final_layer.pt')
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()
model = model.to('cuda' if torch.cuda.is_available() else 'cpu')

print(f"✓ Model loaded from epoch {checkpoint['epoch']}")
print(f"  Best F1: {checkpoint['best_f1']:.4f}")

# Test inference
tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')

test_code = """
def authenticate(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    return execute_query(query)
"""

print("\nTesting inference...")
print(f"Code: {test_code[:100]}...")

inputs = tokenizer(
    test_code,
    max_length=512,
    padding='max_length',
    truncation=True,
    return_tensors='pt'
)

device = 'cuda' if torch.cuda.is_available() else 'cpu'
inputs = {k: v.to(device) for k, v in inputs.items()}

with torch.no_grad():
    logits = model(inputs['input_ids'], inputs['attention_mask'])
    prediction = torch.argmax(logits, dim=1).item()
    confidence = torch.softmax(logits, dim=1)[0][prediction].item()

print(f"\nPrediction: {'Vulnerable' if prediction == 1 else 'Non-vulnerable'}")
print(f"Confidence: {confidence:.4f}")

# ============================================================================
# CELL 7: Download Models (Optional)
# ============================================================================
print("\n" + "="*70)
print("DOWNLOAD INSTRUCTIONS")
print("="*70 + "\n")

print("To download your trained models:")
print("1. Click on the 'Output' tab in the right sidebar")
print("2. Find the 'checkpoints' folder")
print("3. Click the download button")
print("\nOr use the Kaggle API:")
print("  kaggle kernels output <your-username>/<kernel-name>")

print("\n✓ Training Complete! Your models are ready to use.")
