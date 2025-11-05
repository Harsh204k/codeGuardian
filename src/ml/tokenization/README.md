# Tokenization Pipelines for Vulnerability Detection

This directory contains production-ready tokenization scripts for **CodeBERT** and **GraphCodeBERT** models using a **pure-code architecture**.

## 🎯 Pure-Code Architecture

These tokenizers follow the codeGuardian philosophy:
- ✅ **Raw code only** - No engineered features, ASTs, or analytics
- ✅ **JSONL input** - Stratified splits from final dataset
- ✅ **Minimal output** - Only `input_ids`, `attention_mask`, `labels`
- ✅ **Memory efficient** - Streaming processing with progress bars
- ✅ **Exception safe** - Graceful handling of bad data

## 📁 Files

```
src/ml/tokenization/
├── tokenize_codebert.py          # CodeBERT tokenization pipeline
├── tokenize_graphcodebert.py     # GraphCodeBERT tokenization pipeline
├── run_both_tokenizations.py     # Orchestrator script
├── validate_tokenization.ipynb   # Validation notebook
└── README.md                      # This file
```

## 🚀 Quick Start

### Run Both Tokenizers

```bash
# Orchestrate both pipelines
python src/ml/tokenization/run_both_tokenizations.py
```

### CodeBERT Tokenization (Individual)

```bash
python src/ml/tokenization/tokenize_codebert.py
```

**Outputs:**

```
/kaggle/working/tokenized/codebert/
├── train_tokenized.pt
├── val_tokenized.pt
└── test_tokenized.pt
```

### GraphCodeBERT Tokenization (Individual)

```bash
python src/ml/tokenization/tokenize_graphcodebert.py
```

**Outputs:**

```
/kaggle/working/tokenized/graphcodebert/
├── train_tokenized.pt
├── val_tokenized.pt
└── test_tokenized.pt
```

## 📊 Output Format

Each `.pt` file contains a dictionary with:

```python
{
    'input_ids': torch.Tensor,        # Shape: [N, 512], dtype: torch.long
    'attention_mask': torch.Tensor,   # Shape: [N, 512], dtype: torch.long
    'labels': torch.Tensor            # Shape: [N], dtype: torch.long (0 or 1)
}
```

Where:

- `N` = number of samples
- `512` = max sequence length
- Labels: `0` = non-vulnerable, `1` = vulnerable

**Note:** No engineered features are included. This is pure-code tokenization.

## ✅ Validation

After tokenization, run the validation notebook to verify data integrity:

```bash
# In Kaggle/Jupyter
jupyter notebook src/ml/tokenization/validate_tokenization.ipynb
```

The validation checks:

1. ✅ Row counts match JSONL source files
2. ✅ Label distributions are preserved
3. ✅ No data loss during tokenization
4. ✅ CodeBERT and GraphCodeBERT outputs are consistent
5. ✅ Tensor shapes are correct (N, 512)
6. ✅ Label values are binary (0 or 1)

## 🔍 Expected Results

**Dataset Split Sizes (from JSONL):**

- Train: ~507k samples
- Val: ~72k samples
- Test: ~72k samples

**Tokenization Statistics:**

- Skip rate: <0.1%
- Average tokens: ~250-350 (varies by dataset)
- Output file sizes: ~1-2 GB per split per model

## ⚙️ Configuration

Both scripts use minimal configuration for simplicity:

```python
MODEL_NAME = "microsoft/codebert-base"  # or graphcodebert-base
INPUT_DIR = "/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted"
OUTPUT_DIR = f"/kaggle/working/tokenized/{model_name}"
MAX_LENGTH = 512
```

## 🎯 Key Features

### ✅ Implemented

- **Pure-Code Architecture**: No engineered features, only raw code
- **JSONL Streaming**: Memory-efficient line-by-line processing
- **Exception Safety**: Skips bad samples, logs errors
- **Progress Tracking**: Real-time tqdm progress bars
- **Validation**: Built-in shape and label checks
- **Reproducibility**: Deterministic processing
- **Cross-Platform**: Works on Kaggle, Colab, local

### 🔄 Pipeline Steps

1. **Load JSONL** files (train/val/test) line-by-line
2. **Validate** code and label fields
3. **Tokenize** with truncation to 512 tokens
4. **Stack** into tensors (batch format)
5. **Save** to `.pt` files
6. **Validate** shapes and label distributions
7. **Report** statistics and file sizes

## 🧪 Testing

Verify tokenization worked correctly:

```python
import torch

# Load tokenized data
data = torch.load("/kaggle/working/tokenized/codebert/train_tokenized.pt")

# Check structure
print(data.keys())  # ['input_ids', 'attention_mask', 'labels']
print(data['input_ids'].shape)  # torch.Size([507487, 512])
print(data['labels'][:10])  # First 10 labels
print(data['labels'].unique())  # Should be [0, 1]

# Check label distribution
print(torch.bincount(data['labels']))  # Class balance
```

## 📈 Performance

**Expected Runtime (per model, 650k total samples):**

- Tokenization: ~3-5 minutes
- Validation: ~30 seconds
- Total: ~4-6 minutes per model

**Memory Usage:**

- Peak RAM: ~2-3 GB
- Output files: ~3-4 GB total per model

## 🔧 Troubleshooting

### File Not Found Errors

Ensure JSONL files exist at:

```bash
/kaggle/input/codeguardian-dataset-for-model-fine-tuning/random_splitted/
├── train.jsonl
├── val.jsonl
└── test.jsonl
```

### Tokenizer Download Issues

If tokenizer download fails:

```python
# Pre-download in separate cell
from transformers import AutoTokenizer
AutoTokenizer.from_pretrained("microsoft/codebert-base")
AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
```

### Out of Memory

Reduce batch processing (already optimized for streaming):

```python
# Scripts already use streaming, but if issues persist:
# Process in smaller chunks by modifying the script
```

## 🔗 Next Steps

After successful tokenization:

1. **Validate**: Run `validate_tokenization.ipynb`
2. **Fine-Tune**: Use `train_codebert_lora.py`
3. **Train GraphCodeBERT**: Use `train_graphcodebert_lora.py` (to be created)
4. **Create Ensemble**: Combine both models for hybrid predictions

## 📚 References

- **CodeBERT**: <https://huggingface.co/microsoft/codebert-base>
- **GraphCodeBERT**: <https://huggingface.co/microsoft/graphcodebert-base>
- **Transformers**: <https://huggingface.co/docs/transformers/>

## 🐛 Known Issues

- **None** - Scripts are production-ready and tested

## 📝 Architecture Notes

This pipeline implements the **pure-code approach** validated by research:

- Transformers learn code semantics directly from tokens
- No need for hand-crafted features or AST parsing
- Simpler pipeline = fewer failure points
- Better generalization across languages

## � License

Part of the CodeGuardian project by Urva Gandhi.
