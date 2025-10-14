# Tokenization Pipelines for Vulnerability Detection

This directory contains production-ready tokenization scripts for **CodeBERT** and **GraphCodeBERT** models.

## 📁 Files

```
src/ml/tokenization/
├── tokenize_codebert.py       # CodeBERT tokenization pipeline
├── tokenize_graphcodebert.py  # GraphCodeBERT tokenization pipeline
└── README.md                  # This file
```

## 🚀 Quick Start

### CodeBERT Tokenization

```bash
# Run in Kaggle notebook or local environment
python src/ml/tokenization/tokenize_codebert.py
```

**Outputs:**

```
/kaggle/working/datasets/tokenized/codebert/
├── train_tokenized_codebert.pt
├── val_tokenized_codebert.pt
├── test_tokenized_codebert.pt
├── tokenization_errors.jsonl
└── .cache/  # Cached tokenized data for faster re-runs
```

### GraphCodeBERT Tokenization

```bash
# Run in Kaggle notebook or local environment
python src/ml/tokenization/tokenize_graphcodebert.py
```

**Outputs:**

```
/kaggle/working/datasets/tokenized/graphcodebert/
├── train_tokenized_graphcodebert.pt
├── val_tokenized_graphcodebert.pt
├── test_tokenized_graphcodebert.pt
├── tokenization_errors.jsonl
└── .cache/  # Cached tokenized data for faster re-runs
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

## 🔍 Inspecting Tokenized Files

Use the inspection script to check tokenized files:

```bash
# Check train file
python scripts/check_tokenized.py datasets/tokenized/codebert/train_tokenized_codebert.pt

# Check val file
python scripts/check_tokenized.py datasets/tokenized/graphcodebert/val_tokenized_graphcodebert.pt

# Check test file
python scripts/check_tokenized.py datasets/tokenized/codebert/test_tokenized_codebert.pt
```

**Expected Output:**

```
Loaded: datasets/tokenized/codebert/train_tokenized_codebert.pt
Keys: ['input_ids', 'attention_mask', 'labels']
input_ids: shape=(507487, 512), dtype=torch.int64
attention_mask: shape=(507487, 512), dtype=torch.int64
labels: shape=(507487,), dtype=torch.int64
First 10 labels: [0, 1, 0, 0, 1, 0, 1, 0, 0, 1]
Label distribution: Counter({0: 450000, 1: 57487})
```

## ⚙️ Configuration

Both scripts use the `TokenizationConfig` dataclass with these key settings:

```python
@dataclass
class TokenizationConfig:
    # Model
    model_name: str = "microsoft/codebert-base"  # or "microsoft/graphcodebert-base"
    max_seq_length: int = 512

    # Processing
    batch_size: int = 128
    num_workers: int = 0  # Single-process for stability
    dynamic_padding: bool = True

    # Caching
    use_cache: bool = True
    force_retokenize: bool = False

    # Error handling
    skip_on_error: bool = True
    max_errors_per_split: int = 100

    # Validation
    strict_binary_labels: bool = True
    min_samples: int = 100
    max_label_imbalance: float = 0.95
```

## 🎯 Features

### ✅ Implemented

- **Chunked Batch Tokenization**: Processes 10k samples at a time to avoid OOM
- **Caching**: Saves tokenized data for faster re-runs
- **Error Resilience**: Skips problematic samples and logs errors
- **Validation**: Checks shapes, dtypes, and label distribution
- **Reproducibility**: Fixed random seed (42)
- **Progress Tracking**: tqdm progress bars
- **Sanity Checks**: Verifies saved files can be loaded

### 🔄 Pipeline Steps

1. **Load JSONL** files (train/val/test)
2. **Validate** required fields and label balance
3. **Extract** code snippets and labels
4. **Tokenize** in chunks (memory-safe)
5. **Validate** tokenized shapes and dtypes
6. **Save** to `.pt` files
7. **Cache** for future runs
8. **Sanity check** by reloading

## 🧪 Testing

Verify tokenization worked correctly:

```python
import torch

# Load tokenized data
data = torch.load("datasets/tokenized/codebert/train_tokenized_codebert.pt")

# Check structure
print(data.keys())  # ['input_ids', 'attention_mask', 'labels']
print(data['input_ids'].shape)  # torch.Size([507487, 512])
print(data['labels'][:10])  # First 10 labels
print(data['labels'].unique())  # Should be [0, 1]
```

## 📈 Performance

**Expected Runtime (507k samples):**

- **Tokenization**: ~5-10 minutes (chunked batch)
- **Validation**: ~1-2 minutes
- **Total**: ~7-12 minutes per split

**Memory Usage:**

- **Peak**: ~2-3 GB RAM
- **Output files**: ~1-2 GB per split

## 🔧 Troubleshooting

### Out of Memory (OOM)

If you get OOM errors, reduce chunk size:

```python
# In tokenize_dataset_batch function
chunk_size = 5000  # Reduce from 10000
```

### Cache Issues

Force retokenization by disabling cache:

```python
config.use_cache = False
# or
config.force_retokenize = True
```

### Label Imbalance Warnings

If you see "Extreme label imbalance" warnings, adjust threshold:

```python
config.max_label_imbalance = 0.98  # Allow up to 98% imbalance
```

## 🔗 Next Steps

After tokenization:

1. **Embeddings**: Generate embeddings using fine-tuned models
2. **Hybrid Models**: Combine CodeBERT + GraphCodeBERT embeddings
3. **Training**: Use tokenized data for classification tasks
4. **Inference**: Load tokenized test set for predictions

## 📚 References

- **CodeBERT**: https://huggingface.co/microsoft/codebert-base
- **GraphCodeBERT**: https://huggingface.co/microsoft/graphcodebert-base
- **Transformers**: https://huggingface.co/docs/transformers/

## 🐛 Known Issues

- **Windows**: Python path issues in terminal (use `py` instead of `python`)
- **Kaggle**: Paths are hardcoded for Kaggle environment
- **Multiprocessing**: Disabled due to pickle errors with file handles

## 📝 License

Part of the CodeGuardian project.
