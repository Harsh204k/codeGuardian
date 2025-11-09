# 🧠 codeGuardian Semantic Inference Module

**Version:** 1.0-FINAL
**Author:** Urva Gandhi
**Status:** Production-Ready (Frozen)

---

## 📋 Overview

The **Semantic Inference Engine** provides production-grade vulnerability detection using an ensemble of LoRA-fine-tuned CodeBERT and GraphCodeBERT models with temperature-scaled probability calibration.

### Key Features

✅ **Dual-Model Ensemble** - CodeBERT + GraphCodeBERT with configurable weights
✅ **Temperature Scaling** - Post-training probability calibration
✅ **Per-Language Thresholds** - Optimized decision boundaries per language
✅ **Abstention Mechanism** - Flags low-confidence predictions
✅ **GPU/CPU Auto-Detection** - Automatic device selection with FP16 optimization
✅ **Memory-Efficient** - Automatic cleanup and disposal methods
✅ **CLI + Import Support** - Standalone execution or orchestrator integration
✅ **Comprehensive Metadata** - Full traceability with adapter checksums

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│              Input: Code + Language                 │
└────────────────┬────────────────────────────────────┘
                 │
                 ├──────────────┬
                 ▼              ▼
         ┌──────────────┐ ┌──────────────┐
         │  CodeBERT    │ │GraphCodeBERT │
         │  + LoRA      │ │  + LoRA      │
         └──────┬───────┘ └──────┬───────┘
                │                │
                ▼                ▼
         ┌──────────────┐ ┌──────────────┐
         │ Temperature  │ │ Temperature  │
         │  Scaling     │ │  Scaling     │
         └──────┬───────┘ └──────┬───────┘
                │                │
                └────────┬───────┘
                         ▼
                  ┌──────────────┐
                  │   Weighted   │
                  │   Ensemble   │
                  └──────┬───────┘
                         ▼
                  ┌──────────────┐
                  │  Threshold   │
                  │  Application │
                  └──────┬───────┘
                         ▼
                  ┌──────────────┐
                  │   JSON       │
                  │   Output     │
                  └──────────────┘
```

---

## 📦 Dependencies

```python
torch >= 2.0.0
transformers >= 4.30.0
peft >= 0.4.0
```

---

## 🚀 Usage

### CLI Interface

#### Basic Usage
```bash
# Analyze a file
python inference_semantic.py --code path/to/file.c --language C

# Analyze inline code
python inference_semantic.py --code "int main() { return 0; }" --language C

# Save output to file
python inference_semantic.py --code file.py --language Python --output result.json
```

#### Advanced Options
```bash
# Custom configuration
python inference_semantic.py \
  --code vulnerable.c \
  --language C \
  --config custom_ensemble_config.json

# Force CPU execution
python inference_semantic.py --code file.py --language Python --device cpu

# Custom adapter paths
python inference_semantic.py \
  --code file.c \
  --language C \
  --codebert-adapter /path/to/codebert_lora \
  --graphcodebert-adapter /path/to/graphcodebert_lora

# Quiet mode (JSON only)
python inference_semantic.py --code file.c --language C --quiet
```

### Python API

#### Simple Usage
```python
from src.ml.inference.inference_semantic import run_inference

# Run inference
result = run_inference({
    "code": "int main() { char buf[10]; gets(buf); }",
    "language": "C",
    "metadata": {"file": "vuln.c", "commit": "abc123"}
})

print(f"Status: {result['status']}")
print(f"Probability: {result['vulnerability_probability']}")
print(f"Confidence: {result['confidence_level']}")
```

#### Reusable Engine (Recommended for Batch Processing)
```python
from src.ml.inference.inference_semantic import SemanticInferenceEngine

# Initialize once
engine = SemanticInferenceEngine(
    config_path="ensemble_config.json"
)

# Run multiple inferences
for code_snippet in code_samples:
    result = engine.infer(
        code=code_snippet["code"],
        language=code_snippet["language"],
        metadata={"id": code_snippet["id"]}
    )
    # Process result...

# Clean up when done
engine.dispose()
```

---

## 📄 Configuration Schema

### Ensemble Config (`ensemble_config.json`)

The inference engine supports **two schema formats**:

#### New Schema (Recommended)
```json
{
  "models": {
    "codebert": {
      "weight": 0.4,
      "temperature": 0.5974
    },
    "graphcodebert": {
      "weight": 0.6,
      "temperature": 0.4329
    }
  },
  "thresholds": {
    "global": 0.6601,
    "abstain_margin": 0.05,
    "per_language": {
      "c": 0.6601,
      "python": 0.6825,
      "java": 0.6492
    }
  },
  "metadata": {
    "calibration_date": "2025-11-09",
    "validation_f1": 0.8734
  }
}
```

#### Legacy Schema (Still Supported)
```json
{
  "weights": {
    "codebert": 0.4,
    "graphcodebert": 0.6
  },
  "temperatures": {
    "codebert": 0.5974,
    "graphcodebert": 0.4329
  },
  "thresholds": {
    "global": 0.6601,
    "abstain_margin": 0.05,
    "per_language": {
      "c": 0.6601
    }
  }
}
```

### Configuration Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `weights` | Object | Model ensemble weights (must sum to 1.0) |
| `temperatures` | Object | Temperature scaling factors (0 < T ≤ 2.0) |
| `thresholds.global` | Float | Default classification threshold |
| `thresholds.abstain_margin` | Float | Distance from threshold to abstain |
| `thresholds.per_language` | Object | Language-specific thresholds (optional) |

---

## 📊 Output Schema

```json
{
  "status": "vulnerable",
  "language": "C",
  "vulnerability_probability": 0.8327,
  "is_vulnerable": true,
  "confidence_level": "High",
  "threshold_used": 0.6601,
  "abstained": false,
  "model_breakdown": {
    "codebert_prob": 0.7982,
    "graphcodebert_prob": 0.8493,
    "weights": {
      "codebert": 0.4,
      "graphcodebert": 0.6
    },
    "temperatures": {
      "codebert": 0.5974,
      "graphcodebert": 0.4329
    }
  },
  "metadata": {
    "adapter_sha": {
      "codebert": "00ae16d0d707f94dd81c9fa13f488bda",
      "graphcodebert": "9c3218ac5225ec6a6fab67535c7fd474"
    },
    "timestamp": "2025-11-09T14:32:17Z",
    "inference_time_seconds": 1.24,
    "source_file": "main.c"
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `status` | String | Canonical status: `"secure"`, `"vulnerable"`, or `"abstained"` |
| `vulnerability_probability` | Float | Ensemble probability (0.0 - 1.0) |
| `is_vulnerable` | Bool/Null | Classification result (null if abstained) |
| `confidence_level` | String | `"High"`, `"Medium"`, `"Low"`, or `"Abstained"` |
| `threshold_used` | Float | Decision threshold applied |
| `abstained` | Bool | Whether prediction was abstained |
| `model_breakdown` | Object | Individual model probabilities and parameters |
| `metadata.adapter_sha` | Object | MD5 checksums of adapter weights |
| `metadata.timestamp` | String | UTC timestamp (ISO 8601) |
| `metadata.inference_time_seconds` | Float | Inference duration |

---

## 🎯 Exit Codes

When used as a CLI tool, the script returns:

| Code | Status | Description |
|------|--------|-------------|
| 0 | Secure | Code is predicted secure |
| 1 | Vulnerable | Code is predicted vulnerable |
| 2 | Abstained | Low confidence, no prediction |
| 3 | Error | Execution error occurred |

---

## 🔧 Advanced Features

### Memory Management

For long-running sessions or batch processing, use the `dispose()` method:

```python
engine = SemanticInferenceEngine()

# Process many files...
for file in files:
    result = engine.infer(...)

# Clean up GPU memory
engine.dispose()
```

### Custom Device Selection

```python
# Force CPU (e.g., for debugging)
engine = SemanticInferenceEngine(device="cpu")

# Force CUDA
engine = SemanticInferenceEngine(device="cuda")

# Auto-detect (default)
engine = SemanticInferenceEngine(device=None)
```

### Language Normalization

Language names are **case-insensitive**:
- `"C"`, `"c"` → normalized to `"c"`
- `"Python"`, `"python"`, `"PYTHON"` → normalized to `"python"`

Per-language thresholds in config are also case-insensitive.

---

## 🧪 Testing

### Quick Test
```bash
# Test with vulnerable code
echo 'int main() { char buf[10]; gets(buf); }' > test.c
python inference_semantic.py --code test.c --language C

# Expected: status="vulnerable", high probability
```

### Validation Test
```python
from src.ml.inference.inference_semantic import SemanticInferenceEngine

engine = SemanticInferenceEngine()

# Test case 1: Buffer overflow (should be vulnerable)
result = engine.infer(
    code='int main() { char buf[10]; gets(buf); }',
    language='C'
)
assert result['status'] == 'vulnerable'

# Test case 2: Safe code (should be secure)
result = engine.infer(
    code='int main() { return 0; }',
    language='C'
)
assert result['status'] == 'secure'

engine.dispose()
```

---

## 🔍 Troubleshooting

### Issue: "Configuration file not found"
**Solution:** Ensure `ensemble_config.json` exists in the working directory, or provide the path via `--config`.

### Issue: "Adapter not found"
**Solution:** Check adapter paths. Default paths are:
- `/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_codebert`
- `/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/lora_output_graphcodebert`

Override with `--codebert-adapter` and `--graphcodebert-adapter`.

### Issue: Out of Memory (OOM)
**Solution:**
1. Use `engine.dispose()` after batch processing
2. Reduce batch size if processing multiple files
3. Force CPU mode with `--device cpu`

### Issue: Unexpected tokenizer class
**Solution:** Ensure base models are `microsoft/codebert-base` and `microsoft/graphcodebert-base` (both use RobertaTokenizer).

---

## 📈 Performance

### Inference Speed (Single Sample)

| Device | Precision | Time |
|--------|-----------|------|
| NVIDIA T4 | FP16 | ~1.2s |
| NVIDIA T4 | FP32 | ~1.8s |
| CPU (8 cores) | FP32 | ~4.5s |

### Memory Usage

| Device | Memory |
|--------|--------|
| CUDA (FP16) | ~3.2 GB VRAM |
| CUDA (FP32) | ~5.8 GB VRAM |
| CPU | ~2.5 GB RAM |

---

## 🔗 Integration Examples

### Flask API
```python
from flask import Flask, request, jsonify
from src.ml.inference.inference_semantic import SemanticInferenceEngine

app = Flask(__name__)
engine = SemanticInferenceEngine()

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    result = engine.infer(
        code=data['code'],
        language=data['language']
    )
    return jsonify(result)

if __name__ == '__main__':
    app.run(port=5000)
```

### CI/CD Pipeline
```bash
#!/bin/bash
# Run inference on changed files

for file in $(git diff --name-only HEAD~1); do
    if [[ $file == *.c ]]; then
        python inference_semantic.py --code "$file" --language C --quiet > result.json
        status=$(jq -r '.status' result.json)
        if [ "$status" == "vulnerable" ]; then
            echo "❌ Vulnerability detected in $file"
            exit 1
        fi
    fi
done
```

---

## 📚 References

- **Training Scripts:** `src/ml/fine_tuning/train_*_lora_vFinalStable.py`
- **Calibration:** `src/ml/fine_tuning/threshold_optimizer.py`
- **Tokenization:** `src/ml/tokenization/tokenize_*_vFinal.py`
- **Models:** `microsoft/codebert-base`, `microsoft/graphcodebert-base`

---

## 📝 Changelog

### v1.0-FINAL (2025-11-09)
- ✅ Initial production release
- ✅ Dual-model ensemble with LoRA adapters
- ✅ Temperature scaling and per-language thresholds
- ✅ CLI and Python API
- ✅ Comprehensive metadata and logging
- ✅ Memory management with dispose()
- ✅ Backward-compatible config schema
- ✅ Exit code constants
- ✅ FP16 optimization for CUDA
- ✅ Case-insensitive language matching
- ✅ Multiple adapter file format support

---

## 🤝 Contributing

This module is **frozen for production**. For bug reports or feature requests, contact the codeGuardian team.

---

## 📄 License

Part of the codeGuardian project. All rights reserved.

---

**🎉 Ready for Production Deployment**
