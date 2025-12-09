# Static Feature-Engineered Engine (Phase 2)

The **Static Engine** is a high-speed, lightweight vulnerability detection subsystem that relies on **107 engineered features** extracted from source code. Unlike the semantic engine (Deep Learning), this engine uses traditional Machine Learning (XGBoost) to provide deterministic and interpretable signals.

## 📂 File Structure

```
/codeGuardian/
├── src/ml/static/
│   ├── train_static.py          # Full training pipeline
│   └── README_STATIC_ENGINE.md  # This documentation
├── src/ml/inference/
│   └── inference_static.py      # Production inference engine
└── models/static/               # Artifact storage
    ├── static_model.pkl         # Trained XGBoost model
    ├── static_scaler.pkl        # Pre-processing pipeline (Imputer + Scaler)
    ├── static_training_report.json
    └── metadata.json            # Model versioning & Feature mapping
```

---

## 🚀 How to Run Training

The training script automatically handles missing values (Median Imputation), scaling (Standard/MinMax), and Cross-Validation.

**Command:**
```bash
python src/ml/static/train_static.py \
    --input datasets/processed/features_train.csv \
    --output-dir models/static \
    --model-type xgb \
    --scale standard \
    --cv-folds 5 \
    --seed 42
```

**Outputs:**
- Saves best model and scaler to `models/static/`
- Logs metrics (AUC, F1, etc.) to stdout and `training_log.txt`

---

## ⚡ How to Run Inference

The inference engine designed for **< 20ms** latency. It enforces strict feature schema validation.

### CLI Usage
```bash
# Using a JSON file input (List or Dict)
python src/ml/inference/inference_static.py --features-file sample_features.json

# Using raw CSV string (for quick tests)
python src/ml/inference/inference_static.py --features-raw "0.5, 12, 0.01, ... (107 values)"
```

### Python API Usage
```python
from src.ml.inference.inference_static import StaticInferenceEngine

engine = StaticInferenceEngine(models_dir="models/static")

# Input: Dict of features corresponding to metadata.json schema
result = engine.predict({"lines_of_code": 150, "complexity": 12, ...})

print(result)
# {
#   "probability": 0.85,
#   "class_label": 1,
#   "confidence": 0.7,
#   "inference_time_seconds": 0.005
# }
```

---

## 🔗 Integration with Fusion Layer

This component feeds into the **Fusion Layer** of CodeGuardian.

1. **Semantic Engine** outputs `prob_semantic`.
2. **Static Engine** outputs `prob_static` + `feature_vector`.
3. **Fusion Logic**:
   - IF Logic Agree → High Confidence Result.
   - IF Only Static flags High Risk (Score > 0.75) → Override Semantic (Safety fallback).
   - IF Disagreement + Borderline → TRIGGER EXPLAINABILITY.

This engine provides the "Syntax & Structure" viewpoint, complementing the "Semantic & Context" viewpoint of the Transformers.
