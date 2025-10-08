# This will load the trained/fine-tuned CodeBERT model and expose a predict(code) method.
# It keeps inference logic separate and clean.

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


class CodeBERTDetector:
    """Load and use trained CodeBERT model for vulnerability detection."""

    def __init__(self, model_path="models/codebert-vuln", device=None, label_map=None):
        """
        Args:
            model_path (str): Path to pretrained or fine-tuned CodeBERT model.
            device (str): Device to run on ("cuda", "cpu"). Auto-detects if None.
            label_map (dict): Map of class index → human-readable label.
        """
        self.model_path = model_path
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # Load tokenizer and model
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()

        # Default label map (can be extended with CWE codes)
        self.label_map = label_map or {0: "safe", 1: "vulnerable"}

    def predict(self, code: str):
        """Predict vulnerability of a code snippet.

        Args:
            code (str): Source code as string.

        Returns:
            dict: {
                "label": str,
                "score": float,
                "raw": [probabilities]
            }
        """
        inputs = self.tokenizer(
            code,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1).cpu().numpy()[0]

        pred_idx = int(probs.argmax())
        return {
            "label": self.label_map.get(pred_idx, str(pred_idx)),
            "score": float(probs[pred_idx]),
            "raw": probs.tolist()
        }