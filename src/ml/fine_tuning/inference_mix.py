# type: ignore# type: ignore# type: ignore

"""

Enhanced Inference Script for CodeBERT/GraphCodeBERT Models - IIT Delhi Hackathon Stage I""""""

===========================================================================================

Enhanced Inference Script for CodeBERT/GraphCodeBERT Models - IIT Delhi Hackathon Stage I

Test trained CodeBERT/GraphCodeBERT PEFT models on source code files.Kaggle-Ready Inference Script for CodeBERT/GraphCodeBERT Fine-Tuned Models



Features:=====================================================================================================================================================================

- Supports single model or ensemble prediction

- Outputs predictions with vulnerability explanations

- Kaggle-compatible paths

- Heuristic vulnerability detection tagsThis script provides comprehensive inference capabilities for fine-tuned CodeBERT Test trained CodeBERT/GraphCodeBERT PEFT models on source code files.



Usage Examples:and GraphCodeBERT models with enhanced features for the hackathon.

  # Single model (CodeBERT)

  python inference_mix.py \Features:

      --input-dir ./samples \

      --output outputs/preds.jsonl \Features:- Loads models trained with train_codebert_lora.py / train_graphcodebert_lora.py

      --model-choice codebert \

      --checkpoint /kaggle/input/.../codebert_final_layer.pt- Multi-language support (Python, Java, C/C++, Go, PHP, Ruby, JS)- Supports single model or ensemble prediction



  # Ensemble both models- Enhanced LoRA model loading (r=16)- Outputs predictions with vulnerability explanations

  python inference_mix.py \

      --input-dir ./samples \- Top-K vulnerable line detection- Kaggle-compatible paths

      --output outputs/preds.jsonl \

      --ensemble \- CWE mapping and vulnerability classification

      --codebert-checkpoint /kaggle/input/.../codebert_final_layer.pt \

      --graph-checkpoint /kaggle/input/.../graphcodebert_final_layer.pt- Confidence calibration and threshold tuningUsage Examples:



Author: CodeGuardian Team- Explainability with attention visualization  # Single model (CodeBERT)

Date: October 2025

"""- Ensemble prediction capabilities  python test_models_on_code_samples.py \



import os      --input-dir ./samples \

import sys

import reUsage Examples:      --output outputs/preds.jsonl \

import json

import argparse  # Single model inference      --model-choice codebert \

import csv

import hashlib  python inference_mix.py --input-dir ./code_samples --model codebert --threshold 0.18      --checkpoint /kaggle/input/.../codebert_final_layer.pt

from pathlib import Path

from typing import List, Dict, Any, Optional



import torch  # Ensemble inference with both models  # Ensemble both models

import torch.nn as nn

from torch.utils.data import DataLoader, TensorDataset  python inference_mix.py --input-dir ./code_samples --ensemble --threshold 0.18  python test_models_on_code_samples.py \

from tqdm import tqdm

from transformers import RobertaConfig, RobertaModel, RobertaTokenizer        --input-dir ./samples \

from peft import LoraConfig, get_peft_model, TaskType

  # Single file analysis with detailed output      --output outputs/preds.jsonl \



# ============================================================================  python inference_mix.py --input-file vulnerable.py --model graphcodebert --top-k 5      --ensemble \

# MODEL DEFINITION (Must match training scripts)

# ============================================================================      --codebert-checkpoint /kaggle/input/.../codebert_final_layer.pt \



class CodeBERTForVulnerabilityDetection(nn.Module):Author: CodeGuardian Team - IIT Delhi Hackathon      --graph-checkpoint /kaggle/input/.../graphcodebert_final_layer.pt

    """CodeBERT model with classification head - matches training script"""

Date: October 2025

    def __init__(self, model_name: str, num_labels: int = 2):

        super().__init__()"""Author: CodeGuardian Team



        print(f"Loading base model: {model_name}")Date: October 2025

        try:

            self.config = RobertaConfig.from_pretrained(model_name)import argparse"""

            self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)

        except Exception as e:import gc

            print(f"⚠️ Error loading model: {e}")

            raiseimport hashlibimport os



        # Classification headimport jsonimport sys

        self.classifier = nn.Sequential(

            nn.Dropout(0.1), import loggingimport re

            nn.Linear(self.config.hidden_size, num_labels)

        )import osimport json



        # Freeze backboneimport reimport argparse

        for param in self.roberta.parameters():

            param.requires_grad = Falseimport warningsimport csv



    def forward(self, input_ids=None, attention_mask=None, **kwargs):from pathlib import Pathimport hashlib

        if input_ids is None and "inputs_embeds" in kwargs:

            outputs = self.roberta(from typing import Dict, List, Optional, Tuple, Unionfrom pathlib import Path

                inputs_embeds=kwargs["inputs_embeds"],

                attention_mask=attention_maskfrom typing import List, Dict, Any, Optional

            )

        else:import numpy as np

            outputs = self.roberta(

                input_ids=input_ids, import torchimport torch

                attention_mask=attention_mask

            )import torch.nn as nnimport torch.nn as nn



        pooled_output = outputs.pooler_outputfrom sklearn.metrics import classification_reportfrom torch.utils.data import DataLoader, TensorDataset

        logits = self.classifier(pooled_output)

        return logitsfrom torch.cuda.amp import autocastfrom tqdm import tqdm



from transformers import RobertaConfig, RobertaModel, RobertaTokenizer

class GraphCodeBERTForVulnerabilityDetection(nn.Module):

    """GraphCodeBERT model with classification head - matches training script"""from transformers import RobertaModel, RobertaConfig, RobertaTokenizerFast



    def __init__(self, model_name: str, num_labels: int = 2):# LoRA/PEFT importsfrom peft import LoraConfig, get_peft_model, TaskType

        super().__init__()

from peft import LoraConfig, PeftModel, get_peft_model

        print(f"Loading base model: {model_name}")

        try:# ============================================================================

            self.config = RobertaConfig.from_pretrained(model_name)

            self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)warnings.filterwarnings("ignore")# MODEL DEFINITION (Must match training scripts)

        except Exception as e:

            print(f"⚠️ Error loading model: {e}")# ============================================================================

            raise

# Setup logging

        # Classification head

        self.classifier = nn.Sequential(logging.basicConfig(level=logging.INFO)

            nn.Dropout(0.1),

            nn.Linear(self.config.hidden_size, num_labels)logger = logging.getLogger(__name__)class CodeBERTForVulnerabilityDetection(nn.Module):

        )

    """CodeBERT model with classification head - matches training script"""

        # Freeze backbone

        for param in self.roberta.parameters():# Performance optimizations

            param.requires_grad = False

torch.backends.cuda.matmul.allow_tf32 = True    def __init__(self, model_name: str, num_labels: int = 2):

    def forward(self, input_ids=None, attention_mask=None, **kwargs):

        if input_ids is None and "inputs_embeds" in kwargs:torch.backends.cudnn.benchmark = True        super().__init__()

            outputs = self.roberta(

                inputs_embeds=kwargs["inputs_embeds"],

                attention_mask=attention_mask

            )        print(f"Loading base model: {model_name}")

        else:

            outputs = self.roberta(class CWEMapper:        try:

                input_ids=input_ids,

                attention_mask=attention_mask    """Maps vulnerability types to CWE identifiers."""            self.config = RobertaConfig.from_pretrained(model_name)

            )

                self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)

        pooled_output = outputs.pooler_output

        logits = self.classifier(pooled_output)    CWE_MAPPING = {        except Exception as e:

        return logits

        'sql_injection': 'CWE-89',            print(f"⚠️ Error loading model: {e}")



# ============================================================================        'command_injection': 'CWE-78',             raise

# VULNERABILITY DETECTORS (Heuristic explanations)

# ============================================================================        'xss': 'CWE-79',



DETECTORS = {        'path_traversal': 'CWE-22',        # Classification head

    "sql_injection": [

        re.compile(r"\bSELECT\b.*\bFROM\b.*\bWHERE\b.*%s", re.I),        'unsafe_deserialization': 'CWE-502',        self.classifier = nn.Sequential(

        re.compile(r"execute\(|executeQuery\(|exec\(", re.I),

        re.compile(r"LIKE\s*'%.+%'", re.I),        'hardcoded_credentials': 'CWE-798',            nn.Dropout(0.1), nn.Linear(self.config.hidden_size, num_labels)

        re.compile(r"\bWHERE\b.*=\s*'.*'"),

    ],        'buffer_overflow': 'CWE-120',        )

    "command_injection": [

        re.compile(        'integer_overflow': 'CWE-190',

            r"\bsystem\s*\(|\bexec\(|subprocess\.check_output|Runtime\.getRuntime\(\)\.exec",

            re.I,        'use_after_free': 'CWE-416',        # Freeze backbone

        )

    ],        'format_string': 'CWE-134',        for param in self.roberta.parameters():

    "unsafe_deserialization": [

        re.compile(        'race_condition': 'CWE-362',            param.requires_grad = False

            r"pickle\.loads|ObjectInputStream|pickle\.load|marshal\.loads", re.I

        ),        'weak_crypto': 'CWE-327',

        re.compile(r"unserialize\(|deserialize\(|yaml\.load", re.I),

    ],        'improper_auth': 'CWE-287',    def forward(self, input_ids=None, attention_mask=None, **kwargs):

    "hardcoded_credentials": [

        re.compile(        'csrf': 'CWE-352',        if input_ids is None and "inputs_embeds" in kwargs:

            r"(?i)(password|secret|token|key|jwt|apikey)[\"']?\s*[:=]\s*[\"'][\w\-]{6,}",

            re.I,        'xxe': 'CWE-611',            outputs = self.roberta(

        ),

        re.compile(r"\"[a-z0-9]{20,}\"", re.I),        'ldap_injection': 'CWE-90',                inputs_embeds=kwargs["inputs_embeds"], attention_mask=attention_mask

    ],

    "path_traversal": [        'weak_randomness': 'CWE-330',            )

        re.compile(r"\.\./|\bFiles\.write\(|open\(|fopen\(|FileOutputStream\(", re.I)

    ],        'information_disclosure': 'CWE-200',        else:

    "format_string": [

        re.compile(r"printf\s*\(|System\.out\.printf|String\.format|format\(", re.I)        'privilege_escalation': 'CWE-269',            outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)

    ],

    "use_after_free": [re.compile(r"\bfree\s*\(|delete\s+.*;", re.I)],        'dos': 'CWE-400'

    "integer_overflow": [re.compile(r"atoi\(|strtol\(|unsigned\s+int|uint32_t", re.I)],

    "eval_exec": [re.compile(r"\beval\s*\(|\bexec\s*\(", re.I)],    }        pooled_output = outputs.pooler_output

    "buffer_overflow": [re.compile(r"strcpy\(|strcat\(|gets\(|sprintf\(", re.I)],

}            logits = self.classifier(pooled_output)



    SEVERITY_MAPPING = {        return logits

def detect_vulnerability_tags(code: str) -> List[str]:

    """Run heuristic detectors to generate explanation tags"""        'CWE-89': 'CRITICAL',   # SQL Injection

    tags = set()

    for tag, patterns in DETECTORS.items():        'CWE-78': 'CRITICAL',   # Command Injection

        for pattern in patterns:

            try:        'CWE-79': 'HIGH',       # XSSclass GraphCodeBERTForVulnerabilityDetection(nn.Module):

                if pattern.search(code):

                    tags.add(tag)        'CWE-22': 'HIGH',       # Path Traversal    """GraphCodeBERT model with classification head - matches training script"""

                    break

            except re.error:        'CWE-502': 'CRITICAL',  # Unsafe Deserialization

                continue

    return sorted(list(tags))        'CWE-798': 'HIGH',      # Hardcoded Credentials    def __init__(self, model_name: str, num_labels: int = 2):



        'CWE-120': 'CRITICAL',  # Buffer Overflow        super().__init__()

# ============================================================================

# HELPER FUNCTIONS        'CWE-190': 'MEDIUM',    # Integer Overflow

# ============================================================================

        'CWE-416': 'CRITICAL',  # Use After Free        print(f"Loading base model: {model_name}")

def sha1_hash(text: str) -> str:

    """Generate SHA1 hash of text"""        'CWE-134': 'HIGH',      # Format String        try:

    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

        'CWE-362': 'MEDIUM',    # Race Condition            self.config = RobertaConfig.from_pretrained(model_name)



def detect_language(filepath: str) -> str:        'CWE-327': 'MEDIUM',    # Weak Crypto            self.roberta = RobertaModel.from_pretrained(model_name, config=self.config)

    """Detect programming language from file extension"""

    ext = Path(filepath).suffix.lower()        'CWE-287': 'HIGH',      # Improper Auth        except Exception as e:

    lang_map = {

        ".py": "python",        'CWE-352': 'MEDIUM',    # CSRF            print(f"⚠️ Error loading model: {e}")

        ".java": "java",

        ".cpp": "cpp",        'CWE-611': 'HIGH',      # XXE            raise

        ".cc": "cpp",

        ".cxx": "cpp",        'CWE-90': 'HIGH',       # LDAP Injection

        ".c": "c",

        ".js": "javascript",        'CWE-330': 'MEDIUM',    # Weak Randomness        # Classification head

        ".jsx": "javascript",

        ".go": "go",        'CWE-200': 'LOW',       # Information Disclosure        self.classifier = nn.Sequential(

        ".php": "php",

        ".rb": "ruby",        'CWE-269': 'HIGH',      # Privilege Escalation            nn.Dropout(0.1), nn.Linear(self.config.hidden_size, num_labels)

        ".cs": "csharp",

        ".ts": "typescript",        'CWE-400': 'MEDIUM'     # DoS        )

    }

    return lang_map.get(ext, "unknown")    }



            # Freeze backbone

def read_file_safe(filepath: str) -> str:

    """Read file with error handling"""    @classmethod        for param in self.roberta.parameters():

    try:

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:    def get_cwe(cls, vuln_type: str) -> str:            param.requires_grad = False

            return f.read()

    except Exception as e:        """Get CWE identifier for vulnerability type."""

        print(f"⚠️ Failed to read {filepath}: {e}")

        return ""        return cls.CWE_MAPPING.get(vuln_type, 'CWE-UNKNOWN')    def forward(self, input_ids=None, attention_mask=None, **kwargs):



            if input_ids is None and "inputs_embeds" in kwargs:

# ============================================================================

# MODEL LOADER    @classmethod            outputs = self.roberta(

# ============================================================================

    def get_severity(cls, cwe: str) -> str:                inputs_embeds=kwargs["inputs_embeds"], attention_mask=attention_mask

def load_model_from_checkpoint(

    checkpoint_path: str,         """Get severity level for CWE."""            )

    base_model_name: str,

    model_choice: str,         return cls.SEVERITY_MAPPING.get(cwe, 'UNKNOWN')        else:

    device: torch.device

):            outputs = self.roberta(input_ids=input_ids, attention_mask=attention_mask)

    """

    Load trained model from checkpoint (.pt file)



    Args:class VulnerabilityDetector:        pooled_output = outputs.pooler_output

        checkpoint_path: Path to .pt checkpoint file

        base_model_name: Base model name (microsoft/codebert-base or microsoft/graphcodebert-base)    """Enhanced vulnerability pattern detector with multi-language support."""        logits = self.classifier(pooled_output)

        model_choice: 'codebert' or 'graphcodebert'

        device: torch device            return logits



    Returns:    # Pattern definitions for different vulnerability types

        tokenizer, model

    """    PATTERNS = {

    print(f"\n{'='*70}")

    print(f"LOADING MODEL: {model_choice.upper()}")        'sql_injection': [# ============================================================================

    print(f"{'='*70}")

    print(f"Checkpoint: {checkpoint_path}")            r'(?i)(query|execute|executeQuery|exec)\s*\(\s*["\'].*\+.*["\']',# VULNERABILITY DETECTORS (Heuristic explanations)

    print(f"Base model: {base_model_name}")

            r'(?i)SELECT.*FROM.*WHERE.*\+',# ============================================================================

    # Load tokenizer

    tokenizer = RobertaTokenizer.from_pretrained(base_model_name)            r'(?i)INSERT.*INTO.*VALUES.*\+',



    # Create base model (must match training script architecture)            r'(?i)UPDATE.*SET.*WHERE.*\+',DETECTORS = {

    if model_choice == "codebert":

        model = CodeBERTForVulnerabilityDetection(base_model_name, num_labels=2)            r'(?i)DELETE.*FROM.*WHERE.*\+',    "sql_injection": [

    elif model_choice == "graphcodebert":

        model = GraphCodeBERTForVulnerabilityDetection(base_model_name, num_labels=2)            r'(?i)(query|sql).*format.*%s',        re.compile(r"\bSELECT\b.*\bFROM\b.*\bWHERE\b.*%s", re.I),

    else:

        raise ValueError(f"Invalid model_choice: {model_choice}")            r'(?i)cursor\.execute\s*\(\s*f["\']',  # Python f-strings in SQL        re.compile(r"execute\(|executeQuery\(|exec\(", re.I),



    # Apply LoRA configuration (must match training)        ],        re.compile(r"LIKE\s*'%.+%'", re.I),

    lora_config = LoraConfig(

        task_type=TaskType.SEQ_CLS,        'command_injection': [        re.compile(r"\bWHERE\b.*=\s*'.*'"),

        r=8,

        lora_alpha=16,            r'(?i)(system|exec|popen|subprocess|shell_exec|eval)\s*\([^)]*[\+\%]',    ],

        lora_dropout=0.1,

        target_modules=["classifier.1", "roberta.encoder.layer.11.output.dense"],            r'(?i)os\.(system|popen|exec)',    "command_injection": [

        bias="none",

        inference_mode=True,  # Important for inference!            r'(?i)subprocess\.(run|call|check_output).*shell\s*=\s*True',        re.compile(

    )

            r'(?i)Runtime\.getRuntime\(\)\.exec',            r"\bsystem\s*\(|\bexec\(|subprocess\.check_output|Runtime\.getRuntime\(\)\.exec",

    model = get_peft_model(model, lora_config)

            r'(?i)ProcessBuilder.*start\(\)',            re.I,

    # Load checkpoint weights

    print(f"Loading checkpoint weights...")        ],        )

    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)

        'xss': [    ],

    # Extract model state dict

    if "model_state_dict" in checkpoint:            r'(?i)document\.write\s*\([^)]*[\+\%]',    "unsafe_deserialization": [

        state_dict = checkpoint["model_state_dict"]

        epoch = checkpoint.get("epoch", "unknown")            r'(?i)innerHTML\s*=.*[\+\%]',        re.compile(

        best_f1 = checkpoint.get("best_f1", "unknown")

        print(f"✓ Checkpoint from epoch {epoch}, best F1: {best_f1}")            r'(?i)outerHTML\s*=.*[\+\%]',            r"pickle\.loads|ObjectInputStream|pickle\.load|marshal\.loads", re.I

    else:

        state_dict = checkpoint            r'(?i)response\.write\s*\([^)]*[\+\%]',        ),

        print("✓ Loading raw state dict")

            r'(?i)echo.*\$_(GET|POST|REQUEST)',        re.compile(r"unserialize\(|deserialize\(|yaml\.load", re.I),

    # Load weights

    model.load_state_dict(state_dict, strict=False)        ],    ],



    model.to(device)        'path_traversal': [    "hardcoded_credentials": [

    model.eval()

            r'(?i)(file|path|dir).*\.\./.*\.\.',        re.compile(

    print(f"✓ Model loaded successfully on {device}")

    print(f"{'='*70}\n")            r'(?i)(open|read|write|include).*\$_(GET|POST|REQUEST)',            r"(?i)(password|secret|token|key|jwt|apikey)[\"']?\s*[:=]\s*[\"'][\w\-]{6,}",



    return tokenizer, model            r'(?i)File\s*\(\s*.*\+',            re.I,



            r'(?i)FileInputStream.*\+',        ),

# ============================================================================

# INFERENCE ENGINE            r'(?i)os\.path\.join.*\+',        re.compile(r"\"[a-z0-9]{20,}\"", re.I),

# ============================================================================

        ],    ],

class InferenceRunner:

    """Handles model inference with batching and mixed precision"""        'unsafe_deserialization': [    "path_traversal": [



    def __init__(            r'(?i)pickle\.(load|loads)\s*\(',        re.compile(r"\.\./|\bFiles\.write\(|open\(|fopen\(|FileOutputStream\(", re.I)

        self,

        device: Optional[torch.device] = None,            r'(?i)ObjectInputStream.*readObject',    ],

        batch_size: int = 32,

        max_length: int = 512,            r'(?i)unserialize\s*\(\s*\$_(GET|POST|REQUEST)',    "format_string": [

    ):

        self.device = device or (            r'(?i)yaml\.load\s*\(',        re.compile(r"printf\s*\(|System\.out\.printf|String\.format|format\(", re.I)

            torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")

        )            r'(?i)JSON\.parse.*\+',    ],

        self.batch_size = batch_size

        self.max_length = max_length        ],    "use_after_free": [re.compile(r"\bfree\s*\(|delete\s+.*;", re.I)],



        # Check for BF16 support        'hardcoded_credentials': [    "integer_overflow": [re.compile(r"atoi\(|strtol\(|unsigned\s+int|uint32_t", re.I)],

        self.use_bf16 = False

        if torch.cuda.is_available():            r'(?i)(password|pwd|pass|secret|key|token)\s*=\s*["\'][^"\']{3,}["\']',    "eval_exec": [re.compile(r"\beval\s*\(|\bexec\s*\(", re.I)],

            capability = torch.cuda.get_device_capability()

            self.use_bf16 = capability[0] >= 8  # Ampere or newer            r'(?i)api[_-]?key\s*=\s*["\'][^"\']{10,}["\']',    "buffer_overflow": [re.compile(r"strcpy\(|strcat\(|gets\(|sprintf\(", re.I)],



        self.dtype = torch.bfloat16 if self.use_bf16 else torch.float16            r'(?i)(username|user)\s*=\s*["\']admin["\']',}

        print(f"🔧 Inference device: {self.device}")

        print(f"🔧 Precision: {'BFloat16' if self.use_bf16 else 'Float16 (FP16)'}")            r'(?i)connection.*password\s*=',



    def tokenize_batch(self, tokenizer, codes: List[str]):        ],

        """Tokenize a batch of code samples"""

        encoding = tokenizer(        'buffer_overflow': [def detect_vulnerability_tags(code: str) -> List[str]:

            codes,

            truncation=True,            r'(?i)strcpy\s*\(',    """Run heuristic detectors to generate explanation tags"""

            max_length=self.max_length,

            padding="max_length",            r'(?i)strcat\s*\(',    tags = set()

            return_tensors="pt",

        )            r'(?i)sprintf\s*\(',    for tag, patterns in DETECTORS.items():

        return encoding["input_ids"], encoding["attention_mask"]

            r'(?i)gets\s*\(',        for pattern in patterns:

    def predict_single_model(

        self, tokenizer, model, codes: List[str], model_name: str            r'(?i)scanf\s*\([^)]*%s',            try:

    ) -> List[float]:

        """Run inference on a single model"""        ],                if pattern.search(code):

        input_ids, attention_mask = self.tokenize_batch(tokenizer, codes)

        dataset = TensorDataset(input_ids, attention_mask)        'format_string': [                    tags.add(tag)

        loader = DataLoader(

            dataset,            r'(?i)printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',                    break

            batch_size=self.batch_size,

            shuffle=False,            r'(?i)fprintf\s*\([^,]*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',            except re.error:

            num_workers=0,

            pin_memory=True if torch.cuda.is_available() else False,            r'(?i)sprintf\s*\([^,]*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',                continue

        )

        ],    return sorted(list(tags))

        probabilities = []

        'use_after_free': [

        with torch.no_grad():

            for batch in tqdm(loader, desc=f"Inferring {model_name}", leave=False):            r'(?i)free\s*\([^)]+\).*\n.*\1',

                input_ids_b, attention_mask_b = [x.to(self.device) for x in batch]

            r'(?i)delete\s+\w+.*\n.*\1',# ============================================================================

                # Mixed precision inference

                if torch.cuda.is_available():        ],# HELPER FUNCTIONS

                    with torch.cuda.amp.autocast(dtype=self.dtype):

                        logits = model(        'integer_overflow': [# ============================================================================

                            input_ids=input_ids_b, attention_mask=attention_mask_b

                        )            r'(?i)(int|long|size_t)\s+\w+\s*=.*\*.*\+',

                else:

                    logits = model(            r'(?i)malloc\s*\(.*\*.*\)',

                        input_ids=input_ids_b, attention_mask=attention_mask_b

                    )        ]def sha1_hash(text: str) -> str:



                # Softmax to get probabilities    }    """Generate SHA1 hash of text"""

                probs = torch.softmax(logits, dim=-1)[

                    :, 1        return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

                ]  # Probability of class 1 (vulnerable)

                probabilities.extend(probs.cpu().numpy().tolist())    @classmethod



        return probabilities    def detect_vulnerabilities(cls, code: str, language: str = 'unknown') -> List[Dict]:



    def predict_ensemble(        """Detect vulnerabilities in code and return detailed results."""def detect_language(filepath: str) -> str:

        self,

        tokenizer1,        vulnerabilities = []    """Detect programming language from file extension"""

        model1,

        tokenizer2,        lines = code.split('\n')    ext = Path(filepath).suffix.lower()

        model2,

        codes: List[str],            lang_map = {

        weights: tuple = (0.5, 0.5),

    ) -> List[float]:        for vuln_type, patterns in cls.PATTERNS.items():        ".py": "python",

        """Run ensemble prediction with two models"""

        print(            for i, line in enumerate(lines, 1):        ".java": "java",

            f"🔀 Ensemble weights: CodeBERT={weights[0]:.2f}, GraphCodeBERT={weights[1]:.2f}"

        )                for pattern in patterns:        ".cpp": "cpp",



        probs1 = self.predict_single_model(tokenizer1, model1, codes, "CodeBERT")                    if re.search(pattern, line):        ".cc": "cpp",

        probs2 = self.predict_single_model(tokenizer2, model2, codes, "GraphCodeBERT")

                        cwe = CWEMapper.get_cwe(vuln_type)        ".cxx": "cpp",

        # Weighted average

        ensemble_probs = [                        severity = CWEMapper.get_severity(cwe)        ".c": "c",

            weights[0] * p1 + weights[1] * p2 for p1, p2 in zip(probs1, probs2)

        ]                                ".js": "javascript",



        return ensemble_probs                        vulnerabilities.append({        ".jsx": "javascript",



                            'type': vuln_type,        ".go": "go",

# ============================================================================

# INPUT/OUTPUT HANDLING                            'cwe': cwe,        ".php": "php",

# ============================================================================

                            'severity': severity,        ".rb": "ruby",

def gather_input_samples(

    input_dir: Optional[str], input_file: Optional[str]                            'line_number': i,        ".cs": "csharp",

) -> List[Dict[str, Any]]:

    """                            'line_content': line.strip(),        ".ts": "typescript",

    Gather code samples from directory or JSONL file

                            'pattern_matched': pattern,    }

    Returns:

        List of dicts with keys: id, code, language, filename                            'confidence': 0.8  # Static pattern confidence    return lang_map.get(ext, "unknown")

    """

    samples = []                        })



    # Supported extensions

    code_extensions = {

        ".py",        return vulnerabilitiesdef read_file_safe(filepath: str) -> str:

        ".java",

        ".cpp",    """Read file with error handling"""

        ".c",

        ".cc",    try:

        ".cxx",

        ".js",class CodeBERTForVulnerabilityDetection(nn.Module):        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:

        ".jsx",

        ".go",    """Enhanced CodeBERT model for vulnerability detection."""            return f.read()

        ".php",

        ".rb",        except Exception as e:

        ".cs",

        ".ts",    def __init__(self, model_name: str, num_labels: int = 2):        print(f"⚠️ Failed to read {filepath}: {e}")

        ".txt",

    }        super().__init__()        return ""



    # Read from directory

    if input_dir:

        input_path = Path(input_dir)        self.config = RobertaConfig.from_pretrained(model_name)

        if not input_path.exists():

            raise FileNotFoundError(f"Input directory not found: {input_dir}")        self.roberta = RobertaModel.from_pretrained(# ============================================================================



        files = []            model_name, config=self.config, add_pooling_layer=True# MODEL LOADER

        for ext in code_extensions:

            files.extend(list(input_path.rglob(f"*{ext}")))        )# ============================================================================

        files = sorted(files)



        print(f"📂 Found {len(files)} files in {input_dir}")

        # Enhanced classification head

        for filepath in files:

            code = read_file_safe(str(filepath))        self.classifier = nn.Sequential(def load_model_from_checkpoint(

            if code.strip():  # Skip empty files

                samples.append(            nn.Dropout(0.1),    checkpoint_path: str, base_model_name: str, model_choice: str, device: torch.device

                    {

                        "id": sha1_hash(str(filepath) + code)[:12],            nn.Linear(self.config.hidden_size, 512),):

                        "code": code,

                        "language": detect_language(str(filepath)),            nn.ReLU(),    """

                        "filename": str(filepath),

                    }            nn.Dropout(0.1),    Load trained model from checkpoint (.pt file)

                )

            nn.Linear(512, num_labels)

    # Read from JSONL file

    if input_file:        )    Args:

        input_path = Path(input_file)

        if not input_path.exists():                checkpoint_path: Path to .pt checkpoint file

            raise FileNotFoundError(f"Input file not found: {input_file}")

        # Freeze backbone        base_model_name: Base model name (microsoft/codebert-base or microsoft/graphcodebert-base)

        if input_path.suffix.lower() in {".jsonl", ".ndjson"}:

            with input_path.open("r", encoding="utf-8") as f:        for param in self.roberta.parameters():        model_choice: 'codebert' or 'graphcodebert'

                for line_num, line in enumerate(f, 1):

                    if not line.strip():            param.requires_grad = False        device: torch device

                        continue

                    try:

                        obj = json.loads(line)

                        code = (    def forward(self, input_ids=None, attention_mask=None, **kwargs):    Returns:

                            obj.get("code")

                            or obj.get("content")        """Forward pass with attention outputs for explainability."""        tokenizer, model

                            or obj.get("source", "")

                        )        outputs = self.roberta(    """

                        if code.strip():

                            samples.append(            input_ids=input_ids,    print(f"\n{'='*70}")

                                {

                                    "id": obj.get("id") or f"line_{line_num}",            attention_mask=attention_mask,    print(f"LOADING MODEL: {model_choice.upper()}")

                                    "code": code,

                                    "language": obj.get("language")            output_attentions=True,    print(f"{'='*70}")

                                    or detect_language(obj.get("filename", "")),

                                    "filename": obj.get("filename"),            **kwargs    print(f"Checkpoint: {checkpoint_path}")

                                }

                            )        )    print(f"Base model: {base_model_name}")

                    except json.JSONDecodeError as e:

                        print(f"⚠️ Invalid JSON on line {line_num}: {e}")

                        continue

        else:        pooled_output = outputs.pooler_output    # Load tokenizer

            # Plain text file - treat as single code sample

            code = read_file_safe(str(input_path))        logits = self.classifier(pooled_output)    tokenizer = RobertaTokenizerFast.from_pretrained(base_model_name)

            if code.strip():

                samples.append(

                    {

                        "id": sha1_hash(str(input_path))[:12],        return {    # Create base model (must match training script architecture)

                        "code": code,

                        "language": detect_language(str(input_path)),            'logits': logits,    if model_choice == "codebert":

                        "filename": str(input_path),

                    }            'attentions': outputs.attentions,        model = CodeBERTForVulnerabilityDetection(base_model_name, num_labels=2)

                )

            'hidden_states': outputs.last_hidden_state    elif model_choice == "graphcodebert":

    print(f"✓ Loaded {len(samples)} code samples")

    return samples        }        model = GraphCodeBERTForVulnerabilityDetection(base_model_name, num_labels=2)



    else:

def save_results(results: List[Dict[str, Any]], output_path: str):

    """Save results to JSONL and CSV"""        raise ValueError(f"Invalid model_choice: {model_choice}")

    output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)class GraphCodeBERTForVulnerabilityDetection(nn.Module):



    # Save JSONL    """Enhanced GraphCodeBERT model for vulnerability detection."""    # Apply LoRA configuration (must match training)

    jsonl_path = output_path.with_suffix(".jsonl")

    with jsonl_path.open("w", encoding="utf-8") as f:        lora_config = LoraConfig(

        for result in results:

            f.write(json.dumps(result, ensure_ascii=False) + "\n")    def __init__(self, model_name: str, num_labels: int = 2):        task_type=TaskType.SEQ_CLS,

    print(f"✓ Saved JSONL: {jsonl_path}")

        super().__init__()        r=8,

    # Save CSV

    csv_path = output_path.with_suffix(".csv")                lora_alpha=16,

    if results:

        keys = list(results[0].keys())        self.config = RobertaConfig.from_pretrained(model_name)        lora_dropout=0.1,

        with csv_path.open("w", newline="", encoding="utf-8") as f:

            writer = csv.DictWriter(f, fieldnames=keys)        self.roberta = RobertaModel.from_pretrained(        target_modules=["classifier.1", "roberta.encoder.layer.11.output.dense"],

            writer.writeheader()

            for result in results:            model_name, config=self.config, add_pooling_layer=True        bias="none",

                writer.writerow(result)

        print(f"✓ Saved CSV: {csv_path}")        )        inference_mode=True,  # Important for inference!



            )

# ============================================================================

# MAIN        # Enhanced classification head

# ============================================================================

        self.classifier = nn.Sequential(    model = get_peft_model(model, lora_config)

def main():

    parser = argparse.ArgumentParser(            nn.Dropout(0.1),

        description="Test trained CodeBERT/GraphCodeBERT models on code samples",

        formatter_class=argparse.RawDescriptionHelpFormatter,            nn.Linear(self.config.hidden_size, 512),    # Load checkpoint weights

        epilog="""

Examples:            nn.ReLU(),    print(f"Loading checkpoint weights...")

  # Single model inference

  python inference_mix.py \\            nn.Dropout(0.1),    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)

      --input-dir ./test_samples \\

      --output outputs/predictions.jsonl \\            nn.Linear(512, num_labels)

      --model-choice codebert \\

      --checkpoint /kaggle/input/.../codebert_final_layer.pt        )    # Extract model state dict



  # Ensemble both models            if "model_state_dict" in checkpoint:

  python inference_mix.py \\

      --input-dir ./test_samples \\        # Freeze backbone        state_dict = checkpoint["model_state_dict"]

      --output outputs/predictions.jsonl \\

      --ensemble \\        for param in self.roberta.parameters():        epoch = checkpoint.get("epoch", "unknown")

      --codebert-checkpoint /kaggle/input/.../codebert_final_layer.pt \\

      --graph-checkpoint /kaggle/input/.../graphcodebert_final_layer.pt            param.requires_grad = False        best_f1 = checkpoint.get("best_f1", "unknown")

        """,

    )            print(f"✓ Checkpoint from epoch {epoch}, best F1: {best_f1}")



    # Input options    def forward(self, input_ids=None, attention_mask=None, **kwargs):    else:

    parser.add_argument(

        "--input-dir", type=str, help="Directory with source files (recursive)"        """Forward pass with attention outputs for explainability."""        state_dict = checkpoint

    )

    parser.add_argument("--input-file", type=str, help="Single JSONL or text file")        outputs = self.roberta(        print("✓ Loading raw state dict")

    parser.add_argument(

        "--output",            input_ids=input_ids,

        type=str,

        default="outputs/predictions.jsonl",            attention_mask=attention_mask,    # Load weights

        help="Output path (will create .jsonl and .csv)",

    )            output_attentions=True,    model.load_state_dict(state_dict, strict=False)



    # Model options            **kwargs

    parser.add_argument(

        "--model-choice",        )    model.to(device)

        type=str,

        choices=["codebert", "graphcodebert"],            model.eval()

        default="codebert",

        help="Single model to use",        pooled_output = outputs.pooler_output

    )

    parser.add_argument(        logits = self.classifier(pooled_output)    print(f"✓ Model loaded successfully on {device}")

        "--ensemble",

        action="store_true",            print(f"{'='*70}\n")

        help="Ensemble both models (requires both checkpoints)",

    )        return {



    # Checkpoint paths (Kaggle-compatible)            'logits': logits,    return tokenizer, model

    parser.add_argument(

        "--checkpoint", type=str, help="Checkpoint path for single model mode"            'attentions': outputs.attentions,

    )

    parser.add_argument(            'hidden_states': outputs.last_hidden_state

        "--codebert-checkpoint",

        type=str,        }# ============================================================================

        default="/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/codebert/codebert_final_layer.pt",

        help="CodeBERT checkpoint path",# INFERENCE ENGINE

    )

    parser.add_argument(# ============================================================================

        "--graph-checkpoint",

        type=str,class EnhancedInferenceEngine:

        default="/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/graphcodebert/graphcodebert_final_layer.pt",

        help="GraphCodeBERT checkpoint path",    """Enhanced inference engine with explainability and confidence calibration."""

    )

    class InferenceRunner:

    # Base model names

    parser.add_argument("--base-codebert", type=str, default="microsoft/codebert-base")    def __init__(    """Handles model inference with batching and mixed precision"""

    parser.add_argument(

        "--base-graph", type=str, default="microsoft/graphcodebert-base"        self,

    )

        device: str = "auto",    def __init__(

    # Inference options

    parser.add_argument(        max_length: int = 512,        self,

        "--batch-size", type=int, default=32, help="Inference batch size"

    )        batch_size: int = 32,        device: Optional[torch.device] = None,

    parser.add_argument(

        "--threshold",        threshold: float = 0.18,        batch_size: int = 32,

        type=float,

        default=0.2,        top_k: int = 5        max_length: int = 512,

        help="Classification threshold (0.0-1.0). Recommended: 0.15-0.25 for security-focused detection",

    )    ):    ):

    parser.add_argument(

        "--ensemble-weights",        self.device = self._setup_device(device)        self.device = device or (

        type=str,

        default="0.5,0.5",        self.max_length = max_length            torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")

        help="Ensemble weights as 'codebert,graphcodebert'",

    )        self.batch_size = batch_size        )



    args = parser.parse_args()        self.threshold = threshold        self.batch_size = batch_size



    # Validation        self.top_k = top_k        self.max_length = max_length

    if not args.input_dir and not args.input_file:

        parser.error("Provide --input-dir or --input-file")



    if args.ensemble:        # Model components        # Check for BF16 support

        if not os.path.exists(args.codebert_checkpoint):

            parser.error(f"CodeBERT checkpoint not found: {args.codebert_checkpoint}")        self.codebert_model = None        self.use_bf16 = False

        if not os.path.exists(args.graph_checkpoint):

            parser.error(f"GraphCodeBERT checkpoint not found: {args.graph_checkpoint}")        self.graphcodebert_model = None        if torch.cuda.is_available():

    else:

        checkpoint = args.checkpoint or (        self.codebert_tokenizer = None            capability = torch.cuda.get_device_capability()

            args.codebert_checkpoint

            if args.model_choice == "codebert"        self.graphcodebert_tokenizer = None            self.use_bf16 = capability[0] >= 8  # Ampere or newer

            else args.graph_checkpoint

        )

        if not os.path.exists(checkpoint):

            parser.error(f"Checkpoint not found: {checkpoint}")        # Precision detection        self.dtype = torch.bfloat16 if self.use_bf16 else torch.float16



    print("\n" + "=" * 70)        self.dtype = torch.bfloat16 if self._check_bf16_support() else torch.float16        print(f"🔧 Inference device: {self.device}")

    print("CODEGUARDIAN - MODEL INFERENCE")

    print("=" * 70)                print(f"🔧 Precision: {'BFloat16' if self.use_bf16 else 'Float16 (FP16)'}")



    # Gather input samples        logger.info(f"Initialized inference engine on {self.device}")

    samples = gather_input_samples(args.input_dir, args.input_file)

    if not samples:        logger.info(f"Using precision: {'BF16' if self.dtype == torch.bfloat16 else 'FP16'}")    def tokenize_batch(self, tokenizer, codes: List[str]):

        print("❌ No valid code samples found!")

        sys.exit(1)            """Tokenize a batch of code samples"""



    codes = [s["code"] for s in samples]    def _setup_device(self, device: str) -> torch.device:        encoding = tokenizer(



    # Initialize inference runner        """Setup computation device."""            codes,

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    runner = InferenceRunner(device=device, batch_size=args.batch_size)        if device == "auto":            truncation=True,



    # Run inference            return torch.device("cuda" if torch.cuda.is_available() else "cpu")            max_length=self.max_length,

    results = []

        return torch.device(device)            padding="max_length",

    if args.ensemble:

        # Load both models                return_tensors="pt",

        tok_cb, model_cb = load_model_from_checkpoint(

            args.codebert_checkpoint, args.base_codebert, "codebert", device    def _check_bf16_support(self) -> bool:        )

        )

        tok_gcb, model_gcb = load_model_from_checkpoint(        """Check if current GPU supports BFloat16."""        return encoding["input_ids"], encoding["attention_mask"]

            args.graph_checkpoint, args.base_graph, "graphcodebert", device

        )        if not torch.cuda.is_available():



        # Parse weights            return False    def predict_single_model(

        w1, w2 = [float(x) for x in args.ensemble_weights.split(",")]

        capability = torch.cuda.get_device_capability()        self, tokenizer, model, codes: List[str], model_name: str

        # Run ensemble

        probabilities = runner.predict_ensemble(        return capability[0] >= 8    ) -> List[float]:

            tok_cb, model_cb, tok_gcb, model_gcb, codes, weights=(w1, w2)

        )            """Run inference on a single model"""



        model_name = "ensemble"    def load_model(        input_ids, attention_mask = self.tokenize_batch(tokenizer, codes)



    else:        self,         dataset = TensorDataset(input_ids, attention_mask)

        # Single model

        checkpoint = args.checkpoint or (        model_type: str,         loader = DataLoader(

            args.codebert_checkpoint

            if args.model_choice == "codebert"        checkpoint_path: str,             dataset,

            else args.graph_checkpoint

        )        base_model: str = None            batch_size=self.batch_size,

        base_name = (

            args.base_codebert if args.model_choice == "codebert" else args.base_graph    ) -> None:            shuffle=False,

        )

        """Load enhanced LoRA model."""            num_workers=0,

        tokenizer, model = load_model_from_checkpoint(

            checkpoint, base_name, args.model_choice, device        logger.info(f"Loading {model_type} model from {checkpoint_path}")            pin_memory=True if torch.cuda.is_available() else False,

        )

                )

        probabilities = runner.predict_single_model(

            tokenizer, model, codes, args.model_choice        if base_model is None:

        )

            base_model = f"microsoft/{model_type}-base"        probabilities = []

        model_name = args.model_choice



    # Process results

    print(f"\n{'='*70}")        # Load tokenizer        with torch.no_grad():

    print("GENERATING RESULTS")

    print(f"{'='*70}")        tokenizer = RobertaTokenizer.from_pretrained(base_model)            for batch in tqdm(loader, desc=f"Inferring {model_name}", leave=False):



    for sample, prob in zip(samples, probabilities):                        input_ids_b, attention_mask_b = [x.to(self.device) for x in batch]

        pred_label = int(prob >= args.threshold)

        tags = detect_vulnerability_tags(sample["code"])        # Load base model



        results.append(        if model_type == "codebert":                # Mixed precision inference

            {

                "id": sample["id"],            model = CodeBERTForVulnerabilityDetection(base_model)                if torch.cuda.is_available():

                "filename": sample.get("filename"),

                "language": sample.get("language"),        elif model_type == "graphcodebert":                    with torch.cuda.amp.autocast(dtype=self.dtype):

                "model": model_name,

                "prob_vulnerable": round(float(prob), 4),            model = GraphCodeBERTForVulnerabilityDetection(base_model)                        logits = model(

                "pred_label": pred_label,

                "pred_class": "vulnerable" if pred_label == 1 else "safe",        else:                            input_ids=input_ids_b, attention_mask=attention_mask_b

                "explanation_tags": tags if tags else [],

            }            raise ValueError(f"Unsupported model type: {model_type}")                        )

        )

                        else:

    # Save results

    save_results(results, args.output)        # Apply LoRA configuration                    logits = model(



    # Summary        lora_config = LoraConfig(                        input_ids=input_ids_b, attention_mask=attention_mask_b

    print(f"\n{'='*70}")

    print("INFERENCE SUMMARY")            r=16,  # Enhanced LoRA rank                    )

    print(f"{'='*70}")

    print(f"Total samples: {len(results)}")            lora_alpha=32,

    print(f"Predicted vulnerable: {sum(1 for r in results if r['pred_label'] == 1)}")

    print(f"Predicted safe: {sum(1 for r in results if r['pred_label'] == 0)}")            lora_dropout=0.1,                # Softmax to get probabilities

    print(f"Threshold: {args.threshold}")

            target_modules=[                probs = torch.softmax(logits, dim=-1)[

    # Show top vulnerable samples

    vulnerable = [r for r in results if r["pred_label"] == 1]                "classifier.1", "classifier.3",                    :, 1

    if vulnerable:

        print(f"\nTop 10 vulnerable predictions:")                "roberta.encoder.layer.11.attention.self.query",                ]  # Probability of class 1 (vulnerable)

        vulnerable_sorted = sorted(

            vulnerable, key=lambda x: x["prob_vulnerable"], reverse=True                "roberta.encoder.layer.11.attention.self.key",                probabilities.extend(probs.cpu().numpy().tolist())

        )[:10]

        for r in vulnerable_sorted:                "roberta.encoder.layer.11.attention.self.value",

            tags_str = (

                ", ".join(r["explanation_tags"]) if r["explanation_tags"] else "no tags"                "roberta.encoder.layer.11.attention.output.dense",        return probabilities

            )

            print(                "roberta.encoder.layer.11.intermediate.dense",

                f"  {r['id']} | p={r['prob_vulnerable']:.3f} | {tags_str} | {r['filename']}"

            )                "roberta.encoder.layer.11.output.dense",    def predict_ensemble(



    print(f"\n✅ Done! Results saved to {args.output}")            ],        self,



            bias="none",        tokenizer1,

if __name__ == "__main__":

    main()            task_type="SEQ_CLS",        model1,


        )        tokenizer2,

                model2,

        # Load checkpoint        codes: List[str],

        if os.path.exists(checkpoint_path):        weights: tuple = (0.5, 0.5),

            checkpoint = torch.load(checkpoint_path, map_location=self.device)    ) -> List[float]:

                    """Run ensemble prediction with two models"""

            # Apply LoRA and load state dict        print(

            model = get_peft_model(model, lora_config)            f"🔀 Ensemble weights: CodeBERT={weights[0]:.2f}, GraphCodeBERT={weights[1]:.2f}"

            model.load_state_dict(checkpoint['model_state_dict'])        )



            logger.info(f"✓ Loaded checkpoint from epoch {checkpoint.get('epoch', 'unknown')}")        probs1 = self.predict_single_model(tokenizer1, model1, codes, "CodeBERT")

            logger.info(f"✓ Best F1: {checkpoint.get('best_f1', 'unknown'):.4f}")        probs2 = self.predict_single_model(tokenizer2, model2, codes, "GraphCodeBERT")

        else:

            raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")        # Weighted average

                ensemble_probs = [

        model.eval()            weights[0] * p1 + weights[1] * p2 for p1, p2 in zip(probs1, probs2)

        model.to(self.device)        ]



        # Store model and tokenizer        return ensemble_probs

        if model_type == "codebert":

            self.codebert_model = model

            self.codebert_tokenizer = tokenizer# ============================================================================

        else:# INPUT/OUTPUT HANDLING

            self.graphcodebert_model = model# ============================================================================

            self.graphcodebert_tokenizer = tokenizer



        logger.info(f"✓ {model_type} model loaded successfully")def gather_input_samples(

        input_dir: Optional[str], input_file: Optional[str]

    def predict_single() -> List[Dict[str, Any]]:

        self,     """

        code: str,     Gather code samples from directory or JSONL file

        model_type: str,

        return_attention: bool = False    Returns:

    ) -> Dict:        List of dicts with keys: id, code, language, filename

        """Predict vulnerability for a single code sample."""    """

        if model_type == "codebert":    samples = []

            model = self.codebert_model

            tokenizer = self.codebert_tokenizer    # Supported extensions

        elif model_type == "graphcodebert":    code_extensions = {

            model = self.graphcodebert_model        ".py",

            tokenizer = self.graphcodebert_tokenizer        ".java",

        else:        ".cpp",

            raise ValueError(f"Unsupported model type: {model_type}")        ".c",

                ".cc",

        if model is None:        ".cxx",

            raise RuntimeError(f"{model_type} model not loaded")        ".js",

                ".jsx",

        # Tokenize        ".go",

        encoding = tokenizer(        ".php",

            code,        ".rb",

            max_length=self.max_length,        ".cs",

            padding=True,        ".ts",

            truncation=True,        ".txt",

            return_tensors="pt"    }

        )

            # Read from directory

        input_ids = encoding["input_ids"].to(self.device)    if input_dir:

        attention_mask = encoding["attention_mask"].to(self.device)        input_path = Path(input_dir)

                if not input_path.exists():

        # Predict            raise FileNotFoundError(f"Input directory not found: {input_dir}")

        with torch.no_grad():

            with autocast(dtype=self.dtype):        files = []

                outputs = model(input_ids=input_ids, attention_mask=attention_mask)        for ext in code_extensions:

                logits = outputs['logits']            files.extend(list(input_path.rglob(f"*{ext}")))

                        files = sorted(files)

                # Get probabilities

                probs = torch.softmax(logits, dim=-1)        print(f"📂 Found {len(files)} files in {input_dir}")

                vulnerable_prob = probs[0, 1].item()

                prediction = int(vulnerable_prob >= self.threshold)        for filepath in files:

                            code = read_file_safe(str(filepath))

                result = {            if code.strip():  # Skip empty files

                    'prediction': prediction,                samples.append(

                    'confidence': vulnerable_prob,                    {

                    'logits': logits[0].cpu().numpy().tolist(),                        "id": sha1_hash(str(filepath) + code)[:12],

                    'model': model_type                        "code": code,

                }                        "language": detect_language(str(filepath)),

                                        "filename": str(filepath),

                if return_attention:                    }

                    result['attention_weights'] = [                )

                        att[0].cpu().numpy() for att in outputs['attentions']

                    ]    # Read from JSONL file

                    if input_file:

                return result        input_path = Path(input_file)

            if not input_path.exists():

    def predict_ensemble(            raise FileNotFoundError(f"Input file not found: {input_file}")

        self,

        code: str,         if input_path.suffix.lower() in {".jsonl", ".ndjson"}:

        weights: Tuple[float, float] = (0.4, 0.6),            with input_path.open("r", encoding="utf-8") as f:

        return_details: bool = False                for line_num, line in enumerate(f, 1):

    ) -> Dict:                    if not line.strip():

        """Predict using ensemble of both models."""                        continue

        if self.codebert_model is None or self.graphcodebert_model is None:                    try:

            raise RuntimeError("Both models must be loaded for ensemble prediction")                        obj = json.loads(line)

                                code = (

        # Get predictions from both models                            obj.get("code")

        codebert_result = self.predict_single(code, "codebert", return_attention=True)                            or obj.get("content")

        graphcodebert_result = self.predict_single(code, "graphcodebert", return_attention=True)                            or obj.get("source", "")

                                )

        # Ensemble prediction                        if code.strip():

        ensemble_confidence = (                            samples.append(

            weights[0] * codebert_result['confidence'] +                                 {

            weights[1] * graphcodebert_result['confidence']                                    "id": obj.get("id") or f"line_{line_num}",

        )                                    "code": code,

        ensemble_prediction = int(ensemble_confidence >= self.threshold)                                    "language": obj.get("language")

                                            or detect_language(obj.get("filename", "")),

        result = {                                    "filename": obj.get("filename"),

            'prediction': ensemble_prediction,                                }

            'confidence': ensemble_confidence,                            )

            'model': 'ensemble'                    except json.JSONDecodeError as e:

        }                        print(f"⚠️ Invalid JSON on line {line_num}: {e}")

                                continue

        if return_details:        else:

            result['individual_results'] = {            # Plain text file - treat as single code sample

                'codebert': codebert_result,            code = read_file_safe(str(input_path))

                'graphcodebert': graphcodebert_result            if code.strip():

            }                samples.append(

            result['ensemble_weights'] = weights                    {

                                "id": sha1_hash(str(input_path))[:12],

        return result                        "code": code,

                            "language": detect_language(str(input_path)),

    def get_top_vulnerable_lines(                        "filename": str(input_path),

        self,                     }

        code: str,                 )

        model_type: str = "ensemble",

        weights: Tuple[float, float] = (0.4, 0.6)    print(f"✓ Loaded {len(samples)} code samples")

    ) -> List[Dict]:    return samples

        """Get top-K most vulnerable lines using attention analysis."""

        if model_type == "ensemble" and self.codebert_model and self.graphcodebert_model:

            # Use ensemble attentiondef save_results(results: List[Dict[str, Any]], output_path: str):

            codebert_result = self.predict_single(code, "codebert", return_attention=True)    """Save results to JSONL and CSV"""

            graphcodebert_result = self.predict_single(code, "graphcodebert", return_attention=True)    output_path = Path(output_path)

                output_path.parent.mkdir(parents=True, exist_ok=True)

            # Combine attention weights

            combined_attention = []    # Save JSONL

            for i in range(len(codebert_result['attention_weights'])):    jsonl_path = output_path.with_suffix(".jsonl")

                cb_att = codebert_result['attention_weights'][i]    with jsonl_path.open("w", encoding="utf-8") as f:

                gcb_att = graphcodebert_result['attention_weights'][i]        for result in results:

                combined = weights[0] * cb_att + weights[1] * gcb_att            f.write(json.dumps(result, ensure_ascii=False) + "\n")

                combined_attention.append(combined)    print(f"✓ Saved JSONL: {jsonl_path}")



            attention_weights = combined_attention[-1]  # Use last layer    # Save CSV

        else:    csv_path = output_path.with_suffix(".csv")

            # Use single model attention    if results:

            result = self.predict_single(code, model_type, return_attention=True)        keys = list(results[0].keys())

            attention_weights = result['attention_weights'][-1]  # Use last layer        with csv_path.open("w", newline="", encoding="utf-8") as f:

                    writer = csv.DictWriter(f, fieldnames=keys)

        # Get average attention across heads and tokens            writer.writeheader()

        avg_attention = np.mean(attention_weights, axis=(0, 1))  # Average over heads and query positions            for result in results:

                        writer.writerow(result)

        # Map to code lines        print(f"✓ Saved CSV: {csv_path}")

        lines = code.split('\n')

        tokenizer = self.codebert_tokenizer or self.graphcodebert_tokenizer

        # ============================================================================

        # Tokenize to get token-line mapping# MAIN

        encoding = tokenizer(# ============================================================================

            code,

            max_length=self.max_length,

            padding=True,def main():

            truncation=True,    parser = argparse.ArgumentParser(

            return_offsets_mapping=True        description="Test trained CodeBERT/GraphCodeBERT models on code samples",

        )        formatter_class=argparse.RawDescriptionHelpFormatter,

                epilog="""

        line_scores = {}Examples:

        for i, (start, end) in enumerate(encoding.offset_mapping):  # Single model inference

            if i < len(avg_attention) and start < len(code):  python test_models_on_code_samples.py \\

                line_num = code[:start].count('\n')      --input-dir ./test_samples \\

                if line_num not in line_scores:      --output outputs/predictions.jsonl \\

                    line_scores[line_num] = []      --model-choice codebert \\

                line_scores[line_num].append(avg_attention[i])      --checkpoint /kaggle/input/.../codebert_final_layer.pt



        # Average scores per line  # Ensemble both models

        line_rankings = []  python test_models_on_code_samples.py \\

        for line_num, scores in line_scores.items():      --input-dir ./test_samples \\

            if line_num < len(lines):      --output outputs/predictions.jsonl \\

                avg_score = np.mean(scores)      --ensemble \\

                line_rankings.append({      --codebert-checkpoint /kaggle/input/.../codebert_final_layer.pt \\

                    'line_number': line_num + 1,  # 1-indexed      --graph-checkpoint /kaggle/input/.../graphcodebert_final_layer.pt

                    'line_content': lines[line_num].strip(),        """,

                    'attention_score': float(avg_score),    )

                    'vulnerability_likelihood': min(1.0, float(avg_score) * 2)  # Scale to [0,1]

                })    # Input options

            parser.add_argument(

        # Sort by attention score and return top-K        "--input-dir", type=str, help="Directory with source files (recursive)"

        line_rankings.sort(key=lambda x: x['attention_score'], reverse=True)    )

        return line_rankings[:self.top_k]    parser.add_argument("--input-file", type=str, help="Single JSONL or text file")

        parser.add_argument(

    def analyze_file(        "--output",

        self,         type=str,

        file_path: str,         default="outputs/predictions.jsonl",

        model_type: str = "ensemble",        help="Output path (will create .jsonl and .csv)",

        include_static_analysis: bool = True    )

    ) -> Dict:

        """Comprehensive analysis of a code file."""    # Model options

        file_path = Path(file_path)    parser.add_argument(

                "--model-choice",

        # Read file        type=str,

        try:        choices=["codebert", "graphcodebert"],

            with open(file_path, 'r', encoding='utf-8') as f:        default="codebert",

                code = f.read()        help="Single model to use",

        except Exception as e:    )

            return {'error': f"Could not read file: {e}"}    parser.add_argument(

                "--ensemble",

        # Detect language        action="store_true",

        language = self._detect_language(file_path.suffix)        help="Ensemble both models (requires both checkpoints)",

            )

        # Generate file hash for caching

        file_hash = hashlib.md5(code.encode()).hexdigest()[:12]    # Checkpoint paths (Kaggle-compatible)

            parser.add_argument(

        # ML prediction        "--checkpoint", type=str, help="Checkpoint path for single model mode"

        if model_type == "ensemble":    )

            ml_result = self.predict_ensemble(code, return_details=True)    parser.add_argument(

        else:        "--codebert-checkpoint",

            ml_result = self.predict_single(code, model_type, return_attention=True)        type=str,

                default="/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/codebert/codebert_final_layer.pt",

        # Get vulnerable lines        help="CodeBERT checkpoint path",

        top_lines = self.get_top_vulnerable_lines(code, model_type)    )

            parser.add_argument(

        # Static analysis        "--graph-checkpoint",

        static_vulnerabilities = []        type=str,

        if include_static_analysis:        default="/kaggle/input/codeguardian-dataset-for-model-fine-tuning/fine-tuning/graphcodebert/graphcodebert_final_layer.pt",

            static_vulnerabilities = VulnerabilityDetector.detect_vulnerabilities(code, language)        help="GraphCodeBERT checkpoint path",

            )

        # Combine results

        all_vulnerabilities = []    # Base model names

            parser.add_argument("--base-codebert", type=str, default="microsoft/codebert-base")

        # Add ML-detected vulnerabilities    parser.add_argument(

        if ml_result['prediction'] == 1:        "--base-graph", type=str, default="microsoft/graphcodebert-base"

            # Create vulnerability entries for top lines    )

            for line_info in top_lines:

                all_vulnerabilities.append({    # Inference options

                    'type': 'ml_detected',    parser.add_argument(

                    'cwe': 'CWE-GENERIC',        "--batch-size", type=int, default=32, help="Inference batch size"

                    'severity': 'MEDIUM' if ml_result['confidence'] > 0.7 else 'LOW',    )

                    'line_number': line_info['line_number'],    parser.add_argument(

                    'line_content': line_info['line_content'],        "--threshold",

                    'confidence': ml_result['confidence'],        type=float,

                    'detection_method': 'machine_learning'        default=0.2,

                })        help="Classification threshold (0.0-1.0). Recommended: 0.15-0.25 for security-focused detection",

            )

        # Add static analysis results    parser.add_argument(

        for vuln in static_vulnerabilities:        "--ensemble-weights",

            vuln['detection_method'] = 'static_analysis'        type=str,

            all_vulnerabilities.append(vuln)        default="0.5,0.5",

                help="Ensemble weights as 'codebert,graphcodebert'",

        # Deduplicate by line number    )

        unique_vulnerabilities = {}

        for vuln in all_vulnerabilities:    args = parser.parse_args()

            line_num = vuln['line_number']

            if line_num not in unique_vulnerabilities or vuln['confidence'] > unique_vulnerabilities[line_num]['confidence']:    # Validation

                unique_vulnerabilities[line_num] = vuln    if not args.input_dir and not args.input_file:

                parser.error("Provide --input-dir or --input-file")

        return {

            'file_name': str(file_path),    if args.ensemble:

            'file_hash': file_hash,        if not os.path.exists(args.codebert_checkpoint):

            'language': language,            parser.error(f"CodeBERT checkpoint not found: {args.codebert_checkpoint}")

            'ml_prediction': ml_result,        if not os.path.exists(args.graph_checkpoint):

            'predicted_vulnerabilities': list(unique_vulnerabilities.values()),            parser.error(f"GraphCodeBERT checkpoint not found: {args.graph_checkpoint}")

            'top_lines': top_lines,    else:

            'total_vulnerabilities': len(unique_vulnerabilities),        checkpoint = args.checkpoint or (

            'severity_breakdown': self._get_severity_breakdown(unique_vulnerabilities.values()),            args.codebert_checkpoint

            'analysis_metadata': {            if args.model_choice == "codebert"

                'model_type': model_type,            else args.graph_checkpoint

                'threshold': self.threshold,        )

                'top_k': self.top_k,        if not os.path.exists(checkpoint):

                'file_size': len(code),            parser.error(f"Checkpoint not found: {checkpoint}")

                'line_count': len(code.split('\n'))

            }    print("\n" + "=" * 70)

        }    print("CODEGUARDIAN - MODEL INFERENCE")

        print("=" * 70)

    def _detect_language(self, extension: str) -> str:

        """Detect programming language from file extension."""    # Gather input samples

        ext_mapping = {    samples = gather_input_samples(args.input_dir, args.input_file)

            '.py': 'python',    if not samples:

            '.java': 'java',        print("❌ No valid code samples found!")

            '.c': 'c',        sys.exit(1)

            '.cpp': 'cpp',

            '.cxx': 'cpp',    codes = [s["code"] for s in samples]

            '.cc': 'cpp',

            '.go': 'go',    # Initialize inference runner

            '.php': 'php',    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

            '.rb': 'ruby',    runner = InferenceRunner(device=device, batch_size=args.batch_size)

            '.js': 'javascript',

            '.ts': 'typescript',    # Run inference

            '.cs': 'csharp',    results = []

            '.rs': 'rust',

            '.kt': 'kotlin',    if args.ensemble:

            '.scala': 'scala'        # Load both models

        }        tok_cb, model_cb = load_model_from_checkpoint(

        return ext_mapping.get(extension.lower(), 'unknown')            args.codebert_checkpoint, args.base_codebert, "codebert", device

            )

    def _get_severity_breakdown(self, vulnerabilities) -> Dict[str, int]:        tok_gcb, model_gcb = load_model_from_checkpoint(

        """Get count of vulnerabilities by severity."""            args.graph_checkpoint, args.base_graph, "graphcodebert", device

        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}        )

        for vuln in vulnerabilities:

            severity = vuln.get('severity', 'UNKNOWN')        # Parse weights

            breakdown[severity] = breakdown.get(severity, 0) + 1        w1, w2 = [float(x) for x in args.ensemble_weights.split(",")]

        return breakdown

        # Run ensemble

        probabilities = runner.predict_ensemble(

def setup_argparser() -> argparse.ArgumentParser:            tok_cb, model_cb, tok_gcb, model_gcb, codes, weights=(w1, w2)

    """Setup command line argument parser."""        )

    parser = argparse.ArgumentParser(

        description="Enhanced CodeGuardian Inference - IIT Delhi Hackathon Stage I"        model_name = "ensemble"

    )

        else:

    # Input options        # Single model

    input_group = parser.add_mutually_exclusive_group(required=True)        checkpoint = args.checkpoint or (

    input_group.add_argument(            args.codebert_checkpoint

        "--input-dir",             if args.model_choice == "codebert"

        type=str,            else args.graph_checkpoint

        help="Directory containing code files to analyze"        )

    )        base_name = (

    input_group.add_argument(            args.base_codebert if args.model_choice == "codebert" else args.base_graph

        "--input-file",        )

        type=str,

        help="Single code file to analyze"        tokenizer, model = load_model_from_checkpoint(

    )            checkpoint, base_name, args.model_choice, device

            )

    # Model options

    parser.add_argument(        probabilities = runner.predict_single_model(

        "--model",            tokenizer, model, codes, args.model_choice

        choices=["codebert", "graphcodebert", "ensemble"],        )

        default="ensemble",

        help="Model to use for inference"        model_name = args.model_choice

    )

        # Process results

    parser.add_argument(    print(f"\n{'='*70}")

        "--codebert-checkpoint",    print("GENERATING RESULTS")

        type=str,    print(f"{'='*70}")

        help="Path to CodeBERT checkpoint"

    )    for sample, prob in zip(samples, probabilities):

            pred_label = int(prob >= args.threshold)

    parser.add_argument(        tags = detect_vulnerability_tags(sample["code"])

        "--graphcodebert-checkpoint",

        type=str,        results.append(

        help="Path to GraphCodeBERT checkpoint"            {

    )                "id": sample["id"],

                    "filename": sample.get("filename"),

    # Inference options                "language": sample.get("language"),

    parser.add_argument(                "model": model_name,

        "--threshold",                "prob_vulnerable": round(float(prob), 4),

        type=float,                "pred_label": pred_label,

        default=0.18,                "pred_class": "vulnerable" if pred_label == 1 else "safe",

        help="Classification threshold (0.0-1.0)"                "explanation_tags": tags if tags else [],

    )            }

            )

    parser.add_argument(

        "--ensemble-weights",    # Save results

        type=str,    save_results(results, args.output)

        default="0.4,0.6",

        help="Ensemble weights as 'codebert,graphcodebert'"    # Summary

    )    print(f"\n{'='*70}")

        print("INFERENCE SUMMARY")

    parser.add_argument(    print(f"{'='*70}")

        "--top-k",    print(f"Total samples: {len(results)}")

        type=int,    print(f"Predicted vulnerable: {sum(1 for r in results if r['pred_label'] == 1)}")

        default=5,    print(f"Predicted safe: {sum(1 for r in results if r['pred_label'] == 0)}")

        help="Number of top vulnerable lines to return"    print(f"Threshold: {args.threshold}")

    )

        # Show top vulnerable samples

    parser.add_argument(    vulnerable = [r for r in results if r["pred_label"] == 1]

        "--batch-size",    if vulnerable:

        type=int,        print(f"\nTop 10 vulnerable predictions:")

        default=32,        vulnerable_sorted = sorted(

        help="Batch size for inference"            vulnerable, key=lambda x: x["prob_vulnerable"], reverse=True

    )        )[:10]

            for r in vulnerable_sorted:

    # Output options            tags_str = (

    parser.add_argument(                ", ".join(r["explanation_tags"]) if r["explanation_tags"] else "no tags"

        "--output",            )

        type=str,            print(

        default="predicted_vulnerabilities.json",                f"  {r['id']} | p={r['prob_vulnerable']:.3f} | {tags_str} | {r['filename']}"

        help="Output file for predictions"            )

    )

        print(f"\n✅ Done! Results saved to {args.output}")

    parser.add_argument(

        "--detailed-output",

        action="store_true",if __name__ == "__main__":

        help="Include detailed analysis in output"    main()

    )

    parser.add_argument(
        "--include-static",
        action="store_true",
        default=True,
        help="Include static analysis results"
    )

    # Performance options
    parser.add_argument(
        "--device",
        type=str,
        default="auto",
        help="Device to use (auto, cuda, cpu)"
    )

    parser.add_argument(
        "--max-length",
        type=int,
        default=512,
        help="Maximum sequence length"
    )

    return parser


def main():
    """Main inference function."""
    parser = setup_argparser()
    args = parser.parse_args()

    print("🔍 CodeGuardian Enhanced Inference - IIT Delhi Hackathon Stage I")
    print("=" * 70)

    # Parse ensemble weights
    if args.ensemble_weights:
        weights = tuple(map(float, args.ensemble_weights.split(',')))
        if len(weights) != 2 or abs(sum(weights) - 1.0) > 0.01:
            raise ValueError("Ensemble weights must sum to 1.0")
    else:
        weights = (0.4, 0.6)

    # Initialize inference engine
    engine = EnhancedInferenceEngine(
        device=args.device,
        max_length=args.max_length,
        batch_size=args.batch_size,
        threshold=args.threshold,
        top_k=args.top_k
    )

    # Load models
    if args.model in ["codebert", "ensemble"]:
        if not args.codebert_checkpoint:
            # Auto-detect checkpoint path
            if os.path.exists("/kaggle/working"):
                args.codebert_checkpoint = "/kaggle/working/ml/fine_tuning/codebert/codebert_r16_final.pt"
            else:
                args.codebert_checkpoint = "src/ml/fine_tuning/codebert/codebert_r16_final.pt"

        engine.load_model("codebert", args.codebert_checkpoint)

    if args.model in ["graphcodebert", "ensemble"]:
        if not args.graphcodebert_checkpoint:
            # Auto-detect checkpoint path
            if os.path.exists("/kaggle/working"):
                args.graphcodebert_checkpoint = "/kaggle/working/ml/fine_tuning/graphcodebert/graphcodebert_r16_final.pt"
            else:
                args.graphcodebert_checkpoint = "src/ml/fine_tuning/graphcodebert/graphcodebert_r16_final.pt"

        engine.load_model("graphcodebert", args.graphcodebert_checkpoint)

    # Collect input files
    input_files = []
    if args.input_dir:
        input_dir = Path(args.input_dir)
        for ext in ['.py', '.java', '.c', '.cpp', '.go', '.php', '.rb', '.js']:
            input_files.extend(input_dir.rglob(f'*{ext}'))
    else:
        input_files = [Path(args.input_file)]

    print(f"📂 Found {len(input_files)} files to analyze")
    print(f"🎯 Using model: {args.model}")
    print(f"🎚️  Threshold: {args.threshold}")
    print(f"📊 Top-K lines: {args.top_k}")

    # Process files
    results = []
    vulnerable_count = 0

    for file_path in input_files:
        print(f"\n🔍 Analyzing: {file_path}")

        result = engine.analyze_file(
            file_path,
            model_type=args.model,
            include_static_analysis=args.include_static
        )

        if 'error' not in result:
            is_vulnerable = result['ml_prediction']['prediction'] == 1
            if is_vulnerable:
                vulnerable_count += 1

            print(f"   {'🔴 VULNERABLE' if is_vulnerable else '✅ SAFE'} "
                  f"(confidence: {result['ml_prediction']['confidence']:.3f})")
            print(f"   Vulnerabilities found: {result['total_vulnerabilities']}")

            if not args.detailed_output:
                # Simplified output
                simplified_result = {
                    'file_name': result['file_name'],
                    'prediction': result['ml_prediction']['prediction'],
                    'confidence': result['ml_prediction']['confidence'],
                    'predicted_vulnerabilities': [
                        {
                            'type': v['type'],
                            'cwe': v['cwe'],
                            'severity': v['severity'],
                            'line_number': v['line_number']
                        } for v in result['predicted_vulnerabilities']
                    ],
                    'top_lines': [
                        {
                            'line_number': l['line_number'],
                            'vulnerability_likelihood': l['vulnerability_likelihood']
                        } for l in result['top_lines']
                    ]
                }
                results.append(simplified_result)
            else:
                results.append(result)
        else:
            print(f"   ❌ Error: {result['error']}")
            results.append(result)

    # Save results
    output_data = {
        'analysis_summary': {
            'total_files': len(input_files),
            'vulnerable_files': vulnerable_count,
            'safe_files': len(input_files) - vulnerable_count,
            'model_used': args.model,
            'threshold': args.threshold,
            'ensemble_weights': weights if args.model == 'ensemble' else None,
        },
        'results': results
    }

    with open(args.output, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"\n{'='*70}")
    print("📊 ANALYSIS SUMMARY")
    print(f"{'='*70}")
    print(f"Total files analyzed: {len(input_files)}")
    print(f"Vulnerable files: {vulnerable_count}")
    print(f"Safe files: {len(input_files) - vulnerable_count}")
    print(f"✅ Results saved to: {args.output}")

    # Cleanup
    del engine
    torch.cuda.empty_cache()
    gc.collect()


if __name__ == "__main__":
    main()
