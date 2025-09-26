# 📋 **CODEGUARDIAN GIT TRACKING GUIDELINES**

## **✅ SHOULD BE TRACKED (Keep in Git)**

### **Core Application Files**
- `cli.py`, `enhanced_cli.py` - Command line interfaces
- `engine/` - Core scanning engine and modules
- `rules/` - Vulnerability detection rules (YAML files)
- `tests/` - Unit tests and test framework
- `tools/` - Utility scripts and helpers
- `demos/` - Example vulnerable code for testing

### **Configuration & Setup**
- `pyproject.toml`, `setup.py` - Package configuration
- `requirements*.txt` - Dependencies
- `pytest.ini` - Test configuration
- `README.md` - Documentation
- `.gitignore` - This file!

### **Documentation & Analysis**
- `*.md` files - Documentation and analysis reports
- Core documentation and setup guides

## **❌ SHOULD NOT BE TRACKED (Ignored by Git)**

### **Generated Data & Results**
- `*_results/`, `*_test_results/` - All scan result directories
- `models/` - Trained ML models (too large, regeneratable)
- `datasets/` - Training datasets (large external data)
- `*.sarif`, `*.xlsx`, `*.html` - Generated reports

### **Development Artifacts**
- `__pycache__/`, `*.pyc` - Python bytecode
- `.venv/`, `venv/` - Virtual environments
- `*.log`, `*.tmp` - Temporary files
- Debug and test scripts (`debug_*.py`, `test_*.py`)

### **ML Training Outputs**
- `*.pkl`, `*.joblib`, `*.model` - Serialized models
- Training checkpoints and intermediate files
- Large datasets like `DiverseVul Dataset/`

### **IDE & OS Files**
- `.vscode/`, `.idea/` - Editor settings
- `.DS_Store`, `Thumbs.db` - OS metadata files

## **🔧 Git Commands for Cleanup**

If you need to remove already-tracked files:

```bash
# Remove tracked files that should be ignored
git rm -r --cached models/
git rm -r --cached datasets/
git rm -r --cached "*_results/"
git rm -r --cached "*.sarif"

# Add the updated .gitignore
git add .gitignore
git commit -m "Update .gitignore for CodeGuardian tool"
```

## **📦 Repository Structure (What Git Sees)**

```
codeguardian/
├── .gitignore ✅
├── README.md ✅
├── pyproject.toml ✅
├── requirements.txt ✅
├── cli.py ✅
├── enhanced_cli.py ✅
├── engine/ ✅
│   ├── scanner.py ✅
│   ├── rules_loader.py ✅
│   └── ... ✅
├── rules/ ✅
│   ├── python.yml ✅
│   ├── java.yml ✅
│   └── ... ✅
├── ml/ ✅
│   ├── hybrid_detector.py ✅
│   └── ... ✅
├── demos/ ✅
├── tests/ ✅
└── tools/ ✅

# IGNORED (not in Git):
├── models/ ❌
├── datasets/ ❌
├── *_results/ ❌
├── __pycache__/ ❌
└── *.log ❌
```

This keeps the repository clean, focused on source code, and prevents large binary files from bloating the Git history!