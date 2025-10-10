#!/bin/bash
# ============================================================================
# Kaggle-Optimized Installation Script for CodeGuardian
# ============================================================================
# This script installs dependencies in the correct order to avoid conflicts
# Use this in Kaggle notebooks instead of: pip install -r requirements.txt
# ============================================================================

set -e  # Exit on error

echo "========================================"
echo "🚀 Installing CodeGuardian Dependencies"
echo "========================================"
echo "Environment: Kaggle"
echo "Python: $(python --version)"
echo "========================================"

# Step 1: Fix pyarrow version FIRST (most critical conflict)
echo ""
echo "📦 Step 1: Fixing pyarrow version..."
pip install --quiet --no-warn-script-location 'pyarrow>=19.0.0,<20.0.0' --force-reinstall

# Step 2: Fix cudf-polars to match cudf version
echo ""
echo "📦 Step 2: Fixing cudf-polars version..."
pip install --quiet --no-warn-script-location cudf-polars-cu12==25.2.2 polars==1.21.0 --force-reinstall

# Step 3: Install core dependencies (most are already installed)
echo ""
echo "📦 Step 3: Installing core dependencies..."
pip install --quiet --no-warn-script-location \
    'pyyaml>=6.0' \
    'regex>=2023.0.0' \
    'openpyxl>=3.1.0' \
    'rich>=13.0.0,<14.0.0' \
    'requests>=2.31.0' \
    'click>=8.0.0' \
    'tqdm>=4.64.0' \
    'jsonschema>=4.17.0'

# Step 4: Install ML libraries with version constraints
echo ""
echo "📦 Step 4: Installing ML libraries..."
pip install --quiet --no-warn-script-location \
    'scikit-learn>=1.5.0,<1.6.0' \
    'xgboost>=1.7.0' \
    'joblib>=1.3.0'

# Step 5: Install deep learning libraries (most pre-installed)
echo ""
echo "📦 Step 5: Installing deep learning libraries..."
pip install --quiet --no-warn-script-location \
    'transformers>=4.40.0' \
    'tokenizers>=0.19.0' \
    'datasets>=2.19.0' \
    'accelerate>=0.30.0'

# Step 6: Install monitoring tools
echo ""
echo "📦 Step 6: Installing monitoring tools..."
pip install --quiet --no-warn-script-location \
    'tensorboard>=2.18.0,<2.19.0' \
    'loguru>=0.7.0' \
    'memory_profiler>=0.61.0' \
    'bandit>=1.7.5'

# Step 7: Install testing tools
echo ""
echo "📦 Step 7: Installing testing tools..."
pip install --quiet --no-warn-script-location \
    'pytest>=7.0.0' \
    'pytest-cov>=4.0.0'

echo ""
echo "========================================"
echo "✅ Installation complete!"
echo "========================================"
echo ""
echo "📊 Checking for remaining conflicts..."
pip check || echo "⚠️  Some conflicts remain (this is normal on Kaggle)"

echo ""
echo "🎯 Key package versions installed:"
python -c "
import sys
packages = [
    'numpy', 'pandas', 'scikit-learn', 'pyarrow', 
    'torch', 'transformers', 'datasets'
]
for pkg in packages:
    try:
        mod = __import__(pkg.replace('-', '_'))
        version = getattr(mod, '__version__', 'unknown')
        print(f'  {pkg}: {version}')
    except ImportError:
        print(f'  {pkg}: NOT INSTALLED')
"

echo ""
echo "========================================"
echo "🎉 Ready to run preprocessing scripts!"
echo "========================================"
