import sys
from pathlib import Path
import pytest

# Ensure src is on sys.path
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Run specific tests
ret = pytest.main([str(ROOT / 'tests' / 'unit' / 'test_analyzers.py'), '-q'])

if ret != 0:
    raise SystemExit(ret)
