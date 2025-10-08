# codeGuardian - Quick start

This repo contains code analysis, ML models, and datasets for code vulnerability detection.

Quick commands (Windows PowerShell):

- Run the full analyzer runner (uses `src` on PYTHONPATH):

  .\bin\run_analysis.ps1

- Run unit tests (activates `.venv` if present):

  .\bin\run_tests.ps1

Where results go

- Analysis output and ad-hoc runner outputs are stored under the `analysis/` directory and `reports/analysis/` by convention. See `docs/STATIC_ANALYSIS_MASTER.md` for more details on analyzers and configuration.

Recommended tools

- cppcheck (optional) — provide its path when prompted or set the `CPPCHECK_PATH` environment variable.
- SpotBugs, Clang tools, etc. — see `docs/STATIC_ANALYSIS_MASTER.md` for installation links and recommended versions.

Contributing small utilities

- Small CLI wrappers belong in `bin/`.
- Data preprocessing scripts are in `scripts/preprocessing/` and ML helpers in `scripts/training/`.

More documentation

- See `docs/STATIC_ANALYSIS_MASTER.md` and other docs in `docs/` for deeper explanations.
