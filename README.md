# CodeGuardian

A lightweight static analysis and quick-fix engine.

## Structure
- `engine/` core modules (walker, rules, scanner, taint, deps, ranking, explain, fixes)
- `engine/reporters/` exporters (Excel, SARIF, HTML)
- `rules/` YAML rule packs per language
- `demos/` vulnerable sample projects
- `tests/` unit tests
