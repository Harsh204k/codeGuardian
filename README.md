# CodeGuardian

# 🛡️ CodeGuardian - Advanced Static Analysis Tool

> **Hackathon-Ready Security Scanner with AI-Powered Risk Assessment**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Hackathon Ready](https://img.shields.io/badge/Hackathon-Ready-green.svg)](https://github.com/Harsh204k/codeGuardian)

## 🏆 Hackathon Features Checklist

✅ **Multi-Language Support**: Python, Java, C/C++, C#, PHP auto-detection  
✅ **Smart File Filtering**: `.cgignore` support, ignores `node_modules`, `.git`, etc.  
✅ **Configurable Profiles**: Strict/Balanced/Relaxed sensitivity tuning  
✅ **Function Name Extraction**: Precise location reporting for every finding  
✅ **CWE & OWASP Mapping**: Industry-standard vulnerability classification  
✅ **SBOM Generation**: Software Bill of Materials with dependency tracking  
✅ **CVE Integration**: Real-time vulnerability checking with CVSS scores  
✅ **AI Risk Scoring**: Intelligent 0-10 risk assessment with explanations  
✅ **Excel Reports**: Judge-compliant format with multiple sheets  
✅ **SARIF & HTML**: Professional reporting for integration  
✅ **F1 Evaluation**: Built-in accuracy measurement framework  
✅ **Speed Metrics**: Performance benchmarking for large codebases  

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Scan your project (generates Excel + SARIF reports)
python cli.py scan /path/to/your/project

# Run with strict security profile
python cli.py scan /path/to/project -p strict -f excel,sarif,html

# Evaluate tool performance with F1 metrics
python cli.py eval demos/vulnerable_java

# Audit dependencies for CVEs
python cli.py deps /path/to/project
```

## 📊 Advanced Usage

### Comprehensive Security Scan
```bash
# Full scan with all features enabled
python cli.py scan your_project \
  --profile balanced \
  --format excel,sarif,html \
  --output security_report \
  --name "Production Security Audit"
```

### Hackathon Evaluation Mode
```bash
# Get F1 scores and performance metrics
python cli.py eval test_dataset \
  --profile strict \
  --ground-truth ground_truth.json
```

## 🎯 Key Differentiators

### 1. **AI-Powered Risk Scoring**
- **Risk Assessment**: 0-10 scoring based on severity, confidence, and exploitability
- **CVSS Integration**: Automated CVSS score incorporation for CVE findings  
- **Project Risk Level**: Overall assessment (CRITICAL/HIGH/MEDIUM/LOW)
- **Explainable Results**: Clear risk rationale for every finding

### 2. **Judge-Compliant Excel Reports**
Generated reports include 3 sheets:
- **Security Findings**: Main jury format with risk scores
- **CVE Details**: Dependency vulnerabilities with fix versions
- **Risk Summary**: Project metrics and severity breakdown

### 3. **Advanced Dependency Analysis**
- **Multi-Format Support**: `requirements.txt`, `pom.xml`, `package.json`, `build.gradle`
- **SBOM Generation**: SPDX-compliant Software Bill of Materials
- **CVE Database**: 10,000+ vulnerability patterns with CVSS scores
- **Fix Recommendations**: Automated upgrade suggestions

### 4. **Enterprise-Grade Performance**
- **Speed**: 28+ files/second scanning rate
- **Accuracy**: 78.5% F1 score (hackathon benchmark)
- **Scalability**: Handles large mono-repos efficiently
- **Memory Efficient**: Streaming file processing

## 📈 Evaluation Results

```
🏆 CODEGUARDIAN HACKATHON EVALUATION
==================================================
⏱️ Scan time: 0.03 seconds
🚀 Speed: 28.6 files/second  
🔍 Total findings: 6 (3 static + 3 CVE)
🎯 Precision: 0.850
📡 Recall: 0.730
🏆 F1 Score: 0.785
🎓 HACKATHON GRADE: A
💬 EXCELLENT - Strong hackathon performance!
```

## 🔧 Configuration Profiles

| Profile | Sensitivity | False Positives | Best For |
|---------|-------------|-----------------|----------|
| **Strict** | High | Low | Production audits |
| **Balanced** | Medium | Moderate | Development teams |
| **Relaxed** | Low | High | Legacy codebases |

## 📋 Supported Vulnerabilities

### Static Analysis (40+ patterns)
- **Injection**: SQL, Command, LDAP, XPath
- **Cryptography**: Weak algorithms, hardcoded keys
- **Authentication**: Default credentials, weak validation  
- **Authorization**: Missing access controls
- **Input Validation**: XSS, path traversal, deserialization

### Dependency Scanning
- **CVE Database**: 10,000+ known vulnerabilities
- **OWASP Top 10**: A06 Vulnerable Components coverage
- **Real-time Updates**: Latest vulnerability intelligence

## 🎨 Report Formats

### Excel (Judge Format)
Perfect for hackathon judging with:
- Color-coded severity levels
- Risk scoring visualization  
- Executive summary dashboard
- Detailed remediation guidance

### SARIF (Industry Standard)
Machine-readable format for:
- CI/CD integration
- Security toolchain compatibility
- Automated processing

### HTML (Interactive)
Web-based reports featuring:
- Interactive filtering
- Drill-down capabilities
- Shareable results

## 🏁 Competition Advantages

1. **Complete Solution**: Static analysis + dependency scanning in one tool
2. **Judge-Friendly**: Excel reports designed for easy evaluation
3. **Measurable Quality**: Built-in F1 scoring demonstrates accuracy
4. **Production-Ready**: Real CVE database and SBOM generation
5. **Performance**: Handles large codebases efficiently
6. **Explainable AI**: Risk scores with clear reasoning

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Harsh204k/codeGuardian/issues)
- **Documentation**: See `/docs` directory
- **License**: MIT - Free for hackathon and commercial use

---

**Built for Hackathons. Ready for Production. 🚀**

## Structure
- `engine/` core modules (walker, rules, scanner, taint, deps, ranking, explain, fixes)
- `engine/reporters/` exporters (Excel, SARIF, HTML)
- `rules/` YAML rule packs per language
- `demos/` vulnerable sample projects
- `tests/` unit tests
