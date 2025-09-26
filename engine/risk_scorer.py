"""Risk scoring module for CodeGuardian findings."""

def calculate_risk_score(finding):
    """Calculate risk score based on severity, confidence, and exploitability."""
    
    # Base severity scores
    severity_scores = {
        "CRITICAL": 10.0,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.0,
        "INFO": 1.0
    }
    
    # Confidence multipliers
    confidence_multipliers = {
        "HIGH": 1.0,
        "MEDIUM": 0.8,
        "LOW": 0.6
    }
    
    # Get base score from severity
    severity = getattr(finding, 'severity', 'MEDIUM').upper()
    base_score = severity_scores.get(severity, 5.0)
    
    # Apply confidence multiplier
    confidence = getattr(finding, 'confidence', 'MEDIUM')
    if isinstance(confidence, (int, float)):
        # Convert numeric confidence to categorical
        if confidence >= 0.8:
            confidence = 'HIGH'
        elif confidence >= 0.5:
            confidence = 'MEDIUM'
        else:
            confidence = 'LOW'
    confidence_mult = confidence_multipliers.get(str(confidence).upper(), 0.8)
    
    # CVE-specific scoring
    if hasattr(finding, 'cvss_score'):
        # Use CVSS score for CVE findings
        cvss = getattr(finding, 'cvss_score', 5.0)
        risk_score = (cvss * 0.8) + (base_score * 0.2)
    else:
        # Static analysis findings
        risk_score = base_score * confidence_mult
        
        # Boost score for certain high-risk patterns
        rule_name = getattr(finding, 'rule', '').lower()
        if any(keyword in rule_name for keyword in ['sql_injection', 'xss', 'command_injection', 'deserialize']):
            risk_score *= 1.2
    
    # Normalize to 0-10 scale
    return min(10.0, max(0.0, round(risk_score, 1)))

def get_risk_level(score):
    """Convert numeric risk score to risk level."""
    if score >= 8.5:
        return "CRITICAL"
    elif score >= 6.5:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 2.0:
        return "LOW"
    else:
        return "INFO"

def calculate_project_risk(findings):
    """Calculate overall project risk metrics."""
    if not findings:
        return {
            "overall_score": 0.0,
            "risk_level": "LOW",
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        }
    
    # Calculate individual scores
    scores = [calculate_risk_score(f) for f in findings]
    
    # Count by risk level
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for score in scores:
        level = get_risk_level(score)
        risk_counts[level] += 1
    
    # Overall project score (weighted average with emphasis on high-risk findings)
    if scores:
        # Weight critical/high findings more heavily
        weighted_sum = sum(
            score * (2.0 if score >= 8.5 else 1.5 if score >= 6.5 else 1.0)
            for score in scores
        )
        weight_total = sum(
            2.0 if score >= 8.5 else 1.5 if score >= 6.5 else 1.0
            for score in scores
        )
        overall_score = weighted_sum / weight_total if weight_total > 0 else 0
    else:
        overall_score = 0
    
    return {
        "overall_score": round(overall_score, 1),
        "risk_level": get_risk_level(overall_score),
        "critical_count": risk_counts["CRITICAL"],
        "high_count": risk_counts["HIGH"], 
        "medium_count": risk_counts["MEDIUM"],
        "low_count": risk_counts["LOW"] + risk_counts["INFO"],
        "total_findings": len(findings),
        "avg_score": round(sum(scores) / len(scores), 1) if scores else 0.0
    }

if __name__ == "__main__":
    # Test the scoring system
    class TestFinding:
        def __init__(self, severity, rule="test"):
            self.severity = severity
            self.rule = rule
            self.confidence = "HIGH"
    
    class TestCVE:
        def __init__(self, cvss_score):
            self.cvss_score = cvss_score
            self.severity = "HIGH"
    
    findings = [
        TestFinding("CRITICAL", "sql_injection"),
        TestFinding("HIGH", "xss"),
        TestFinding("MEDIUM", "weak_crypto"),
        TestCVE(7.5)
    ]
    
    for f in findings:
        score = calculate_risk_score(f)
        level = get_risk_level(score)
        print(f"Finding: {getattr(f, 'rule', 'CVE')} → Score: {score}, Level: {level}")
    
    project_risk = calculate_project_risk(findings)
    print(f"\nProject Risk: {project_risk}")
