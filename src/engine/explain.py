def build_explanation(finding):
    return f"{finding.name}. {finding.why} (Mapped to {finding.cwe or 'â€”'} / {finding.owasp or 'â€”'})."
