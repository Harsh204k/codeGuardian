"""LLM-based fix generation using fine-tuned code generation models."""

from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import re


class LLMFixGenerator:
    def __init__(self, model_name="salesforce/codet5-large-ntp-py"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.generator = None

    def load_model(self):
        """Load pre-trained code generation model."""
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForCausalLM.from_pretrained(self.model_name)
        self.generator = pipeline(
            "text-generation",
            model=self.model,
            tokenizer=self.tokenizer,
            max_length=512,
            temperature=0.1,
            do_sample=True,
        )

    def generate_fix_prompt(self, vulnerable_code, vulnerability_type, context=""):
        """Create prompt for fix generation."""
        prompt = f"""
# Fix the following security vulnerability in this code:
# Vulnerability: {vulnerability_type}
# Context: {context}

# Vulnerable Code:
{vulnerable_code}

# Fixed Code:
"""
        return prompt.strip()

    def generate_fix(self, vulnerable_code, vulnerability_type, context=""):
        """Generate secure code fix."""
        if not self.generator:
            self.load_model()

        prompt = self.generate_fix_prompt(vulnerable_code, vulnerability_type, context)

        # Generate fix
        results = self.generator(
            prompt,
            max_new_tokens=200,
            num_return_sequences=3,
            pad_token_id=self.tokenizer.eos_token_id,
        )

        fixes = []
        for result in results:
            generated = result["generated_text"]
            # Extract the fixed code part
            if "# Fixed Code:" in generated:
                fixed_code = generated.split("# Fixed Code:")[-1].strip()
                fixes.append(
                    {
                        "fixed_code": fixed_code,
                        "confidence": self._calculate_fix_confidence(
                            fixed_code, vulnerability_type
                        ),
                    }
                )

        return sorted(fixes, key=lambda x: x["confidence"], reverse=True)

    def _calculate_fix_confidence(self, fixed_code, vuln_type):
        """Calculate confidence score for generated fix."""
        confidence = 0.7  # Base confidence

        # Check for common secure patterns
        secure_patterns = {
            "SQL Injection": [r"PreparedStatement", r"setString\(", r"setInt\("],
            "Command Injection": [r"ProcessBuilder", r"whitelist", r"validate"],
            "XSS": [r"htmlspecialchars", r"escapeHtml", r"sanitize"],
            "Path Traversal": [r"Paths\.get", r"normalize", r"startsWith"],
        }

        if vuln_type in secure_patterns:
            for pattern in secure_patterns[vuln_type]:
                if re.search(pattern, fixed_code, re.IGNORECASE):
                    confidence += 0.1

        # Penalize if still contains vulnerable patterns
        vulnerable_patterns = [
            r"exec\s*\(",
            r"eval\s*\(",
            r"String\s+sql\s*=.*\+",
            r"innerHTML\s*=",
        ]

        for pattern in vulnerable_patterns:
            if re.search(pattern, fixed_code, re.IGNORECASE):
                confidence -= 0.3

        return max(0.1, min(1.0, confidence))


# Training data preparation for fine-tuning
class FixTrainingDataGenerator:
    @staticmethod
    def create_training_pairs():
        """Create vulnerable → secure code pairs for training."""
        training_pairs = [
            {
                "vulnerable": 'String sql = "SELECT * FROM users WHERE id = " + userId;',
                "secure": 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); stmt.setString(1, userId);',
                "vulnerability": "SQL Injection",
            },
            {
                "vulnerable": "Runtime.getRuntime().exec(userCommand);",
                "secure": "if (ALLOWED_COMMANDS.contains(userCommand)) { ProcessBuilder pb = new ProcessBuilder(userCommand); pb.start(); }",
                "vulnerability": "Command Injection",
            },
            {
                "vulnerable": 'response.getWriter().println("<div>" + userInput + "</div>");',
                "secure": 'response.getWriter().println("<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>");',
                "vulnerability": "XSS",
            },
            {
                "vulnerable": "new File(basePath + File.separator + fileName);",
                "secure": "Path safePath = Paths.get(basePath).resolve(fileName).normalize(); if (safePath.startsWith(basePath)) { new File(safePath.toString()); }",
                "vulnerability": "Path Traversal",
            },
        ]
        return training_pairs

    @staticmethod
    def format_for_training(pairs):
        """Format pairs for model fine-tuning."""
        formatted = []
        for pair in pairs:
            text = (
                f"Fix {pair['vulnerability']}: {pair['vulnerable']} → {pair['secure']}"
            )
            formatted.append({"text": text})
        return formatted


# Integration with CodeGuardian
def integrate_llm_fixes(finding):
    """Integrate LLM fix generation with existing CodeGuardian findings."""
    fix_generator = LLMFixGenerator()

    # Extract vulnerability context
    vuln_type = getattr(finding, "name", "Security Vulnerability")
    code_snippet = getattr(finding, "snippet", "")

    if code_snippet:
        fixes = fix_generator.generate_fix(
            code_snippet,
            vuln_type,
            context=f"File: {finding.file}, Line: {finding.line}",
        )

        if fixes:
            best_fix = fixes[0]
            return {
                "original_code": code_snippet,
                "fixed_code": best_fix["fixed_code"],
                "confidence": best_fix["confidence"],
                "llm_generated": True,
            }

    return None


if __name__ == "__main__":
    # Example usage
    generator = LLMFixGenerator()

    vulnerable = (
        'String query = "SELECT * FROM users WHERE name = \'" + userName + "\'";'
    )
    fixes = generator.generate_fix(vulnerable, "SQL Injection")

    print("Generated Fixes:")
    for i, fix in enumerate(fixes, 1):
        print(f"{i}. Confidence: {fix['confidence']:.2f}")
        print(f"   Fix: {fix['fixed_code']}")
        print()
