import json, pathlib  # <-- add pathlib


def export_sarif(findings, out_path):
    def to_file_uri(p):
        # absolute path -> file:// URI, works even if file doesn't exist
        try:
            return pathlib.Path(str(p)).resolve(strict=False).as_uri()
        except Exception:
            # very defensive fallback
            pp = pathlib.Path(str(p))
            if not pp.is_absolute():
                pp = (pathlib.Path.cwd() / pp).resolve()
            return "file:///" + str(pp).replace("\\", "/").lstrip("/")

    results = []
    for f in findings:
        uri = to_file_uri(f.file)
        results.append(
            {
                "ruleId": f.rule_id,
                "message": {
                    "text": f"{f.name} | {f.cwe} {f.owasp} | conf={round(f.confidence, 2)}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {
                                "startLine": (
                                    int(f.line) if getattr(f, "line", None) else 0
                                )
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "cwe": f.cwe,
                },
            }
        )

    runs = [
        {
            "tool": {
                "driver": {"name": "CodeGuardian", "informationUri": "https://local"}
            },
            "results": results,
        }
    ]
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    }
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
