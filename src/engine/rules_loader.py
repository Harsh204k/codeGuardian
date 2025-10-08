import yaml, pathlib


def load_rules(langs: str):
    base = pathlib.Path(__file__).parent.parent / "rules"
    lang_list = (
        ["python", "java", "cpp", "csharp", "php", "javascript", "go"]
        if langs == "auto"
        else [x.strip() for x in langs.split(",")]
    )
    all_rules = []
    for lang in lang_list:
        f = base / f"{lang}.yml"
        if f.exists():
            data = yaml.safe_load(f.read_text(encoding="utf-8", errors="ignore")) or {}
            for r in data.get("rules", []):
                r["language"] = lang
                all_rules.append(r)
    return all_rules
