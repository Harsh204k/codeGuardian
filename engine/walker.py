import pathlib, fnmatch

DEFAULT_IGNORES = ["*/.git/*","*/node_modules/*","*/build/*","*/dist/*","*/venv/*","*/.venv/*"]

LANG_MAP = {
    ".py":"python",".java":"java",".c":"cpp",".h":"cpp",".cpp":"cpp",".hpp":"cpp",".cs":"csharp",".php":"php"
}

def load_ignores(root: str):
    ig = set(DEFAULT_IGNORES)
    cg = pathlib.Path(root) / ".cgignore"
    if cg.exists():
        for line in cg.read_text(encoding="utf-8", errors="ignore").splitlines():
            line=line.strip()
            if line and not line.startswith("#"): ig.add(line)
    return list(ig)

def is_ignored(path: str, ignores):
    return any(fnmatch.fnmatch(path, pat) for pat in ignores)

def collect_files(root: str, langs: str):
    rootp = pathlib.Path(root)
    ignores = load_ignores(root)
    targets = []
    for p in rootp.rglob("*"):
        if not p.is_file(): continue
        sp = str(p)
        if is_ignored(sp, ignores): continue
        lang = LANG_MAP.get(p.suffix.lower())
        if not lang: continue
        if langs != "auto" and lang not in langs.split(","): continue
        targets.append((lang, p))
    return targets
