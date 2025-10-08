import shutil, pathlib, uuid, re


def apply_fix_interactive(repo_path: str, finding_id: str, backup=True) -> bool:
    print("Enter file path containing the finding:")
    file_path = input().strip()
    p = pathlib.Path(file_path)
    if not p.exists():
        print("File not found.")
        return False
    text = p.read_text(encoding="utf-8", errors="ignore")
    changed = False
    if "shell=True" in text:
        new = text.replace("shell=True", "shell=False")
        changed = True
    else:
        new = re.sub(
            r"(\\n)",
            "\\n# CODEGUARDIAN: Review and apply parameterized/safe API.\\n",
            text,
            count=1,
        )
        changed = True
    if changed:
        if backup:
            shutil.copy(file_path, f"{file_path}.bak.{uuid.uuid4().hex[:6]}")
        p.write_text(new, encoding="utf-8")
        print(f"Updated {file_path} (backup created).")
        return True
    return False
