import subprocess, pathlib
def run_dependency_audit(path: str, outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    sbom = outdir / "sbom.json"; osv = outdir / "osv_report.json"
    try:
        subprocess.run(["syft","packages",path,"-o","json"], check=True, stdout=sbom.open("w", encoding="utf-8"))
        subprocess.run(["osv-scanner","--sbom",str(sbom)], check=False, stdout=osv.open("w", encoding="utf-8"))
        print(f"Dependency audit complete â†’ {osv}")
    except FileNotFoundError:
        print("Install syft and osv-scanner for dependency CVE audits.")
