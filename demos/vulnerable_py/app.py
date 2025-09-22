import subprocess, pickle
user = input("cmd? ")
subprocess.run(user, shell=True)  # vuln: PY-CMDI-001
def load(x): return pickle.loads(x)  # vuln: PY-DESER-001
