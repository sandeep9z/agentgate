import sys, json, pathlib
from .graph import review_terraform

def main():
    if len(sys.argv) < 2:
        print("usage: python -m agentgate.cli <file.tf> [--fail-on-high]"); sys.exit(2)
    rep = review_terraform(pathlib.Path(sys.argv[1]).read_text())
    print(json.dumps(rep, indent=2))
    if "--fail-on-high" in sys.argv and any(f["severity"] == "high" for f in rep["findings"]):
        sys.exit(1)

if __name__ == "__main__":
    main()
