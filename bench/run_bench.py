"""Benchmark: rules-only vs LLM-only vs AgentGate on labeled Terraform snippets.
Metrics: precision, recall, false-alarm rate (fraction of clean snippets with >=1 finding), bootstrap 95% CIs.
LLM systems run only if NEBIUS_API_KEY is set. Ground-truth labels were written by the author (see README limitations)."""
import json, random, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from agentgate import llm
from agentgate.rules import run_rules
from agentgate.graph import review_terraform, SYSTEM
from agentgate.verifier import verify_additional

CASES = json.load(open(pathlib.Path(__file__).parent / "cases.json"))
def norm(rule, res, src): return ("OTHER" if src == "llm" else rule, res)

def sys_rules(tf): return {norm(f.rule_id, f.resource, f.source) for f in run_rules(tf)}
def sys_agentgate(tf):
    return {norm(f["rule_id"], f["resource"], f["source"]) for f in review_terraform(tf)["findings"]}
def sys_llm_only(tf):
    out = llm.chat_json("You are a Terraform security reviewer. Reply ONLY JSON: "
        '{"findings":[{"resource":"type.name","message":".."}]}. Report real security or cost issues only.', tf)
    res = set()
    for f in out.get("findings", []):
        res.add(("OTHER", str(f.get("resource"))))
    return res

def score(fn):
    per = []
    for c in CASES:
        truth = {tuple(t) for t in c["truth"]}
        pred = fn(c["tf"])
        # LLM-only has no rule ids: match any truth on the same resource
        if fn is sys_llm_only:
            pred = {t for t in truth if ("OTHER", t[1]) in pred} | {("FP", p[1]) for p in pred if p[1] not in {t[1] for t in truth}}
        per.append((len(pred & truth), len(pred - truth), len(truth - pred), not truth, bool(pred)))
    return per

def agg(per):
    tp = sum(p[0] for p in per); fp = sum(p[1] for p in per); fn = sum(p[2] for p in per)
    clean = [p for p in per if p[3]]
    return (tp / (tp + fp) if tp + fp else 1.0, tp / (tp + fn) if tp + fn else 1.0,
            (sum(p[4] for p in clean) / len(clean)) if clean else 0.0)

def boot(per, n=2000, seed=0):
    rnd = random.Random(seed); vals = []
    for _ in range(n):
        vals.append(agg([rnd.choice(per) for _ in per]))
    ci = lambda i: tuple(round(x, 2) for x in (sorted(v[i] for v in vals)[int(.025*n)], sorted(v[i] for v in vals)[int(.975*n)]))
    return ci(0), ci(1), ci(2)

if __name__ == "__main__":
    systems = [("rules-only", sys_rules)]
    if llm.available():
        systems += [("llm-only (Nemotron)", sys_llm_only), ("AgentGate (rules+LLM+verifier)", sys_agentgate)]
    else:
        print("NEBIUS_API_KEY not set: running rules-only baseline only.\n")
    print(f"{len(CASES)} snippets, {sum(len(c['truth']) for c in CASES)} labeled issues\n")
    print(f"{'system':34}{'precision':>16}{'recall':>16}{'false-alarm':>16}")
    for name, fn in systems:
        per = score(fn); p, r, fa = agg(per); cp, cr, cf = boot(per)
        print(f"{name:34}{p:7.2f} {str(cp):>8}{r:7.2f} {str(cr):>8}{fa:7.2f} {str(cf):>8}")
