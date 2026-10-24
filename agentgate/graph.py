"""LangGraph pipeline: rules -> enrich (Tavily) -> review (Nemotron) -> verify -> report."""
from __future__ import annotations
from typing import TypedDict
from langgraph.graph import StateGraph, END
from . import llm, tavily
from .rules import Finding, run_rules
from .verifier import verify_additional, verify_explanations

SYSTEM = """You are a cloud security reviewer for Terraform. You receive the source and findings from a
deterministic scanner. Reply with ONLY a JSON object:
{"explanations":[{"rule_id":..,"resource":..,"priority":1-5,"why":"one sentence","fix":"HCL snippet or one-line fix"}],
 "additional_findings":[{"rule_id":"SHORT-NAME","resource":"type.name","severity":"high|medium|low","message":"..","evidence":"EXACT text copied from the source"}]}
Rules: only explain scanner findings you were given. Only add findings that are real security or cost problems
NOT already reported; copy evidence verbatim from the source; if unsure, add nothing. Port 80/443 open to the internet is normal."""

class State(TypedDict, total=False):
    tf: str
    findings: list[Finding]
    refs: dict
    llm_used: bool
    explanations: dict
    rejected: list
    report: dict

def n_rules(s: State) -> State:
    return {"findings": run_rules(s["tf"])}

def n_enrich(s: State) -> State:
    refs = {}
    for rid in {f.rule_id for f in s["findings"]}:
        r = tavily.lookup(rid)
        if r: refs[rid] = r
    return {"refs": refs}

def n_review(s: State) -> State:
    if not llm.available():
        return {"llm_used": False, "explanations": {}, "rejected": []}
    import json
    payload = "SOURCE:\n" + s["tf"] + "\n\nSCANNER FINDINGS:\n" + json.dumps([f.to_dict() for f in s["findings"]])
    try:
        out = llm.chat_json(SYSTEM, payload)
    except Exception as e:  # network / auth error: degrade to rules-only, say so
        return {"llm_used": False, "explanations": {}, "rejected": [{"reason": f"LLM error: {type(e).__name__}"}]}
    extra, rejected = verify_additional(s["tf"], out.get("additional_findings", []))
    seen = {f.key() for f in s["findings"]}
    extra = [f for f in extra if f.key() not in seen]
    return {"llm_used": True, "findings": s["findings"] + extra, "rejected": rejected,
            "explanations": verify_explanations(s["findings"], out.get("explanations", []))}

def n_report(s: State) -> State:
    sev = {"high": 0, "medium": 1, "low": 2}
    rows = []
    for f in s["findings"]:
        e = s.get("explanations", {}).get((f.rule_id, f.resource), {})
        rows.append({**f.to_dict(), "priority": e.get("priority"), "why": e.get("why"), "fix": e.get("fix"),
                     "reference": s.get("refs", {}).get(f.rule_id)})
    rows.sort(key=lambda r: (sev.get(r["severity"], 3), r["priority"] or 9))
    return {"report": {"findings": rows, "llm_used": s.get("llm_used", False),
                       "rejected_llm_claims": s.get("rejected", [])}}

def build():
    g = StateGraph(State)
    for name, fn in [("rules", n_rules), ("enrich", n_enrich), ("review", n_review), ("report", n_report)]:
        g.add_node(name, fn)
    g.set_entry_point("rules")
    g.add_edge("rules", "enrich"); g.add_edge("enrich", "review"); g.add_edge("review", "report"); g.add_edge("report", END)
    return g.compile()

def review_terraform(tf: str) -> dict:
    return build().invoke({"tf": tf})["report"]
