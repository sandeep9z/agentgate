"""Deterministic verifier: nothing the LLM says reaches the report unless it traces to the source."""
from __future__ import annotations
import re
from .rules import Finding, parse

def _n(s: str) -> str: return re.sub(r"\s+", "", s or "")

def verify_additional(tf: str, proposed: list[dict]) -> tuple[list[Finding], list[dict]]:
    addrs = set(parse(tf))
    src = _n(tf)
    ok, rejected = [], []
    for p in proposed or []:
        try:
            res, ev = str(p["resource"]), str(p["evidence"])
        except KeyError:
            rejected.append({**p, "reason": "missing fields"}); continue
        if res not in addrs:
            rejected.append({**p, "reason": "resource does not exist"}); continue
        if len(_n(ev)) < 6 or _n(ev) not in src:
            rejected.append({**p, "reason": "evidence not found verbatim in source"}); continue
        ok.append(Finding("LLM-" + str(p.get("rule_id", "FINDING")).upper().replace("LLM-", ""),
                          res, str(p.get("severity", "medium")).lower(),
                          str(p.get("message", ""))[:300], ev, source="llm"))
    return ok, rejected

def verify_explanations(findings: list[Finding], expl: list[dict]) -> dict:
    keys = {f.key() for f in findings}
    return {(e.get("rule_id"), e.get("resource")): e for e in expl or []
            if (e.get("rule_id"), e.get("resource")) in keys}
