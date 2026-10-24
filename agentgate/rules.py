"""Deterministic Terraform security/cost rules. No LLM involved."""
from __future__ import annotations
import re
from dataclasses import dataclass, asdict
import hcl2

@dataclass
class Finding:
    rule_id: str
    resource: str          # e.g. aws_security_group.web
    severity: str          # high | medium | low
    message: str
    evidence: str          # exact substring of the source
    source: str = "rules"  # rules | llm
    def key(self): return (self.rule_id, self.resource)
    def to_dict(self): return asdict(self)

def _norm(v):
    if isinstance(v, str) and len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    if isinstance(v, list): return [_norm(x) for x in v]
    if isinstance(v, dict):
        return {_norm(k): _norm(x) for k, x in v.items() if k != "__is_block__"}
    return v

def parse(tf: str) -> dict[str, dict]:
    """Return {'type.name': attrs}."""
    doc = _norm(hcl2.loads(tf))
    out = {}
    for block in doc.get("resource", []):
        for rtype, named in block.items():
            for name, attrs in named.items():
                out[f"{rtype}.{name}"] = attrs
    return out

def _s(v):
    while isinstance(v, list) and v: v = v[0]
    return v

def _ev(tf: str, pattern: str, fallback: str) -> str:
    m = re.search(pattern, tf)
    return m.group(0).strip() if m else fallback

def run_rules(tf: str) -> list[Finding]:
    res = parse(tf)
    F: list[Finding] = []
    for addr, a in res.items():
        t = addr.split(".")[0]
        if t == "aws_security_group" or t == "aws_security_group_rule":
            blocks = a.get("ingress", []) if t == "aws_security_group" else [a]
            for ing in blocks:
                cidrs = _s(ing.get("cidr_blocks", [])) or []
                cidrs = cidrs if isinstance(cidrs, list) else [cidrs]
                if "0.0.0.0/0" in cidrs:
                    fp, tp = _s(ing.get("from_port", 0)), _s(ing.get("to_port", 0))
                    try: fp, tp = int(fp), int(tp)
                    except (TypeError, ValueError): continue
                    admin = any(fp <= p <= tp for p in (22, 3389, 3306, 5432))
                    if admin or (fp == 0 and tp == 0) or tp == 65535:
                        F.append(Finding("SG-OPEN-ADMIN", addr, "high",
                            f"Ingress from the whole internet on ports {fp}-{tp}.",
                            '0.0.0.0/0'))
        if t == "aws_s3_bucket" and _s(a.get("acl")) in ("public-read", "public-read-write"):
            F.append(Finding("S3-PUBLIC-ACL", addr, "high", "Bucket ACL is public.",
                             _ev(tf, r'acl\s*=\s*"public-read(-write)?"', "public-read")))
        if t == "aws_s3_bucket_public_access_block":
            for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
                if _s(a.get(k)) is False:
                    F.append(Finding("S3-PAB-OFF", addr, "high", f"{k} is false.",
                                     _ev(tf, rf'{k}\s*=\s*false', f"{k} = false")))
                    break
        if t == "aws_db_instance":
            if _s(a.get("publicly_accessible")) is True:
                F.append(Finding("RDS-PUBLIC", addr, "high", "Database is publicly accessible.",
                                 _ev(tf, r'publicly_accessible\s*=\s*true', "publicly_accessible = true")))
            if _s(a.get("storage_encrypted")) is not True:
                F.append(Finding("RDS-NO-ENCRYPTION", addr, "medium", "storage_encrypted is not true.",
                                 f'resource "aws_db_instance" "{addr.split(".")[1]}"'))
            pw = _s(a.get("password"))
            if isinstance(pw, str) and not pw.startswith("${") and "var." not in pw:
                F.append(Finding("HARDCODED-SECRET", addr, "high", "Password is hardcoded in config.",
                                 _ev(tf, r'password\s*=\s*"[^"]+"', 'password = "..."')))
        if t == "aws_ebs_volume" and _s(a.get("encrypted")) is not True:
            F.append(Finding("EBS-NO-ENCRYPTION", addr, "medium", "EBS volume is not encrypted.",
                             f'resource "aws_ebs_volume" "{addr.split(".")[1]}"'))
        if t in ("aws_iam_policy", "aws_iam_role_policy"):
            pol = str(a.get("policy", ""))
            if re.search(r'"Action"\s*:\s*"\*"', pol) and re.search(r'"Resource"\s*:\s*"\*"', pol):
                F.append(Finding("IAM-WILDCARD", addr, "high", "Policy allows Action * on Resource *.",
                                 _ev(tf, r'"Action"\s*:\s*"\*"', '"Action": "*"')))
        if t == "aws_instance":
            it = str(_s(a.get("instance_type", "")))
            if re.match(r"^(p4d|p5|x2|x1e|u-)", it) or it.endswith(("48xlarge", "24xlarge")):
                F.append(Finding("COST-OVERSIZED", addr, "medium",
                                 f"Very large instance type {it}; confirm sizing.",
                                 _ev(tf, rf'instance_type\s*=\s*"{re.escape(it)}"', it)))
    return F

RULE_IDS = ["SG-OPEN-ADMIN", "S3-PUBLIC-ACL", "S3-PAB-OFF", "RDS-PUBLIC", "RDS-NO-ENCRYPTION",
            "HARDCODED-SECRET", "EBS-NO-ENCRYPTION", "IAM-WILDCARD", "COST-OVERSIZED"]
