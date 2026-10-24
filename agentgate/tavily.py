"""Optional Tavily enrichment: current guidance per rule id."""
from __future__ import annotations
import os, json, urllib.request

QUERIES = {
    "SG-OPEN-ADMIN": "AWS security group restrict SSH RDP 0.0.0.0/0 best practice",
    "S3-PUBLIC-ACL": "AWS S3 block public access best practice",
    "S3-PAB-OFF": "AWS S3 block public access best practice",
    "RDS-PUBLIC": "RDS publicly accessible security best practice",
    "RDS-NO-ENCRYPTION": "RDS storage encryption at rest AWS best practice",
    "HARDCODED-SECRET": "Terraform avoid hardcoded secrets AWS Secrets Manager",
    "EBS-NO-ENCRYPTION": "EBS default encryption AWS best practice",
    "IAM-WILDCARD": "IAM least privilege avoid wildcard actions AWS",
    "COST-OVERSIZED": "AWS EC2 right sizing cost optimization",
}

def available() -> bool: return bool(os.getenv("TAVILY_API_KEY"))

def lookup(rule_id: str) -> dict | None:
    if not available() or rule_id not in QUERIES: return None
    req = urllib.request.Request("https://api.tavily.com/search",
        data=json.dumps({"query": QUERIES[rule_id], "max_results": 2, "search_depth": "basic"}).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + os.environ["TAVILY_API_KEY"]})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
        hit = (d.get("results") or [None])[0]
        return {"title": hit["title"], "url": hit["url"]} if hit else None
    except Exception:
        return None
