"""Nebius Token Factory client (OpenAI-compatible) running an NVIDIA Nemotron model."""
from __future__ import annotations
import json, os, re

BASE_URL = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/")
MODEL = os.getenv("AGENTGATE_MODEL", "nvidia/Llama-3_1-Nemotron-Ultra-253B-v1")

def available() -> bool:
    return bool(os.getenv("NEBIUS_API_KEY"))

def chat_json(system: str, user: str, max_tokens: int = 2000) -> dict:
    from openai import OpenAI
    client = OpenAI(base_url=BASE_URL, api_key=os.environ["NEBIUS_API_KEY"])
    r = client.chat.completions.create(
        model=MODEL, temperature=0.0, max_tokens=max_tokens,
        messages=[{"role": "system", "content": "detailed thinking off\n" + system},
                  {"role": "user", "content": user}])
    return extract_json(r.choices[0].message.content or "")

def extract_json(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m: return {}
    try: return json.loads(m.group(0))
    except json.JSONDecodeError: return {}
