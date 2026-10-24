# AgentGate

**A governed, evaluated agent for reviewing Terraform pull requests.** Built for the Nebius x NVIDIA Global AI Hackathon (track: Coding & Agentic Engineering).

Most "LLM reviews your IaC" demos let the model say anything. AgentGate puts the model inside guardrails:

1. **Deterministic rules first** (`agentgate/rules.py`): nine checks for open admin ports, public S3, public or unencrypted RDS/EBS, hardcoded secrets, wildcard IAM and oversized instances. The LLM cannot remove or alter these findings.
2. **Tavily lookup** (`agentgate/tavily.py`): current guidance links per finding (optional, needs `TAVILY_API_KEY`).
3. **NVIDIA Nemotron on Nebius Token Factory** (`agentgate/llm.py`): explains and prioritizes scanner findings, writes fixes, and may propose *additional* findings the rules miss.
4. **Verifier** (`agentgate/verifier.py`): an LLM claim is kept only if its resource exists in the parsed Terraform and its cited evidence appears verbatim in the source. Everything else is rejected and counted in the report.
5. **LangGraph pipeline** (`agentgate/graph.py`): `rules -> enrich -> review -> report`. If the LLM is unavailable, AgentGate degrades to rules-only and says so.

## Run it

```bash
pip install -r requirements.txt
export NEBIUS_API_KEY=...          # Nebius Token Factory
export AGENTGATE_MODEL=...         # an NVIDIA Nemotron model id from your Token Factory catalog
export TAVILY_API_KEY=...          # optional
python -m agentgate.cli examples/main.tf --fail-on-high
python web/server.py               # demo UI on :8080
python bench/run_bench.py          # evaluation
python -m pytest tests             # verifier tests
```

Without `NEBIUS_API_KEY` everything still runs in rules-only mode. A GitHub Action (`.github/workflows/agentgate.yml`) runs the review on every pull request, and a `Dockerfile` serves the demo.

## Evaluation (honest version)

`bench/cases.json` holds 23 labeled Terraform snippets with 20 known issues. Eight snippets are clean "traps" (for example port 443 open to the internet, a private bucket, a scoped IAM policy) that test for false alarms. Five issues are deliberately outside the rule set (secret in `user_data`, `Principal: "*"`, IAM policy via `jsonencode`, unauthenticated Lambda URL, KMS rotation off) so that the LLM's added value can be measured. The script reports precision, recall and false-alarm rate with 95% bootstrap confidence intervals for three systems: rules-only, LLM-only, and AgentGate.

Rules-only baseline (measured, no API key needed):

| system | precision | recall | false-alarm rate |
|---|---|---|---|
| rules-only | 1.00 | 0.75 (CI 0.47-0.94) | 0.00 |

LLM-only and AgentGate rows: **RESULTS_PLACEHOLDER** (run `python bench/run_bench.py` with a Nebius key).

**Limitations.** The benchmark is small and the labels were written by the author alongside the rules, so rules-only precision of 1.00 is optimistic and says little about real-world repositories. Resource-level matching is used for LLM findings. The rules cover a fraction of what tools such as checkov or tfsec cover; AgentGate is a demonstration of the governance pattern (rules, then model, then verifier), not a replacement for them. The verifier prevents invented resources and invented evidence, but it cannot judge whether a grounded claim is actually a good finding.

## Feedback on the tools

See `FEEDBACK.md`.

## License

MIT.
