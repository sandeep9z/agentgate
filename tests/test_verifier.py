import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from agentgate.verifier import verify_additional
from agentgate.rules import run_rules

TF = 'resource "aws_instance" "app" {\n  ami = "a"\n  instance_type = "t3.small"\n  user_data = "export KEY=abcdef123456"\n}\n'

def test_accepts_grounded_claim():
    ok, rej = verify_additional(TF, [{"rule_id": "secret", "resource": "aws_instance.app", "evidence": 'user_data = "export KEY=abcdef123456"'}])
    assert len(ok) == 1 and not rej

def test_rejects_invented_resource():
    ok, rej = verify_additional(TF, [{"rule_id": "x", "resource": "aws_instance.ghost", "evidence": "instance_type"}])
    assert not ok and rej[0]["reason"] == "resource does not exist"

def test_rejects_invented_evidence():
    ok, rej = verify_additional(TF, [{"rule_id": "x", "resource": "aws_instance.app", "evidence": "publicly_accessible = true"}])
    assert not ok and "evidence" in rej[0]["reason"]

def test_443_not_flagged():
    tf = 'resource "aws_security_group" "w" {\n  ingress {\n    from_port = 443\n    to_port = 443\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    assert run_rules(tf) == []
