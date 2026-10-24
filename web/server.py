"""Tiny demo server: paste Terraform, get a verified review. Run: python web/server.py"""
import json, sys, pathlib, os
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from agentgate.graph import review_terraform

PAGE = (pathlib.Path(__file__).parent / "index.html").read_text()
SAMPLE = pathlib.Path(__file__).parent / "sample.tf"

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        b = body.encode(); self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/sample": return self._send(200, SAMPLE.read_text(), "text/plain")
        self._send(200, PAGE, "text/html")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            rep = review_terraform(json.loads(self.rfile.read(n))["tf"])
            self._send(200, json.dumps(rep), "application/json")
        except Exception as e:
            self._send(400, json.dumps({"error": f"Could not parse Terraform: {e}"[:300]}), "application/json")

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    print(f"AgentGate demo on http://0.0.0.0:{port}"); HTTPServer(("0.0.0.0", port), H).serve_forever()
