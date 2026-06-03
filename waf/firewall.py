# Mini Web Application Firewall: a small HTTP server that checks each request
# (URL params, POST body and a few headers) and returns 403 on a likely SQLi.

import json
import datetime
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from dataclasses import dataclass, field
from typing import List

from core.detector import SQLiDetector, DetectionResult
from core import console as c

BLOCK_THRESHOLD = 25


@dataclass
class WAFLog:
    timestamp: str
    client_ip: str
    method: str
    path: str
    blocked: bool
    risk_level: str
    risk_score: int
    findings: List[str] = field(default_factory=list)


class WAFStats:
    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.allowed_requests = 0
        self.logs: List[WAFLog] = []
        self._lock = threading.Lock()

    def record(self, log: WAFLog):
        with self._lock:
            self.total_requests += 1
            if log.blocked:
                self.blocked_requests += 1
            else:
                self.allowed_requests += 1
            self.logs.append(log)

    def summary(self) -> dict:
        rate = (self.blocked_requests / self.total_requests * 100) if self.total_requests else 0
        return {
            "total": self.total_requests,
            "blocked": self.blocked_requests,
            "allowed": self.allowed_requests,
            "block_rate": f"{rate:.1f}%",
        }


waf_stats = WAFStats()
detector = SQLiDetector()


def inspect_request(method, path, query_string, headers, body, client_ip="unknown"):
    results: List[DetectionResult] = []
    findings_summary: List[str] = []
    max_score = 0
    worst_level = "SAFE"

    def check(label, value):
        nonlocal max_score, worst_level
        result = detector.analyze(value)
        result.input_value = f"[{label}] {value}"
        results.append(result)
        if result.risk_score > max_score:
            max_score = result.risk_score
            worst_level = result.risk_level
        if result.is_malicious:
            findings_summary.append(f"{label}: {result.risk_level} ({result.risk_score}/100)")

    for name, values in urllib.parse.parse_qs(query_string, keep_blank_values=True).items():
        for val in values:
            check(f"URL param '{name}'", val)

    if body:
        body_params = urllib.parse.parse_qs(body, keep_blank_values=True)
        if body_params:
            for name, values in body_params.items():
                for val in values:
                    check(f"POST param '{name}'", val)
        else:
            check("POST body", body[:500])

    for name, val in headers.items():
        if name.lower() in ("user-agent", "referer", "x-forwarded-for", "cookie"):
            check(f"Header '{name}'", val)

    should_block = max_score > BLOCK_THRESHOLD
    log = WAFLog(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        client_ip=client_ip,
        method=method,
        path=path,
        blocked=should_block,
        risk_level=worst_level,
        risk_score=max_score,
        findings=findings_summary,
    )
    waf_stats.record(log)
    return should_block, results, log


class WAFRequestHandler(BaseHTTPRequestHandler):
    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        return ""

    def _handle(self):
        parsed = urllib.parse.urlparse(self.path)
        body = self._read_body() if self.command == "POST" else ""

        should_block, results, log = inspect_request(
            method=self.command,
            path=parsed.path,
            query_string=parsed.query,
            headers=dict(self.headers),
            body=body,
            client_ip=self.client_address[0],
        )
        self._print_log(log)

        status_code = 403 if should_block else 200
        if should_block:
            payload = {
                "error": "Forbidden",
                "message": "Request blocked by WAF: SQL injection attempt detected",
                "risk_score": log.risk_score,
                "risk_level": log.risk_level,
            }
        else:
            payload = {
                "status": "allowed",
                "message": "Request passed WAF inspection",
                "risk_score": log.risk_score,
            }

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, fmt, *args):
        pass

    def _print_log(self, log: WAFLog):
        status = c.color("BLOCKED", c.BOLD, c.RED) if log.blocked else c.color("ALLOWED", c.BOLD, c.GREEN)
        score = c.color(f"{log.risk_score}/100 ({log.risk_level})", c.risk_color(log.risk_level))

        print(c.color(c.rule("-"), c.DIM))
        print(f"  WAF [{log.timestamp}]  {log.method} {log.path}  ->  {status}")
        print(f"  Client: {log.client_ip}   Risk: {score}")
        for item in log.findings:
            print(f"    - {item}")
        stats = waf_stats.summary()
        print(f"  Stats -> total: {stats['total']} | blocked: {stats['blocked']} | block rate: {stats['block_rate']}")
        print(c.color(c.rule("-"), c.DIM))


def start_waf(host="127.0.0.1", port=8080):
    server = HTTPServer((host, port), WAFRequestHandler)
    print(c.color(f"\n[WAF] Listening on http://{host}:{port}", c.CYAN))
    print(c.color("[WAF] Inspecting: URL params | POST body | headers", c.CYAN))
    print(c.color("[WAF] Press Ctrl+C to stop\n", c.YELLOW))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(c.color("\n[WAF] Shutting down...", c.YELLOW))
        print(f"[WAF] Final stats: {waf_stats.summary()}")
        server.server_close()
