"""
SEN 2008 - SQL Injection Detection & Prevention Tool

Group members:
  - Yusuf Enes Yilmaz - 2200515
  - Yazan Ghais - 2473651
  - Belal Baalbaki - 2362025
  - Kerem Percin - 2484083

Modes:
  analyze        analyze inputs one by one (default)
  demo           run all three modules once
  sast <path>    static analysis of a Python file or folder
  waf            start the mini WAF server
  waf-demo       start the WAF and send it sample requests
  web            start the browser-based web UI
"""

import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import console as c
from core.detector import SQLiDetector
from sast.analyzer import analyze_file, analyze_directory

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
SAMPLE_FILE = os.path.join(SAMPLES_DIR, "vulnerable_app.py")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4}

EXAMPLE_INPUTS = [
    "Hello, how are you?",
    "O'Connor",
    "SELECT * FROM products WHERE price > 100",
    "admin'--",
    "1 AND SLEEP(5)",
    "1 UNION SELECT username, password FROM users",
    "admin' OR '1'='1",
    "%27%20OR%201%3D1",
]


def print_banner():
    print(c.color("=" * 65, c.CYAN))
    print(c.color("  SEN 2008 - Software Security Term Project", c.BOLD, c.WHITE))
    print(c.color("  SQL Injection Detection & Prevention Tool", c.WHITE))
    print(c.color("  Modules: Input Analyzer | SAST Engine | Mini WAF", c.DIM))
    print(c.color("=" * 65, c.CYAN))


def risk_badge(level, score):
    return c.color(f"[{level}]", c.BOLD, c.risk_color(level)) + c.color(f" ({score}/100)", c.DIM)


def explain_score(result):
    # turn the score into a human-readable reason (where the points came from)
    if result.is_whitelisted:
        return "whitelisted (safe value, e.g. a real name)"
    bd = result.score_breakdown
    parts = []
    if bd.get("patterns"):
        parts.append(f"attack pattern +{bd['patterns']}")
    if bd.get("keywords"):
        parts.append(f"SQL keywords +{bd['keywords']}")
    if bd.get("special_chars"):
        parts.append(f"special chars +{bd['special_chars']}")
    if bd.get("encoding"):
        parts.append(f"decoded payload +{bd['encoding']}")
    return ", ".join(parts) if parts else "nothing suspicious matched"


def print_examples():
    print(c.color("\n  Copy and paste one of these to try it:", c.BOLD, c.CYAN))
    for ex in EXAMPLE_INPUTS:
        print(c.color(f"    {ex}", c.YELLOW))
    print()


def run_analyzer():
    detector = SQLiDetector()
    print(c.color("\n[MODE] Input Analyzer", c.BOLD, c.CYAN))
    print(c.color("  Type an input to analyze it. Commands: 'demo', 'example', 'exit'.\n", c.DIM))

    while True:
        try:
            user_input = input(c.color("sqli> ", c.BLUE)).strip()
        except (KeyboardInterrupt, EOFError):
            print(c.color("\nExiting analyzer...", c.YELLOW))
            break

        if not user_input:
            continue
        if user_input.lower() == "exit":
            break
        if user_input.lower() == "demo":
            run_detector_cases(detector)
            continue
        if user_input.lower() == "example":
            print_examples()
            continue

        print_analysis_result(detector.analyze(user_input))


def print_analysis_result(result):
    print(c.color(c.rule(), c.DIM))
    print(f"  Input:  {result.input_value[:80]}")
    print(f"  Status: {risk_badge(result.risk_level, result.risk_score)}")
    print(c.color(f"  Why:    {explain_score(result)}", c.DIM))

    if result.is_whitelisted:
        print(c.color("  [OK] Whitelisted - false positive prevented", c.GREEN))
    elif result.is_malicious:
        print(c.color("  [!!] MALICIOUS - block this input", c.RED))
    else:
        print(c.color("  [OK] SAFE - input appears clean", c.GREEN))

    if result.matched_keywords:
        print(c.color(f"  Dangerous keywords: {', '.join(result.matched_keywords)}", c.RED))
    if result.matched_patterns:
        print(c.color(f"  Matched patterns:   {len(result.matched_patterns)}", c.RED))
    if result.is_malicious:
        print(c.color(f"  Sanitized:          {result.sanitized_value[:80]}", c.GREEN))
    print(c.color(c.rule(), c.DIM))
    print()


def run_detector_cases(detector):
    cases = [
        ("admin' OR '1'='1", "Boolean-based SQLi"),
        ("1 UNION SELECT username, password FROM users--", "UNION-based SQLi"),
        ("1'; DROP TABLE users;--", "Stacked query SQLi"),
        ("1 AND SLEEP(5)", "Time-based blind SQLi"),
        ("%27%20OR%201%3D1", "URL-encoded SQLi"),
        ("0x27204f522031203d2031", "Hex-encoded SQLi"),
        ("1 EXTRACTVALUE(1,CONCAT(0x7e,version()))", "Error-based SQLi"),
        ("O'Connor", "Safe name (false positive test)"),
        ("SELECT * FROM products WHERE price > 100", "Developer SQL (not an attack)"),
        ("Hello, how are you?", "Normal safe input"),
    ]
    print(c.color(f"\n[Analyzer] Running {len(cases)} test cases", c.BOLD, c.CYAN))
    print(c.color("  (the last column shows WHY the input got that score)\n", c.DIM))
    for payload, label in cases:
        r = detector.analyze(payload)
        if r.is_whitelisted:
            verdict, vcol = "WHITELISTED", c.GREEN
        elif r.is_malicious:
            verdict, vcol = "BLOCKED", c.RED
        else:
            verdict, vcol = "ALLOWED", c.GREEN
        risk = f"{r.risk_level} ({r.risk_score})"
        print(f"  {label:<33}"
              f"{c.color(f'{risk:<12}', c.risk_color(r.risk_level))} "
              f"{c.color(f'{verdict:<12}', vcol)} "
              f"{c.color(explain_score(r), c.DIM)}")
    print()


def run_sast(target):
    print(c.color("\n[MODE] SAST - Static Code Analyzer", c.BOLD, c.CYAN))
    print(c.color(f"  Target: {target}\n", c.DIM))

    if os.path.isfile(target):
        findings = analyze_file(target)
    elif os.path.isdir(target):
        findings = analyze_directory(target)
    else:
        print(c.color(f"  Error: target '{target}' not found.", c.RED))
        return

    if not findings:
        print(c.color(f"  [OK] No SQL injection vulnerabilities found in {target}\n", c.GREEN))
        return

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    print(c.color(f"  Found {len(findings)} vulnerability(ies):", c.BOLD, c.RED))
    print(c.color(c.rule("="), c.DIM))
    for i, f in enumerate(findings, 1):
        print(f"\n  [{i}] {c.color(f.severity, c.BOLD, c.risk_color(f.severity))} - {f.vulnerability_type}")
        print(c.color(f"      File: {f.file_path}:{f.line_number}", c.DIM))
        print(f"      Code: {c.color(f.code_snippet, c.YELLOW)}")
        print(f"      Why:  {f.description}")
        print(c.color(f"      Fix:  {f.recommendation}", c.GREEN))
    print()
    print(c.color(c.rule("="), c.DIM))

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print(c.color("\n  Summary:", c.BOLD))
    for sev, n in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9)):
        print(f"    {c.color(f'{sev:<10}', c.risk_color(sev))} {n} finding(s)")
    print()


def run_waf(host, port):
    from waf.firewall import start_waf
    print(c.color("\n[MODE] Mini WAF - Web Application Firewall", c.BOLD, c.CYAN))
    start_waf(host, port)


def run_web(host, port):
    from web.server import start_web
    print(c.color("\n[MODE] Web UI", c.BOLD, c.CYAN))
    start_web(host, port)


def run_waf_demo():
    import threading
    import urllib.request
    import urllib.error
    from http.server import HTTPServer
    from waf.firewall import WAFRequestHandler, waf_stats

    host, port = "127.0.0.1", 8088
    server = HTTPServer((host, port), WAFRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    print(c.color("\n[MODE] WAF Demo - sending sample requests to the firewall", c.BOLD, c.CYAN))
    print(c.color(f"  WAF running at http://{host}:{port}\n", c.DIM))

    requests = [
        ("Safe login", "/login?username=alice&password=secret"),
        ("Safe search", "/search?q=laptop"),
        ("Boolean SQLi", "/login?username=admin'%20OR%20'1'%3D'1&password=x"),
        ("UNION SQLi", "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--"),
        ("Stacked query", "/item?id=1';%20DROP%20TABLE%20users;--"),
    ]
    for label, path in requests:
        url = f"http://{host}:{port}{path}"
        try:
            code = urllib.request.urlopen(url, timeout=3).status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:
            print(c.color(f"  {label}: request failed ({e})", c.RED))
            continue
        verdict = c.color("BLOCKED (403)", c.RED) if code == 403 else c.color("ALLOWED (200)", c.GREEN)
        print(f"  {label:<16} -> {verdict}")

    server.shutdown()
    s = waf_stats.summary()
    print(c.color(f"\n  Final WAF stats -> total: {s['total']} | blocked: {s['blocked']} | allowed: {s['allowed']} | block rate: {s['block_rate']}\n", c.BOLD))


def run_full_demo():
    print(c.color("\n===== FULL DEMO: analyzer, SAST and WAF =====", c.BOLD, c.CYAN))
    run_detector_cases(SQLiDetector())
    run_sast(SAMPLE_FILE)
    run_waf_demo()
    print(c.color("===== end of demo =====\n", c.BOLD, c.CYAN))


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="SEN 2008 - SQL Injection Detection & Prevention Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                       # interactive analyzer\n"
            "  python main.py demo                  # full demo of all modules\n"
            "  python main.py sast samples/vulnerable_app.py\n"
            "  python main.py waf                   # start the WAF server\n"
            "  python main.py waf-demo              # WAF + automatic sample requests\n"
            "  python main.py web                   # browser-based web UI\n"
        ),
    )
    parser.add_argument("mode", nargs="?", default="analyze",
                        choices=["analyze", "demo", "sast", "waf", "waf-demo", "web"],
                        help="tool mode (default: analyze)")
    parser.add_argument("target", nargs="?", default=None,
                        help="file or directory path (for sast mode)")
    parser.add_argument("--host", default="127.0.0.1", help="WAF host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="WAF port (default: 8080)")
    args = parser.parse_args()

    if args.mode == "analyze":
        run_analyzer()
    elif args.mode == "demo":
        run_full_demo()
    elif args.mode == "sast":
        run_sast(args.target or SAMPLES_DIR)
    elif args.mode == "waf":
        run_waf(args.host, args.port)
    elif args.mode == "waf-demo":
        run_waf_demo()
    elif args.mode == "web":
        run_web(args.host, args.port)


if __name__ == "__main__":
    main()
