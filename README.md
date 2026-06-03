# SEN 2008 - SQL Injection Detection & Prevention Tool

Group members:
- Yusuf Enes Yilmaz - 2200515
- Yazan Ghais - 2473651
- Belal Baalbaki - 2362025
- Kerem Percin - 2484083

A small Python toolkit that detects and prevents SQL injection (SQLi) in three
layers, so it does not rely on a single technique (defense in depth):

- **Input Analyzer** (`core/`): scores a single input. It decodes the input,
  matches known attack patterns, counts risky keywords and keeps a small whitelist
  so normal inputs are not flagged.
- **SAST Engine** (`sast/`): reads Python source code and reports queries built in
  an unsafe way (concatenation, `%`, f-strings, `.format()`).
- **Mini WAF** (`waf/`): an HTTP server that checks each request and returns 403
  when it finds a SQL injection attempt.

## Requirements

Only Python 3.8 or newer. No external libraries.

## How to run

```
python main.py                 # interactive analyzer (type 'demo' for test cases)
python main.py demo            # runs all three modules once
python main.py sast samples/vulnerable_app.py   # analyze one file
python main.py sast samples/                     # analyze a folder
python main.py waf             # start the WAF on 127.0.0.1:8080
python main.py waf-demo        # start the WAF and send it sample requests
```

`python main.py demo` is the easiest thing to show; it runs everything in one go.

## Project structure

```
sqli_tool/
  main.py                 entry point / menu
  core/
    console.py            colored output that also works on Windows
    detector.py           the detection engine
    payloads.py           patterns, keywords, whitelist, scoring weights
  sast/
    analyzer.py           AST-based static analyzer
  waf/
    firewall.py           mini web application firewall
  samples/
    vulnerable_app.py     test file with deliberate SQLi bugs
```

## How the detection works

1. **Whitelist:** if the whole input matches a safe pattern (like `O'Connor`) it is
   allowed. This is the standard false-positive case: a legitimate value that
   contains an apostrophe, which a naive quote filter would wrongly block.
2. **Decode:** URL, double-URL, HTML, hex and `CHAR()` decoding. Inline comments
   (`/* */`) are turned into a space, matching how MySQL treats them, so
   `UNION/**/SELECT` becomes `UNION SELECT` and is still caught.
3. **Patterns:** regex signatures for boolean, UNION, error-based, time-based and
   stacked-query injection. A comment marker (`--`, `#`) is only treated as risky
   when it sits right after a quote (e.g. `admin'--`), so `C#` is not flagged.
4. **Keywords:** count of dangerous SQL keywords.
5. **Score:** the steps above give a 0-100 score (SAFE / LOW / MEDIUM / HIGH /
   CRITICAL). Above 25 is treated as an attack.

## Test results

We checked the analyzer with a 30-case set (15 real attacks + 15 safe inputs):

| Metric | Result |
|--------|--------|
| Attacks detected | 15 / 15 |
| False positives | 0 / 15 |

The attacks cover boolean, UNION, stacked, time-based, error-based and encoded
(URL / hex / `CHAR()` / `/**/`) variants. On the safe side, tricky inputs such as
`C#`, `O'Connor`, the sentence `SELECT a book from the shelf` and the color code
`0xFF00AA` are all allowed correctly.

## Limitations

- Detection is pattern- and score-based, so normal developer SQL can get a low
  score without being blocked, and a brand new trick could still get through.
- The SAST taint check only works inside a single function, not across functions.
- Sanitization is a demo-only fallback; the real fix is always a parameterized
  query.

## Based on

This tool builds on well known SQLi work: the attack classification by Halfond,
Viegas and Orso (2006), the static-plus-runtime idea from AMNESIA (Halfond and Orso,
2005), the SQLrand idea (Boyd and Keromytis, 2004), and OWASP guidance (SQL Injection
Prevention Cheat Sheet, ModSecurity Core Rule Set). Full references are in the report.
