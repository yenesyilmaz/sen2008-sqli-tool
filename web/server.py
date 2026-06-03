# Small web UI for the SQLi detector. Standard library only (http.server), so it
# runs with no external packages. Serves one page and a JSON /analyze endpoint.
# Every response goes through json.dumps (always '.' for numbers) and the score is
# an integer, so there is no locale issue that could break the JSON.
#
# The page shows the input travelling through the detection pipeline
# (whitelist -> decode -> patterns -> keywords -> score -> sanitize) as a timeline,
# which mirrors how the engine actually works (defense in depth).

import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

from core.detector import SQLiDetector
from core import console as c

detector = SQLiDetector()

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SQLi Detector</title>
<style>
  :root{ --ink:#16181d; --muted:#8a909b; --hair:#ececf1; --bg:#fbfbfc; --card:#fff;
         --teal:#0f766e; --green:#15803d; --amber:#b45309; --red:#be123c; }
  *{ box-sizing:border-box; margin:0; padding:0; }
  body{ font-family:'Inter',system-ui,'Segoe UI',sans-serif; background:
        radial-gradient(900px 420px at 50% -120px, #f1f6f5 0%, var(--bg) 70%); color:var(--ink);
        line-height:1.55; -webkit-font-smoothing:antialiased; min-height:100vh; }
  .head{ max-width:680px; margin:0 auto; padding:40px 24px 0; }
  .head h1{ font-size:1.18rem; font-weight:800; letter-spacing:-.02em; }
  .head p{ font-size:.8rem; color:var(--muted); margin-top:3px; }
  main{ max-width:680px; margin:0 auto; padding:22px 24px 80px; }
  .bar{ display:flex; border:1.5px solid #dfe1e7; border-radius:14px; overflow:hidden; background:var(--card);
        transition:border-color .15s, box-shadow .15s; box-shadow:0 1px 2px rgba(16,24,40,.04); }
  .bar:focus-within{ border-color:var(--teal); box-shadow:0 0 0 4px rgba(15,118,110,.10); }
  .bar input{ flex:1; border:0; outline:0; padding:15px 16px; font-size:1rem; background:transparent;
              font-family:'JetBrains Mono','Consolas',monospace; color:var(--ink); }
  .bar button{ border:0; background:var(--ink); color:#fff; padding:0 24px; font-size:.9rem; font-weight:600;
               cursor:pointer; transition:background .15s; }
  .bar button:hover{ background:#000; }
  .chips{ display:flex; flex-wrap:wrap; gap:6px; margin-top:13px; }
  .chip{ background:transparent; border:1px solid #e3e5ea; color:#6b7280; padding:4px 10px; border-radius:8px;
         font-size:.74rem; cursor:pointer; font-family:'JetBrains Mono','Consolas',monospace; transition:.12s; }
  .chip:hover{ border-color:var(--teal); color:var(--teal); transform:translateY(-1px); }
  #out{ display:none; margin-top:30px; }
  .verdict{ display:flex; flex-direction:column; gap:11px; padding:18px 20px; border-radius:15px;
            border:1px solid var(--hair); box-shadow:0 6px 20px rgba(16,24,40,.05); }
  .verdict.safe{ background:#f0fdf4; border-color:#bbf7d0; }
  .verdict.warn{ background:#fffbeb; border-color:#fde68a; }
  .verdict.bad{ background:#fff1f2; border-color:#fecdd3; }
  .vrow{ display:flex; align-items:baseline; gap:13px; flex-wrap:wrap; }
  .vrow .v{ font-size:1.55rem; font-weight:800; letter-spacing:-.02em; }
  .verdict.safe .v{ color:var(--green);} .verdict.warn .v{ color:var(--amber);} .verdict.bad .v{ color:var(--red);}
  .vrow .s{ font-size:.85rem; color:#6b7280; font-variant-numeric:tabular-nums; }
  .meter{ height:8px; border-radius:99px; background:rgba(0,0,0,.06); overflow:hidden; }
  .meterfill{ height:100%; width:0; border-radius:99px; transition:width .65s cubic-bezier(.34,1.2,.4,1); }
  .flow{ margin-top:16px; padding:6px 4px; }
  .flow .lead{ font-size:.7rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; color:var(--muted);
               margin:16px 0 18px 4px; }
  .step{ position:relative; padding:0 0 19px 32px; opacity:0; transform:translateY(7px);
         transition:opacity .34s ease, transform .34s ease; }
  .step.in{ opacity:1; transform:none; }
  .step::before{ content:''; position:absolute; left:9px; top:5px; bottom:-3px; width:2px; background:var(--hair); }
  .step:last-child::before{ display:none; }
  .dot{ position:absolute; left:0; top:0; width:20px; height:20px; border-radius:50%; background:#fff;
        border:2px solid #cfd3da; display:flex; align-items:center; justify-content:center;
        font-size:11px; font-weight:900; color:#fff; line-height:1; }
  .step.green .dot{ border-color:var(--green); background:var(--green); }
  .step.red .dot{ border-color:var(--red); background:var(--red); }
  .step.amber .dot{ border-color:var(--amber); background:var(--amber); }
  .step.skip .dot{ border-style:dashed; background:#fff; }
  .step .nm{ font-size:.71rem; font-weight:700; letter-spacing:.05em; color:#aab0bb; text-transform:uppercase; }
  .step.green .nm{ color:var(--green);} .step.red .nm{ color:var(--red);} .step.amber .nm{ color:var(--amber);}
  .step .tx{ font-size:.93rem; color:#2b2f38; margin-top:1px; }
  .step .tx b{ color:var(--ink); }
  .code{ font-family:'JetBrains Mono','Consolas',monospace; background:#f4f5f7; border:1px solid #ececef;
         padding:1px 6px; border-radius:6px; font-size:.85em; color:#0f172a; }
  .skip .tx{ color:#b6bbc4; }
</style>
</head>
<body>
<header class="head">
  <h1>SQLi Detector</h1>
  <p>SEN 2008 &middot; Software Security</p>
</header>
<main>
  <div class="bar">
    <input id="in" type="text" autocomplete="off" spellcheck="false" placeholder="type a value to test...   e.g.  ' OR 1=1--">
    <button id="go">Analyze</button>
  </div>
  <div class="chips" id="ex"></div>
  <div id="out">
    <div id="verdict" class="verdict">
      <div class="vrow"><span id="vword" class="v"></span><span id="vscore" class="s"></span></div>
      <div class="meter"><div id="meter" class="meterfill"></div></div>
    </div>
    <div class="flow"><div class="lead">Detection pipeline</div><div id="steps"></div></div>
  </div>
</main>
<script>
const EX=["john@example.com","O'Connor","SELECT * FROM products WHERE price > 100","admin'--","1 UNION SELECT username,password FROM users","' OR '1'='1","%27%20OR%201%3D1","0xFF00AA"];
const LABELS={patterns:"pattern",keywords:"keywords",special_chars:"special chars",encoding:"decoded"};
const GLYPH={green:"\\u2713",red:"\\u2717",amber:"\\u2193",plain:"",skip:""};
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
const exBox=document.getElementById('ex');
EX.forEach(function(p){ var b=document.createElement('span'); b.className='chip'; b.textContent=p; b.onclick=function(){ document.getElementById('in').value=p; analyze(); }; exBox.appendChild(b); });

function steps(d){
  var wl=d.verdict==='WHITELISTED', out=[];
  out.push({tone: wl?'green':'plain', nm:'1 \\u2014 Whitelist',
    tx: wl ? 'Matches a known-safe pattern, so it is allowed without further checks.'
           : 'Not on the safe list &mdash; running the full analysis.'});
  if(wl){ ['2 \\u2014 Decode','3 \\u2014 Attack patterns','4 \\u2014 SQL keywords','5 \\u2014 Risk score'].forEach(function(n){ out.push({tone:'skip',nm:n,tx:'skipped (already trusted)'}); }); return out; }
  var changed=d.normalized && d.normalized!==d.input;
  out.push({tone:d.bypass_attempts.length?'amber':'plain', nm:'2 \\u2014 Decode',
    tx:d.bypass_attempts.length ? ('Encoding found: '+esc(d.bypass_attempts.join(', '))+(changed?(' &rarr; <span class="code">'+esc(d.normalized)+'</span>'):'')) : 'No encoding or obfuscation detected.'});
  out.push({tone:d.matched_patterns?'red':'green', nm:'3 \\u2014 Attack patterns',
    tx:d.matched_patterns ? ('<b>'+d.matched_patterns+'</b> known attack pattern(s) matched.') : 'No attack patterns matched.'});
  out.push({tone:d.matched_keywords.length?'red':'green', nm:'4 \\u2014 SQL keywords',
    tx:d.matched_keywords.length ? ('Found: '+d.matched_keywords.map(esc).join(', ')) : 'No dangerous SQL keywords.'});
  var parts=[]; for(var k in d.breakdown){ if(d.breakdown[k]>0) parts.push(LABELS[k]+' +'+d.breakdown[k]); }
  out.push({tone:d.risk_score>25?'red':'green', nm:'5 \\u2014 Risk score',
    tx:(parts.length?parts.join('  \\u00b7  '):'no signals')+'  =  <b>'+d.risk_score+'/100</b>  (blocks above 25)'});
  if(d.verdict==='BLOCKED') out.push({tone:'green', nm:'6 \\u2014 Sanitized (prevention)',
    tx:'Neutralised form &rarr; <span class="code">'+esc(d.sanitized||'(empty)')+'</span>'});
  return out;
}

async function analyze(){
  var v=document.getElementById('in').value; if(!v.trim()) return;
  var r=await fetch('/analyze',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'input='+encodeURIComponent(v)});
  var d=await r.json();
  document.getElementById('out').style.display='block';
  var tone=(d.risk_level==='SAFE'||d.risk_level==='LOW')?'safe':(d.risk_level==='MEDIUM'?'warn':'bad');
  document.getElementById('verdict').className='verdict '+tone;
  document.getElementById('vword').textContent=d.verdict;
  document.getElementById('vscore').textContent=d.risk_score+' / 100  \\u00b7  '+d.risk_level;
  var mf=document.getElementById('meter');
  mf.style.background = tone==='safe'?'var(--green)':(tone==='warn'?'var(--amber)':'var(--red)');
  mf.style.width='0%';
  requestAnimationFrame(function(){ requestAnimationFrame(function(){ mf.style.width=Math.max(d.risk_score,3)+'%'; }); });
  var box=document.getElementById('steps'); box.innerHTML='';
  steps(d).forEach(function(s,i){
    var el=document.createElement('div'); el.className='step '+(s.tone==='plain'?'':s.tone);
    el.innerHTML='<span class="dot">'+(GLYPH[s.tone]||'')+'</span><div class="nm">'+s.nm+'</div><div class="tx">'+s.tx+'</div>';
    box.appendChild(el);
    setTimeout(function(){ el.classList.add('in'); }, 70+i*75);
  });
}
document.getElementById('go').onclick=analyze;
document.getElementById('in').addEventListener('keydown',function(e){ if(e.key==='Enter') analyze(); });
</script>
</body>
</html>"""


class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if urllib.parse.urlparse(self.path).path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/analyze":
            self._send(404, "not found", "text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        value = urllib.parse.parse_qs(raw, keep_blank_values=True).get("input", [""])[0]

        result = detector.analyze(value)
        if result.is_whitelisted:
            verdict = "WHITELISTED"
        elif result.is_malicious:
            verdict = "BLOCKED"
        else:
            verdict = "ALLOWED"
        payload = {
            "verdict": verdict,
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
            "breakdown": result.score_breakdown,
            "matched_keywords": result.matched_keywords,
            "matched_patterns": len(result.matched_patterns),
            "bypass_attempts": result.bypass_attempts,
            "sanitized": result.sanitized_value,
            "input": value,
            "normalized": result.normalized_value,
        }
        self._send(200, json.dumps(payload), "application/json; charset=utf-8")


def start_web(host="127.0.0.1", port=8080, open_browser=True):
    server = HTTPServer((host, port), WebHandler)
    url = f"http://{host}:{port}"
    print(c.color(f"\n[WEB] SQLi pipeline UI running at {url}", c.CYAN))
    print(c.color("[WEB] Open that link in your browser. Press Ctrl+C to stop.\n", c.YELLOW))
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(c.color("\n[WEB] Shutting down...", c.YELLOW))
        server.server_close()
