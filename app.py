import os, re, html, io, collections
from collections import deque
from pathlib import Path
from flask import Flask, request, Response, render_template_string, send_file
from datetime import datetime, timezone

LOG_ROOT = Path("/var/log/watchguard")
USER = os.getenv("WATCHLOG_USER", "admin")
PASS = os.getenv("WATCHLOG_PASS", "changeme")

app = Flask(__name__)

# ---------- Auth ----------
def check_auth(u, p): return u == USER and p == PASS
def authenticate():
    return Response("Auth required", 401, {"WWW-Authenticate": 'Basic realm="watchlog"'})
def requires_auth(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*a, **kw)
    return wrapper

# ---------- Layout ----------
LAYOUT = """
<!doctype html>
<meta charset="utf-8">
<title>WatchLog Lite</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b1220;color:#dbe3f4}
 .wrap{max-width:1100px;margin:24px auto;padding:0 16px}
 h1{font-size:22px;margin:4px 0 16px}
 .bar{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
 select,input[type=number],input[type=text]{background:#0f172a;border:1px solid #223054;border-radius:8px;color:#dbe3f4;padding:8px}
 button{background:#324e86;border:0;border-radius:9px;color:#fff;padding:8px 12px;cursor:pointer}
 pre{background:#0f172a;border:1px solid #223054;border-radius:12px;padding:12px;white-space:pre-wrap}
 a{color:#9bbcff;text-decoration:none}
 mark{background:#f59e0b;color:#111;padding:0 2px;border-radius:3px}
 table.mini{border-collapse:collapse;margin:.5rem 0}
 table.mini th,table.mini td{border:1px solid #ddd;padding:.25rem .5rem;font-size:.9rem}
 .badge{display:inline-block;padding:2px 6px;border-radius:6px;margin-right:6px}
 .badge.allow{background:#10b981;color:#0b251f}
 .badge.deny{background:#ef4444;color:#220606}
 .flow{color:#cbd5e1;margin-right:8px}
 .nowrap{white-space:pre}
 .box{background:#0f172a;border:1px solid #223054;border-radius:12px;padding:12px}
 .lines{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
 .line{margin:2px 0}
 .muted{color:#94a3b8}
 .chip{display:inline-block;padding:2px 6px;border-radius:6px;margin-left:6px;background:#334155;color:#cbd5e1}
 .chip.port{background:#1f2a44}
 .rel{position:relative}
 .popover{position:absolute;left:0;top:40px;z-index:60;display:none;max-width:540px;background:#0f172a;border:1px solid #223054;border-radius:12px;padding:12px;box-shadow:0 10px 30px rgba(2,6,23,.6)}
 .popover.open{display:block}
 .overlay{position:fixed;inset:0;background:rgba(2,6,23,.8);color:#e2e8f0;display:none;align-items:center;justify-content:center;z-index:50}
 .overlay .panel{background:#0f172a;border:1px solid #223054;border-radius:12px;padding:16px;max-width:680px}
</style>
<div class="wrap">
  <h1>WatchLog Lite</h1>
  {{ content|safe }}
</div>
"""

def list_hosts():
    if not LOG_ROOT.exists(): return []
    return sorted([p.name for p in LOG_ROOT.iterdir() if p.is_dir()])

def list_months(host):
    base = LOG_ROOT/host
    if not base.exists(): return []
    return sorted([p.name for p in base.iterdir() if p.is_dir()])

def tail_file(path: Path, n: int):
    """Efficiently read last n lines from a potentially large file.
    Falls back to None if file missing.
    """
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = 8192
            buf = b""
            pos = size
            lines = []
            while pos > 0 and len(lines) <= n:
                rd = min(block, pos)
                pos -= rd
                f.seek(pos)
                buf = f.read(rd) + buf
                lines = buf.splitlines()
            out = [l.decode("utf-8", "ignore") for l in lines[-n:]]
            return out
    except FileNotFoundError:
        return None

# ---------- Helpers ----------
RE_IP    = re.compile(r'(?:src(?:_ip)?=|saddr=)(\d+\.\d+\.\d+\.\d+)')
RE_DPORT = re.compile(r'(?:d(?:st_)?port=|dpt=)(\d{1,5})')
KV       = re.compile(r'(\w+)=([^\s]+)')

# Optional host mapping: /opt/watchlog-lite/hosts.yaml with lines like "1.2.3.4: laptop"
HOSTS_FILE = Path("/opt/watchlog-lite/hosts.yaml")
_HOST_MAP = None
_HOST_MAP_MTIME = None

def _load_hosts_map():
    global _HOST_MAP, _HOST_MAP_MTIME
    try:
        st = HOSTS_FILE.stat()
    except FileNotFoundError:
        _HOST_MAP = {}
        _HOST_MAP_MTIME = None
        return _HOST_MAP
    if _HOST_MAP is not None and _HOST_MAP_MTIME == st.st_mtime:
        return _HOST_MAP
    mp = {}
    try:
        with HOSTS_FILE.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                # very tiny YAML-ish: ip: name
                if ':' in line:
                    ip, name = line.split(':', 1)
                    mp[ip.strip()] = name.strip()
    except Exception:
        mp = {}
    _HOST_MAP = mp
    _HOST_MAP_MTIME = st.st_mtime
    return _HOST_MAP

def _map_ip(ip: str) -> str:
    if not ip: return ip
    mp = _load_hosts_map()
    if ip in mp:
        return f"{mp[ip]} ({ip})"
    return ip

def parse_kv(line: str):
    d = dict(KV.findall(line))
    d["src_ip"] = d.get("src") or d.get("src_ip") or d.get("saddr")
    d["dst_ip"] = d.get("dst") or d.get("dst_ip") or d.get("daddr")
    d["dport"]  = d.get("dport") or d.get("dst_port") or d.get("dpt")
    d["sport"]  = d.get("sport") or d.get("src_port") or d.get("spt")
    d["action"] = d.get("action") or d.get("msg") or d.get("log")
    d["ip"] = d.get("src_ip")  # alias for convenience in filters
    # Attempt to normalize timestamp fields if present
    # WatchGuard often has date=YYYY-MM-DD time=HH:MM:SS or ts=iso8601
    ts = d.get("ts") or None
    if not ts:
        date, time_ = d.get("date"), d.get("time")
        if date and time_:
            ts = f"{date} {time_}"
    d["ts"] = ts
    return d

def _rel_time(ts: str) -> str:
    if not ts:
        return ""
    s = ts.strip()
    dt = None
    try:
        if 'T' in s or 'Z' in s:
            s2 = s.replace('Z', '+00:00')
            dt = datetime.fromisoformat(s2)
        else:
            # assume "YYYY-MM-DD HH:MM:SS"
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        dt = None
    if not dt:
        return ts
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    delta = now - dt
    secs = int(delta.total_seconds())
    if secs < 0:
        secs = 0
    if secs < 60:
        return f"{secs}s ago"
    mins = secs // 60
    if mins < 60:
        return f"{mins}m ago"
    hours = mins // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"

def summarize(lines):
    ips, ports = collections.Counter(), collections.Counter()
    for ln in lines:
        m = RE_IP.search(ln)
        if m and m.group(1).startswith("192.168."):
            ips[m.group(1)] += 1
        m = RE_DPORT.search(ln)
        if m:
            ports[m.group(1)] += 1
    return ips.most_common(10), ports.most_common(10)

def apply_filters(lines, regex, q_raw: str):
    """Advanced filters: supports
    - regex tokens (space or | separated)
    - negative tokens: -word
    - key=value and key!=value
    - numeric ranges: dport=6881-6999 (and sport)
    Regex and structured terms combine with OR semantics for positive matches.
    Negatives always exclude.
    """
    terms = [t for t in re.split(r'[| ]+', (q_raw or '').strip()) if t]
    rx_pos_terms = [t for t in terms if ('=' not in t) and not t.startswith('-')]
    rx_neg_terms = [t[1:] for t in terms if t.startswith('-') and ('=' not in t)]
    kv_pos, kv_neg, range_pos = [], [], []
    for t in terms:
        if '=' in t:
            if '!=' in t:
                k, v = t.split('!=', 1)
                kv_neg.append((k, v))
            else:
                k, v = t.split('=', 1)
                if re.fullmatch(r'\d+-\d+', v) and k in {"dport", "sport"}:
                    lo, hi = v.split('-', 1)
                    try:
                        range_pos.append((k, int(lo), int(hi)))
                    except ValueError:
                        pass
                else:
                    kv_pos.append((k, v))

    rx_pos = None
    rx_neg = None
    if rx_pos_terms:
        try:
            rx_pos = re.compile("|".join(rx_pos_terms), re.I)
        except re.error:
            rx_pos = None
    if rx_neg_terms:
        try:
            rx_neg = re.compile("|".join(rx_neg_terms), re.I)
        except re.error:
            rx_neg = None

    def keep(line: str) -> bool:
        # Negative regex excludes
        if rx_neg and rx_neg.search(line):
            return False

        need_struct = bool(kv_pos or range_pos or kv_neg)
        kv = None
        if need_struct:
            kv = parse_kv(line)
            # Negative KV excludes
            for k, v in kv_neg:
                if kv.get(k) == v:
                    return False

        # Range requirements
        ranges_ok = True
        if range_pos:
            for k, lo, hi in range_pos:
                try:
                    val = int(kv.get(k) or -1)
                except (TypeError, ValueError):
                    return False
                if not (lo <= val <= hi):
                    return False

        # Positive KV requirements
        kv_ok = all(kv.get(k) == v for k, v in kv_pos) if kv_pos else False

        # Regex positive match (either via combined regex or separate rx_pos)
        rx_ok = bool(regex.search(line)) if regex else False
        if rx_pos is not None:
            rx_ok = rx_ok or bool(rx_pos.search(line))

        if regex or rx_pos is not None:
            if kv_pos or range_pos:
                return rx_ok or ((not kv_pos or kv_ok) and (not range_pos or ranges_ok))
            return rx_ok
        if kv_pos or range_pos:
            return ((not kv_pos or kv_ok) and (not range_pos or ranges_ok))
        return True

    return [ln for ln in lines if keep(ln)]

def pick_log_path(host: str, ym: str) -> Path:
    return LOG_ROOT / host / ym / "watchguard.log"

def pretty_header(kv: dict) -> str:
    act = (kv.get("action") or "").lower()
    badge = f'<span class="badge {act}">{html.escape(kv.get("action") or "")}</span>' if act else ""
    def _is_private(ip: str) -> bool:
        return ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31) or ip.startswith("127.")
    src_ip = kv.get("src_ip") or ""
    dst_ip = kv.get("dst_ip") or ""
    src = _map_ip(src_ip) + ((":" + kv.get("sport")) if kv.get("sport") else "")
    dst = _map_ip(dst_ip) + ((":" + kv.get("dport")) if kv.get("dport") else "")
    flow = f'<span class="flow">{html.escape(src)} → {html.escape(dst)}</span>' if (src or dst) else ""
    whois = ""
    if dst_ip and not _is_private(dst_ip):
        whois = f' <a class="chip" target="_blank" rel="noreferrer" href="https://rdap.org/ip/{html.escape(dst_ip)}">whois</a>'
    rel = ""
    if kv.get("ts"):
        reltxt = _rel_time(kv.get("ts"))
        if reltxt:
            rel = f' <span class="chip muted">{html.escape(reltxt)}</span>'
    return badge + flow + whois + rel

def fold_dupes(lines):
    out = []
    last = None
    cnt = 0
    for ln in lines + [None]:
        if ln == last:
            cnt += 1
            continue
        if last is not None:
            suf = f' <span class="badge" style="background:#334155;color:#cbd5e1">×{cnt}</span>' if cnt > 1 else ''
            out.append((last, suf))
        last, cnt = ln, 1
    return out

@app.get("/")
@requires_auth
def index():
    hosts = list_hosts()
    if not hosts:
        body = "<p>No logs yet under <code>/var/log/watchguard</code>.</p>"
        return render_template_string(LAYOUT, content=body)

    host = request.args.get("host", hosts[-1])
    months = list_months(host)
    if not months:
        body = f"<p>No month folders under <code>{html.escape(str(LOG_ROOT/host))}</code></p>"
        return render_template_string(LAYOUT, content=body)

    ym = request.args.get("ym", months[-1])
    try:
        n = max(1, min(50000, int(request.args.get("n", "2000"))))
    except ValueError:
        n = 2000
    q = request.args.get("q", "").strip()
    view = request.args.get("view", "pretty")
    wrap = request.args.get("wrap", "1")
    refresh = request.args.get("refresh", "0")
    hide_dns = request.args.get("hide_dns", "0")
    hide_bcast = request.args.get("hide_bcast", "0")
    regex = None
    if q:
        try:
            terms = [t for t in re.split(r'[| ]+', q) if t]
            rx_terms = [t for t in terms if '=' not in t]
            if rx_terms:
                regex = re.compile("|".join(rx_terms), re.I)
        except re.error:
            regex = None

    prefix = request.headers.get("X-Forwarded-Prefix", "/logs")
    if not prefix.endswith("/"):
        prefix += "/"

    log_path = pick_log_path(host, ym)
    lines_all = tail_file(log_path, n)
    if lines_all is None:
        body = f"<p>File not found: <code>{html.escape(str(log_path))}</code></p>"
        return render_template_string(LAYOUT, content=body)

    # Optional noise toggles: augment q
    q_full = q
    if request.args.get("hide_dns", "0") == "1":
        q_full = (q_full + " dport!=53").strip()
    if request.args.get("hide_bcast", "0") == "1":
        q_full = (q_full + " -dst_ip=224. -dst_ip=239. -dst_ip=255.255.255.255").strip()

    lines = apply_filters(lines_all, regex, q_full)
    total, shown = len(lines_all), len(lines)

    # build UI
    opts_host = "".join(
        f'<option value="{html.escape(h)}" {"selected" if h==host else ""}>{html.escape(h)}</option>'
        for h in hosts
    )
    opts_month = "".join(
        f'<option value="{html.escape(m)}" {"selected" if m==ym else ""}>{html.escape(m)}</option>'
        for m in months
    )
    view_opts = [("raw","Raw"),("pretty","Pretty"),("chips","Chips")]
    opts_view = "".join(
        f'<option value="{v}" {"selected" if view==v else ""}>{label}</option>'
        for v,label in view_opts
    )
    refresh_opts = ["0","5","10","30"]
    opts_refresh = "".join(
        f'<option value="{val}" {"selected" if refresh==val else ""}>{"Off" if val=="0" else val+"s"}</option>'
        for val in refresh_opts
    )

    form = f"""
    <form class="bar" method="get" action="{prefix}">
      <label>Host <select name="host">{opts_host}</select></label>
      <label>Month <select name="ym">{opts_month}</select></label>
      <label>Last lines <input type="number" name="n" value="{n}" min="1" max="50000" style="width:110px"></label>
      <label class="rel">Filter (regex ok) <input id="q" type="text" name="q" value="{html.escape(q)}" style="width:260px">
        <a href="#" id="qHelp" class="chip" title="Filter help">?</a>
        <div id="qHelpPop" class="popover"><b>Filter syntax</b><br>
          <ul style="margin:.5rem 0 .25rem 1rem">
            <li>Regex tokens: space or | separated (OR match)</li>
            <li>Negation: -word, or key!=value</li>
            <li>key=value: ip, src_ip, dst_ip, dport, sport, action</li>
            <li>Ranges: dport=6881-6999 (also sport)</li>
            <li>Combine: regex OR all key=value/ranges; negatives always exclude</li>
            <li>Aliases: src/src_ip/saddr; dst/dst_ip/daddr; dport/dst_port/dpt; sport/src_port/spt; action/msg/log; ip aliases src_ip</li>
          </ul>
          <div class="muted">Examples: <code>bittorrent ip=192.168.1.23</code>, <code>-Deny action!=Allow</code>, <code>dport=51413</code></div>
        </div></label>
      <label>View <select id="view" name="view">{opts_view}</select></label>
      <label>Wrap <input id="wrap" type="checkbox" name="wrap" value="1" {"checked" if wrap=="1" else ""}></label>
      <label>Refresh <select name="refresh">{opts_refresh}</select></label>
      <label class="muted"><input type="checkbox" name="hide_dns" value="1" {"checked" if hide_dns=="1" else ""}> Hide DNS</label>
      <label class="muted"><input type="checkbox" name="hide_bcast" value="1" {"checked" if hide_bcast=="1" else ""}> Hide broadcast</label>
      <button type="submit">View</button>
    </form>
    """

    # Render according to view
    if view == "raw":
        txt = html.escape("\n".join(lines))
        if regex:
            txt = regex.sub(lambda m: f"<mark>{html.escape(m.group(0))}</mark>", txt)
        rendered = txt
    elif view == "chips":
        parts = []
        for base, suf in fold_dupes(lines):
            kv = parse_kv(base)
            header = pretty_header(kv)
            dpc = ""
            if kv.get("dport"):
                r = refresh
                hd = hide_dns
                hb = hide_bcast
                dp = html.escape(kv["dport"])
                dpc = f'<a class="chip port" href="{prefix}?host={host}&ym={ym}&n={n}&view={view}&wrap={wrap}&refresh={r}&hide_dns={hd}&hide_bcast={hb}&q=dport={dp}">dport {dp}</a>'
            txt = html.escape(base)
            if regex:
                txt = regex.sub(lambda m: f"<mark>{html.escape(m.group(0))}</mark>", txt)
            parts.append(f'<div class="line">{header}{dpc}{suf}<div class="muted">{txt}</div></div>')
        rendered = "\n".join(parts)
    else:  # pretty
        parts = []
        for base, suf in fold_dupes(lines):
            kv = parse_kv(base)
            header = pretty_header(kv)
            txt = html.escape(base)
            if regex:
                txt = regex.sub(lambda m: f"<mark>{html.escape(m.group(0))}</mark>", txt)
            parts.append(header + txt + suf)
        rendered = "\n".join(parts)

    # Top talkers / ports summary
    ips, ports = summarize(lines)
    def mk_table(title, rows, kind):
        r = request.args.get('refresh','0'); hd = request.args.get('hide_dns','0'); hb = request.args.get('hide_bcast','0')
        items = "".join(
          f'<tr><td>{html.escape(k)}</td><td>{v}</td>'
          f'<td><a href="{prefix}?host={host}&ym={ym}&n={n}&view={view}&wrap={wrap}&refresh={r}&hide_dns={hd}&hide_bcast={hb}&q={kind}={html.escape(k)}">filter</a></td></tr>'
          for k,v in rows
        )
        return f"<h3>{title}</h3><table class='mini'><tr><th>{kind}</th><th>count</th><th></th></tr>{items}</table>"
    summary_html  = mk_table("Top internal IPs", ips, "ip")
    summary_html += mk_table("Top dst ports", ports, "dport")

    # Download link (preserve query) + counts + copy link
    qs = request.query_string.decode() or ""
    counts_html = f'<div class="bar"><span class="muted">Showing {shown} / {total}</span> <button type="button" onclick="navigator.clipboard.writeText(location.href)">Copy link</button> <label class="muted"><input type="checkbox" id="pauseRefresh"> Pause</label></div>'
    download_html = f'<div class="bar"><a href="{prefix}export?{qs}">Download</a></div>'
    if view in ("raw", "pretty"):
        pre_class = "" if wrap == "1" else "nowrap"
        results_html = f'<pre class="{pre_class}">' + rendered + "</pre>"
    else:
        results_html = '<div class="box lines">' + rendered + '</div>'
    saved_html = '<div class="bar"><input type="text" id="saveName" placeholder="Save as..." style="width:160px"><button type="button" id="saveBtn">Save filter</button><span id="savedList"></span></div>'
    script = """
    <script>
    (function(){
      var params=new URLSearchParams(location.search);
      var r=parseInt(params.get('refresh')||'0',10);
      var paused=false; var cb=document.getElementById('pauseRefresh'); if(cb) cb.addEventListener('change',function(){paused=this.checked});
      if(r>0){ setInterval(function(){ if(!paused) location.reload(); }, r*1000); }
      var q=document.getElementById('q'); var view=document.getElementById('view'); var wrap=document.getElementById('wrap');
      var saveBtn=document.getElementById('saveBtn'); var saveName=document.getElementById('saveName'); var list=document.getElementById('savedList');
      function renderSaved(){
        var m = JSON.parse(localStorage.getItem('watchlog_saves')||'{}');
        list.innerHTML='';
        Object.keys(m).sort().forEach(function(k){
          var a=document.createElement('a'); a.href='javascript:void(0)'; a.className='chip'; a.textContent=k; a.onclick=function(){
            var s=m[k];
            q.value=s.q||''; view.value=s.view||'pretty'; wrap.checked=s.wrap==='1';
            var params=new URLSearchParams(location.search);
            params.set('q', q.value); params.set('view', view.value); params.set('wrap', wrap.checked?'1':'0');
            location.search = params.toString();
          }; list.appendChild(a);
        });
      }
      renderSaved();
      if(saveBtn) saveBtn.onclick=function(){
        var name=saveName.value.trim(); if(!name) return;
        var m = JSON.parse(localStorage.getItem('watchlog_saves')||'{}');
        m[name] = {q: q.value, view: view.value, wrap: wrap.checked?'1':'0'};
        localStorage.setItem('watchlog_saves', JSON.stringify(m));
        saveName.value=''; renderSaved();
      };
      // Shortcuts
      var helpShown=false; function toggleHelp(){ var o=document.getElementById('helpOverlay'); if(!o) return; helpShown=!helpShown; o.style.display=helpShown?'flex':'none'; }
      // Filter popover toggle
      (function(){
        var btn=document.getElementById('qHelp'); var pop=document.getElementById('qHelpPop');
        if(!btn||!pop) return;
        btn.addEventListener('click', function(ev){ ev.preventDefault(); pop.classList.toggle('open'); });
        document.addEventListener('click', function(ev){ if(pop.classList.contains('open')){ var t=ev.target; if(t!==pop && !pop.contains(t) && t!==btn){ pop.classList.remove('open'); } } });
      })();

      document.addEventListener('keydown', function(e){
        if(e.key==='/' && !e.metaKey && !e.ctrlKey && !e.altKey){ e.preventDefault(); var el=document.getElementById('q'); if(el) el.focus(); }
        else if(e.key==='r' && !e.metaKey && !e.ctrlKey && !e.altKey){ var w=document.getElementById('wrap'); if(w){w.checked=!w.checked; var params=new URLSearchParams(location.search); params.set('wrap', w.checked?'1':'0'); location.search=params.toString();} }
        else if(e.key==='p' && !e.metaKey && !e.ctrlKey && !e.altKey){ var v=document.getElementById('view'); if(v){ var opts=['raw','pretty','chips']; var i=opts.indexOf(v.value); v.value=opts[(i+1)%opts.length]; var params=new URLSearchParams(location.search); params.set('view', v.value); location.search=params.toString(); } }
        else if(e.key==='?' && !e.metaKey && !e.ctrlKey && !e.altKey){ e.preventDefault(); toggleHelp(); }
      });
    })();
    </script>
    <div id="helpOverlay" class="overlay"><div class="panel">
      <h3>Shortcuts</h3>
      <ul>
        <li><b>/</b>: focus filter</li>
        <li><b>r</b>: toggle wrap</li>
        <li><b>p</b>: cycle view</li>
        <li><b>?</b>: toggle help</li>
      </ul>
    </div></div>
    """
    content = form + saved_html + summary_html + counts_html + download_html + results_html + script
    return render_template_string(LAYOUT, content=content)

@app.get("/export")
@requires_auth
def export():
    # reuse the same selection logic as index()
    hosts = list_hosts()
    if not hosts:
        return Response("No logs", 404)
    host = request.args.get("host", hosts[-1])
    months = list_months(host)
    if not months:
        return Response("No months", 404)
    ym = request.args.get("ym", months[-1])
    try:
        n = max(1, min(50000, int(request.args.get("n", "2000"))))
    except ValueError:
        n = 2000
    q = request.args.get("q", "").strip()
    regex = None
    if q:
        try:
            terms = [t for t in re.split(r'[| ]+', q) if t]
            rx_terms = [t for t in terms if '=' not in t]
            if rx_terms:
                regex = re.compile("|".join(rx_terms), re.I)
        except re.error:
            regex = None

    log_path = pick_log_path(host, ym)
    lines = tail_file(log_path, n) or []
    lines = apply_filters(lines, regex, q)

    buf = io.BytesIO("\n".join(lines).encode("utf-8", "ignore"))
    return send_file(buf, as_attachment=True, download_name="watchguard.txt", mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8811)
