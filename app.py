import os, re, html, io, collections, json
from pathlib import Path
from flask import Flask, request, Response, render_template_string, send_file
from datetime import datetime, timezone
from watchlog_lite.services.logs import (
    list_hosts, list_months, tail_file, apply_filters, summarize, pick_log_path, parse_kv, BASE as LOG_BASE
)
from watchlog_lite.services.ui import pretty_header, fold_dupes

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

"""Helper functions have been moved into watchlog_lite.services.* modules."""

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
        body = f"<p>No month folders under <code>{html.escape(str(LOG_BASE/host))}</code></p>"
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
    r_js = refresh if refresh.isdigit() else "0"


    script = """
    <script>
    (function () {
      // Auto-refresh + Pause
      var params = new URLSearchParams(location.search);
      var r = parseInt(params.get('refresh') || '0', 10);
      var paused = false;
      var cb = document.getElementById('pauseRefresh');
      if (cb) cb.addEventListener('change', function () { paused = this.checked; });
      if (r > 0) { setInterval(function () { if (!paused) location.reload(); }, r * 1000); }

      // Saved filters
      var qEl = document.getElementById('q');
      var viewEl = document.getElementById('view');
      var wrapEl = document.getElementById('wrap');
      var saveBtn = document.getElementById('saveBtn');
      var saveName = document.getElementById('saveName');
      var list = document.getElementById('savedList');
      function renderSaved() {
        var m = JSON.parse(localStorage.getItem('watchlog_saves') || '{}');
        list.innerHTML = '';
        Object.keys(m).sort().forEach(function (k) {
          var a = document.createElement('a'); a.href = 'javascript:void(0)'; a.className = 'chip'; a.textContent = k; a.onclick = function () {
            var s = m[k];
            qEl.value = s.q || ''; viewEl.value = s.view || 'pretty'; wrapEl.checked = s.wrap === '1';
            var p = new URLSearchParams(location.search);
            p.set('q', qEl.value); p.set('view', viewEl.value); p.set('wrap', wrapEl.checked ? '1' : '0');
            location.search = p.toString();
          }; list.appendChild(a);
        });
      }
      renderSaved();
      if (saveBtn) saveBtn.onclick = function () {
        var name = saveName.value.trim(); if (!name) return;
        var m = JSON.parse(localStorage.getItem('watchlog_saves') || '{}');
        m[name] = { q: qEl.value, view: viewEl.value, wrap: wrapEl.checked ? '1' : '0' };
        localStorage.setItem('watchlog_saves', JSON.stringify(m));
        saveName.value = ''; renderSaved();
      };

      // Popover toggle
      (function () {
        var btn = document.getElementById('qHelp'); var pop = document.getElementById('qHelpPop');
        if (!btn || !pop) return;
        btn.addEventListener('click', function (ev) { ev.preventDefault(); pop.classList.toggle('open'); });
        document.addEventListener('click', function (ev) { if (pop.classList.contains('open')) { var t = ev.target; if (t !== pop && !pop.contains(t) && t !== btn) { pop.classList.remove('open'); } } });
      })();

      // Shortcuts
      var helpShown = false; function toggleHelp() { var o = document.getElementById('helpOverlay'); if (!o) return; helpShown = !helpShown; o.style.display = helpShown ? 'flex' : 'none'; }
      document.addEventListener('keydown', function (e) {
        if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) { e.preventDefault(); var el = document.getElementById('q'); if (el) el.focus(); }
        else if (e.key === 'r' && !e.metaKey && !e.ctrlKey && !e.altKey) { var w = document.getElementById('wrap'); if (w) { w.checked = !w.checked; var p = new URLSearchParams(location.search); p.set('wrap', w.checked ? '1' : '0'); location.search = p.toString(); } }
        else if (e.key === 'p' && !e.metaKey && !e.ctrlKey && !e.altKey) { var v = document.getElementById('view'); if (v) { var opts = ['raw','pretty','chips']; var i = opts.indexOf(v.value); v.value = opts[(i + 1) % opts.length]; var p = new URLSearchParams(location.search); p.set('view', v.value); location.search = p.toString(); } }
        else if (e.key === '?' && !e.metaKey && !e.ctrlKey && !e.altKey) { e.preventDefault(); toggleHelp(); }
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
