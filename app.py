import os, re, html
from collections import deque
from pathlib import Path
from flask import Flask, request, Response, render_template_string

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
    dq = deque(maxlen=n)
    try:
        with path.open("r", errors="ignore") as f:
            for line in f:
                dq.append(line.rstrip("\n"))
    except FileNotFoundError:
        return None
    return list(dq)

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
    regex = None
    if q:
        try:
            regex = re.compile(q, re.I)
        except re.error as e:
            regex = None
            q = f"(invalid regex: {html.escape(str(e))})"

    log_path = LOG_ROOT / host / ym / "watchguard.log"
    lines = tail_file(log_path, n)
    if lines is None:
        body = f"<p>File not found: <code>{html.escape(str(log_path))}</code></p>"
        return render_template_string(LAYOUT, content=body)

    if regex:
        lines = [ln for ln in lines if regex.search(ln)]

    # build UI
    opts_host = "".join(
        f'<option value="{html.escape(h)}" {"selected" if h==host else ""}>{html.escape(h)}</option>'
        for h in hosts
    )
    opts_month = "".join(
        f'<option value="{html.escape(m)}" {"selected" if m==ym else ""}>{html.escape(m)}</option>'
        for m in months
    )

    form = f"""
    <form class="bar" method="get" action="/">
      <label>Host <select name="host">{opts_host}</select></label>
      <label>Month <select name="ym">{opts_month}</select></label>
      <label>Last lines <input type="number" name="n" value="{n}" min="1" max="50000" style="width:110px"></label>
      <label>Filter (regex ok) <input type="text" name="q" value="{html.escape(q)}" style="width:260px"></label>
      <button type="submit">View</button>
    </form>
    """

    body = form + "<pre>" + html.escape("\n".join(lines)) + "</pre>"
    return render_template_string(LAYOUT, content=body)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8811)
