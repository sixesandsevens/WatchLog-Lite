import html
from pathlib import Path

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

def _rel_time(ts: str) -> str:
    from datetime import datetime
    if not ts:
        return ""
    s = ts.strip()
    dt = None
    try:
        if 'T' in s or 'Z' in s:
            s2 = s.replace('Z', '+00:00')
            dt = datetime.fromisoformat(s2)
        else:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        dt = None
    if not dt:
        return ts
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    delta = now - dt
    secs = int(delta.total_seconds())
    secs = max(0, secs)
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

