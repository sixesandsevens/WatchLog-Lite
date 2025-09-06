import re, html
from .logs import parse_kv
from .detect import PAT_BT

RE_IP_INLINE   = re.compile(r'(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)')
RE_PORT_INLINE = re.compile(r'(?:(?:dpt|dst_port|dport)=|:)(\d{1,5})\b')

def _ip_link(ip: str) -> str:
    return f'<a class="ip" href="https://rdap.org/ip/{ip}" target="_blank" rel="noreferrer">{ip}</a>'

def pretty_line(line: str) -> str:
    """
    Compact, resilient colorizer:
      - badge [Allow/Deny] + src → dst:port + optional app
      - RDAP links for IPs, bold ports, BitTorrent tag when suspected
      - falls back to lightly colorized raw if parse_kv lacks fields
    """
    d = parse_kv(line)
    act = (d.get("action") or "").lower()
    if   act.startswith("allow"): cls = "allow"
    elif act.startswith("deny"):  cls = "deny"
    else:                          cls = "info"

    src   = d.get("src_ip")
    dst   = d.get("dst_ip")
    dport = d.get("dport")
    app   = d.get("log") or d.get("msg") or d.get("app_name") or ""

    tags = []
    if PAT_BT.search(line) or (dport and dport.isdigit() and (6881 <= int(dport) <= 6999 or int(dport) in (38315, 51413))):
        tags.append('<span class="tag tag-bt">BitTorrent?</span>')

    # If we have the main pieces, render a compact row
    if src or dst or dport or act:
        left  = _ip_link(src) if src else ""
        right = ((_ip_link(dst) if dst else "") + (f':<span class="port">{dport}</span>' if dport else ""))
        app_s = f'<span class="app">{html.escape(app)}</span>' if app else ""
        action_badge = f'<span class="badge {cls}">{html.escape(d.get("action") or "log")}</span>'
        arrow = '<span class="arrow">→</span>' if left or right else ""
        return f'{action_badge} {left} {arrow} {right} {app_s} {" ".join(tags)}'.strip()

    # Fallback: lightly colorize the raw line
    raw = html.escape(line)
    raw = re.sub(r'\b(Allow|Deny)\b', lambda m: f'<span class="badge {m.group(1).lower()}">{m.group(1)}</span>', raw, flags=re.I)
    raw = RE_IP_INLINE.sub(lambda m: _ip_link(m.group(1)), raw)
    raw = RE_PORT_INLINE.sub(lambda m: f':<span class="port">{m.group(1)}</span>', raw)
    if PAT_BT.search(line):
        raw += ' <span class="tag tag-bt">BitTorrent?</span>'
    return raw

