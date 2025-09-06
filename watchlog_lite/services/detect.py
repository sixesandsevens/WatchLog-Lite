import re
from typing import List, Dict, Tuple
from .logs import parse_kv

# BitTorrent heuristics and other risk flags
PAT_BT = re.compile(r"(bittorrent|dht|announce|magnet:|d(?:st_)?port=(?:38315|51413|68[8-9]\d|69\d\d))", re.I)
RISKY_PORTS = {23, 2323, 445, 3389, 1433, 3306, 5900, 5901, 25, 21}

# lightweight IPv4 finder for fallback
RE_IP_INLINE = re.compile(r'(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)')

def _is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except Exception:
            return False
    return False

def analyze_suspicious(lines: List[str]) -> Dict:
    """Aggregate simple suspicious indicators from a list of log lines."""
    bt_count = 0
    bt_ips = set()
    scan_map = {}  # src_ip -> set of dports
    risky_port_counts = {}  # dport -> count

    for ln in lines:
        if PAT_BT.search(ln):
            bt_count += 1
            kv = parse_kv(ln)
            ip = kv.get("src_ip")
            if not ip:
                m = RE_IP_INLINE.search(ln)
                ip = m.group(1) if m else None
            if ip and _is_private_ip(ip):
                bt_ips.add(ip)
        # kv for scan/risky
        kv = parse_kv(ln)
        sip = kv.get("src_ip")
        dpt = kv.get("dport")
        act = (kv.get("action") or "").lower()
        if sip and _is_private_ip(sip) and dpt and dpt.isdigit():
            scan_map.setdefault(sip, set()).add(int(dpt))
        if dpt and dpt.isdigit():
            dpti = int(dpt)
            if dpti in RISKY_PORTS and act == "allow":
                risky_port_counts[dpti] = risky_port_counts.get(dpti, 0) + 1

    # Build suspects list: top sources with many distinct dports
    suspects = sorted(((sip, len(ports)) for sip, ports in scan_map.items()), key=lambda x: x[1], reverse=True)
    suspects = [s for s in suspects if s[1] >= 10][:10]
    risky_list = sorted(risky_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "bt_count": bt_count,
        "bt_ips": sorted(bt_ips),
        "scan_suspects": suspects,
        "risky_ports": risky_list,
    }

def summarize_bittorrent(lines: List[str]) -> List[Tuple[str, int]]:
    """Return [(ip, count), ...] for lines that match BT heuristics (top 10)."""
    counts = {}
    for ln in lines:
        if PAT_BT.search(ln):
            d = parse_kv(ln)
            ip = d.get("src_ip")
            if not ip:
                m = RE_IP_INLINE.search(ln)
                ip = m.group(1) if m else None
            if ip:
                counts[ip] = counts.get(ip, 0) + 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]

