import os, re, html, gzip
import collections
import glob
from pathlib import Path
from typing import List, Tuple, Optional

# Base path for logs
BASE = Path(os.environ.get("WG_LOG_BASE", "/var/log/watchguard"))

# Patterns
RE_IP    = re.compile(r'(?:src(?:_ip)?=|saddr=)(\d+\.\d+\.\d+\.\d+)')
RE_DPORT = re.compile(r'(?:d(?:st_)?port=|dpt=)(\d{1,5})')
KV       = re.compile(r'(\w+)=([^\s]+)')

def list_hosts() -> List[str]:
    if not BASE.exists():
        return []
    return sorted([p.name for p in BASE.iterdir() if p.is_dir()])

def list_months(host: str) -> List[str]:
    base = BASE / host
    if not base.exists():
        return []
    return sorted([p.name for p in base.iterdir() if p.is_dir()])

def pick_log_path(host: str, ym: str) -> Path:
    return BASE / host / ym / "watchguard.log"

def tail_file(path: Path, n: int) -> Optional[List[str]]:
    """Efficiently read last n lines from a potentially large file."""
    try:
        # Support .gz if needed
        if str(path).endswith('.gz'):
            from collections import deque
            dq = deque(maxlen=n)
            with gzip.open(path, 'rt', errors='ignore') as f:
                for line in f:
                    dq.append(line.rstrip('\n'))
            return list(dq)

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

def parse_kv(line: str) -> dict:
    d = dict(KV.findall(line))
    d["src_ip"] = d.get("src") or d.get("src_ip") or d.get("saddr")
    d["dst_ip"] = d.get("dst") or d.get("dst_ip") or d.get("daddr")
    d["dport"]  = d.get("dport") or d.get("dst_port") or d.get("dpt")
    d["sport"]  = d.get("sport") or d.get("src_port") or d.get("spt")
    d["action"] = d.get("action") or d.get("msg") or d.get("log")
    d["ip"] = d.get("src_ip")
    # Timestamps if present
    ts = d.get("ts") or None
    if not ts:
        date, time_ = d.get("date"), d.get("time")
        if date and time_:
            ts = f"{date} {time_}"
    d["ts"] = ts
    return d

def summarize(lines: List[str]) -> Tuple[List[Tuple[str,int]], List[Tuple[str,int]]]:
    ips, ports = collections.Counter(), collections.Counter()
    for ln in lines:
        m = RE_IP.search(ln)
        if m and m.group(1).startswith("192.168."):
            ips[m.group(1)] += 1
        m = RE_DPORT.search(ln)
        if m:
            ports[m.group(1)] += 1
    return ips.most_common(10), ports.most_common(10)

def apply_filters(lines: List[str], regex, q_raw: str):
    """Advanced filters supporting regex, negatives, kv and ranges."""
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
        if rx_neg and rx_neg.search(line):
            return False
        need_struct = bool(kv_pos or range_pos or kv_neg)
        kv = None
        if need_struct:
            kv = parse_kv(line)
            for k, v in kv_neg:
                if kv.get(k) == v:
                    return False
        ranges_ok = True
        if range_pos:
            for k, lo, hi in range_pos:
                try:
                    val = int(kv.get(k) or -1)
                except (TypeError, ValueError):
                    return False
                if not (lo <= val <= hi):
                    return False
        kv_ok = all(kv.get(k) == v for k, v in kv_pos) if kv_pos else False
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

