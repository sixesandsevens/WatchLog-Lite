#!/usr/bin/env python3
import os, re, sys, glob, json, urllib.request
from pathlib import Path

BASE = Path("/var/log/watchguard")
FIREWALL = os.getenv("WG_HOST", "GRC-GAIN-FW01-2")

def newest_log():
    months = sorted(glob.glob(str(BASE / FIREWALL / "20*")), reverse=True)
    if not months:
        return None
    log = Path(months[0]) / "watchguard.log"
    return log if log.exists() else None

# Ports: 38315, 51413, 6881-6999 (bittorrent)
PAT = re.compile(r'(bittorrent|dht|announce|magnet:|d(?:st_)?port=(?:38315|51413|68[8-9]\d|69\d\d))', re.I)
IP  = re.compile(r'(?:src(?:_ip)?=|saddr=)(\d+\.\d+\.\d+\.\d+)')

def tail(path: Path, n=10000):
    lines = []
    with path.open("rb") as f:
        f.seek(0,2); size=f.tell(); block=8192; buf=b""; pos=size
        while pos>0 and len(lines)<=n:
            rd=min(block,pos); pos-=rd; f.seek(pos)
            buf=f.read(rd)+buf; lines=buf.splitlines()
    return [l.decode("utf-8","ignore") for l in lines[-n:]]

def main():
    log = newest_log()
    if not log:
        return 0
    hits = [ln for ln in tail(log) if PAT.search(ln)]
    if not hits:
        return 0
    ips=set()
    for ln in hits:
        m=IP.search(ln)
        if m and m.group(1).startswith("192.168."):
            ips.add(m.group(1))
    msg = f"[watchlog-detector] BT signatures in {log}:\n" + ("\n".join(sorted(ips)) if ips else "(no internal src_ip parsed)")
    print(msg)

    webhook=os.getenv("SLACK_WEBHOOK","" ).strip()
    if webhook:
        data=json.dumps({"text":msg}).encode()
        req=urllib.request.Request(webhook, data=data, headers={"Content-Type":"application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"slack notify error: {e}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

