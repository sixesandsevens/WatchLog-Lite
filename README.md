# WatchLog-Lite

Lightweight WatchGuard log viewer (Flask). Zero DB, fast tail of the active log.

Features
- Prefix-aware UI: respects `X-Forwarded-Prefix` (defaults to `/logs`).
- Regex highlight and filter.
- Views: Raw, Pretty, Chips (with badges/flow and duplicate folding).
- Wrap toggle to switch long-line wrapping.
- key=value filters: `ip=`, `dport=`, `sport=`, `action=` with common aliases parsed.
- Download current filtered view (`/export`).
- Top talkers: internal IPs and dst ports from the current view.

Run
- `python3 app.py` (dev) or via systemd/gunicorn behind nginx.
- Protect with nginx basic auth (recommended). The app also supports basic auth via `WATCHLOG_USER`/`WATCHLOG_PASS`.

Reverse proxy snippet
```
location ^~ /logs/ {
  proxy_pass http://127.0.0.1:8811/;
  proxy_set_header X-Forwarded-Prefix /logs;
}
```

Detector (optional)
- Script: `tools/detector.py` finds BitTorrent signatures in the newest WG log.
- Systemd examples: `systemd/watchlog-detector.service.example` + `.timer.example`.
- Env:
  - `WG_HOST`: firewall host folder name under `/var/log/watchguard`
  - `SLACK_WEBHOOK`: optional Slack Incoming Webhook URL
