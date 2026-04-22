import json
import redis
from datetime import datetime

r = redis.Redis(host='127.0.0.1', port=6379)

# Simulated C2 beacon + DNS exfil traffic
packets = [
    {
        "frame_time": "2026-04-22 19:00:01.123",
        "ip_src": "192.168.179.132",
        "ip_dst": "185.220.101.45",
        "protocol": "TCP",
        "dst_port": 443,
        "length": 144,
        "info": "C2 beacon - consistent 60s interval",
        "flag": "BEACON"
    },
    {
        "frame_time": "2026-04-22 19:01:01.124",
        "ip_src": "192.168.179.132",
        "ip_dst": "185.220.101.45",
        "protocol": "TCP",
        "dst_port": 443,
        "length": 144,
        "info": "C2 beacon - consistent 60s interval",
        "flag": "BEACON"
    },
    {
        "frame_time": "2026-04-22 19:02:01.125",
        "ip_src": "192.168.179.132",
        "ip_dst": "185.220.101.45",
        "protocol": "TCP",
        "dst_port": 443,
        "length": 144,
        "info": "C2 beacon - consistent 60s interval",
        "flag": "BEACON"
    },
    {
        "frame_time": "2026-04-22 19:03:15.001",
        "ip_src": "192.168.179.132",
        "ip_dst": "8.8.8.8",
        "protocol": "DNS",
        "dst_port": 53,
        "length": 512,
        "info": "dns.qry.name: aGVsbG8gd29ybGQ.exfil.evilc2.net",
        "flag": "DNS_EXFIL"
    },
    {
        "frame_time": "2026-04-22 19:03:16.002",
        "ip_src": "192.168.179.132",
        "ip_dst": "8.8.8.8",
        "protocol": "DNS",
        "dst_port": 53,
        "length": 498,
        "info": "dns.qry.name: dGhpcyBpcyBleGZpbA.exfil.evilc2.net",
        "flag": "DNS_EXFIL"
    },
    {
        "frame_time": "2026-04-22 19:03:17.003",
        "ip_src": "192.168.179.132",
        "ip_dst": "8.8.8.8",
        "protocol": "DNS",
        "dst_port": 53,
        "length": 501,
        "info": "dns.qry.name: dGVzdGluZyAxMjM.exfil.evilc2.net",
        "flag": "DNS_EXFIL"
    }
]

# Write to Redis
key = f"win11:network:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
r.set(key, json.dumps(packets))
print(f"[+] Network artifacts injected -> {key}")
print(f"[+] {len([p for p in packets if p['flag']=='BEACON'])} C2 beacons")
print(f"[+] {len([p for p in packets if p['flag']=='DNS_EXFIL'])} DNS exfil packets")
