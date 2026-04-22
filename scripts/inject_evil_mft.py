import json
import redis
from datetime import datetime

r = redis.Redis(host='127.0.0.1', port=6379)

# MFT entries where $SI is NEWER than $FN = timestomping
mft_entries = [
    {
        "inode": "642",
        "filename": "svchost.exe",
        "path": "C:\\Users\\lab-U\\AppData\\Local\\Temp\\svchost.exe",
        "si_modified": "2026-04-22 19:00:00",
        "fn_modified": "2024-01-15 08:23:11",
        "si_created":  "2026-04-22 19:00:00",
        "fn_created":  "2024-01-15 08:23:11",
        "delta_days": 828,
        "anomaly": "$SI newer than $FN by 828 days - TIMESTOMPING DETECTED",
        "mitre": "T1070.006"
    },
    {
        "inode": "891",
        "filename": "xkqtmrwz.exe",
        "path": "C:\\Users\\lab-U\\AppData\\Roaming\\xkqtmrwz.exe",
        "si_modified": "2026-04-22 19:00:01",
        "fn_modified": "2023-06-10 14:05:33",
        "si_created":  "2026-04-22 19:00:01",
        "fn_created":  "2023-06-10 14:05:33",
        "delta_days": 1047,
        "anomaly": "$SI newer than $FN by 1047 days - TIMESTOMPING DETECTED",
        "mitre": "T1070.006"
    },
    {
        "inode": "1024",
        "filename": "cfg.dat",
        "path": "C:\\Users\\lab-U\\AppData\\Roaming\\cfg.dat",
        "si_modified": "2026-04-22 19:00:02",
        "fn_modified": "2022-11-03 09:17:44",
        "si_created":  "2026-04-22 19:00:02",
        "fn_created":  "2022-11-03 09:17:44",
        "delta_days": 1266,
        "anomaly": "$SI newer than $FN by 1266 days - TIMESTOMPING DETECTED",
        "mitre": "T1070.006"
    }
]

key = f"win11:mft:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
r.set(key, json.dumps(mft_entries))
print(f"[+] MFT artifacts injected -> {key}")
print(f"[+] {len(mft_entries)} timestomped files detected")
for e in mft_entries:
    print(f"    inode {e['inode']}: {e['filename']} - delta {e['delta_days']} days")
