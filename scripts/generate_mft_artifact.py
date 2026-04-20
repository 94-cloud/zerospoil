import json
import os

# Simulate istat output for a timestomped file
# $SI backdated to 2020, $FN shows real creation time in 2026

OUTPUT = "/home/sansforensics/artifacts/mft_timestomp_sample.json"

mft_artifact = {
    "inode": "642",
    "file_name": "svchost.exe",
    "full_path": "C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe",
    "file_size": 14848,
    "allocated": True,
    "SI_timestamps": {
        "created":  "2020-03-15 08:22:11 UTC",
        "modified": "2020-03-15 08:22:11 UTC",
        "mft_modified": "2020-03-15 08:22:11 UTC",
        "accessed": "2020-03-15 08:22:11 UTC"
    },
    "FN_timestamps": {
        "created":  "2026-04-17 15:31:58 UTC",
        "modified": "2026-04-17 15:31:58 UTC",
        "mft_modified": "2026-04-17 15:31:58 UTC",
        "accessed": "2026-04-17 15:31:58 UTC"
    },
    "anomaly_notes": {
        "si_fn_delta_days": 2224,
        "verdict": "$SI predates $FN by 2224 days — timestomping detected",
        "tool": "timestomp or equivalent",
        "mitre": "T1070.006 - Indicator Removal: Timestomp"
    },
    "md5": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
}

os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
with open(OUTPUT, "w") as f:
    json.dump(mft_artifact, f, indent=4)

print(f"[+] MFT artifact written: {OUTPUT}")
print(f"[+] SI created:  {mft_artifact['SI_timestamps']['created']}")
print(f"[+] FN created:  {mft_artifact['FN_timestamps']['created']}")
print(f"[+] Delta: {mft_artifact['anomaly_notes']['si_fn_delta_days']} days")
print(f"[+] Verdict: {mft_artifact['anomaly_notes']['verdict']}")
