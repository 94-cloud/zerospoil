import subprocess
import json
import datetime
import os
from pathlib import Path

SIFT_IP = "10.10.10.20"
SIFT_USER = "sansforensics"
REMOTE_DIR = "/home/sansforensics/artifacts"
LOCAL_DIR = Path("C:/forensic/artifacts")

def collect_processes():
    """Collect process list via WMI and return as JSON."""
    ps_script = """
    $procs = Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
    $procs | ConvertTo-Json -Depth 3
    """
    result = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True, text=True
    )
    return result.stdout

def save_and_ship(data, artifact_type):
    """Save artifact locally then SCP to SIFT."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{artifact_type}_{timestamp}.json"
    local_path = LOCAL_DIR / filename

    LOCAL_DIR.mkdir(exist_ok=True)
    with open(local_path, "w", encoding="utf-8") as f:
        f.write(data)
    print(f"[+] Saved: {local_path}")

    remote = f"{SIFT_USER}@{SIFT_IP}:{REMOTE_DIR}/{filename}"
    result = subprocess.run(
        ["scp", str(local_path), remote],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"[+] Shipped: {filename} -> SIFT")
    else:
        print(f"[-] SCP failed: {result.stderr}")

if __name__ == "__main__":
    print("[*] Collecting processes via WMI...")
    data = collect_processes()
    if data.strip():
        save_and_ship(data, "processes")
    else:
        print("[-] No process data collected")
