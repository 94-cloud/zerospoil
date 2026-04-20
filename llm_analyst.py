import os
import json
import redis
import numpy as np
import datetime
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
r = redis.Redis(host=os.getenv("REDIS_HOST", "127.0.0.1"), port=6379, decode_responses=True)
MAX_ITERATIONS = 3
LOG_FILE = "logs/execution_log.jsonl"

def log(entry):
    entry["timestamp"] = datetime.datetime.now().isoformat()
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[LOG] {entry}")

def load_processes():
    keys = r.keys("win11:processes:*")
    processes = []
    for key in sorted(keys):
        raw = r.get(key)
        if raw:
            try:
                data = json.loads(raw)
                processes.extend(data)
                log({"event": "loaded", "key": key, "count": len(data)})
            except json.JSONDecodeError:
                log({"event": "parse_error", "key": key})
    return processes

def load_mft():
    keys = r.keys("win11:mft:*")
    findings = []
    for key in keys:
        raw = r.get(key)
        if raw:
            entry = json.loads(raw)
            delta = entry.get("anomaly_notes", {}).get("si_fn_delta_days", 0)
            if delta > 1:
                findings.append({
                    "file": entry.get("full_path"),
                    "inode": entry.get("inode"),
                    "SI_created": entry.get("SI_timestamps", {}).get("created"),
                    "FN_created": entry.get("FN_timestamps", {}).get("created"),
                    "delta_days": delta,
                    "verdict": entry.get("anomaly_notes", {}).get("verdict"),
                    "mitre": entry.get("anomaly_notes", {}).get("mitre")
                })
            log({"event": "mft_analyzed", "key": key, "delta_days": delta})
    return findings

def detect_parent_anomalies(processes):
    pid_map = {p["ProcessId"]: p["Name"] for p in processes}
    anomalies = []
    suspicious = {
        "powershell.exe": ["explorer.exe", "cmd.exe"],
        "cmd.exe": ["explorer.exe"],
        "wscript.exe": ["explorer.exe"],
        "mshta.exe": ["explorer.exe"],
    }
    for proc in processes:
        name = proc.get("Name", "").lower()
        parent = pid_map.get(proc.get("ParentProcessId"), "unknown").lower()
        if name in suspicious:
            if parent not in [p.lower() for p in suspicious[name]]:
                anomalies.append({
                    "process": proc,
                    "reason": f"{name} spawned by {parent}"
                })
    return anomalies

def detect_missing_paths(processes):
    flagged = []
    watchlist = ["svchost.exe", "lsass.exe", "services.exe"]
    for proc in processes:
        if proc.get("Name", "").lower() in watchlist:
            if not proc.get("ExecutablePath"):
                flagged.append({
                    "process": proc,
                    "reason": f"{proc['Name']} has null ExecutablePath"
                })
    return flagged

def three_sigma(processes):
    pids = [p.get("ProcessId", 0) for p in processes]
    if len(pids) < 3:
        return []
    mean, std = np.mean(pids), np.std(pids)
    if std == 0:
        return []
    return [p for p in processes if abs(p.get("ProcessId", 0) - mean) > 3 * std]

def analyze(anomalies, mft_findings, iteration):
    prompt = f"""You are a senior forensic analyst. Iteration {iteration} of {MAX_ITERATIONS}.

PARENT ANOMALIES:
{json.dumps(anomalies.get("parent_anomalies", []), indent=2)}

MISSING PATH INDICATORS:
{json.dumps(anomalies.get("missing_paths", []), indent=2)}

THREE-SIGMA OUTLIERS:
{json.dumps(anomalies.get("sigma_outliers", []), indent=2)}

MFT TIMESTAMP ANOMALIES ($SI vs $FN):
{json.dumps(mft_findings, indent=2)}

Respond in this exact format:
FINDINGS: <each anomaly with severity CRITICAL/HIGH/MEDIUM/LOW and MITRE ATT&CK ID>
FALSE_POSITIVES: <list any with reasoning>
VERDICT: <overall assessment and kill chain narrative>
CONFIDENCE: <HIGH/MEDIUM/LOW>
NEXT_STEPS: <recommended IR actions>"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text

def run():
    print("[*] ZeroSpoil starting...")
    log({"event": "start"})

    processes = load_processes()
    if not processes:
        print("[-] No process artifacts in Redis")
        return
    print(f"[+] {len(processes)} processes loaded")

    mft_findings = load_mft()
    print(f"[+] {len(mft_findings)} MFT timestamp anomalies found")

    anomalies = {
        "parent_anomalies": detect_parent_anomalies(processes),
        "missing_paths": detect_missing_paths(processes),
        "sigma_outliers": three_sigma(processes)
    }
    log({
        "event": "detection_complete",
        "parent": len(anomalies["parent_anomalies"]),
        "missing": len(anomalies["missing_paths"]),
        "sigma": len(anomalies["sigma_outliers"]),
        "mft": len(mft_findings)
    })

    report = None
    for i in range(1, MAX_ITERATIONS + 1):
        print(f"[*] Iteration {i}/{MAX_ITERATIONS}")
        log({"event": "iteration_start", "iteration": i})
        report = analyze(anomalies, mft_findings, i)
        log({"event": "iteration_done", "iteration": i, "report": report})
        if "CONFIDENCE: HIGH" in report:
            print(f"[+] High confidence at iteration {i}, stopping")
            break

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"logs/triage_report_{ts}.md"
    with open(path, "w") as f:
        f.write(f"# ZeroSpoil Triage Report\n")
        f.write(f"Generated: {datetime.datetime.now().isoformat()}\n\n")
        f.write(f"## Artifacts Analyzed\n")
        f.write(f"- Processes: {len(processes)}\n")
        f.write(f"- MFT anomalies: {len(mft_findings)}\n\n")
        f.write(f"## Final Analysis\n\n{report}\n")
    print(f"[+] Report: {path}")
    log({"event": "complete", "report": path})

if __name__ == "__main__":
    run()
