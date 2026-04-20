import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Forensic-Network-Server")

class NetworkAnalyzer:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path

    def run_tshark(self, display_filter, fields):
        """Standardized TShark wrapper for surgical packet extraction."""
        cmd = ["tshark", "-r", self.pcap_path, "-Y", display_filter, "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

@mcp.tool()
def get_connection_summary():
    """Provides a high-level flow view of TCP SYN packets (IPs and ports)."""
    analyzer = NetworkAnalyzer("/home/sansforensics/evidence.pcap")
    return analyzer.run_tshark(
        "tcp.flags.syn==1",
        ["frame.time", "ip.src", "ip.dst", "tcp.dstport"]
    )

@mcp.tool()
def search_dns_queries(query_pattern: str):
    """
    Finds C2 beacons or data exfiltration via DNS.
    query_pattern: substring to match against dns.qry.name
    ""
cat > llm_analyst.py << 'EOF'
import os
import json
import redis
import numpy as np
import datetime
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
REDIS_HOST = os.getenv("REDIS_HOST", "10.10.10.20")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
MAX_ITERATIONS = 3
LOG_FILE = "logs/execution_log.jsonl"

client = Anthropic(api_key=ANTHROPIC_API_KEY)
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def log(entry: dict):
    """Append structured entry to audit trail."""
    entry["timestamp"] = datetime.datetime.now().isoformat()
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[LOG] {entry}")

def load_artifacts_from_redis():
    """Pull all win11 process artifacts from Redis."""
    keys = r.keys("win11:processes:*")
    artifacts = []
    for key in sorted(keys):
        raw = r.get(key)
        if raw:
            try:
                data = json.loads(raw)
                artifacts.append({"key": key, "processes": data})
                log({"event": "artifact_loaded", "key": key, "count": len(data)})
            except json.JSONDecodeError:
                log({"event": "artifact_parse_error", "key": key})
    return artifacts

def three_sigma_detection(processes: list) -> list:
    """Flag processes whose PID is a statistical outlier (demo anomaly signal)."""
    pids = [p.get("ProcessId", 0) for p in processes]
    if len(pids) < 3:
        return []
    mean = np.mean(pids)
    std = np.std(pids)
    if std == 0:
        return []
    flagged = [
        p for p in processes
        if abs(p.get("ProcessId", 0) - mean) > 3 * std
    ]
    return flagged

def detect_parent_anomalies(processes: list) -> list:
    """Flag processes with suspicious parent relationships."""
    pid_map = {p["ProcessId"]: p["Name"] for p in processes}
    anomalies = []
    suspicious_parents = {
        "powershell.exe": ["explorer.exe", "cmd.exe"],
        "cmd.exe": ["explorer.exe"],
        "wscript.exe": ["explorer.exe", "winword.exe"],
        "mshta.exe": ["explorer.exe"],
    }
    for proc in processes:
        name = proc.get("Name", "").lower()
        ppid = proc.get("ParentProcessId")
        parent_name = pid_map.get(ppid, "unknown").lower()
        if name in suspicious_parents:
            if parent_name not in [p.lower() for p in suspicious_parents[name]]:
                anomalies.append({
                    "process": proc,
                    "reason": f"{name} spawned by {parent_name} (expected: {suspicious_parents[name]})"
                })
    return anomalies

def detect_missing_paths(processes: list) -> list:
    """Flag svchost and other system processes with null ExecutablePath."""
    flagged = []
    watch_list = ["svchost.exe", "lsass.exe", "services.exe"]
    for proc in processes:
        if proc.get("Name", "").lower() in watch_list:
            if not proc.get("ExecutablePath"):
                flagged.append({
                    "process": proc,
                    "reason": f"{proc['Name']} has null ExecutablePath (masquerading indicator)"
                })
    return flagged

def analyze_with_llm(anomalies: dict, iteration: int) -> str:
    """Send anomalies to Claude for triage analysis."""
    prompt = f"""You are a senior forensic analyst performing incident response triage.

Iteration: {iteration} of {MAX_ITERATIONS}

The following anomalies were detected in a Windows 11 process snapshot:

PARENT ANOMALIES:
{json.dumps(anomalies.get('parent_anomalies', []), indent=2)}

MISSING PATH INDICATORS:
{json.du
cat > llm_analyst.py << 'EOF'
import os
import json
import redis
import numpy as np
import datetime
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
REDIS_HOST = os.getenv("REDIS_HOST", "10.10.10.20")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
MAX_ITERATIONS = 3
LOG_FILE = "logs/execution_log.jsonl"

client = Anthropic(api_key=ANTHROPIC_API_KEY)
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def log(entry: dict):
    """Append structured entry to audit trail."""
    entry["timestamp"] = datetime.datetime.now().isoformat()
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[LOG] {entry}")

def load_artifacts_from_redis():
    """Pull all win11 process artifacts from Redis."""
    keys = r.keys("win11:processes:*")
    artifacts = []
    for key in sorted(keys):
        raw = r.get(key)
        if raw:
            try:
                data = json.loads(raw)
                artifacts.append({"key": key, "processes": data})
                log({"event": "artifact_loaded", "key": key, "count": len(data)})
            except json.JSONDecodeError:
                log({"event": "artifact_parse_error", "key": key})
    return artifacts

def three_sigma_detection(processes: list) -> list:
    """Flag processes whose PID is a statistical outlier (demo anomaly signal)."""
    pids = [p.get("ProcessId", 0) for p in processes]
    if len(pids) < 3:
        return []
    mean = np.mean(pids)
    std = np.std(pids)
    if std == 0:
        return []
    flagged = [
        p for p in processes
        if abs(p.get("ProcessId", 0) - mean) > 3 * std
    ]
    return flagged

def detect_parent_anomalies(processes: list) -> list:
    """Flag processes with suspicious parent relationships."""
    pid_map = {p["ProcessId"]: p["Name"] for p in processes}
    anomalies = []
    suspicious_parents = {
        "powershell.exe": ["explorer.exe", "cmd.exe"],
        "cmd.exe": ["explorer.exe"],
        "wscript.exe": ["explorer.exe", "winword.exe"],
        "mshta.exe": ["explorer.exe"],
    }
    for proc in processes:
        name = proc.get("Name", "").lower()
        ppid = proc.get("ParentProcessId")
        parent_name = pid_map.get(ppid, "unknown").lower()
        if name in suspicious_parents:
            if parent_name not in [p.lower() for p in suspicious_parents[name]]:
                anomalies.append({
                    "process": proc,
                    "reason": f"{name} spawned by {parent_name} (expected: {suspicious_parents[name]})"
                })
    return anomalies

def detect_missing_paths(processes: list) -> list:
    """Flag svchost and other system processes with null ExecutablePath."""
    flagged = []
    watch_list = ["svchost.exe", "lsass.exe", "services.exe"]
    for proc in processes:
        if proc.get("Name", "").lower() in watch_list:
            if not proc.get("ExecutablePath"):
                flagged.append({
                    "process": proc,
                    "reason": f"{proc['Name']} has null ExecutablePath (masquerading indicator)"
                })
    return flagged

def analyze_with_llm(anomalies: dict, iteration: int) -> str:
    """Send anomalies to Claude for triage analysis."""
    prompt = f"""You are a senior forensic analyst performing incident response triage.

Iteration: {iteration} of {MAX_ITERATIONS}

The following anomalies were detected in a Windows 11 process snapshot:

PARENT ANOMALIES:
{json.dumps(anomalies.get('parent_anomalies', []), indent=2)}

MISSING PATH INDICATORS:
{json.dumps(anomalies.get('missing_paths', []), indent=2)}

THREE-SIGMA PID OUTLIERS:
{json.dumps(anomalies.get('sigma_outliers', []), indent=2)}

Instructions:
1. Assess each anomaly for malicious intent
2. Assign severity: CRITICAL / HIGH / MEDIUM / LOW
3. Identify any false positives and explain why
4. If this is iteration > 1, re-evaluate your previous assessment
5. Produce a structured triage report

Respond in this format:
FINDINGS: <list each anomaly with severity>
FALSE_POSITIVES: <list any false positives with reasoning>
VERDICT: <overall assessment>
CONFIDENCE: <HIGH/MEDIUM/LOW>
NEXT_STEPS: <recommended IR actions>
"""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text

def run_analysis():
    """Main analysis loop with self-correction."""
    print("[*] ZeroSpoil LLM Analyst starting...")
    log({"event": "analysis_start"})

    artifacts = load_artifacts_from_redis()
    if not artifacts:
        print("[-] No artifacts found in Redis")
        log({"event": "no_artifacts"})
        return

    all_processes = []
    for artifact in artifacts:
        all_processes.extend(artifact["processes"])

    print(f"[+] Loaded {len(all_processes)} processes from Redis")

    anomalies = {
        "parent_anomalies": detect_parent_anomalies(all_processes),
        "missing_paths": detect_missing_paths(all_processes),
        "sigma_outliers": three_sigma_detection(all_processes)
    }

    log({
        "event": "anomalies_detected",
        "parent_anomalies": len(anomalies["parent_anomalies"]),
        "missing_paths": len(anomalies["missing_paths"]),
        "sigma_outliers": len(anomalies["sigma_outliers"])
    })

    last_report = None
    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"[*] LLM analysis iteration {iteration}/{MAX_ITERATIONS}")
        log({"event": "llm_iteration_start", "iteration": iteration})

        report = analyze_with_llm(anomalies, iteration)
        log({"event": "llm_iteration_complete", "iteration": iteration, "report": report})

        if last_report and "CONFIDENCE: HIGH" in report:
            print(f"[+] High confidence reached at iteration {iteration}, stopping")
            break
        last_report = report

    os.makedirs("logs", exist_ok=True)
    report_path = f"logs/triage_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_path, "w") as f:
        f.write(f"# ZeroSpoil Triage Report\n\n")
        f.write(f"Generated: {datetime.datetime.now().isoformat()}\n\n")
        f.write(f"## Final Analysis\n\n{last_report}\n")

    print(f"[+] Report written: {report_path}")
    log({"event": "analysis_complete", "report_path": report_path})

if __name__ == "__main__":
    run_analysis()
