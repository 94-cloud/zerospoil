import redis, json, time
from pathlib import Path

WATCH_DIR = Path("/home/sansforensics/artifacts")
r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
seen = set()
print("[+] Ingestor watching", WATCH_DIR)
while True:
    for f in WATCH_DIR.glob("*.json"):
        if f not in seen:
            seen.add(f)
            try:
                parts = f.stem.split("_", 1)
                artifact_type = parts[0]
                timestamp = parts[1] if len(parts) > 1 and parts[1] else "unknown"
                data = json.loads(f.read_text(encoding="utf-8-sig"))
                key = f"win11:{artifact_type}:{timestamp}"
                r.set(key, json.dumps(data))
                r.lpush("win11:artifact_queue", key)
                print(f"[+] Ingested -> {key}")
            except Exception as e:
                print(f"[!] Error {f.name}: {e}")
    time.sleep(5)
