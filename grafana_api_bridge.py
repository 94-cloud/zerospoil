"""
ZeroSpoil Grafana API Bridge
Reads forensic data from Redis and serves as JSON for Grafana.
Run alongside Grafana on the SIFT VM.

Usage:
    python3 grafana_api_bridge.py              # Start on port 5000
    python3 grafana_api_bridge.py &            # Background

Grafana JSON API datasource URL: http://localhost:5000
"""
import json
import time
import os
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request

import redis

app = Flask(__name__)

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_timeout=5)


def get_alerts(count=100):
    """Read alerts from zerospoil:alerts sorted set, newest first."""
    raw = r.zrevrange("zerospoil:alerts", 0, count - 1, withscores=True)
    alerts = []
    for alert_json, score in raw:
        try:
            alert = json.loads(alert_json)
            alert["_score"] = score
            alerts.append(alert)
        except json.JSONDecodeError:
            continue
    return alerts


# -- Grafana health check --
@app.route("/", methods=["GET"])
def health():
    try:
        r.ping()
        alert_count = r.zcard("zerospoil:alerts") or 0
        return jsonify({"status": "ok", "redis": "connected", "alerts": alert_count}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500


# -- Alert endpoints --
@app.route("/alerts", methods=["GET"])
def alerts_all():
    return jsonify(get_alerts(request.args.get("count", 100, type=int)))


@app.route("/alerts/recent", methods=["GET"])
def alerts_recent():
    return jsonify(get_alerts(request.args.get("count", 20, type=int)))


@app.route("/alerts/critical", methods=["GET"])
def alerts_critical():
    return jsonify([a for a in get_alerts(200) if a.get("severity") == "critical"])


@app.route("/alerts/by_source", methods=["GET"])
def alerts_by_source():
    counts = {}
    for a in get_alerts(500):
        src = a.get("source", "unknown")
        counts[src] = counts.get(src, 0) + 1
    return jsonify([{"source": k, "count": v} for k, v in counts.items()])


@app.route("/alerts/by_severity", methods=["GET"])
def alerts_by_severity():
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in get_alerts(500):
        sev = a.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return jsonify(counts)


# -- LLM findings --
@app.route("/findings", methods=["GET"])
def findings():
    raw = r.get("zerospoil:findings")
    return jsonify(json.loads(raw)) if raw else jsonify({"findings": []})


@app.route("/kill_chain", methods=["GET"])
def kill_chain():
    raw = r.get("zerospoil:kill_chain")
    return jsonify(json.loads(raw)) if raw else jsonify({"detected": False, "phases": [], "narrative": "No analysis yet"})


# -- System status --
@app.route("/status", methods=["GET"])
def status():
    raw = r.get("zerospoil:status")
    return jsonify(json.loads(raw)) if raw else jsonify({"phase": "idle"})


@app.route("/metrics", methods=["GET"])
def metrics():
    raw = r.get("zerospoil:metrics")
    return jsonify(json.loads(raw)) if raw else jsonify({})


@app.route("/heartbeat", methods=["GET"])
def heartbeat():
    hb = r.hgetall("zerospoil:heartbeat")
    servers = []
    now = datetime.now(timezone.utc)
    for server, last_seen in hb.items():
        try:
            ts = datetime.fromisoformat(last_seen)
            age = (now - ts).total_seconds()
            online = age < 120
        except Exception:
            age = -1
            online = False
        servers.append({"server": server, "last_seen": last_seen, "age_seconds": round(age, 1), "online": online})
    return jsonify(servers)


# -- Evidence summary (reads actual win11:* keys) --
@app.route("/evidence", methods=["GET"])
def evidence():
    """Summary of all evidence stored in Redis."""
    keys = list(r.scan_iter("win11:*"))
    summary = {"total_keys": len(keys), "keys": []}
    for key in sorted(keys):
        key_type = r.type(key)
        if key_type == "string":
            val = r.get(key)
            try:
                parsed = json.loads(val)
                if isinstance(parsed, list):
                    summary["keys"].append({"key": key, "type": "list", "count": len(parsed)})
                else:
                    summary["keys"].append({"key": key, "type": "object"})
            except Exception:
                summary["keys"].append({"key": key, "type": "string", "length": len(val) if val else 0})
        elif key_type == "list":
            summary["keys"].append({"key": key, "type": "list", "count": r.llen(key)})
    return jsonify(summary)


# -- Timeline for graph panels --
@app.route("/timeline", methods=["GET"])
def timeline():
    minutes = request.args.get("minutes", 60, type=int)
    now = time.time()
    start = now - (minutes * 60)
    raw = r.zrangebyscore("zerospoil:alerts", start, now, withscores=True)
    buckets = {}
    for alert_json, score in raw:
        bucket = int(score // 60) * 60
        try:
            sev = json.loads(alert_json).get("severity", "info")
        except Exception:
            sev = "info"
        if bucket not in buckets:
            buckets[bucket] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        buckets[bucket][sev] = buckets[bucket].get(sev, 0) + 1
        buckets[bucket]["total"] += 1
    series = []
    for ts in sorted(buckets.keys()):
        entry = {"timestamp": ts * 1000, "time": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()}
        entry.update(buckets[ts])
        series.append(entry)
    return jsonify(series)


# -- Annotations --
@app.route("/annotations", methods=["GET", "POST"])
def annotations():
    result = []
    for alert in get_alerts(100):
        if alert.get("severity") in ("critical", "high"):
            ts = alert.get("timestamp", "")
            try:
                epoch_ms = int(datetime.fromisoformat(ts).timestamp() * 1000)
            except Exception:
                epoch_ms = int(alert.get("_score", time.time()) * 1000)
            result.append({"time": epoch_ms, "title": alert.get("title", ""), "text": alert.get("detail", ""), "tags": [alert.get("severity", ""), alert.get("source", "")]})
    return jsonify(result)


if __name__ == "__main__":
    print(f"ZeroSpoil API Bridge starting on :5000")
    print(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    app.run(host="0.0.0.0", port=5000, debug=False)
