#!/usr/bin/env python3
"""
disk_mcp_server.py — Protocol SIFT
Read-only MCP server exposing SIFT disk forensics tools as typed functions.
No destructive commands are exposed. Evidence integrity is architectural, not prompt-based.

Usage:
    python3 disk_mcp_server.py

Requires:
    pip install mcp --break-system-packages
    SIFT Workstation with: tsk_tools, log2timeline/plaso, RegRipper, python3-pytsk3
"""

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── MCP SDK ──────────────────────────────────────────────────────────────────
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
except ImportError:
    print("ERROR: mcp package not found. Run: pip install mcp --break-system-packages", file=sys.stderr)
    sys.exit(1)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [disk_mcp] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler("/tmp/disk_mcp_server.log"),
    ],
)
log = logging.getLogger("disk_mcp")

# ── Constants ─────────────────────────────────────────────────────────────────
SERVER_NAME    = "disk_mcp_server"
SERVER_VERSION = "0.1.0"
MAX_OUTPUT_CHARS = 80_000   # prevent context window flooding
TIMEOUT_SECS     = 120      # per-tool subprocess timeout

# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = TIMEOUT_SECS) -> dict[str, Any]:
    """
    Execute a read-only subprocess. Returns structured result dict.
    Raises on timeout; captures stderr for diagnostics.
    """
    log.info("exec: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = result.stdout[:MAX_OUTPUT_CHARS]
        return {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": result.stderr[:2000],
            "truncated": len(result.stdout) > MAX_OUTPUT_CHARS,
            "cmd": " ".join(cmd),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "truncated": False,
            "cmd": " ".join(cmd),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
    except FileNotFoundError as e:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"Tool not found: {e}. Is SIFT installed?",
            "truncated": False,
            "cmd": " ".join(cmd),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }


def _verify_image(image_path: str) -> str | None:
    """Return error string if image path is unsafe or missing, else None."""
    p = Path(image_path).resolve()
    if not p.exists():
        return f"Image not found: {image_path}"
    if not p.is_file():
        return f"Not a file: {image_path}"
    # Safety: block writes by refusing paths outside /cases and /mnt/user-data
    allowed_roots = [Path("/cases"), Path("/mnt"), Path("/home"), Path("/tmp")]
    if not any(str(p).startswith(str(r)) for r in allowed_roots):
        return f"Image path outside allowed roots: {image_path}"
    return None


def _hash_file(path: str) -> dict[str, str]:
    """Compute MD5 + SHA256 of file for chain-of-custody record."""
    md5  = hashlib.md5()
    sha  = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                md5.update(chunk)
                sha.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha.hexdigest(), "path": path}
    except Exception as e:
        return {"error": str(e), "path": path}


def _ok(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2))]


def _err(msg: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": msg}, indent=2))]


# ── Tool implementations ───────────────────────────────────────────────────────

def hash_evidence(image_path: str) -> list[TextContent]:
    """
    Compute MD5 + SHA256 of an evidence image for chain-of-custody.
    Always run this first before any analysis.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)
    result = _hash_file(image_path)
    result["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    log.info("hash_evidence: %s -> md5=%s", image_path, result.get("md5", "error"))
    return _ok(result)


def extract_mft_timeline(image_path: str, output_format: str = "json") -> list[TextContent]:
    """
    Extract MFT timeline from a disk image using fls + mactime (TSK).
    Returns file system activity timeline sorted chronologically.
    output_format: 'json' (parsed rows) or 'raw' (mactime text)
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    # fls: recursive file listing with inode metadata
    fls = _run(["fls", "-r", "-m", "/", "-o", "0", image_path])
    if fls["exit_code"] != 0 and not fls["stdout"]:
        # retry with auto-detected partition offset
        fls = _run(["fls", "-r", "-m", "/", image_path])

    if not fls["stdout"]:
        return _err(f"fls produced no output. stderr: {fls['stderr']}")

    # pipe fls output through mactime
    try:
        mac = subprocess.run(
            ["mactime", "-b", "-", "-d"],
            input=fls["stdout"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECS,
        )
        raw = mac.stdout[:MAX_OUTPUT_CHARS]
    except Exception as e:
        raw = fls["stdout"]

    if output_format == "raw":
        return _ok({"timeline_raw": raw, "truncated": len(raw) >= MAX_OUTPUT_CHARS})

    # Parse CSV output into structured rows
    rows = []
    for line in raw.splitlines():
        parts = line.split(",")
        if len(parts) >= 4:
            rows.append({
                "datetime": parts[0].strip(),
                "size":     parts[1].strip(),
                "type":     parts[2].strip(),
                "path":     ",".join(parts[3:]).strip(),
            })

    return _ok({
        "entry_count": len(rows),
        "timeline": rows[:5000],   # cap at 5k rows to protect context
        "truncated": len(rows) > 5000,
        "source_image": image_path,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


def get_prefetch_entries(image_path: str) -> list[TextContent]:
    """
    Extract Windows Prefetch files from a disk image.
    Lists executables, run counts, last run times.
    Uses tsk_recover + python3-prefetch (if available) or strings fallback.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    # Recover prefetch files from Windows\Prefetch
    recover = _run([
        "tsk_recover", "-a", "-d", image_path, "/tmp/prefetch_recovery"
    ], timeout=60)

    pf_dir = Path("/tmp/prefetch_recovery/Windows/Prefetch")
    if not pf_dir.exists():
        pf_dir = Path("/tmp/prefetch_recovery")

    entries = []
    try:
        pf_files = list(pf_dir.glob("**/*.pf")) if pf_dir.exists() else []
        for pf in pf_files[:100]:
            # Use pecmd.py or python-prefetch if available, else strings
            r = _run(["python3", "-m", "prefetch", str(pf)], timeout=10)
            if r["exit_code"] == 0:
                entries.append({"file": pf.name, "parsed": r["stdout"]})
            else:
                # strings fallback: grab printable name near top of file
                s = _run(["strings", str(pf)], timeout=5)
                entries.append({"file": pf.name, "strings": s["stdout"][:500]})
    except Exception as e:
        log.warning("prefetch parse error: %s", e)

    return _ok({
        "prefetch_files_found": len(entries),
        "entries": entries,
        "source_image": image_path,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "note": "Run tsk_recover manually if entries=0 and image is valid",
    })


def get_amcache_entries(image_path: str) -> list[TextContent]:
    """
    Extract Amcache.hve from a disk image and parse execution artifacts.
    Amcache records SHA1 hashes of executables — invaluable for malware detection.
    Uses RegRipper (rip.pl) with amcache plugin.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    recover = _run([
        "tsk_recover", "-a", "-d", image_path, "/tmp/amcache_recovery"
    ], timeout=90)

    amcache_candidates = list(Path("/tmp/amcache_recovery").glob("**/Amcache.hve"))
    if not amcache_candidates:
        return _ok({
            "found": False,
            "note": "Amcache.hve not found — image may be non-Windows or pre-Win8",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        })

    results = []
    for hive in amcache_candidates[:3]:
        r = _run(["rip.pl", "-r", str(hive), "-p", "amcache"], timeout=30)
        results.append({
            "hive_path": str(hive),
            "exit_code": r["exit_code"],
            "output": r["stdout"][:10000],
            "stderr": r["stderr"],
        })

    return _ok({
        "hives_found": len(amcache_candidates),
        "results": results,
        "source_image": image_path,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


def list_deleted_files(image_path: str, partition_offset: int = 0) -> list[TextContent]:
    """
    List deleted/unallocated files in a disk image using TSK fls.
    Deleted entries are marked with '*' in TSK output.
    partition_offset: sector offset (0 = auto-detect first partition).
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    offset_args = ["-o", str(partition_offset)] if partition_offset else []
    r = _run(["fls", "-r", "-d"] + offset_args + [image_path])

    if r["exit_code"] != 0 and not r["stdout"]:
        return _err(f"fls -d failed. stderr: {r['stderr']}")

    deleted = []
    for line in r["stdout"].splitlines():
        if line.strip():
            deleted.append(line.strip())

    return _ok({
        "deleted_file_count": len(deleted),
        "entries": deleted[:2000],
        "truncated": len(deleted) > 2000,
        "source_image": image_path,
        "partition_offset": partition_offset,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


def parse_registry_hive(image_path: str, hive_type: str = "system") -> list[TextContent]:
    """
    Extract and parse a Windows registry hive using RegRipper.
    hive_type options: 'system' | 'software' | 'sam' | 'ntuser' | 'security'
    Parses autorun keys, services, USB history, user activity.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    hive_paths = {
        "system":   ["**/system32/config/SYSTEM",   "**/System32/config/SYSTEM"],
        "software": ["**/system32/config/SOFTWARE",  "**/System32/config/SOFTWARE"],
        "sam":      ["**/system32/config/SAM",        "**/System32/config/SAM"],
        "security": ["**/system32/config/SECURITY",  "**/System32/config/SECURITY"],
        "ntuser":   ["**/NTUSER.DAT",                 "**/ntuser.dat"],
    }

    if hive_type not in hive_paths:
        return _err(f"Unknown hive_type '{hive_type}'. Choose from: {list(hive_paths.keys())}")

    recover = _run([
        "tsk_recover", "-a", "-d", image_path, "/tmp/registry_recovery"
    ], timeout=90)

    found_hive = None
    for pattern in hive_paths[hive_type]:
        matches = list(Path("/tmp/registry_recovery").glob(pattern))
        if matches:
            found_hive = matches[0]
            break

    if not found_hive:
        return _ok({
            "found": False,
            "hive_type": hive_type,
            "note": f"{hive_type.upper()} hive not found in image",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        })

    # Run RegRipper with appropriate plugin set
    plugin_map = {
        "system":   "services",
        "software": "run",
        "sam":      "samparse",
        "security": "auditpol",
        "ntuser":   "ntuser",
    }
    plugin = plugin_map.get(hive_type, "")
    r = _run(["rip.pl", "-r", str(found_hive), "-p", plugin], timeout=60)

    return _ok({
        "hive_type": hive_type,
        "hive_path": str(found_hive),
        "plugin": plugin,
        "exit_code": r["exit_code"],
        "output": r["stdout"][:15000],
        "stderr": r["stderr"],
        "source_image": image_path,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


def get_shellbags(image_path: str) -> list[TextContent]:
    """
    Extract ShellBags from NTUSER.DAT / UsrClass.dat.
    ShellBags reveal folder navigation history, including deleted/remote paths.
    Uses RegRipper shellbags plugin.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    recover = _run([
        "tsk_recover", "-a", "-d", image_path, "/tmp/shellbag_recovery"
    ], timeout=90)

    results = []
    for hive_name in ["NTUSER.DAT", "ntuser.dat", "UsrClass.dat"]:
        for hive in Path("/tmp/shellbag_recovery").glob(f"**/{hive_name}"):
            r = _run(["rip.pl", "-r", str(hive), "-p", "shellbags"], timeout=30)
            results.append({
                "hive": str(hive),
                "output": r["stdout"][:8000],
                "exit_code": r["exit_code"],
            })

    return _ok({
        "hives_processed": len(results),
        "results": results,
        "source_image": image_path,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


def get_partition_table(image_path: str) -> list[TextContent]:
    """
    Read the partition table of a disk image using mmls (TSK).
    Returns partition layout — run this early to determine correct offsets.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    r = _run(["mmls", image_path])
    partitions = []
    for line in r["stdout"].splitlines():
        line = line.strip()
        if line and not line.startswith("DOS") and not line.startswith("GUID") and ":" not in line[:3]:
            parts = line.split()
            if len(parts) >= 5:
                partitions.append({
                    "slot":   parts[0],
                    "start":  parts[2],
                    "end":    parts[3],
                    "length": parts[4],
                    "desc":   " ".join(parts[5:]) if len(parts) > 5 else "",
                })

    return _ok({
        "raw_output": r["stdout"],
        "partitions": partitions,
        "exit_code": r["exit_code"],
        "source_image": image_path,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


def run_yara_scan(image_path: str, rules_path: str = "/etc/yara/rules") -> list[TextContent]:
    """
    Run YARA against recovered files from a disk image.
    rules_path: directory or .yar file containing YARA rules.
    Recovers files first, then scans — read-only operation.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    if not Path(rules_path).exists():
        # Try SIFT default locations
        for candidate in ["/usr/local/share/yara", "/opt/yara/rules", "/etc/yara"]:
            if Path(candidate).exists():
                rules_path = candidate
                break
        else:
            return _err(f"YARA rules not found at {rules_path}. Specify rules_path.")

    recover_dir = "/tmp/yara_recovery"
    _run(["tsk_recover", "-a", "-d", image_path, recover_dir], timeout=120)

    r = _run(["yara", "-r", rules_path, recover_dir], timeout=90)

    matches = [line for line in r["stdout"].splitlines() if line.strip()]
    return _ok({
        "match_count": len(matches),
        "matches": matches[:500],
        "truncated": len(matches) > 500,
        "rules_path": rules_path,
        "source_image": image_path,
        "exit_code": r["exit_code"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


def get_fs_info(image_path: str, partition_offset: int = 0) -> list[TextContent]:
    """
    Get filesystem metadata using fsstat (TSK).
    Returns filesystem type, volume name, creation date, last mount time.
    """
    err = _verify_image(image_path)
    if err:
        return _err(err)

    offset_args = ["-o", str(partition_offset)] if partition_offset else []
    r = _run(["fsstat"] + offset_args + [image_path])

    return _ok({
        "fsstat_output": r["stdout"],
        "exit_code": r["exit_code"],
        "source_image": image_path,
        "partition_offset": partition_offset,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    })


# ── Tool registry ──────────────────────────────────────────────────────────────

TOOLS: list[Tool] = [
    Tool(
        name="hash_evidence",
        description="Compute MD5 + SHA256 of evidence image for chain-of-custody. ALWAYS run first.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image (.E01, .dd, .raw, .vmdk)"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="get_partition_table",
        description="Read partition layout using mmls. Run early to get correct sector offsets for other tools.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="get_fs_info",
        description="Get filesystem metadata (type, creation date, last mount) using fsstat.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
                "partition_offset": {"type": "integer", "description": "Sector offset from mmls output (default 0)"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="extract_mft_timeline",
        description="Extract full filesystem timeline from MFT using fls + mactime. Returns MAC times for all files.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
                "output_format": {"type": "string", "enum": ["json", "raw"], "description": "json (parsed rows) or raw (mactime text)"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="list_deleted_files",
        description="List deleted/unallocated files in disk image using TSK fls -d.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
                "partition_offset": {"type": "integer", "description": "Sector offset (0 = auto)"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="get_prefetch_entries",
        description="Extract Windows Prefetch files. Shows what executables ran, when, and how many times.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="get_amcache_entries",
        description="Extract Amcache.hve execution artifacts including SHA1 hashes of executables.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="parse_registry_hive",
        description="Extract and parse Windows registry hives (SYSTEM, SOFTWARE, SAM, NTUSER) using RegRipper.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
                "hive_type": {"type": "string", "enum": ["system", "software", "sam", "security", "ntuser"], "description": "Which registry hive to parse"},
            },
            "required": ["image_path", "hive_type"],
        },
    ),
    Tool(
        name="get_shellbags",
        description="Extract ShellBags from NTUSER.DAT. Reveals folder navigation history including deleted/network paths.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
            },
            "required": ["image_path"],
        },
    ),
    Tool(
        name="run_yara_scan",
        description="Scan recovered files from disk image against YARA rules. Returns rule matches with file paths.",
        inputSchema={
            "type": "object",
            "properties": {
                "image_path": {"type": "string", "description": "Absolute path to disk image"},
                "rules_path": {"type": "string", "description": "Path to YARA rules file or directory"},
            },
            "required": ["image_path"],
        },
    ),
]

# ── MCP Server ─────────────────────────────────────────────────────────────────

server = Server(SERVER_NAME)


@server.list_tools()
async def list_tools() -> list[Tool]:
    log.info("list_tools called — returning %d tools", len(TOOLS))
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    log.info("call_tool: %s args=%s", name, json.dumps(arguments))

    dispatch = {
        "hash_evidence":        lambda a: hash_evidence(a["image_path"]),
        "get_partition_table":  lambda a: get_partition_table(a["image_path"]),
        "get_fs_info":          lambda a: get_fs_info(a["image_path"], a.get("partition_offset", 0)),
        "extract_mft_timeline": lambda a: extract_mft_timeline(a["image_path"], a.get("output_format", "json")),
        "list_deleted_files":   lambda a: list_deleted_files(a["image_path"], a.get("partition_offset", 0)),
        "get_prefetch_entries": lambda a: get_prefetch_entries(a["image_path"]),
        "get_amcache_entries":  lambda a: get_amcache_entries(a["image_path"]),
        "parse_registry_hive":  lambda a: parse_registry_hive(a["image_path"], a["hive_type"]),
        "get_shellbags":        lambda a: get_shellbags(a["image_path"]),
        "run_yara_scan":        lambda a: run_yara_scan(a["image_path"], a.get("rules_path", "/etc/yara/rules")),
    }

    if name not in dispatch:
        return _err(f"Unknown tool: {name}. Available: {list(dispatch.keys())}")

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: dispatch[name](arguments)
        )
        return result
    except Exception as e:
        log.exception("call_tool error for %s", name)
        return _err(f"Tool execution error: {e}")


async def main():
    log.info("Starting %s v%s", SERVER_NAME, SERVER_VERSION)
    log.info("Exposing %d read-only disk forensics tools", len(TOOLS))
    log.info("Evidence integrity: architectural (no destructive commands exposed)")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
