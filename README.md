# ZeroSpoil

**Autonomous forensic incident response with a zero-spoliation guarantee.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hackathon: SANS Find Evil](https://img.shields.io/badge/SANS-Find%20Evil%202026-blue)](https://findevil.devpost.com)

> Autonomous triage via MCP-isolated forensic tools. Three-sigma anomaly detection, self-correction loop, full audit trail. Zero spoliation by design — the LLM cannot touch evidence.

## Architecture: Pattern 3 — Isolated MCP Servers
**The LLM has no write access to evidence. Spoliation is impossible by construction.**

## Quick Start

```bash
git clone https://github.com/94-cloud/zerospoil
cd zerospoil
pip install -r requirements.txt
cp .env.example .env  # Add your ANTHROPIC_API_KEY
redis-server &
python artifact_ingestor.py
python llm_analyst.py --offline
```

## MCP Servers

| Server | Tools | Underlying Tool |
|---|---|---|
| disk_mcp_server.py | get_mft_summary, inspect_mft_entry | TSK (fls, istat) |
| memory_mcp_server.py | list_active_processes, find_hidden_processes | Volatility3 |
| network_mcp_server.py | get_connection_summary, search_dns_queries | TShark |

## Built With

Python · FastMCP · Redis · Volatility3 · The Sleuth Kit · TShark · Claude API · Hyper-V · SIFT Workstation

## License

MIT — see [LICENSE](LICENSE)
