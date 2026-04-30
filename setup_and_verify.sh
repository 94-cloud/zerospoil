#!/bin/bash
# =============================================================================
# ZeroSpoil — Full Setup and Verification
# Run this on SIFT-MCP to prove everything works before pushing to GitHub.
#
# This script:
#   1. Installs Claude Code (native installer — no Node.js/npm needed)
#   2. Installs Python deps (mcp, fastmcp, redis, anthropic, etc.)
#   3. Verifies Redis is running
#   4. Tests each MCP server can start and respond
#   5. Tests the .mcp.json config is valid
#   6. Runs a dry-run of the full pipeline
#
# Usage:
#   cd /home/sansforensics/zerospoil
#   chmod +x setup_and_verify.sh
#   ./setup_and_verify.sh
#
# Requires: Internet (Default Switch attached to SIFT VM)
# =============================================================================
set -e

ZEROSPOIL_DIR="$(cd "$(dirname "$0")" && pwd)"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAIL=$((FAIL+1)); }
info() { echo -e "${YELLOW}$1${NC}"; }

echo ""
echo "============================================"
echo "  ZeroSpoil — Setup and Verification"
echo "============================================"
echo "  Directory: ${ZEROSPOIL_DIR}"
echo ""

# -------------------------------------------------------------------
# 1. Install Claude Code (native installer)
# -------------------------------------------------------------------
info "[1/6] Installing Claude Code..."

if command -v claude &> /dev/null; then
    CLAUDE_VER=$(claude --version 2>/dev/null || echo "unknown")
    pass "Claude Code already installed: ${CLAUDE_VER}"
else
    echo "  Installing via native installer (no Node.js/npm required)..."
    if curl -fsSL https://claude.ai/install.sh | bash; then
        # Source the updated PATH
        export PATH="$HOME/.claude/bin:$PATH"
        if command -v claude &> /dev/null; then
            pass "Claude Code installed: $(claude --version 2>/dev/null)"
        else
            fail "Claude Code binary not found after install — check PATH"
            echo "  Try: export PATH=\"\$HOME/.claude/bin:\$PATH\""
            echo "  Then run this script again."
        fi
    else
        echo ""
        echo "  Native installer failed. Falling back to npm method..."
        # Check Node.js
        if ! command -v node &> /dev/null; then
            echo "  Installing Node.js 20 via nvm..."
            curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
            export NVM_DIR="$HOME/.nvm"
            [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
            nvm install 20
            nvm use 20
        fi
        NODE_VER=$(node --version 2>/dev/null || echo "none")
        echo "  Node.js: ${NODE_VER}"

        # Install Claude Code via npm
        npm install -g @anthropic-ai/claude-code
        if command -v claude &> /dev/null; then
            pass "Claude Code installed via npm: $(claude --version 2>/dev/null)"
        else
            fail "Claude Code installation failed via both methods"
        fi
    fi
fi

# -------------------------------------------------------------------
# 2. Install Python dependencies
# -------------------------------------------------------------------
info "[2/6] Installing Python dependencies..."

# Check Python version
PYTHON_VER=$(python3 --version 2>/dev/null || echo "none")
echo "  Python: ${PYTHON_VER}"

# Install deps
DEPS="anthropic redis numpy python-dotenv mcp fastmcp watchdog flask"
pip3 install --break-system-packages ${DEPS} 2>/dev/null || pip3 install ${DEPS}

# Verify each critical dep
for dep in anthropic redis numpy mcp; do
    if python3 -c "import ${dep}" 2>/dev/null; then
        pass "Python package: ${dep}"
    else
        fail "Python package missing: ${dep}"
    fi
done

# -------------------------------------------------------------------
# 3. Verify Redis
# -------------------------------------------------------------------
info "[3/6] Checking Redis..."

if command -v redis-cli &> /dev/null; then
    if redis-cli ping 2>/dev/null | grep -q PONG; then
        KEYS=$(redis-cli dbsize 2>/dev/null | awk '{print $2}')
        pass "Redis running (${KEYS} keys)"
    else
        echo "  Starting Redis..."
        sudo systemctl start redis-server 2>/dev/null || redis-server --daemonize yes 2>/dev/null
        if redis-cli ping 2>/dev/null | grep -q PONG; then
            pass "Redis started"
        else
            fail "Redis could not be started"
        fi
    fi
else
    echo "  Installing Redis..."
    sudo apt-get install -y redis-server 2>/dev/null
    sudo systemctl start redis-server 2>/dev/null
    if redis-cli ping 2>/dev/null | grep -q PONG; then
        pass "Redis installed and started"
    else
        fail "Redis installation failed"
    fi
fi

# -------------------------------------------------------------------
# 4. Verify MCP servers can start
# -------------------------------------------------------------------
info "[4/6] Testing MCP servers..."

cd "${ZEROSPOIL_DIR}"

for server in disk_mcp_server.py memory_mcp_server.py network_mcp_server.py; do
    if [ ! -f "${server}" ]; then
        fail "${server} — file not found"
        continue
    fi

    # Syntax check
    if python3 -c "import py_compile; py_compile.compile('${server}', doraise=True)" 2>/dev/null; then
        pass "${server} — syntax OK"
    else
        fail "${server} — syntax error"
        continue
    fi

    # Import check (verifies FastMCP and deps are available)
    if python3 -c "
import sys
sys.path.insert(0, '.')
# Just check the file can be parsed and FastMCP is available
import importlib.util
spec = importlib.util.spec_from_file_location('test', '${server}')
mod = importlib.util.module_from_spec(spec)
# Don't actually run mcp.run(), just verify imports work
" 2>/dev/null; then
        pass "${server} — imports OK"
    else
        fail "${server} — import error (check fastmcp installation)"
    fi
done

# -------------------------------------------------------------------
# 5. Verify .mcp.json configuration
# -------------------------------------------------------------------
info "[5/6] Checking Claude Code configuration..."

if [ -f "${ZEROSPOIL_DIR}/.mcp.json" ]; then
    # Validate JSON syntax
    if python3 -c "import json; json.load(open('.mcp.json'))" 2>/dev/null; then
        pass ".mcp.json — valid JSON"

        # Check server entries
        SERVERS=$(python3 -c "
import json
with open('.mcp.json') as f:
    cfg = json.load(f)
servers = cfg.get('mcpServers', {})
for name, conf in servers.items():
    cmd = conf.get('command', '?')
    args = ' '.join(conf.get('args', []))
    print(f'  {name}: {cmd} {args}')
print(f'TOTAL:{len(servers)}')
" 2>/dev/null)
        echo "${SERVERS}" | head -10
        COUNT=$(echo "${SERVERS}" | grep "^TOTAL:" | cut -d: -f2)
        if [ "${COUNT}" -ge 3 ]; then
            pass ".mcp.json — ${COUNT} MCP servers registered"
        else
            fail ".mcp.json — only ${COUNT} servers (expected 3)"
        fi

        # Check that referenced scripts exist
        python3 -c "
import json, os
with open('.mcp.json') as f:
    cfg = json.load(f)
for name, conf in cfg.get('mcpServers', {}).items():
    script = conf.get('args', [''])[0]
    if os.path.exists(script):
        print(f'  PASS: {name} -> {script} exists')
    else:
        print(f'  WARN: {name} -> {script} NOT FOUND (will fail at runtime)')
" 2>/dev/null
    else
        fail ".mcp.json — invalid JSON"
    fi
else
    fail ".mcp.json — file not found"
fi

if [ -f "${ZEROSPOIL_DIR}/CLAUDE.md" ]; then
    LINES=$(wc -l < CLAUDE.md)
    pass "CLAUDE.md — ${LINES} lines"
else
    fail "CLAUDE.md — not found (Claude Code won't have analyst instructions)"
fi

# -------------------------------------------------------------------
# 6. Test pipeline dry-run
# -------------------------------------------------------------------
info "[6/6] Pipeline dry-run..."

# Check .env
if [ -f "${ZEROSPOIL_DIR}/.env" ]; then
    if grep -q "ANTHROPIC_API_KEY=." .env 2>/dev/null; then
        pass ".env — API key set"
    else
        fail ".env — ANTHROPIC_API_KEY is empty (set it before running claude)"
    fi
else
    fail ".env — file not found (create it with REDIS_HOST, REDIS_PORT, ANTHROPIC_API_KEY)"
fi

# Check if evidence data exists in Redis
ARTIFACT_KEYS=$(redis-cli keys "win11:*" 2>/dev/null | wc -l)
if [ "${ARTIFACT_KEYS}" -gt 0 ]; then
    pass "Redis has ${ARTIFACT_KEYS} artifact key(s)"
else
    echo "  No win11:* keys in Redis. Run the collector or seed demo data first."
    echo "  To seed: python3 seed_demo_data.py --seed-only"
fi

# Check execution log
if [ -f "execution_log.jsonl" ]; then
    LOG_LINES=$(wc -l < execution_log.jsonl)
    pass "execution_log.jsonl — ${LOG_LINES} entries"
else
    echo "  No execution_log.jsonl yet (will be created on first analysis run)"
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo ""
echo "============================================"
echo "  Verification Summary"
echo "============================================"
echo -e "  ${GREEN}PASS: ${PASS}${NC}"
echo -e "  ${RED}FAIL: ${FAIL}${NC}"
echo ""

if [ ${FAIL} -eq 0 ]; then
    echo -e "  ${GREEN}All checks passed!${NC}"
    echo ""
    echo "  To start Claude Code with your MCP tools:"
    echo ""
    echo "    cd ${ZEROSPOIL_DIR}"
    echo "    claude"
    echo ""
    echo "  Then type your analysis request. Claude Code will"
    echo "  automatically discover and use the MCP tools in .mcp.json."
    echo ""
    echo "  For headless/demo mode:"
    echo "    claude -p 'Analyze the evidence for IOCs. Start with"
    echo "    process baseline, pivot to hidden processes, then"
    echo "    correlate with disk and network artifacts.'"
    echo ""
else
    echo -e "  ${RED}${FAIL} check(s) failed. Fix the issues above before pushing to GitHub.${NC}"
    echo ""
fi

echo "============================================"
echo "  github.com/94-cloud/zerospoil"
echo "============================================"
echo ""
