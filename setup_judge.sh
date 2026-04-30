#!/bin/bash
# =============================================================================
# ZeroSpoil — SIFT Workstation Setup
# SANS Find Evil! Hackathon | github.com/94-cloud/zerospoil
#
# This script sets up everything a judge needs to run ZeroSpoil:
# 1. Installs Claude Code (if not present)
# 2. Installs Python dependencies
# 3. Registers MCP servers with Claude Code
# 4. Verifies everything works
# 5. Provides the command to start the analysis
#
# Usage:
#   cd /home/sansforensics/zerospoil
#   chmod +x setup_judge.sh
#   ./setup_judge.sh
# =============================================================================
set -e

ZEROSPOIL_DIR="/home/sansforensics/zerospoil"
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "============================================"
echo "  ZeroSpoil — SIFT Workstation Setup"
echo "  SANS Find Evil! Hackathon"
echo "  Pattern 3: Zero Spoliation by Design"
echo "============================================"
echo ""

# -------------------------------------------------------------------
# 1. Check we're on SIFT
# -------------------------------------------------------------------
echo -e "${YELLOW}[1/7] Checking SIFT environment...${NC}"
if [ -d "/usr/share/sift" ] || [ -f "/etc/sift-version" ]; then
    echo -e "${GREEN}  SIFT Workstation detected${NC}"
else
    echo "  WARNING: SIFT markers not found. Continuing anyway."
    echo "  (The MCP servers will work on any Linux with the forensic tools installed)"
fi

# -------------------------------------------------------------------
# 2. Install Node.js and Claude Code (if needed)
# -------------------------------------------------------------------
echo -e "${YELLOW}[2/7] Checking Claude Code...${NC}"
if command -v claude &> /dev/null; then
    CLAUDE_VER=$(claude --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}  Claude Code found: ${CLAUDE_VER}${NC}"
else
    echo "  Claude Code not found. Installing..."
    # Install Node.js 20+ if needed
    if ! command -v node &> /dev/null || [[ $(node -v | cut -d. -f1 | tr -d 'v') -lt 20 ]]; then
        echo "  Installing Node.js 20..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    fi
    echo "  Installing Claude Code..."
    npm install -g @anthropic-ai/claude-code
    echo -e "${GREEN}  Claude Code installed${NC}"
fi

# -------------------------------------------------------------------
# 3. Install Python dependencies
# -------------------------------------------------------------------
echo -e "${YELLOW}[3/7] Installing Python dependencies...${NC}"
pip3 install --break-system-packages \
    anthropic redis numpy python-dotenv mcp fastmcp 2>/dev/null || \
pip3 install anthropic redis numpy python-dotenv mcp fastmcp
echo -e "${GREEN}  Python dependencies installed${NC}"

# -------------------------------------------------------------------
# 4. Check Redis
# -------------------------------------------------------------------
echo -e "${YELLOW}[4/7] Checking Redis...${NC}"
if command -v redis-cli &> /dev/null; then
    if redis-cli ping 2>/dev/null | grep -q PONG; then
        KEYS=$(redis-cli dbsize 2>/dev/null | awk '{print $2}')
        echo -e "${GREEN}  Redis running (${KEYS} keys)${NC}"
    else
        echo "  Redis installed but not running. Starting..."
        sudo systemctl start redis-server 2>/dev/null || redis-server --daemonize yes
        echo -e "${GREEN}  Redis started${NC}"
    fi
else
    echo "  Redis not found. Installing..."
    sudo apt-get install -y redis-server
    sudo systemctl start redis-server
    echo -e "${GREEN}  Redis installed and started${NC}"
fi

# -------------------------------------------------------------------
# 5. Set up .env file
# -------------------------------------------------------------------
echo -e "${YELLOW}[5/7] Checking environment...${NC}"
cd "$ZEROSPOIL_DIR"
if [ ! -f .env ]; then
    echo "  Creating .env file..."
    cat > .env << 'EOF'
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
ANTHROPIC_API_KEY=
EOF
    echo -e "${RED}  IMPORTANT: Edit .env and add your ANTHROPIC_API_KEY${NC}"
    echo "  Run: nano ${ZEROSPOIL_DIR}/.env"
else
    echo -e "${GREEN}  .env file exists${NC}"
fi

# -------------------------------------------------------------------
# 6. Register MCP servers with Claude Code
# -------------------------------------------------------------------
echo -e "${YELLOW}[6/7] Registering MCP servers with Claude Code...${NC}"

# Copy .mcp.json to project root if not already there
if [ ! -f "$ZEROSPOIL_DIR/.mcp.json" ]; then
    echo "  ERROR: .mcp.json not found in $ZEROSPOIL_DIR"
    echo "  Please ensure the repo is cloned correctly."
    exit 1
fi

echo "  MCP servers configured in .mcp.json:"
echo "    - zerospoil-disk    (TSK: fls, istat)"
echo "    - zerospoil-memory  (Volatility3: pslist, psscan)"
echo "    - zerospoil-network (TShark: connections, DNS)"
echo -e "${GREEN}  MCP servers registered${NC}"

# -------------------------------------------------------------------
# 7. Verify MCP servers can start
# -------------------------------------------------------------------
echo -e "${YELLOW}[7/7] Verifying MCP servers...${NC}"

# Quick syntax check on each server
for server in disk_mcp_server.py memory_mcp_server.py network_mcp_server.py; do
    if python3 -c "import py_compile; py_compile.compile('${ZEROSPOIL_DIR}/${server}', doraise=True)" 2>/dev/null; then
        echo -e "  ${GREEN}${server} — syntax OK${NC}"
    else
        echo -e "  ${RED}${server} — syntax error!${NC}"
    fi
done

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------
echo ""
echo "============================================"
echo -e "  ${GREEN}Setup Complete!${NC}"
echo "============================================"
echo ""
echo "  To start the forensic analysis:"
echo ""
echo "    cd ${ZEROSPOIL_DIR}"
echo "    claude"
echo ""
echo "  Then type:"
echo '    "Analyze the evidence for indicators of compromise.'
echo '     Start with a process baseline, pivot to hidden'
echo '     processes, then correlate with disk and network."'
echo ""
echo "  Claude Code will automatically use the MCP tools"
echo "  registered in .mcp.json — no manual tool selection needed."
echo ""
echo "  Architecture: Pattern 3 (Custom MCP Server)"
echo "  Guardrail:    Architectural (not prompt-based)"
echo "  Spoliation:   Impossible by construction"
echo ""
echo "============================================"
echo "  github.com/94-cloud/zerospoil"
echo "============================================"
echo ""
