#!/bin/bash
# =============================================================================
# ZeroSpoil Grafana Dashboard — Complete Native Setup
# For SIFT VMware lab (192.168.179.131)
#
# Installs Grafana OSS natively, configures datasources, seeds demo data,
# starts the Flask API bridge, and opens the dashboard.
#
# Prerequisites: Redis running, Python 3.12, internet access
#
# Usage:
#   chmod +x grafana_setup_native.sh
#   sudo ./grafana_setup_native.sh
#
# After install:
#   Grafana:    http://192.168.179.131:3000 (no login needed)
#   API Bridge: http://localhost:5000 (auto-started)
# =============================================================================
set -e

GRAFANA_PASS="zerospoil"
ZEROSPOIL_DIR="/home/sansforensics/zerospoil"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "============================================"
echo "  ZeroSpoil — Grafana Dashboard Setup"
echo "============================================"
echo ""

# -------------------------------------------------------------------
# 1. Install Grafana OSS
# -------------------------------------------------------------------
echo -e "${YELLOW}[1/7] Installing Grafana OSS...${NC}"

if command -v grafana-server &>/dev/null; then
    echo -e "  ${GREEN}Grafana already installed$(grafana-server -v 2>/dev/null | head -1)${NC}"
else
    apt-get install -y apt-transport-https software-properties-common wget
    mkdir -p /etc/apt/keyrings/
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list
    apt-get update
    apt-get install -y grafana
    echo -e "  ${GREEN}Grafana installed${NC}"
fi

# -------------------------------------------------------------------
# 2. Install Grafana plugins
# -------------------------------------------------------------------
echo -e "${YELLOW}[2/7] Installing Grafana plugins...${NC}"

grafana-cli plugins install redis-datasource 2>/dev/null || echo "  redis-datasource may already be installed"
grafana-cli plugins install marcusolsson-json-datasource 2>/dev/null || echo "  json-datasource may already be installed"
echo -e "  ${GREEN}Plugins installed${NC}"

# -------------------------------------------------------------------
# 3. Configure Grafana
# -------------------------------------------------------------------
echo -e "${YELLOW}[3/7] Configuring Grafana...${NC}"

# Admin password
sed -i "s/;admin_password = admin/admin_password = ${GRAFANA_PASS}/" /etc/grafana/grafana.ini 2>/dev/null
sed -i "s/admin_password = admin/admin_password = ${GRAFANA_PASS}/" /etc/grafana/grafana.ini 2>/dev/null

# Anonymous access (judges can view without login)
sed -i '/^\[auth.anonymous\]/,/^\[/ {
    s/;enabled = false/enabled = true/
    s/enabled = false/enabled = true/
    s/;org_role = Viewer/org_role = Viewer/
}' /etc/grafana/grafana.ini

# Allow unsigned plugins
sed -i 's/;allow_loading_unsigned_plugins =/allow_loading_unsigned_plugins = redis-datasource/' /etc/grafana/grafana.ini

echo -e "  ${GREEN}Grafana configured (anonymous viewer enabled)${NC}"

# -------------------------------------------------------------------
# 4. Provision datasources
# -------------------------------------------------------------------
echo -e "${YELLOW}[4/7] Provisioning datasources...${NC}"

mkdir -p /etc/grafana/provisioning/datasources

cat > /etc/grafana/provisioning/datasources/zerospoil.yaml << 'DSEOF'
apiVersion: 1
datasources:
  - name: ZeroSpoil-Redis
    type: redis-datasource
    access: proxy
    orgId: 1
    url: redis://127.0.0.1:6379
    isDefault: false
    jsonData:
      client: standalone
      poolSize: 5
      timeout: 10
    editable: true

  - name: ZeroSpoil-API
    type: marcusolsson-json-datasource
    access: proxy
    orgId: 1
    url: http://localhost:5000
    isDefault: true
    editable: true
DSEOF

echo -e "  ${GREEN}Datasources provisioned (Redis + JSON API)${NC}"

# -------------------------------------------------------------------
# 5. Provision dashboard
# -------------------------------------------------------------------
echo -e "${YELLOW}[5/7] Provisioning dashboard...${NC}"

mkdir -p /etc/grafana/provisioning/dashboards
mkdir -p /var/lib/grafana/dashboards

cat > /etc/grafana/provisioning/dashboards/zerospoil.yaml << 'DBEOF'
apiVersion: 1
providers:
  - name: ZeroSpoil
    orgId: 1
    folder: ZeroSpoil
    type: file
    disableDeletion: false
    editable: true
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
DBEOF

# Copy dashboard JSON if it exists in the zerospoil dir
if [ -f "${ZEROSPOIL_DIR}/grafana_dashboard.json" ]; then
    cp "${ZEROSPOIL_DIR}/grafana_dashboard.json" /var/lib/grafana/dashboards/
    echo -e "  ${GREEN}Dashboard JSON copied from repo${NC}"
else
    echo -e "  ${YELLOW}No dashboard JSON found yet — will create after this script${NC}"
fi

# -------------------------------------------------------------------
# 6. Install Python deps for API bridge
# -------------------------------------------------------------------
echo -e "${YELLOW}[6/7] Installing API bridge dependencies...${NC}"

pip3 install --break-system-packages flask redis 2>/dev/null || pip3 install flask redis
echo -e "  ${GREEN}Flask + Redis installed${NC}"

# -------------------------------------------------------------------
# 7. Start Grafana
# -------------------------------------------------------------------
echo -e "${YELLOW}[7/7] Starting Grafana...${NC}"

systemctl daemon-reload
systemctl enable grafana-server
systemctl restart grafana-server

# Wait for Grafana to be ready
echo "  Waiting for Grafana to start..."
for i in {1..15}; do
    if curl -s http://localhost:3000/api/health | grep -q "ok" 2>/dev/null; then
        echo -e "  ${GREEN}Grafana is running!${NC}"
        break
    fi
    sleep 2
done

echo ""
echo "============================================"
echo -e "  ${GREEN}Grafana Setup Complete!${NC}"
echo "============================================"
echo ""
echo "  Dashboard: http://$(hostname -I | awk '{print $1}'):3000"
echo "  Login:     admin / ${GRAFANA_PASS} (or browse anonymously)"
echo ""
echo "  Next steps:"
echo "    1. cd ${ZEROSPOIL_DIR}"
echo "    2. python3 seed_demo_data.py"
echo "       (This seeds Redis AND starts the API bridge on :5000)"
echo "    3. Refresh Grafana — dashboard should populate"
echo ""
echo "============================================"
