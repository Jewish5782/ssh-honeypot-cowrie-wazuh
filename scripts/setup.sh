#!/usr/bin/env bash
# One-time setup for the Cowrie + Wazuh lab.
# - tunes the kernel for the Wazuh indexer (OpenSearch)
# - generates the indexer TLS certs
# - wires Cowrie's JSON log into the Wazuh manager
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[*] Checking Docker..."
command -v docker >/dev/null || { echo "Docker not found. Install Docker + Compose v2."; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose v2 required."; exit 1; }

echo "[*] Setting vm.max_map_count (required by the Wazuh indexer)..."
if [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]; then
  sudo sysctl -w vm.max_map_count=262144 || echo "  (could not set; set it manually before starting)"
fi

echo "[*] Generating Wazuh indexer certificates..."
mkdir -p wazuh/certs
if [ ! -f wazuh/certs/root-ca.pem ]; then
  docker run --rm -v "$(pwd)/wazuh/certs.yml:/config/certs.yml" -v "$(pwd)/wazuh/certs:/certs" \
    wazuh/wazuh-certs-generator:0.0.2 || \
    echo "  If cert generation fails, follow: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html"
fi

echo "[*] Injecting Cowrie localfile into the manager on first boot..."
echo "    (the manager reads /wazuh-config-mount/ossec_localfile.conf — see README)"

echo "[+] Setup complete. Start the stack with:  docker compose up -d"
echo "    Dashboard: https://localhost:5601   (default admin / SecretPassword)"
echo "    Point an SSH scanner at localhost:2222 to generate events."
