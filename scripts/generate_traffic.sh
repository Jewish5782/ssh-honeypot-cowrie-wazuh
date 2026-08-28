#!/usr/bin/env bash
# Generate honeypot traffic so you can see events flow into Wazuh.
# Safe: it only hits your own local Cowrie on port 2222.
set -euo pipefail
HOST="${1:-localhost}"
PORT="${2:-2222}"

echo "[*] Firing failed logins at $HOST:$PORT (expect them to fail — it's a honeypot)..."
for u in root admin oracle postgres ubuntu; do
  sshpass -p "wrongpass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -p "$PORT" "$u@$HOST" "id" 2>/dev/null || true
done
echo "[+] Done. Check the Wazuh dashboard (rules 100102 / 100110) at https://localhost:5601"
echo "    (Install 'sshpass' if the loop did nothing: apt-get install sshpass)"
