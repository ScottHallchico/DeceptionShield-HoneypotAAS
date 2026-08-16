#!/bin/bash
set -e
apt-get update
apt-get install -y curl xz-utils tar unzip bzip2 gzip
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/midnightntwrk/compact/releases/download/compact-v0.5.1/compact-installer.sh | sh
/root/.local/bin/compact update
/root/.local/bin/compact list
cd /workspace
mkdir -p build
/root/.local/bin/compact compile src/defense_ledger.compact build
