#!/usr/bin/env bash
# Copies the agent where the collector serves it (/downloads/agent/, used by install.sh).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../../expresscollect/public/downloads/agent"
mkdir -p "$out"
cp "$here/analytics-agent" "$here/analytics-agent.service" "$here/install.sh" "$out/"
echo "Copied to $out"
