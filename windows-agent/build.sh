#!/usr/bin/env bash
# Copies the Windows agent where the collector serves it
# (/downloads/agent/windows/, used by install.ps1).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../../expresscollect/public/downloads/agent/windows"
mkdir -p "$out"
cp "$here/analytics-agent.ps1" "$here/install.ps1" "$out/"
echo "Copied to $out"
