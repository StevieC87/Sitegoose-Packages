#!/bin/sh
# Installs the analytics server agent: the firewall for any Linux server.
#
#   curl -fsSL COLLECTOR/downloads/agent/install.sh -o /tmp/agent-install.sh
#   sudo ANALYTICS_ENDPOINT=COLLECTOR ANALYTICS_SITE_ID=SITE sh /tmp/agent-install.sh
#
# Not `curl | sudo sh`: sudo-rs (Ubuntu 26.04) gives a command whose stdin is a
# pipe a terminal of its own, so the keyboard never reaches the prompt below and
# it waits for ever.
#
# Asks for the site secret (or reads ANALYTICS_SITE_SECRET), writes
# /etc/analytics-agent.json (readable by root only) and starts the
# analytics-agent service. Backend: the one an earlier install wrote, else
# nftables when `nft` is there, else iptables when it and ipset are, else nginx
# (ANALYTICS_BACKEND=nftables|iptables|nginx to choose; none: file monitoring only).
# File monitoring watches ANALYTICS_WEBROOT (folders, comma-separated), else
# the first of /var/www/html, /usr/share/nginx/html, /var/www that exists.
set -eu

fail() { echo "analytics-agent: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || fail "run it as root (sudo)"
command -v python3 >/dev/null 2>&1 || fail "python3 is needed (apt install python3, dnf install python3...)"
command -v systemctl >/dev/null 2>&1 || fail "systemd is needed to run it as a service"
[ -n "${ANALYTICS_ENDPOINT:-}" ] || fail "set ANALYTICS_ENDPOINT (the collector's URL)"
[ -n "${ANALYTICS_SITE_ID:-}" ] || fail "set ANALYTICS_SITE_ID"

endpoint="${ANALYTICS_ENDPOINT%/}"
# The agent is a Python file fetched from this address and installed as root, so
# the address has to be one that can't be tampered with on the way. Over https
# the certificate is what makes that true (the agent verifies it too). Plain
# http would let whoever sits on the network hand over their own agent, as root.
# ANALYTICS_INSECURE=1 is for trying it against a collector on your own machine.
case "$endpoint" in
  https://*) ;;
  http://*)
    [ "${ANALYTICS_INSECURE:-}" = 1 ] || fail "ANALYTICS_ENDPOINT must be https:// (the agent is installed as root from it). For a local collector: ANALYTICS_INSECURE=1"
    echo "analytics-agent: WARNING: installing over plain http, as asked. Anyone on the network can replace the agent." >&2
    ;;
  *) fail "ANALYTICS_ENDPOINT must start with https://" ;;
esac
secret="${ANALYTICS_SITE_SECRET:-}"
if [ -z "$secret" ]; then
  [ -r /dev/tty ] || fail "set ANALYTICS_SITE_SECRET (no terminal to ask on)"
  printf "Site secret (Site settings in your dashboard): " >/dev/tty
  stty -echo </dev/tty 2>/dev/null || true
  read -r secret </dev/tty
  stty echo </dev/tty 2>/dev/null || true
  printf "\n" >/dev/tty
fi
[ -n "$secret" ] || fail "no site secret"
# A paste can carry invisible characters, and the prompt hides them. The
# collector then answers 400 to every request, for as long as the agent runs.
case "$secret" in
  *[!A-Za-z0-9]*) fail "the site secret has more than letters and digits in it, so nothing was installed: copy it again" ;;
esac

backend="${ANALYTICS_BACKEND:-}"
# Installing again keeps the backend the config already has.
if [ -z "$backend" ] && [ -r /etc/analytics-agent.json ]; then
  backend="$(python3 -c 'import json; print(json.load(open("/etc/analytics-agent.json")).get("backend") or "")' 2>/dev/null || true)"
fi
if [ -z "$backend" ]; then
  # The kernel first (address lists, connection limits and what they caught,
  # reported): nftables, else iptables with ipset; nginx's allow/deny lines
  # only where neither is there. nginx's request limit and browser check are
  # used with any of them.
  if command -v nft >/dev/null 2>&1; then backend=nftables
  elif command -v iptables >/dev/null 2>&1 && command -v ipset >/dev/null 2>&1; then backend=iptables
  elif command -v nginx >/dev/null 2>&1; then backend=nginx
  else backend=none; echo "Neither nftables, iptables with ipset, nor nginx found: file monitoring only, no firewall."
  fi
fi

webroot="${ANALYTICS_WEBROOT:-}"
if [ -z "$webroot" ]; then
  for dir in /var/www/html /usr/share/nginx/html /var/www; do
    if [ -d "$dir" ]; then webroot="$dir"; break; fi
  done
fi

echo "Downloading the agent..."
tmp="$(mktemp)"
curl -fsSL "$endpoint/downloads/agent/analytics-agent" -o "$tmp" || fail "download failed"
head -n 1 "$tmp" | grep -q python3 || fail "the download isn't the agent"
# Pin the exact agent if you want to: take the sum from the dashboard (or from a
# copy you already trust) and pass ANALYTICS_AGENT_SHA256. Without it, https is
# what stands between this file and the network.
if [ -n "${ANALYTICS_AGENT_SHA256:-}" ]; then
  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is needed to check ANALYTICS_AGENT_SHA256"
  got="$(sha256sum "$tmp" | cut -d' ' -f1)"
  [ "$got" = "$ANALYTICS_AGENT_SHA256" ] || { rm -f "$tmp"; fail "the agent's checksum is $got, not the $ANALYTICS_AGENT_SHA256 you asked for; nothing installed"; }
  echo "Checksum matches."
fi
install -m 0755 "$tmp" /usr/local/bin/analytics-agent
curl -fsSL "$endpoint/downloads/agent/analytics-agent.service" -o /etc/systemd/system/analytics-agent.service || fail "download failed"
rm -f "$tmp"

umask 077
ANALYTICS_SITE_ID="$ANALYTICS_SITE_ID" ANALYTICS_SECRET="$secret" ANALYTICS_ENDPOINT="$endpoint" ANALYTICS_BACKEND="$backend" ANALYTICS_WEBROOT="$webroot" \
python3 -c 'import json, os; print(json.dumps({"site_id": os.environ["ANALYTICS_SITE_ID"], "secret": os.environ["ANALYTICS_SECRET"], "endpoint": os.environ["ANALYTICS_ENDPOINT"], "backend": os.environ["ANALYTICS_BACKEND"], "files_roots": [r.strip() for r in os.environ["ANALYTICS_WEBROOT"].split(",") if r.strip()]}, indent=2))' \
  > /etc/analytics-agent.json
chmod 600 /etc/analytics-agent.json

echo "Fetching the rules once..."
/usr/local/bin/analytics-agent once || fail "the first run failed (see above); nothing was started"

systemctl daemon-reload
systemctl enable --now analytics-agent >/dev/null
echo "Done: analytics-agent is running ($backend)."
if [ -n "$webroot" ]; then
  echo "Watching the files in $webroot: the first check (within a minute) is the accepted version."
  echo "After each deploy run: analytics-agent accept"
else
  echo "No web folder found, so files aren't watched: add \"files_roots\": [\"/path/to/site\"] to /etc/analytics-agent.json and restart."
fi
if [ "$backend" = nginx ]; then
  echo "Add this line inside the http { } block of your nginx config, then reload nginx:"
  echo "    include /etc/nginx/analytics-firewall.conf;"
fi
echo "Status: analytics-agent status · logs: journalctl -u analytics-agent · remove the rules: analytics-agent clear"
