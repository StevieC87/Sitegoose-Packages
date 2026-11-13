#!/usr/bin/env bash
# Builds the WordPress plugin zip: copies the PHP package (sdk/platform-php/src,
# the one source; not its Laravel part) into the plugin and zips it where the
# collector serves it (/downloads/site-analytics-wordpress.zip, linked from the dashboard).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../../expresscollect/public/downloads"
rm -rf "$here/site-analytics/lib"
mkdir -p "$here/site-analytics/lib" "$out"
cp "$here"/../platform-php/src/*.php "$here/site-analytics/lib/"
rm -f "$out/site-analytics-wordpress.zip"
(cd "$here" && zip -qr "$out/site-analytics-wordpress.zip" site-analytics)
echo "Built $out/site-analytics-wordpress.zip"
