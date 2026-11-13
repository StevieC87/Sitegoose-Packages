<?php
// Which tracker version the plugin loads, and the integrity hash that pins it.
//
// The plugin moves to new tracker releases by itself, but never by loading
// whatever the auto-updating /v1/s.js serves: a server that was no longer ours
// could serve anything there, to every visitor of every site with the plugin.
// So the tag always names one version with its hash, and the browser refuses
// a file that doesn't match. Which version: the one built in below, until the
// plugin reads a newer one from the collector's tracker-release.json, which it
// believes only when it's signed by a key listed here. That key is kept off
// every server (expresscollect/scripts/trackerSigning.mjs).
//
// The three constants are written by scripts: the version and hash by
// npm run release:tracker, the keys by npm run tracker:keygen.

if (!defined('ABSPATH')) {
    exit;
}

const SITE_ANALYTICS_TRACKER_VERSION = '1.0.85';
const SITE_ANALYTICS_TRACKER_INTEGRITY = 'sha384-nDanHQwWmMQTTuyxu4qGJPOKTNkUNBK/Gd/Qe2P+V1nzLtYYpxA4orMdnO9riVoL';
const SITE_ANALYTICS_RELEASE_KEYS = array();

// The release a tracker-release.json body names for $major, as
// array('version', 'integrity', 'seq'), when it is signed by one of $keys and
// newer than $after (the seq of the last one taken, so an old file served
// again is refused). Anything else is null.
function site_analytics_release_verify($body, array $keys, $major, $after)
{
    $file = json_decode((string) $body, true);
    if (!is_array($file) || !isset($file['payload'], $file['signature']) || !is_string($file['payload']) || !is_string($file['signature'])) {
        return null;
    }
    $signature = base64_decode($file['signature'], true);
    // WordPress carries sodium_compat for PHP built without sodium.
    if ($signature === false || strlen($signature) !== 64 || !function_exists('sodium_crypto_sign_verify_detached')) {
        return null;
    }
    $signed = false;
    foreach ($keys as $key) {
        $raw = base64_decode((string) $key, true);
        if ($raw === false || strlen($raw) !== 32) {
            continue;
        }
        try {
            if (sodium_crypto_sign_verify_detached($signature, $file['payload'], $raw)) {
                $signed = true;
                break;
            }
        } catch (\Throwable $e) {
            // A malformed key or signature is just not a match.
        }
    }
    if (!$signed) {
        return null;
    }
    $payload = json_decode($file['payload'], true);
    if (!is_array($payload) || !isset($payload['product'], $payload['seq'], $payload['latest'][$major]) || $payload['product'] !== 'sitegoose-tracker') {
        return null;
    }
    // Milliseconds: a float on 32-bit PHP, which compares the same.
    $seq = $payload['seq'];
    if ((!is_int($seq) && !is_float($seq)) || $seq <= $after) {
        return null;
    }
    $entry = $payload['latest'][$major];
    $version = is_array($entry) && isset($entry['version']) && is_string($entry['version']) ? $entry['version'] : '';
    $integrity = is_array($entry) && isset($entry['integrity']) && is_string($entry['integrity']) ? $entry['integrity'] : '';
    if (!preg_match('/^' . preg_quote((string) $major, '/') . '\.\d+\.\d+$/D', $version) || !preg_match('#^sha384-[A-Za-z0-9+/]{64}$#D', $integrity)) {
        return null;
    }
    return array('version' => $version, 'integrity' => $integrity, 'seq' => $seq);
}
