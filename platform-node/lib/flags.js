// Feature flags module: turn features of your app on or off from the
// dashboard (Security → Server package), for everyone, for a share of users, or
// for listed user IDs. isEnabled() answers from memory; the flags come with
// the module switches (core.js), about once a minute.
"use strict";

// FNV-1a over "key:user", 0-99: the same user always gets the same answer,
// in every package (Python and PHP work it out the same way).
function bucket(key, user) {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(`${key}:${user}`)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash % 100;
}

function evaluate(flag, key, user) {
  if (!flag.on) return false;
  const id = user === undefined || user === null ? "" : String(user);
  if (id && flag.users?.includes(id)) return true;
  if (flag.rollout >= 100) return true;
  if (flag.rollout <= 0 || !id) return false;
  return bucket(key, id) < flag.rollout;
}

function createFlags(core) {
  // key: the flag's key; options: user (for rollouts and user lists),
  // default (when the flag isn't known yet, or the module is off; false).
  function isEnabled(key, { user, default: fallback = false } = {}) {
    try {
      const flag = core.isOn("flags") ? core.flags()[key] : undefined;
      return flag ? evaluate(flag, key, user) : fallback;
    } catch {
      return fallback;
    }
  }
  return { isEnabled };
}

module.exports = { createFlags, bucket, evaluate };
