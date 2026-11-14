// Database queries with their values taken out (sdk/protocols/queries.md):
// the rule applied before a query is counted, so no value in it ever leaves
// the server. A port of the collector's expresscollect/Analytics/queryText.js,
// which applies it again on arrival; the tests run the cases every package
// shares (sdk/protocols/query-cases.json). Change the rule there first.
//
//   SELECT * FROM users WHERE email = 'a@b.c' AND id IN (1, 2, 3)
//   -> SELECT * FROM users WHERE email = ? AND id IN (?)
"use strict";

const MAX_STATEMENT = 1000;
const OTHER_STATEMENT = "(other)";
// The databases a row may name; anything else is "other".
const DATABASES = new Set(["postgresql", "mysql", "mariadb", "sqlite", "mssql", "oracle", "clickhouse", "mongodb", "redis", "other"]);

// A digit right after one of these is part of a name or a placeholder
// (table2, $1, @p1, :1), not a value. ASCII only, in every package.
const WORD = /[A-Za-z0-9_$@:]/;
const NUMBER = /^(?:0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/;
const DOLLAR_TAG = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/;
// A string's one-letter prefix: E'..' N'..' X'..' B'..'.
const PREFIX = /(^|[^A-Za-z0-9_])[EeNnXxBb]$/;
const PLACEHOLDER = String.raw`(?:\?|\$\d+|:\w+|@\w+)`;
const LIST = new RegExp(String.raw`\(\s*${PLACEHOLDER}(?:\s*,\s*${PLACEHOLDER})*\s*\)`, "g");
const ROWS = /\(\?\)(?:\s*,\s*\(\?\))+/g;
// Where "..." may hold a value rather than a name: SQLite takes a
// double-quoted string as a literal when no column has that name (SQLCipher's
// PRAGMA key = "x'2DD2…'"), Oracle writes a password as a quoted name, and an
// unknown database may do either. There "..." is kept only when it reads as a
// plain name, closed: "email", never "x'2D…'", "N3w P@ss" or an unclosed one.
const VALUE_QUOTES = new Set(["sqlite", "oracle", "other"]);
const NAME = /^"[A-Za-z_][A-Za-z0-9_$#]{0,127}"$/;
// A password or key written as a name, on any database: Oracle's
// ALTER USER u IDENTIFIED BY pw and SQLCipher's PRAGMA key = "passphrase".
// What follows is "?" whether it was a word or a quoted name.
const SECRET_NAME = String.raw`("(?:[^"]|"")*"?|\x60(?:[^\x60]|\x60\x60)*\x60?|[^\s;,()]+)`;
const IDENTIFIED = new RegExp(String.raw`(\bIDENTIFIED BY )${SECRET_NAME}`, "gi");
const PRAGMA_KEY = new RegExp(String.raw`(\bPRAGMA (?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:HEX)?(?:RE)?KEY ?[=(] ?)${SECRET_NAME}`, "gi");

// The end of a quoted run starting at `start` (the opening quote): the index
// after the closing quote, or the text's length. A doubled quote escapes,
// and a backslash too unless `backslash` is false.
function quoteEnd(sql, start, quote, backslash = true) {
  let i = start + 1;
  while (i < sql.length) {
    const c = sql[i];
    if (c === "\\" && backslash) i += 2;
    else if (c === quote) {
      if (sql[i + 1] === quote) i += 2;
      else return i + 1;
    } else i += 1;
  }
  return sql.length;
}

function sqlShape(sql, db, backslashLiteral) {
  const mysql = db === "mysql" || db === "mariadb";
  const postgres = db === "postgresql";
  // Where a backslash in a string is just a character: PostgreSQL's plain
  // strings (standard_conforming_strings, on since 9.1), SQLite, SQL Server
  // and Oracle. Read as an escape there, 'C:\' ends late and lets what
  // follows out. MySQL, MariaDB, ClickHouse and unknown databases escape.
  const literal = backslashLiteral ?? (postgres || db === "sqlite" || db === "mssql" || db === "oracle");
  let out = "";
  const space = () => {
    if (out && !out.endsWith(" ")) out += " ";
  };
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    const next = sql[i + 1];
    const prev = i > 0 ? sql[i - 1] : "";
    if ((c === "-" && next === "-") || (c === "#" && mysql)) {
      const end = sql.indexOf("\n", i);
      i = end === -1 ? sql.length : end;
      space();
    } else if (c === "/" && next === "*") {
      const end = sql.indexOf("*/", i + 2);
      i = end === -1 ? sql.length : end + 2;
      space();
    } else if (c === "'" || (c === '"' && mysql)) {
      // Only PostgreSQL's E'..' escapes with a backslash where it is literal.
      // Both tests look at the last two characters only: run over the whole
      // growing output for every quote, these end-anchored patterns made a
      // statement of many short literals cost quadratic time.
      const tail = out.slice(-2);
      const escapes = !literal || (postgres && /(^|[^A-Za-z0-9_])[Ee]$/.test(tail));
      if (PREFIX.test(tail)) out = out.slice(0, -1);
      i = quoteEnd(sql, i, c, escapes);
      out += "?";
    } else if (c === '"' || c === "`") {
      const end = quoteEnd(sql, i, c, !literal);
      const run = sql.slice(i, end);
      out += c === '"' && VALUE_QUOTES.has(db) && !NAME.test(run) ? "?" : run;
      i = end;
    } else if (c === "$" && !WORD.test(prev) && DOLLAR_TAG.test(sql.slice(i, i + 64))) {
      const tag = DOLLAR_TAG.exec(sql.slice(i, i + 64))[0];
      const end = sql.indexOf(tag, i + tag.length);
      i = end === -1 ? sql.length : end + tag.length;
      out += "?";
    } else if ((/\d/.test(c) || (c === "." && /\d/.test(next || ""))) && !WORD.test(prev)) {
      i += NUMBER.exec(sql.slice(i, i + 400))[0].length;
      out += "?";
    } else if (/\s/.test(c)) {
      i += 1;
      space();
    } else {
      out += c;
      i += 1;
    }
  }
  return out.replace(IDENTIFIED, "$1?").replace(PRAGMA_KEY, "$1?").replace(LIST, "(?)").replace(ROWS, "(?)").trim();
}

// A Mongo filter or pipeline's shape: keys kept, every value "?", and an
// array whose items all have the same shape kept as one.
function mongoShape(value, depth = 0) {
  if (value === null || typeof value !== "object" || depth >= 6) return "?";
  if (Array.isArray(value)) {
    const items = value.map((item) => mongoShape(item, depth + 1));
    const seen = new Set(items.map((item) => JSON.stringify(item)));
    return seen.size === 1 ? [items[0]] : items;
  }
  const out = {};
  for (const [key, item] of Object.entries(value)) out[key] = mongoShape(item, depth + 1);
  return out;
}

// "find users {...}": the command, the collection, and the filter's shape.
function mongoStatement(text) {
  const match = /^(\S+)(?: (\S+))?(?: ([\s\S]*))?$/.exec(text.trim());
  if (!match) return "";
  const [, command] = match;
  let [, , collection, rest] = match;
  // A "collection" with a brace, bracket or quote in it is the filter's start.
  if (collection && /[{}[\]"']/.test(collection)) {
    rest = rest === undefined ? collection : `${collection} ${rest}`;
    collection = undefined;
  }
  let shape = "";
  if (rest) {
    try {
      shape = JSON.stringify(mongoShape(JSON.parse(rest)));
    } catch {
      shape = "";
    }
  }
  return [command, collection, shape].filter(Boolean).join(" ");
}

// Redis: the command and its first key's shape, never an argument or value
// (queries.md, "Redis"). A key keeps each ":" segment that is only letters
// and "_" (32 at most); every other segment is "?", so IDs, slugs, emails and
// hashes never leave the server: user:42:cart -> user:?:cart.
const REDIS_WORD = /^[A-Za-z][A-Za-z0-9_.|-]{0,39}$/;
const REDIS_SEGMENT = /^[A-Za-z_]{1,32}$/;
// Commands whose second word is a subcommand (CLIENT SETNAME, XINFO STREAM).
const REDIS_CONTAINERS = new Set(["ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "DEBUG", "FUNCTION", "LATENCY", "MEMORY", "MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO"]);
// Of those, the ones with a key after the subcommand.
const REDIS_SUB_KEY = new Set(["OBJECT", "MEMORY", "XGROUP", "XINFO"]);
// No key: what follows is a password, a message, a number or nothing.
const REDIS_NO_KEY = new Set(["PING", "ECHO", "INFO", "AUTH", "HELLO", "SELECT", "QUIT", "RESET", "MULTI", "EXEC", "DISCARD", "UNWATCH", "DBSIZE", "TIME", "FLUSHDB", "FLUSHALL", "SAVE", "BGSAVE", "BGREWRITEAOF", "LASTSAVE", "SCAN", "RANDOMKEY", "SWAPDB", "SHUTDOWN", "ROLE", "REPLICAOF", "SLAVEOF", "READONLY", "READWRITE", "LOLWUT", "FAILOVER", "PSYNC", "SYNC", "REPLCONF", "MIGRATE"]);
// Script calls: script or name, then how many keys, then the keys.
const REDIS_SCRIPTS = new Set(["EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO"]);
// How many keys first, then the keys.
const REDIS_NUMKEYS = new Set(["ZUNION", "ZINTER", "ZDIFF", "SINTERCARD", "ZINTERCARD", "LMPOP", "ZMPOP"]);
// Waiting, not working: a queue worker sits in these for seconds, so timing
// them would put every idle worker at the top of the slow list.
const REDIS_WAITING = new Set(["BLPOP", "BRPOP", "BRPOPLPUSH", "BLMOVE", "BLMPOP", "BZPOPMIN", "BZPOPMAX", "BZMPOP", "WAIT", "WAITAOF", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE", "MONITOR"]);
const REDIS_PREFIXES = new Set(["PIPELINE", "MULTI"]);

const asciiUpper = (text) => text.replace(/[a-z]/g, (c) => c.toUpperCase());

function redisKeyShape(key) {
  // An empty key is "?" too: "GET " would come back from the collector as "GET".
  if (typeof key !== "string" || key === "") return "?";
  return key.split(":").map((part) => (part === "" || REDIS_SEGMENT.test(part) ? part : "?")).join(":");
}

// A command as the client sends it (["GET", "user:42"]) -> "GET user:?", or
// null for one that isn't timed (blocking, or not a command). Packages only:
// what they send is this, and the collector checks it with redisStatement.
function redisCommand(args) {
  if (!Array.isArray(args) || typeof args[0] !== "string" || !REDIS_WORD.test(args[0])) return null;
  const name = asciiUpper(args[0]);
  const word = (i) => (typeof args[i] === "string" ? asciiUpper(args[i]) : "");
  if (REDIS_WAITING.has(name)) return null;
  let command = name;
  let key;
  if (REDIS_CONTAINERS.has(name)) {
    if (typeof args[1] === "string" && REDIS_WORD.test(args[1])) {
      command = `${name} ${asciiUpper(args[1])}`;
      // Only after a subcommand: "OBJECT user" would read back as OBJECT USER.
      if (REDIS_SUB_KEY.has(name)) key = 2;
    }
  } else if (REDIS_SCRIPTS.has(name)) {
    if (Number(args[2]) > 0) key = 3;
  } else if (REDIS_NUMKEYS.has(name)) {
    if (Number(args[1]) > 0) key = 2;
  } else if (name === "BITOP") key = 2;
  else if (name === "XREAD" || name === "XREADGROUP") {
    // Its options, then STREAMS and the keys. XREADGROUP's group and consumer
    // come first and may be named anything, as may a stream ("block").
    let at = -1;
    for (let i = name === "XREADGROUP" ? 4 : 1; i < args.length && at < 0; i++) {
      if (word(i) === "BLOCK") return null;
      if (word(i) === "STREAMS") at = i;
    }
    if (at > 0) key = at + 1;
  } else if (!REDIS_NO_KEY.has(name) && !REDIS_PREFIXES.has(name)) key = 1;
  return key !== undefined && key < args.length ? `${command} ${redisKeyShape(args[key])}` : command;
}

// A statement a package sent: [PIPELINE|MULTI] COMMAND [SUBCOMMAND] [key].
// Anything else (an argument a package let through) is (other).
function redisStatement(text) {
  const words = text.trim().split(/\s+/);
  if (words[0] === "") return "";
  const out = [];
  let i = 0;
  if (REDIS_PREFIXES.has(asciiUpper(words[0])) && words.length > 1) out.push(asciiUpper(words[i++]));
  if (!REDIS_WORD.test(words[i])) return OTHER_STATEMENT;
  const name = asciiUpper(words[i++]);
  if (REDIS_WAITING.has(name)) return OTHER_STATEMENT;
  out.push(name);
  if (REDIS_CONTAINERS.has(name) && i < words.length && REDIS_WORD.test(words[i])) out.push(asciiUpper(words[i++]));
  if (i < words.length - 1) return OTHER_STATEMENT;
  if (i < words.length) out.push(redisKeyShape(words[i]));
  return out.join(" ");
}

const cut = (text) => {
  const chars = Array.from(text);
  return chars.length > MAX_STATEMENT ? chars.slice(0, MAX_STATEMENT).join("").trim() : text;
};

const databaseOf = (db) => {
  const name = String(db ?? "").toLowerCase();
  return DATABASES.has(name) ? name : "other";
};

// The statement to store, or "" when nothing is left of it.
function normalizeStatement(text, db) {
  if (typeof text !== "string") return "";
  if (text === OTHER_STATEMENT) return text;
  const name = databaseOf(db);
  let shaped;
  if (name === "mongodb") shaped = mongoStatement(text);
  else if (name === "redis") shaped = redisStatement(text);
  else if (name === "other" && text.includes("\\")) {
    // A database we don't know may or may not take a backslash as an escape,
    // and each reading leaks what the other hides. When they disagree the
    // query keeps its timing under (other) and its text is left out.
    const escaped = sqlShape(text, name, false);
    shaped = escaped === sqlShape(text, name, true) ? escaped : OTHER_STATEMENT;
  } else shaped = sqlShape(text, name);
  return cut(shaped);
}

module.exports = { normalizeStatement, redisCommand, redisKeyShape, databaseOf, MAX_STATEMENT, OTHER_STATEMENT, DATABASES, REDIS_CONTAINERS };
