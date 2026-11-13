<?php
// Redis commands for Server speed (sdk/protocols/queries.md, "Redis"), with
// the phpredis extension. \Redis has no hook a command passes through, so
// this stands in front of the one you made and forwards everything to it:
//
//   $redis = new AnalyticsPlatform\TimedRedis(new \Redis());
//   $redis->connect('127.0.0.1', 6379);
//
// Each command is timed until it answers, as db "redis", by its command and
// first key's shape only ("GET user:?:cart", Queries::redisCommand()): no
// other argument or value is ever kept. Failed: it threw (no answer, a lost
// connection), or it returned false with a new getLastError() (an error
// reply: WRONGTYPE, NOSCRIPT...; a nil reply is not one). The same error
// twice in a row, with no clearLastError() between, counts once.
// multi()/pipeline() to exec() is one call, "MULTI <first command>" or
// "PIPELINE <first command>", its time every step of it. Blocking commands
// (BLPOP, BRPOP, XREAD with a block...) and subscribe aren't timed. A method
// that hands back the client hands back this, so chaining stays timed;
// scan(), hScan(), sScan() and zScan() keep their iterator by reference.
// \RedisCluster works the same. Code that type-hints \Redis can't take this:
// time those with $platform->recordQuery('redis',
// Queries::redisCommand(['GET', $key]), $ms, $failed).
//
// Its static argsOf()/statementOf() turn a client method and its arguments
// into the command as Redis gets it, for Laravel's CommandExecuted and
// TimedPredis too. Nothing of the extension is changed. Reported to the
// Platform's queries module (Queries::report()), so it may be made before
// the Platform is.

namespace AnalyticsPlatform;

class TimedRedis
{
    use RedisGroup;

    // Client methods that send no command of the app's (phpredis and Predis).
    const NOT_COMMANDS = array('connect' => 1, 'pconnect' => 1, 'open' => 1, 'popen' => 1, 'close' => 1,
        'setoption' => 1, 'getoption' => 1, 'getlasterror' => 1, 'clearlasterror' => 1, 'isconnected' => 1,
        'gethost' => 1, 'getport' => 1, 'getdbnum' => 1, 'gettimeout' => 1, 'getreadtimeout' => 1,
        'getpersistentid' => 1, 'getauth' => 1, 'getmode' => 1, 'socket' => 1, 'getconnection' => 1,
        'getclientfor' => 1, 'getclientby' => 1, 'getcommandfactory' => 1, 'getoptions' => 1, 'createcommand' => 1,
        'disconnect' => 1, 'getiterator' => 1, 'pubsubloop' => 1, 'getprofile' => 1, 'executecommand' => 1,
        'gettransferredbytes' => 1, 'cleartransferredbytes' => 1, 'servername' => 1, 'serverversion' => 1);
    // A new connection: no group is open on it, whatever was left unfinished.
    const RECONNECTS = array('connect' => 1, 'pconnect' => 1, 'open' => 1, 'popen' => 1, 'close' => 1, 'reset' => 1);
    // phpredis' older names for commands.
    const ALIASES = array('delete' => 'del', 'lget' => 'lindex', 'lsize' => 'llen', 'lremove' => 'lrem',
        'listtrim' => 'ltrim', 'settimeout' => 'expire', 'zsize' => 'zcard', 'zdelete' => 'zrem', 'zremove' => 'zrem',
        'zdeleterangebyscore' => 'zremrangebyscore', 'zdeleterangebyrank' => 'zremrangebyrank',
        'zremoverangebyscore' => 'zremrangebyscore', 'sgetmembers' => 'smembers', 'sremove' => 'srem', 'ssize' => 'scard',
        'scontains' => 'sismember', 'getkeys' => 'keys', 'getmultiple' => 'mget', 'evaluate' => 'eval',
        'evaluatesha' => 'evalsha', 'renamekey' => 'rename', 'lgetrange' => 'lrange', 'zreverserange' => 'zrevrange');
    const SCRIPTS = array('eval' => 1, 'evalsha' => 1, 'eval_ro' => 1, 'evalsha_ro' => 1);
    // Their keys as an array of their own, the count added by the client:
    // fcall($fn, $keys, ...) in both, and Predis' eval_ro/evalsha_ro.
    const KEYED_SCRIPTS = array('fcall' => 1, 'fcall_ro' => 1);
    const PREDIS_KEYED_SCRIPTS = array('fcall' => 1, 'fcall_ro' => 1, 'eval_ro' => 1, 'evalsha_ro' => 1);
    const NUMKEYS = array('zunion' => 1, 'zinter' => 1, 'zdiff' => 1, 'sintercard' => 1, 'zintercard' => 1, 'lmpop' => 1, 'zmpop' => 1);
    // The arguments looked at: the key is never past the fourth, and a
    // stream read's BLOCK and STREAMS come early.
    const ARGS = 32;

    private $client;
    // Whether the client tells an error reply by getLastError() (phpredis).
    private $errors;

    public function __construct($client)
    {
        $this->client = $client;
        $this->errors = is_object($client) && method_exists($client, 'getLastError');
    }

    // The client this stands in front of; with arguments, phpredis' own
    // client() (CLIENT LIST, CLIENT SETNAME...), timed like any command.
    public function client(...$args)
    {
        return $args ? $this->__call('client', $args) : $this->client;
    }

    public function __call($name, $args)
    {
        return $this->run((string) $name, $args, function () use ($name, $args) {
            return $this->client->$name(...$args);
        });
    }

    public function __get($name)
    {
        return $this->client->$name;
    }

    // The scans hand their cursor back through the iterator.
    public function scan(&$iterator, ...$rest)
    {
        return $this->run('scan', array(), function () use (&$iterator, $rest) {
            return $this->client->scan($iterator, ...$rest);
        });
    }

    public function hScan($key, &$iterator, ...$rest)
    {
        return $this->run('hscan', array($key), function () use ($key, &$iterator, $rest) {
            return $this->client->hScan($key, $iterator, ...$rest);
        });
    }

    public function sScan($key, &$iterator, ...$rest)
    {
        return $this->run('sscan', array($key), function () use ($key, &$iterator, $rest) {
            return $this->client->sScan($key, $iterator, ...$rest);
        });
    }

    public function zScan($key, &$iterator, ...$rest)
    {
        return $this->run('zscan', array($key), function () use ($key, &$iterator, $rest) {
            return $this->client->zScan($key, $iterator, ...$rest);
        });
    }

    private function run($name, array $args, callable $call)
    {
        $lower = strtolower($name);
        // A multi() the app never ended (it threw, then reconnected): what
        // follows isn't part of it, in a worker that keeps this for hours.
        if (isset(self::RECONNECTS[$lower])) {
            $this->group = null;
        }
        if ($lower === 'multi' || $lower === 'pipeline') {
            return $this->open($lower, $args, $call);
        }
        if (($lower === 'exec' || $lower === 'discard') && $this->group !== null) {
            return $this->close($call, $lower === 'discard');
        }
        $statement = null;
        try {
            $statement = self::statementOf($name, $args);
        } catch (\Throwable $e) {
            // untimed
        }
        if ($statement === null) {
            $result = $call();
            return $result === $this->client ? $this : $result;
        }
        $before = $this->lastError();
        $started = microtime(true);
        $failed = true;
        try {
            $result = $call();
            $failed = $result === false && $this->newError($before);
            return $result === $this->client ? $this : $result;
        } finally {
            $this->settle($statement, (microtime(true) - $started) * 1000, $failed);
        }
    }

    // multi() or pipeline(): what follows until exec() is one call.
    private function open($lower, array $args, callable $call)
    {
        $started = microtime(true);
        $failed = true;
        try {
            $result = $call();
            $failed = $result === false;
            if ($result !== $this->client) {
                return $result;
            }
            if ($this->group === null && !Queries::isUntimed()) {
                $pipeline = $lower === 'pipeline' || (isset($args[0]) && defined('Redis::PIPELINE') && $args[0] === constant('Redis::PIPELINE'));
                $this->group = self::newGroup($pipeline ? 'PIPELINE' : 'MULTI');
            }
            return $this;
        } finally {
            // multi() itself is a step of its group, not a command to name it.
            if ($this->group !== null) {
                $this->settle(null, (microtime(true) - $started) * 1000, $failed);
            }
        }
    }

    // exec() or discard(): the call ends, recorded unless none of its
    // commands is timed, or it is a pipeline discarded (nothing was sent).
    private function close(callable $call, $discard = false)
    {
        $group = $this->group;
        $this->group = null;
        if ($discard && $group[0] === 'PIPELINE') {
            $group[1] = null;
        }
        $before = $this->lastError();
        $started = microtime(true);
        $failed = true;
        try {
            $result = $call();
            $failed = $this->newError($before);
            return $result === $this->client ? $this : $result;
        } finally {
            self::settleGroup($group, (microtime(true) - $started) * 1000, $failed);
        }
    }

    private function lastError()
    {
        if (!$this->errors) {
            return null;
        }
        try {
            return $this->client->getLastError();
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function newError($before)
    {
        $after = $this->lastError();
        return $after !== null && $after !== false && $after !== $before;
    }

    // ---- A client method as the command Redis gets ---------------------------------

    // What a client method and its arguments are timed as: the statement
    // (Queries::redisCommand() of the command), or null when it isn't timed
    // (not a command, blocking, or the package's own). Predis' pipeline() and
    // transaction() with a callback, which Laravel announces as one command,
    // are "PIPELINE" and "MULTI": the commands inside aren't seen. $predis:
    // the arguments are in Predis' order where it differs from phpredis'.
    public static function statementOf($method, array $params, $predis = false)
    {
        if (Queries::isUntimed() || !is_string($method)) {
            return null;
        }
        $lower = strtolower($method);
        if ($lower === 'pipeline' || $lower === 'transaction') {
            if (!self::hasCallback($params)) {
                return null;
            }
            return $lower === 'pipeline' ? 'PIPELINE' : 'MULTI';
        }
        $args = self::argsOf($method, $params, $predis);
        return $args === null ? null : Queries::redisCommand($args);
    }

    // The command as Redis gets it, from a phpredis or Predis method and its
    // arguments (array('mget', array(array('a', 'b'))) -> array('mget', 'a',
    // 'b')): arrays flattened one level, an associative one as key, value;
    // the methods whose arguments come in another order than Redis's put in
    // Redis's. null for a method that sends no command.
    public static function argsOf($method, array $params, $predis = false)
    {
        if (!is_string($method) || $method === '' || $method[0] === '_') {
            return null;
        }
        $name = strtolower($method);
        if (isset(self::NOT_COMMANDS[$name])) {
            return null;
        }
        if (isset(self::ALIASES[$name])) {
            $name = self::ALIASES[$name];
        }
        $params = array_values($params);
        $first = isset($params[0]) ? $params[0] : null;
        if ($name === 'rawcommand') {
            return self::flat($params, array());
        }
        if ($name === 'executeraw') {
            return is_array($first) ? self::flat($first, array()) : null;
        }
        // fcall($fn, $keys, ...), and Predis' eval_ro($script, $keys, ...):
        // the keys' count goes before them, as Redis gets it.
        if (isset($params[1]) && is_array($params[1]) && ($predis ? isset(self::PREDIS_KEYED_SCRIPTS[$name]) : isset(self::KEYED_SCRIPTS[$name]))) {
            return self::flat($params[1], array($name, $first, count($params[1])));
        }
        // phpredis: eval($script, $args, $numkeys). Predis has Redis's order.
        if (isset(self::SCRIPTS[$name]) && isset($params[1]) && is_array($params[1])) {
            return self::flat($params[1], array($name, $first, isset($params[2]) ? $params[2] : 0));
        }
        // Both: the keys as an array, their count added by the client.
        if (isset(self::NUMKEYS[$name]) && is_array($first)) {
            return self::flat($first, array($name, count($first)));
        }
        if (($name === 'xread' || $name === 'xreadgroup') && !self::hasWord($params, 'STREAMS')) {
            return self::streamRead($name, $params);
        }
        return self::flat($params, array($name));
    }

    // A stream read written as the client's method: phpredis' xRead($streams,
    // $count, $block) and xReadGroup($group, $consumer, $streams, $count,
    // $block), Predis' xread($count, $block, $streams). A block given is a
    // blocking read; a form not known counts as one, so it is never timed.
    private static function streamRead($name, array $params)
    {
        $at = $name === 'xread' ? 0 : 2;
        if (isset($params[$at]) && is_array($params[$at])) {
            $out = $name === 'xread' ? array('xread') : array('xreadgroup', 'GROUP', $params[0], $params[1]);
            $block = isset($params[$at + 2]) ? $params[$at + 2] : null;
            if (is_numeric($block) && $block >= 0) {
                $out[] = 'BLOCK';
            }
            $out[] = 'STREAMS';
            foreach ($params[$at] as $stream => $id) {
                $out[] = is_int($stream) ? $id : $stream;
                break;
            }
            return $out;
        }
        if ($name === 'xread' && !isset($params[1]) && isset($params[2]) && is_array($params[2])) {
            return array('xread', 'STREAMS', reset($params[2]));
        }
        return array($name, 'BLOCK');
    }

    private static function hasWord(array $params, $word)
    {
        foreach ($params as $param) {
            if (is_string($param) && strlen($param) === strlen($word) && strtoupper($param) === $word) {
                return true;
            }
        }
        return false;
    }

    // $items appended to $out, an array among them flattened one level, up
    // to ARGS in all.
    private static function flat(array $items, array $out)
    {
        foreach ($items as $item) {
            if (count($out) >= self::ARGS) {
                break;
            }
            if (!is_array($item)) {
                $out[] = $item;
                continue;
            }
            $i = 0;
            foreach ($item as $key => $value) {
                if (count($out) >= self::ARGS) {
                    break;
                }
                if ($key !== $i++) {
                    $out[] = $key;
                }
                $out[] = $value;
            }
        }
        return $out;
    }
}
