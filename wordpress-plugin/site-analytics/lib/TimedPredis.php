<?php
// Redis commands for Server speed (sdk/protocols/queries.md, "Redis"), with
// Predis. Its client has no public hook a command passes through, so this
// stands in front of the one you made and forwards everything to it:
//
//   $redis = new AnalyticsPlatform\TimedPredis(new Predis\Client($parameters));
//
// Each command is timed until it answers, as db "redis", by its command and
// first key's shape only ("GET user:?:cart", Queries::redisCommand()): no
// other argument or value is ever kept. Failed: it threw (an error reply
// with Predis' exceptions on, no answer, a lost connection), or it returned
// an error reply (exceptions off); a nil reply is not one. executeCommand()
// and executeRaw() are timed too. A pipeline() or transaction() is one call:
// without a callback, "PIPELINE <first command>" or "MULTI <first command>"
// from the first command to execute(); with one, the whole callback as
// "PIPELINE" or "MULTI", since what it queues can't be seen from outside.
// Blocking commands (BLPOP, BRPOP, XREAD with a block...) and subscriptions
// aren't timed. A method that hands back the client hands back this, so
// chaining stays timed. Code that type-hints Predis\Client or
// Predis\ClientInterface can't take this: time those with
// $platform->recordQuery('redis', Queries::redisCommand(['GET', $key]), $ms, $failed).
//
// Nothing of Predis is changed. Reported to the Platform's queries module
// (Queries::report()), so it may be made before the Platform is.

namespace AnalyticsPlatform;

class TimedPredis
{
    // $group is set when this stands in front of a pipeline or transaction
    // (pipeline() or transaction() without a callback).
    use RedisGroup;

    private $client;

    public function __construct($client)
    {
        $this->client = $client;
    }

    // The client (or pipeline) this stands in front of; with arguments,
    // Predis' own client() (CLIENT LIST, CLIENT SETNAME...), timed like any
    // command.
    public function client(...$args)
    {
        return $args ? $this->__call('client', $args) : $this->client;
    }

    private static function grouped($object, $prefix)
    {
        $timed = new self($object);
        $timed->group = self::newGroup($prefix);
        return $timed;
    }

    public function __call($name, $args)
    {
        $name = (string) $name;
        $call = function () use ($name, $args) {
            return $this->client->$name(...$args);
        };
        $lower = strtolower($name);
        if ($this->group === null && ($lower === 'pipeline' || $lower === 'transaction')) {
            return $this->unit($lower === 'pipeline' ? 'PIPELINE' : 'MULTI', $args, $call);
        }
        if ($this->group !== null && ($lower === 'execute' || $lower === 'exec')) {
            return $this->close($call);
        }
        if ($this->group !== null && $lower === 'discard') {
            $this->group = self::newGroup($this->group[0]);
            return $this->pass($call);
        }
        $statement = null;
        try {
            if ($lower === 'executecommand') {
                $command = isset($args[0]) ? $args[0] : null;
                if (is_object($command) && method_exists($command, 'getId') && method_exists($command, 'getArguments')) {
                    $statement = TimedRedis::statementOf('rawCommand', array_merge(array($command->getId()), (array) $command->getArguments()));
                }
            } else {
                $statement = TimedRedis::statementOf($name, $args, true);
            }
        } catch (\Throwable $e) {
            // untimed
        }
        if ($statement === null) {
            return $this->pass($call);
        }
        return $this->time($statement, $call);
    }

    public function __get($name)
    {
        return $this->client->$name;
    }

    // Its $error is set by reference.
    public function executeRaw(array $arguments, &$error = null)
    {
        $statement = null;
        try {
            $statement = TimedRedis::statementOf('rawCommand', $arguments);
        } catch (\Throwable $e) {
            // untimed
        }
        $call = function () use ($arguments, &$error) {
            return $this->client->executeRaw($arguments, $error);
        };
        if ($statement === null) {
            return $call();
        }
        return $this->time($statement, $call, function () use (&$error) {
            return (bool) $error;
        });
    }

    private function pass(callable $call)
    {
        $result = $call();
        return $result === $this->client ? $this : $result;
    }

    private function time($statement, callable $call, ?callable $error = null)
    {
        $started = microtime(true);
        $failed = true;
        try {
            $result = $call();
            $failed = self::isError($result) || ($error !== null && $error());
            return $result === $this->client ? $this : $result;
        } finally {
            $this->settle($statement, (microtime(true) - $started) * 1000, $failed);
        }
    }

    // pipeline() or transaction(): with a callback, it runs here and is
    // timed whole; without one, what it hands back is timed until execute().
    private function unit($prefix, array $args, callable $call)
    {
        if (Queries::isUntimed()) {
            return $call();
        }
        if (!self::hasCallback($args)) {
            $result = $call();
            return is_object($result) ? self::grouped($result, $prefix) : $result;
        }
        $started = microtime(true);
        $failed = true;
        try {
            $result = $call();
            $failed = self::anyError($result);
            return $result;
        } finally {
            Queries::report('redis', $prefix, (microtime(true) - $started) * 1000, $failed);
        }
    }

    // execute(): the pipeline or transaction ends, recorded unless none of
    // its commands is timed.
    private function close(callable $call)
    {
        $group = $this->group;
        $this->group = self::newGroup($group[0]);
        $started = microtime(true);
        $failed = true;
        try {
            $result = $call();
            $failed = self::anyError($result);
            return $result;
        } finally {
            self::settleGroup($group, (microtime(true) - $started) * 1000, $failed);
        }
    }

    private static function isError($result)
    {
        return $result instanceof \Predis\Response\ErrorInterface;
    }

    // An error reply, or one among a pipeline's replies.
    private static function anyError($result)
    {
        if (self::isError($result)) {
            return true;
        }
        if (is_array($result)) {
            foreach ($result as $item) {
                if (self::isError($item)) {
                    return true;
                }
            }
        }
        return false;
    }
}
