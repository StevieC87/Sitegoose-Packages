<?php
// What TimedRedis and TimedPredis share (sdk/protocols/queries.md, "Redis"):
// a multi(), pipeline() or transaction() up to its exec() is one call, its
// time every step of it, failed if any step failed.

namespace AnalyticsPlatform;

trait RedisGroup
{
    // The open group, or null: its prefix ("MULTI" or "PIPELINE"), its first
    // timed command, its time so far and whether a step failed.
    private $group = null;

    private static function newGroup($prefix)
    {
        return array($prefix, null, 0.0, false);
    }

    // A step's time: part of the open group (its first timed command names
    // the group), or with none open, a call of its own.
    private function settle($statement, $ms, $failed)
    {
        if ($this->group === null) {
            Queries::report('redis', $statement, $ms, $failed);
            return;
        }
        if ($this->group[1] === null) {
            $this->group[1] = $statement;
        }
        $this->group[2] += $ms;
        $this->group[3] = $this->group[3] || $failed;
    }

    // A group ended with its exec(): recorded unless none of its commands
    // was timed.
    private static function settleGroup(array $group, $ms, $failed)
    {
        if ($group[1] !== null) {
            Queries::report('redis', $group[0] . ' ' . $group[1], $group[2] + $ms, $group[3] || $failed);
        }
    }

    // Predis' pipeline(function ($pipe) {...}) and transaction(...): a
    // callback among the arguments.
    private static function hasCallback(array $params)
    {
        foreach ($params as $param) {
            if ($param instanceof \Closure || (is_object($param) && method_exists($param, '__invoke'))) {
                return true;
            }
        }
        return false;
    }
}
