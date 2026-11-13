<?php
// ClickHouse queries for Server speed (sdk/protocols/queries.md), with
// smi2/phpclickhouse. Its client has no hook a query passes through, so this
// stands in front of the one you made and forwards everything to it:
//
//   $db = new AnalyticsPlatform\TimedClickHouse(new ClickHouseDB\Client($config));
//
// select(), write(), insert(), insertAssocBulk(), selectWithParams() and
// writeWithParams() are timed until they answer, as db "clickhouse";
// selectAsync() ones when executeAsync() has run them, each by its own
// transfer time. A select the server refused counts as failed even though the
// library only throws when you read it. insert() is counted as
// "INSERT INTO <table> (<columns>) VALUES (?)": its values are never read.
// Everything else goes straight through, and a method that hands back the
// client (database(), settings) hands back this, so chaining stays timed.
// Code that type-hints ClickHouseDB\Client can't take this: time those calls
// with $platform->recordQuery('clickhouse', $sql, $ms, $failed).
//
// Nothing of the library is changed. Reported to the Platform's queries
// module (Queries::report()), so it may be made before the Platform is.

namespace AnalyticsPlatform;

class TimedClickHouse
{
    private $client;
    // selectAsync() statements not yet run, with their SQL.
    private $pending = array();

    public function __construct($client)
    {
        $this->client = $client;
    }

    // The client this stands in front of.
    public function client()
    {
        return $this->client;
    }

    public function select($sql, ...$rest)
    {
        return $this->time((string) $sql, true, function () use ($sql, $rest) {
            return $this->client->select($sql, ...$rest);
        });
    }

    public function selectWithParams($sql, ...$rest)
    {
        return $this->time((string) $sql, true, function () use ($sql, $rest) {
            return $this->client->selectWithParams($sql, ...$rest);
        });
    }

    public function write($sql, ...$rest)
    {
        return $this->time((string) $sql, false, function () use ($sql, $rest) {
            return $this->client->write($sql, ...$rest);
        });
    }

    public function writeWithParams($sql, ...$rest)
    {
        return $this->time((string) $sql, false, function () use ($sql, $rest) {
            return $this->client->writeWithParams($sql, ...$rest);
        });
    }

    public function insert($table, $values, $columns = array(), ...$rest)
    {
        return $this->time(self::insertText($table, $columns), false, function () use ($table, $values, $columns, $rest) {
            return $this->client->insert($table, $values, $columns, ...$rest);
        });
    }

    public function insertAssocBulk($table, $values, ...$rest)
    {
        $first = is_array($values) && isset($values[0]) && is_array($values[0]) ? $values[0] : $values;
        return $this->time(self::insertText($table, is_array($first) ? array_keys($first) : array()), false, function () use ($table, $values, $rest) {
            return $this->client->insertAssocBulk($table, $values, ...$rest);
        });
    }

    public function selectAsync($sql, ...$rest)
    {
        $statement = $this->client->selectAsync($sql, ...$rest);
        if (count($this->pending) >= 1000) {
            $this->pending = array();
        }
        $this->pending[] = array($statement, (string) $sql);
        return $statement;
    }

    public function executeAsync(...$args)
    {
        $pending = $this->pending;
        $this->pending = array();
        $started = microtime(true);
        try {
            return $this->client->executeAsync(...$args);
        } finally {
            $all = (microtime(true) - $started) * 1000;
            foreach ($pending as $item) {
                list($statement, $sql) = $item;
                $ms = $all;
                $failed = false;
                try {
                    // The transfer's own time, from curl, when it has one.
                    $time = $statement->response()->total_time();
                    if (is_numeric($time) && $time >= 0) {
                        $ms = $time * 1000;
                    }
                    $failed = (bool) $statement->isError();
                } catch (\Throwable $e) {
                    $failed = true;
                }
                Queries::report('clickhouse', $sql, $ms, $failed);
            }
        }
    }

    public function __call($name, $args)
    {
        $result = $this->client->$name(...$args);
        return $result === $this->client ? $this : $result;
    }

    public function __get($name)
    {
        return $this->client->$name;
    }

    // Runs one query and reports it: failed when it threw, or (a select,
    // which throws only when read) when the statement says the server
    // refused it.
    private function time($sql, $select, callable $run)
    {
        $started = microtime(true);
        $failed = true;
        try {
            $statement = $run();
            $failed = false;
            if ($select && is_object($statement) && method_exists($statement, 'isError')) {
                try {
                    $failed = (bool) $statement->isError();
                } catch (\Throwable $e) {
                    $failed = true;
                }
            }
            return $statement;
        } finally {
            Queries::report('clickhouse', $sql, (microtime(true) - $started) * 1000, $failed);
        }
    }

    // What an insert is counted as: its table and columns, never its values.
    // Worked out before the insert runs, so nothing in it may warn or throw:
    // a framework's error handler would turn that into the insert failing.
    private static function insertText($table, $columns)
    {
        $text = 'INSERT INTO ' . (is_scalar($table) ? (string) $table : '?');
        $names = array();
        foreach (is_array($columns) ? $columns : array() as $column) {
            if (is_scalar($column)) {
                $names[] = (string) $column;
            }
        }
        if ($names) {
            $text .= ' (' . implode(', ', $names) . ')';
        }
        return $text . ' VALUES (?)';
    }
}
