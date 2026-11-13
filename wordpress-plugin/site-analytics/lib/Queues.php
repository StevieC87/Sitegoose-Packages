<?php
// Job queues (protocol in sdk/protocols/queues.md): how many jobs wait, run,
// are delayed or kept as failed, how long the oldest waiting one has waited,
// and how many jobs this server added and finished, per queue a minute, to
// POST /events/server-queues (Health → Server speed → Jobs). Jobs piling up
// is what request timings can't show: every request is quick, and the
// emails go out an hour late.
//
// PHP has no loop of its own between requests, so the readings come from
// whoever has one: a queue worker reads its queues at most once a minute
// between jobs (Laravel: the Looping event, Laravel\QueueWatch), and every
// process counts the jobs it adds and finishes. Both are appended to
// queues.jsonl in the state folder and sent once a minute, one minute at a
// time once it is over, by whichever process gets there: a worker after its
// reading, or a web request after its response.
//
// Gauges are the queue's own, so where several processes read one queue the
// dashboard takes the largest; the counts are this server's own (shared:
// false), which the dashboard adds up. A reading that fails is a gap, never
// a zero. Rides on the performance module's switch; 'queues' => false leaves
// it out.

namespace AnalyticsPlatform;

class Queues
{
    const SAMPLE_EVERY = 60;
    const MAX_QUEUES = 100;
    const MAX_ROWS = 500;
    const SPOOL_MAX = 1000000;
    const SYSTEMS = array('bullmq', 'bull', 'sidekiq', 'laravel', 'celery', 'rq', 'hangfire', 'asynq', 'rabbitmq', 'other');
    // A row's gauges, in a line's order after system, broker and queue.
    const GAUGES = array('waiting', 'running', 'delayed', 'failed', 'oldest_s');

    private $core;
    private $options;
    // This process, so the collector can tell a batch resent after a failed
    // answer from another process's with the same counts.
    private $sender;
    // system\0broker\0queue -> array(system, broker, queue, added, finished):
    // this process's counts since they were last spooled, null for one it
    // doesn't count.
    private $counts = array();
    private $readAt = 0;
    private $shutdown = false;

    // Options: server_name (default the host name).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '');
        $this->sender = bin2hex(random_bytes(8));
    }

    public function sender()
    {
        return $this->sender;
    }

    // Jobs this process added to a queue and finished from it (done, or
    // failed for good: an attempt that will be retried isn't finished).
    // null for a count this process doesn't keep; 0 says it keeps it.
    public function count($system, $broker, $queue, $added, $finished)
    {
        try {
            if (!$this->core->isOn('performance')) {
                return;
            }
            $key = self::keyOf($system, $broker, $queue);
            if ($key === null) {
                return;
            }
            if (!isset($this->counts[$key])) {
                if (count($this->counts) >= self::MAX_QUEUES) {
                    return;
                }
                $this->counts[$key] = array(self::systemOf($system), self::cut($broker), self::cut($queue), null, null);
            }
            if ($added !== null) {
                $this->counts[$key][3] = (int) $this->counts[$key][3] + max(0, (int) $added);
            }
            if ($finished !== null) {
                $this->counts[$key][4] = (int) $this->counts[$key][4] + max(0, (int) $finished);
            }
            // A worker stopping keeps what it counted since its last reading.
            if (!$this->shutdown && PHP_SAPI === 'cli') {
                $this->shutdown = true;
                register_shutdown_function(array($this, 'onShutdown'));
            }
        } catch (\Throwable $e) {
            // not counted
        }
    }

    // Whether this process should read its queues now: once a minute.
    public function readingDue()
    {
        return time() - $this->readAt >= self::SAMPLE_EVERY && $this->core->isOn('performance');
    }

    // A reading of some queues: each array('system', 'broker', 'queue' and
    // the gauges, left out or null where the system can't say, every one
    // of them for a queue that couldn't be read). Spooled with this
    // process's counts, which start again from 0.
    public function record(array $readings)
    {
        $this->readAt = time();
        if (!$this->core->isOn('performance') || !$this->core->ensureDir()) {
            return;
        }
        $rows = array();
        foreach ($readings as $reading) {
            if (!is_array($reading) || !isset($reading['system'], $reading['broker'], $reading['queue'])) {
                continue;
            }
            $key = self::keyOf($reading['system'], $reading['broker'], $reading['queue']);
            if ($key === null || isset($rows[$key])) {
                continue;
            }
            $row = array(self::systemOf($reading['system']), self::cut($reading['broker']), self::cut($reading['queue']));
            foreach (self::GAUGES as $gauge) {
                $row[] = isset($reading[$gauge]) && is_numeric($reading[$gauge]) ? max(0, (int) $reading[$gauge]) : null;
            }
            $row[] = isset($this->counts[$key]) ? $this->counts[$key][3] : null;
            $row[] = isset($this->counts[$key]) ? $this->counts[$key][4] : null;
            // Not read and nothing counted: a gap, not a row.
            if (array_filter(array_slice($row, 3), function ($value) {
                return $value !== null;
            }) === array()) {
                continue;
            }
            $rows[$key] = $row;
            if (count($rows) >= self::MAX_QUEUES) {
                break;
            }
        }
        // Counts of queues this reading didn't cover.
        foreach ($this->counts as $key => $entry) {
            if (!isset($rows[$key]) && ($entry[3] || $entry[4])) {
                $rows[$key] = array($entry[0], $entry[1], $entry[2], null, null, null, null, null, $entry[3], $entry[4]);
            }
        }
        $this->reset();
        if ($rows) {
            $this->core->append('queues', array('t' => time(), 'q' => array_values($rows)), self::SPOOL_MAX);
        }
    }

    // This process's counts so far, spooled (the end of a request, or a
    // worker stopping).
    public function save()
    {
        $rows = array();
        foreach ($this->counts as $entry) {
            if ($entry[3] || $entry[4]) {
                $rows[] = array($entry[0], $entry[1], $entry[2], null, null, null, null, null, $entry[3], $entry[4]);
            }
        }
        $this->reset();
        if ($rows && $this->core->isOn('performance') && $this->core->ensureDir()) {
            $this->core->append('queues', array('t' => time(), 'q' => $rows), self::SPOOL_MAX);
        }
    }

    // Counts start again from 0, and those this process doesn't keep stay null.
    private function reset()
    {
        foreach ($this->counts as $key => $entry) {
            $this->counts[$key][3] = $entry[3] === null ? null : 0;
            $this->counts[$key][4] = $entry[4] === null ? null : 0;
        }
    }

    public function onShutdown()
    {
        try {
            $this->save();
            $this->core->within(Core::DEADLINE, function () {
                $this->flush(true);
            });
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    public function due()
    {
        return $this->core->waiting('queues') && $this->core->sendDue('queues', self::SAMPLE_EVERY);
    }

    // Adds the lines up per minute and queue and sends the minutes that are
    // over (all of them with $force): the largest of each gauge, the sum of
    // each count. The minute still running goes back to wait, so one
    // sender never sends two halves of a minute.
    public function flush($force = false)
    {
        $this->core->drain('queues', self::SAMPLE_EVERY, $force, function (array $lines) use ($force) {
            $current = (int) (floor(time() / 60) * 60);
            $rows = array();
            foreach ($lines as $line) {
                if (!isset($line['t'], $line['q']) || !is_array($line['q'])) {
                    continue;
                }
                $minute = (int) (floor($line['t'] / 60) * 60);
                if (!$force && $minute >= $current) {
                    $this->core->append('queues', $line, self::SPOOL_MAX);
                    continue;
                }
                foreach ($line['q'] as $item) {
                    if (!is_array($item) || count($item) < 10) {
                        continue;
                    }
                    $key = json_encode(array($minute, (string) $item[0], (string) $item[1], (string) $item[2]));
                    if (!isset($rows[$key])) {
                        if (count($rows) >= self::MAX_QUEUES * 10) {
                            continue;
                        }
                        $rows[$key] = array('minute' => gmdate('Y-m-d\TH:i:s.000\Z', $minute), 'system' => self::systemOf($item[0]),
                            'broker' => self::cut($item[1]), 'queue' => self::cut($item[2]),
                            'waiting' => null, 'running' => null, 'delayed' => null, 'failed' => null, 'oldest_s' => null,
                            'added' => null, 'finished' => null, 'shared' => false);
                    }
                    foreach (self::GAUGES as $i => $gauge) {
                        $value = $item[3 + $i];
                        if (is_int($value) && ($rows[$key][$gauge] === null || $value > $rows[$key][$gauge])) {
                            $rows[$key][$gauge] = $value;
                        }
                    }
                    foreach (array('added' => 8, 'finished' => 9) as $name => $i) {
                        if (is_int($item[$i])) {
                            $rows[$key][$name] = (int) $rows[$key][$name] + $item[$i];
                        }
                    }
                }
            }
            foreach (array_chunk(array_values($rows), self::MAX_ROWS) as $batch) {
                $this->core->post('queues', '/events/server-queues', array(
                    'site_id' => (string) $this->core->opt('site_id'),
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'sender' => $this->sender,
                    'rows' => $batch,
                ), 'bearer');
            }
        });
    }

    private static function keyOf($system, $broker, $queue)
    {
        $broker = self::cut($broker);
        $queue = self::cut($queue);
        if ($broker === '' || $queue === '') {
            return null;
        }
        return self::systemOf($system) . "\0" . $broker . "\0" . $queue;
    }

    private static function systemOf($system)
    {
        $name = strtolower(is_scalar($system) ? (string) $system : '');
        return in_array($name, self::SYSTEMS, true) ? $name : 'other';
    }

    private static function cut($text)
    {
        $text = is_scalar($text) ? trim((string) $text) : '';
        return function_exists('mb_substr') ? mb_substr($text, 0, 200, 'UTF-8') : substr($text, 0, 200);
    }
}
