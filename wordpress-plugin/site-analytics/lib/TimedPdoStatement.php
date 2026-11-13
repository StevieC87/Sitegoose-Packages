<?php
// TimedPdo's prepared statements: each execute() timed, under the statement's
// SQL (its values are bound parameters, never read). PDO makes these itself
// (PDO::ATTR_STATEMENT_CLASS), which is why the constructor isn't public.

namespace AnalyticsPlatform;

class TimedPdoStatement extends \PDOStatement
{
    private $analyticsDb;

    protected function __construct($db = 'other')
    {
        $this->analyticsDb = $db;
    }

    #[\ReturnTypeWillChange]
    public function execute($params = null)
    {
        return Queries::timed($this->analyticsDb, $this->queryString, function () use ($params) {
            return $params === null ? parent::execute() : parent::execute($params);
        });
    }
}
