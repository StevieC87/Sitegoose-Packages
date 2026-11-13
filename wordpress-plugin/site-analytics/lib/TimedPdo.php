<?php
// Database queries for plain PHP (sdk/protocols/queries.md): a PDO that
// times what it runs, for Health → Server speed → Queries. Use it where you
// would use PDO; nothing else changes:
//
//   $db = new AnalyticsPlatform\TimedPdo('mysql:host=localhost;dbname=shop', $user, $password);
//
// exec() and query() are timed here, and a prepared statement's execute()
// by TimedPdoStatement, PDO's statement class for it (PDO::ATTR_STATEMENT_CLASS:
// PDO's own option for this, so nothing of PDO is patched). Two cases keep
// prepared statements untimed: a statement class of your own (yours is kept),
// and a persistent connection, which PHP won't give a statement class.
// Reported to the Platform's queries module (Queries::report()), so it may be
// made before the Platform is.

namespace AnalyticsPlatform;

class TimedPdo extends \PDO
{
    private $analyticsDb = 'other';

    public function __construct($dsn, $username = null, $password = null, $options = null)
    {
        parent::__construct($dsn, $username, $password, $options);
        try {
            $this->analyticsDb = Queries::databaseOfDriver($this->getAttribute(\PDO::ATTR_DRIVER_NAME));
            $options = is_array($options) ? $options : array();
            if (empty($options[\PDO::ATTR_PERSISTENT]) && !isset($options[\PDO::ATTR_STATEMENT_CLASS])) {
                $this->setAttribute(\PDO::ATTR_STATEMENT_CLASS, array(TimedPdoStatement::class, array($this->analyticsDb)));
            }
        } catch (\Throwable $e) {
            // untimed, but working
        }
    }

    #[\ReturnTypeWillChange]
    public function exec($statement)
    {
        return Queries::timed($this->analyticsDb, $statement, function () use ($statement) {
            return parent::exec($statement);
        });
    }

    #[\ReturnTypeWillChange]
    public function query($query, $fetchMode = null, ...$fetchModeArgs)
    {
        return Queries::timed($this->analyticsDb, $query, function () use ($query, $fetchMode, $fetchModeArgs) {
            return $fetchMode === null ? parent::query($query) : parent::query($query, $fetchMode, ...$fetchModeArgs);
        });
    }
}
