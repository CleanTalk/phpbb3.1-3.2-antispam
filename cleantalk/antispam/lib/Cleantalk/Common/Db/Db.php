<?php

namespace Cleantalk\Common\Db;

use Cleantalk\Common\Templates\Singleton;

/**
 * CleanTalk abstract Data Base driver.
 * Shows what should be inside.
 * Uses singleton pattern.
 *
 * @version 1.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam
 *
 * @psalm-suppress UnusedProperty
 * @psalm-suppress PossiblyUnusedProperty
 */
abstract class Db
{
    use Singleton;

    /**
     * @var string Query string
     */
    private $query;

    /**
     * @var array Processed result
     */
    public $result = array();

    /**
     * @var string Database prefix
     */
    public $prefix = '';

    /**
     * Alternative constructor.
     * Initialize Database object and write it to property.
     * Set tables prefix.
     */
    abstract protected function init();

    /**
     * Set $this->query string for next uses
     *
     * @param $query
     *
     * @return $this|void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function setQuery($query)
    {
        $this->query = $query;
        return $this;
    }

    public function getQuery()
    {
        return $this->query;
    }

    /**
     * Safely replace placeholders
     *
     * @param string $query
     * @param array $vars
     *
     * @return $this
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function prepare($query, $vars = array())
    {
        $query = $query ?: $this->query;
        $vars  = $vars ?: array();

        $this->query = call_user_func($this->getPreparingMethod(), $query, $vars);

        return $this;
    }

    /**
     * @important This is very weak protection method
     * @important Overload this method in CMS-based class
     */
    public function getPreparingMethod()
    {
        return [$this, 'simplePreparingMethod'];
    }

    private function simplePreparingMethod($query, $vars)
    {
        array_walk($vars, function (&$item) {
            $item = '"' . addslashes($item) . '"';
        });
        return vsprintf($query, $vars);
    }

    public function prepareAndExecute($query, $vars = array())
    {
        $this->prepare($query, $vars);
        return $this->execute($this->query);
    }

    /**
     * Run any raw request
     *
     * @param $query string
     * @param $return_affected bool Need to the drupal class
     *
     * @return bool|int|void Raw result
     * @psalm-suppress PossiblyUnusedParam
     */
    abstract public function execute($query, $return_affected = false);

    /**
     * Fetchs first column from query.
     * May receive raw or prepared query.
     *
     * @param string $query
     * @param bool|string $response_type
     *
     * @return array|object|void|null
     * @psalm-suppress PossiblyUnusedMethod
     */
    abstract public function fetch($query, $response_type = false);

    /**
     * Fetchs all result from query.
     * May receive raw or prepared query.
     *
     * @param string $query
     * @param bool|string $response_type
     *
     * @return array|object|null|void
     * @psalm-suppress PossiblyUnusedMethod
     */
    abstract public function fetchAll($query = '', $response_type = false);

    public function getVar($query)
    {
        return array_values($this->fetch($query))[0];
    }

    abstract public function getAffectedRows();

    /**
     * Checks if the table exists
     *
     * @param $table_name
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function isTableExists($table_name)
    {
        return (bool)$this->execute("SHOW TABLES LIKE '" . $table_name . "'");
    }

    public function getLastError()
    {
        return 'Not implemented';
    }

    public function sfwGetFromBlacklist($table_name, $personal_table_name, $needles, $current_ip_v4)
    {
        $query = "(SELECT
                    network, mask, status, source, 0 as is_personal
                    FROM " . $table_name . "
                    WHERE network IN (" . implode(',', $needles) . ")
                    AND	network = " . $current_ip_v4 . " & mask 
                    AND " . rand(1, 100000) . "  
                    ORDER BY status DESC LIMIT 1)";

        // Add personal table UNION if available
        if ( $personal_table_name && $this->isTableExists($personal_table_name) ) {
            $query .= " UNION (SELECT
                network, mask, status, NULL as source, 1 as is_personal
                FROM " . $personal_table_name . "
                WHERE network IN (" . implode(',', $needles) . ")
                AND	network = " . $current_ip_v4 . " & mask 
                AND " . rand(1, 100000) . "  
                ORDER BY status DESC LIMIT 1)";
        };
        return $query;
    }

    public function acGetFromBlacklist($table, $ip, $sign)
    {
        return "SELECT ip"
            . " FROM " . $table
            . " WHERE ip = '$ip'"
            . " AND ua = '$sign' AND " . rand(1, 100000) . ";";
    }

    public function afGetFromBlacklist($table, $ip, $time)
    {
        return "SELECT SUM(entries) as total_count"
            . ' FROM ' . $table
            . " WHERE ip = '$ip' AND interval_start > '$time' AND " . rand(1, 100000) . ";";
    }

    public function resetAutoIncrement($table_name)
    {
        return $this->execute("ALTER TABLE {$table_name} AUTO_INCREMENT = 1;"); // Drop AUTO INCREMENT
    }

    public function renameTable($old_name, $new_name)
    {
        return $this->execute('ALTER TABLE ' . $old_name . ' RENAME ' . $new_name . ';');
    }

    public function getUpdateLogQuery($table, $module_name, $status, $ip, $source)
    {
        $id   = md5($ip . $module_name);
        $time = time();
        return "INSERT INTO " . $table . "
                SET
                    id = '$id',
                    ip = '$ip',
                    status = '$status',
                    all_entries = 1,
                    blocked_entries = " . (strpos($status, 'DENY') !== false ? 1 : 0) . ",
                    entries_timestamp = '" . $time . "',
                    ua_name = %s,
                    source = $source,
                    network = %s,
                    first_url = %s,
                    last_url = %s
                ON DUPLICATE KEY
                UPDATE
                    status = '$status',
                    source = $source,
                    all_entries = all_entries + 1,
                    blocked_entries = blocked_entries" . (strpos($status, 'DENY') !== false ? ' + 1' : '') . ",
                    entries_timestamp = '" . $time . "',
                    ua_name = %s,
                    network = %s,
                    last_url = %s";
    }

    public function getUpdateAcLogQuery($table, $id, $current_ip, $sign, $interval_time)
    {
        return "INSERT INTO " . $table . " SET
                    id = '$id',
                    ip = '$current_ip',
                    ua = '$sign',
                    entries = 1,
                    interval_start = $interval_time
                ON DUPLICATE KEY UPDATE
                    ip = ip,
                    entries = entries + 1,
                    interval_start = $interval_time;";
    }

    public function getCLearAcQuery($table, $interval_start, $sign)
    {
        return "DELETE
                    FROM " . $table . "
                    WHERE interval_start < " . $interval_start . "
                    AND ua = '$sign'
                    LIMIT 100000;";
    }

    public function altCookiesStoreQuery($table)
    {
        return "INSERT INTO {$table}
                (id, name, value, last_update)
                VALUES (:id, :name, :value, :last_update)
                ON DUPLICATE KEY UPDATE
                value = :value,
                last_update = :last_update";
    }

    public function altCookiesClearQuery($table)
    {
        return "DELETE
                FROM {$table}
                WHERE last_update < NOW() - INTERVAL " . APBCT_SESSION__LIVE_TIME . " SECOND
                LIMIT 100000;";
    }
}
