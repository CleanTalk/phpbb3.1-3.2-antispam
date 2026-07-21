<?php

namespace Cleantalk\Custom\Db;

/**
 * phpBB-specific database driver for CleanTalk common libraries.
 * Wraps phpBB's driver_interface using global $db and $table_prefix.
 */
class Db extends \Cleantalk\Common\Db\Db
{
    /**
     * @var \phpbb\db\driver\driver_interface
     */
    private $phpbb_db;

    /**
     * @var int|null
     */
    private $affected_rows;

    /**
     * Initialize database connection using phpBB globals.
     */
    protected function init($params = array())
    {
        global $db, $table_prefix;

        $this->phpbb_db = $db;
        $this->prefix = $table_prefix;
    }

    /**
     * @inheritdoc
     */
    public function execute($query, $return_affected = false)
    {
        // Suppress phpBB's fatal error on SQL failures — Common libraries expect false on error
        $this->phpbb_db->sql_return_on_error(true);
        $result = $this->phpbb_db->sql_query($query);
        $this->phpbb_db->sql_return_on_error(false);

        $this->affected_rows = $this->phpbb_db->sql_affectedrows();

        return $result !== false;
    }

    /**
     * @inheritdoc
     */
    public function fetch($query = '', $response_type = false)
    {
        $query = $query ?: $this->getQuery();
        $result = $this->phpbb_db->sql_query($query);
        $row = $this->phpbb_db->sql_fetchrow($result);
        $this->phpbb_db->sql_freeresult($result);

        $this->result = $row ?: array();

        return $this->result;
    }

    /**
     * @inheritdoc
     */
    public function fetchAll($query = '', $response_type = false)
    {
        $query = $query ?: $this->getQuery();
        $result = $this->phpbb_db->sql_query($query);
        $rows = $this->phpbb_db->sql_fetchrowset($result);
        $this->phpbb_db->sql_freeresult($result);

        $this->result = $rows ?: array();

        return $this->result;
    }

    /**
     * @inheritdoc
     */
    public function getAffectedRows()
    {
        return $this->affected_rows !== null ? $this->affected_rows : 0;
    }

    /**
     * @inheritdoc
     */
    public function isTableExists($table_name)
    {
        $result = $this->phpbb_db->sql_query("SHOW TABLES LIKE '" . $this->phpbb_db->sql_escape($table_name) . "'");
        $row = $this->phpbb_db->sql_fetchrow($result);
        $this->phpbb_db->sql_freeresult($result);

        return !empty($row);
    }

    /**
     * @inheritdoc
     */
    public function getLastError()
    {
        return $this->phpbb_db->sql_error();
    }
}
