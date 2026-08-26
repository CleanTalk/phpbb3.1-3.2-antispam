<?php
/**
 * @package phpBB Extension - Antispam by CleanTalk
 * @author  CleanTalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

namespace cleantalk\antispam\migrations;

class release_5_9_0 extends \phpbb\db\migration\migration
{
    public function effectively_installed()
    {
        return $this->db_tools->sql_column_exists($this->table_prefix . 'cleantalk_sfw', 'source');
    }

    static public function depends_on()
    {
        return array('\cleantalk\antispam\migrations\release_5_7_7');
    }

    public function update_schema()
    {
        return array(
            'add_tables' => array(
                // Personal SFW lists table
                $this->table_prefix . 'cleantalk_sfw_personal' => array(
                    'COLUMNS' => array(
                        'id'      => array('UINT:11', null, 'auto_increment'),
                        'network' => array('UINT:11', 0),
                        'mask'    => array('UINT:11', 0),
                        'status'  => array('TINT:1', 0),
                    ),
                    'PRIMARY_KEY' => 'id',
                    'KEYS' => array(
                        'network_mask' => array('INDEX', array('network', 'mask')),
                    ),
                ),
                // Custom storage table for FwStats and other settings
                $this->table_prefix . 'cleantalk_custom_storage' => array(
                    'COLUMNS' => array(
                        'name'  => array('VCHAR:100', ''),
                        'value' => array('MTEXT_UNI', ''),
                    ),
                    'PRIMARY_KEY' => 'name',
                ),
                // User-Agent blacklist for AntiCrawler module
                $this->table_prefix . 'cleantalk_ua_bl' => array(
                    'COLUMNS' => array(
                        'id'          => array('UINT', 0),
                        'ua_template' => array('VCHAR:255', ''),
                        'ua_status'   => array('TINT:1', null),
                    ),
                    'PRIMARY_KEY' => 'id',
                    'KEYS' => array(
                        'ua_template' => array('INDEX', array('ua_template')),
                    ),
                ),
            ),
            'add_columns' => array(
                // Add source column to main SFW table
                $this->table_prefix . 'cleantalk_sfw' => array(
                    'source' => array('TINT:1', null),
                ),
                // Add new columns to SFW logs table
                $this->table_prefix . 'cleantalk_sfw_logs' => array(
                    'id'        => array('VCHAR:40', ''),
                    'status'    => array('VCHAR:40', ''),
                    'ua_id'     => array('INT:11', null),
                    'ua_name'   => array('VCHAR:1024', ''),
                    'source'    => array('TINT:1', null),
                    'network'   => array('VCHAR:20', ''),
                    'first_url' => array('VCHAR:100', ''),
                    'last_url'  => array('VCHAR:100', ''),
                ),
            ),
        );
    }

    /**
     * Custom migration step: rebuild sfw_logs PK from ip to id.
     */
    public function update_data()
    {
        return array(
            array('custom', array(array($this, 'rebuild_sfw_logs_pk'))),
        );
    }

    public function rebuild_sfw_logs_pk()
    {
        $table = $this->table_prefix . 'cleantalk_sfw_logs';

        // Only rebuild if id column exists but is not yet the PK
        // (fresh installs via add_columns will need this step)
        $this->db->sql_query("DELETE FROM {$table}");
        $this->db->sql_query("ALTER TABLE {$table} DROP PRIMARY KEY");
        $this->db->sql_query("ALTER TABLE {$table} ADD PRIMARY KEY (id)");
    }

    public function revert_schema()
    {
        return array(
            'drop_tables' => array(
                $this->table_prefix . 'cleantalk_sfw_personal',
                $this->table_prefix . 'cleantalk_custom_storage',
                $this->table_prefix . 'cleantalk_ua_bl',
            ),
            'drop_columns' => array(
                $this->table_prefix . 'cleantalk_sfw' => array(
                    'source',
                ),
                $this->table_prefix . 'cleantalk_sfw_logs' => array(
                    'id',
                    'status',
                    'ua_id',
                    'ua_name',
                    'source',
                    'network',
                    'first_url',
                    'last_url',
                ),
            ),
        );
    }
}
