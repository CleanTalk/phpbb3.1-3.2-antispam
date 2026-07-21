<?php

namespace Cleantalk\Custom\StorageHandler;

use Cleantalk\Common\Mloader\Mloader;

/**
 * phpBB-specific storage handler for CleanTalk common libraries.
 * Uses cleantalk_custom_storage table for persistent key-value storage.
 */
class StorageHandler implements \Cleantalk\Common\StorageHandler\StorageHandler
{
    /**
     * @var \Cleantalk\Common\Db\Db
     */
    private $db_object;

    /**
     * @var string
     */
    private $table_name;

    public function __construct()
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $this->db_object = $db_class::getInstance();
        $this->table_name = $this->db_object->prefix . 'cleantalk_custom_storage';
    }

    /**
     * @inheritdoc
     */
    public function getSetting($setting_name)
    {
        $setting_name_escaped = addslashes($setting_name);
        $query = "SELECT value FROM {$this->table_name} WHERE name = '{$setting_name_escaped}'";
        $result_raw = $this->db_object->fetch($query);

        if ($result_raw && isset($result_raw['value'])) {
            return json_decode($result_raw['value'], true);
        }

        return null;
    }

    /**
     * @inheritdoc
     */
    public function deleteSetting($setting_name)
    {
        $setting_name_escaped = addslashes($setting_name);
        $query = "DELETE FROM {$this->table_name} WHERE name = '{$setting_name_escaped}'";

        return $this->db_object->execute($query);
    }

    /**
     * @inheritdoc
     */
    public function saveSetting($setting_name, $setting_value)
    {
        is_int($setting_value) && $setting_value = (string) $setting_value;
        $setting_value_encoded = addslashes(json_encode($setting_value));
        $setting_name_escaped = addslashes($setting_name);

        // Try UPDATE first, then INSERT if no rows affected
        $query_update = "UPDATE {$this->table_name} SET value = '{$setting_value_encoded}' WHERE name = '{$setting_name_escaped}'";
        $this->db_object->execute($query_update);

        if ($this->db_object->getAffectedRows() === 0) {
            // Check if the row actually exists (it might exist but with the same value)
            $existing = $this->getSetting($setting_name);
            if ($existing === null) {
                $query_insert = "INSERT INTO {$this->table_name} (name, value) VALUES ('{$setting_name_escaped}', '{$setting_value_encoded}')";
                return $this->db_object->execute($query_insert);
            }
        }

        return true;
    }

    /**
     * @inheritdoc
     */
    public static function getUpdatingFolder()
    {
        $dir = dirname(dirname(dirname(dirname(__DIR__)))) . DIRECTORY_SEPARATOR . 'cleantalk_fw_files' . DIRECTORY_SEPARATOR;

        return $dir;
    }

    /**
     * @inheritdoc
     */
    public static function getJsLocation()
    {
        return '';
    }
}
