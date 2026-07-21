<?php

namespace Cleantalk\Common\Db;

use Cleantalk\Common\Mloader\Mloader;

class DbTablesCreator
{
    /**
     * Create all plugin tables from Schema
     */
    public function createAllTables($prefix = '')
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        $db_schema = Schema::getStructureSchemas();
        $schema_prefix = Schema::getSchemaTablePrefix();
        $prefix = $prefix ?: $db_obj->prefix;

        foreach ($db_schema as $table_key => $table_schema) {
            $sql = 'CREATE TABLE IF NOT EXISTS `%s' . $schema_prefix . $table_key . '` (';
            $sql = sprintf($sql, $prefix);
            foreach ($table_schema as $column_name => $column_params) {
                if ($column_name !== '__indexes' && $column_name !== '__createkey') {
                    $sql .= '`' . $column_name . '` ' . $column_params . ', ';
                } elseif ($column_name === '__indexes') {
                    $sql .= $table_schema['__indexes'];
                }
            }
            $sql .= ');';

            $result = $db_obj->execute($sql);
            if ($result === false) {
                $errors[] = "Failed.\nQuery: $db_obj->last_query\nError: $db_obj->last_error";
            }
        }

        // Logging errors
        if (!empty($errors)) {
            //@ToDo implement errors handling
        }
    }

    /**
     * Create Table by table name
     */
    public function createTable($table_name)
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        $db_schema = Schema::getStructureSchemas();
        $schema_prefix = Schema::getSchemaTablePrefix();
        $table_key = explode($schema_prefix, $table_name)[1];
        $table_key = str_replace('_temp', '', $table_key);

        $sql = 'CREATE TABLE IF NOT EXISTS `' . $table_name . '` (';
        foreach ($db_schema[$table_key] as $column_name => $column_params) {
            if ($column_name !== '__indexes' && $column_name !== '__createkey') {
                $sql .= '`' . $column_name . '` ' . $column_params . ', ';
            } elseif ($column_name === '__indexes') {
                $sql .= $db_schema[$table_key]['__indexes'];
            }
        }
        $sql .= ');';

        $result = $db_obj->execute($sql);
        if ($result === false) {
            $errors[] = "Failed.\nQuery: $db_obj->last_query\nError: $db_obj->last_error";
        }

        // Logging errors
        if (!empty($errors)) {
            //@ToDo implement errors handling
        }
    }
}
