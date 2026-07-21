<?php

namespace Cleantalk\Common\Firewall\Modules;

use Cleantalk\Common\Helper\Helper;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Cleaner\Validate;

class AntiCrawler
{
    public static function update($file_path_ua)
    {
        /** @var Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        $ua_table = $db_obj->prefix . APBCT_TBL_AC_UA_BL;

        $file_content = file_get_contents($file_path_ua);

        if ( function_exists('gzdecode') ) {
            $unzipped_content = gzdecode($file_content);

            if ( $unzipped_content !== false ) {
                $lines = $helper_class::bufferParseCsv($unzipped_content);

                if ( empty($lines['errors']) ) {
                    $result__clear_db = self::clearDataTable($db_obj, $ua_table);

                    if ( empty($result__clear_db['error']) ) {
                        for ( $count_result = 0; current($lines) !== false; ) {
                            $query = "INSERT INTO " . $ua_table . " (id, ua_template, ua_status) VALUES ";

                            for (
                                $i = 0, $values = array();
                                APBCT_WRITE_LIMIT !== $i && current($lines) !== false;
                                $i++, $count_result++, next($lines)
                            ) {
                                $entry = current($lines);

                                if ( empty($entry) || !isset($entry[0], $entry[1]) ) {
                                    continue;
                                }

                                // Cast result to int
                                $ua_id = preg_replace('/[^\d]*/', '', $entry[0]);
                                $ua_template = isset($entry[1]) && Validate::isRegexp($entry[1])
                                    ? $helper_class::dbPrepareParam($entry[1])
                                    : 0;
                                $ua_status = isset($entry[2]) ? $entry[2] : 0;

                                if ( !$ua_template ) {
                                    continue;
                                }

                                $values[] = '(' . $ua_id . ',' . $ua_template . ',' . $ua_status . ')';
                            }

                            if ( !empty($values) ) {
                                $query = $query . implode(',', $values) . ';';
                                $db_obj->execute($query);
                            }
                        }

                        if ( file_exists($file_path_ua) ) {
                            unlink($file_path_ua);
                        }

                        return $count_result;
                    } else {
                        return $result__clear_db;
                    }
                } else {
                    return array('error' => 'UAL_UPDATE_ERROR: ' . $lines['error']);
                }
            } else {
                return array('error' => 'Can not unpack datafile');
            }
        } else {
            return array('error' => 'Function gzdecode not exists. Please update your PHP at least to version 5.4 ');
        }
    }

    public static function directUpdate($useragents)
    {
        /** @var Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        $ua_table = $db_obj->prefix . APBCT_TBL_AC_UA_BL;

        $result__clear_db = self::clearDataTable($db_obj, $ua_table);

        if ( empty($result__clear_db['error']) ) {
            for ( $count_result = 0; current($useragents) !== false; ) {
                $query = "INSERT INTO " . $ua_table . " (id, ua_template, ua_status) VALUES ";

                for (
                    $i = 0, $values = array();
                    APBCT_WRITE_LIMIT !== $i && current($useragents) !== false;
                    $i++, $count_result++, next($useragents)
                ) {
                    $entry = current($useragents);

                    if ( empty($entry) ) {
                        continue;
                    }

                    // Cast result to int
                    // @ToDo check the output $entry
                    $ua_id = preg_replace('/[^\d]*/', '', $entry[0]);
                    $ua_template = isset($entry[1]) && Validate::isRegexp($entry[1]) ? $helper_class::dbPrepareParam(
                        $entry[1]
                    ) : 0;
                    $ua_status = isset($entry[2]) ? $entry[2] : 0;

                    $values[] = '(' . $ua_id . ',' . $ua_template . ',' . $ua_status . ')';
                }

                if ( !empty($values) ) {
                    $query = $query . implode(',', $values) . ';';
                    $result = $db_obj->execute($query);
                    if ( $result === false ) {
                        return array('error' => $db_obj->getLastError());
                    }
                }
            }

            return $count_result;
        }

        return $result__clear_db;
    }

    private static function clearDataTable($db, $db__table__data)
    {
        if ( ! $db->isTableExists($db__table__data) ) {
            // @ToDo need to handle errors here
            return;
        }
        $db->execute("TRUNCATE TABLE {$db__table__data};");
        $db->setQuery("SELECT COUNT(*) as cnt FROM {$db__table__data};")->fetch(); // Check if it is clear
        if ( $db->result['cnt'] != 0 ) {
            $db->execute("DELETE FROM {$db__table__data};"); // Truncate table
            $db->setQuery("SELECT COUNT(*) as cnt FROM {$db__table__data};")->fetch(); // Check if it is clear
            if ( $db->result['cnt'] != 0 ) {
                return array('error' => 'COULD_NOT_CLEAR_UA_BL_TABLE'); // throw an error
            }
        }
        $db->resetAutoIncrement($db__table__data);
    }
}
