<?php

namespace Cleantalk\Common\Firewall;

use Cleantalk\Common\Db\DbTablesCreator;
use Cleantalk\Common\Db\Schema;
use Cleantalk\Common\Firewall\Exceptions\SfwUpdateException;
use Cleantalk\Common\Firewall\Exceptions\SfwUpdateExit;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Queue\Queue;
use Cleantalk\Common\Variables\Request;

class FirewallUpdater
{
    /**
     * @var string
     */
    private $api_key;

    /**
     * @var \Cleantalk\Common\RemoteCalls\RemoteCalls
     */
    private $rc;

    /**
     * @var \Cleantalk\Common\Queue\Queue
     */
    private $queue;

    /**
     * @var \Cleantalk\Common\Cron\Cron
     */
    private $cron;

    /**
     * @var Firewall
     */
    private $fw;

    /**
     * @var FwStats
     */
    private $fwStats;

    public $debug = false;

    /**
     * FirewallUpdater constructor.
     *
     * @param Firewall $fw
     */
    public function __construct($fw)
    {
        $this->rc = Mloader::get('RemoteCalls');
        $this->queue = Mloader::get('Queue');
        $this->fw = $fw;
        $this->api_key = $fw->api_key;
        $this->fwStats = $fw::getFwStats();
    }

    public function update()
    {
        try {
            if ( Request::get('worker') ) {
                return $this->updateWorker();
            }
            return $this->updateInit();
        } catch ( SfwUpdateException $e ) {
            $this->saveSfwUpdateError($e);
        } catch ( SfwUpdateExit $e ) {
            $this->logSfwExit($e);
        }

        return false;
    }

    /**
     * Called by sfw_update remote call
     * Starts SFW update and could use a delay before start
     *
     * @param int $delay
     *
     * @return bool|string|string[]
     */
    private function updateInit($delay = 0)
    {
        // Prevent start an update if update is already running and started less than 10 minutes ago
        if (
            $this->fwStats->updating_id &&
            time() - $this->fwStats->updating_last_start < 600 &&
            $this->isUpdateInProgress()
        ) {
            throw new SfwUpdateExit(
                'updateInit: Prevent start an update if update is already running and started less than 10 minutes ago'
            );
        }

        // The Access key is empty
        if ( !$this->api_key ) {
            throw new SfwUpdateException('updateInit: API key is empty');
        }

        // Get update period for server
        /** @var \Cleantalk\Common\Dns\Dns $dns_class */
        $dns_class = Mloader::get('Dns');
        $fw_class = $this->fw;
        $rc_class = $this->rc;
        $update_period = $dns_class::getRecord('spamfirewall-ttl-txt.cleantalk.org', true, DNS_TXT);
        $update_period = isset($update_period['txt']) ? $update_period['txt'] : 0;
        $update_period = (int)$update_period > 14400 ? (int)$update_period : 14400;
        if ( $this->fwStats->update_period != $update_period ) {
            $this->fwStats->update_period = $update_period;
            $fw_class::saveFwStats($this->fwStats);
        }

        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler */
        $storage_handler = Mloader::get('StorageHandler');
        $this->fwStats->updating_folder = $storage_handler::getUpdatingFolder();

        $prepare_dir__result = $this->prepareUpdDir();
        $test_rc_result = $rc_class::perform(
            'sfw_update',
            'apbct',
            $this->api_key,
            ['test' => 'test']
        );

        // Clear errors here
        $this->fwStats->errors = [];

        // Set a new update ID and an update time start
        $this->fwStats->calls = 0;
        $this->fwStats->updating_id = md5((string)rand(0, 100000));
        $this->fwStats->updating_last_start = time();
        $fw_class::saveFwStats($this->fwStats);

        if ( (is_array($prepare_dir__result) && !empty($prepare_dir__result['error'])) || !empty($test_rc_result['error']) ) {
            return $this->directUpdate();
        }

        Queue::clearQueue();

        $queue = new Queue($this->api_key);
        $queue->addStage([self::class, 'getMultifiles']);

        $cron = new \Cleantalk\Common\Cron\Cron();
        $cron->addTask(
            'sfw_update_checker',
            '\Cleantalk\Common\Firewall\FirewallUpdater::apbctSfwUpdateChecker',
            15,
            null,
            [$this->api_key]
        );

        return $rc_class::perform(
            'sfw_update',
            'apbct',
            $this->api_key,
            array(
                'firewall_updating_id' => $this->fwStats->updating_id,
                'delay' => $delay,
                'worker' => 1,
            ),
            ['async']
        );
    }

    /**
     * Called by sfw_update__worker remote call
     * gather all process about SFW updating
     *
     * @param bool $checker_work
     *
     * @return array|bool|int|string|string[]
     * @throws SfwUpdateException
     */
    private function updateWorker($checker_work = false)
    {
        if ( !$checker_work ) {
            if (
                Request::equal('firewall_updating_id', '') ||
                !Request::equal('firewall_updating_id', $this->fwStats->updating_id)
            ) {
                throw new SfwUpdateException('updateWorker: Wrong update ID');
            }
        }

        if ( !isset($this->fwStats->calls) ) {
            $this->fwStats->calls = 0;
        }

        $fw_class = $this->fw;
        $this->fwStats->calls++;
        $fw_class::saveFwStats($this->fwStats);

        if ( $this->fwStats->calls > 600 ) {
            throw new SfwUpdateException('updateWorker: Worker call limit exceeded');
        }

        $queue = new $this->queue($this->api_key);

        if ( count($queue->queue['stages']) === 0 ) {
            // Queue is already empty. Exit.
            throw new SfwUpdateExit('updateWorker: Queue is already empty. Exit.');
        }

        $result = $queue->executeStage();

        if ( $result === null ) {
            // The stage is in progress, will try to wait up to 5 seconds to its complete
            for ( $i = 0; $i < 5; $i++ ) {
                sleep(1);
                $queue->refreshQueue();
                if ( !$queue->isQueueInProgress() ) {
                    // The stage executed, break waiting and continue sfw_update__worker process
                    break;
                }
                if ( $i >= 4 ) {
                    // The stage still not executed, exit from sfw_update__worker
                    throw new SfwUpdateExit('updateWorker: The stage still not executed, exit from sfw_update__worker');
                }
            }
        }

        if ( isset($result['error'], $result['status']) && $result['status'] === 'FINISHED' ) {
            $this->updateFallback();

            $direct_upd_res = $this->directUpdate();

            if ( $direct_upd_res['error'] ) {
                throw new SfwUpdateException($direct_upd_res['error']);
            }
            throw new SfwUpdateExit('updateWorker: Direct update executed success.');
        }

        if ( $queue->isQueueFinished() ) {
            $queue->queue['finished'] = time();
            $queue->saveQueue($queue->queue);
            foreach ( $queue->queue['stages'] as $stage ) {
                if ( isset($stage['error'], $stage['status']) && $stage['status'] !== 'FINISHED' ) {
                    //there could be an array of errors of files processed
                    if ( is_array($stage['error']) ) {
                        $error = implode(" ", array_values($stage['error']));
                    } else {
                        $error = $result['error'];
                    }
                    throw new SfwUpdateException($error);
                }
            }

            // Do logging the queue process here
            throw new SfwUpdateExit('updateWorker: Queue finished success.');
        }


        // This is the repeat stage request, do not generate any new RC
        if ( stripos(Request::get('stage'), 'Repeat') !== false ) {
            throw new SfwUpdateExit('updateWorker: This is the `repeat` stage. Skipping making new RC.');
        }
        $rc_class = $this->rc;
        return $rc_class::perform(
            'sfw_update',
            'apbct',
            $this->api_key,
            array(
                'firewall_updating_id' => $this->fwStats->updating_id,
                'worker' => 1,
            ),
            array('async')
        );
    }

    public static function getMultifiles($api_key)
    {
        // The Access key is empty
        if ( !$api_key ) {
            throw new SfwUpdateException('getMultifiles: API key is empty');
        }

        $fw_stats = Firewall::getFwStats();
        /** @var \Cleantalk\Common\Api\Api $api_class */
        $api_class = Mloader::get('Api');
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        $urls = array();

        // Getting common lists
        $result = $api_class::methodGet2sBlacklistsDb($api_key, 'multifiles', '3_2', 1);

        if ( empty($result['error']) ) {
            if ( !empty($result['file_url']) ) {
                $file_urls = $helper_class::httpGetDataFromRemoteGzAndParseCsv($result['file_url']);
                if ( empty($file_urls['error']) ) {
                    // Extract common_lists_url_id from the file URL
                    preg_match('/bl_list_(.+)\.multifiles/m', $result['file_url'], $url_id_common);
                    if ( isset($url_id_common[1]) ) {
                        $fw_stats->common_lists_url_id = $url_id_common[1];
                    }
                    if ( !empty($result['file_ua_url']) ) {
                        $file_urls[][0] = $result['file_ua_url'];
                    }
                    if ( !empty($result['file_ck_url']) ) {
                        $file_urls[][0] = $result['file_ck_url'];
                    }
                    foreach ( $file_urls as $value ) {
                        $urls[] = $value[0];
                    }
                } else {
                    throw new SfwUpdateException('getMultifiles: common: ' . $file_urls['error']);
                }
            }
        } else {
            return $result;
        }

        // Getting personal lists
        $result_personal = $api_class::methodGet2sBlacklistsDb($api_key, 'multifiles', '3_2', 0);

        if ( empty($result_personal['error']) ) {
            if ( !empty($result_personal['file_url']) ) {
                $file_urls_personal = $helper_class::httpGetDataFromRemoteGzAndParseCsv($result_personal['file_url']);
                if ( empty($file_urls_personal['error']) ) {
                    // Extract personal_lists_url_id from the file URL
                    preg_match('/bl_list_(.+)\.multifiles/m', $result_personal['file_url'], $url_id);
                    if ( isset($url_id[1]) ) {
                        $fw_stats->personal_lists_url_id = $url_id[1];
                    }
                    if ( !empty($result_personal['file_ck_url']) ) {
                        $file_urls_personal[][0] = $result_personal['file_ck_url'];
                    }
                    foreach ( $file_urls_personal as $value ) {
                        $urls[] = $value[0];
                    }
                }
            }
        }

        if ( empty($urls) ) {
            throw new SfwUpdateException('getMultifiles: No URLs to download');
        }

        $tries_for_download_again = 3 + (int)(count($urls) / 20);
        $fw_stats->update_percent = round(100 / count($urls), 2);
        Firewall::saveFwStats($fw_stats);

        return array(
            'next_stage' => array(
                'name' => [self::class, 'downloadFiles'],
                'args' => $urls,
                'accepted_tries' => $tries_for_download_again
            )
        );
    }

    public static function downloadFiles($api_key, $urls)
    {
        // The Access key is empty
        if ( !$api_key ) {
            throw new SfwUpdateException('downloadFiles: API key is empty');
        }

        $fw_stats = Firewall::getFwStats();
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        sleep(3);

        $urls_array = array_chunk($urls, 18);
        $results_array = [];

        foreach ( $urls_array as $_urls ) {
            //Reset keys
            $_urls = array_values($_urls);
            $results_array[] = $helper_class::httpMultiRequest(array_slice($_urls, 0, 50), $fw_stats->updating_folder);
        }

        $results = [];
        foreach ($results_array as $result) {
            foreach ( $result as $key => $value ) {
                $results[$key] = $value;
            }
        }

        $count_urls = count($urls);
        $count_results = count($results);

        if ( empty($results['error']) && ($count_urls === $count_results) ) {
            $download_again = array();
            $results = array_values($results);
            for ( $i = 0; $i < $count_results; $i++ ) {
                if ( $results[$i] === 'error' ) {
                    $download_again[] = $urls[$i];
                }
            }

            if ( count($download_again) !== 0 ) {
                return array(
                    'error' => 'Files download not completed.',
                    'update_args' => array(
                        'args' => $download_again
                    )
                );
            }

            return array(
                'next_stage' => array(
                    'name' => [self::class, 'createTables']
                )
            );
        }

        if ( !empty($results['error']) ) {
            throw new SfwUpdateException('downloadFiles: ' . $results['error']);
        }

        throw new SfwUpdateException('downloadFiles: Files download not completed');
    }

    public static function createTables($_api_key)
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        // Preparing database infrastructure
        // Creating SFW tables to make sure that they are exists
        $db_tables_creator = new DbTablesCreator();
        $table_name_sfw = $db_obj->prefix . Schema::getSchemaTablePrefix() . 'sfw';
        $db_tables_creator->createTable($table_name_sfw);
        $table_name_sfw_personal = $db_obj->prefix . Schema::getSchemaTablePrefix() . 'sfw_personal';
        $db_tables_creator->createTable($table_name_sfw_personal);
        $table_name_ua = $db_obj->prefix . Schema::getSchemaTablePrefix() . 'ua_bl';
        $db_tables_creator->createTable($table_name_ua);

        return array(
            'next_stage' => array(
                'name' => [self::class, 'createTempTables'],
            )
        );
    }

    public static function createTempTables($_api_key)
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        // Preparing temporary tables for common SFW
        $result = \Cleantalk\Common\Firewall\Modules\Sfw::createTempTables(
            $db_obj,
            $db_obj->prefix . APBCT_TBL_FIREWALL_DATA
        );
        if ( !empty($result['error']) ) {
            throw new SfwUpdateException('createTempTables: ' . $result['error']);
        }

        // Preparing temporary tables for personal SFW
        $result = \Cleantalk\Common\Firewall\Modules\Sfw::createTempTables(
            $db_obj,
            $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL
        );
        if ( !empty($result['error']) ) {
            throw new SfwUpdateException('createTempTables personal: ' . $result['error']);
        }

        return array(
            'next_stage' => array(
                'name' => [self::class, 'processFiles'],
            )
        );
    }

    public static function processFiles($_api_key)
    {
        $fw_stats = Firewall::getFwStats();
        $files = glob($fw_stats->updating_folder . '/*csv.gz');
        $files = array_filter($files, static function ($element) {
            return strpos($element, 'list') !== false;
        });

        if ( count($files) ) {
            reset($files);
            $concrete_file = current($files);

            if ( strpos($concrete_file, 'bl_list') !== false ) {
                // Determine direction: personal or common
                if (
                    !empty($fw_stats->personal_lists_url_id)
                    && strpos($concrete_file, $fw_stats->personal_lists_url_id) !== false
                ) {
                    $direction = 'personal';
                } elseif (
                    !empty($fw_stats->common_lists_url_id)
                    && strpos($concrete_file, $fw_stats->common_lists_url_id) !== false
                ) {
                    $direction = 'common';
                } else {
                    $direction = 'common';
                }
                $result = self::processFile($concrete_file, $direction);
            }

            if ( strpos($concrete_file, 'ua_list') !== false ) {
                $result = self::processUa($concrete_file);
            }

            if ( strpos($concrete_file, 'ck_list') !== false ) {
                $result = self::processCk($concrete_file);
            }

            if ( !empty($result['error']) ) {
                throw new SfwUpdateException('processFiles: ' . $concrete_file . ' -> ' . $result['error']);
            }

            $fw_stats = Firewall::getFwStats();
            $fw_stats->update_percent = round(100 / count($files), 2);
            Firewall::saveFwStats($fw_stats);

            return array(
                'next_stage' => array(
                    'name' => [self::class, 'processFiles'],
                )
            );
        }

        return array(
            'next_stage' => array(
                'name' => [self::class, 'processExclusions'],
            )
        );
    }

    public static function processFile($file_path, $direction = 'common')
    {
        if ( !file_exists($file_path) ) {
            return array('error' => 'PROCESS FILE: ' . $file_path . ' is not exists.');
        }

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        $table_name = $direction === 'common'
            ? $db_obj->prefix . APBCT_TBL_FIREWALL_DATA . '_temp'
            : $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL . '_temp';

        $include_source = $direction === 'common';

        $result = \Cleantalk\Common\Firewall\Modules\Sfw::updateWriteToDb(
            $db_obj,
            $table_name,
            $file_path,
            $include_source
        );

        if ( !empty($result['error']) ) {
            throw new SfwUpdateException('processFile: ' . $file_path . ' -> ' . $result['error']);
        }

        if ( !is_int($result) ) {
            throw new SfwUpdateException('processFiles: ' . $file_path . ' -> WRONG RESPONSE FROM update__write_to_db');
        }

        return $result;
    }

    public static function processUa($file_path)
    {
        $result = \Cleantalk\Common\Firewall\Modules\AntiCrawler::update($file_path);

        if ( !empty($result['error']) ) {
            throw new SfwUpdateException('processUa: ' . $file_path . ' -> ' . $result['error']);
        }

        if ( !is_int($result) ) {
            throw new SfwUpdateException('processUa: ' . $file_path . ' ->  WRONG_RESPONSE AntiCrawler::update');
        }

        return $result;
    }

    public static function processCk($file_path)
    {
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        // Save expected_networks_count and expected_ua_count if exists
        $file_content = file_get_contents($file_path);

        if ( !function_exists('gzdecode') ) {
            throw new SfwUpdateException(
                'processCk: Function gzdecode not exists. Please update your PHP at least to version 5.4'
            );
        }

        $unzipped_content = gzdecode($file_content);

        if ( $unzipped_content === false ) {
            throw new SfwUpdateException('processCk: Can not unpack datafile');
        }

        $fw_stats = Firewall::getFwStats();
        $file_ck_url__data = $helper_class::bufferParseCsv($unzipped_content);

        if ( !empty($file_ck_url__data['error']) ) {
            throw new SfwUpdateException(
                'processCk: ' . $file_path . ' ->  GET EXPECTED RECORDS COUNT DATA: ' . $file_ck_url__data['error']
            );
        }

        $expected_networks_count = 0;
        $expected_ua_count = 0;

        // Determine if this is a personal ck_list
        $is_personal_ck =
        !empty($fw_stats->personal_lists_url_id) &&
        strpos($file_path, $fw_stats->personal_lists_url_id) !==
        false;

        foreach ( $file_ck_url__data as $value ) {
            if ( trim($value[0], '"') === 'networks_count' ) {
                $expected_networks_count = $value[1];
            }
            if ( trim($value[0], '"') === 'ua_count' ) {
                $expected_ua_count = $value[1];
            }
        }

        if ( $is_personal_ck ) {
            $fw_stats->expected_networks_count_personal = $expected_networks_count;
        } else {
            $fw_stats->expected_networks_count = $expected_networks_count;
            $fw_stats->expected_ua_count = $expected_ua_count;
        }
        Firewall::saveFwStats($fw_stats);

        if ( file_exists($file_path) ) {
            unlink($file_path);
        }
    }

    public static function processExclusions($_api_key)
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        $result = \Cleantalk\Common\Firewall\Modules\Sfw::updateWriteToDbExclusions(
            $db_obj,
            $db_obj->prefix . APBCT_TBL_FIREWALL_DATA . '_temp'
        );

        if ( !empty($result['error']) ) {
            throw new SfwUpdateException('processExclusions: ' . $result['error']);
        }

        if ( !is_int($result) ) {
            throw new SfwUpdateException('processExclusions: WRONG_RESPONSE update__write_to_db__exclusions');
        }

        /**
         * Update expected_networks_count
         */
        if ( $result > 0 ) {
            $fw_stats->expected_networks_count += $result;
            Firewall::saveFwStats($fw_stats);
        }

        return array(
            'next_stage' => array(
                'name' => [self::class, 'endOfUpdateRenamingTables'],
                'accepted_tries' => 1
            )
        );
    }

    public static function endOfUpdateRenamingTables($_api_key)
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        if ( !$db_obj->isTableExists($db_obj->prefix . APBCT_TBL_FIREWALL_DATA . '_temp') ) {
            throw new SfwUpdateException('endOfUpdateRenamingTables: SFW temp table does not exist');
        }

        $fw_stats->update_mode = 1;
        Firewall::saveFwStats($fw_stats);
        usleep(10000);

        // ATOMIC REMOVE AND RENAME
        $result = \Cleantalk\Common\Firewall\Modules\Sfw::replaceDataTablesAtomically(
            $db_obj,
            $db_obj->prefix . APBCT_TBL_FIREWALL_DATA
        );

        if ( !empty($result['error']) ) {
            $fw_stats->update_mode = 0;
            Firewall::saveFwStats($fw_stats);
            throw new SfwUpdateException('endOfUpdateRenamingTables: ' . $result['error']);
        }

        // ATOMIC REMOVE AND RENAME personal table
        if ( $db_obj->isTableExists($db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL . '_temp') ) {
            $result = \Cleantalk\Common\Firewall\Modules\Sfw::replaceDataTablesAtomically(
                $db_obj,
                $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL
            );
            if ( !empty($result['error']) ) {
                $fw_stats->update_mode = 0;
                Firewall::saveFwStats($fw_stats);
                throw new SfwUpdateException('endOfUpdateRenamingTables personal: ' . $result['error']);
            }
        }

        $fw_stats->update_mode = 0;
        Firewall::saveFwStats($fw_stats);

        return array(
            'next_stage' => array(
                'name' => [self::class, 'endOfUpdateCheckingData'],
                'accepted_tries' => 1
            )
        );
    }

    public static function endOfUpdateCheckingData($_api_key)
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        if ( !$db_obj->isTableExists($db_obj->prefix . APBCT_TBL_FIREWALL_DATA) ) {
            throw new SfwUpdateException('endOfUpdateCheckingData: SFW main table does not exist');
        }

        $entries = $db_obj->setQuery('')->getVar('SELECT COUNT(*) FROM ' . $db_obj->prefix . APBCT_TBL_FIREWALL_DATA);

        /**
         * Checking the integrity of the sfw database update
         */
        if ( $entries != $fw_stats->expected_networks_count ) {
            throw new SfwUpdateException(
                'endOfUpdateCheckingData: '
                . 'The discrepancy between the amount of data received for the update and in the final table: '
                . $db_obj->prefix . APBCT_TBL_FIREWALL_DATA
                . '. RECEIVED: ' . $fw_stats->expected_networks_count
                . '. ADDED: ' . $entries
            );
        }

        $fw_stats->entries = $entries;
        // Check personal table entries if exists
        if ( $db_obj->isTableExists($db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL) ) {
            $entries_personal = $db_obj->setQuery('')->getVar(
                'SELECT COUNT(*) FROM ' . $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL
            );
            $fw_stats->entries_personal = $entries_personal;
        }
        Firewall::saveFwStats($fw_stats);

        return array(
            'next_stage' => array(
                'name' => [self::class, 'endOfUpdateUpdatingStats'],
                'accepted_tries' => 1
            )
        );
    }

    public static function endOfUpdateUpdatingStats($_api_key, $is_direct_update = false)
    {
        $fw_stats = Firewall::getFwStats();

        $is_first_updating = !$fw_stats->last_update_time;
        $fw_stats->last_update_time = time();
        $fw_stats->last_update_way = $is_direct_update ? 'Direct update' : 'Queue update';
        Firewall::saveFwStats($fw_stats);

        return array(
            'next_stage' => array(
                'name' => [self::class, 'endOfUpdate'],
                'accepted_tries' => 1,
                'args' => $is_first_updating
            )
        );
    }

    public static function endOfUpdate($_api_key, $is_first_updating = false)
    {
        // @ToDo implement errors handling
        // Delete update errors
        //$apbct->errorDelete('sfw_update', true);

        // @ToDo implement this!
        // Running sfw update once again in 12 min if entries is < 4000
        /*if ( $is_first_updating &&
            $apbct->stats['sfw']['entries'] < 4000
        ) {
            wp_schedule_single_event(time() + 720, 'apbct_sfw_update__init');
        }*/

        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\Cron\Cron $cron_class */
        $cron_class = Mloader::get('Cron');

        $cron = new $cron_class();
        $sfw_update_handler = defined(
            'APBCT_CRON_HANDLER__SFW_UPDATE'
        ) ? APBCT_CRON_HANDLER__SFW_UPDATE : 'apbct_sfw_update__init';
        $cron->updateTask('sfw_update', $sfw_update_handler, $fw_stats->update_period);
        $cron->removeTask('sfw_update_checker');

        self::removeUpdDir($fw_stats->updating_folder);

        // Reset all FW stats
        $fw_stats->update_percent = 0;
        $fw_stats->updating_id = null;
        $fw_stats->expected_networks_count = false;
        $fw_stats->expected_networks_count_personal = false;
        $fw_stats->expected_ua_count = false;
        $fw_stats->personal_lists_url_id = null;
        $fw_stats->common_lists_url_id = null;
        Firewall::saveFwStats($fw_stats);

        return true;
    }

    private function prepareUpdDir()
    {
        $dir_name = $this->fwStats->updating_folder;

        if ( $dir_name === '' ) {
            return array('error' => 'FW dir can not be blank.');
        }

        if ( !is_dir($dir_name) ) {
            if ( !mkdir($dir_name) && !is_dir($dir_name) ) {
                return array('error' => 'Can not to make FW dir.');
            }
        } else {
            $files = glob($dir_name . '/*');
            if ( $files === false ) {
                return array('error' => 'Can not find FW files.');
            }
            if ( count($files) === 0 ) {
                return (bool)file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
            }
            foreach ( $files as $file ) {
                if ( is_file($file) && unlink($file) === false ) {
                    return array('error' => 'Can not delete the FW file: ' . $file);
                }
            }
        }

        return (bool)file_put_contents($dir_name . 'index.php', '<?php');
    }

    private static function removeUpdDir($dir_name)
    {
        if ( is_dir($dir_name) ) {
            $files = glob($dir_name . '/*');

            if ( !empty($files) ) {
                foreach ( $files as $file ) {
                    if ( is_file($file) ) {
                        unlink($file);
                    }
                    if ( is_dir($file) ) {
                        self::removeUpdDir($file);
                    }
                }
            }

            //add more paths if some strange files has been detected
            $non_cleantalk_files_filepaths = array(
                $dir_name . '.last.jpegoptim'
            );

            foreach ( $non_cleantalk_files_filepaths as $filepath ) {
                if ( file_exists($filepath) && is_file($filepath) && !is_writable($filepath) ) {
                    unlink($filepath);
                }
            }

            rmdir($dir_name);
        }
    }

    public static function apbctSfwUpdateChecker($api_key)
    {
        $queue = new \Cleantalk\Common\Queue\Queue($api_key);
        if ( count($queue->queue['stages']) ) {
            foreach ( $queue->queue['stages'] as $stage ) {
                if ( $stage['status'] === 'NULL' ) {
                    // @ToDo Have to be implemented this!
                    //return updateWorker(true);
                }
            }
        }

        return true;
    }

    public function directUpdate()
    {
        // The Access key is empty
        if ( empty($this->api_key) ) {
            return array('error' => 'SFW DIRECT UPDATE: KEY_IS_EMPTY');
        }

        // Getting BL
        $result = \Cleantalk\Common\Firewall\Modules\Sfw::directUpdateGetBlackLists($this->api_key);

        if ( empty($result['error']) ) {
            $fw_stats = Firewall::getFwStats();

            /** @var \Cleantalk\Common\Db\Db $db_class */
            $db_class = Mloader::get('Db');
            $db_obj = $db_class::getInstance();

            $blacklists = $result['blacklist'];
            $useragents = $result['useragents'];
            $bl_count = $result['bl_count'];
            $ua_count = $result['ua_count'];

            if ( isset($bl_count, $ua_count) ) {
                $fw_stats->expected_networks_count = $bl_count;
                $fw_stats->expected_ua_count = $ua_count;
                Firewall::saveFwStats($fw_stats);
            }

            // Preparing database infrastructure
            $db_tables_creator = new DbTablesCreator();
            $table_name = $db_obj->prefix . Schema::getSchemaTablePrefix() . 'sfw';
            $db_tables_creator->createTable($table_name);
            $table_name_personal = $db_obj->prefix . Schema::getSchemaTablePrefix() . 'sfw_personal';
            $db_tables_creator->createTable($table_name_personal);

            $result__creating_tmp_table = \Cleantalk\Common\Firewall\Modules\SFW::createTempTables(
                $db_obj,
                $db_obj->prefix . APBCT_TBL_FIREWALL_DATA
            );
            if ( !empty($result__creating_tmp_table['error']) ) {
                return array('error' => 'DIRECT UPDATING CREATE TMP TABLE: ' . $result__creating_tmp_table['error']);
            }

            // Create personal temp table
            $result__creating_tmp_table_personal = \Cleantalk\Common\Firewall\Modules\SFW::createTempTables(
                $db_obj,
                $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL
            );
            if ( !empty($result__creating_tmp_table_personal['error']) ) {
                return array('error' => 'DIRECT UPDATING CREATE PERSONAL TMP TABLE: ' . $result__creating_tmp_table_personal['error']);
            }

            /**
             * UPDATING UA LIST
             */
            if ( $useragents ) {
                $ua_result = \Cleantalk\Common\Firewall\Modules\AntiCrawler::directUpdate($useragents);

                if ( !empty($ua_result['error']) ) {
                    return array('error' => 'DIRECT UPDATING UA LIST: ' . $result['error']);
                }

                if ( !is_int($ua_result) ) {
                    return array('error' => 'DIRECT UPDATING UA LIST: : WRONG_RESPONSE AntiCrawler::directUpdate');
                }
            }

            /**
             * UPDATING BLACK LIST
             */
            $upd_result = \Cleantalk\Common\Firewall\Modules\SFW::directUpdate(
                $db_obj,
                $db_obj->prefix . APBCT_TBL_FIREWALL_DATA . '_temp',
                $blacklists
            );

            if ( !empty($upd_result['error']) ) {
                return array('error' => 'DIRECT UPDATING BLACK LIST: ' . $upd_result['error']);
            }

            if ( !is_int($upd_result) ) {
                return array('error' => 'DIRECT UPDATING BLACK LIST: WRONG RESPONSE FROM SFW::directUpdate');
            }

            /**
             * UPDATING PERSONAL LIST
             */
            $result_personal = \Cleantalk\Common\Firewall\Modules\Sfw::directUpdateGetBlackListsPersonal($this->api_key);
            if ( empty($result_personal['error']) && !empty($result_personal['blacklist']) ) {
                $personal_blacklists = $result_personal['blacklist'];

                $upd_result_personal = \Cleantalk\Common\Firewall\Modules\SFW::directUpdate(
                    $db_obj,
                    $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL . '_temp',
                    $personal_blacklists
                );

                if ( !empty($upd_result_personal['error']) ) {
                    // Personal lists errors are not critical, continue update
                }

                if ( is_int($upd_result_personal) ) {
                    $fw_stats = Firewall::getFwStats();
                    $fw_stats->expected_networks_count_personal = $upd_result_personal;
                    Firewall::saveFwStats($fw_stats);
                }
            }

            /**
             * UPDATING EXCLUSIONS LIST
             */
            $excl_result = self::processExclusions('');

            if ( !empty($excl_result['error']) ) {
                return array('error' => 'DIRECT UPDATING EXCLUSIONS: ' . $excl_result['error']);
            }

            /**
             * DELETING AND RENAMING THE TABLES
             */
            $rename_tables_res = self::endOfUpdateRenamingTables('');
            if ( !empty($rename_tables_res['error']) ) {
                return array('error' => 'DIRECT UPDATING BLACK LIST: ' . $rename_tables_res['error']);
            }

            /**
             * CHECKING THE UPDATE
             */
            $check_data_res = self::endOfUpdateCheckingData('');
            if ( !empty($check_data_res['error']) ) {
                return array('error' => 'DIRECT UPDATING BLACK LIST: ' . $check_data_res['error']);
            }

            /**
             * WRITE UPDATING STATS
             */
            $update_stats_res = self::endOfUpdateUpdatingStats('', true);
            if ( !empty($update_stats_res['error']) ) {
                return array('error' => 'DIRECT UPDATING BLACK LIST: ' . $update_stats_res['error']);
            }

            /**
             * END OF UPDATE
             */
            return self::endOfUpdate('');
        }

        return $result;
    }

    public static function cleanData()
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db_obj = $db_class::getInstance();

        \Cleantalk\Common\Firewall\Modules\SFW::dataTablesDelete(
            $db_obj,
            $db_obj->prefix . APBCT_TBL_FIREWALL_DATA . '_temp'
        );

        \Cleantalk\Common\Firewall\Modules\SFW::dataTablesDelete(
            $db_obj,
            $db_obj->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL . '_temp'
        );

        $fw_stats->firewall_update_percent = 0;
        $fw_stats->firewall_updating_id = null;
        Firewall::saveFwStats($fw_stats);
    }

    public function updateFallback()
    {
        $fw_stats = Firewall::getFwStats();

        /**
         * Remove the upd folder
         */
        if ( $fw_stats->updating_folder ) {
            self::removeUpdDir($fw_stats->updating_folder);
        }

        /**
         * Remove SFW updating checker cron-task
         */
        $cron = new \Cleantalk\Common\Cron\Cron();
        $cron->removeTask('sfw_update_checker');
        $sfw_update_handler = defined(
            'APBCT_CRON_HANDLER__SFW_UPDATE'
        ) ? APBCT_CRON_HANDLER__SFW_UPDATE : 'apbct_sfw_update__init';
        $cron->updateTask('sfw_update', $sfw_update_handler, $fw_stats->update_period);

        /**
         * Remove _temp table
         */
        self::cleanData();

        /**
         * Create SFW table if not exists
         */
        self::createTables('');
    }

    private function isUpdateInProgress()
    {
        return (new $this->queue($this->api_key))->isQueueInProgress();
    }

    /**
     * Show warning in the admin panel and write error log.
     * @param SfwUpdateException $e
     * @return void
     */
    private function saveSfwUpdateError(SfwUpdateException $e)
    {
        $fw_stats = Firewall::getFwStats();
        $fw_stats->errors[time()] = $e->getMessage();
        Firewall::saveFwStats($fw_stats);
        if ( $this->debug ) {
            error_log($e->getMessage());
        }
    }

    /**
     * Write to the stderr
     *
     * @param SfwUpdateExit $e
     * @return void
     */
    private function logSfwExit(SfwUpdateExit $e)
    {
        if ( $this->debug ) {
            error_log($e->getMessage());
        }
    }
}
