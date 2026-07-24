<?php

namespace Cleantalk\Common\Queue;

use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Queue\Exceptions\QueueError;
use Cleantalk\Common\Queue\Exceptions\QueueExit;

class Queue
{
    const QUEUE_NAME = 'sfw_update_queue';

    public $queue;

    private $unstarted_stage;

    /**
     * @var string
     */
    private $api_key;

    /**
     * Process identifier
     *
     * @var int
     */
    private $pid;

    public function __construct($api_key)
    {
        $this->api_key = $api_key;
        $this->pid = mt_rand(0, mt_getrandmax());

        $queue = $this->getQueue();
        if ( $queue !== false && isset($queue['stages']) ) {
            $this->queue = $queue;
        } else {
            $this->queue = array(
                'started' => time(),
                'finished' => '',
                'stages' => array(),
            );
        }
    }

    public function getQueue()
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        return $storage_handler_class->getSetting(self::QUEUE_NAME);
    }

    public static function clearQueue()
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        return $storage_handler_class->deleteSetting(self::QUEUE_NAME);
    }

    public function saveQueue($queue)
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        return $storage_handler_class->saveSetting(self::QUEUE_NAME, $queue);
    }

    /**
     * Refreshes the $this->queue from the DB
     *
     * @return void
     */
    public function refreshQueue()
    {
        $this->queue = $this->getQueue();
    }

    /**
     * @param string|array $stage_name
     * @param array $args
     */
    public function addStage($stage_name, $args = array(), $accepted_tries = 3)
    {
        $this->queue['stages'][] = array(
            'name' => $stage_name,
            'status' => 'NULL',
            'tries' => '0',
            'accepted_tries' => $accepted_tries,
            'args' => $args,
            'pid' => null,
        );
        $this->saveQueue($this->queue);
    }

    /**
     * @throws QueueExit
     */
    public function executeStage()
    {
        // @ToDo need to replace this Firewall dependency
        $fw_stats = Firewall::getFwStats();
        $stage_to_execute = null;

        if ( $this->hasUnstartedStages() ) {
            $this->queue['stages'][$this->unstarted_stage]['status'] = 'IN_PROGRESS';
            $this->queue['stages'][$this->unstarted_stage]['start'] = time();
            $this->queue['stages'][$this->unstarted_stage]['pid'] = $this->pid;

            $this->saveQueue($this->queue);

            sleep(2);

            $this->refreshQueue();

            if ( $this->queue['stages'][$this->unstarted_stage]['pid'] !== $this->pid ) {
                throw new QueueExit(
                    'Queue pid is wrong for the stage ' . $this->queue['stages'][$this->unstarted_stage]['name']
                );
            }

            $stage_to_execute = &$this->queue['stages'][$this->unstarted_stage];
        }

        if ( $stage_to_execute ) {
            if ( is_array($stage_to_execute['name']) ) {
                $class_to_execute = $stage_to_execute['name'][0];
                $method_to_execute = $stage_to_execute['name'][1];
                if ( is_callable(array($class_to_execute, $method_to_execute)) ) {
                    ++$stage_to_execute['tries'];

                    if ( !empty($stage_to_execute['args']) ) {
                        $result = $class_to_execute::$method_to_execute($this->api_key, $stage_to_execute['args']);
                    } else {
                        $result = $class_to_execute::$method_to_execute($this->api_key);
                    }
                } else {
                    throw new QueueError(
                        $class_to_execute . '::' . $method_to_execute . ' is not a callable function.'
                    );
                }
            } else {
                if ( is_callable($stage_to_execute['name']) ) {
                    ++$stage_to_execute['tries'];

                    if ( !empty($stage_to_execute['args']) ) {
                        $result = $stage_to_execute['name']($stage_to_execute['args']);
                    } else {
                        $result = $stage_to_execute['name']();
                    }
                } else {
                    throw new QueueError($stage_to_execute['name'] . ' is not a callable function.');
                }
            }

            if ( isset($result['error']) ) {
                $stage_to_execute['status'] = 'NULL';
                $stage_to_execute['error'][] = $result['error'];
                if ( isset($result['update_args']['args']) ) {
                    $stage_to_execute['args'] = $result['update_args']['args'];
                }
                $this->saveQueue($this->queue);
                $accepted_tries = isset($stage_to_execute['accepted_tries']) ? $stage_to_execute['accepted_tries'] : 3;
                if ( $stage_to_execute['tries'] >= $accepted_tries ) {
                    $stage_to_execute['status'] = 'FINISHED';
                    $this->saveQueue($this->queue);
                    return $result;
                }

                /** @var \Cleantalk\Common\RemoteCalls\RemoteCalls $remote_calls_class */
                $remote_calls_class = Mloader::get('RemoteCalls');
                return $remote_calls_class::perform(
                    'sfw_update',
                    'apbct',
                    $this->api_key,
                    array(
                        'firewall_updating_id' => $fw_stats->updating_id,
                        'worker' => 1,
                        'stage' => 'Repeat ' .
                        is_array($stage_to_execute['name'])
                            ? $stage_to_execute['name'][0] . '::' . $stage_to_execute['name'][1]
                            : $stage_to_execute['name']
                    ),
                    array('async')
                );
            }

            if ( isset($result['next_stage']) ) {
                $this->addStage(
                    $result['next_stage']['name'],
                    isset($result['next_stage']['args']) ? $result['next_stage']['args'] : array(),
                    isset($result['next_stage']['accepted_tries']) ? $result['next_stage']['accepted_tries'] : 3
                );
            }

            if ( isset($result['next_stages']) && count($result['next_stages']) ) {
                foreach ( $result['next_stages'] as $next_stage ) {
                    $this->addStage(
                        $next_stage['name'],
                        isset($next_stage['args']) ? $next_stage['args'] : array(),
                        isset($result['next_stage']['accepted_tries']) ? $result['next_stage']['accepted_tries'] : 3
                    );
                }
            }

            $stage_to_execute['status'] = 'FINISHED';
            $this->saveQueue($this->queue);

            return $result;
        }

        throw new QueueExit('No stage to execute. Exit.');
    }

    public function isQueueInProgress()
    {
        if ( count($this->queue['stages']) > 0 ) {
            $this->unstarted_stage = array_search('IN_PROGRESS', array_column($this->queue['stages'], 'status'), true);

            return is_int($this->unstarted_stage);
        }

        return false;
    }

    public function isQueueFinished()
    {
        return !$this->isQueueInProgress() && !$this->hasUnstartedStages();
    }

    /**
     * Checks if the queue is over
     *
     * @return bool
     */
    public function hasUnstartedStages()
    {
        if ( count($this->queue['stages']) > 0 ) {
            $this->unstarted_stage = array_search('NULL', array_column($this->queue['stages'], 'status'), true);

            return is_int($this->unstarted_stage);
        }

        return false;
    }
}
