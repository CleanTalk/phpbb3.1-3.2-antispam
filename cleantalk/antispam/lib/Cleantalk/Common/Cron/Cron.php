<?php

namespace Cleantalk\Common\Cron;

use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\StorageHandler\StorageHandler;

/**
 * CleanTalk Cron class
 *
 * @package Anti-Spam by CleanTalk
 * @Version 3.0.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */
class Cron
{
    public $debug = false;

    protected $tasks = array();           // Array with tasks
    protected $tasks_completed = array(); // Result of executed tasks

    // Option name with cron data
    protected $cron_option_name;

    // Interval in seconds for restarting the task
    protected $task_execution_min_interval;

    // Interval in seconds for cron work availability
    protected $cron_execution_min_interval;

    private $id;

    /**
     * Cron constructor.
     * Getting tasks option.
     *
     * @param string $cron_option_name
     * @param int $task_execution_min_interval
     * @param int $cron_execution_min_interval
     */
    public function __construct(
        $cron_option_name = 'cleantalk_cron',
        $task_execution_min_interval = 120,
        $cron_execution_min_interval = 120
    ) {
        /*
         * @todo perform this logic
        // Assign properties from the given parameters if exists
        // Notice that if $this->$param_name is NULL new value won't be set
        foreach( $params as $param_name => $param ){
            $this->$param_name = isset( $this->$param_name ) ? $param : null;
        }
        */

        $this->cron_option_name = $cron_option_name;
        $this->task_execution_min_interval = $task_execution_min_interval;
        $this->cron_execution_min_interval = $cron_execution_min_interval;
        if ( time() - $this->getCronLastStart() > $this->cron_execution_min_interval ) {
            if ( !$this->setCronLastStart() ) {
                return;
            }

            $this->tasks = $this->getTasks();

            if ( !empty($this->tasks) ) {
                $this->createId();
                usleep(10000); // 10 ms
            }
        }
    }

    /**
     * Get timestamp last Cron started.
     *
     * @return int timestamp
     */
    public function getCronLastStart()
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        return (int)$storage_handler_class->getSetting('cleantalk_cron_last_start');
    }

    /**
     * Save timestamp of running Cron.
     *
     * @return bool
     */
    public function setCronLastStart()
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        return $storage_handler_class->saveSetting('cleantalk_cron_last_start', time());
    }

    /**
     * Save option with tasks
     *
     * @param array $tasks
     *
     * @return bool
     */
    public function saveTasks($tasks)
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        return $storage_handler_class->saveSetting($this->cron_option_name, $tasks);
    }

    /**
     * Getting all tasks
     *
     * @return array
     */
    public function getTasks()
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        $tasks = $storage_handler_class->getSetting($this->cron_option_name);

        return empty($tasks) ? array() : $tasks;
    }

    /**
     * Adding new cron task.
     *
     * @param string $task
     * @param string $handler
     * @param int $period
     * @param null|int $first_call
     * @param array $params
     *
     * @return bool
     */
    public function addTask($task, $handler, $period, $first_call = null, $params = array())
    {
        // First call time() + period
        $first_call = !$first_call ? time() + $period : $first_call;

        $tasks = !empty($this->tasks) ? $this->tasks : $this->getTasks();

        if ( isset($tasks[$task]) ) {
            return false;
        }

        // Task entry
        $tasks[$task] = array(
            'handler' => $handler,
            'next_call' => $first_call,
            'period' => $period,
            'params' => $params,
        );

        return $this->saveTasks($tasks);
    }

    /**
     * Removing cron task
     *
     * @param string $task
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function removeTask($task)
    {
        $tasks = !empty($this->tasks) ? $this->tasks : $this->getTasks();
        if ( !isset($tasks[$task]) ) {
            return false;
        }

        unset($tasks[$task]);

        return $this->saveTasks($tasks);
    }

    /**
     * Updates cron task, create task if not exists.
     *
     * @param string $task
     * @param string $handler
     * @param int $period
     * @param null|int $first_call
     * @param array $params
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateTask($task, $handler, $period, $first_call = null, $params = array())
    {
        $tasks = !empty($this->tasks) ? $this->tasks : $this->getTasks();

        if ( isset($tasks[$task]) ) {
            // Rewrite the task
            $tasks[$task] = array(
                'handler' => $handler,
                'next_call' => is_null($first_call) ? time() + $period : $first_call,
                'period' => $period,
                'params' => $params,
                'last_call' => isset($tasks[$task]['last_call']) ? $tasks[$task]['last_call'] : 0,
            );

            return $this->saveTasks($tasks);
        }

        // Add task if it's disappeared
        return $this->addTask($task, $handler, $period, $first_call, $params);
    }

    /**
     * Get cron option name
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getCronOptionName()
    {
        return $this->cron_option_name;
    }

    /**
     * Getting tasks which should be run
     *
     * @return bool|array
     */
    public function checkTasks()
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();

        // No tasks to run
        if ( empty($this->tasks) || (string)$storage_handler_class->getSetting('cleantalk_cron_pid') !== (string)$this->id ) {
            return false;
        }

        //validate format of tasks
        $validated_tasks = array();
        foreach ($this->tasks as $task_name => $task_data) {
            if (!is_array($task_data)) {
                if ($this->debug) {
                    error_log(var_export('Task data is not array ' . $task_name, true));
                }
                continue;
            }

            if ( ! isset($task_data['params'])) {
                $task_data['params'] = array();
            }

            if (
                !isset(
                    $task_data['handler'],
                    $task_data['next_call'],
                    $task_data['period']
                )
            ) {
                if ($this->debug) {
                    error_log(var_export('Task data format is incorrect ' . $task_name, true));
                }
                continue;
            }

            if (!is_callable($task_data['handler'])) {
                if ($this->debug) {
                    error_log(var_export('Task data handler is not callable ' . $task_name, true));
                }
                continue;
            }

            $validated_tasks[$task_name] = $task_data;
        }

        $this->tasks = $validated_tasks;

        if ($this->debug) {
            error_log('Validated tasks ' . var_export($this->tasks, true));
        }

        $tasks_to_run = array();

        foreach ($this->tasks as $task => &$task_data) {
            if (
                ! isset($task_data['processing'], $task_data['last_call']) ||
                ($task_data['processing'] === true &&
                time() - $task_data['last_call'] > $this->task_execution_min_interval)
            ) {
                $task_data['processing'] = false;
                if ( ! isset($task_data['last_call'])) {
                    $task_data['last_call'] = 0;
                }
            }

            if (
                $task_data['processing'] === false &&
                $task_data['next_call'] <= time() // default condition
            ) {
                $task_data['processing'] = true;
                $task_data['last_call'] = time();

                $tasks_to_run[] = $task;
            }

            // Hard bug fix
            if ( !isset($task_data['params']) ) {
                $task_data['params'] = array();
            }
        }
        unset($task_data);

        $this->saveTasks($this->tasks);

        return $tasks_to_run;
    }

    /**
     * Run all tasks from $this->tasks_to_run.
     * Saving all results to (array) $this->tasks_completed
     *
     * @param $tasks
     *
     * @return void|array  Array of completed and uncompleted tasks.
     */
    public function runTasks($tasks)
    {
        if ( empty($tasks) ) {
            return;
        }

        foreach ( $tasks as $task ) {
            if ( is_callable($this->tasks[$task]['handler']) ) {
                if ( $this->debug ) {
                    error_log(var_export('Task ' . $task . ' will be run.', true));
                }

                $result = call_user_func_array(
                    $this->tasks[$task]['handler'],
                    isset($this->tasks[$task]['params']) ? $this->tasks[$task]['params'] : array()
                );

                if ( $this->debug ) {
                    error_log(var_export('Result:', true));
                    error_log(var_export($result, true));
                }

                if ( empty($result['error']) ) {
                    $this->tasks_completed[$task] = true;

                    if ( $this->tasks[$task]['period'] == 0 ) {
                        // One time scheduled event
                        unset($this->tasks[$task]);
                    } else {
                        // Multi time scheduled event
                        $this->tasks[$task]['next_call'] = time() + $this->tasks[$task]['period'];
                        $this->tasks[$task]['last_call'] = time();
                    }
                } else {
                    $this->tasks_completed[$task] = $result['error'];
                    $this->tasks[$task]['next_call'] = time() + $this->tasks[$task]['period'] / 4;
                    $this->tasks[$task]['last_call'] = time();
                }
            } else {
                $this->tasks_completed[$task] = $this->tasks[$task]['handler'] . '_IS_NOT_EXISTS';
            }
        }

        $this->saveTasks($this->tasks);

        return $this->tasks_completed;
    }

    /**
     * Generates and save Cron ID to the base
     */
    public function createId()
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();

        $this->id = mt_rand(0, mt_getrandmax());
        $storage_handler_class->saveSetting('cleantalk_cron_pid', $this->id);
    }

    /**
     * Service function for launching cron tasks
     *
     * @param string $task
     * @param int $time
     * @return void
     */
    public function serveCronActions($task, $time)
    {
        if ( ! is_string($task) || ! is_int($time) ) {
            return;
        }

        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();

        $tasks = $storage_handler_class->getSetting($this->cron_option_name);

        if ( ! isset($tasks[$task]) ) {
            return;
        }

        $tasks[$task]['next_call'] = $time;

        $this->saveTasks($tasks);
    }
}
