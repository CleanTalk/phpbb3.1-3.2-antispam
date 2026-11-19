<?php

namespace Cleantalk\Common\Firewall {
    class Firewall
    {
        public static $outcome;
        public static $url;

        public function __construct($api_key, $log_table)
        {
        }

        public function getUpdater()
        {
            return $this;
        }

        public function update()
        {
            return $this->execute();
        }

        public function sendLogs()
        {
            return $this->execute();
        }

        private function execute()
        {
            self::$url = \Cleantalk\Custom\RemoteCalls\RemoteCalls::getSiteUrl();
            if (self::$outcome instanceof \Throwable) {
                throw self::$outcome;
            }
            return self::$outcome;
        }
    }
}

namespace {
    $root = dirname(__DIR__, 4);
    require $root . '/phpbb/request/request_interface.php';
    require $root . '/phpbb/request/type_cast_helper_interface.php';
    require $root . '/phpbb/request/type_cast_helper.php';
    require $root . '/phpbb/request/deactivated_super_global.php';
    require $root . '/phpbb/request/request.php';
    require $root . '/phpbb/config/config.php';
    require $root . '/phpbb/cron/task/task.php';
    require $root . '/phpbb/cron/task/base.php';
    require __DIR__ . '/../model/SuperGlobals.php';
    require __DIR__ . '/../cron/task/cleantalk_antispam_sfw_update.php';
    require __DIR__ . '/../cron/task/cleantalk_antispam_sfw_logs_send.php';
    require __DIR__ . '/../lib/autoload.php';

    function check($condition, $message)
    {
        if (!$condition) {
            throw new \RuntimeException($message);
        }
    }

    $_SERVER['HTTPS'] = 'on';
    $_SERVER['HTTP_HOST'] = 'forum.example';
    $request = new \phpbb\request\request();
    $tasks = array(
        'cleantalk_antispam_sfw_update' => 'cleantalk_antispam_sfw_update_last_gc',
        'cleantalk_antispam_sfw_logs_send' => 'cleantalk_antispam_sfw_logs_send_last_gc',
    );

    foreach ($tasks as $task_name => $last_gc) {
        foreach (array(true, false) as $disabled) {
            foreach (array('success', 'failure', 'exception', 'error') as $scenario) {
                $request->enable_super_globals();
                if ($disabled) {
                    $request->disable_super_globals();
                }
                $config = new \phpbb\config\config(array('cleantalk_antispam_apikey' => 'test', $last_gc => 0));
                $class = '\\cleantalk\\antispam\\cron\\task\\' . $task_name;
                $task = new $class($config, $request);
                \Cleantalk\Common\Firewall\Firewall::$url = null;
                switch ($scenario) {
                    case 'failure':
                        \Cleantalk\Common\Firewall\Firewall::$outcome = array('error' => 'test');
                        break;
                    case 'exception':
                        \Cleantalk\Common\Firewall\Firewall::$outcome = new \Exception('expected test exception');
                        break;
                    case 'error':
                        \Cleantalk\Common\Firewall\Firewall::$outcome = new \Error('expected test error');
                        break;
                    default:
                        \Cleantalk\Common\Firewall\Firewall::$outcome = array();
                }

                try {
                    $task->run();
                    check($scenario !== 'error', 'Error should propagate');
                } catch (\Error $e) {
                    check($scenario === 'error' && $e->getMessage() === 'expected test error', 'Unexpected error');
                }

                $label = $task_name . ' ' . $scenario . ' disabled=' . (int) $disabled;
                check(\Cleantalk\Common\Firewall\Firewall::$url === 'https://forum.example/', $label . ': URL');
                check($request->super_globals_disabled() === $disabled, $label . ': superglobals state');
                check(($config[$last_gc] > 0) === ($scenario === 'success'), $label . ': last run');
            }
        }
    }

    $request->enable_super_globals();
    echo "SFW cron superglobals checks passed\n";
}
