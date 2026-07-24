Install:

`composer require cleantalk/cron`

Using:

```php
<?php

$cron = new $cron_class();
$cron_option = \Drupal::state()->get($cron->getCronOptionName());
if (empty($cron_option)) {
$cron->saveTasks($cron->getDefaultTasks());
}
$tasks_to_run = $cron->checkTasks(); // Check for current tasks. Drop tasks inner counters.

if (
! empty( $tasks_to_run ) && // There is tasks to run
! $rc_class::check() && // Do not doing CRON in remote call action
(
! defined( 'DOING_CRON' ) ||
( defined( 'DOING_CRON' ) && DOING_CRON !== true )
)
){
$cron_res = $cron->runTasks( $tasks_to_run );
// Handle the $cron_res for errors here.
}
```