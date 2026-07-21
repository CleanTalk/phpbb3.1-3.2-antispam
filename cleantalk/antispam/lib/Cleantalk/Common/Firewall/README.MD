## Install:

`composer require cleantalk/firewall`

## Using:

### Running checking FireWall

```php
<?php

namespace Cleantalk\Common\Firewall;

$api_key = 'API_KEY_HERE';
$fw_logs_table_name = 'TBL_FIREWALL_LOG';
$fw_data_table_name = 'TBL_FIREWALL_DATA';

try {
    $firewall = new Firewall($api_key, $fw_logs_table_name);

    $firewall->loadFwModule(
        new SFW($fw_logs_table_name, $fw_data_table_name)
    );
    
    $firewall->run();
} catch (\Exception $e) {
    error_log('CleanTalk Firewall is not loaded: ' . $e->getMessage());
}

```

### Running updating FireWall

```php
<?php

namespace Cleantalk\Common\Firewall;

$api_key = 'API_KEY_HERE';
$fw_logs_table_name = 'TBL_FIREWALL_LOG';

$firewall = new Firewall($api_key, $fw_logs_table_name);

$fw_updater = $firewall->getUpdater();
if ( defined('APBCT_SFW_DIRECT_UPDATE') && APBCT_SFW_DIRECT_UPDATE ) {
    return $fw_updater->directUpdate();
}
return $fw_updater->update();

```

### Running sending FireWall logs

```php
<?php

namespace Cleantalk\Common\Firewall;

$api_key = 'API_KEY_HERE';
$fw_logs_table_name = 'TBL_FIREWALL_LOG';

$firewall = new Firewall($api_key, $fw_logs_table_name);
return $firewall->sendLogs();

```