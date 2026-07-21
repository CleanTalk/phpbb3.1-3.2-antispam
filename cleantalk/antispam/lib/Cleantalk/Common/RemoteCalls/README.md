Install:

`composer require cleantalk/remote-calls`

Using:

```php
<?php

$storage_handler = new \Cleantalk\Custom\StorageHandler\StorageHandler();
$api_key = 'your_api_key';

$remote_calls = new \Cleantalk\Common\RemoteCalls\RemoteCalls($api_key, $storage_handler);

if ( $remote_calls::check() ) {
    try {
        die $remote_calls->process();
    } catch ( \Cleantalk\Common\RemoteCalls\Exceptions\RemoteCallsException $exception ) {
        // Do logging here
        die 'FAIL ' . json_encode(array('error' => $exception->getMessage()))
    }
}
```