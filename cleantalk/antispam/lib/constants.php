<?php

/**
 * CleanTalk constants for phpBB extension.
 * Table names (without DB prefix — prefix is added by the Db driver).
 */

if (!defined('APBCT_TBL_FIREWALL_DATA')) {
    define('APBCT_TBL_FIREWALL_DATA', 'cleantalk_sfw');
}
if (!defined('APBCT_TBL_FIREWALL_DATA_PERSONAL')) {
    define('APBCT_TBL_FIREWALL_DATA_PERSONAL', 'cleantalk_sfw_personal');
}
if (!defined('APBCT_TBL_FIREWALL_LOG')) {
    define('APBCT_TBL_FIREWALL_LOG', 'cleantalk_sfw_logs');
}
if (!defined('APBCT_TBL_AC_UA_BL')) {
    define('APBCT_TBL_AC_UA_BL', 'cleantalk_ua_bl');
}
if (!defined('APBCT_TBL_AC_LOG')) {
    define('APBCT_TBL_AC_LOG', 'cleantalk_ac_log');
}
if (!defined('APBCT_TBL_SESSIONS')) {
    define('APBCT_TBL_SESSIONS', 'cleantalk_sessions');
}
if (!defined('APBCT_TBL_STORAGE')) {
    define('APBCT_TBL_STORAGE', 'cleantalk_custom_storage');
}
if (!defined('APBCT_WRITE_LIMIT')) {
    define('APBCT_WRITE_LIMIT', 5000);
}
if (!defined('APBCT_SELECT_LIMIT')) {
    define('APBCT_SELECT_LIMIT', 5000);
}
if (!defined('APBCT_DIR_PATH')) {
    define('APBCT_DIR_PATH', dirname(__DIR__));
}
