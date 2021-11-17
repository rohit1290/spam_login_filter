<?php
const PLUGIN_ID = 'spam_login_filter';
const UPGRADE_VERSION = 20180414;
const PLUGIN_DIR = __DIR__;

require_once __DIR__ . '/lib/hooks.php';
require_once __DIR__ . '/lib/events.php';
require_once __DIR__ . '/lib/functions.php';

return [
	'plugin' => [
		'name' => 'Spam Login Filter',
		'version' => '4.0',
		'dependencies' => [],
	],
	'bootstrap' => SpamLoginFilter::class,
	'actions' => [
		'spam_login_filter/delete_ip' => [],
		'spam_login_filter/delete' => [],
	],
];
