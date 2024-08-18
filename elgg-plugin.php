<?php
require_once __DIR__ . '/lib/events.php';
require_once __DIR__ . '/lib/functions.php';

return [
	'plugin' => [
		'name' => 'Spam Login Filter',
		'version' => '6.0',
		'dependencies' => [],
	],
	'bootstrap' => SpamLoginFilter::class,
	'actions' => [
		'spam_login_filter/delete_ip' => [],
		'spam_login_filter/delete' => [],
	],
	'events' => [
		'register' => [
			'menu:admin_header' => [
				'Elgg\SpamLoginFilter\Menus\AdminHeader::register' => [],
			],
		],
	],
];
