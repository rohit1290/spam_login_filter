<?php

namespace Spam\LoginFilter;

const PLUGIN_ID = 'spam_login_filter';
const UPGRADE_VERSION = 20180414;
const PLUGIN_DIR = __DIR__;

require_once __DIR__ . '/lib/hooks.php';
require_once __DIR__ . '/lib/events.php';
require_once __DIR__ . '/lib/functions.php';

elgg_register_event_handler('init', 'system', function() {
	// register hooks
	elgg_register_plugin_hook_handler("action:validate", "register", __NAMESPACE__ . "\\verify_action_hook");
	elgg_register_plugin_hook_handler("action:validate", "login", __NAMESPACE__ . "\\login_action_hook");
	elgg_register_plugin_hook_handler('cron', 'daily', __NAMESPACE__ . '\\daily_cron');
	elgg_register_plugin_hook_handler('route:rewrite', 'all', __NAMESPACE__ . '\\filter_router');
	elgg_register_plugin_hook_handler('register', 'menu:user_hover', __NAMESPACE__ . '\\user_hover_menu', 1000);
	elgg_register_plugin_hook_handler('register', 'user', __NAMESPACE__ . '\\register_user');


	// register events
	// recored ip addresses for users on creation and each time they log in
	elgg_register_event_handler('login:before', 'user', __NAMESPACE__ . '\\login_event');
	elgg_register_event_handler('create', 'user', __NAMESPACE__ . '\\create_user_event');

	elgg_register_menu_item('page', [
		'name' => 'manageip',
		'href' => 'admin/administer_utilities/manageip',
		'text' => elgg_echo('admin:administer_utilities:manageip'),
		'context' => 'admin',
		'parent_name' => 'administer_utilities',
		'section' => 'administer',
	]);
});
