<?php

namespace Spam\LoginFilter;

require_once __DIR__ . '/lib/hooks.php';
require_once __DIR__ . '/lib/events.php';
require_once __DIR__ . '/lib/functions.php';

const PLUGIN_ID = 'spam_login_filter';
const UPGRADE_VERSION = 20141127;

elgg_register_event_handler('init', 'system', __NAMESPACE__ . '\\init');

function init() {

	// register hooks
	elgg_register_plugin_hook_handler("action", "register", __NAMESPACE__ . "\\verify_action_hook", 999);
	elgg_register_plugin_hook_handler('cron', 'daily', __NAMESPACE__ . '\\daily_cron');
	elgg_register_plugin_hook_handler('route', 'all', __NAMESPACE__ . '\\filter_router');

	// register events
	elgg_register_event_handler('login', 'user', __NAMESPACE__ . '\\login_event');

	elgg_register_admin_menu_item('administer', 'manageip', 'administer_utilities');
	
	
	// register actions
	elgg_register_action('spam_login_filter/delete_ip', __DIR__ . "/actions/delete_ip.php", 'admin');

	// Extend context menu with admin links
	if (elgg_is_admin_logged_in()) {
		if (elgg_is_active_plugin('tracker')) {
			elgg_register_plugin_hook_handler('register', 'menu:user_hover', __NAMESPACE__ . '\\user_hover_menu', 1000);
			elgg_register_action("spam_login_filter/delete", __DIR__ . "/actions/delete.php", "admin");
		}
	}

	return true;
}
