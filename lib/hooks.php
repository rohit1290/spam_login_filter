<?php

namespace Spam\LoginFilter;
use ElggMenuItem;


/**
 * called on register action - checks user ip/email against rules
 * 
 * @return boolean
 */
function verify_action_hook(\Elgg\Hook $hook) {
	//Check against stopforumspam and domain blacklist
	$return = $hook->getValue();
	$email = get_input('email');
	$ip = get_ip();

	if (check_spammer($email, $ip)) {
		return $return;
	}
	return false;
}


/**
 * called on daily cron - cleans up ip address cache
 */
function daily_cron() {
	
	$ia = elgg_set_ignore_access(true);
	
	//Retrieve the ips older than one week
	$week_ago = time() - 604800; //(7 * 24 * 60 * 60);
	
	elgg_delete_annotations(array(
		'guid' => elgg_get_site_entity()->guid,
		'annotation_names' => 'spam_login_filter_ip',
		'annotation_created_time_upper' => $week_ago,
		'limit' => false
	));

	elgg_set_ignore_access($ia);
}


function filter_router(\Elgg\Hook $hook) {
	
	$return = $hook->getValue();
	
  if (elgg_is_admin_logged_in()) {
    return $return;
  }

	// get uris to protect
	$protect_setting = elgg_get_plugin_setting('protected_pages', PLUGIN_ID);
	if (empty($protect_setting)) {
		return $return;
	}

	$protect = explode("\n", $protect_setting);
	$protect_uris = array_map('trim', $protect);

	// reconstruct URI
	if (is_array($return['segments'])) {
		$parts = array_merge(array($return['handler']), $return['segments']);
		$uri = implode('/', $parts);
	} else {
		$uri = $return['handler'];
	}

	if (!in_array($uri, $protect_uris)) {
		return $return;
	}

	$ip = get_ip();

	if (!check_spammer('', $ip, false)) {
		header("HTTP/1.1 403 Forbidden");

		if (elgg_get_plugin_setting("custom_error_page", PLUGIN_ID) == "yes") {
			include(dirname(__DIR__) . "/pages/403.php");
		}

		return false;
	}
}


/**
 * Add delete as spammer link to user hover menu
 * 
 * @return type
 */
function user_hover_menu(\Elgg\Hook $hook) {
	$params = $hook->getParams();
  $return = $hook->getValue();
	$user = $params['entity'];

	if ($user->guid != elgg_get_logged_in_user_guid() && elgg_is_admin_logged_in()) {

		$item = ElggMenuItem::factory(array(
			'name' => "spam_login_filter_delete",
			'href' => "action/spam_login_filter/delete?guid={$user->guid}",
			'text' => elgg_echo("spam_login_filter:delete_and_report"),
			'is_action' => true,
			'section' => 'admin',
			'icon' => 'user-times',
			'confirm' => elgg_echo('question:areyousure')
		));
		$return[] = $item;
	}

	return $return;
}


function register_user(\Elgg\Hook $hook) {
	$p = $hook->getParams();
  $r = $hook->getValue();

	$email = $p['user']->email;
	$ip = get_ip();
	if (!check_spammer($email, $ip)) {
		if (elgg_get_plugin_setting("custom_error_page", PLUGIN_ID) == "yes") {
			// explicitly delete the user before fowarding to 403
			$ia = elgg_set_ignore_access(true);
			$p['user']->delete();
			elgg_set_ignore_access($ia);
			forward('', '403');
			exit;
		}
		return false;
	}
	
	return $r;
}

function login_action_hook(\Elgg\Hook $hook) {
  $r = $hook->getValue();
	$username = get_input('username');

	if (empty($username)) {
		return $r;
	}

	// check if logging in with email address
	if (strpos($username, '@') !== false && ($users = get_user_by_email($username))) {
		$username = $users[0]->username;
	}

	$user = get_user_by_username($username);
	
	if($user !== false) {
		if (login_event('', '', $user) === false) {
			register_error(elgg_echo('spam_login_filter:access_denied'));
			return false;
		}
	}
}