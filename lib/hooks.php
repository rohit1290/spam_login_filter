<?php

namespace Spam\LoginFilter;
use ElggMenuItem;


/**
 * called on register action - checks user ip/email against rules
 * 
 * @param type $hook
 * @param type $entity_type
 * @param type $returnvalue
 * @param type $params
 * @return boolean
 */
function verify_action_hook($hook, $type, $return, $params) {
	//Check against stopforumspam and domain blacklist

	$email = get_input('email');
	$ip = get_ip();

	if (check_spammer($email, $ip)) {
		return $return;
	}
    
	forward();
}


/**
 * called on daily cron - cleans up ip address cache
 * 
 * @param type $hook
 * @param type $entity_type
 * @param type $returnvalue
 * @param type $params
 */
function daily_cron($hook, $entity_type, $returnvalue, $params) {
	
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


function filter_router($hook, $type, $return, $params) {

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
	$deny = false;

	if (!check_spammer('', $ip, false)) {
		$deny = true;
	}

	if ($deny) {
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
 * @param type $hook
 * @param type $type
 * @param type $return
 * @param type $params
 * @return type
 */
function user_hover_menu($hook, $type, $return, $params) {
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


function register_user($h, $t, $r, $p) {
	$email = $p['user']->email;
	$ip = get_ip();
	if (!check_spammer($email, $ip)) {
		if (elgg_get_plugin_setting("custom_error_page", PLUGIN_ID) == "yes") {
			// explicitly delete the user before fowarding to 403
			$ia = elgg_set_ignore_access(true);
			$p['user']->delete();
			elgg_set_ignore_access($ia);
			header("HTTP/1.1 403 Forbidden");
			include(dirname(__DIR__) . "/pages/403.php");
			exit;
		}
		return false;
	}
	
	return $r;
}

function login_action_hook($h, $t, $r, $p) {
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