<?php

namespace Spam\LoginFilter;


/**
 * called on register action - checks user ip/email against rules
 * 
 * @param type $hook
 * @param type $entity_type
 * @param type $returnvalue
 * @param type $params
 * @return boolean
 */
function verify_action_hook($hook, $entity_type, $returnvalue, $params) {
	//Check against stopforumspam and domain blacklist

	$email = get_input('email');
	$ip = get_ip();

	if (check_spammer($email, $ip)) {
		return true;
	} else {
		//Check if the ip exists
		$options = array(
			"type" => "object",
			"subtype" => "spam_login_filter_ip",
			"metadata_name_value_pairs" => array(
				"name" => "ip_address",
				"value" => $ip,
			),
			"count" => true
		);

		$ia = elgg_set_ignore_access(true);

		$spam_login_filter_ip_list = elgg_get_entities_from_metadata($options);

		if ($spam_login_filter_ip_list == 0) {
			//Create the banned ip
			$ip_obj = new ElggObject();
			$ip_obj->subtype = 'spam_login_filter_ip';
			$ip_obj->access_id = ACCESS_PRIVATE;
			$ip_obj->ip_address = $ip;
			$ip_obj->owner_guid = elgg_get_site_entity()->guid;
			$ip_obj->container_guid = elgg_get_site_entity()->guid;
			$ip_obj->save();
		}

		elgg_set_ignore_access($ia);

		//return false;
		forward();
	}
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
	//Retrieve the ips older than one week
	$time_to_seek = time() - 604800; //(7 * 24 * 60 * 60);

	$options = array(
		"type" => "object",
		"subtype" => "spam_login_filter_ip",
		"created_time_upper" => $time_to_seek,
		"limit" => false
	);

	$ia = elgg_set_ignore_access(true);
	$access = access_get_show_hidden_status();
	access_show_hidden_entities(true);

	$spam_login_filter_ip_list = elgg_get_entities($options);

	if ($spam_login_filter_ip_list) {
		foreach($spam_login_filter_ip_list as $ip_to_exclude) {
			$ip_to_exclude->delete();
		}
	}

	access_show_hidden_entities($access);
	elgg_set_ignore_access($ia);
}


function filter_router($hook, $type, $return, $params) {

	// get uris to protect
	$protect_setting = elgg_get_plugin_setting('protected_pages', 'spam_login_filter');
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

	if (is_ip_whitelisted()) {
		return $return;
	}

	$ip = get_ip();

	// we need to protect this page
	//Check if the ip exists
	$options = array(
		"type" => "object",
		"subtype" => "spam_login_filter_ip",
		"metadata_name_value_pairs" => array(
			"name" => "ip_address",
			"value" => $ip,
		),
		"count" => true
	);

	$ia = elgg_set_ignore_access(true);

	$spam_login_filter_ip_list = elgg_get_entities_from_metadata($options);

	elgg_set_ignore_access($ia);

	$deny = false;
	if ($spam_login_filter_ip_list > 0) {
		$deny = true;
	}

	if (!check_spammer('', $ip, false)) {
		$deny = true;
	}

	if ($deny) {
		header("HTTP/1.1 403 Forbidden");

		if (elgg_get_plugin_setting("custom_error_page", "spam_login_filter") == "yes") {
			include(dirname(__FILE__) . "/pages/403.php");
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

	if ($user->guid != elgg_get_logged_in_user_guid()) {

		$item = ElggMenuItem::factory(array(
			'name' => "spam_login_filter_delete",
			'href' => "action/spam_login_filter/delete?guid={$user->guid}",
			'text' => elgg_echo("spam_login_filter:delete_and_report"),
			'is_action' => true,
			'section' => 'admin',
		));
		$return[] = $item;
	}

	return $return;
}