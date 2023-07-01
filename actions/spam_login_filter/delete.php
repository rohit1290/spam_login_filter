<?php

use ElggUser;

$deleted = false;

// Get the user
$guid = get_input('guid');
$obj = get_entity($guid);

if (!$obj instanceof \ElggUser) {
	return elgg_redirect_response(REFERRER);
}

$name = $obj->name;
$username = $obj->username;
$email = $obj->email;
$ip_address = $obj->ip_address;
$api_key = get_sfs_api_key();

if (empty($ip_address)) {
	elgg_register_error_message(elgg_echo('spam_login_filter:empty_ip_error'));
	return elgg_redirect_response(REFERRER);
} else {
	if (elgg_get_plugin_setting('use_ip_blacklist_cache', 'spam_login_filter') == "yes") {
		// Blacklist the IP
		//Check if the ip exists
		$options = [
			'guid' => elgg_get_site_entity()->guid,
			'annotation_name' => 'spam_login_filter_ip',
			'annotation_value' => $ip_address
		];

		$spam_login_filter_ip_list = elgg_get_annotations($options);

		if (!$spam_login_filter_ip_list) {
			//Create the banned ip
			elgg_get_site_entity()->annotate('spam_login_filter_ip', $ip_address, ACCESS_PUBLIC);
		}
	}
}

//Report to stopforumspam.com
if (elgg_get_plugin_setting('use_stopforumspam', 'spam_login_filter') == "yes") {
	if (empty($api_key)) {
		elgg_register_error_message(elgg_echo('spam_login_filter:empty_api_key_error'));
		return elgg_redirect_response(REFERRER);
	}

	if (!empty($ip_address) && !empty($api_key)) {
		//Report the spammer
		$url = 'http://www.stopforumspam.com/add.php?username='.$username.'&ip_addr='.$ip_address.'&email='.$email.'&api_key='.$api_key;
		$return = call_url($url);

		if ($return == false) {
			elgg_register_error_message(elgg_echo('spam_login_filter:unable_report'));
			return elgg_redirect_response(REFERRER);
		}
	}
}

if (($obj instanceof ElggUser) && ($obj->canEdit())) {
	if ($obj->delete()) {
		elgg_ok_response('', elgg_echo('spam_login_filter:user_deleted', [$name]));
		$deleted = true;
	} else {
		elgg_register_error_message(elgg_echo('spam_login_filter:user_not_deleted'));
	}
} else {
	elgg_register_error_message(elgg_echo('spam_login_filter:user_not_deleted'));
}

// forward to user administration if on a user's page as it no longer exists
$forward = REFERRER;
if ($deleted) {
	$forward = "admin/";
}

return elgg_redirect_response($forward);
