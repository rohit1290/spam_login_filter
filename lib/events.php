<?php

namespace Spam\LoginFilter;

/**
 * Called on the login user event
 * Checks for spammers
 * 
 * @param type $event
 * @param type $type
 * @param type $user
 * @return boolean
 */
function login_event($event, $type, $user) {
	$check_login = elgg_get_plugin_setting('event_login', 'spam_login_filter');

	$ip = get_ip();
	if ($check_login != 'no') { // do it by default
		if (!check_spammer($user->email, $ip, true)) {
			register_error(elgg_echo('spam_login_filter:access_denied_mail_blacklist'));
			notify_admin($user->email, $ip, "Existing member identified as spammer has tried to login, check this account");
			return false;
		}
	}

	// check user metadata for banned words/phrases
	$banned = get_banned_strings();
	$metadata = get_metadata_names();

	if ($banned && $metadata) {
		foreach ($metadata as $m) {
			foreach ($banned as $str) {
				if (strpos($user->$m, $str) !== false) {
					return false;
				}
			}
		}
	}
}
