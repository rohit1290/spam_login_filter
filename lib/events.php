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
function login_event(\Elgg\Event $event) {
	$user = $event->getObject();

	if ($user->isAdmin()) {
		return; // don't block admin logins
	}

	$check_login = elgg_get_plugin_setting('event_login', PLUGIN_ID);

	$ip = get_ip();
	$user->ip_address = $ip;
	if ($check_login != 'no' || !$user->last_login) { // do it by default
		if (!check_spammer($user->email, $ip, true)) {
			notify_admin($user->email, $ip, "Existing member identified as spammer has tried to login, check this account");
			return false;
		}

		// check user metadata for banned words/phrases
		$banned = get_banned_strings();
		$metadata = get_metadata_names();

		if ($banned && $metadata) {
			foreach ($metadata as $m) {
				foreach ($banned as $str) {
					$test_str = (string) $user->$m;
					if (strpos($test_str, $str) !== false) {
						register_error(elgg_echo('spam_login_filter:access_denied_banned_metadata'));
						return false;
					}
				}
			}
		}
	}
}


function create_user_event(\Elgg\Event $event) {
	$user = $event->getObject();
	// check for logged in status, we don't want to record an admin ip address
	// on an account they just created for example
	if (!elgg_is_logged_in()) {
		$user->ip_address = get_ip();
	}
}
