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
	return spam_login_event_check($user);
}


function create_user_event(\Elgg\Event $event) {
	$user = $event->getObject();
	// check for logged in status, we don't want to record an admin ip address
	// on an account they just created for example
	if (!elgg_is_logged_in()) {
		$user->ip_address = get_ip();
	}
}
