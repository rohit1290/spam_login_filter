<?php

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
?>
<?php

/**
 * called on register action - checks user ip/email against rules
 *
 * @return boolean
 */
function verify_action_event(\Elgg\Event $event) {
	//Check against stopforumspam and domain blacklist
	$return = $event->getValue();
	$email = get_input('email');
	$ip = get_ip();
	
	$result = check_spammer($email, $ip, true, true);
	if(is_bool($result)) {
		if ($result == true) {
			return $return;
		}
	}
	throw new \Elgg\Exceptions\Http\ValidationException($result);
	return false;
}


/**
 * called on daily cron - cleans up ip address cache
 */
function daily_cron() {
	
	elgg_call(ELGG_IGNORE_ACCESS, function() {
	
		//Retrieve the ips older than one week
		$week_ago = time() - 604800; //(7 * 24 * 60 * 60);
		
		elgg_delete_annotations([
			'guid' => elgg_get_site_entity()->guid,
			'annotation_names' => 'spam_login_filter_ip',
			'annotation_created_time_upper' => $week_ago,
			'limit' => false
		]);

	});
}


function filter_router(\Elgg\Event $event) {

	$return = $event->getValue();
	
	if (elgg_is_admin_logged_in()) {
		return $return;
	}

	// get uris to protect
	$protect_setting = elgg_get_plugin_setting('protected_pages', 'spam_login_filter');
	if (empty($protect_setting)) {
		return $return;
	}

	$protect = explode("\n", $protect_setting);
	$protect_uris = array_map('trim', $protect);

	$uri = elgg_get_context();

	if (!in_array($uri, $protect_uris)) {
		return $return;
	}

	$ip = get_ip();
	$result = check_spammer('', $ip, false, false);
	if ($result !== true) {
		throw new \Elgg\Exceptions\HttpException(elgg_echo('spam_login_filter:access_denied'), ELGG_HTTP_FORBIDDEN);
	}
	return $return;
}


/**
 * Add delete as spammer link to user hover menu
 *
 * @return type
 */
function user_hover_menu(\Elgg\Event $event) {
	$params = $event->getParams();
	$return = $event->getValue();
	$user = $params['entity'];

	if ($user->guid != elgg_get_logged_in_user_guid() && elgg_is_admin_logged_in()) {
		$item = ElggMenuItem::factory([
			'name' => "spam_login_filter_delete",
			'href' => "action/spam_login_filter/delete?guid={$user->guid}",
			'text' => elgg_echo("spam_login_filter:delete_and_report"),
			'is_action' => true,
			'section' => 'admin',
			'icon' => 'user-times',
			'confirm' => elgg_echo('question:areyousure')
		]);
		$return[] = $item;
	}

	return $return;
}


function verify_register_user(\Elgg\Event $event) {
	$p = $event->getParams();

	$email = $p['user']->email;
	$ip = get_ip();
	$result = check_spammer($email, $ip, true, false);
	if ($result !== true) {
		$msg = "Your registration did not pass our spam verification process.";
		throw new \Elgg\Exceptions\Configuration\RegistrationException($msg);
		return false;
	}
}

function login_action_event(\Elgg\Event $event) {
	$r = $event->getValue();
	$username = get_input('username');

	if (empty($username)) {
		return $r;
	}

	$user = elgg_get_user_by_username($username, true);
	
	if ($user instanceof \ElggUser) {
		$result = spam_login_event_check($user);
		if(!is_bool($result)) {
			throw new \Elgg\Exceptions\Http\ValidationException($result);
			return false;
		}
	}
	return $r;
}
