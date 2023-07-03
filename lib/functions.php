<?php

use Elgg\Email;

/**
 * checks email/ip for spammer status
 *
 * @param type $register_email
 * @param type $register_ip
 * @param type $checkemail
 * @return boolean (show message false) or string (show message is true)
 */
function check_spammer($register_email, $register_ip, $checkemail = true, $show_error = true) {

	if ($checkemail) {
		if (is_email_whitelisted($register_email)) {
			return true; // not a spammer, no need for any further checks
		}
	}

	if (is_ip_whitelisted($register_ip)) {
		// not a spammer, no need for any further checks
		return true;
	}

	// check ip cache
	$blacklisted = elgg_get_annotations([
		'guid' => elgg_get_site_entity()->guid,
		'annotation_names' => ['spam_login_filter_ip'],
		'annotation_values' => [$register_ip]
	]);

	if ($blacklisted) {
		if($show_error == true) {
			return elgg_echo('spam_login_filter:access_denied_ip_blacklist');
			notify_admin($register_email, $register_ip, "Internal IP blacklist");
		}
		return false;
	}

	// //Country Blacklist
	$ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$register_ip));
	if ($ip_data && $ip_data->geoplugin_countryName != null) {
		$geo_country = $ip_data->geoplugin_countryCode;
	}

	$country_blacklisted = elgg_get_plugin_setting('fassim_blocked_country_list', "spam_login_filter");
	$country_blacklisted = str_replace(' ', '', $country_blacklisted); // cleanup
	$country_list = explode(",", $country_blacklisted);
	if (in_array($geo_country, $country_list) && (count($country_list)> 0) && ($geo_country!="")) {
		if($show_error == true) {
			return elgg_echo('spam_login_filter:access_denied_country_blacklist');
			notify_admin($register_email, $register_ip, "Country blacklist");
		}
		return false;
	}

	//Mail domain blacklist
	if (elgg_get_plugin_setting('use_mail_domain_blacklist', 'spam_login_filter') == "yes") {
		$blacklistedMailDomains = preg_split('/\\s+/', strip_spaces(strip_tags(elgg_get_plugin_setting('blacklisted_mail_domains', 'spam_login_filter'))), -1, PREG_SPLIT_NO_EMPTY);
		$mailDomain = explode("@", $register_email);

		foreach ($blacklistedMailDomains as $domain) {
			if ($mailDomain[1] == $domain) {
				if($show_error == true) {
					return elgg_echo('spam_login_filter:access_denied_domain_blacklist');
					notify_admin($register_email, $register_ip, "Internal domain blacklist");
				}
				return false;
				break;
			}
		}
	}

	//Mail blacklist
	if (elgg_get_plugin_setting('use_mail_blacklist', 'spam_login_filter') == "yes") {
		$blacklistedMails = preg_split('/\\s+/', strip_spaces(strip_tags(elgg_get_plugin_setting('blacklisted_mails', 'spam_login_filter'))), -1, PREG_SPLIT_NO_EMPTY);

		foreach ($blacklistedMails as $blacklistedMail) {
			if ($blacklistedMail == $register_email) {
				if($show_error == true) {
					return elgg_echo('spam_login_filter:access_denied_mail_blacklist');
					notify_admin($register_email, $register_ip, "Internal e-mail blacklist");
				}
				return false;
				break;
			}
		}
	}

	//StopForumSpam
	if (elgg_get_plugin_setting('use_stopforumspam', 'spam_login_filter') == "yes") {
		//check the e-mail adress
		$url = "http://api.stopforumspam.com/api?ip=" . $register_ip . "&email=" . $register_email . "&f=json";

		$return = call_url($url);

		if ($return != false) {
			
			$data = json_decode($return, true);
			
			if(array_key_exists("email",$data)) {
				$email_frequency = (int)$data['email']['frequency'];
			  if ($email_frequency != 0) {
					if($show_error == true) {
						return elgg_echo('spam_login_filter:access_denied_mail_blacklist');
						notify_admin($register_email, $register_ip, "Stopforumspam e-mail blacklist");
					}
					return false;
				}
			}

			if(array_key_exists("ip",$data)) {
				$ip_frequency = (int)$data['ip']['frequency'];
		    if ($ip_frequency != 0) {
					if($show_error == true) {
						return elgg_echo('spam_login_filter:access_denied_ip_blacklist');
						notify_admin($register_email, $register_ip, "Stopforumspam IP blacklist");
					}
					// cache this ip
					elgg_get_site_entity()->annotate('spam_login_filter_ip', $register_ip, ACCESS_PUBLIC);
					return false;
				}
			}
		}
	}

	// passed all the tests
	return true;
}

function call_url($url) {
	$curl = curl_init($url);

	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($curl, CURLOPT_TIMEOUT, 10);

	$contents = curl_exec($curl);
	$info = curl_getinfo($curl);

	if ($info['http_code'] === 200) {
		return $contents;
	}

	return false;
}


/**
 *
 * @return array
 */
function get_banned_strings() {
	$string = elgg_get_plugin_setting('banned_metadata', 'spam_login_filter');
	if (!$string) {
		return [];
	}

	$array = explode("\n", $string);
	$array = array_map('trim', $array);

	return $array;
}


/**
 *
 * @return string ip | null
 */
function get_ip() {
	// note we need to look at these values first before REMOTE_ADDR
	// as cloud hosting routes through other servers giving false
	// or invalid internal ips
	//check ip from share internet
	if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
		$realip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$realip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
		$realip = $_SERVER['REMOTE_ADDR'];
	}

	return $realip;
}

function get_sfs_api_key() {
	static $sfs_api_key;
	if ($sfs_api_key) {
		return $sfs_api_key;
	}

	$sfs_api_key = elgg_get_plugin_setting('stopforumspam_api_key', 'spam_login_filter');

	return $sfs_api_key;
}


function get_metadata_names() {
	$string = elgg_get_plugin_setting('user_metadata', 'spam_login_filter');
	if (!$string) {
		return [];
	}

	$array = explode("\n", $string);
	$array = array_map('trim', $array);

	return $array;
}

//
// function get_upgrade_version() {
// 	return elgg_get_plugin_setting('upgrade_version', 'spam_login_filter');
// }
//
// function set_upgrade_version($version) {
// 	return elgg_get_plugin_from_id('spam_login_filter')->setSetting('upgrade_version', $version);
// }


/**
 *
 * @param type $ip
 * @return boolean
 */
function is_ip_whitelisted($ip = false) {

	if (!$ip) {
		$ip = get_ip();
	}

	// check for whitelist first
	$whitelist = elgg_get_plugin_setting('whitelist_ip', 'spam_login_filter');
	$whitelist = explode("\n", $whitelist);
	$whitelist = array_map('trim', $whitelist);

	foreach ($whitelist as $w) {
		$list_parts = explode('.', $w);
		$ip_parts = explode('.', $ip);

		$match = true;
		foreach ($list_parts as $key => $val) {
			if ($val != $ip_parts[$key] && $val != '*') {
				$match = false;
			}
		}

		if ($match) {
			return true;
		}
	}

	return false;
}


/**
 *
 * @param type $email
 * @return boolean
 */
function is_email_whitelisted($email) {
	// check for domain whitelist first
	$whitelist = elgg_get_plugin_setting('whitelist_email_domain', 'spam_login_filter');
	$whitelist = explode("\n", $whitelist);
	$whitelist = array_map('trim', $whitelist);

	$parts = explode('@', $email);

	if (in_array($parts[1], $whitelist)) {
		return true; // we're whitelisted!
	}

	// check for specific email whitelist
	$whitelist = elgg_get_plugin_setting('whitelist_email', 'spam_login_filter');
	$whitelist = explode("\n", $whitelist);
	$whitelist = array_map('trim', $whitelist);

	if (in_array($email, $whitelist)) {
		return true; // we're whitelisted!
	}

	return false;
}


/**
 * Notify an admin about the reason for rejection
 *
 * @param type $blockedEmail
 * @param type $blockedIp
 * @param type $reason
 * @return type
 */
function notify_admin($blockedEmail, $blockedIp, $reason) {
	if (elgg_get_plugin_setting('notify_by_mail', 'spam_login_filter') == "yes") {
		//Notify spam tentative to administrator

		$site = elgg_get_site_entity();
		if (($site) && (isset($site->email))) {
			$from = $site->email;
		} else {
			$from = 'noreply@' . $site->getDomain();
		}

		$to = elgg_get_plugin_setting('notify_mail_address', 'spam_login_filter');
		if (!is_email_address($to)) {
			return;
		}
		
		$email = Email::factory([
			'to' => $to,
			'from' => $from,
			'subject' => elgg_echo('spam_login_filter:notify_subject'),
			'body' => elgg_echo('spam_login_filter:notify_message', [$blockedEmail, $blockedIp, $reason]),
		]);

		elgg_send_email($email);
	}
}



function strip_spaces($content) {
	$searchSpaces = [' ', '&nbsp;'];
	$content = str_replace($searchSpaces, '', $content);
	return $content;
}

function spam_login_event_check($user) {
		if ($user->isAdmin()) {
			return true; // don't block admin logins
		}

		$check_login = elgg_get_plugin_setting('event_login', 'spam_login_filter');

		$ip = get_ip();
		$user->ip_address = $ip;
		if ($check_login != 'no' || !$user->last_login) { // do it by default
			if (!check_spammer($user->email, $ip, true, false)) {
				notify_admin($user->email, $ip, "Existing member identified as spammer has tried to login, check this account");
				return elgg_echo('spam_login_filter:access_denied');
			}

			// check user metadata for banned words/phrases
			$banned = get_banned_strings();
			$metadata = get_metadata_names();

			if ($banned && $metadata) {
				foreach ($metadata as $m) {
					foreach ($banned as $str) {
						$test_str = (string) $user->$m;
						if (strpos($test_str, $str) !== false) {
							return elgg_echo('spam_login_filter:access_denied_banned_metadata');
						}
					}
				}
			}
		}
		return true;
}
