<?php

namespace Spam\LoginFilter;

/**
 * checks email/ip for spammer status
 * 
 * @param type $register_email
 * @param type $register_ip
 * @param type $checkemail
 * @return boolean
 */
function check_spammer($register_email, $register_ip, $checkemail = true) {
	$spammer = false;

	if ($checkemail) {
		$email_whitelisted = is_email_whitelisted($register_email);
	} else {
		$email_whitelisted = true;
	}
	$ip_whitelisted = is_ip_whitelisted($register_ip);

	if ($email_whitelisted && $ip_whitelisted) {
		// short circuit
		return true;
	}

	//Mail domain blacklist
	if (elgg_get_plugin_setting('use_mail_domain_blacklist', 'spam_login_filter') == "yes" && !$email_whitelisted) {
		$blacklistedMailDomains = preg_split('/\\s+/', strip_spaces(strip_tags(elgg_get_plugin_setting('blacklisted_mail_domains', 'spam_login_filter'))), -1, PREG_SPLIT_NO_EMPTY);
		$mailDomain = explode("@", $register_email);

		foreach ($blacklistedMailDomains as $domain) {
			if ($mailDomain[1] == $domain) {
				register_error(elgg_echo('spam_login_filter:access_denied_domain_blacklist'));
				notify_admin($register_email, $register_ip, "Internal domain blacklist");
				$spammer = true;
				break;
			}
		}
	}

	if (!$spammer) {
		//Mail blacklist
		if (elgg_get_plugin_setting('use_mail_blacklist', 'spam_login_filter') == "yes" && !$email_whitelisted) {
			$blacklistedMails = preg_split('/\\s+/', strip_spaces(strip_tags(elgg_get_plugin_setting('blacklisted_mails', 'spam_login_filter'))), -1, PREG_SPLIT_NO_EMPTY);

			foreach ($blacklistedMails as $blacklistedMail) {
				if ($blacklistedMail == $register_email) {
					register_error(elgg_echo('spam_login_filter:access_denied_mail_blacklist'));
					notify_admin($register_email, $register_ip, "Internal e-mail blacklist");
					$spammer = true;
					break;
				}
			}
		}
	}

	if (!$spammer) {
		//StopForumSpam
		if (elgg_get_plugin_setting('use_stopforumspam', 'spam_login_filter') == "yes") {

			//check the e-mail adress
			$url = "http://www.stopforumspam.com/api?email=" . $register_email . "&f=serial";

			$return = call_url($url);

			if ($return != false) {
				$data = unserialize($return);
				$email_frequency = $data['email']['frequency'];
				if ($email_frequency != '0' && !$email_whitelisted) {
					register_error(elgg_echo('spam_login_filter:access_denied_mail_blacklist'));
					notify_admin($register_email, $register_ip, "Stopforumspam e-mail blacklist");
					$spammer = true;
				}
			}

			if (!$spammer && !$ip_whitelisted) {
				//e-mail not found in the database, now check the ip
				$url = "http://www.stopforumspam.com/api?ip=" . $register_ip . "&f=serial";

				$return = call_url($url);

				if ($return != false) {
					$data = unserialize($return);
					$ip_frequency = $data['ip']['frequency'];
					if ($ip_frequency != '0') {
						register_error(elgg_echo('spam_login_filter:access_denied_ip_blacklist'));
						notify_admin($register_email, $register_ip, "Stopforumspam IP blacklist");
						$spammer = true;
					}
				}
			}
		}
	}

	if (!$spammer) {
		//Fassim
		if (elgg_get_plugin_setting('use_fassim', 'spam_login_filter') == "yes") {
			$fassim_api_key = elgg_get_plugin_setting('fassim_api_key', 'spam_login_filter');
			$fassim_check_email = elgg_get_plugin_setting('fassim_check_email', 'spam_login_filter');
			$fassim_check_ip = elgg_get_plugin_setting('fassim_check_ip', 'spam_login_filter');
			$fassim_block_proxies = elgg_get_plugin_setting('fassim_block_proxies', 'spam_login_filter');
			$fassim_block_top_spamming_isps = elgg_get_plugin_setting('fassim_block_top_spamming_isps', 'spam_login_filter');
			$fassim_block_top_spamming_domains = elgg_get_plugin_setting('fassim_block_top_spamming_domains', 'spam_login_filter');
			$fassim_blocked_country_list = elgg_get_plugin_setting('fassim_blocked_country_list', 'spam_login_filter');
			$fassim_blocked_region_list = elgg_get_plugin_setting('fassim_blocked_region_list', 'spam_login_filter');

			if (!empty($fassim_api_key) && preg_match('/^[0-9a-z]{8}(-[0-9a-z]{4}){3}-[0-9a-z]{12}$/i', $fassim_api_key)) {

				$url = 'http://api.fassim.com/regcheck.php?apikey=' . $fassim_api_key . '&email=' . $register_email . "&ip=" . $register_ip . '&proxy=' . $fassim_block_proxies . '&topisp=' . $fassim_block_top_spamming_isps . '&topdm=' . $fassim_block_top_spamming_domains . '&cc=' . $fassim_blocked_country_list . '&region=' . $fassim_blocked_region_list . '&hostForumVersion=ELGG';

				$return = call_url($url);

				if ($return != false) {
					$results = json_decode($return);

					if ($results != null) {
						if ($fassim_check_email == 1 && isset($results->email_status) && $results->email_status == true) {
							if (!$email_whitelisted) {
								register_error(elgg_echo('spam_login_filter:access_denied_mail_blacklist'));
								notify_admin($register_email, $register_ip, "Fassim e-mail blacklist");
								$spammer = true;
							}
						}

						if ($fassim_check_ip == 1 && isset($results->ip_status) && $results->ip_status == true) {
							if (!$ip_whitelisted) {
								register_error(elgg_echo('spam_login_filter:access_denied_ip_blacklist'));
								notify_admin($register_email, $register_ip, "Fassim IP blacklist");
								$spammer = true;
							}
						}

						if ($fassim_block_proxies == 1 && isset($results->proxy) && $results->proxy == true) {
							register_error(elgg_echo('spam_login_filter:access_denied_ip_blacklist'));
							notify_admin($register_email, $register_ip, "Fassim proxy blacklist");
							$spammer = true;
						}

						if ($fassim_block_top_spamming_isps == 1 && isset($results->top_isp) && $results->top_isp == true) {
							register_error(elgg_echo('spam_login_filter:access_denied_ip_blacklist'));
							notify_admin($register_email, $register_ip, "Fassim top ISP blacklist");
							$spammer = true;
						}

						if ($fassim_block_top_spamming_domains == 1 && isset($results->top_domain) && $results->top_domain == true) {
							register_error(elgg_echo('spam_login_filter:access_denied_domain_blacklist'));
							notify_admin($register_email, $register_ip, "Fassim top domains blacklist");
							$spammer = true;
						}

						if (!empty($fassim_blocked_country_list) && isset($results->country_match) && $results->country_match == true) {
							register_error(elgg_echo('spam_login_filter:access_denied_country_blacklist'));
							notify_admin($register_email, $register_ip, "Fassim country blacklist");
							$spammer = true;
						}

						if (!empty($fassim_blocked_region_list) && isset($results->region) && $results->region == true) {
							register_error(elgg_echo('spam_login_filter:access_denied_region_blacklist'));
							notify_admin($register_email, $register_ip, "Fassim region blacklist");
							$spammer = true;
						}
					}
				}
			}
		}
	}

	return !$spammer;
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
		return array();
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
	}
	elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		$realip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
		$realip = $_SERVER['REMOTE_ADDR'];
	}

	return $realip;
}


function get_metadata_names() {
	$string = elgg_get_plugin_setting('user_metadata', 'spam_login_filter');
	if (!$string) {
		return array();
	}

	$array = explode("\n", $string);
	$array = array_map('trim', $array);

	return $array;
}


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

		$message = elgg_echo('spam_login_filter:notify_message', array($blockedEmail, $blockedIp, $reason));

		$to = elgg_get_plugin_setting('notify_mail_address', 'spam_login_filter');
		if (!is_email_address($to)) {
			return;
		}

		elgg_send_email($from, $to, elgg_echo('spam_login_filter:notify_subject'), $message);
	}
}



function strip_spaces($content) {
	$searchSpaces = array(' ', '&nbsp;');
	$content = str_replace($searchSpaces, '', $content);
	return $content;
}