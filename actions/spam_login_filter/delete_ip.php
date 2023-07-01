<?php

$spam_login_filter_ip_list = get_input('spam_login_filter_ip_list');
$error = false;

if (!$spam_login_filter_ip_list) {
	elgg_register_error_message(elgg_echo('spam_login_filter:errors:unknown_ips'));
	return elgg_redirect_response('admin/administer_utilities/manageip');
}

foreach ($spam_login_filter_ip_list as $id) {
	if (!elgg_delete_annotation_by_id($id)) {
		$error = true;
		continue;
	}
}

if (count($spam_login_filter_ip_list) == 1) {
	$message_txt = elgg_echo('spam_login_filter:messages:deleted_ip');
	$error_txt = elgg_echo('spam_login_filter:errors:could_not_delete_ip');
} else {
	$message_txt = elgg_echo('spam_login_filter:messages:deleted_ips');
	$error_txt = elgg_echo('spam_login_filter:errors:could_not_delete_ips');
}

if ($error) {
	elgg_register_error_message($error_txt);
} else {
	elgg_register_success_message($message_txt);
}

return elgg_redirect_response('admin/administer_utilities/manageip');
