<?php

$plugin = elgg_extract("entity", $vars);

$yesno_options = [
	"yes" => elgg_echo("option:yes"),
	"no" => elgg_echo("option:no")
];

$onezero_options = [
	1 => elgg_echo("option:yes"),
	0 => elgg_echo("option:no")
];

// Stop Forum Spam
$title = elgg_echo("spam_login_filter:title_stopforumspam");

$content = "<div class='mbs'>";
	$content .= elgg_echo("spam_login_filter:use_stopforumspam");
$content .= elgg_view("input/dropdown", ["name" => "params[use_stopforumspam]", "options_values" => $yesno_options, "value" => $plugin->use_stopforumspam, "class" => "mls"]);
$content .= "</div>";

$content .= "<div>";
$content .= elgg_echo("spam_login_filter:stopforumspam_api_key");
$content .= elgg_view("input/text", ["name" => "params[stopforumspam_api_key]", "value" => $plugin->stopforumspam_api_key]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// Country BlackList
$title = elgg_echo("Country Blacklist");

$content = "<div class='mbs'>";
$content .= elgg_echo("Block the following countries:");
$content .= elgg_view("input/text", ["name" => "params[fassim_blocked_country_list]", "value" => $plugin->fassim_blocked_country_list]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("(Just type in the country abbreviation of the countries you want to block, for multiple countries separated by comma, e.g. US,LV,HK. For a full list of supported country abbreviations click <a href='http://www.worldatlas.com/aatlas/ctycodes.htm' target='_blank'>Country Codes</a>)"), "class" => "elgg-subtext"]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// Domain blacklist
$title = elgg_echo("spam_login_filter:title_domain_blacklist");

$content = "<div class='mbs'>";
$content .= elgg_echo("spam_login_filter:use_mail_domain_blacklist");
$content .= elgg_view("input/dropdown", ["name" => "params[use_mail_domain_blacklist]", "options_values" => array_reverse($yesno_options), "value" => $plugin->use_mail_domain_blacklist, "class" => "mls"]);
$content .= "</div>";

$content .= "<div>";
$content .= elgg_echo("spam_login_filter:blacklisted_mail_domains");
$content .= elgg_view("input/plaintext", ["name" => "params[blacklisted_mail_domains]", "value" => $plugin->blacklisted_mail_domains]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// Email blacklist
$title = elgg_echo("spam_login_filter:title_email_blacklist");

$content = "<div class='mbs'>";
$content .= elgg_echo("spam_login_filter:use_mail_blacklist");
$content .= elgg_view("input/dropdown", ["name" => "params[use_mail_blacklist]", "options_values" => array_reverse($yesno_options), "value" => $plugin->use_mail_blacklist, "class" => "mls"]);
$content .= "</div>";

$content .= "<div>";
$content .= elgg_echo("spam_login_filter:blacklisted_mails");
$content .= elgg_view("input/plaintext", ["name" => "params[blacklisted_mails]", "value" => $plugin->blacklisted_mails]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// Notify by mail
$title = elgg_echo("spam_login_filter:title_plugin_notifications");

$content = "<div class='mbs'>";
$content .= elgg_echo("spam_login_filter:notify_by_mail");
$content .= elgg_view("input/dropdown", ["name" => "params[notify_by_mail]", "options_values" => array_reverse($yesno_options), "value" => $plugin->notify_by_mail, "class" => "mls"]);
$content .= "</div>";

$content .= "<div>";
$content .= elgg_echo("spam_login_filter:notify_mail_address");
$content .= elgg_view("input/text", ["name" => "params[notify_mail_address]", "value" => $plugin->notify_mail_address]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// IP blacklist
$title = elgg_echo("spam_login_filter:title_ip_blacklist");

$content = "<div class='mbm'>";
$content .= elgg_echo("spam_login_filter:protected_pages");
$content .= elgg_view("input/plaintext", ["name" => "params[protected_pages]", "value" => $plugin->protected_pages]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:protected_pages:help"), "class" => "elgg-subtext"]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// whitelist
$title = elgg_echo("spam_login_filter:whitelist");

$content = "<div class='mbs'>";
$content .= elgg_echo("spam_login_filter:whitelist:ip");
$content .= elgg_view("input/plaintext", ["name" => "params[whitelist_ip]", "value" => $plugin->whitelist_ip]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:whitelist:ip:help"), "class" => "elgg-subtext"]);
$content .= "</div>";

$content .= "<div class='mbs'>";
$content .= elgg_echo("spam_login_filter:whitelist:email:domain");
$content .= elgg_view("input/plaintext", ["name" => "params[whitelist_email_domain]", "value" => $plugin->whitelist_email_domain]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:whitelist:email:domain:help"), "class" => "elgg-subtext"]);
$content .= "</div>";

$content .= "<div class='mbs'>";
$content .= elgg_echo("spam_login_filter:whitelist:email");
$content .= elgg_view("input/plaintext", ["name" => "params[whitelist_email]", "value" => $plugin->whitelist_email]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:whitelist:email:help"), "class" => "elgg-subtext"]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// events
$title = elgg_echo("spam_login_filter:events");

$content = "<div class='mbs'>";
$content .= elgg_echo("spam_login_filter:check_login");
$content .= elgg_view("input/dropdown", ["name" => "params[event_login]", "value" => $plugin->event_login, "options_values" => array_reverse($yesno_options), "class" => "mls"]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:check_login:help"), "class" => "elgg-subtext"]);
$content .= "</div>";

$content .= "<div>";
$content .= elgg_echo("spam_login_filter:label:user_metadata");
$content .= elgg_view("input/plaintext", ["name" => "params[user_metadata]", "value" => $plugin->user_metadata]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:user_metadata:help"), "class" => "elgg-subtext"]);
$content .= "</div>";

$content .= "<div>";
$content .= elgg_echo("spam_login_filter:label:banned_metadata");
$content .= elgg_view("input/plaintext", ["name" => "params[banned_metadata]", "value" => $plugin->banned_metadata]);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:banned_metadata:help"), "class" => "elgg-subtext"]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);

// tracker
$title = elgg_echo("spam_login_filter:tracker");

$content = "<div class='mbs'>";
$content .= elgg_view("input/text", ["name" => "params[tracker_url]", "value" => $plugin->tracker_url ? $plugin->tracker_url : 'http://www.ip-address.org/lookup/ip-locator.php?track=%s']);
$content .= elgg_view("output/longtext", ["value" => elgg_echo("spam_login_filter:tracker:help") , "class" => "elgg-subtext"]);
$content .= "</div>";

echo elgg_view_module("inline", $title, $content);
