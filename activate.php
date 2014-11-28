<?php

$pages = elgg_get_plugin_setting('protected_pages', 'spam_login_filter');

if (!$pages) {
	elgg_set_plugin_setting('protected_pages', 'register', 'spam_login_filter');
}