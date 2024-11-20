<?php
use Elgg\DefaultPluginBootstrap;

class SpamLoginFilter extends DefaultPluginBootstrap {

  public function init() {
    // register events
    elgg_register_event_handler("action:validate", "register", "verify_action_event");
    elgg_register_event_handler("action:validate", "login", "login_action_event");
    elgg_register_event_handler('cron', 'daily', 'daily_cron');
    elgg_register_event_handler('route', 'all', 'filter_router');
    elgg_register_event_handler('register', 'menu:user_hover', 'user_hover_menu', 1000);
    elgg_register_event_handler('register', 'user', 'verify_register_user', 0);


    // register events
    // recored ip addresses for users on creation and each time they log in
    elgg_register_event_handler('login:before', 'user', 'login_event');
    elgg_register_event_handler('create', 'user', 'create_user_event');

  }
  
  public function activate() {
    $pages = elgg_get_plugin_setting('protected_pages', 'spam_login_filter');
    if (!$pages) {
    	elgg_get_plugin_from_id('spam_login_filter')->setSetting('protected_pages', 'register');
    }
  }
}