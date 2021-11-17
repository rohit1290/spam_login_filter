<?php
use Elgg\DefaultPluginBootstrap;

class SpamLoginFilter extends DefaultPluginBootstrap {

  public function init() {
    // register hooks
    elgg_register_plugin_hook_handler("action:validate", "register", "verify_action_hook");
    elgg_register_plugin_hook_handler("action:validate", "login", "login_action_hook");
    elgg_register_plugin_hook_handler('cron', 'daily', 'daily_cron');
    elgg_register_plugin_hook_handler('route', 'all', 'filter_router');
    elgg_register_plugin_hook_handler('register', 'menu:user_hover', 'user_hover_menu', 1000);
    elgg_register_plugin_hook_handler('register', 'user', 'verify_register_user');


    // register events
    // recored ip addresses for users on creation and each time they log in
    elgg_register_event_handler('login:before', 'user', 'login_event');
    elgg_register_event_handler('create', 'user', 'create_user_event');

    elgg_register_menu_item('page', [
      'name' => 'manageip',
      'href' => 'admin/administer_utilities/manageip',
      'text' => elgg_echo('admin:administer_utilities:manageip'),
      'context' => 'admin',
      'parent_name' => 'administer_utilities',
      'section' => 'administer',
    ]);
  }
  
  public function activate() {
    $pages = elgg_get_plugin_setting('protected_pages', PLUGIN_ID);
    if (!$pages) {
    	elgg_get_plugin_from_id(PLUGIN_ID)->setSetting('protected_pages', 'register');
    }
  }
}