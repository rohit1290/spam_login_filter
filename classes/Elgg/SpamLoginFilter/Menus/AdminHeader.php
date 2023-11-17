<?php

namespace Elgg\SpamLoginFilter\Menus;

/**
 * Event callbacks for menus
 *
 * @since 5.0
 * @internal
 */
class AdminHeader {
	
	/**
	 * Add to the page menu
	 *
	 * @param \Elgg\Event $event 'register', 'menu:admin_header'
	 *
	 * @return void|\Elgg\Menu\MenuItems
	 */
	public static function register(\Elgg\Event $event) {
    if (!elgg_in_context('admin') || !elgg_is_admin_logged_in()) {
			return;
		}
	
		$return = $event->getValue();
		$return[] = \ElggMenuItem::factory([
      'name' => 'administer_utilities:manageip',
      'text' => elgg_echo('admin:administer_utilities:manageip'),
      'href' => 'admin/administer_utilities/manageip',
      'parent_name' => 'utilities',
		]);
    
		return $return;
	}
}