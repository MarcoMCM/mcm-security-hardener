<?php
/**
 * Locks down plugin and theme actions by removing capabilities at runtime.
 *
 * DISALLOW_FILE_MODS in wp-config blocks file-level operations (install, update, delete).
 * This class additionally blocks activate/deactivate/switch via capability filtering.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Lockdown_Manager {

	/**
	 * MCM-eigenaar logins die NOOIT gelocked worden.
	 *
	 * Configureer per site via een mu-plugin of wp-config:
	 *   define( 'MCM_SECURITY_OWNERS', [ 'beheerder_login_1', 'beheerder_login_2' ] );
	 *
	 * Default leeg → klant-admins houden gewoon hun manage_options-bypass,
	 * MCM-owner force-rights gelden alleen op sites waar je de constante zet.
	 */
	public static function get_owners() {
		if ( defined( 'MCM_SECURITY_OWNERS' ) && is_array( MCM_SECURITY_OWNERS ) ) {
			return MCM_SECURITY_OWNERS;
		}
		return apply_filters( 'mcm_security_owners', [] );
	}

	private $settings = [];

	public function __construct() {
		$this->settings = get_option( 'mcm_security_settings', [] );

		// ALTIJD: MCM eigenaar override — forceert volledige rechten
		// op het diepste WordPress niveau, ongeacht alle andere instellingen.
		add_filter( 'file_mod_allowed', [ __CLASS__, 'force_file_mods_for_owner' ], 999999, 2 );
		add_filter( 'map_meta_cap', [ __CLASS__, 'force_caps_for_owner' ], 999999, 4 );
		add_filter( 'user_has_cap', [ __CLASS__, 'force_allcaps_for_owner' ], 999999, 4 );

		if ( empty( $this->settings['lockdown_plugins'] ) && empty( $this->settings['lockdown_themes'] ) ) {
			return;
		}

		// Registreer lockdown hooks pas bij 'init' zodat we weten wie er is ingelogd.
		add_action( 'init', [ $this, 'maybe_register_lockdown' ], 0 );
	}

	/**
	 * Forceer file_mod_allowed = true voor MCM eigenaar.
	 * Dit overrulet DISALLOW_FILE_MODS, hosting-restricties, en alles.
	 */
	public static function force_file_mods_for_owner( $allowed, $context ) {
		if ( self::is_mcm_owner() ) {
			return true;
		}
		return $allowed;
	}

	/**
	 * Forceer capabilities via map_meta_cap voor MCM eigenaar.
	 * Mapt install_plugins etc. naar 'exist' (= altijd toegestaan).
	 */
	public static function force_caps_for_owner( $caps, $cap, $user_id, $args ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return $caps;
		}
		if ( ! in_array( $user->user_login, self::get_owners(), true ) ) {
			return $caps;
		}

		$force_caps = [
			'install_plugins', 'update_plugins', 'delete_plugins',
			'activate_plugins', 'upload_plugins', 'edit_plugins',
			'install_themes', 'update_themes', 'delete_themes',
			'switch_themes', 'upload_themes',
			'update_core', 'manage_options', 'edit_theme_options',
		];

		if ( in_array( $cap, $force_caps, true ) ) {
			return [ 'exist' ]; // WP interpreteert dit als "toegestaan"
		}

		return $caps;
	}

	/**
	 * Forceer user_has_cap voor MCM eigenaar — als laatste safety net.
	 */
	public static function force_allcaps_for_owner( $allcaps, $caps, $args, $user ) {
		if ( ! in_array( $user->user_login, self::get_owners(), true ) ) {
			return $allcaps;
		}

		$allcaps['install_plugins']    = true;
		$allcaps['update_plugins']     = true;
		$allcaps['delete_plugins']     = true;
		$allcaps['activate_plugins']   = true;
		$allcaps['upload_plugins']     = true;
		$allcaps['install_themes']     = true;
		$allcaps['update_themes']      = true;
		$allcaps['switch_themes']      = true;
		$allcaps['manage_options']     = true;
		$allcaps['edit_theme_options'] = true;
		$allcaps['update_core']        = true;

		return $allcaps;
	}

	/**
	 * Helper: check of de huidige gebruiker een MCM eigenaar is.
	 *
	 * Drie routes (in volgorde):
	 *   1. user_login staat in de MCM_SECURITY_OWNERS lijst (via get_owners())
	 *   2. user_email is gelijk aan het MCM Notifier-adres (= marco@mcmwebsites.nl)
	 *   3. Filter 'mcm_security_is_owner' geeft true
	 *
	 * De email-fallback is handig op sites waar de MCM_SECURITY_OWNERS-constante
	 * (nog) niet gezet is — zolang de owner is ingelogd met het juiste mailadres.
	 */
	public static function is_mcm_owner( $user = null ) {
		if ( null === $user ) {
			$user = wp_get_current_user();
		}
		if ( ! $user || ! $user->exists() ) {
			return false;
		}

		// 1. Login op de owners-lijst.
		if ( in_array( $user->user_login, self::get_owners(), true ) ) {
			return true;
		}

		// 2. Email matcht de MCM Notifier-bestemming.
		if ( class_exists( 'MCM_Notifier' ) ) {
			$notify_email = MCM_Notifier::notify_email();
			if ( ! empty( $notify_email ) && 0 === strcasecmp( $user->user_email, $notify_email ) ) {
				return true;
			}
		}

		// 3. Filter-fallback voor custom override.
		return (bool) apply_filters( 'mcm_security_is_owner', false, $user );
	}

	/**
	 * Registreer lockdown hooks ALLEEN als de huidige gebruiker GEEN admin/eigenaar is.
	 * Draait op 'init' omdat wp_get_current_user() dan beschikbaar is.
	 */
	public function maybe_register_lockdown() {
		// MCM eigenaar: NOOIT locken, geen enkele hook registreren.
		$user = wp_get_current_user();
		if ( $user && $user->exists() ) {
			if ( in_array( $user->user_login, self::get_owners(), true ) ) {
				return;
			}
			if ( current_user_can( 'manage_options' ) ) {
				return;
			}
		}

		add_filter( 'user_has_cap', [ $this, 'filter_capabilities' ], 10, 4 );

		// Block plugin activate/deactivate actions.
		if ( ! empty( $this->settings['lockdown_plugins'] ) ) {
			add_filter( 'plugin_action_links', [ $this, 'remove_plugin_action_links' ], 99, 2 );
			add_filter( 'bulk_actions-plugins', [ $this, 'remove_plugin_bulk_actions' ] );
			add_action( 'activate_plugin', [ $this, 'block_plugin_activation' ], 0 );
			add_action( 'deactivate_plugin', [ $this, 'block_plugin_deactivation' ], 0 );
		}

		// Block theme switching via additional hook as safety net.
		if ( ! empty( $this->settings['lockdown_themes'] ) ) {
			add_filter( 'wp_prepare_themes_for_js', [ $this, 'hide_theme_actions' ] );
		}
	}

	/**
	 * Remove plugin/theme capabilities dynamically.
	 * Keeps activate_plugins so the Plugins menu stays visible.
	 */
	public function filter_capabilities( $allcaps, $caps, $args, $user ) {
		// MCM eigenaar wordt NOOIT gelocked.
		if ( in_array( $user->user_login, self::get_owners(), true ) ) {
			return $allcaps;
		}

		// Never lock out super admins on multisite.
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			return $allcaps;
		}

		// Administrators keep full access to plugin/theme management.
		if ( ! empty( $allcaps['manage_options'] ) ) {
			return $allcaps;
		}

		if ( ! empty( $this->settings['lockdown_plugins'] ) || ! empty( $this->settings['disallow_file_mods'] ) ) {
			$allcaps['install_plugins']  = false;
			$allcaps['update_plugins']   = false;
			$allcaps['delete_plugins']   = false;
			$allcaps['upload_plugins']   = false;
		}

		if ( ! empty( $this->settings['lockdown_themes'] ) || ! empty( $this->settings['disallow_file_mods'] ) ) {
			$allcaps['install_themes'] = false;
			$allcaps['update_themes']  = false;
			$allcaps['delete_themes']  = false;
			$allcaps['switch_themes']  = false;
			$allcaps['upload_themes']  = false;
		}

		return $allcaps;
	}

	/**
	 * Remove activate/deactivate/delete links from plugin rows.
	 * Keeps only the MCM Security settings link on our own plugin.
	 */
	public function remove_plugin_action_links( $actions, $plugin_file ) {
		if ( current_user_can( 'manage_options' ) ) {
			return $actions;
		}
		unset( $actions['activate'] );
		unset( $actions['deactivate'] );
		unset( $actions['delete'] );
		unset( $actions['edit'] );
		return $actions;
	}

	/**
	 * Remove bulk actions on plugins page.
	 */
	public function remove_plugin_bulk_actions( $actions ) {
		if ( current_user_can( 'manage_options' ) ) {
			return $actions;
		}
		unset( $actions['activate-selected'] );
		unset( $actions['deactivate-selected'] );
		unset( $actions['delete-selected'] );
		unset( $actions['update-selected'] );
		return $actions;
	}

	/**
	 * Block plugin activation attempts.
	 */
	public function block_plugin_activation( $plugin ) {
		if ( current_user_can( 'manage_options' ) ) {
			return;
		}
		// Allow our own plugin to stay active.
		if ( plugin_basename( MCM_SECURITY_FILE ) === $plugin ) {
			return;
		}
		wp_die(
			'Plugin activatie is geblokkeerd door MCM Security Hardener.',
			'Geblokkeerd',
			[ 'back_link' => true, 'response' => 403 ]
		);
	}

	/**
	 * Block plugin deactivation attempts.
	 */
	public function block_plugin_deactivation( $plugin ) {
		if ( current_user_can( 'manage_options' ) ) {
			return;
		}
		// Allow deactivating our own plugin (emergency escape).
		if ( plugin_basename( MCM_SECURITY_FILE ) === $plugin ) {
			return;
		}
		wp_die(
			'Plugin deactivatie is geblokkeerd door MCM Security Hardener.',
			'Geblokkeerd',
			[ 'back_link' => true, 'response' => 403 ]
		);
	}

	/**
	 * Remove action buttons from theme cards.
	 */
	public function hide_theme_actions( $prepared_themes ) {
		if ( current_user_can( 'manage_options' ) ) {
			return $prepared_themes;
		}
		foreach ( $prepared_themes as &$theme ) {
			$theme['actions'] = [];
		}
		return $prepared_themes;
	}

}
