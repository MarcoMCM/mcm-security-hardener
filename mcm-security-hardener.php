<?php
/**
 * Plugin Name: MCM Security Hardener
 * Plugin URI:  https://github.com/MarcoMCM/mcm-security-hardener
 * Description: Schrijft security-hardening regels naar wp-config.php en .htaccess, gebaseerd op SecuPress Pro-niveau instellingen.
 * Version: 1.8.6
 * Author: MCM Websites
 * Author URI: https://mcmwebsites.nl
 * Update URI: https://github.com/MarcoMCM/mcm-security-hardener
 * Text Domain: mcm-security-hardener
 * Requires at least: 5.6
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MCM_SECURITY_VERSION', '1.8.6' );
define( 'MCM_SECURITY_FILE', __FILE__ );
define( 'MCM_SECURITY_DIR', plugin_dir_path( __FILE__ ) );

// Self-update via publieke GitHub repo. Pikt nieuwste GitHub-release op
// en biedt 'm aan via WP's normale update-flow (en dus ook MainWP).
require_once MCM_SECURITY_DIR . 'vendor/plugin-update-checker/plugin-update-checker.php';
$mcm_update_checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
	'https://github.com/MarcoMCM/mcm-security-hardener/',
	MCM_SECURITY_FILE,
	'mcm-security-hardener'
);
$mcm_update_checker->setBranch( 'main' );

require_once MCM_SECURITY_DIR . 'includes/class-notifier.php';
require_once MCM_SECURITY_DIR . 'includes/class-staging-detector.php';
require_once MCM_SECURITY_DIR . 'includes/class-basic-auth.php';
MCM_Basic_Auth::init();
require_once MCM_SECURITY_DIR . 'includes/class-wpconfig-manager.php';
require_once MCM_SECURITY_DIR . 'includes/class-htaccess-manager.php';
require_once MCM_SECURITY_DIR . 'includes/class-login-url-manager.php';
require_once MCM_SECURITY_DIR . 'includes/class-lockdown-manager.php';
require_once MCM_SECURITY_DIR . 'includes/class-runtime-security.php';
require_once MCM_SECURITY_DIR . 'includes/class-human-verification.php';
require_once MCM_SECURITY_DIR . 'includes/class-db-prefix-manager.php';
require_once MCM_SECURITY_DIR . 'includes/class-profiles.php';
require_once MCM_SECURITY_DIR . 'includes/class-admin-page.php';

/**
 * Main plugin class.
 */
final class MCM_Security_Hardener {

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		register_activation_hook( MCM_SECURITY_FILE, [ $this, 'activate' ] );
		register_deactivation_hook( MCM_SECURITY_FILE, [ $this, 'deactivate' ] );

		new MCM_Login_URL_Manager();
		new MCM_Lockdown_Manager();
		new MCM_Runtime_Security();
		new MCM_Human_Verification();
		new MCM_DB_Prefix_Manager();

		if ( is_admin() ) {
			new MCM_Admin_Page();
		}
	}

	/**
	 * On activation: set defaults, write rules.
	 */
	public function activate() {
		$defaults = self::get_defaults();
		if ( ! get_option( 'mcm_security_settings' ) ) {
			update_option( 'mcm_security_settings', $defaults );
		}

		$settings = get_option( 'mcm_security_settings', $defaults );
		MCM_WPConfig_Manager::write( $settings );
		MCM_Htaccess_Manager::write( $settings );
	}

	/**
	 * On deactivation: remove all injected rules.
	 */
	public function deactivate() {
		MCM_WPConfig_Manager::remove();
		MCM_Htaccess_Manager::remove();
	}

	/**
	 * Default settings.
	 */
	public static function get_defaults() {
		return [
			// wp-config.php constants
			'disallow_file_edit'      => true,
			'disallow_unfiltered'     => true,
			'skip_bundled'            => true,
			'no_concatenate'          => true,
			'no_repair'              => true,
			'no_relocate'            => true,
			'no_db_error'            => true,
			'no_debug_display'       => true,
			'lock_admin_email'       => true,
			'admin_email'            => get_option( 'admin_email', '' ),

			// Plugins & Themes lockdown
			'disallow_file_mods'     => true,
			'lockdown_plugins'       => true,
			'lockdown_themes'        => true,

			// Login URL — leeg laten, jij vult per site een unieke slug in via Bulk Settings Manager
			'login_slug'                  => '',
			'mail_admins_on_slug_change'  => false,
			'mail_admins_recipients'      => [], // array of user IDs.

			// Basic Auth (staging) — feature B
			'basic_auth_enabled'          => false,
			'basic_auth_user'             => 'staging',

			// Human verification
			'human_verification'       => true,
			'human_verification_delay' => 3,

			// WordPress Core
			'auto_update_minor'      => true,
			'random_cookie_hash'     => true,
			'secure_keys'            => true,

			// Version hiding & endpoints
			'hide_wp_version'        => true,
			'hide_php_version'       => true,
			'robots_blackhole'       => true,
			'block_bad_urls'         => true,

			// Bad behaviors
			'block_bad_user_agents'  => true,
			'block_fake_seo_bots'    => true,
			'block_bad_referers'     => true,
			'bad_referers_list'      => '',
			'block_ai_bots'          => true,

			// Malicious URLs
			'block_bad_url_content'  => false, // Uitgezet: regex gaf 44% false positives op legit URLs (apostrof in zoekterm, fragment-URLs, dubbele streepjes). Server-WAF doet dit beter.
			'block_php_404'          => true,

			// .htaccess rules
			'block_readme_files'     => true,
			'block_sensitive_php'    => true,
			'disable_directory_listing' => true,
			'block_php_easter_eggs'  => true,
			'block_script_concat'    => true,
			'block_xmlrpc'           => true,
			'block_debug_log'        => true,
			'block_log_txt_files'    => true,
			'block_php_in_uploads'   => true,
			'block_wp_includes_php'  => true,
		];
	}
}

MCM_Security_Hardener::get_instance();
