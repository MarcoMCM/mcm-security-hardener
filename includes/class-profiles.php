<?php
/**
 * Profiles & Smart Detection
 *
 * Drie voorgedefinieerde profielen (Basic / Standard / Strict) plus een
 * detectie-mechanisme dat actieve plugins/integraties scant en op basis
 * daarvan een passend profiel aanbeveelt + waarschuwt voor specifieke
 * settings die conflicteren met gedetecteerde integraties.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Profiles {

	/**
	 * Definieer de drie profielen.
	 *
	 * Elk profiel zet alleen toggle-settings. Config-waardes
	 * (admin_email, login_slug, human_verification_delay, etc.) blijven onaangeraakt.
	 */
	public static function get_profiles() {
		// Volledig veilig — geen impact op API's of integraties.
		$basic = [
			// wp-config
			'disallow_file_edit'        => true,
			'disallow_unfiltered'       => true,
			'skip_bundled'              => true,
			'no_concatenate'            => true,
			'no_repair'                 => true,
			'no_relocate'               => true,
			'no_db_error'               => true,
			'no_debug_display'          => true,
			'lock_admin_email'          => true,
			'auto_update_minor'         => true,
			'random_cookie_hash'        => true,
			'secure_keys'               => true,
			// version hiding
			'hide_wp_version'           => true,
			'hide_php_version'          => true,
			'robots_blackhole'          => true,
			// htaccess (defensief)
			'block_readme_files'        => true,
			'block_sensitive_php'       => true,
			'disable_directory_listing' => true,
			'block_php_easter_eggs'     => true,
			'block_debug_log'           => true,
			'block_log_txt_files'       => true,
			'block_php_in_uploads'      => true,
			'block_wp_includes_php'     => true,
			'block_php_404'             => true,
			// runtime
			'block_bad_urls'            => true,
			'block_fake_seo_bots'       => true,
			'block_ai_bots'             => true,
			'block_bad_referers'        => true,
			// human verification
			'human_verification'        => true,
			// registratiebescherming (anti-bot bij registratie)
			'registration_honeypot'     => true,
			'block_disposable_email'    => true,
			// backend toegang
			'skip_admin_email_confirmation' => true,
			// file exposure scanner
			'exposure_scanner_enabled'      => true,
		];

		// Basic + lockdown + xmlrpc blokkeren + script concat blokkeren.
		// Updates moeten via SFTP/Composer of door tijdelijk te ontgrendelen.
		$standard = $basic + [
			'disallow_file_mods'  => true,
			'lockdown_plugins'    => true,
			'lockdown_themes'     => true,
			'block_xmlrpc'        => true,
			'block_script_concat' => true,
		];

		// Standard + agressieve URL/UA-filtering + klant-rollen niet in backend.
		// Risico false positives bij externe API integraties.
		$strict = $standard + [
			'block_bad_user_agents'           => true,
			'block_bad_url_content'           => true,
			'block_non_admin_backend'         => true,
			'block_risky_files_via_htaccess'  => true,
		];

		// Staging — alleen "stille" bescherming. Lockdown/file_mods uit
		// (anders kun je niets testen), human_verification uit (vervelend),
		// auto_update_minor uit (jij wilt zelf controle wanneer staging update).
		// Toegang wordt geregeld via HTTP Basic Auth, niet via login-slug
		// (dat is voor live). Daarom override config: login_slug = ''.
		$staging = $basic;
		$staging['human_verification']     = false;
		$staging['auto_update_minor']      = false;
		// Op staging mogen test-emails (mailinator etc.) wél door — anders
		// kun je de registratieflow niet testen met wegwerp-accounts.
		$staging['block_disposable_email'] = false;

		return [
			'basic' => [
				'label'       => 'Basic',
				'tagline'     => 'Veilig voor elke site',
				'description' => 'Alleen settings zonder impact op API\'s of integraties. Goed startpunt voor sites met externe koppelingen (Mollie, Exact, Amelia, etc.).',
				'safe_for'    => 'Webshops, sites met externe API\'s, drukke productiesites',
				'settings'    => $basic,
			],
			'standard' => [
				'label'       => 'Standard',
				'tagline'     => 'Aanbevolen voor de meeste sites',
				'description' => 'Basic + lockdown van plugins/themes + XML-RPC blokkeren. Plugin-updates moeten via SFTP/Composer of door lockdown tijdelijk uit te zetten.',
				'safe_for'    => 'Standaard WordPress sites zonder Jetpack of XML-RPC-afhankelijke tools',
				'settings'    => $standard,
			],
			'strict' => [
				'label'       => 'Strict',
				'tagline'     => 'Maximale beveiliging',
				'description' => 'Standard + agressieve URL- en User-Agent-filtering. Blokkeert curl/python-requests/etc. en URLs met verdachte patronen. Test grondig op staging.',
				'safe_for'    => 'Brochure-sites zonder externe API\'s of webhook-integraties',
				'settings'    => $strict,
			],
			'staging' => [
				'label'       => 'Staging',
				'tagline'     => 'Voor test/staging-omgevingen',
				'description' => 'Alleen stille bescherming (versie verbergen, bad bots blokkeren). Lockdown van plugins/themes &amp; file-mods uit, zodat je kunt testen. Login-slug wordt leeg gemaakt &mdash; toegang regel je via HTTP Basic Auth.',
				'safe_for'    => 'Staging/test-sites (Vivid Backup Pro, MainWP staging clones, *.test, staging.*)',
				'settings'    => $staging,
				'config_overrides' => [
					'login_slug' => '',
				],
			],
		];
	}

	/**
	 * Pas een profiel toe op de huidige settings.
	 * Behoudt config-waardes (email, login slug, etc.).
	 */
	public static function apply( $profile_name ) {
		$profiles = self::get_profiles();
		if ( ! isset( $profiles[ $profile_name ] ) ) {
			return new WP_Error( 'unknown_profile', 'Onbekend profiel: ' . $profile_name );
		}

		$current = get_option( 'mcm_security_settings', MCM_Security_Hardener::get_defaults() );
		$preset  = $profiles[ $profile_name ]['settings'];

		// Reset alle bekende toggles op basis van het profiel.
		// Toggles die niet in het profiel zitten worden expliciet false.
		$all_toggles = self::all_toggle_keys();
		foreach ( $all_toggles as $key ) {
			$current[ $key ] = ! empty( $preset[ $key ] );
		}

		// Optioneel: profiel kan ook config-waardes overschrijven
		// (bv. Staging-profiel maakt login_slug leeg).
		if ( ! empty( $profiles[ $profile_name ]['config_overrides'] ) && is_array( $profiles[ $profile_name ]['config_overrides'] ) ) {
			foreach ( $profiles[ $profile_name ]['config_overrides'] as $key => $value ) {
				$current[ $key ] = $value;
			}
		}

		update_option( 'mcm_security_settings', $current );

		// Toepassen op wp-config + htaccess.
		MCM_WPConfig_Manager::write( $current );
		MCM_Htaccess_Manager::write( $current );

		// Sla op welk profiel actief is voor UI-feedback.
		update_option( 'mcm_security_active_profile', $profile_name );

		return true;
	}

	/**
	 * Welke toggles bestaan er überhaupt — bron van waarheid.
	 */
	public static function all_toggle_keys() {
		return [
			// wp-config
			'disallow_file_edit', 'disallow_unfiltered', 'skip_bundled',
			'no_concatenate', 'no_repair', 'no_relocate', 'no_db_error',
			'no_debug_display', 'lock_admin_email',
			'auto_update_minor', 'random_cookie_hash', 'secure_keys',
			// lockdown
			'disallow_file_mods', 'lockdown_plugins', 'lockdown_themes',
			// version + endpoints
			'hide_wp_version', 'hide_php_version', 'robots_blackhole',
			'block_bad_urls',
			// bad behaviors
			'block_bad_user_agents', 'block_fake_seo_bots',
			'block_bad_referers', 'block_ai_bots',
			// malicious URLs
			'block_bad_url_content', 'block_php_404',
			// htaccess
			'block_readme_files', 'block_sensitive_php', 'disable_directory_listing',
			'block_php_easter_eggs', 'block_script_concat', 'block_xmlrpc',
			'block_debug_log', 'block_log_txt_files', 'block_php_in_uploads',
			'block_wp_includes_php',
			// human verification
			'human_verification',
			// registratiebescherming
			'registration_honeypot', 'block_disposable_email',
			// backend toegang
			'skip_admin_email_confirmation', 'block_non_admin_backend',
			// file exposure scanner
			'exposure_scanner_enabled', 'block_risky_files_via_htaccess',
		];
	}

	/**
	 * Detecteer of de huidige settings exact overeenkomen met één van de profielen.
	 *
	 * @return string|null Profielnaam of null als er geen exacte match is.
	 */
	public static function detect_current_profile() {
		$current   = get_option( 'mcm_security_settings', [] );
		$profiles  = self::get_profiles();
		$all_keys  = self::all_toggle_keys();

		foreach ( $profiles as $key => $profile ) {
			$matches = true;
			foreach ( $all_keys as $toggle_key ) {
				$expected = ! empty( $profile['settings'][ $toggle_key ] );
				$actual   = ! empty( $current[ $toggle_key ] );
				if ( $expected !== $actual ) {
					$matches = false;
					break;
				}
			}
			if ( $matches ) {
				return $key;
			}
		}
		return null;
	}

	/**
	 * Scan actieve plugins + theme om integraties te detecteren.
	 *
	 * Geeft een lijst van detecties met risiconiveau (low/medium/high)
	 * en welke settings beter NIET aan kunnen.
	 */
	public static function detect_integrations() {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$detections    = [];
		$active_plugins = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$active_plugins = array_merge( $active_plugins, array_keys( get_site_option( 'active_sitewide_plugins', [] ) ) );
		}

		// Map: plugin-slug fragment → [name, risk, avoid_settings, reason]
		$known = [
			'woocommerce/woocommerce.php' => [
				'name'   => 'WooCommerce',
				'risk'   => 'medium',
				'avoid'  => [ 'block_bad_url_content' ],
				'reason' => 'WooCommerce REST API en checkout-flow kunnen URL-content blocking triggeren.',
			],
			'mollie-payments-for-woocommerce' => [
				'name'   => 'Mollie',
				'risk'   => 'low',
				'avoid'  => [],
				'reason' => 'Mollie webhooks gebruiken eigen UA + clean URLs — geen conflict met defaults.',
			],
			'jetpack/jetpack.php' => [
				'name'   => 'Jetpack',
				'risk'   => 'high',
				'avoid'  => [ 'block_xmlrpc' ],
				'reason' => 'Jetpack vereist XML-RPC voor sync naar wordpress.com.',
			],
			'ameliabooking' => [
				'name'   => 'Amelia',
				'risk'   => 'medium',
				'avoid'  => [ 'block_bad_url_content' ],
				'reason' => 'Amelia REST endpoints kunnen complexe query-params bevatten.',
			],
			'gravityforms/gravityforms.php' => [
				'name'   => 'Gravity Forms',
				'risk'   => 'low',
				'avoid'  => [],
				'reason' => 'Standaard form submissions zijn meestal cleaner. Wel oppassen met externe API-calls vanuit GF.',
			],
			'wp-stateless' => [
				'name'   => 'WP-Stateless',
				'risk'   => 'medium',
				'avoid'  => [ 'block_bad_user_agents' ],
				'reason' => 'Google Cloud SDK gebruikt soms generieke UAs.',
			],
			'akismet' => [
				'name'   => 'Akismet',
				'risk'   => 'low',
				'avoid'  => [],
				'reason' => 'Akismet uitgaande calls — geen impact.',
			],
			'wordfence' => [
				'name'   => 'Wordfence',
				'risk'   => 'medium',
				'avoid'  => [],
				'reason' => 'Dubbele security plugins kunnen conflicteren — overweeg uitschakelen van overlap.',
			],
			'all-in-one-wp-migration' => [
				'name'   => 'All-in-One WP Migration',
				'risk'   => 'medium',
				'avoid'  => [ 'lockdown_plugins', 'disallow_file_mods' ],
				'reason' => 'Migratie-tooling vereist file mods.',
			],
			'wp-mail-smtp' => [
				'name'   => 'WP Mail SMTP',
				'risk'   => 'low',
				'avoid'  => [],
				'reason' => 'Mail-only — geen impact.',
			],
			'updraftplus' => [
				'name'   => 'UpdraftPlus',
				'risk'   => 'medium',
				'avoid'  => [ 'block_bad_user_agents' ],
				'reason' => 'Cloud-storage SDKs kunnen generieke UAs gebruiken.',
			],
		];

		// Match elke active plugin tegen bekende patronen.
		foreach ( $active_plugins as $plugin_file ) {
			foreach ( $known as $needle => $info ) {
				if ( false !== stripos( $plugin_file, $needle ) ) {
					$detections[] = $info;
					break;
				}
			}
		}

		// Detecteer custom Exact / ERP integraties op naamfragmenten.
		$erp_fragments = [ 'exact', 'snelstart', 'moneybird', 'twinfield', 'erp-' ];
		foreach ( $active_plugins as $plugin_file ) {
			foreach ( $erp_fragments as $frag ) {
				if ( false !== stripos( $plugin_file, $frag ) ) {
					$detections[] = [
						'name'   => 'ERP/boekhouding integratie (' . $plugin_file . ')',
						'risk'   => 'high',
						'avoid'  => [ 'block_bad_user_agents', 'block_bad_url_content' ],
						'reason' => 'Externe ERP-integraties gebruiken vaak afwijkende User-Agents (curl/Java/Go) en complexe URL-patronen voor sync.',
					];
					break 2;
				}
			}
		}

		// Detecteer Avada (Fusion).
		$theme = wp_get_theme();
		if ( 'Avada' === $theme->get( 'Template' ) || 'Avada' === $theme->get( 'Name' ) ) {
			$detections[] = [
				'name'   => 'Avada theme',
				'risk'   => 'low',
				'avoid'  => [],
				'reason' => 'Avada Fusion Builder werkt prima met defaults. Wel oppassen met file_mods bij theme-options updates.',
			];
		}

		return $detections;
	}

	/**
	 * Bepaal het aanbevolen profiel op basis van detecties.
	 */
	public static function recommend_profile() {
		$detections    = self::detect_integrations();
		$highest_risk  = 'low';
		$avoid_globaal = [];

		foreach ( $detections as $d ) {
			if ( 'high' === $d['risk'] ) {
				$highest_risk = 'high';
			} elseif ( 'medium' === $d['risk'] && 'high' !== $highest_risk ) {
				$highest_risk = 'medium';
			}
			$avoid_globaal = array_merge( $avoid_globaal, $d['avoid'] );
		}

		$avoid_globaal = array_unique( $avoid_globaal );

		switch ( $highest_risk ) {
			case 'high':
				$profile = 'basic';
				break;
			case 'medium':
				$profile = 'standard';
				break;
			default:
				$profile = 'strict';
				break;
		}

		return [
			'profile'      => $profile,
			'reasoning'    => $highest_risk,
			'avoid'        => $avoid_globaal,
			'detections'   => $detections,
		];
	}
}
