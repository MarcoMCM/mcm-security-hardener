<?php
/**
 * MCM Basic Auth — HTTP-wachtwoordbeveiliging voor staging.
 *
 * PHP-based (geen .htaccess wijzigingen) — werkt op elke host, geen
 * AllowOverride AuthConfig nodig. WordPress laadt vóór de auth-check,
 * voor staging is dat acceptabel qua performance.
 *
 * Werkt alleen op staging — MCM_Staging_Detector::is_staging() moet true zijn.
 *
 * Wachtwoord-flow:
 *   1. Marco klikt "Activeer & genereer wachtwoord"
 *   2. Plugin genereert random plain-text wachtwoord (16 chars)
 *   3. Bcrypt-hash wordt opgeslagen in aparte WP option (mcm_security_basic_auth_hash)
 *   4. Plain-text wordt 30 minuten in transient gezet (zodat Marco 'm kan
 *      kopiëren of mailen). Daarna verdwijnt de plain-text definitief.
 *   5. Wachtwoord vergeten? → "Regenereer" knop maakt nieuwe.
 *
 * Bypass-paden (auth wordt niet getriggerd):
 *   - WP-CLI commands
 *   - WordPress cron (wp_doing_cron())
 *   - REST API requests (default — geen Basic Auth challenge op /wp-json/)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Basic_Auth {

	const SETTING_ENABLED = 'basic_auth_enabled';
	const SETTING_USER    = 'basic_auth_user';

	// Hash apart van mcm_security_settings (security separation).
	const HASH_OPTION = 'mcm_security_basic_auth_hash';

	const TRANSIENT_PLAIN = 'mcm_basic_auth_plain_password';
	const PLAIN_TTL       = 1800; // 30 minuten

	const REALM = 'Staging - MCM Beveiliging';

	/**
	 * Hook de challenge zo vroeg mogelijk in.
	 * Wordt aangeroepen vanuit hoofd plugin-file.
	 */
	public static function init() {
		add_action( 'plugins_loaded', [ __CLASS__, 'maybe_challenge' ], 0 );
	}

	/**
	 * Is Basic Auth nu actief?
	 */
	public static function is_active() {
		$settings = get_option( 'mcm_security_settings', [] );
		if ( empty( $settings[ self::SETTING_ENABLED ] ) ) {
			return false;
		}
		return ! empty( get_option( self::HASH_OPTION ) );
	}

	/**
	 * Hoofd-challenge: check credentials of stuur 401.
	 * Hook: plugins_loaded priority 0.
	 */
	public static function maybe_challenge() {
		if ( ! self::is_active() ) {
			return;
		}

		// Bypass-paden — auth niet triggeren.
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}
		// REST API: laat door zonder challenge.
		// (Anders breken externe integraties + WP block-editor REST calls.)
		if ( self::is_rest_request() ) {
			return;
		}

		// Credentials uitlezen — meerdere fallbacks voor PHP-FPM compatibility.
		list( $user, $pass ) = self::get_credentials();

		// Geen credentials → toon login-popup.
		if ( null === $user ) {
			self::send_challenge();
		}

		// Credentials check.
		$settings = get_option( 'mcm_security_settings', [] );
		$expected_user = isset( $settings[ self::SETTING_USER ] ) ? $settings[ self::SETTING_USER ] : 'staging';
		$hash = get_option( self::HASH_OPTION );

		if ( $user === $expected_user && password_verify( $pass, $hash ) ) {
			return; // OK, laat door.
		}

		// Foute credentials → opnieuw popup.
		self::send_challenge();
	}

	/**
	 * Detecteer of dit een REST API request is — voor 'rest_api_init' is er
	 * geen WordPress-helper, dus check via URI.
	 */
	private static function is_rest_request() {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return true;
		}
		$uri = $_SERVER['REQUEST_URI'] ?? '';
		// Standaard rest prefix is wp-json; sites met custom prefix vallen hier buiten.
		return false !== strpos( $uri, '/wp-json/' );
	}

	/**
	 * Lees Basic Auth credentials — meerdere fallbacks (mod_php / PHP-FPM / FCGI).
	 *
	 * @return array [user, pass] — user is null als niets gevonden.
	 */
	private static function get_credentials() {
		// 1. Standaard mod_php / FPM met juiste config.
		if ( isset( $_SERVER['PHP_AUTH_USER'] ) ) {
			return [ $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ?? '' ];
		}

		// 2. apache_request_headers fallback (FPM met config).
		if ( function_exists( 'apache_request_headers' ) ) {
			$headers = apache_request_headers();
			$auth = $headers['Authorization'] ?? ( $headers['authorization'] ?? null );
			$creds = self::parse_basic_header( $auth );
			if ( $creds ) {
				return $creds;
			}
		}

		// 3. $_SERVER raw fallbacks.
		foreach ( [ 'HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION', 'REDIRECT_REDIRECT_HTTP_AUTHORIZATION' ] as $key ) {
			if ( isset( $_SERVER[ $key ] ) ) {
				$creds = self::parse_basic_header( $_SERVER[ $key ] );
				if ( $creds ) {
					return $creds;
				}
			}
		}

		return [ null, null ];
	}

	/**
	 * Parse "Basic base64encoded" header naar [user, pass] of null.
	 */
	private static function parse_basic_header( $header ) {
		if ( ! $header || stripos( $header, 'Basic ' ) !== 0 ) {
			return null;
		}
		$decoded = base64_decode( substr( $header, 6 ), true );
		if ( false === $decoded || strpos( $decoded, ':' ) === false ) {
			return null;
		}
		return explode( ':', $decoded, 2 );
	}

	/**
	 * Stuur 401 met WWW-Authenticate Basic — browser toont popup.
	 */
	private static function send_challenge() {
		header( 'WWW-Authenticate: Basic realm="' . self::REALM . '"' );
		header( 'HTTP/1.0 401 Unauthorized' );
		// Cache nooit een 401 om verwarring te voorkomen.
		header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		echo '<!DOCTYPE html><html><head><title>Toegang vereist</title></head><body>';
		echo '<h1>Toegang vereist</h1>';
		echo '<p>Deze stagingomgeving is afgeschermd. Vul je toegangsgegevens in via de browser-popup.</p>';
		echo '</body></html>';
		exit;
	}

	/**
	 * Activeer: genereer wachtwoord, sla hash op.
	 *
	 * @param string $user Gebruikersnaam (default: "staging").
	 * @return array|WP_Error ['user' => ..., 'password' => 'plain text'] of WP_Error.
	 */
	public static function activate( $user ) {
		if ( ! self::is_staging_or_overridden() ) {
			return new WP_Error( 'not_staging', 'Basic Auth mag alleen op staging draaien. Definieer MCM_IS_STAGING = true in wp-config.php als override.' );
		}

		$user = self::sanitize_user( $user );
		if ( '' === $user ) {
			return new WP_Error( 'invalid_user', 'Ongeldige gebruikersnaam.' );
		}

		$plain = self::generate_password();
		$hash  = password_hash( $plain, PASSWORD_BCRYPT );
		if ( false === $hash ) {
			return new WP_Error( 'hash_failed', 'Wachtwoord-hash mislukt.' );
		}

		update_option( self::HASH_OPTION, $hash, false ); // false = niet autoload (alleen geladen wanneer nodig).

		$settings = get_option( 'mcm_security_settings', [] );
		$settings[ self::SETTING_ENABLED ] = true;
		$settings[ self::SETTING_USER ]    = $user;
		update_option( 'mcm_security_settings', $settings );

		set_transient( self::TRANSIENT_PLAIN, $plain, self::PLAIN_TTL );

		return [ 'user' => $user, 'password' => $plain ];
	}

	/**
	 * Deactiveer: alle settings/hash/transient weg.
	 */
	public static function deactivate() {
		delete_option( self::HASH_OPTION );
		delete_transient( self::TRANSIENT_PLAIN );

		$settings = get_option( 'mcm_security_settings', [] );
		$settings[ self::SETTING_ENABLED ] = false;
		update_option( 'mcm_security_settings', $settings );

		// Legacy cleanup: oude .htpasswd/.htaccess restanten van eerdere v1.8.0.
		self::legacy_cleanup();

		return true;
	}

	/**
	 * Genereer nieuw wachtwoord (overschrijft hash, settings blijven).
	 */
	public static function regenerate_password() {
		if ( ! self::is_active() ) {
			return new WP_Error( 'not_active', 'Basic Auth is niet actief — gebruik Activeer in plaats van regenereren.' );
		}

		$plain = self::generate_password();
		$hash  = password_hash( $plain, PASSWORD_BCRYPT );
		update_option( self::HASH_OPTION, $hash, false );
		set_transient( self::TRANSIENT_PLAIN, $plain, self::PLAIN_TTL );

		return [
			'user'     => self::current_user(),
			'password' => $plain,
		];
	}

	/**
	 * Lees plain-text wachtwoord uit transient (alleen beschikbaar binnen TTL).
	 */
	public static function get_plain_password() {
		return get_transient( self::TRANSIENT_PLAIN );
	}

	/**
	 * Huidige opgeslagen username.
	 */
	public static function current_user() {
		$settings = get_option( 'mcm_security_settings', [] );
		return isset( $settings[ self::SETTING_USER ] ) ? $settings[ self::SETTING_USER ] : 'staging';
	}

	/**
	 * Genereer veilig random wachtwoord (geen verwarrende chars).
	 */
	public static function generate_password( $length = 16 ) {
		$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
		$max   = strlen( $chars ) - 1;
		$out   = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$out .= $chars[ random_int( 0, $max ) ];
		}
		return $out;
	}

	/**
	 * Sanitize username — alleen alfanumeriek + underscore + dash.
	 */
	public static function sanitize_user( $u ) {
		$u = preg_replace( '/[^a-zA-Z0-9_\-]/', '', (string) $u );
		return substr( $u, 0, 64 );
	}

	/**
	 * Check: staging detected of override actief?
	 */
	private static function is_staging_or_overridden() {
		if ( ! class_exists( 'MCM_Staging_Detector' ) ) {
			return false;
		}
		return MCM_Staging_Detector::is_staging();
	}

	/**
	 * Legacy: ruim .htaccess block + .htpasswd op uit v1.8.0/1.8.1 (file-based versie).
	 * Wordt aangeroepen bij deactivate. Veilig om altijd te draaien.
	 */
	private static function legacy_cleanup() {
		$ht = ABSPATH . '.htaccess';
		if ( file_exists( $ht ) && is_writable( $ht ) ) {
			$content = file_get_contents( $ht );
			$pattern = '/# BEGIN MCM Security - Basic Auth.*?# END MCM Security - Basic Auth\s*/s';
			$cleaned = preg_replace( $pattern, '', $content );
			if ( $cleaned !== $content ) {
				file_put_contents( $ht, $cleaned );
			}
		}
		@unlink( MCM_SECURITY_DIR . '.htpasswd' );
		@unlink( MCM_SECURITY_DIR . '.htaccess' );
	}
}
