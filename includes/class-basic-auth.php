<?php
/**
 * MCM Basic Auth — HTTP-wachtwoordbeveiliging voor staging.
 *
 * Schrijft een AuthBasic-blok in de site-root .htaccess en een
 * .htpasswd-bestand in de plugin-folder (afgeschermd door eigen .htaccess).
 *
 * Werkt alleen op staging — MCM_Staging_Detector::is_staging() moet true zijn.
 *
 * Wachtwoord-flow:
 *   1. Marco klikt "Activeer & genereer wachtwoord"
 *   2. Plugin genereert random plain-text wachtwoord (16 chars)
 *   3. Bcrypt-hash wordt opgeslagen in .htpasswd
 *   4. Plain-text wordt 30 minuten in transient gezet (zodat Marco 'm kan
 *      kopiëren of mailen). Daarna verdwijnt de plain-text definitief.
 *   5. Wachtwoord vergeten? → "Regenereer" knop maakt nieuwe.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Basic_Auth {

	const HTACCESS_START = '# BEGIN MCM Security - Basic Auth';
	const HTACCESS_END   = '# END MCM Security - Basic Auth';

	const SETTING_ENABLED = 'basic_auth_enabled';
	const SETTING_USER    = 'basic_auth_user';
	// We bewaren GEEN hash in DB — die staat in .htpasswd. DB heeft alleen status + user.

	const TRANSIENT_PLAIN = 'mcm_basic_auth_plain_password';
	const PLAIN_TTL       = 1800; // 30 minuten

	const REALM = 'Staging - MCM Beveiliging';

	/**
	 * Pad naar .htpasswd (in plugin-folder, beschermd door eigen .htaccess).
	 */
	public static function htpasswd_path() {
		return MCM_SECURITY_DIR . '.htpasswd';
	}

	/**
	 * Pad naar de site-root .htaccess.
	 */
	public static function root_htaccess_path() {
		$path = ABSPATH . '.htaccess';
		return file_exists( $path ) ? $path : false;
	}

	/**
	 * Is Basic Auth nu actief? (block staat in .htaccess + htpasswd bestaat)
	 */
	public static function is_active() {
		$ht = self::root_htaccess_path();
		if ( ! $ht ) {
			return false;
		}
		$content = @file_get_contents( $ht );
		if ( false === $content ) {
			return false;
		}
		return ( false !== strpos( $content, self::HTACCESS_START ) ) && file_exists( self::htpasswd_path() );
	}

	/**
	 * Activeer Basic Auth: genereer nieuw wachtwoord, schrijf bestanden.
	 *
	 * @param string $user Gebruikersnaam (default: "staging").
	 * @return array|WP_Error ['user' => ..., 'password' => 'plain text'] of WP_Error.
	 */
	public static function activate( $user ) {
		// Veiligheidscheck: alleen op staging.
		if ( ! self::is_staging_or_overridden() ) {
			return new WP_Error( 'not_staging', 'Basic Auth mag alleen op staging draaien. Definieer MCM_IS_STAGING = true in wp-config.php als override.' );
		}

		$user = self::sanitize_user( $user );
		if ( '' === $user ) {
			return new WP_Error( 'invalid_user', 'Ongeldige gebruikersnaam.' );
		}

		$ht = self::root_htaccess_path();
		if ( ! $ht ) {
			return new WP_Error( 'no_htaccess', 'Site-root .htaccess niet gevonden.' );
		}
		if ( ! is_writable( $ht ) ) {
			return new WP_Error( 'not_writable', 'Site-root .htaccess is niet schrijfbaar.' );
		}

		$plain = self::generate_password();
		$hash  = password_hash( $plain, PASSWORD_BCRYPT );
		if ( false === $hash ) {
			return new WP_Error( 'hash_failed', 'Wachtwoord-hash mislukt.' );
		}

		// Backup .htaccess vóór wijziging — voor handmatig herstel als 't fout gaat.
		@copy( $ht, $ht . '.mcm-backup' );

		if ( ! self::write_htpasswd( $user, $hash ) ) {
			return new WP_Error( 'htpasswd_write', 'Kon .htpasswd niet schrijven.' );
		}
		self::protect_htpasswd_folder();

		if ( ! self::write_htaccess_block() ) {
			// Rollback htpasswd.
			@unlink( self::htpasswd_path() );
			return new WP_Error( 'htaccess_write', 'Kon .htaccess block niet schrijven.' );
		}

		// Settings + transient.
		$settings = get_option( 'mcm_security_settings', [] );
		$settings[ self::SETTING_ENABLED ] = true;
		$settings[ self::SETTING_USER ]    = $user;
		update_option( 'mcm_security_settings', $settings );
		set_transient( self::TRANSIENT_PLAIN, $plain, self::PLAIN_TTL );

		return [ 'user' => $user, 'password' => $plain ];
	}

	/**
	 * Deactiveer: verwijder htaccess block + .htpasswd + transient.
	 */
	public static function deactivate() {
		self::remove_htaccess_block();
		@unlink( self::htpasswd_path() );
		delete_transient( self::TRANSIENT_PLAIN );

		$settings = get_option( 'mcm_security_settings', [] );
		$settings[ self::SETTING_ENABLED ] = false;
		update_option( 'mcm_security_settings', $settings );

		return true;
	}

	/**
	 * Genereer nieuw wachtwoord (overschrijft .htpasswd, htaccess blijft).
	 */
	public static function regenerate_password() {
		$settings = get_option( 'mcm_security_settings', [] );
		$user     = isset( $settings[ self::SETTING_USER ] ) ? $settings[ self::SETTING_USER ] : 'staging';
		if ( ! self::is_active() ) {
			return new WP_Error( 'not_active', 'Basic Auth is niet actief — gebruik Activeer in plaats van regenereren.' );
		}

		$plain = self::generate_password();
		$hash  = password_hash( $plain, PASSWORD_BCRYPT );
		if ( ! self::write_htpasswd( $user, $hash ) ) {
			return new WP_Error( 'htpasswd_write', 'Kon .htpasswd niet herschrijven.' );
		}
		set_transient( self::TRANSIENT_PLAIN, $plain, self::PLAIN_TTL );

		return [ 'user' => $user, 'password' => $plain ];
	}

	/**
	 * Lees plain-text wachtwoord uit transient (alleen beschikbaar binnen TTL).
	 */
	public static function get_plain_password() {
		return get_transient( self::TRANSIENT_PLAIN );
	}

	/**
	 * Genereer veilig random wachtwoord.
	 */
	public static function generate_password( $length = 16 ) {
		// Geen verwarrende chars (0/O, 1/l/I).
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
	 * Schrijf .htpasswd in standaard Apache formaat: "user:bcrypt-hash\n"
	 */
	private static function write_htpasswd( $user, $hash ) {
		$content = $user . ':' . $hash . "\n";
		$result  = @file_put_contents( self::htpasswd_path(), $content );
		if ( false === $result ) {
			return false;
		}
		@chmod( self::htpasswd_path(), 0640 );
		return true;
	}

	/**
	 * Beveilig de plugin-folder — kleine .htaccess die .htpasswd afschermt.
	 * Nodig zodat .htpasswd niet via HTTP opvraagbaar is.
	 */
	private static function protect_htpasswd_folder() {
		$plugin_htaccess = MCM_SECURITY_DIR . '.htaccess';
		$content = "# Bescherm .htpasswd tegen publieke toegang\n";
		$content .= "<Files \".htpasswd\">\n";
		$content .= "    Require all denied\n";
		$content .= "    # Apache 2.2 fallback\n";
		$content .= "    <IfModule !mod_authz_core.c>\n";
		$content .= "        Order allow,deny\n";
		$content .= "        Deny from all\n";
		$content .= "    </IfModule>\n";
		$content .= "</Files>\n";
		@file_put_contents( $plugin_htaccess, $content );
		@chmod( $plugin_htaccess, 0644 );
	}

	/**
	 * Schrijf het AuthBasic-block in site-root .htaccess (vóór WordPress block).
	 */
	private static function write_htaccess_block() {
		$ht = self::root_htaccess_path();
		if ( ! $ht ) {
			return false;
		}

		// Verwijder eerst eventueel bestaand block.
		self::remove_htaccess_block();

		$content = file_get_contents( $ht );
		if ( false === $content ) {
			return false;
		}

		$abs_htpasswd = self::htpasswd_path();
		$block  = self::HTACCESS_START . "\n";
		$block .= "AuthType Basic\n";
		$block .= 'AuthName "' . self::REALM . '"' . "\n";
		$block .= 'AuthUserFile "' . $abs_htpasswd . '"' . "\n";
		$block .= "Require valid-user\n";
		$block .= self::HTACCESS_END . "\n\n";

		// Plaats vóór '# BEGIN MCM Security Hardener' als die er is, anders helemaal bovenaan.
		$pos = strpos( $content, '# BEGIN MCM Security Hardener' );
		if ( false === $pos ) {
			$pos = strpos( $content, '# BEGIN WordPress' );
		}
		if ( false !== $pos ) {
			$content = substr( $content, 0, $pos ) . $block . substr( $content, $pos );
		} else {
			$content = $block . $content;
		}

		return file_put_contents( $ht, $content ) !== false;
	}

	/**
	 * Verwijder het AuthBasic-block uit .htaccess.
	 */
	private static function remove_htaccess_block() {
		$ht = self::root_htaccess_path();
		if ( ! $ht || ! is_writable( $ht ) ) {
			return false;
		}
		$content = file_get_contents( $ht );
		$pattern = '/' . preg_quote( self::HTACCESS_START, '/' ) . '.*?' . preg_quote( self::HTACCESS_END, '/' ) . '\s*/s';
		$content = preg_replace( $pattern, '', $content );
		return file_put_contents( $ht, $content ) !== false;
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
}
