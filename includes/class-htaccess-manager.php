<?php
/**
 * Manages security rules in .htaccess.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Htaccess_Manager {

	const START_MARKER = '# BEGIN MCM Security Hardener';
	const END_MARKER   = '# END MCM Security Hardener';

	/**
	 * Write security rules to .htaccess.
	 *
	 * Veilig schrijven: de nieuwe inhoud wordt in één keer weggeschreven, er
	 * wordt vooraf een back-up gezet in uploads/mcm-security-backups/, en een
	 * loopback-request naar de homepage controleert na het schrijven of de
	 * site nog werkt. Geeft die een 5xx, een time-out of een nieuwe 403, dan
	 * wordt de oude .htaccess direct teruggezet en krijgt de eigenaar een mail.
	 *
	 * @param array $settings Plugin-instellingen.
	 * @param bool  $require_verification True = niet schrijven als de loopback
	 *                                    vooraf al niet werkt (voor de
	 *                                    automatische upgrade-routine, waar
	 *                                    niemand meekijkt). False = dan toch
	 *                                    schrijven, zonder controle achteraf
	 *                                    (handmatig opslaan: oud gedrag).
	 * @return true|WP_Error
	 */
	public static function write( array $settings, $require_verification = false ) {
		$htaccess_path = self::get_htaccess_path();
		if ( ! $htaccess_path ) {
			return new WP_Error( 'not_found', '.htaccess niet gevonden.' );
		}
		if ( ! is_writable( $htaccess_path ) ) {
			return new WP_Error( 'not_writable', '.htaccess is niet schrijfbaar.' );
		}

		$old_content = file_get_contents( $htaccess_path );
		if ( false === $old_content ) {
			return new WP_Error( 'not_readable', '.htaccess kon niet gelezen worden.' );
		}
		$new_content = self::build_content( $old_content, self::build_rules( $settings ) );

		if ( $new_content === $old_content ) {
			return true; // Niets veranderd: niet schrijven, geen loopback.
		}

		$baseline = self::loopback_status();
		if ( null === $baseline && $require_verification ) {
			return new WP_Error(
				'loopback_unavailable',
				'.htaccess niet bijgewerkt: de site kan zichzelf niet bereiken (loopback-request faalt), dus na het schrijven valt niet te controleren of de site nog werkt.'
			);
		}

		self::backup( $old_content );

		if ( false === file_put_contents( $htaccess_path, $new_content ) ) {
			return new WP_Error( 'write_failed', '.htaccess kon niet worden weggeschreven.' );
		}

		if ( null === $baseline ) {
			return true; // Geen controle mogelijk; handmatig opslaan gaat door zoals voorheen.
		}

		$after = self::loopback_status();
		if ( ! self::is_broken( $baseline, $after ) ) {
			return true;
		}

		file_put_contents( $htaccess_path, $old_content );

		$after_label = null === $after ? 'time-out / geen antwoord' : 'HTTP ' . $after;
		MCM_Notifier::email(
			'.htaccess-wijziging automatisch teruggedraaid',
			"Na het bijwerken van de .htaccess reageerde de homepage niet meer goed.\n\n" .
			"Voor de wijziging: HTTP {$baseline}\n" .
			"Na de wijziging:   {$after_label}\n\n" .
			"De vorige .htaccess is direct teruggezet. Een kopie van de oude versie staat in wp-content/uploads/mcm-security-backups/.\n" .
			"Controleer welke regel hier niet wordt ondersteund voordat je opnieuw opslaat."
		);

		return new WP_Error(
			'reverted',
			sprintf( 'De nieuwe .htaccess brak de site (%s) en is automatisch teruggedraaid.', $after_label )
		);
	}

	/**
	 * Zet ons blok (opnieuw) in de .htaccess-inhoud: bestaand blok eruit,
	 * nieuw blok vóór "# BEGIN WordPress". Lege $rules = alleen verwijderen.
	 */
	private static function build_content( $content, $rules ) {
		$pattern = '/' . preg_quote( self::START_MARKER, '/' ) . '.*?' . preg_quote( self::END_MARKER, '/' ) . '\s*/s';
		$content = preg_replace( $pattern, '', $content );

		if ( '' === $rules ) {
			return $content;
		}

		$block  = self::START_MARKER . "\n";
		$block .= $rules;
		$block .= self::END_MARKER . "\n\n";

		// Insert before WordPress rewrite block, anders vooraan.
		$pos = strpos( $content, '# BEGIN WordPress' );
		if ( false !== $pos ) {
			return substr( $content, 0, $pos ) . $block . substr( $content, $pos );
		}
		return $block . $content;
	}

	/**
	 * HTTP-status van de homepage via een loopback-request, of null als er
	 * geen antwoord komt (time-out, DNS, geblokkeerde loopback). Cache-buster
	 * + no-cache-headers, anders geeft Varnish een oude 200 terug.
	 */
	public static function loopback_status() {
		$url = add_query_arg( 'mcm-loopback', wp_generate_password( 8, false ), home_url( '/' ) );

		$response = wp_remote_get(
			$url,
			[
				'timeout'     => 10,
				'redirection' => 3,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
				'headers'     => [
					'Cache-Control' => 'no-cache',
					'Pragma'        => 'no-cache',
				],
			]
		);

		if ( is_wp_error( $response ) ) {
			return null;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		return $code > 0 ? $code : null;
	}

	/**
	 * Is de site door de wijziging stukgegaan? Alleen een verslechtering
	 * telt: een 401 (Basic Auth op staging) of 404 die er vóór ook al was
	 * is prima.
	 */
	private static function is_broken( $baseline, $after ) {
		if ( null === $after || $after >= 500 ) {
			return true;
		}
		return 403 === $after && 403 !== $baseline;
	}

	/**
	 * Back-up van de huidige .htaccess in de back-upmap (MCM_Backup_Store:
	 * .php met guard, dus ook op nginx niet publiek). Houdt de laatste 10.
	 */
	private static function backup( $content ) {
		MCM_Backup_Store::save( 'htaccess', '.php', $content, 10 );
	}

	/**
	 * Remove security rules from .htaccess.
	 */
	public static function remove() {
		$htaccess_path = self::get_htaccess_path();
		if ( ! $htaccess_path || ! is_writable( $htaccess_path ) ) {
			return false;
		}

		$content = self::build_content( file_get_contents( $htaccess_path ), '' );

		return file_put_contents( $htaccess_path, $content ) !== false;
	}

	/**
	 * Check if our block exists in .htaccess.
	 */
	public static function is_active() {
		$htaccess_path = self::get_htaccess_path();
		if ( ! $htaccess_path ) {
			return false;
		}
		$content = file_get_contents( $htaccess_path );
		return strpos( $content, self::START_MARKER ) !== false;
	}

	/**
	 * Build all .htaccess rules from settings.
	 */
	private static function build_rules( array $s ) {
		$rules = '';

		// 1. Block readme, changelog, debug files.
		if ( ! empty( $s['block_readme_files'] ) ) {
			$rules .= <<<'HTACCESS'
# Block readme/changelog/debug disclosure
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^(.*/)?(readme|changelog|debug)\.(txt|md|log|html?)$ - [R=404,L,NC]
</IfModule>

HTACCESS;
		}

		// 2. Block direct access to sensitive PHP files.
		if ( ! empty( $s['block_sensitive_php'] ) ) {
			$rules .= <<<'HTACCESS'
# Block direct access to sensitive files
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !wp-includes/js/tinymce/wp-tinymce\.php$
    RewriteRule ^(php\.ini|wp-config\.php|wp-includes/.+\.php|wp-admin/(admin-functions|install|menu-header|setup-config|([^/]+/)?menu|upgrade-functions|includes/.+)\.php)$ - [R=404,L,NC]
</IfModule>

<FilesMatch "^(readme\.html|install\.php|wp-config\.php)$">
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</FilesMatch>

HTACCESS;
		}

		// 3. Disable directory listing.
		if ( ! empty( $s['disable_directory_listing'] ) ) {
			$rules .= <<<'HTACCESS'
# Disable directory listing
<IfModule mod_autoindex.c>
    Options -Indexes
</IfModule>

HTACCESS;
		}

		// 4. Block PHP Easter Eggs / info disclosure.
		if ( ! empty( $s['block_php_easter_eggs'] ) ) {
			$rules .= <<<'HTACCESS'
# Block PHP info disclosure (Easter Eggs)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC]
    RewriteRule .* - [F]
</IfModule>

HTACCESS;
		}

		// 5. Block script concatenation DoS.
		if ( ! empty( $s['block_script_concat'] ) ) {
			$rules .= <<<'HTACCESS'
# Block load-scripts/load-styles concatenation DoS
<FilesMatch "load-scripts\.php|load-styles\.php">
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</FilesMatch>

HTACCESS;
		}

		// 6. Block XML-RPC.
		if ( ! empty( $s['block_xmlrpc'] ) ) {
			$rules .= <<<'HTACCESS'
# Block XML-RPC
<Files xmlrpc.php>
    <IfModule !mod_authz_core.c>
        Order Deny,Allow
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</Files>

HTACCESS;
		}

		// 7. Block debug.log.
		if ( ! empty( $s['block_debug_log'] ) ) {
			$rules .= <<<'HTACCESS'
# Block debug.log access
<Files "debug.log">
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</Files>

HTACCESS;
		}

		// 8. Block .log and .txt files.
		if ( ! empty( $s['block_log_txt_files'] ) ) {
			$rules .= <<<'HTACCESS'
# Block .log and .txt files (behalve robots.txt & co, die WordPress of de
# site zelf publiek hoort te serveren)
<FilesMatch "^(?!(robots|ads|app-ads|llms|llms-full|humans|security)\.txt$).+\.(log|txt)$">
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</FilesMatch>

HTACCESS;
		}

		// 9. Block PHP execution in uploads.
		if ( ! empty( $s['block_php_in_uploads'] ) ) {
			$rules .= <<<'HTACCESS'
# Block PHP execution in uploads directory
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^wp-content/uploads/.*\.(php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$ - [F,L]
</IfModule>

HTACCESS;
		}

		// 10. Block direct access to wp-includes PHP files.
		if ( ! empty( $s['block_wp_includes_php'] ) ) {
			$rules .= <<<'HTACCESS'
# Block direct PHP access in wp-includes
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !wp-includes/js/tinymce/wp-tinymce\.php$ [NC]
    RewriteCond %{REQUEST_URI} !wp-includes/js/ [NC]
    RewriteRule ^wp-includes/.*\.php$ - [F,L]
</IfModule>

HTACCESS;
		}

		// 11. Remove PHP version header + server signature.
		if ( ! empty( $s['hide_php_version'] ) ) {
			$rules .= <<<'HTACCESS'
# Remove PHP version and server signature
<IfModule mod_headers.c>
    Header unset X-Powered-By
    Header always unset X-Powered-By
</IfModule>
ServerSignature Off

HTACCESS;
		}

		// 12. Remove WordPress version from meta + feeds.
		if ( ! empty( $s['hide_wp_version'] ) ) {
			$rules .= <<<'HTACCESS'
# Block access to WordPress readme (version disclosure)
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^readme\.html$ - [R=404,L,NC]
</IfModule>

HTACCESS;
		}

		// 13. Blokkeer risico-bestandsnamen die de exposure-scanner detecteert.
		// Zelfde lijst-categorie als MCM_File_Exposure_Scanner::risky_filename_patterns()
		// maar dan als preventieve laag op Apache-niveau.
		if ( ! empty( $s['block_risky_files_via_htaccess'] ) ) {
			$rules .= <<<'HTACCESS'
# Block risky test/debug files (info.php, .env, SQL-dumps, wp-config backups, etc.)
<FilesMatch "^(info|phpinfo|test|php|i|adminer.*)\.php$">
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</FilesMatch>
<FilesMatch "(^\.env|^\.env\.|wp-config\.php\.(bak|save|old|orig|tmp|txt)$|wp-config\.php~$)">
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</FilesMatch>
<FilesMatch "\.(sql|sql\.gz)$">
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</FilesMatch>
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteRule ^phpmyadmin(/|$) - [F,L,NC]
</IfModule>

HTACCESS;
		}

		// 14. Blokkeer directe download van archieven/dumps in uploads.
		// Preventieve tegenhanger van niveau 2 van de exposure-scanner: die
		// vindt zips die er al staan, dit blokkeert ook de zip die er morgen
		// wordt neergezet. Aanleiding: twee publiek downloadbare premium
		// plugin-zips in uploads/2023/01/ op susenso.nl (Xel-scan 2026-08-17).
		//
		// Twee uitzonderingen, anders breken legitieme downloads:
		//   - woocommerce_uploads      : downloadbare producten (Woo serveert
		//                                die zelf, soms via redirect naar de
		//                                directe URL)
		//   - wp-personal-data-exports : AVG-exports die WordPress als zip
		//                                naar de gebruiker mailt
		if ( ! empty( $s['block_archives_in_uploads'] ) ) {
			$rules .= <<<'HTACCESS'
# Block direct download of archives/dumps in uploads
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} !^/wp-content/uploads/woocommerce_uploads/ [NC]
    RewriteCond %{REQUEST_URI} !^/wp-content/uploads/wp-personal-data-exports/ [NC]
    RewriteRule ^wp-content/uploads/.*\.(zip|rar|7z|tar|tgz|gz|bz2|sql|bak|old|sav)$ - [F,L,NC]
</IfModule>

HTACCESS;
		}

		return $rules;
	}

	/**
	 * Locate .htaccess.
	 */
	private static function get_htaccess_path() {
		$path = ABSPATH . '.htaccess';
		return file_exists( $path ) ? $path : false;
	}
}
