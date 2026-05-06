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
	 */
	public static function write( array $settings ) {
		$htaccess_path = self::get_htaccess_path();
		if ( ! $htaccess_path ) {
			return new WP_Error( 'not_found', '.htaccess niet gevonden.' );
		}
		if ( ! is_writable( $htaccess_path ) ) {
			return new WP_Error( 'not_writable', '.htaccess is niet schrijfbaar.' );
		}

		// Remove existing block first.
		self::remove();

		$rules = self::build_rules( $settings );
		if ( empty( $rules ) ) {
			return true;
		}

		$block  = self::START_MARKER . "\n";
		$block .= $rules;
		$block .= self::END_MARKER . "\n\n";

		$content = file_get_contents( $htaccess_path );

		// Insert before WordPress rewrite block.
		$wp_marker = '# BEGIN WordPress';
		$pos       = strpos( $content, $wp_marker );
		if ( false !== $pos ) {
			$content = substr( $content, 0, $pos ) . $block . substr( $content, $pos );
		} else {
			// Prepend if no WordPress block found.
			$content = $block . $content;
		}

		return file_put_contents( $htaccess_path, $content ) !== false;
	}

	/**
	 * Remove security rules from .htaccess.
	 */
	public static function remove() {
		$htaccess_path = self::get_htaccess_path();
		if ( ! $htaccess_path || ! is_writable( $htaccess_path ) ) {
			return false;
		}

		$content = file_get_contents( $htaccess_path );
		$pattern = '/' . preg_quote( self::START_MARKER, '/' ) . '.*?' . preg_quote( self::END_MARKER, '/' ) . '\s*/s';
		$content = preg_replace( $pattern, '', $content );

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
# Block .log and .txt files
<FilesMatch "\.(log|txt)$">
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
