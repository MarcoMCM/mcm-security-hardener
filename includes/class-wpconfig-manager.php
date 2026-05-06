<?php
/**
 * Manages security constants in wp-config.php.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_WPConfig_Manager {

	const START_MARKER = '# BEGIN MCM Security Hardener';
	const END_MARKER   = '# END MCM Security Hardener';

	/**
	 * Write security constants to wp-config.php.
	 */
	public static function write( array $settings ) {
		$config_path = self::get_config_path();
		if ( ! $config_path || ! is_writable( $config_path ) ) {
			return new WP_Error( 'not_writable', 'wp-config.php is niet schrijfbaar.' );
		}

		// First remove any existing block and restore commented-out lines.
		self::remove();

		$lines = self::build_lines( $settings );
		if ( empty( $lines ) ) {
			return true;
		}

		$config_content = file_get_contents( $config_path );

		// Comment out existing define() calls for the same constants to avoid duplicates.
		$constants = self::get_managed_constants( $settings );
		$config_content = self::comment_out_constants( $config_content, $constants );

		$block  = self::START_MARKER . "\n";
		$block .= implode( "\n", $lines ) . "\n";
		$block .= self::END_MARKER . "\n\n";

		// Insert right after the opening <?php tag.
		$pos = strpos( $config_content, '<?php' );
		if ( false !== $pos ) {
			$insert_at      = $pos + 5; // After <?php
			$config_content = substr( $config_content, 0, $insert_at ) . "\n" . $block . substr( $config_content, $insert_at );
		}

		return file_put_contents( $config_path, $config_content ) !== false;
	}

	/**
	 * Remove security constants from wp-config.php and restore original lines.
	 */
	public static function remove() {
		$config_path = self::get_config_path();
		if ( ! $config_path || ! is_writable( $config_path ) ) {
			return false;
		}

		$content = file_get_contents( $config_path );

		// Remove our injected block.
		$pattern = '/' . preg_quote( self::START_MARKER, '/' ) . '.*?' . preg_quote( self::END_MARKER, '/' ) . '\s*/s';
		$content = preg_replace( $pattern, '', $content );

		// Restore any lines we commented out.
		$content = self::restore_commented_constants( $content );

		return file_put_contents( $config_path, $content ) !== false;
	}

	/**
	 * Check if our block exists in wp-config.php.
	 */
	public static function is_active() {
		$config_path = self::get_config_path();
		if ( ! $config_path ) {
			return false;
		}
		$content = file_get_contents( $config_path );
		return strpos( $content, self::START_MARKER ) !== false;
	}

	/**
	 * Build the define() lines from settings.
	 */
	private static function build_lines( array $s ) {
		$lines = [];

		if ( ! empty( $s['disallow_unfiltered'] ) ) {
			$lines[] = "define( 'ALLOW_UNFILTERED_UPLOADS', false );";
		}
		if ( ! empty( $s['skip_bundled'] ) ) {
			$lines[] = "define( 'CORE_UPGRADE_SKIP_NEW_BUNDLED', true );";
		}
		if ( ! empty( $s['no_concatenate'] ) ) {
			$lines[] = "define( 'CONCATENATE_SCRIPTS', false );";
		}
		if ( ! empty( $s['no_repair'] ) ) {
			$lines[] = "define( 'WP_ALLOW_REPAIR', false );";
		}
		if ( ! empty( $s['no_relocate'] ) ) {
			$lines[] = "define( 'RELOCATE', false );";
		}
		if ( ! empty( $s['disallow_file_edit'] ) ) {
			$lines[] = "define( 'DISALLOW_FILE_EDIT', true );";
		}
		// DISALLOW_FILE_MODS is handled at runtime by MCM_Lockdown_Manager
		// so that administrators can still manage plugins/themes.
		if ( ! empty( $s['no_db_error'] ) ) {
			$lines[] = "define( 'DIEONDBERROR', false );";
		}
		if ( ! empty( $s['no_debug_display'] ) ) {
			$lines[] = "define( 'WP_DEBUG_DISPLAY', false );";
		}
		if ( ! empty( $s['lock_admin_email'] ) && ! empty( $s['admin_email'] ) ) {
			$email   = sanitize_email( $s['admin_email'] );
			$lines[] = "define( 'SECUPRESS_LOCKED_ADMIN_EMAIL', '{$email}' );";
		}
		if ( ! empty( $s['auto_update_minor'] ) ) {
			$lines[] = "define( 'WP_AUTO_UPDATE_CORE', 'minor' );";
		}
		if ( ! empty( $s['random_cookie_hash'] ) ) {
			$hash = get_option( 'mcm_cookie_hash', '' );
			if ( empty( $hash ) ) {
				$hash = bin2hex( random_bytes( 16 ) );
				update_option( 'mcm_cookie_hash', $hash );
			}
			$lines[] = "define( 'COOKIEHASH', '{$hash}' );";
		}
		if ( ! empty( $s['secure_keys'] ) ) {
			$keys = self::get_secure_keys();
			foreach ( $keys as $name => $value ) {
				$lines[] = "define( '{$name}', '{$value}' );";
			}
		}

		return $lines;
	}

	/**
	 * Generate or retrieve secure keys/salts.
	 */
	private static function get_secure_keys() {
		$key_names = [
			'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
			'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
		];

		$stored = get_option( 'mcm_secure_keys', [] );

		// Generate only if not yet stored.
		if ( empty( $stored ) || count( $stored ) !== count( $key_names ) ) {
			$stored = [];
			$chars  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
			$len    = strlen( $chars ) - 1;

			foreach ( $key_names as $name ) {
				$key = '';
				for ( $i = 0; $i < 64; $i++ ) {
					$key .= $chars[ random_int( 0, $len ) ];
				}
				// Escape single quotes for PHP define().
				$stored[ $name ] = str_replace( "'", "\\'", $key );
			}
			update_option( 'mcm_secure_keys', $stored );
		}

		return $stored;
	}

	/**
	 * Get list of constant names that our block will define.
	 */
	private static function get_managed_constants( array $s ) {
		$constants = [];

		if ( ! empty( $s['disallow_unfiltered'] ) )  $constants[] = 'ALLOW_UNFILTERED_UPLOADS';
		if ( ! empty( $s['skip_bundled'] ) )          $constants[] = 'CORE_UPGRADE_SKIP_NEW_BUNDLED';
		if ( ! empty( $s['no_concatenate'] ) )        $constants[] = 'CONCATENATE_SCRIPTS';
		if ( ! empty( $s['no_repair'] ) )             $constants[] = 'WP_ALLOW_REPAIR';
		if ( ! empty( $s['no_relocate'] ) )           $constants[] = 'RELOCATE';
		if ( ! empty( $s['disallow_file_edit'] ) )    $constants[] = 'DISALLOW_FILE_EDIT';
		// DISALLOW_FILE_MODS handled at runtime by MCM_Lockdown_Manager
		if ( ! empty( $s['no_db_error'] ) )           $constants[] = 'DIEONDBERROR';
		if ( ! empty( $s['no_debug_display'] ) )      $constants[] = 'WP_DEBUG_DISPLAY';
		if ( ! empty( $s['lock_admin_email'] ) )      $constants[] = 'SECUPRESS_LOCKED_ADMIN_EMAIL';
		if ( ! empty( $s['auto_update_minor'] ) )     $constants[] = 'WP_AUTO_UPDATE_CORE';
		if ( ! empty( $s['random_cookie_hash'] ) )    $constants[] = 'COOKIEHASH';
		if ( ! empty( $s['secure_keys'] ) ) {
			$constants = array_merge( $constants, [
				'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
				'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT',
			] );
		}

		return $constants;
	}

	/**
	 * Comment out existing define() calls for managed constants.
	 * Marks them with // MCM_DISABLED: so they can be restored later.
	 */
	private static function comment_out_constants( $content, array $constants ) {
		foreach ( $constants as $name ) {
			$pattern = '/^(\s*define\s*\(\s*[\'"]' . preg_quote( $name, '/' ) . '[\'"]\s*,.*\);.*)$/m';
			$content = preg_replace( $pattern, '// MCM_DISABLED: $1', $content );
		}
		return $content;
	}

	/**
	 * Restore lines that were commented out by comment_out_constants().
	 */
	private static function restore_commented_constants( $content ) {
		return preg_replace( '/^\/\/ MCM_DISABLED: (.*)$/m', '$1', $content );
	}

	/**
	 * Locate wp-config.php.
	 */
	private static function get_config_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		if ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
			return dirname( ABSPATH ) . '/wp-config.php';
		}
		return false;
	}
}
