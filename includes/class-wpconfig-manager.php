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

	// Placeholder used to reversibly neutralize a literal PHP closing tag
	// when a define() line gets turned into a comment — see comment_out_constants().
	const PHP_CLOSE_PLACEHOLDER = '__MCM_PHP_CLOSE_TAG__';

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

		// Safety net: never write a version of wp-config.php that isn't valid PHP.
		// A regex-based rewrite of live PHP source can't fully understand PHP's
		// own string-escaping rules, so a defensive syntax check before writing
		// is what actually prevents a broken site — not the regex being "clever".
		$syntax_check = self::check_syntax( $config_content );
		if ( is_wp_error( $syntax_check ) ) {
			return $syntax_check;
		}

		// Keep one rolling backup so a bad write is a one-command restore,
		// even in the case the syntax check above can't run on this host.
		@copy( $config_path, $config_path . '.mcm-backup' );

		return file_put_contents( $config_path, $config_content ) !== false;
	}

	/**
	 * Best-effort validation that $content is syntactically valid PHP.
	 *
	 * Uses `php -l` when the host allows shelling out. If exec() is disabled
	 * (common on locked-down hosting), falls back to a lightweight tokenizer
	 * check that at least catches the failure mode we've actually seen in
	 * production: a define() line getting truncated mid-string so PHP falls
	 * out of PHP mode and starts echoing the rest of the file as HTML.
	 */
	public static function check_syntax( $content ) {
		$php_binary = defined( 'PHP_BINARY' ) && PHP_BINARY ? PHP_BINARY : 'php';

		// On PHP-FPM, PHP_BINARY often resolves to the FPM daemon itself
		// (e.g. /usr/sbin/php-fpm8.3) rather than the CLI binary. That
		// binary doesn't support `-l` for linting — it just prints its own
		// usage text and exits non-zero — which would make every write
		// falsely look like invalid syntax. Verified on a live xel.nl host:
		// `php-fpm8.3 -l <file>` exits 64 with a usage dump, regardless of
		// the file's actual content. Skip straight to the tokenizer
		// fallback in that case instead of trusting a bogus exit code.
		$binary_is_fpm = (bool) preg_match( '/fpm/i', basename( $php_binary ) );

		if ( ! $binary_is_fpm && function_exists( 'exec' ) && ! in_array( 'exec', array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) ), true ) ) {
			$tmp_file = wp_tempnam( 'mcm-wpconfig-check' );
			if ( $tmp_file ) {
				file_put_contents( $tmp_file, $content );
				$output    = [];
				$exit_code = 0;
				exec( escapeshellarg( $php_binary ) . ' -l ' . escapeshellarg( $tmp_file ) . ' 2>&1', $output, $exit_code );
				@unlink( $tmp_file );

				if ( 0 !== $exit_code ) {
					return new WP_Error(
						'invalid_syntax',
						'Wijziging aan wp-config.php afgebroken: het resultaat is geen geldige PHP (php -l meldde: ' . implode( ' ', $output ) . '). Er is niets weggeschreven.'
					);
				}

				return true;
			}
		}

		// Fallback: no exec() available. Tokenize and reject if PHP mode
		// closes (inline HTML) anywhere after the opening tag — a valid
		// wp-config.php should be 100% PHP from start to finish.
		if ( function_exists( 'token_get_all' ) ) {
			$tokens        = @token_get_all( $content );
			$seen_open_tag = false;
			foreach ( $tokens as $token ) {
				if ( ! is_array( $token ) ) {
					continue;
				}
				if ( T_OPEN_TAG === $token[0] ) {
					$seen_open_tag = true;
					continue;
				}
				if ( $seen_open_tag && T_INLINE_HTML === $token[0] && '' !== trim( $token[1] ) ) {
					return new WP_Error(
						'invalid_syntax',
						'Wijziging aan wp-config.php afgebroken: het resultaat lijkt uit PHP-modus te breken (onverwachte tekst gevonden). Er is niets weggeschreven.'
					);
				}
			}
		}

		return true;
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
		$debug_mode = self::get_debug_mode( $s );
		if ( 'off' === $debug_mode ) {
			$lines[] = "define( 'WP_DEBUG', false );";
		} elseif ( 'log' === $debug_mode ) {
			$lines[] = "define( 'WP_DEBUG', true );";
			$lines[] = "define( 'WP_DEBUG_LOG', true );";
		}
		// Debug-met-log toont nooit fouten aan bezoekers, ook als "Verberg
		// foutmeldingen" uit staat. Eén define, anders "already defined".
		if ( ! empty( $s['no_debug_display'] ) || 'log' === $debug_mode ) {
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
	 * Genormaliseerde WP_DEBUG-modus: 'keep', 'off' of 'log'.
	 */
	public static function get_debug_mode( array $s ) {
		$mode = isset( $s['debug_mode'] ) ? (string) $s['debug_mode'] : 'keep';
		return in_array( $mode, [ 'keep', 'off', 'log' ], true ) ? $mode : 'keep';
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
		$debug_mode = self::get_debug_mode( $s );
		if ( 'off' === $debug_mode )                  $constants[] = 'WP_DEBUG';
		if ( 'log' === $debug_mode )                  $constants = array_merge( $constants, [ 'WP_DEBUG', 'WP_DEBUG_LOG' ] );
		if ( ! empty( $s['no_debug_display'] ) || 'log' === $debug_mode ) $constants[] = 'WP_DEBUG_DISPLAY';
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
		// The value is matched as a properly escaped single- or double-quoted
		// PHP string (or a bare token like true/false/123) rather than a bare
		// ".*". A naive ".*" doesn't know PHP's string-escaping rules and can
		// mis-detect where the value actually ends when it contains quotes,
		// backslashes or backticks — exactly what WordPress's own secret-key
		// generator produces, and exactly what corrupted a live site here.
		$value = "(?:'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|[^;]*?)";
		foreach ( $constants as $name ) {
			$pattern = '/^(\s*define\s*\(\s*[\'"]' . preg_quote( $name, '/' ) . '[\'"]\s*,\s*' . $value . '\s*\)\s*;.*)$/m';
			$content = preg_replace_callback(
				$pattern,
				function ( $matches ) {
					// A define() value can legitimately contain a literal
					// PHP closing tag sequence — it turns up by chance in
					// randomly generated secret keys/salts. PHP closes
					// script mode on that sequence even inside a //
					// comment, so commenting such a line out as-is would
					// truncate the rest of wp-config.php into raw HTML
					// output. Neutralize it reversibly;
					// restore_commented_constants() puts it back verbatim.
					$safe = str_replace( '?>', self::PHP_CLOSE_PLACEHOLDER, $matches[1] );
					return '// MCM_DISABLED: ' . $safe;
				},
				$content
			);
		}
		return $content;
	}

	/**
	 * Restore lines that were commented out by comment_out_constants().
	 */
	private static function restore_commented_constants( $content ) {
		$content = preg_replace( '/^\/\/ MCM_DISABLED: (.*)$/m', '$1', $content );
		return str_replace( self::PHP_CLOSE_PLACEHOLDER, '?>', $content );
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
