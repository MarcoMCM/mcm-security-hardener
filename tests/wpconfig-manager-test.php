<?php
/**
 * Regression tests for MCM_WPConfig_Manager (comment-out, write, repair),
 * with the real MCM_Backup_Store for the back-ups.
 *
 * Run from the plugin folder:  php tests/wpconfig-manager-test.php
 *
 * Runs everything twice: once with `php -l` as the syntax check, and once in
 * a child process with exec() disabled, so the tokenizer fallback in
 * check_syntax() is covered too (the situation on php-fpm hosts). Exit code
 * 0 = all passed. Not part of the release zip (.gitattributes export-ignore).
 */

if ( 'cli' !== PHP_SAPI ) {
	exit;
}

$tmp = sys_get_temp_dir() . '/mcm-wpconfig-test-' . getmypid() . '/';
@mkdir( $tmp );
define( 'ABSPATH', $tmp );

// Just enough WordPress for the classes.
class WP_Error {
	private $code, $message;
	public function __construct( $code = '', $message = '' ) {
		$this->code    = $code;
		$this->message = $message;
	}
	public function get_error_code() {
		return $this->code;
	}
	public function get_error_message() {
		return $this->message;
	}
}
function is_wp_error( $thing ) {
	return $thing instanceof WP_Error;
}
function wp_tempnam( $prefix = '' ) {
	return tempnam( sys_get_temp_dir(), $prefix );
}
function wp_upload_dir( $time = null, $create_dir = true ) {
	return [ 'basedir' => ABSPATH . 'uploads', 'error' => false ];
}
function trailingslashit( $path ) {
	return rtrim( $path, '/\\' ) . '/';
}
function untrailingslashit( $path ) {
	return rtrim( $path, '/\\' );
}
function wp_mkdir_p( $dir ) {
	return is_dir( $dir ) || @mkdir( $dir, 0777, true );
}

require dirname( __DIR__ ) . '/includes/class-backup-store.php';
require dirname( __DIR__ ) . '/includes/class-wpconfig-manager.php';

$fallback = in_array( '--fallback', $argv, true );
$failures = 0;

function check( $label, $ok, $detail = '' ) {
	global $failures;
	$failures += $ok ? 0 : 1;
	printf( "  %s  %s%s\n", $ok ? 'ok  ' : 'FAIL', $label, $ok || '' === $detail ? '' : "\n        " . str_replace( "\n", "\n        ", $detail ) );
}

function call_private( $method, ...$args ) {
	$r = new ReflectionMethod( 'MCM_WPConfig_Manager', $method );
	if ( PHP_VERSION_ID < 80100 ) {
		$r->setAccessible( true ); // No-op since 8.1, deprecated since 8.5.
	}
	return $r->invoke( null, ...$args );
}

// Full parse without exec(), so it also works in the --fallback run.
function parses( $code ) {
	try {
		token_get_all( $code, TOKEN_PARSE );
		return true;
	} catch ( ParseError $e ) {
		return false;
	}
}

// Number of active (not commented out) define( 'NAME', ... ) calls.
function live_defines( $code, $name ) {
	$tokens = token_get_all( $code );
	$count  = count( $tokens );
	$found  = 0;
	for ( $i = 0; $i < $count; $i++ ) {
		if ( ! is_array( $tokens[ $i ] ) || T_STRING !== $tokens[ $i ][0] || 'define' !== strtolower( $tokens[ $i ][1] ) ) {
			continue;
		}
		$j = $i + 1;
		while ( $j < $count && is_array( $tokens[ $j ] ) && T_WHITESPACE === $tokens[ $j ][0] ) {
			$j++;
		}
		if ( '(' !== $tokens[ $j ] ) {
			continue;
		}
		$j++;
		while ( $j < $count && is_array( $tokens[ $j ] ) && T_WHITESPACE === $tokens[ $j ][0] ) {
			$j++;
		}
		if ( is_array( $tokens[ $j ] ) && trim( $tokens[ $j ][1], '\'"' ) === $name ) {
			$found++;
		}
	}
	return $found;
}

function config( $content = null ) {
	$path = ABSPATH . 'wp-config.php';
	if ( null !== $content ) {
		file_put_contents( $path, $content );
		array_map( 'unlink', backups() );
	}
	return file_get_contents( $path );
}

// wp-config back-ups in MCM_Backup_Store, oldest first.
function backups() {
	$list = glob( ABSPATH . 'uploads/' . MCM_Backup_Store::DIR . '/wp-config-*.php' ) ?: [];
	sort( $list );
	return $list;
}

// Newest back-up without the guard line, or null if there is none or the
// guard is missing.
function latest_backup() {
	$list = backups();
	if ( ! $list ) {
		return null;
	}
	$data = file_get_contents( end( $list ) );
	return 0 === strpos( $data, MCM_Backup_Store::GUARD ) ? substr( $data, strlen( MCM_Backup_Store::GUARD ) ) : null;
}

function empty_markers( $code ) {
	return preg_match_all( '/^\/\/ MCM_DISABLED: [ \t]*\r?$/m', $code );
}

$block_debug = "# BEGIN MCM Security Hardener\ndefine( 'WP_DEBUG', false );\ndefine( 'WP_DEBUG_DISPLAY', false );\n# END MCM Security Hardener\n";

echo $fallback ? "Syntax check: tokenizer fallback (exec disabled)\n" : "Syntax check: php -l\n";

if ( ! $fallback ) {
	echo "\ncomment_out_constants()\n";

	// Value as it appears in wp-config: escaped quote, backslashes, a PHP
	// closing tag, ; and ). Built with a string so this file stays parseable.
	$salt  = 'a\\\'b' . '?' . '>c"d\\\\e`f;g)h';
	$cases = [
		// label => [ input, constant, active define()s expected afterwards ]
		'blank line before (LF)'           => [ "<?php\n\$x = 1;\n\ndefine( 'WP_DEBUG', true );\n", 'WP_DEBUG', 0 ],
		'two blank lines before'           => [ "<?php\n\$x = 1;\n\n\ndefine( 'WP_DEBUG', true );\n", 'WP_DEBUG', 0 ],
		'blank line before (CRLF)'         => [ "<?php\r\n\$x = 1;\r\n\r\ndefine( 'WP_DEBUG', true );\r\n", 'WP_DEBUG', 0 ],
		'whitespace-only line before'      => [ "<?php\n\$x = 1;\n  \t\ndefine( 'WP_DEBUG', true );\n", 'WP_DEBUG', 0 ],
		'indented, inside if-block'        => [ "<?php\nif ( true ) {\n\n\tdefine( 'WP_DEBUG', true );\n}\n", 'WP_DEBUG', 0 ],
		'double-quoted name, no spaces'    => [ "<?php\n\ndefine(\"WP_DEBUG\",true);\n", 'WP_DEBUG', 0 ],
		'trailing comment'                 => [ "<?php\n\ndefine( 'WP_DEBUG', true ); // on for now\n", 'WP_DEBUG', 0 ],
		'first line after <?php'           => [ "<?php\ndefine( 'WP_DEBUG', true );\n", 'WP_DEBUG', 0 ],
		'salt with quotes, \\ and ?>'      => [ "<?php\n\ndefine( 'AUTH_KEY', '$salt' );\n\$z = 1;\n", 'AUTH_KEY', 0 ],
		'salt in double quotes'            => [ "<?php\n\ndefine( 'AUTH_KEY', \"q'?" . ">\\\"x\\\\\" );\n", 'AUTH_KEY', 0 ],
		'salt, CRLF, blank line before'    => [ "<?php\r\n\r\ndefine( 'AUTH_KEY', '$salt' );\r\n", 'AUTH_KEY', 0 ],
		'WP_DEBUG_LOG is not WP_DEBUG'     => [ "<?php\n\ndefine( 'WP_DEBUG_LOG', true );\n", 'WP_DEBUG_LOG', 1, 'WP_DEBUG' ],
		// Must not match any more: stays active instead of half commented out.
		'multi-line define() stays active' => [ "<?php\ndefine(\n\t'WP_DEBUG',\n\ttrue\n);\n", 'WP_DEBUG', 1 ],
		'value on next line stays active'  => [ "<?php\ndefine( 'WP_DEBUG',\n\ttrue );\n", 'WP_DEBUG', 1 ],
		'multi-line string stays active'   => [ "<?php\ndefine( 'AUTH_KEY', 'ab\ncd' );\n", 'AUTH_KEY', 1 ],
	];
	foreach ( $cases as $label => $case ) {
		list( $in, $name, $expect ) = $case;
		$managed  = isset( $case[3] ) ? $case[3] : $name;
		$out      = call_private( 'comment_out_constants', $in, [ $managed ] );
		$restored = call_private( 'restore_commented_constants', $out );
		check(
			$label,
			live_defines( $out, $name ) === $expect && parses( $out ) && $restored === $in && 0 === empty_markers( $out ),
			$out
		);
	}
}

echo "\nwrite()\n";

$original = "<?php\n/** DB */\ndefine( 'DB_NAME', 'x' );\n\$table_prefix = 'wp_';\n\ndefine( 'WP_DEBUG', true );\n\ndefine( 'WP_DEBUG_DISPLAY', true );\nif ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n";
$settings = [ 'debug_mode' => 'off', 'no_debug_display' => true ];
config( $original );
$first = MCM_WPConfig_Manager::write( $settings );
$after = config();
check( 'returns true', true === $first );
check( 'exactly one active WP_DEBUG and WP_DEBUG_DISPLAY', 1 === live_defines( $after, 'WP_DEBUG' ) && 1 === live_defines( $after, 'WP_DEBUG_DISPLAY' ), $after );
check( 'block value wins (block comes first)', false !== strpos( $after, "<?php\n# BEGIN MCM Security Hardener\ndefine( 'WP_DEBUG', false );" ) );
check( 'no empty markers, result parses', 0 === empty_markers( $after ) && parses( $after ) );
check( 'one guarded back-up, holding the original', 1 === count( backups() ) && latest_backup() === $original );
MCM_WPConfig_Manager::write( $settings );
check( 'second write: unchanged, no new back-up', config() === $after && 1 === count( backups() ) );
MCM_WPConfig_Manager::remove();
check( 'remove() restores the original exactly', config() === $original );

config( "<?php\n\$x = 1;\ndefine(\n\t'WP_DEBUG',\n\ttrue\n);\n" );
$result = MCM_WPConfig_Manager::write( $settings );
$after  = config();
check( 'multi-line define(): written, parses, define stays active', true === $result && parses( $after ) && 2 === live_defines( $after, 'WP_DEBUG' ), $after );

// A rejected write must leave the file alone, block included. The original
// is already broken (parse error for php -l, inline HTML for the fallback),
// so any rewrite of it is rejected.
$broken = "<?php\n" . $block_debug . "\n\$x = ;\n// MCM_DISABLED: define( 'WP_DEBUG', true );\n?" . ">\nGARBAGE\n";
config( $broken );
$result = MCM_WPConfig_Manager::write( [ 'debug_mode' => 'log' ] );
check( 'rejected write: WP_Error, file untouched, no back-up', is_wp_error( $result ) && config() === $broken && 0 === count( backups() ), is_wp_error( $result ) ? $result->get_error_message() : var_export( $result, true ) );

echo "\nrepair_markers() on files damaged by 1.31.0\n";

// Exactly what 1.31.0 wrote for $original above.
$damaged = "<?php\n" . $block_debug . "\n\n/** DB */\ndefine( 'DB_NAME', 'x' );\n\$table_prefix = 'wp_';\n// MCM_DISABLED: \ndefine( 'WP_DEBUG', true );\n// MCM_DISABLED: \ndefine( 'WP_DEBUG_DISPLAY', true );\nif ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n";
config( $damaged );
check( 'needs_marker_repair() sees the damage', true === MCM_WPConfig_Manager::needs_marker_repair() );
$result = MCM_WPConfig_Manager::repair_markers();
$after  = config();
check( 'repaired: one active define each, no empty markers', true === $result && 1 === live_defines( $after, 'WP_DEBUG' ) && 1 === live_defines( $after, 'WP_DEBUG_DISPLAY' ) && 0 === empty_markers( $after ) && parses( $after ), $after );
check( 'block unchanged, blank lines back', 0 === strpos( $after, "<?php\n" . $block_debug ) && false !== strpos( $after, "\$table_prefix = 'wp_';\n\n// MCM_DISABLED: define( 'WP_DEBUG', true );\n\n// MCM_DISABLED: define( 'WP_DEBUG_DISPLAY', true );" ), $after );
check( 'back-up holds the damaged file', latest_backup() === $damaged );
check( 'needs_marker_repair() false afterwards', false === MCM_WPConfig_Manager::needs_marker_repair() );
MCM_WPConfig_Manager::remove();
check( 'remove() afterwards gives the pre-plugin file', config() === $original );

// CRLF file (our block is always LF) with a secret key containing a closing tag.
$salt    = 'k\\\'e' . '?' . '>y\\\\';
$damaged = "<?php\n# BEGIN MCM Security Hardener\ndefine( 'AUTH_KEY', 'new' );\n# END MCM Security Hardener\n\n\r\n\$x = 1;\r\n// MCM_DISABLED: \r\ndefine( 'AUTH_KEY', '$salt' );\r\n";
config( $damaged );
check( 'CRLF: needs_marker_repair() sees the damage', true === MCM_WPConfig_Manager::needs_marker_repair() );
$result = MCM_WPConfig_Manager::repair_markers();
$after  = config();
check( 'CRLF: repaired, closing tag neutralised, parses', true === $result && 1 === live_defines( $after, 'AUTH_KEY' ) && 0 === empty_markers( $after ) && parses( $after ) && false !== strpos( $after, "\r\n// MCM_DISABLED: define( 'AUTH_KEY', 'k\\'e" . MCM_WPConfig_Manager::PHP_CLOSE_PLACEHOLDER ), $after );
MCM_WPConfig_Manager::remove();
check( 'CRLF: remove() puts the key back verbatim', false !== strpos( config(), "\r\ndefine( 'AUTH_KEY', '$salt' );\r\n" ) && 1 === live_defines( config(), 'AUTH_KEY' ) );

config( "<?php\n\$x = 1;\n// MCM_DISABLED: \ndefine( 'WP_DEBUG', true );\n" );
check( 'no block: repair_markers() refuses, file untouched', is_wp_error( MCM_WPConfig_Manager::repair_markers() ) && 0 === count( backups() ) );

config( "<?php\n" . $block_debug . "\n\$x = 1;\n// MCM_DISABLED: define( 'WP_DEBUG', true );\n" );
check( 'healthy file: needs_marker_repair() false', false === MCM_WPConfig_Manager::needs_marker_repair() );

// Up to 1.31.0 every write left a plain-text copy next to wp-config.php.
check( 'never a wp-config.php.mcm-backup in the webroot', ! file_exists( ABSPATH . 'wp-config.php.mcm-backup' ) );

array_map( 'unlink', backups() );
foreach ( [ '/.htaccess', '/index.php', '' ] as $f ) {
	$f ? @unlink( ABSPATH . 'uploads/' . MCM_Backup_Store::DIR . $f ) : @rmdir( ABSPATH . 'uploads/' . MCM_Backup_Store::DIR );
}
@rmdir( ABSPATH . 'uploads' );
@unlink( $tmp . 'wp-config.php' );
@rmdir( $tmp );

if ( ! $fallback ) {
	if ( function_exists( 'exec' ) ) {
		echo "\n";
		passthru( escapeshellarg( PHP_BINARY ) . ' -d disable_functions=exec ' . escapeshellarg( __FILE__ ) . ' --fallback', $child_exit );
		$failures += $child_exit ? 1 : 0;
	} else {
		echo "\nexec() not available: fallback run skipped.\n";
	}
	echo $failures ? "\nFAILED ($failures)\n" : "\nAll tests passed.\n";
}

exit( $failures ? 1 : 0 );
