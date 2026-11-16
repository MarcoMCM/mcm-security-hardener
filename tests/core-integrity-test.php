<?php
/**
 * Tests voor MCM_Core_Integrity_Scanner::scan(), met nagebootste WordPress-
 * functies en een nagebootste checksum-API (geen netwerk nodig).
 *
 * Draaien vanuit de pluginmap:  php tests/core-integrity-test.php
 *
 * Belangrijkste geval (1.35.3): een Nederlandse site met de Engelse
 * wp-includes/version.php na een automatische update geeft geen melding
 * meer; elk ander afwijkend bestand nog wel. Exit code 0 = alles goed.
 * Niet in de release-zip (.gitattributes export-ignore).
 */

if ( 'cli' !== PHP_SAPI ) {
	exit;
}

$root = sys_get_temp_dir() . '/mcm-ci-test-' . getmypid();
@mkdir( $root . '/wp-includes', 0777, true );
define( 'ABSPATH', $root . '/' );
define( 'WEEK_IN_SECONDS', 604800 );
define( 'HOUR_IN_SECONDS', 3600 );

class WP_Error {
	private $m;
	function __construct( $c, $m ) { $this->m = $m; }
	function get_error_message() { return $this->m; }
}
function is_wp_error( $x ) { return $x instanceof WP_Error; }
function add_filter() {}
function add_action() {}
function untrailingslashit( $s ) { return rtrim( $s, '/\\' ); }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args, '', '&', PHP_QUERY_RFC3986 ); }

$GLOBALS['t_locale']   = 'nl_NL';
$GLOBALS['t_api']      = [];   // locale => checksums-array of 'fail'
$GLOBALS['t_requests'] = [];
function get_locale() { return $GLOBALS['t_locale']; }
function wp_remote_get( $url, $args ) {
	$GLOBALS['t_requests'][] = $url;
	parse_str( parse_url( $url, PHP_URL_QUERY ), $q );
	$loc = $q['locale'] ?? '';
	if ( ( $q['version'] ?? '' ) !== $GLOBALS['wp_version'] ) {
		return [ 'code' => 404, 'body' => '{}' ];
	}
	if ( ! isset( $GLOBALS['t_api'][ $loc ] ) ) {
		return [ 'code' => 200, 'body' => json_encode( [ 'checksums' => false ] ) ];
	}
	if ( 'fail' === $GLOBALS['t_api'][ $loc ] ) {
		return new WP_Error( 'http', 'timeout' );
	}
	return [ 'code' => 200, 'body' => json_encode( [ 'checksums' => $GLOBALS['t_api'][ $loc ] ] ) ];
}
function wp_remote_retrieve_response_code( $r ) { return $r['code']; }
function wp_remote_retrieve_body( $r ) { return $r['body']; }

require $argv[1] ?? dirname( __DIR__ ) . '/includes/class-core-integrity-scanner.php';

// Officiële inhoud (zelfde opbouw als echt: nl = en + één regel).
$en_version = "<?php\n\$wp_version = '7.1.4';\n\$wp_db_version = 60717;\n";
$nl_version = $en_version . "\n\$wp_local_package = 'nl_NL';\n";
$load       = "<?php\n// wp-load\n";
$load_en    = "<?php\n// wp-load (hypothetisch andere en_US-variant)\n";

$GLOBALS['wp_version'] = '7.1.4';

function api_set( $nl_load = null ) {
	global $en_version, $nl_version, $load;
	$GLOBALS['t_api'] = [
		'en_US' => [ 'wp-includes/version.php' => md5( $en_version ), 'wp-load.php' => md5( $load ) ],
		'nl_NL' => [ 'wp-includes/version.php' => md5( $nl_version ), 'wp-load.php' => md5( $nl_load ?? $load ) ],
	];
}

function run_case( $name, $version_content, $load_content, $expect_paths, $expect_requests = null, $setup = null ) {
	global $root;
	$GLOBALS['t_locale']         = 'nl_NL';
	$GLOBALS['wp_local_package'] = null;
	$GLOBALS['t_requests']       = [];
	api_set();
	if ( $setup ) { $setup(); }
	$p = new ReflectionProperty( 'MCM_Core_Integrity_Scanner', 'checksum_cache' );
	$p->setAccessible( true );
	$p->setValue( null, [] );

	if ( null === $version_content ) {
		@unlink( $root . '/wp-includes/version.php' );
	} else {
		file_put_contents( $root . '/wp-includes/version.php', $version_content );
	}
	file_put_contents( $root . '/wp-load.php', $load_content );

	$r     = MCM_Core_Integrity_Scanner::scan();
	$paths = array_map( function ( $f ) { return $f['relpath'] . ' (' . $f['severity'] . ')'; }, $r['findings'] );
	sort( $paths );
	$ok = ( $paths === $expect_paths ) && ( null === $expect_requests || count( $GLOBALS['t_requests'] ) === $expect_requests );
	printf( "%s  %-62s bevindingen=[%s] aanvragen=%d%s\n",
		$ok ? 'OK  ' : 'FOUT', $name, implode( ', ', $paths ), count( $GLOBALS['t_requests'] ),
		$r['error'] ? ' error=' . $r['error'] : '' );
	return $ok;
}

$all = true;
$H   = 'wp-includes/version.php (high)';
$L   = 'wp-load.php (high)';

$all &= run_case( '1. nl-site, alles nl_NL (normaal)', $nl_version, $load, [], 1 );
$all &= run_case( '2. nl-site, version.php = en_US (het vals alarm)', $en_version, $load, [], 2 );
$all &= run_case( '3. nl-site, version.php aangepast (hack)', $en_version . "@eval(\$_GET['x']);\n", $load, [ $H ] );
$all &= run_case( '4. nl-site, nl-regel + extra code', $nl_version . "@eval(\$_GET['x']);\n", $load, [ $H ] );
$all &= run_case( '5. ander bestand = en_US-variant, niet nl_NL -> streng', $nl_version, $load_en, [ $L ], 1,
	function () { global $load_en; $GLOBALS['t_api']['en_US']['wp-load.php'] = md5( $load_en ); } );
$all &= run_case( '6. ander bestand aangepast', $nl_version, $load . "//x\n", [ $L ] );
$all &= run_case( '7. en-site, version.php = nl_NL via $wp_local_package', $nl_version, $load, [], 2,
	function () { $GLOBALS['t_locale'] = 'en_US'; $GLOBALS['wp_local_package'] = 'nl_NL'; } );
$all &= run_case( '8. en-site, nl-bestand, geen $wp_local_package -> melding', $nl_version, $load, [ $H ], 1,
	function () { $GLOBALS['t_locale'] = 'en_US'; } );
$all &= run_case( '9. nl-site, en-bestand, en_US-API onbereikbaar -> melding', $en_version, $load, [ $H ], 2,
	function () { $GLOBALS['t_api']['en_US'] = 'fail'; } );
$all &= run_case( '10. rare $wp_local_package wordt genegeerd', $nl_version, $load, [ $H ], 1,
	function () { $GLOBALS['t_locale'] = 'en_US'; $GLOBALS['wp_local_package'] = "nl_NL&version=1"; } );
$all &= run_case( '11. de-site (de_DE) met en_US-version.php', $en_version, $load, [], 2,
	function () {
		global $en_version, $load;
		$GLOBALS['t_locale']       = 'de_DE';
		$GLOBALS['t_api']['de_DE'] = [ 'wp-includes/version.php' => md5( $en_version . "\n\$wp_local_package = 'de_DE';\n" ), 'wp-load.php' => md5( $load ) ];
	} );
$all &= run_case( '12. nl_NL-API weg, nl-bestand niet na te gaan -> melding', $nl_version, $load, [ $H ], 2,
	function () { $GLOBALS['t_api']['nl_NL'] = 'fail'; $GLOBALS['wp_local_package'] = 'nl_NL'; } );
$all &= run_case( '13. version.php ontbreekt', null, $load, [ $H ], 1 );

// opruimen
@unlink( $root . '/wp-includes/version.php' ); @unlink( $root . '/wp-load.php' );
@rmdir( $root . '/wp-includes' ); @rmdir( $root );

echo $all ? "\nALLES OK\n" : "\nER GING IETS MIS\n";
exit( $all ? 0 : 1 );
