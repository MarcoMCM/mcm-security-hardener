<?php
/**
 * File Exposure Scanner — detecteert losse "test"-bestanden in de webroot
 * die per ongeluk publiek bereikbaar zijn (info.php met phpinfo(), .env,
 * wp-config-backups, DB-dumps, adminer, phpmyadmin, etc.).
 *
 * Aanleiding: op mcmwebsites.nl werd op 2026-06-25 toevallig een publieke
 * info.php gevonden met `<?php phpinfo(); ?>` — lekt PHP-versie, paden,
 * modules. Voortaan vindt de plugin dit zelf.
 *
 * Gedrag:
 *   - Wekelijkse wp-cron scan + handmatige "Nu scannen"-knop in admin.
 *   - Scant het bestandssysteem (NIET via HTTP — Varnish op Xel kan een
 *     cache-hit geven die niet de waarheid is over wat er op disk staat).
 *   - Twee detectie-vormen:
 *       a) Risico-bestandsnamen (regex op naam): info.php, .env, *.sql, etc.
 *       b) Elk .php-bestand in scan-paden waarvan de eerste 4 KB `phpinfo(`
 *          bevat.
 *   - Meldt nieuwe bevindingen via MCM_Notifier (admin notice + mail naar
 *     marco@mcmwebsites.nl). Geen mail bij identieke bevindingen als vorige
 *     scan — voorkomt mail-moeheid.
 *   - Verwijdert NOOIT zelf. Detectie + melding only. Verwijderen blijft een
 *     bewuste handeling van de beheerder.
 *
 * Settings (in mcm_security_settings):
 *   - 'exposure_scanner_enabled'      bool  default true   (cron + UI actief)
 *   - 'block_risky_files_via_htaccess' bool default false  (extra .htaccess-block)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_File_Exposure_Scanner {

	const CRON_HOOK             = 'mcm_security_exposure_scan';
	const CRON_SCHEDULE         = 'mcm_weekly';
	const ACTION_MANUAL_SCAN    = 'mcm_security_run_exposure_scan';
	const OPTION_RESULTS        = 'mcm_exposure_scan_results';
	const OPTION_LAST_MAIL_HASH = 'mcm_exposure_last_mailed_hash';
	const MAX_FILES_PER_DIR     = 500;   // perf-cap per directory
	const PHPINFO_READ_BYTES    = 4096;  // eerste 4 KB van een .php-file lezen

	public function __construct() {
		// Custom 'wekelijks' schedule registreren — WP heeft alleen
		// hourly/twicedaily/daily standaard.
		add_filter( 'cron_schedules', [ __CLASS__, 'register_weekly_schedule' ] );

		// Cron-callback.
		add_action( self::CRON_HOOK, [ __CLASS__, 'run_cron_scan' ] );

		// Handmatige scan-knop (admin-post action — gebruikt eigen URL ipv
		// outer form, zodat 'm niet conflicteert met het hoofd-form).
		add_action( 'admin_post_' . self::ACTION_MANUAL_SCAN, [ __CLASS__, 'handle_manual_scan' ] );

		// Zorg dat de cron actief is wanneer de feature aan staat.
		add_action( 'init', [ __CLASS__, 'maybe_schedule_cron' ] );
	}

	/**
	 * Voegt 'mcm_weekly' toe aan wp_get_schedules().
	 */
	public static function register_weekly_schedule( $schedules ) {
		if ( ! isset( $schedules[ self::CRON_SCHEDULE ] ) ) {
			$schedules[ self::CRON_SCHEDULE ] = [
				'interval' => WEEK_IN_SECONDS,
				'display'  => 'Wekelijks (MCM)',
			];
		}
		return $schedules;
	}

	/**
	 * Plan cron als de feature aan staat; haal hem weg als 'ie uit gaat.
	 */
	public static function maybe_schedule_cron() {
		$settings = get_option( 'mcm_security_settings', [] );
		$enabled  = ! empty( $settings['exposure_scanner_enabled'] );
		$next     = wp_next_scheduled( self::CRON_HOOK );

		if ( $enabled && ! $next ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, self::CRON_SCHEDULE, self::CRON_HOOK );
		} elseif ( ! $enabled && $next ) {
			wp_unschedule_event( $next, self::CRON_HOOK );
		}
	}

	/**
	 * Risico-bestandsnamen — regex op de FILE-naam (niet het volledige pad).
	 * Case-insensitive.
	 *
	 * @return array<string,string> regex => beschrijving
	 */
	public static function risky_filename_patterns() {
		return [
			'/^info\.php$/i'                                 => 'PHP info-dump (info.php)',
			'/^phpinfo\.php$/i'                              => 'PHP info-dump (phpinfo.php)',
			'/^test\.php$/i'                                 => 'Test-script (test.php)',
			'/^php\.php$/i'                                  => 'Test-script (php.php)',
			'/^i\.php$/i'                                    => 'Korte test-script (i.php)',
			'/^adminer.*\.php$/i'                            => 'Adminer (database admin tool)',
			'/^phpmyadmin/i'                                 => 'phpMyAdmin (folder of file)',
			'/^\.env(\..+)?$/i'                              => '.env config-bestand (lekt secrets)',
			'/^wp-config\.php\.(bak|save|old|orig|tmp|txt)$/i' => 'wp-config backup-bestand',
			'/^wp-config\.php~$/'                            => 'wp-config editor-backup (~)',
			'/\.sql(\.gz)?$/i'                               => 'SQL-dump',
			'/^dump.*\.sql$/i'                               => 'Database-dump',
			'/^backup.*\.(zip|tar\.gz|tgz)$/i'               => 'Backup-archief in webroot',
			'/^db.*\.(zip|sql|tar\.gz)$/i'                   => 'Database-backup in webroot',
			'/^debug\.log$/i'                                => 'WP debug.log in webroot',
		];
	}

	/**
	 * Scan-paden (filesystem). ABSPATH + 1 niveau diep, géén recursieve
	 * scan van plugin/theme code (anders te traag + te veel ruis).
	 *
	 * @return string[] Absolute paden, met trailing slash.
	 */
	public static function scan_paths() {
		$root = untrailingslashit( ABSPATH );
		$paths = [
			$root,
			$root . '/wp-content',
		];
		return array_values( array_filter( $paths, 'is_dir' ) );
	}

	/**
	 * Voer een scan uit en retourneer de bevindingen.
	 *
	 * @return array<int,array{type:string,reason:string,path:string,relpath:string,size:int,mtime:int,public_guess:bool}>
	 */
	public static function scan() {
		$findings = [];
		$patterns = self::risky_filename_patterns();
		$abspath  = untrailingslashit( ABSPATH );

		foreach ( self::scan_paths() as $dir ) {
			$files = self::list_dir_entries( $dir );
			foreach ( $files as $entry ) {
				$path = $dir . '/' . $entry;
				if ( ! file_exists( $path ) ) {
					continue;
				}
				if ( is_dir( $path ) ) {
					// Folder-namen alleen tegen pattern-check (bv. phpmyadmin/).
					self::collect_filename_hit( $path, $entry, $patterns, $abspath, $findings );
					continue;
				}
				// Bestandsnaam-check.
				self::collect_filename_hit( $path, $entry, $patterns, $abspath, $findings );

				// Inhoud-check: alleen .php files, eerste 4 KB.
				if ( preg_match( '/\.php$/i', $entry ) ) {
					if ( self::file_contains_phpinfo( $path ) ) {
						$findings[] = self::build_finding(
							'phpinfo_call',
							'PHP-bestand roept phpinfo() aan',
							$path,
							$abspath
						);
					}
				}
			}
		}

		// Deduplicate op pad (kan bv. via folder+inhoud beide hitten).
		$seen   = [];
		$unique = [];
		foreach ( $findings as $f ) {
			$key = $f['type'] . '|' . $f['path'];
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$unique[]     = $f;
		}

		return $unique;
	}

	/**
	 * Lijst entries in een directory (cap voor perf).
	 *
	 * @return string[]
	 */
	private static function list_dir_entries( $dir ) {
		$entries = @scandir( $dir );
		if ( ! is_array( $entries ) ) {
			return [];
		}
		$entries = array_diff( $entries, [ '.', '..' ] );
		if ( count( $entries ) > self::MAX_FILES_PER_DIR ) {
			// Cap: alleen de eerste N — voorkomt vastlopen op vreemd grote dirs.
			$entries = array_slice( $entries, 0, self::MAX_FILES_PER_DIR );
		}
		return $entries;
	}

	/**
	 * Match bestandsnaam tegen risico-patronen en voeg toe aan $findings.
	 */
	private static function collect_filename_hit( $path, $entry, $patterns, $abspath, array &$findings ) {
		foreach ( $patterns as $regex => $reason ) {
			if ( preg_match( $regex, $entry ) ) {
				$findings[] = self::build_finding( 'risky_name', $reason, $path, $abspath );
				return; // Eén hit per file is genoeg.
			}
		}
	}

	/**
	 * Bouwt een finding-record.
	 */
	private static function build_finding( $type, $reason, $path, $abspath ) {
		$rel = ltrim( str_replace( $abspath, '', $path ), '/\\' );
		return [
			'type'         => $type,
			'reason'       => $reason,
			'path'         => $path,
			'relpath'      => $rel,
			'size'         => is_file( $path ) ? (int) @filesize( $path ) : 0,
			'mtime'        => (int) @filemtime( $path ),
			'public_guess' => self::guess_public( $rel ),
		];
	}

	/**
	 * Eerste 4 KB van een .php-bestand controleren op een phpinfo()-aanroep.
	 */
	private static function file_contains_phpinfo( $path ) {
		$bytes = @file_get_contents( $path, false, null, 0, self::PHPINFO_READ_BYTES );
		if ( false === $bytes || '' === $bytes ) {
			return false;
		}
		// Match: phpinfo( met eventuele whitespace ertussen. Voorkomt valse
		// hits op "phpinfo" als tekst zonder ronde haak.
		return (bool) preg_match( '/phpinfo\s*\(/i', $bytes );
	}

	/**
	 * Heuristische gok of het bestand via HTTP bereikbaar zou zijn vanaf
	 * de webroot. Niet 100% accuraat (kan zijn dat .htaccess het blokt),
	 * maar geeft een indicatie.
	 */
	private static function guess_public( $relpath ) {
		// Standaard WP-paden die normaal niet direct via HTTP geserveerd worden.
		$private_prefixes = [
			'wp-content/uploads/mcm-security-backups/',
		];
		foreach ( $private_prefixes as $prefix ) {
			if ( 0 === strpos( $relpath, $prefix ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Wp-cron callback — voer scan uit, sla op, mail bij nieuwe bevindingen.
	 */
	public static function run_cron_scan() {
		$settings = get_option( 'mcm_security_settings', [] );
		if ( empty( $settings['exposure_scanner_enabled'] ) ) {
			return;
		}
		self::run_and_maybe_notify();
	}

	/**
	 * Voert scan uit, slaat resultaten op, en mailt indien bevindingen
	 * verschillen van de vorige mail (anti-spam).
	 *
	 * @return array De bevindingen.
	 */
	public static function run_and_maybe_notify() {
		$findings = self::scan();

		update_option( self::OPTION_RESULTS, [
			'timestamp' => time(),
			'findings'  => $findings,
		] );

		if ( empty( $findings ) ) {
			// Geen bevindingen — reset hash zodat een volgende detectie
			// (na bv. een week schoon) wél weer een mail triggert.
			delete_option( self::OPTION_LAST_MAIL_HASH );
			return $findings;
		}

		// Hash van bevindingen vergelijken met vorige mail.
		$hash = self::findings_signature( $findings );
		$last = get_option( self::OPTION_LAST_MAIL_HASH, '' );
		if ( $hash === $last ) {
			// Zelfde set bevindingen als vorige mail — geen herhaling.
			return $findings;
		}

		self::send_findings_mail( $findings );
		update_option( self::OPTION_LAST_MAIL_HASH, $hash );

		return $findings;
	}

	private static function findings_signature( array $findings ) {
		$keys = array_map( function ( $f ) {
			return $f['type'] . '|' . $f['path'];
		}, $findings );
		sort( $keys );
		return md5( implode( "\n", $keys ) );
	}

	/**
	 * Mail naar de Notifier-bestemming met de lijst bevindingen.
	 */
	private static function send_findings_mail( array $findings ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}
		$count   = count( $findings );
		$subject = sprintf( 'Blootgestelde bestanden gevonden (%d)', $count );

		$body  = "Op deze site zijn één of meer bestanden gevonden die mogelijk\n";
		$body .= "publiek bereikbaar zijn en gevoelige informatie kunnen lekken.\n\n";

		foreach ( $findings as $i => $f ) {
			$body .= sprintf( "%d. %s\n", $i + 1, $f['reason'] );
			$body .= sprintf( "   Pad:           %s\n", $f['relpath'] );
			$body .= sprintf( "   Grootte:       %s bytes\n", number_format( $f['size'], 0, ',', '.' ) );
			$body .= sprintf( "   Laatst gewijz: %s\n", $f['mtime'] ? wp_date( 'Y-m-d H:i', $f['mtime'] ) : '?' );
			$body .= sprintf( "   Lijkt publiek: %s\n", $f['public_guess'] ? 'ja' : 'nee' );
			$body .= "\n";
		}

		$body .= "----\n";
		$body .= "ACTIE: controleer elk bestand en verwijder als het er niet hoort.\n";
		$body .= "De plugin verwijdert NIETS automatisch.\n\n";
		$body .= "Let op: op Xel zit Varnish ervoor. Na verwijderen moet de cache\n";
		$body .= "gepurged worden, anders blijft de URL publiek 200 geven. Vanaf de\n";
		$body .= "server:\n";
		$body .= "   curl -X PURGE -H 'Host: <domein>' http://127.0.0.1/<pad>\n";

		MCM_Notifier::email( $subject, $body );
	}

	/**
	 * Handler voor de "Nu scannen"-knop in admin.
	 */
	public static function handle_manual_scan() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::ACTION_MANUAL_SCAN );

		self::run_and_maybe_notify();

		wp_safe_redirect(
			add_query_arg(
				'mcm_status',
				'exposure_scan_done',
				wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' )
			)
		);
		exit;
	}

	/**
	 * Hulpmethode voor admin-page rendering: laatste scan-state.
	 *
	 * @return array{timestamp:int,findings:array}|null
	 */
	public static function get_last_results() {
		$saved = get_option( self::OPTION_RESULTS, null );
		if ( ! is_array( $saved ) || ! isset( $saved['findings'] ) ) {
			return null;
		}
		return $saved;
	}
}
