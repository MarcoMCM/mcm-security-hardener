<?php
/**
 * Core Integrity Scanner — vergelijkt élk WordPress-kernbestand (root,
 * wp-admin/, wp-includes/) tegen de officiële checksums van WordPress.org
 * voor de geïnstalleerde versie. Zelfde principe als `wp core
 * verify-checksums`, maar dan automatisch en wekelijks vanuit de plugin
 * zelf, zonder dat iemand met SSH/wp-cli hoeft in te loggen.
 *
 * Aanleiding: bij de tessaswinkels.com-hack (sept 2026) waren `index.php`
 * en `wp-blog-header.php` — WordPress-kernbestanden — geïnfecteerd met
 * gokspam-cloaking. Niets in de plugin merkte dat op; het werd pas
 * ontdekt doordat Xel de site zelf blokkeerde nadat Google de cloaking
 * had gedetecteerd. Xel's eigen scan komt er dus wél achter, maar dan
 * staat de site meteen op slot — deze module is bedoeld om er eerder
 * bij te zijn, vóór het zover komt.
 *
 * Werkwijze: haalt de officiële checksum-lijst op via
 * https://api.wordpress.org/core/checksums/1.0/?version=X&locale=Y (dezelfde
 * bron als wp-cli gebruikt), berekent lokaal de md5 van elk genoemd
 * bestand, en meldt elke afwijking of elk ontbrekend bestand. wp-content
 * zit hier bewust niet in — dat is geen "core" en heeft zijn eigen
 * detectie via de Anomaly Scanner en de Snippet Monitor.
 *
 * Gedrag:
 *   - Wekelijkse wp-cron scan + handmatige "Nu scannen"-knop in admin.
 *   - Locale-fallback: probeert eerst de site-locale, valt terug op en_US
 *     als de officiële checksums voor die locale niet beschikbaar zijn.
 *   - Eén uitzondering: wp-includes/version.php (zie LOCALE_VARIANT_FILES).
 *     Het Nederlandse pakket heeft daar één regel extra
 *     (`$wp_local_package = 'nl_NL';`); verder is het bestand gelijk aan de
 *     Engelse versie. Een automatische WordPress-update zet soms de Engelse
 *     versie neer op een Nederlandse site. Dat is geen hack. Voor dit ene
 *     bestand telt daarom ook de officiële checksum van dezelfde versie in
 *     en_US (en in de taal uit $wp_local_package) als "in orde". Alle andere
 *     bestanden moeten exact gelijk zijn aan de lijst van de site-locale.
 *   - Mailt bij elke afwijking (altijd HIGH — een core-bestand hoort
 *     nooit te wijzigen buiten een WordPress-update om). Anti-spam via
 *     dezelfde hash-vergelijking als de andere scanners.
 *   - Verwijdert/herstelt NOOIT zelf. Detectie + melding only — herstel is
 *     één `wp core download --force --skip-content` op de server, bewust
 *     een handeling van de beheerder.
 *   - Respecteert MCM_Finding_Ignore (bron 'core_integrity'), al is er in
 *     de praktijk zelden een legitieme reden om een core-afwijking te
 *     negeren.
 *
 * Settings (in mcm_security_settings):
 *   - 'core_integrity_enabled'  bool  default true  (cron + UI actief)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Core_Integrity_Scanner {

	const CRON_HOOK             = 'mcm_security_core_integrity_scan';
	const CRON_SCHEDULE         = 'mcm_weekly';
	const ACTION_MANUAL_SCAN    = 'mcm_security_run_core_integrity_scan';
	const OPTION_RESULTS        = 'mcm_core_integrity_scan_results';
	const OPTION_LAST_MAIL_HASH = 'mcm_core_integrity_last_mailed_hash';
	const CHECKSUMS_URL         = 'https://api.wordpress.org/core/checksums/1.0/';

	/**
	 * Kernbestanden die per taalpakket officieel verschillen. Voor deze
	 * bestanden is elke officiële variant van dezelfde WP-versie goed
	 * (site-locale, en_US, of de taal uit $wp_local_package).
	 *
	 * Gecontroleerd voor 7.1.4 (16 nov 2026): buiten wp-content is
	 * version.php het enige bestand dat tussen nl_NL en en_US verschilt.
	 * Aanleiding: pensioenfonds-sagittarius.nl, auto-update 7.1.3 -> 7.1.4
	 * op 28 okt 2026 zette de en_US-versie neer; de securityscan van Wizzbit
	 * meldde dat als "core-integriteit", severity high.
	 */
	const LOCALE_VARIANT_FILES = [ 'wp-includes/version.php' ];

	/**
	 * Checksums die tijdens deze request al zijn opgehaald, per
	 * "versie|locale". false = ophalen mislukt. Zo kost de extra controle
	 * van version.php geen tweede aanvraag voor dezelfde locale.
	 *
	 * @var array<string,array|false>
	 */
	private static $checksum_cache = [];

	public function __construct() {
		// 'mcm_weekly' wordt ook door andere scanners geregistreerd; de
		// isset-guard maakt dubbel registreren veilig (decoupled van die classes).
		add_filter( 'cron_schedules', [ __CLASS__, 'register_weekly_schedule' ] );

		add_action( self::CRON_HOOK, [ __CLASS__, 'run_cron_scan' ] );
		add_action( 'admin_post_' . self::ACTION_MANUAL_SCAN, [ __CLASS__, 'handle_manual_scan' ] );
		add_action( 'init', [ __CLASS__, 'maybe_schedule_cron' ] );
	}

	public static function register_weekly_schedule( $schedules ) {
		if ( ! isset( $schedules[ self::CRON_SCHEDULE ] ) ) {
			$schedules[ self::CRON_SCHEDULE ] = [
				'interval' => WEEK_IN_SECONDS,
				'display'  => 'Wekelijks (MCM)',
			];
		}
		return $schedules;
	}

	private static function is_enabled() {
		$settings = get_option( 'mcm_security_settings', [] );
		if ( ! array_key_exists( 'core_integrity_enabled', $settings ) ) {
			$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
				? MCM_Security_Hardener::get_defaults()
				: [];
			return ! empty( $defaults['core_integrity_enabled'] );
		}
		return ! empty( $settings['core_integrity_enabled'] );
	}

	public static function is_active() {
		return self::is_enabled();
	}

	public static function maybe_schedule_cron() {
		$enabled = self::is_enabled();
		$next    = wp_next_scheduled( self::CRON_HOOK );

		if ( $enabled && ! $next ) {
			wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, self::CRON_SCHEDULE, self::CRON_HOOK );
		} elseif ( ! $enabled && $next ) {
			wp_unschedule_event( $next, self::CRON_HOOK );
		}
	}

	/**
	 * Haalt de officiële checksum-lijst op voor de geïnstalleerde
	 * WP-versie. Probeert eerst de site-locale, valt terug op en_US.
	 *
	 * @return array<string,string>|WP_Error relpath => md5, of WP_Error bij falen.
	 */
	private static function fetch_checksums() {
		foreach ( array_unique( [ get_locale(), 'en_US' ] ) as $locale ) {
			$checksums = self::fetch_checksums_for_locale( $locale );
			if ( is_array( $checksums ) ) {
				return $checksums;
			}
		}

		return new WP_Error( 'mcm_core_checksums_unavailable', 'Kon geen checksums ophalen bij WordPress.org.' );
	}

	/**
	 * Haalt de officiële checksum-lijst op voor de geïnstalleerde versie in
	 * één locale. Het resultaat (ook een mislukking) wordt per request
	 * onthouden.
	 *
	 * @param string $locale Bv. 'nl_NL' of 'en_US'.
	 * @return array<string,string>|false relpath => md5, of false bij falen.
	 */
	private static function fetch_checksums_for_locale( $locale ) {
		global $wp_version;

		$key = $wp_version . '|' . $locale;
		if ( array_key_exists( $key, self::$checksum_cache ) ) {
			return self::$checksum_cache[ $key ];
		}

		$result = false;
		$url    = add_query_arg(
			[ 'version' => rawurlencode( $wp_version ), 'locale' => rawurlencode( $locale ) ],
			self::CHECKSUMS_URL
		);

		$response = wp_remote_get( $url, [ 'timeout' => 15 ] );
		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! empty( $body['checksums'] ) && is_array( $body['checksums'] ) ) {
				$result = $body['checksums'];
			}
		}

		self::$checksum_cache[ $key ] = $result;
		return $result;
	}

	/**
	 * Is dit bestand gelijk aan de officiële versie van dezelfde WP-versie
	 * in een andere taal? Alleen voor LOCALE_VARIANT_FILES.
	 *
	 * Geprobeerd: en_US, de taal uit $wp_local_package (staat in
	 * version.php zelf) en de site-locale. Elke kandidaat is een bestand
	 * dat WordPress.org zelf uitlevert; een aangepast bestand matcht er
	 * geen enkele. Lukt het ophalen niet, dan blijft de bevinding staan.
	 *
	 * @param string $relpath    Bv. 'wp-includes/version.php'.
	 * @param string $actual_md5 md5 van het bestand op de server.
	 * @return bool
	 */
	private static function matches_other_official_locale( $relpath, $actual_md5 ) {
		global $wp_local_package;

		$locales = [ 'en_US' ];
		if ( is_string( $wp_local_package ) && preg_match( '/^[a-z]{2,3}(?:_[A-Za-z0-9]+)*$/', $wp_local_package ) ) {
			$locales[] = $wp_local_package;
		}
		$locales[] = get_locale();

		foreach ( array_unique( $locales ) as $locale ) {
			$checksums = self::fetch_checksums_for_locale( $locale );
			if ( is_array( $checksums )
				&& isset( $checksums[ $relpath ] )
				&& is_string( $checksums[ $relpath ] )
				&& hash_equals( $checksums[ $relpath ], $actual_md5 )
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Voer een scan uit en retourneer de bevindingen.
	 *
	 * @return array{findings:array,error:string}
	 */
	public static function scan() {
		$checksums = self::fetch_checksums();
		if ( is_wp_error( $checksums ) ) {
			return [ 'findings' => [], 'error' => $checksums->get_error_message() ];
		}

		$abspath  = untrailingslashit( ABSPATH );
		$findings = [];

		foreach ( $checksums as $relpath => $expected_md5 ) {
			// wp-content zit niet in de officiële lijst, maar voor de
			// zekerheid: nooit meenemen als een toekomstige API-versie dat
			// wel zou doen — dat is het territorium van de Anomaly Scanner.
			if ( 0 === strpos( $relpath, 'wp-content/' ) ) {
				continue;
			}

			$path = $abspath . '/' . ltrim( $relpath, '/' );

			if ( ! is_file( $path ) ) {
				$findings[] = self::build_finding( $relpath, $path, $abspath, 'Kernbestand ontbreekt' );
				continue;
			}

			$actual_md5 = md5_file( $path );
			if ( false === $actual_md5 || $actual_md5 !== $expected_md5 ) {
				// Alleen voor version.php: de officiële versie in een andere
				// taal (meestal en_US na een auto-update) is ook goed.
				if ( false !== $actual_md5
					&& in_array( $relpath, self::LOCALE_VARIANT_FILES, true )
					&& self::matches_other_official_locale( $relpath, $actual_md5 )
				) {
					continue;
				}
				$findings[] = self::build_finding( $relpath, $path, $abspath, 'Kernbestand wijkt af van de officiële WordPress-versie' );
			}
		}

		if ( class_exists( 'MCM_Finding_Ignore' ) ) {
			$findings = MCM_Finding_Ignore::filter( 'core_integrity', $findings );
		}

		return [ 'findings' => $findings, 'error' => '' ];
	}

	private static function build_finding( $relpath, $path, $abspath, $reason ) {
		return [
			'type'     => 'core_checksum_mismatch',
			'reason'   => $reason,
			'severity' => 'high',
			'path'     => $path,
			'relpath'  => $relpath,
			'is_dir'   => false,
			'size'     => is_file( $path ) ? (int) @filesize( $path ) : 0,
			'mtime'    => is_file( $path ) ? (int) @filemtime( $path ) : 0,
		];
	}

	public static function run_cron_scan() {
		if ( ! self::is_enabled() ) {
			return;
		}
		self::run_and_maybe_notify();
	}

	/**
	 * Voert scan uit, slaat resultaten op, en mailt bij elke afwijking
	 * (anti-spam via hash-vergelijking met de vorige mail).
	 *
	 * @return array De bevindingen.
	 */
	public static function run_and_maybe_notify() {
		$result   = self::scan();
		$findings = $result['findings'];

		update_option( self::OPTION_RESULTS, [
			'timestamp' => time(),
			'findings'  => $findings,
			'error'     => $result['error'],
		] );

		if ( empty( $findings ) ) {
			delete_option( self::OPTION_LAST_MAIL_HASH );
			return $findings;
		}

		$hash = self::findings_signature( $findings );
		$last = get_option( self::OPTION_LAST_MAIL_HASH, '' );
		if ( $hash === $last ) {
			return $findings;
		}

		self::send_findings_mail( $findings );
		update_option( self::OPTION_LAST_MAIL_HASH, $hash );

		return $findings;
	}

	private static function findings_signature( array $findings ) {
		$keys = array_map( function ( $f ) {
			return $f['path'];
		}, $findings );
		sort( $keys );
		return md5( implode( "\n", $keys ) );
	}

	private static function send_findings_mail( array $findings ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}
		global $wp_version;
		$count   = count( $findings );
		$subject = sprintf( 'WordPress-kernbestanden gewijzigd (%d)', $count );

		$body  = "Een of meer WordPress-kernbestanden wijken af van de officiële\n";
		$body .= sprintf( "versie %s. Een kernbestand hoort NOOIT te wijzigen buiten een\n", $wp_version );
		$body .= "WordPress-update om — dit is het patroon van een gehackte site.\n\n";

		foreach ( $findings as $i => $f ) {
			$body .= sprintf( "%d. %s\n", $i + 1, $f['reason'] );
			$body .= sprintf( "   Pad:           %s\n", $f['relpath'] );
			$body .= sprintf( "   Laatst gewijz: %s\n\n", $f['mtime'] ? wp_date( 'Y-m-d H:i', $f['mtime'] ) : '?' );
		}

		$body .= "----\n";
		$body .= "ACTIE: herstel via SSH met wp-cli:\n";
		$body .= sprintf( "   wp core download --version=%s --force --skip-content\n", $wp_version );
		$body .= "Dat vervangt ALLE kernbestanden door een verse, officiële kopie —\n";
		$body .= "wp-content (plugins/thema/uploads) blijft onaangeroerd. Controleer\n";
		$body .= "daarna ook gebruikers, actieve plugins en code-snippets: een\n";
		$body .= "kernbestand-infectie komt zelden alleen.\n";

		MCM_Notifier::email( $subject, $body );
	}

	public static function handle_manual_scan() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::ACTION_MANUAL_SCAN );

		self::run_and_maybe_notify();

		wp_safe_redirect(
			add_query_arg(
				'mcm_status',
				'core_integrity_scan_done',
				wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' )
			)
		);
		exit;
	}

	/**
	 * @return array{timestamp:int,findings:array,error:string}|null
	 */
	public static function get_last_results() {
		$saved = get_option( self::OPTION_RESULTS, null );
		if ( ! is_array( $saved ) || ! isset( $saved['findings'] ) ) {
			return null;
		}
		return $saved;
	}
}
