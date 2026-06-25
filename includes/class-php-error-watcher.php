<?php
/**
 * PHP Error Watcher — monitort wp-content/debug.log op nieuwe fatal/parse/
 * warning/deprecated entries en mailt bij relevante stijging.
 *
 * Bedoeld om tijdens en na een PHP-upgrade (bv. 8.2 -> 8.5) snel te kunnen
 * reageren op compat-problemen — sneller dan de wekelijkse Debug Watchdog
 * die alleen WP_DEBUG=true detecteert, en sneller dan de wekelijkse File
 * Exposure Scanner die debug.log als bestand vindt.
 *
 * Werking:
 *   - Wp-cron elk uur. Leest alleen NIEUWE bytes in debug.log sinds vorige
 *     check (offset opgeslagen in option). Bij log-rotatie (huidige size <
 *     laatste offset) begint hij opnieuw vanaf 0.
 *   - Telt entries per type: Fatal / Parse error / Warning / Deprecated.
 *   - Detecteert een PHP-versie-wissel (vergelijkt PHP_VERSION met opgeslagen
 *     vorige) en zet de "post-upgrade" modus aan voor 7 dagen — strenger
 *     drempel om kleine stijgingen sneller te vangen.
 *   - Mail-triggers (anti-spam via signature-hash):
 *       * Fatal of Parse error: >= 1 in deze check  -> direct mail
 *       * Warning/Deprecated:  > drempel per uur    -> mail
 *
 * Drempels (normaal/post-upgrade) instelbaar via settings:
 *   - php_error_warning_threshold_per_hour          default 50
 *   - php_error_post_upgrade_threshold_per_hour     default 10
 *
 * Filter:
 *   - 'mcm_php_error_watcher_max_read_bytes' (default 1 MiB) — kap op het
 *     aantal bytes dat per check uit debug.log gelezen wordt, om memory te
 *     beperken bij plotselinge log-explosies.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_PHP_Error_Watcher {

	const CRON_HOOK             = 'mcm_security_php_error_check';
	const OPTION_OFFSET         = 'mcm_php_log_offset';
	const OPTION_LAST_VERSION   = 'mcm_php_last_version';
	const OPTION_UPGRADE_AT     = 'mcm_php_upgrade_at';
	const OPTION_LAST_MAIL_HASH = 'mcm_php_last_mail_hash';
	const POST_UPGRADE_WINDOW   = 7 * DAY_IN_SECONDS;
	const DEFAULT_MAX_BYTES     = 1048576; // 1 MiB per check

	public function __construct() {
		add_action( self::CRON_HOOK, [ __CLASS__, 'run_cron_check' ] );
		add_action( 'init', [ __CLASS__, 'maybe_schedule_cron' ] );
	}

	/**
	 * Plan cron als de feature aan staat; haal hem weg als 'ie uit gaat.
	 */
	public static function maybe_schedule_cron() {
		$settings = get_option( 'mcm_security_settings', [] );
		// Backward-compat: oudere sites missen de key nog in DB. Val terug op
		// de plugin-default zodat de cron toch start zonder dat de admin
		// eerst handmatig opslaat na update.
		if ( ! array_key_exists( 'php_error_watcher_enabled', $settings ) ) {
			$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
				? MCM_Security_Hardener::get_defaults()
				: [];
			$enabled  = ! empty( $defaults['php_error_watcher_enabled'] );
		} else {
			$enabled = ! empty( $settings['php_error_watcher_enabled'] );
		}
		$next = wp_next_scheduled( self::CRON_HOOK );

		if ( $enabled && ! $next ) {
			// Eerste keer: over 10 min, daarna hourly.
			wp_schedule_event( time() + 10 * MINUTE_IN_SECONDS, 'hourly', self::CRON_HOOK );
		} elseif ( ! $enabled && $next ) {
			wp_unschedule_event( $next, self::CRON_HOOK );
		}
	}

	/**
	 * Pad naar wp-content/debug.log. Respecteert WP_CONTENT_DIR.
	 */
	private static function log_path() {
		$dir = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content';
		return rtrim( $dir, '/\\' ) . '/debug.log';
	}

	/**
	 * Cron-callback: detecteer eventuele PHP-upgrade, lees nieuwe log-bytes,
	 * tel entries, en mail indien nodig.
	 *
	 * @return array Stats van de check (voor unit-testen / handmatige aanroep).
	 */
	public static function run_cron_check() {
		$settings = get_option( 'mcm_security_settings', [] );
		// Backward-compat fallback (zie maybe_schedule_cron).
		if ( ! array_key_exists( 'php_error_watcher_enabled', $settings ) ) {
			$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
				? MCM_Security_Hardener::get_defaults()
				: [];
			$enabled = ! empty( $defaults['php_error_watcher_enabled'] );
		} else {
			$enabled = ! empty( $settings['php_error_watcher_enabled'] );
		}
		if ( ! $enabled ) {
			return [ 'skipped' => 'feature disabled' ];
		}

		$upgrade = self::detect_php_upgrade();

		$path = self::log_path();
		if ( ! is_readable( $path ) ) {
			return [ 'skipped' => 'no debug.log', 'upgrade' => $upgrade ];
		}

		$size       = (int) @filesize( $path );
		$last_off   = (int) get_option( self::OPTION_OFFSET, 0 );

		// Log-rotatie? Truncate? Begin opnieuw.
		if ( $size < $last_off ) {
			$last_off = 0;
		}

		$new_bytes = $size - $last_off;
		if ( $new_bytes <= 0 ) {
			update_option( self::OPTION_OFFSET, $size );
			return [
				'new_bytes' => 0,
				'upgrade'   => $upgrade,
			];
		}

		$max_read = (int) apply_filters( 'mcm_php_error_watcher_max_read_bytes', self::DEFAULT_MAX_BYTES );
		$read     = min( $new_bytes, $max_read );

		$chunk = @file_get_contents( $path, false, null, $last_off, $read );
		// Schuif offset naar het einde — bewust ook bij read-cap, anders
		// blijft de watcher in een explosief gevulde log hangen.
		update_option( self::OPTION_OFFSET, $size );

		if ( false === $chunk || '' === $chunk ) {
			return [ 'read' => 0, 'upgrade' => $upgrade ];
		}

		$counts = self::count_entries( $chunk );

		$post_upgrade = self::is_in_post_upgrade_window();
		$threshold    = $post_upgrade
			? (int) ( $settings['php_error_post_upgrade_threshold_per_hour'] ?? 10 )
			: (int) ( $settings['php_error_warning_threshold_per_hour'] ?? 50 );

		$should_mail = false;
		$reason      = '';

		if ( $counts['fatal'] > 0 || $counts['parse'] > 0 ) {
			$should_mail = true;
			$reason      = 'fatal_or_parse';
		} elseif ( ( $counts['warning'] + $counts['deprecated'] ) > $threshold ) {
			$should_mail = true;
			$reason      = $post_upgrade ? 'threshold_exceeded_post_upgrade' : 'threshold_exceeded';
		}

		if ( $should_mail ) {
			$samples = self::extract_samples( $chunk );
			self::maybe_send_mail( $counts, $samples, $reason, $post_upgrade, $upgrade );
		}

		return [
			'new_bytes'    => $new_bytes,
			'read'         => $read,
			'counts'       => $counts,
			'threshold'    => $threshold,
			'post_upgrade' => $post_upgrade,
			'should_mail'  => $should_mail,
			'reason'       => $reason,
			'upgrade'      => $upgrade,
		];
	}

	/**
	 * Tel entries per type in een log-chunk.
	 *
	 * @return array{fatal:int,parse:int,warning:int,deprecated:int,notice:int}
	 */
	private static function count_entries( $chunk ) {
		return [
			'fatal'      => preg_match_all( '/PHP Fatal/i', $chunk ),
			'parse'      => preg_match_all( '/PHP Parse error/i', $chunk ),
			'warning'    => preg_match_all( '/PHP Warning/i', $chunk ),
			'deprecated' => preg_match_all( '/PHP Deprecated/i', $chunk ),
			'notice'     => preg_match_all( '/PHP Notice/i', $chunk ),
		];
	}

	/**
	 * Pak een paar voorbeelden per kritiek type, gededupliceerd op message-
	 * signatuur (eerste 120 tekens), zodat de mail niet uitloopt op
	 * herhaalde identieke errors.
	 *
	 * @return array<string,string[]>
	 */
	private static function extract_samples( $chunk ) {
		$samples = [
			'fatal'      => [],
			'parse'      => [],
			'deprecated' => [],
			'warning'    => [],
		];
		$lines = preg_split( '/\R/', $chunk );
		$seen  = [];

		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$type = null;
			if ( preg_match( '/PHP Fatal/i', $line ) ) {
				$type = 'fatal';
			} elseif ( preg_match( '/PHP Parse error/i', $line ) ) {
				$type = 'parse';
			} elseif ( preg_match( '/PHP Deprecated/i', $line ) ) {
				$type = 'deprecated';
			} elseif ( preg_match( '/PHP Warning/i', $line ) ) {
				$type = 'warning';
			}
			if ( null === $type ) {
				continue;
			}
			$sig = substr( $line, 0, 120 );
			if ( isset( $seen[ $sig ] ) ) {
				continue;
			}
			$seen[ $sig ] = true;
			if ( count( $samples[ $type ] ) < 5 ) {
				$samples[ $type ][] = $line;
			}
		}
		return $samples;
	}

	/**
	 * Detecteert PHP-upgrade door PHP_VERSION te vergelijken met opgeslagen
	 * vorige versie. Bij verschil: sla nieuwe versie + timestamp op.
	 *
	 * @return array{from:string|null,to:string|null,detected:bool}
	 */
	private static function detect_php_upgrade() {
		$current = PHP_VERSION;
		$last    = (string) get_option( self::OPTION_LAST_VERSION, '' );

		if ( '' === $last ) {
			// Eerste keer ooit — sla op, niets te melden.
			update_option( self::OPTION_LAST_VERSION, $current );
			return [ 'from' => null, 'to' => $current, 'detected' => false ];
		}

		if ( $last !== $current ) {
			update_option( self::OPTION_LAST_VERSION, $current );
			update_option( self::OPTION_UPGRADE_AT, time() );
			// Reset mail-hash zodat na upgrade een nieuwe mail wel doorkomt.
			delete_option( self::OPTION_LAST_MAIL_HASH );
			return [ 'from' => $last, 'to' => $current, 'detected' => true ];
		}

		return [ 'from' => null, 'to' => $current, 'detected' => false ];
	}

	/**
	 * Zit de site binnen de post-upgrade gevoeligheidswindow (7 dagen)?
	 */
	private static function is_in_post_upgrade_window() {
		$at = (int) get_option( self::OPTION_UPGRADE_AT, 0 );
		if ( $at <= 0 ) {
			return false;
		}
		return ( time() - $at ) < self::POST_UPGRADE_WINDOW;
	}

	/**
	 * Stuur de mail, met anti-spam: hash van counts+reason. Zelfde hash =
	 * geen herhaling. Bij fatal/parse override anti-spam want die zijn
	 * altijd dringend.
	 */
	private static function maybe_send_mail( array $counts, array $samples, $reason, $post_upgrade, $upgrade ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}

		$hash = md5( $reason . '|' . wp_json_encode( $counts ) );
		$last = (string) get_option( self::OPTION_LAST_MAIL_HASH, '' );

		// Voor fatal/parse: altijd doormailen. Anders: skippen als zelfde
		// signature als vorige mail (= zelfde set sinds laatste alert).
		if ( 'fatal_or_parse' !== $reason && $hash === $last ) {
			return;
		}

		$subject = self::subject_for( $reason, $counts, $post_upgrade );
		$body    = self::body_for( $counts, $samples, $reason, $post_upgrade, $upgrade );

		MCM_Notifier::email( $subject, $body );
		update_option( self::OPTION_LAST_MAIL_HASH, $hash );
	}

	private static function subject_for( $reason, $counts, $post_upgrade ) {
		if ( 'fatal_or_parse' === $reason ) {
			$n = $counts['fatal'] + $counts['parse'];
			return sprintf( 'PHP FATAL errors gedetecteerd (%d)', $n );
		}
		$n = $counts['warning'] + $counts['deprecated'];
		return $post_upgrade
			? sprintf( 'Stijging PHP-warnings/deprecaties na PHP-upgrade (%d)', $n )
			: sprintf( 'Stijging PHP-warnings/deprecaties boven drempel (%d)', $n );
	}

	private static function body_for( $counts, $samples, $reason, $post_upgrade, $upgrade ) {
		$lines  = [];
		$lines[] = 'Op deze site zijn relevante PHP-foutmeldingen binnengekomen in';
		$lines[] = 'wp-content/debug.log sinds de vorige check.';
		$lines[] = '';

		$lines[] = 'Tellingen sinds vorige check:';
		$lines[] = sprintf( '  Fatal:        %d', $counts['fatal'] );
		$lines[] = sprintf( '  Parse error:  %d', $counts['parse'] );
		$lines[] = sprintf( '  Warning:      %d', $counts['warning'] );
		$lines[] = sprintf( '  Deprecated:   %d', $counts['deprecated'] );
		$lines[] = sprintf( '  Notice (info): %d', $counts['notice'] );
		$lines[] = '';

		if ( $upgrade && ! empty( $upgrade['detected'] ) ) {
			$lines[] = sprintf( 'Recent gedetecteerde PHP-versie-wijziging: %s -> %s.', (string) $upgrade['from'], (string) $upgrade['to'] );
			$lines[] = 'De watcher staat 7 dagen in extra gevoelige modus.';
			$lines[] = '';
		} elseif ( $post_upgrade ) {
			$lines[] = 'Site staat binnen de 7-dagen post-PHP-upgrade gevoeligheidswindow.';
			$lines[] = '';
		}

		$lines[] = 'Voorbeelden (max 5 per type, gededupliceerd):';
		foreach ( [ 'fatal' => 'Fatal', 'parse' => 'Parse error', 'deprecated' => 'Deprecated', 'warning' => 'Warning' ] as $key => $label ) {
			if ( empty( $samples[ $key ] ) ) {
				continue;
			}
			$lines[] = '';
			$lines[] = "[$label]";
			foreach ( $samples[ $key ] as $sample ) {
				$lines[] = '  - ' . $sample;
			}
		}

		$lines[] = '';
		$lines[] = '----';
		$lines[] = 'Acties:';
		if ( 'fatal_or_parse' === $reason ) {
			$lines[] = '- Controleer onmiddellijk of de site nog werkt.';
			$lines[] = '- Tail wp-content/debug.log voor de volledige context.';
		} else {
			$lines[] = '- Controleer welke plugin/theme de meeste warnings veroorzaakt.';
			$lines[] = '- Tijdens een PHP-upgrade: bedrijfskritiek = vooral de fatal/parse-meldingen.';
		}
		$lines[] = '';
		$lines[] = 'Volledige log:    wp-content/debug.log';
		$lines[] = 'Aanpassen drempel: MCM Security -> sectie "PHP Error Watcher".';

		return implode( "\n", $lines );
	}

	/**
	 * Helper voor UI: huidige stand (voor admin-page).
	 *
	 * @return array
	 */
	public static function get_status() {
		return [
			'cron_next_run'   => wp_next_scheduled( self::CRON_HOOK ),
			'log_path'        => self::log_path(),
			'log_exists'      => is_readable( self::log_path() ),
			'last_offset'     => (int) get_option( self::OPTION_OFFSET, 0 ),
			'last_version'    => (string) get_option( self::OPTION_LAST_VERSION, '' ),
			'current_version' => PHP_VERSION,
			'upgrade_at'      => (int) get_option( self::OPTION_UPGRADE_AT, 0 ),
			'post_upgrade'    => self::is_in_post_upgrade_window(),
		];
	}
}
