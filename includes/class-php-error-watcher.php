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
 *   - Telt entries per type: Fatal / Parse error / Warning / Deprecated / Notice.
 *   - Detecteert een PHP-versie-wissel (vergelijkt PHP_VERSION met opgeslagen
 *     vorige) en zet de "post-upgrade" modus aan voor 7 dagen — strenger
 *     drempel om kleine stijgingen sneller te vangen.
 *   - Herkomst-filtering tegen mail-moeheid: warning/deprecated tellen alleen
 *     mee voor de drempel als ze uit JOUW EIGEN code komen (wp-content/
 *     plugins|themes|mu-plugins). Core-ruis (wp-includes, wp-login.php) en
 *     systeem-paden (/etc/...) blijven in de log staan maar alarmeren niet —
 *     daar kun je toch niets aan doen. Notices tellen nooit mee.
 *   - Mail-triggers (anti-spam via signature-hash op de relevante tellingen):
 *       * Fatal of Parse error: >= 1 in deze check        -> direct mail (elke herkomst)
 *       * Warning/Deprecated UIT EIGEN CODE: > drempel/uur -> mail
 *   - De mail toont het totaal én de eigen-code-telling én de grootste
 *     ruisbronnen, zodat een hoog totaal meteen te plaatsen is.
 *
 * Drempels (normaal/post-upgrade) instelbaar via settings:
 *   - php_error_warning_threshold_per_hour          default 50
 *   - php_error_post_upgrade_threshold_per_hour     default 10
 *
 * Filters:
 *   - 'mcm_php_error_watcher_max_read_bytes' (default 1 MiB) — kap op het
 *     aantal bytes dat per check uit debug.log gelezen wordt, om memory te
 *     beperken bij plotselinge log-explosies.
 *   - 'mcm_php_error_watcher_own_paths' (array van pad-fragmenten) — bepaalt
 *     wat als "eigen code" geldt voor de drempel. Default: wp-content/
 *     plugins|themes|mu-plugins.
 *   - 'mcm_php_error_watcher_ignore' (array van tekstfragmenten) — demp een
 *     bekende, geaccepteerde eigen-code-melding volledig (bv. 'wp-migrate-db-pro').
 *
 * Tegen volume-ruis telt de drempel UNIEKE problemen (genormaliseerde
 * signatuur), niet hoe vaak dezelfde melding herhaald is. De anti-spam-hash
 * zit op de SET signaturen: een herhaalde flood blijft stil, een nieuw soort
 * probleem alarmeert wél.
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

		$analysis = self::analyze( $chunk );
		$counts   = $analysis['total'];
		$own      = $analysis['own'];

		$post_upgrade = self::is_in_post_upgrade_window();
		$threshold    = $post_upgrade
			? (int) ( $settings['php_error_post_upgrade_threshold_per_hour'] ?? 10 )
			: (int) ( $settings['php_error_warning_threshold_per_hour'] ?? 50 );

		$should_mail = false;
		$reason      = '';

		// Fatal/parse: altijd mailen, ongeacht herkomst (kapot = kapot).
		// Warning/deprecated: alleen de meldingen uit je EIGEN code
		// (wp-content/plugins|themes|mu-plugins) tellen mee voor de drempel.
		// Core (wp-includes, wp-login.php) en systeem (/etc/...) zijn ruis
		// waar je toch niets aan kunt doen — die blijven wel in de log staan.
		// Drempel telt UNIEKE eigen-code-problemen, niet rauwe herhalingen —
		// 14.000 keer dezelfde deprecatie = 1 issue, niet 14.000.
		$own_unique = $analysis['own_unique']['warning'] + $analysis['own_unique']['deprecated'];

		if ( $counts['fatal'] > 0 || $counts['parse'] > 0 ) {
			$should_mail = true;
			$reason      = 'fatal_or_parse';
		} elseif ( $own_unique > $threshold ) {
			$should_mail = true;
			$reason      = $post_upgrade ? 'threshold_exceeded_post_upgrade' : 'threshold_exceeded';
		}

		if ( $should_mail ) {
			self::maybe_send_mail( $analysis, $reason, $post_upgrade, $upgrade );
		}

		return [
			'new_bytes'    => $new_bytes,
			'read'         => $read,
			'counts'       => $counts,
			'own'          => $own,
			'own_unique'   => $analysis['own_unique'],
			'ignored'      => $analysis['ignored'],
			'threshold'    => $threshold,
			'post_upgrade' => $post_upgrade,
			'should_mail'  => $should_mail,
			'reason'       => $reason,
			'upgrade'      => $upgrade,
		];
	}

	/**
	 * Analyseer een log-chunk: tel per type, splits warning/deprecated naar
	 * "eigen code" (telt mee voor de drempel) versus core/systeem-ruis, en
	 * verzamel gededupliceerde voorbeelden + de grootste ruisbronnen.
	 *
	 * @return array{
	 *   total:array{fatal:int,parse:int,warning:int,deprecated:int,notice:int},
	 *   own:array{warning:int,deprecated:int},
	 *   own_unique:array{warning:int,deprecated:int},
	 *   signatures:string[],
	 *   ignored:int,
	 *   samples:array<string,string[]>,
	 *   noise:array<string,int>
	 * }
	 */
	private static function analyze( $chunk ) {
		$total   = [ 'fatal' => 0, 'parse' => 0, 'warning' => 0, 'deprecated' => 0, 'notice' => 0 ];
		$own     = [ 'warning' => 0, 'deprecated' => 0 ]; // rauwe aantallen (weergave)
		$own_sig = [ 'warning' => [], 'deprecated' => [] ]; // distinct signaturen
		$samples = [ 'fatal' => [], 'parse' => [], 'deprecated' => [], 'warning' => [] ];
		$noise   = []; // bronbestand => aantal (alleen core/systeem warning+deprecated)
		$ignored = 0;  // eigen-code-regels die via filter bewust gedempt zijn
		$seen    = [];
		$ignore  = self::ignore_patterns();

		foreach ( preg_split( '/\R/', $chunk ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$type = self::line_type( $line );
			if ( null === $type ) {
				continue;
			}
			$total[ $type ]++;

			// Notices nooit relevant voor de drempel — alleen meetellen.
			if ( 'notice' === $type ) {
				continue;
			}

			$is_own = self::is_own_code_line( $line );

			if ( 'warning' === $type || 'deprecated' === $type ) {
				if ( $is_own ) {
					// Bewust gedempte bron (filter)? Apart tellen, geen signaal.
					if ( self::is_ignored( $line, $ignore ) ) {
						$ignored++;
						continue;
					}
					$own[ $type ]++;
					$own_sig[ $type ][ self::signature( $line ) ] = true;
				} else {
					$src = self::source_file( $line );
					$key = $src ? self::short_path( $src ) : '(onbekende bron)';
					$noise[ $key ] = ( $noise[ $key ] ?? 0 ) + 1;
				}
			}

			// Voorbeelden: fatal/parse altijd; warning/deprecated alleen uit
			// eigen code. Dedupe op signatuur zodat één issue niet 5× verschijnt.
			$want_sample = ( 'fatal' === $type || 'parse' === $type ) ? true : $is_own;
			if ( $want_sample && isset( $samples[ $type ] ) ) {
				$sig = self::signature( $line );
				if ( ! isset( $seen[ $sig ] ) ) {
					$seen[ $sig ] = true;
					if ( count( $samples[ $type ] ) < 5 ) {
						$samples[ $type ][] = $line;
					}
				}
			}
		}

		arsort( $noise );

		// Alle distinct eigen-code-signaturen (gesorteerd) voor een STABIELE
		// anti-spam-hash: zolang de set ongewijzigd is geen herhaling, een
		// nieuw soort probleem alarmeert wél.
		$signatures = array_keys( $own_sig['warning'] + $own_sig['deprecated'] );
		sort( $signatures );

		return [
			'total'      => $total,
			'own'        => $own,
			'own_unique' => [
				'warning'    => count( $own_sig['warning'] ),
				'deprecated' => count( $own_sig['deprecated'] ),
			],
			'signatures' => $signatures,
			'ignored'    => $ignored,
			'samples'    => $samples,
			'noise'      => $noise,
		];
	}

	/**
	 * Bepaal het PHP-fouttype van één log-regel (of null als het er geen is).
	 *
	 * @return string|null
	 */
	private static function line_type( $line ) {
		if ( preg_match( '/PHP Fatal/i', $line ) ) {
			return 'fatal';
		}
		if ( preg_match( '/PHP Parse error/i', $line ) ) {
			return 'parse';
		}
		if ( preg_match( '/PHP Deprecated/i', $line ) ) {
			return 'deprecated';
		}
		if ( preg_match( '/PHP Warning/i', $line ) ) {
			return 'warning';
		}
		if ( preg_match( '/PHP Notice/i', $line ) ) {
			return 'notice';
		}
		return null;
	}

	/**
	 * Haal het bronbestand uit een PHP-foutregel ("... in /pad/bestand.php on
	 * line N"). Retourneert null als er geen pad in staat.
	 *
	 * @return string|null
	 */
	private static function source_file( $line ) {
		if ( preg_match( '#\bin (/[^ ]+\.php)(?: on line \d+)?#i', $line, $m ) ) {
			return $m[1];
		}
		return null;
	}

	/**
	 * Pad-fragmenten die als "eigen code" gelden — alleen fouten hieruit
	 * tellen mee voor de warning/deprecated-drempel. Per site aan te passen
	 * via de filter (bv. om een extra map mee te tellen).
	 *
	 * @return string[]
	 */
	private static function own_code_paths() {
		return (array) apply_filters( 'mcm_php_error_watcher_own_paths', [
			'/wp-content/plugins/',
			'/wp-content/themes/',
			'/wp-content/mu-plugins/',
		] );
	}

	/**
	 * Komt deze foutregel uit eigen code (plugins/thema's/mu-plugins)?
	 * Geen toewijsbaar pad → behandel als ruis (alarmeert niet) zodat losse,
	 * niet-plaatsbare core-meldingen je niet onder mails bedelven.
	 */
	private static function is_own_code_line( $line ) {
		$path = self::source_file( $line );
		if ( null === $path ) {
			return false;
		}
		foreach ( self::own_code_paths() as $needle ) {
			if ( false !== strpos( $path, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Verkort een absoluut pad tot iets leesbaars voor de mail (vanaf
	 * wp-content/ of anders de bestandsnaam).
	 */
	private static function short_path( $path ) {
		$pos = strpos( $path, '/wp-content/' );
		if ( false !== $pos ) {
			return substr( $path, $pos + 1 ); // zonder leidende slash
		}
		$pos = strrpos( $path, '/' );
		return false !== $pos ? substr( $path, $pos + 1 ) : $path;
	}

	/**
	 * Normaliseer een log-regel tot een herkenbaar "issue": timestamp eraf en
	 * het absolute pad teruggebracht tot wp-content-relatief. Zo is hetzelfde
	 * probleem op elke site dezelfde tekst (en dus dezelfde signatuur).
	 */
	private static function normalize( $line ) {
		$s = preg_replace( '/^\[[^\]]*\]\s*/', '', $line );
		$s = preg_replace_callback( '#in (/\S+\.php)#i', function ( $m ) {
			return 'in ' . self::short_path( $m[1] );
		}, (string) $s );
		return trim( (string) $s );
	}

	/**
	 * MD5-signatuur van een genormaliseerde regel — identiteit van één issue.
	 */
	private static function signature( $line ) {
		return md5( self::normalize( $line ) );
	}

	/**
	 * Tekstfragmenten waarmee je een bekende, geaccepteerde eigen-code-melding
	 * volledig kunt dempen (per site, zonder code te wijzigen). Gematcht tegen
	 * de genormaliseerde regel, case-insensitive. Bv.:
	 *
	 *   add_filter( 'mcm_php_error_watcher_ignore', function ( $p ) {
	 *       $p[] = 'wp-migrate-db-pro'; // demp deprecaties uit deze plugin
	 *       return $p;
	 *   } );
	 *
	 * @return string[]
	 */
	private static function ignore_patterns() {
		return (array) apply_filters( 'mcm_php_error_watcher_ignore', [] );
	}

	/**
	 * Matcht een regel tegen de ignore-patronen.
	 */
	private static function is_ignored( $line, array $patterns ) {
		if ( empty( $patterns ) ) {
			return false;
		}
		$norm = self::normalize( $line );
		foreach ( $patterns as $needle ) {
			if ( '' !== (string) $needle && false !== stripos( $norm, (string) $needle ) ) {
				return true;
			}
		}
		return false;
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
	private static function maybe_send_mail( array $analysis, $reason, $post_upgrade, $upgrade ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}

		$counts = $analysis['total'];

		// Anti-spam-hash op de SET unieke eigen-code-signaturen (niet op
		// oplopende tellers) + fatal/parse. Zelfde set issues = geen herhaling;
		// een NIEUW soort probleem verandert de set en alarmeert wél.
		$hash = md5( $reason . '|' . $counts['fatal'] . '|' . $counts['parse'] . '|' . implode( ',', $analysis['signatures'] ) );
		$last = (string) get_option( self::OPTION_LAST_MAIL_HASH, '' );

		// Voor fatal/parse: altijd doormailen. Anders: skippen als zelfde
		// signature als vorige mail (= zelfde set sinds laatste alert).
		if ( 'fatal_or_parse' !== $reason && $hash === $last ) {
			return;
		}

		$subject = self::subject_for( $reason, $counts, $analysis['own_unique'], $post_upgrade );
		$body    = self::body_for( $analysis, $reason, $post_upgrade, $upgrade );

		MCM_Notifier::email( $subject, $body );
		update_option( self::OPTION_LAST_MAIL_HASH, $hash );
	}

	private static function subject_for( $reason, $counts, $unique, $post_upgrade ) {
		if ( 'fatal_or_parse' === $reason ) {
			$n = $counts['fatal'] + $counts['parse'];
			return sprintf( 'PHP FATAL errors gedetecteerd (%d)', $n );
		}
		// Drempel-mail draait om het aantal UNIEKE eigen-code-problemen.
		$n = $unique['warning'] + $unique['deprecated'];
		return $post_upgrade
			? sprintf( 'Nieuwe PHP-warnings/deprecaties uit eigen code na PHP-upgrade (%d uniek)', $n )
			: sprintf( 'Nieuwe PHP-warnings/deprecaties uit eigen code boven drempel (%d uniek)', $n );
	}

	private static function body_for( $analysis, $reason, $post_upgrade, $upgrade ) {
		$counts  = $analysis['total'];
		$own     = $analysis['own'];
		$unique  = $analysis['own_unique'];
		$samples = $analysis['samples'];
		$noise   = $analysis['noise'];

		$lines  = [];
		$lines[] = 'Op deze site zijn relevante PHP-foutmeldingen binnengekomen in';
		$lines[] = 'wp-content/debug.log sinds de vorige check.';
		$lines[] = '';

		$lines[] = 'Tellingen sinds vorige check (totaal in de log):';
		$lines[] = sprintf( '  Fatal:        %d', $counts['fatal'] );
		$lines[] = sprintf( '  Parse error:  %d', $counts['parse'] );
		$lines[] = sprintf( '  Warning:      %d', $counts['warning'] );
		$lines[] = sprintf( '  Deprecated:   %d', $counts['deprecated'] );
		$lines[] = sprintf( '  Notice (info): %d', $counts['notice'] );
		$lines[] = '';

		$lines[] = 'Waarvan uit JOUW EIGEN code (plugins/thema\'s/mu-plugins) —';
		$lines[] = 'dit is wat meetelt en waar je iets aan kunt doen. We tellen';
		$lines[] = 'UNIEKE problemen, niet hoe vaak ze herhaald zijn:';
		$lines[] = sprintf( '  Warning:     %d uniek (%d keer in totaal)', $unique['warning'], $own['warning'] );
		$lines[] = sprintf( '  Deprecated:  %d uniek (%d keer in totaal)', $unique['deprecated'], $own['deprecated'] );
		if ( ! empty( $analysis['ignored'] ) ) {
			$lines[] = sprintf( '  (%d eigen-code-regels bewust gedempt via filter)', $analysis['ignored'] );
		}
		$lines[] = '';

		if ( ! empty( $noise ) ) {
			$noise_total = array_sum( $noise );
			$lines[] = sprintf( 'Genegeerd als core/server-ruis (%d, geen actie nodig). Grootste bronnen:', $noise_total );
			$shown = 0;
			foreach ( $noise as $src => $cnt ) {
				$lines[] = sprintf( '  - %s (%d×)', $src, $cnt );
				if ( ++$shown >= 5 ) {
					break;
				}
			}
			$lines[] = '';
		}

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
