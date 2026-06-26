<?php
/**
 * Anomaly Scanner — detecteert vreemde bestanden/mappen in de webroot en
 * boven in wp-content die er bij een standaard WordPress-installatie niet
 * horen. Klassiek hack-artefact: een aanvaller dropt een losse .php-shell
 * met een rare naam in de root of in wp-content.
 *
 * Aanleiding: bij een eerdere hack werden vreemde bestanden/mappen
 * geïnstalleerd. WordPress is redelijk standaard — wat er niet hoort, valt op.
 *
 * Verschil met MCM_File_Exposure_Scanner:
 *   - Exposure-scanner zoekt naar BLOOTGESTELDE gevoelige bestanden die je
 *     zelf per ongeluk neerzet (info.php, .env, SQL-dumps, backups).
 *   - Deze scanner werkt met een WHITELIST: alles wat NIET op de lijst van
 *     bekende WP-/host-/plugin-items staat, wordt gemeld. Dat vangt juist de
 *     onbekende dropper waarvan we de naam niet vooraf kennen.
 *
 * Gedrag:
 *   - Top-level only (géén recursie): ABSPATH en ABSPATH/wp-content, ieder
 *     één niveau diep. Snel + voorspelbaar, zelfde keuze als de exposure-scanner.
 *   - Severity-tiers om alarm-moeheid te voorkomen:
 *       HIGH    onbekend .php-bestand (root of los in wp-content) → daar
 *               landen shells.
 *       MEDIUM  onbekende map in de root.
 *       LOW     onbekende map in wp-content (vaak door een plugin gemaakt)
 *               of een onbekend niet-uitvoerbaar bestand.
 *   - Mailt alleen bij HIGH/MEDIUM-bevindingen (anti-ruis). LOW-items staan
 *     wél in de admin-tabel maar triggeren geen mail.
 *   - Anti-spam: dezelfde set bevindingen mailt maar één keer (hash-vergelijk).
 *   - Verwijdert NOOIT zelf. Detectie + melding only.
 *
 * Bijstellen zonder code te wijzigen:
 *   - filter 'mcm_anomaly_root_whitelist'       (array van namen, lowercase)
 *   - filter 'mcm_anomaly_wpcontent_whitelist'  (array van namen, lowercase)
 *
 * Settings (in mcm_security_settings):
 *   - 'anomaly_scanner_enabled'  bool  default true   (cron + UI actief)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Anomaly_Scanner {

	const CRON_HOOK             = 'mcm_security_anomaly_scan';
	const CRON_SCHEDULE         = 'mcm_weekly';
	const ACTION_MANUAL_SCAN    = 'mcm_security_run_anomaly_scan';
	const ACTION_TOGGLE         = 'mcm_security_toggle_anomaly';
	const OPTION_RESULTS        = 'mcm_anomaly_scan_results';
	const OPTION_LAST_MAIL_HASH = 'mcm_anomaly_last_mailed_hash';
	const MAX_FILES_PER_DIR     = 1000; // perf-cap per directory

	public function __construct() {
		// 'mcm_weekly' wordt ook door de exposure-scanner geregistreerd; de
		// isset-guard maakt dubbel registreren veilig (decoupled van die class).
		add_filter( 'cron_schedules', [ __CLASS__, 'register_weekly_schedule' ] );

		add_action( self::CRON_HOOK, [ __CLASS__, 'run_cron_scan' ] );
		add_action( 'admin_post_' . self::ACTION_MANUAL_SCAN, [ __CLASS__, 'handle_manual_scan' ] );
		add_action( 'admin_post_' . self::ACTION_TOGGLE, [ __CLASS__, 'handle_toggle' ] );
		add_action( 'init', [ __CLASS__, 'maybe_schedule_cron' ] );
	}

	/**
	 * Voegt 'mcm_weekly' toe aan wp_get_schedules() (idempotent).
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
	 * Is de feature ingeschakeld? Met backward-compat fallback op de
	 * plugin-default zodat de cron ook start zonder dat de admin eerst
	 * handmatig opslaat na een update.
	 */
	private static function is_enabled() {
		$settings = get_option( 'mcm_security_settings', [] );
		if ( ! array_key_exists( 'anomaly_scanner_enabled', $settings ) ) {
			$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
				? MCM_Security_Hardener::get_defaults()
				: [];
			return ! empty( $defaults['anomaly_scanner_enabled'] );
		}
		return ! empty( $settings['anomaly_scanner_enabled'] );
	}

	/**
	 * Publieke status-helper (voor o.a. de admin-bar). True = scan staat aan.
	 */
	public static function is_active() {
		return self::is_enabled();
	}

	/**
	 * Plan cron als de feature aan staat; haal hem weg als 'ie uit gaat.
	 */
	public static function maybe_schedule_cron() {
		$enabled = self::is_enabled();
		$next    = wp_next_scheduled( self::CRON_HOOK );

		if ( $enabled && ! $next ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, self::CRON_SCHEDULE, self::CRON_HOOK );
		} elseif ( ! $enabled && $next ) {
			wp_unschedule_event( $next, self::CRON_HOOK );
		}
	}

	/**
	 * Bestandsnaam-extensies die als uitvoerbaar PHP gelden — een onbekend
	 * bestand met zo'n extensie in root of los in wp-content is hoog-risico.
	 *
	 * @return string[]
	 */
	private static function executable_extensions() {
		return [ 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar' ];
	}

	/**
	 * Bekende, legitieme items in de WordPress-root (lowercase namen).
	 * Zowel bestanden als mappen. Wat hier NIET op staat, wordt gemeld.
	 *
	 * @return string[]
	 */
	public static function root_whitelist() {
		$names = [
			// Core mappen.
			'wp-admin', 'wp-includes', 'wp-content',
			// Core bestanden.
			'index.php', 'wp-activate.php', 'wp-blog-header.php',
			'wp-comments-post.php', 'wp-config.php', 'wp-config-sample.php',
			'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
			'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php',
			'xmlrpc.php', 'license.txt', 'readme.html',
			// Server-/config-bestanden die normaal in de root mogen staan.
			'.htaccess', '.htpasswd', '.user.ini', 'php.ini', '.well-known',
			'cgi-bin', 'robots.txt', 'error_log',
			// SEO/verificatie-bestanden die mensen vaak in de root zetten.
			'favicon.ico', 'ads.txt', 'app-ads.txt', 'sitemap.xml',
			'sitemap_index.xml', 'manifest.json', 'browserconfig.xml',
			'bingsiteauth.xml', 'humans.txt', 'security.txt',
			// Mac/sync-ruis (op Marco's gemounte Storagebox-werkmappen).
			'.ds_store',
		];

		/**
		 * Voeg site-specifieke bekende root-items toe (lowercase namen) of
		 * verwijder er. Zo kun je een terechte melding permanent stilzetten
		 * zonder code te wijzigen.
		 */
		$names = apply_filters( 'mcm_anomaly_root_whitelist', $names );

		return array_map( 'strtolower', (array) $names );
	}

	/**
	 * Regex-patronen voor root-items die per definitie legitiem zijn maar een
	 * variabele naam hebben (bv. Google Search Console verificatie).
	 *
	 * @return string[]
	 */
	private static function root_whitelist_regex() {
		return [
			'/^google[0-9a-f]+\.html$/i',   // Google Search Console.
			'/^pinterest-[0-9a-z]+\.html$/i',
			'/^[0-9a-f]{32}\.txt$/i',        // Sommige verificatie-tokens.
		];
	}

	/**
	 * Bekende, legitieme items direct in wp-content (lowercase namen).
	 * wp-content is rommeliger dan de root: veel plugins maken hier mappen
	 * en WP heeft een rits "drop-in" bestanden die hier mogen liggen.
	 *
	 * @return string[]
	 */
	public static function wpcontent_whitelist() {
		$names = [
			// Core mappen.
			'plugins', 'themes', 'uploads', 'languages', 'mu-plugins',
			'upgrade', 'upgrade-temp-backup', 'cache', 'fonts',
			// Multisite.
			'blogs.dir', 'sunrise.php',
			// Core drop-ins (mogen rechtstreeks in wp-content liggen).
			'index.php', '.htaccess', 'advanced-cache.php', 'object-cache.php',
			'db.php', 'db-error.php', 'install.php', 'maintenance.php',
			'php-error.php', 'fatal-error-handler.php', 'blog-deleted.php',
			'blog-inactive.php', 'blog-suspended.php',
			// Veelvoorkomende, legitieme plugin-/host-mappen.
			'wflogs', 'et-cache', 'w3tc-config', 'ai1wm-backups',
			'backups-dup-pro', 'updraft', 'litespeed',
			'endurance-page-cache', 'mcm-security-backups',
			// WP Rocket (cache-plugin op MCM-sites).
			'wp-rocket-config',
			// WPvivid (backup-plugin op MCM-sites) — maakt meerdere mappen.
			'wpvividbackups', 'wpvivid_staging', 'wpvivid_uploads',
			'wpvivid_image_optimization',
			// Mac/sync-ruis.
			'.ds_store',
		];

		/**
		 * Zelfde idee als de root-whitelist, maar voor wp-content.
		 */
		$names = apply_filters( 'mcm_anomaly_wpcontent_whitelist', $names );

		return array_map( 'strtolower', (array) $names );
	}

	/**
	 * Voer een scan uit en retourneer de bevindingen.
	 *
	 * @return array<int,array{type:string,reason:string,severity:string,path:string,relpath:string,is_dir:bool,size:int,mtime:int}>
	 */
	public static function scan() {
		$findings = [];
		$abspath  = untrailingslashit( ABSPATH );

		// 1) Root.
		$root_white = self::root_whitelist();
		$root_regex = self::root_whitelist_regex();
		foreach ( self::list_dir_entries( $abspath ) as $entry ) {
			if ( self::is_whitelisted( $entry, $root_white, $root_regex ) ) {
				continue;
			}
			$path  = $abspath . '/' . $entry;
			$isdir = is_dir( $path );
			$findings[] = self::classify( 'root', $entry, $path, $isdir, $abspath );
		}

		// 2) wp-content (top-level).
		$wpc = $abspath . '/wp-content';
		if ( is_dir( $wpc ) ) {
			$wpc_white = self::wpcontent_whitelist();
			foreach ( self::list_dir_entries( $wpc ) as $entry ) {
				if ( self::is_whitelisted( $entry, $wpc_white, [] ) ) {
					continue;
				}
				$path  = $wpc . '/' . $entry;
				$isdir = is_dir( $path );
				$findings[] = self::classify( 'wp-content', $entry, $path, $isdir, $abspath );
			}
		}

		return $findings;
	}

	/**
	 * Is dit entry bekend (whitelist exact óf via regex)?
	 */
	private static function is_whitelisted( $entry, array $exact, array $regex ) {
		if ( in_array( strtolower( $entry ), $exact, true ) ) {
			return true;
		}
		foreach ( $regex as $re ) {
			if ( preg_match( $re, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Bepaal severity + reden voor een onbekend item en bouw de finding.
	 */
	private static function classify( $location, $entry, $path, $isdir, $abspath ) {
		$ext = strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) );

		if ( $isdir ) {
			if ( 'root' === $location ) {
				$severity = 'medium';
				$reason   = 'Onbekende map in de webroot';
			} else {
				$severity = 'low';
				$reason   = 'Onbekende map in wp-content (vaak door een plugin aangemaakt — controleer of je \'m herkent)';
			}
		} elseif ( in_array( $ext, self::executable_extensions(), true ) ) {
			// Een los uitvoerbaar PHP-bestand hier is het klassieke shell-signaal.
			$severity = 'high';
			$reason   = ( 'root' === $location )
				? 'Onbekend PHP-bestand in de webroot — mogelijke shell/dropper'
				: 'Onbekend PHP-bestand los in wp-content — mogelijke shell/dropper';
		} else {
			$severity = 'low';
			$reason   = 'Onbekend bestand ' . ( 'root' === $location ? 'in de webroot' : 'in wp-content' );
		}

		$rel = ltrim( str_replace( $abspath, '', $path ), '/\\' );

		return [
			'type'     => 'unexpected',
			'reason'   => $reason,
			'severity' => $severity,
			'path'     => $path,
			'relpath'  => $rel,
			'is_dir'   => (bool) $isdir,
			'size'     => is_file( $path ) ? (int) @filesize( $path ) : 0,
			'mtime'    => (int) @filemtime( $path ),
		];
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
			$entries = array_slice( $entries, 0, self::MAX_FILES_PER_DIR );
		}
		return $entries;
	}

	/**
	 * Wp-cron callback.
	 */
	public static function run_cron_scan() {
		if ( ! self::is_enabled() ) {
			return;
		}
		self::run_and_maybe_notify();
	}

	/**
	 * Voert scan uit, slaat resultaten op, en mailt indien er HIGH/MEDIUM-
	 * bevindingen zijn die afwijken van de vorige mail (anti-spam).
	 *
	 * @return array De bevindingen.
	 */
	public static function run_and_maybe_notify() {
		$findings = self::scan();

		update_option( self::OPTION_RESULTS, [
			'timestamp' => time(),
			'findings'  => $findings,
		] );

		// Alleen HIGH/MEDIUM zijn mail-waardig — LOW is informatief en blijft
		// in de admin-tabel staan.
		$mailable = array_values( array_filter( $findings, function ( $f ) {
			return in_array( $f['severity'], [ 'high', 'medium' ], true );
		} ) );

		if ( empty( $mailable ) ) {
			delete_option( self::OPTION_LAST_MAIL_HASH );
			return $findings;
		}

		$hash = self::findings_signature( $mailable );
		$last = get_option( self::OPTION_LAST_MAIL_HASH, '' );
		if ( $hash === $last ) {
			return $findings;
		}

		self::send_findings_mail( $mailable );
		update_option( self::OPTION_LAST_MAIL_HASH, $hash );

		return $findings;
	}

	private static function findings_signature( array $findings ) {
		$keys = array_map( function ( $f ) {
			return $f['severity'] . '|' . $f['path'];
		}, $findings );
		sort( $keys );
		return md5( implode( "\n", $keys ) );
	}

	/**
	 * Mail naar de Notifier-bestemming met de lijst HIGH/MEDIUM-bevindingen.
	 */
	private static function send_findings_mail( array $findings ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}
		$count   = count( $findings );
		$subject = sprintf( 'Vreemde bestanden/mappen gevonden (%d)', $count );

		$body  = "Op deze site staan één of meer bestanden/mappen die niet bij een\n";
		$body .= "standaard WordPress-installatie horen. Dit kan onschuldig zijn,\n";
		$body .= "maar bij een hack worden vaak juist zulke vreemde items neergezet.\n\n";

		foreach ( $findings as $i => $f ) {
			$body .= sprintf( "%d. [%s] %s\n", $i + 1, strtoupper( $f['severity'] ), $f['reason'] );
			$body .= sprintf( "   Pad:           %s\n", $f['relpath'] );
			$body .= sprintf( "   Type:          %s\n", $f['is_dir'] ? 'map' : 'bestand' );
			if ( ! $f['is_dir'] ) {
				$body .= sprintf( "   Grootte:       %s bytes\n", number_format( $f['size'], 0, ',', '.' ) );
			}
			$body .= sprintf( "   Laatst gewijz: %s\n", $f['mtime'] ? wp_date( 'Y-m-d H:i', $f['mtime'] ) : '?' );
			$body .= "\n";
		}

		$body .= "----\n";
		$body .= "ACTIE: controleer elk item. Herken je het niet, ga er dan van uit\n";
		$body .= "dat het verdacht is en onderzoek de inhoud vóór je iets verwijdert.\n";
		$body .= "De plugin verwijdert NIETS automatisch.\n";

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
				'anomaly_scan_done',
				wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' )
			)
		);
		exit;
	}

	/**
	 * Handler voor de 1-klik aan/uit-toggle uit de admin-bar.
	 * Flipt de huidige effectieve status, schrijft 'm expliciet weg en
	 * (her)plant of verwijdert de cron meteen.
	 */
	public static function handle_toggle() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::ACTION_TOGGLE );

		$settings = get_option( 'mcm_security_settings', [] );
		if ( ! is_array( $settings ) ) {
			$settings = [];
		}
		$new_state = ! self::is_enabled();          // flip huidige effectieve waarde
		$settings['anomaly_scanner_enabled'] = $new_state;
		update_option( 'mcm_security_settings', $settings );

		self::maybe_schedule_cron();                // cron direct (un)schedulen

		wp_safe_redirect(
			add_query_arg(
				'mcm_status',
				$new_state ? 'anomaly_enabled' : 'anomaly_disabled',
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
