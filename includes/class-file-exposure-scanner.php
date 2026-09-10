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
 *   - Meldt nieuwe bevindingen via MCM_Notifier (admin notice + mail naar
 *     marco@mcmwebsites.nl). Geen mail bij identieke bevindingen als vorige
 *     scan — voorkomt mail-moeheid.
 *   - Verwijdert NOOIT zelf. Detectie + melding only. Verwijderen blijft een
 *     bewuste handeling van de beheerder.
 *
 * Drie scan-niveaus (elk met eigen setting), samengevoegd in één resultaat:
 *
 *   1. WEBROOT (altijd) — ABSPATH + wp-content, alleen top-level:
 *        a) Risico-bestandsnamen (regex op naam): info.php, .env, *.sql, etc.
 *        b) Elk .php-bestand waarvan de eerste 4 KB `phpinfo(` bevat.
 *
 *   2. UPLOADS (recursief) — archieven en dumps die per ongeluk in de
 *      mediabibliotheek belanden. Aanleiding: de Xel-beveiligingsscan van
 *      2026-08-17 vond op susenso.nl twee publiek downloadbare premium
 *      plugin-zips in wp-content/uploads/2023/01/ (staan er sinds juli 2024).
 *      Niveau 1 kon die per definitie niet zien: uploads werd niet gescand en
 *      een archief matchte alleen als het 'backup*' of 'db*' heette.
 *      Per bevinding wordt gecheckt of de map een deny-.htaccess heeft — een
 *      afgeschermd backup-mapje (zoals onze eigen mcm-security-backups) is
 *      géén lek en zakt naar LOW.
 *
 *   3. BOVEN DE WEBROOT — dirname( ABSPATH ), alleen dat ene niveau, alleen
 *      bestanden. Niet publiek bereikbaar, dus standaard LOW: dit is de
 *      "achtergelaten rommel"-check (losse .bak/.tar.gz/scripts van eerder
 *      werk). Uitzondering: een wp-config-kopie is HIGH, want die bevat
 *      DB-credentials en salts, publiek bereikbaar of niet.
 *
 * Severity-tiers, gelijk aan de anomalie-scanner:
 *   HIGH   = publiek bereikbare dump/dataleak of een wp-config-kopie
 *   MEDIUM = publiek bereikbaar archief
 *   LOW    = afgeschermd, of boven de webroot (alleen rommel)
 * Mail gaat alleen bij HIGH/MEDIUM; LOW staat alleen in de admin-tabel.
 *
 * Settings (in mcm_security_settings):
 *   - 'exposure_scanner_enabled'      bool  default true   (cron + UI actief)
 *   - 'exposure_scan_uploads'         bool  default true   (niveau 2)
 *   - 'exposure_scan_above_root'      bool  default true   (niveau 3)
 *   - 'block_risky_files_via_htaccess' bool default false  (extra .htaccess-block)
 *   - 'block_archives_in_uploads'     bool  default false  (.htaccess: 403 op
 *                                                           archieven in uploads)
 *
 * Filters:
 *   - mcm_exposure_archive_regex      — welke extensies gelden als archief/dump
 *   - mcm_exposure_uploads_skip_dirs  — mapnamen die de uploads-scan overslaat
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
	const MAX_FILES_PER_DIR     = 500;   // perf-cap per directory (niveau 1)
	const PHPINFO_READ_BYTES    = 4096;  // eerste 4 KB van een .php-file lezen

	// Caps voor de recursieve uploads-scan (niveau 2). Bij het bereiken van een
	// cap stopt de scan en wordt vastgelegd WELKE cap dat was, zodat de admin
	// ziet dat het beeld incompleet is — stil afkappen zou "niets gevonden"
	// suggereren.
	//
	// De tijdslimiet is de echte beveiliging, niet de bestandsteller: op een
	// snelle server is een grote mediabibliotheek geen probleem (susenso.nl
	// loopt 250.000 bestanden af in 1,2 sec), maar op trage of netwerk-opslag
	// kan dezelfde hoeveelheid minuten kosten.
	//
	// De bestandsteller staat daarom hoog: hij is een noodrem tegen een
	// oneindige lus (symlink-cyclus), geen normale grens. Bij het bouwen bleek
	// susenso 293.000 bestanden in uploads te hebben — een teller van 25.000
	// of 250.000 kapte die scan af terwijl er ruim tijd over was, en dat
	// leverde stilzwijgend een incompleet beeld op.
	const MAX_UPLOADS_FILES     = 1000000;
	const MAX_UPLOADS_SECONDS   = 20;
	const MAX_UPLOADS_DEPTH     = 8;

	/**
	 * Meta over de laatste scan-run: welke niveaus liepen, of de uploads-cap
	 * is geraakt, of de map boven de webroot leesbaar was. Wordt opgeslagen
	 * bij het resultaat zodat de admin-tabel eerlijk kan zeggen "incompleet"
	 * in plaats van "geen bevindingen".
	 *
	 * @var array
	 */
	private static $scan_meta = [];

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
		// Backward-compat: oudere sites missen de key nog in DB. Val terug op
		// de plugin-default zodat de cron toch start zonder dat de admin
		// eerst handmatig opslaat na update.
		if ( ! array_key_exists( 'exposure_scanner_enabled', $settings ) ) {
			$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
				? MCM_Security_Hardener::get_defaults()
				: [];
			$enabled  = ! empty( $defaults['exposure_scanner_enabled'] );
		} else {
			$enabled = ! empty( $settings['exposure_scanner_enabled'] );
		}
		$next = wp_next_scheduled( self::CRON_HOOK );

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
	 * Archief- en dump-extensies. Gebruikt voor niveau 2 (uploads) en
	 * niveau 3 (boven de webroot) — daar kijken we niet naar specifieke
	 * bestandsnamen maar naar het TYPE bestand, want de naam van een
	 * achtergelaten zip is niet te voorspellen.
	 *
	 * @return string Case-insensitive regex op de bestandsnaam.
	 */
	public static function archive_regex() {
		$regex = '/\.(zip|rar|7z|tar|tgz|tar\.gz|gz|bz2|sql|sql\.gz|bak|old|sav)$/i';
		return (string) apply_filters( 'mcm_exposure_archive_regex', $regex );
	}

	/**
	 * Is dit een kopie van wp-config.php? Die lekt DB-credentials en salts,
	 * dus die weegt zwaarder dan een willekeurig archief — ook boven de
	 * webroot, waar hij niet publiek bereikbaar is.
	 */
	public static function is_wpconfig_copy( $filename ) {
		return (bool) preg_match( '/^wp-config.*\.(bak|save|old|orig|tmp|txt|php~)$/i', $filename )
			|| (bool) preg_match( '/^wp-config\.php~$/', $filename )
			|| (bool) preg_match( '/^wp-config.*(backup|safety|copy|kopie).*$/i', $filename );
	}

	/**
	 * Mapnamen die de uploads-scan overslaat.
	 *
	 * Bewust kort: hoe minder we overslaan, hoe meer we vinden. Alleen mappen
	 * die óf puur cache zijn (ruis + traag), óf waar archieven legitiem staan
	 * én door de betreffende plugin zelf worden afgeschermd:
	 *
	 *   - woocommerce_uploads : downloadbare producten; Woo regelt de
	 *                           afscherming en serveert via een PHP-handler.
	 *                           Zou anders bij elke shop vals alarm geven.
	 *   - cache-mappen        : duizenden bestanden, geen archieven.
	 *
	 * Backup-mappen van plugins (wpvivid, wp-migrate-db) staan er NIET tussen:
	 * die scannen we juist, en de deny-.htaccess-check bepaalt of het een lek
	 * is of niet.
	 *
	 * @return string[] Lowercase mapnamen.
	 */
	public static function uploads_skip_dirs() {
		$dirs = [
			'woocommerce_uploads',
			'cache',
			'et-cache',
			'w3tc-cache',
			'wp-rocket-config',
			'fusion-styles',
			'smush-webp',
			'webp-express',
		];
		$dirs = apply_filters( 'mcm_exposure_uploads_skip_dirs', $dirs );
		return array_map( 'strtolower', (array) $dirs );
	}

	/**
	 * Heeft deze map (of een map erboven, tot aan uploads) een .htaccess die
	 * directe toegang weigert? Zo ja, dan is een archief daarin geen publiek
	 * lek maar een correct afgeschermde backup.
	 *
	 * Dit is de reden dat onze eigen mcm-security-backups-map niet als lek
	 * wordt gemeld: die schrijft zelf een 'Require all denied'-.htaccess
	 * (op susenso.nl geverifieerd: die URL geeft een 403).
	 *
	 * Apache past de DICHTSTBIJZIJNDE .htaccess toe, en een map kan een deny
	 * van hogerop expliciet terugdraaien. Bij het bouwen bleek MainWP dat te
	 * doen: uploads/mainwp/0/.htaccess zegt 'deny from all', maar
	 * uploads/mainwp/0/favorites/.htaccess zegt 'Order allow,deny / Allow from
	 * all' — en die zips zijn dus wél downloadbaar (HTTP 206 geverifieerd).
	 * Een eerdere versie liep gewoon omhoog tot hij een deny vond en zette 48
	 * publiek downloadbare premium-zips daardoor op LOW: geen mail, valse rust.
	 *
	 * Daarom stopt de wandeling bij de eerste .htaccess die iets over toegang
	 * zegt, en telt een blanket allow als NIET afgeschermd.
	 *
	 * Let op: dit zegt niets op nginx (waar .htaccess wordt genegeerd) en niets
	 * als de host AllowOverride heeft uitgezet.
	 *
	 * @param string $dir       Absolute map.
	 * @param string $stop_at   Absolute map waar we stoppen met omhoog lopen.
	 * @return bool
	 */
	private static function dir_is_protected( $dir, $stop_at ) {
		static $cache = [];

		$dir     = untrailingslashit( $dir );
		$stop_at = untrailingslashit( $stop_at );

		if ( isset( $cache[ $dir ] ) ) {
			return $cache[ $dir ];
		}

		$protected = false;
		$current   = $dir;
		$guard     = 0;

		while ( $current && $guard < self::MAX_UPLOADS_DEPTH + 2 ) {
			$guard++;
			$htaccess = $current . '/.htaccess';
			if ( is_readable( $htaccess ) ) {
				$verdict = self::htaccess_access_verdict(
					(string) @file_get_contents( $htaccess, false, null, 0, 4096 )
				);
				if ( 'deny' === $verdict ) {
					$protected = true;
					break;
				}
				if ( 'allow' === $verdict ) {
					$protected = false;
					break;
				}
				// 'none' — deze .htaccess zegt niets over toegang tot de hele
				// map (bv. alleen Options -Indexes, of een <Files>-regel voor
				// één bestand). Verder omhoog kijken.
			}
			if ( $current === $stop_at ) {
				break;
			}
			$parent = dirname( $current );
			if ( $parent === $current ) {
				break;
			}
			$current = $parent;
		}

		$cache[ $dir ] = $protected;
		return $protected;
	}

	/**
	 * Is dit specifieke BESTAND geblokkeerd via .htaccess?
	 *
	 * Twee vormen, in deze volgorde:
	 *   1. De hele map is afgeschermd (blanket deny) — dir_is_protected().
	 *   2. Een scoped regel noemt dit bestand: <Files "debug.log"> of
	 *      <FilesMatch "\.(log|txt)$"> met een deny erin.
	 *
	 * Vorm 2 is nodig omdat de plugin zijn eigen hardening zo schrijft. Zonder
	 * deze check bleef de scanner een debug.log in de webroot elke week als
	 * HIGH melden terwijl onze eigen .htaccess-regel hem al met 403 weigerde —
	 * mail over een probleem dat al opgelost is.
	 *
	 * Wat we NIET nabouwen: mod_rewrite-regels met [F]. Die staan er ook
	 * (block_php_in_uploads bijvoorbeeld), maar het volledig evalueren van
	 * RewriteCond-ketens is geen scanner-werk. Gevolg is hoogstens een melding
	 * die strenger is dan de werkelijkheid, niet omgekeerd.
	 *
	 * @param string $path    Absoluut pad naar het bestand.
	 * @param string $stop_at Map waar we stoppen met omhoog lopen.
	 * @return bool
	 */
	private static function file_is_blocked_by_htaccess( $path, $stop_at ) {
		$dir      = dirname( $path );
		$filename = basename( $path );

		if ( self::dir_is_protected( $dir, $stop_at ) ) {
			return true;
		}

		$current = untrailingslashit( $dir );
		$stop_at = untrailingslashit( $stop_at );
		$guard   = 0;

		while ( $current && $guard < self::MAX_UPLOADS_DEPTH + 2 ) {
			$guard++;
			$htaccess = $current . '/.htaccess';
			if ( is_readable( $htaccess ) ) {
				$contents = (string) @file_get_contents( $htaccess, false, null, 0, 16384 );
				if ( self::htaccess_blocks_filename( $contents, $filename ) ) {
					return true;
				}
			}
			if ( $current === $stop_at ) {
				break;
			}
			$parent = dirname( $current );
			if ( $parent === $current ) {
				break;
			}
			$current = $parent;
		}

		return false;
	}

	/**
	 * Noemt een <Files>/<FilesMatch>-blok met een deny erin deze bestandsnaam?
	 */
	private static function htaccess_blocks_filename( $contents, $filename ) {
		if ( '' === trim( $contents ) ) {
			return false;
		}

		if ( ! preg_match_all(
			'#<\s*(Files|FilesMatch)\s+([^>]+)>(.*?)<\s*/\s*\1\s*>#is',
			$contents,
			$matches,
			PREG_SET_ORDER
		) ) {
			return false;
		}

		foreach ( $matches as $m ) {
			$tag     = strtolower( $m[1] );
			$pattern = trim( $m[2] );
			$body    = $m[3];

			// Alleen blokken die daadwerkelijk weigeren.
			if ( ! preg_match( '/^\s*(Require\s+all\s+denied|Deny\s+from\s+all)\s*$/im', $body ) ) {
				continue;
			}

			$pattern = trim( $pattern, "\"'" );
			if ( '' === $pattern ) {
				continue;
			}

			if ( 'filesmatch' === $tag ) {
				// Apache-regex → PCRE. Alleen als de regex geldig is; een
				// onbruikbaar patroon mag geen PHP-warning opleveren.
				$regex = '#' . str_replace( '#', '\#', $pattern ) . '#i';
				if ( false !== @preg_match( $regex, '' ) && @preg_match( $regex, $filename ) ) {
					return true;
				}
				continue;
			}

			// <Files> gebruikt shell-achtige wildcards (* en ?), of een
			// letterlijke naam.
			if ( false !== strpos( $pattern, '*' ) || false !== strpos( $pattern, '?' ) ) {
				// fnmatch() ontbreekt op sommige platforms (o.a. Windows).
				if ( function_exists( 'fnmatch' ) && fnmatch( $pattern, $filename, FNM_CASEFOLD ) ) {
					return true;
				}
				continue;
			}

			if ( 0 === strcasecmp( $pattern, $filename ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Wat zegt deze .htaccess over toegang tot de HELE map?
	 *
	 * Scoped blokken (<Files>, <FilesMatch>, <Limit>) worden eerst gestript:
	 * die zeggen alleen iets over specifieke bestanden. De uploads-.htaccess
	 * van MC4WP bijvoorbeeld weigert alleen mc4wp-debug-log.php — dat maakt de
	 * map niet afgeschermd.
	 *
	 * @return string 'deny' | 'allow' | 'none'
	 */
	private static function htaccess_access_verdict( $contents ) {
		if ( '' === trim( $contents ) ) {
			return 'none';
		}

		// Scoped blokken weghalen (incl. hun inhoud). <IfModule> blijft staan:
		// daarin zit juist vaak de blanket deny.
		$stripped = preg_replace(
			'#<\s*(Files|FilesMatch|Limit|LimitExcept|Directory)\b.*?<\s*/\s*\1\s*>#is',
			'',
			$contents
		);
		if ( null === $stripped ) {
			$stripped = $contents; // preg-fout (bv. te grote backtrack) — val terug.
		}

		// 'Deny from all' / 'Require all denied' als losstaande directive.
		// Let op: 'Order allow,deny' is géén Deny-directive — het woord 'deny'
		// is daar een argument. Vandaar de regel-anchors.
		if ( preg_match( '/^\s*(Require\s+all\s+denied|Deny\s+from\s+all)\s*$/im', $stripped ) ) {
			return 'deny';
		}

		if ( preg_match( '/^\s*(Require\s+all\s+granted|Allow\s+from\s+all)\s*$/im', $stripped ) ) {
			return 'allow';
		}

		return 'none';
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
	 * Voer een scan uit over alle ingeschakelde niveaus en retourneer de
	 * bevindingen.
	 *
	 * @return array<int,array{type:string,reason:string,severity:string,location:string,path:string,relpath:string,size:int,mtime:int,public_guess:bool}>
	 */
	public static function scan() {
		self::$scan_meta = [
			'uploads_scanned'     => false,
			'uploads_files_seen'  => 0,
			'uploads_capped'      => false,
			'uploads_cap_reason'  => '',
			'above_root_scanned'  => false,
			'above_root_readable' => null,
			'above_root_path'     => '',
		];

		$findings = self::scan_webroot();

		if ( self::setting_bool( 'exposure_scan_uploads' ) ) {
			$findings = array_merge( $findings, self::scan_uploads() );
		}

		if ( self::setting_bool( 'exposure_scan_above_root' ) ) {
			$findings = array_merge( $findings, self::scan_above_root() );
		}

		// Deduplicate op PAD, niet op type+pad: één bestand kan op meerdere
		// checks hitten (info.php matcht op naam én op de phpinfo()-inhoud) en
		// dat leverde twee regels voor hetzelfde bestand op — en een te hoge
		// telling in de mail. Redenen worden samengevoegd, de zwaarste
		// severity wint.
		$rank   = [ 'high' => 0, 'medium' => 1, 'low' => 2 ];
		$unique = [];
		foreach ( $findings as $f ) {
			$key = $f['path'];

			if ( ! isset( $unique[ $key ] ) ) {
				$unique[ $key ] = $f;
				continue;
			}

			$existing = $unique[ $key ];

			if ( false === strpos( $existing['reason'], $f['reason'] ) ) {
				$unique[ $key ]['reason'] = $existing['reason'] . ' + ' . $f['reason'];
			}

			$r_new = isset( $rank[ $f['severity'] ] ) ? $rank[ $f['severity'] ] : 3;
			$r_old = isset( $rank[ $existing['severity'] ] ) ? $rank[ $existing['severity'] ] : 3;
			if ( $r_new < $r_old ) {
				$unique[ $key ]['severity'] = $f['severity'];
				$unique[ $key ]['type']     = $f['type'];
			}
		}
		$unique = array_values( $unique );

		// Zwaarste bevindingen bovenaan.
		usort( $unique, function ( $a, $b ) {
			$rank = [ 'high' => 0, 'medium' => 1, 'low' => 2 ];
			$ra   = isset( $rank[ $a['severity'] ] ) ? $rank[ $a['severity'] ] : 3;
			$rb   = isset( $rank[ $b['severity'] ] ) ? $rank[ $b['severity'] ] : 3;
			if ( $ra === $rb ) {
				return strcmp( $a['relpath'], $b['relpath'] );
			}
			return $ra < $rb ? -1 : 1;
		} );

		// Als "veilig" gemarkeerde bevindingen (MCM_Finding_Ignore) blijven
		// permanent buiten beeld, ook uit de mail — zie class-finding-ignore.php.
		if ( class_exists( 'MCM_Finding_Ignore' ) ) {
			$unique = MCM_Finding_Ignore::filter( 'exposure', $unique );
		}

		return $unique;
	}

	/**
	 * Niveau 1 — webroot + wp-content, alleen top-level.
	 *
	 * @return array
	 */
	private static function scan_webroot() {
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

		// Bevindingen die al door een .htaccess-regel worden geweigerd zakken
		// naar LOW. Zonder deze stap blijft de scanner wekelijks HIGH mailen
		// over een bestand dat allang 403 geeft — bijvoorbeeld een debug.log
		// die door onze eigen block_log_txt_files-regel wordt geblokkeerd.
		foreach ( $findings as $i => $f ) {
			if ( ! is_file( $f['path'] ) ) {
				continue;
			}
			if ( ! self::file_is_blocked_by_htaccess( $f['path'], $abspath ) ) {
				continue;
			}
			$findings[ $i ]['severity']     = 'low';
			$findings[ $i ]['public_guess'] = false;
			$findings[ $i ]['reason']      .= ' — geblokkeerd via .htaccess';
		}

		return $findings;
	}

	/**
	 * Niveau 2 — uploads recursief op archieven en dumps.
	 *
	 * Dit is de check die de twee premium plugin-zips op susenso.nl had
	 * gevonden: publiek downloadbare archieven, jaren onaangeroerd, in een
	 * gewone jaar/maand-map van de mediabibliotheek.
	 *
	 * @return array
	 */
	private static function scan_uploads() {
		$uploads = wp_get_upload_dir();
		if ( empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
			return [];
		}

		$basedir = untrailingslashit( $uploads['basedir'] );
		$abspath = untrailingslashit( ABSPATH );
		$regex   = self::archive_regex();
		$skip    = self::uploads_skip_dirs();

		self::$scan_meta['uploads_scanned'] = true;

		$findings = [];
		$seen     = 0;
		$capped   = false;
		$deadline = microtime( true ) + self::MAX_UPLOADS_SECONDS;

		// Iteratieve breedte-eerst walk. Bewust geen RecursiveIteratorIterator:
		// die gooit bij een onleesbare submap een exception midden in de scan,
		// en we willen juist zoveel mogelijk doorlopen.
		$queue = [ [ $basedir, 0 ] ];

		while ( $queue ) {
			list( $dir, $depth ) = array_shift( $queue );

			// Tijdslimiet per map controleren i.p.v. per bestand: microtime()
			// per bestand zou op 250.000 bestanden zelf overhead worden.
			if ( microtime( true ) > $deadline ) {
				$capped = 'time';
				break;
			}

			$entries = @scandir( $dir );
			if ( ! is_array( $entries ) ) {
				continue;
			}

			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}

				$path = $dir . '/' . $entry;

				if ( is_dir( $path ) ) {
					if ( in_array( strtolower( $entry ), $skip, true ) ) {
						continue;
					}
					if ( $depth < self::MAX_UPLOADS_DEPTH ) {
						$queue[] = [ $path, $depth + 1 ];
					}
					continue;
				}

				$seen++;
				if ( $seen > self::MAX_UPLOADS_FILES ) {
					$capped = 'files';
					break 2;
				}

				if ( ! preg_match( $regex, $entry ) ) {
					continue;
				}

				$protected = self::dir_is_protected( $dir, $basedir );
				$is_dump   = (bool) preg_match( '/\.(sql|sql\.gz)$/i', $entry );

				if ( $protected ) {
					$severity = 'low';
					$reason   = $is_dump
						? 'Database-dump in uploads (map is afgeschermd)'
						: 'Archiefbestand in uploads (map is afgeschermd)';
				} else {
					$severity = $is_dump ? 'high' : 'medium';
					$reason   = $is_dump
						? 'Database-dump publiek downloadbaar in uploads'
						: 'Archiefbestand publiek downloadbaar in uploads';
				}

				$finding                 = self::build_finding( 'archive_in_uploads', $reason, $path, $abspath, $severity, 'uploads' );
				$finding['public_guess'] = ! $protected;
				$findings[]              = $finding;
			}
		}

		self::$scan_meta['uploads_files_seen'] = $seen;
		self::$scan_meta['uploads_capped']     = (bool) $capped;
		self::$scan_meta['uploads_cap_reason'] = $capped ? $capped : '';

		return $findings;
	}

	/**
	 * Niveau 3 — één niveau boven de webroot, alleen bestanden.
	 *
	 * Op Xel is de webroot ~/<domein>/ en is de map erboven de home-dir van de
	 * hostingaccount. Daar belandt in de praktijk het werkmateriaal: losse
	 * .bak-kopieën, tar.gz-archieven, migratie-scripts, wp-config-kopieën.
	 * Niet publiek bereikbaar (geen docroot), dus standaard LOW — behalve een
	 * wp-config-kopie, want die bevat credentials en salts.
	 *
	 * @return array
	 */
	private static function scan_above_root() {
		$abspath = untrailingslashit( ABSPATH );
		$parent  = dirname( $abspath );

		// Geen zinnige parent (webroot is filesystem-root, of chroot).
		if ( ! $parent || $parent === $abspath || '.' === $parent ) {
			return [];
		}

		self::$scan_meta['above_root_scanned'] = true;
		self::$scan_meta['above_root_path']    = $parent;

		// open_basedir kan het lezen van de parent blokkeren. Dat expliciet
		// vastleggen: een lege uitslag mag niet als "schoon" worden gelezen.
		if ( ! is_dir( $parent ) || ! is_readable( $parent ) ) {
			self::$scan_meta['above_root_readable'] = false;
			return [];
		}

		$entries = @scandir( $parent );
		if ( ! is_array( $entries ) ) {
			self::$scan_meta['above_root_readable'] = false;
			return [];
		}

		self::$scan_meta['above_root_readable'] = true;

		$regex    = self::archive_regex();
		$findings = [];
		$count    = 0;

		foreach ( $entries as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			// Dotfiles overslaan: .bash_history, .ssh, .cache — dat is de
			// normale inrichting van een home-dir, geen achtergelaten rommel.
			if ( 0 === strpos( $entry, '.' ) ) {
				continue;
			}

			$path = $parent . '/' . $entry;
			if ( ! is_file( $path ) ) {
				continue; // Mappen boven de webroot zijn normaal (andere sites).
			}

			$count++;
			if ( $count > self::MAX_FILES_PER_DIR ) {
				break;
			}

			if ( self::is_wpconfig_copy( $entry ) ) {
				$severity = 'high';
				$reason   = 'wp-config-kopie boven de webroot (bevat DB-credentials + salts)';
			} elseif ( preg_match( $regex, $entry ) ) {
				$severity = 'low';
				$reason   = 'Archief/backup boven de webroot (niet publiek, wel rommel)';
			} elseif ( preg_match( '/\.php$/i', $entry ) ) {
				$severity = 'low';
				$reason   = 'Los PHP-script boven de webroot (niet publiek, wel rommel)';
			} else {
				continue;
			}

			$finding                 = self::build_finding( 'above_webroot', $reason, $path, $abspath, $severity, 'above_root' );
			$finding['public_guess'] = false;
			$findings[]              = $finding;
		}

		return $findings;
	}

	/**
	 * Setting uitlezen met terugval op de plugin-default.
	 *
	 * Nodig omdat sites die van een oudere versie updaten de nieuwe keys nog
	 * niet in de DB hebben staan: zonder terugval zou een nieuwe scan-laag
	 * uit blijven staan tot iemand handmatig opslaat.
	 */
	private static function setting_bool( $key ) {
		$settings = get_option( 'mcm_security_settings', [] );
		if ( array_key_exists( $key, (array) $settings ) ) {
			return ! empty( $settings[ $key ] );
		}
		$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
			? MCM_Security_Hardener::get_defaults()
			: [];
		return ! empty( $defaults[ $key ] );
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
	 *
	 * @param string $severity high|medium|low — default 'high' zodat de
	 *                         bestaande webroot-checks hun oude gedrag
	 *                         (altijd mailen) houden.
	 * @param string $location webroot|uploads|above_root
	 */
	private static function build_finding( $type, $reason, $path, $abspath, $severity = 'high', $location = 'webroot' ) {
		$rel = ltrim( str_replace( $abspath, '', $path ), '/\\' );

		// Boven de webroot levert str_replace() geen relatief pad op (het pad
		// zit niet ónder ABSPATH). Daar is "../<bestand>" leesbaarder dan het
		// volledige serverpad.
		if ( 'above_root' === $location ) {
			$rel = '../' . basename( $path );
		}

		return [
			'type'         => $type,
			'reason'       => $reason,
			'severity'     => $severity,
			'location'     => $location,
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
			'wp-content/uploads/mcm-nepaccount-logs/',
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
		// Backward-compat fallback (zie maybe_schedule_cron).
		if ( ! array_key_exists( 'exposure_scanner_enabled', $settings ) ) {
			$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
				? MCM_Security_Hardener::get_defaults()
				: [];
			$enabled = ! empty( $defaults['exposure_scanner_enabled'] );
		} else {
			$enabled = ! empty( $settings['exposure_scanner_enabled'] );
		}
		if ( ! $enabled ) {
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
			'meta'      => self::$scan_meta,
		] );

		// Alleen HIGH/MEDIUM mailen. LOW (afgeschermde archieven, rommel boven
		// de webroot) staat alleen in de admin-tabel — anders krijg je een mail
		// over elk .bak-bestand dat je zelf net hebt neergezet.
		$mailable = array_values( array_filter( $findings, function ( $f ) {
			$severity = isset( $f['severity'] ) ? $f['severity'] : 'high';
			return in_array( $severity, [ 'high', 'medium' ], true );
		} ) );

		if ( empty( $mailable ) ) {
			// Niets mailwaardigs — reset hash zodat een volgende detectie
			// (na bv. een week schoon) wél weer een mail triggert.
			delete_option( self::OPTION_LAST_MAIL_HASH );
			return $findings;
		}

		// Hash van bevindingen vergelijken met vorige mail.
		$hash = self::findings_signature( $mailable );
		$last = get_option( self::OPTION_LAST_MAIL_HASH, '' );
		if ( $hash === $last ) {
			// Zelfde set bevindingen als vorige mail — geen herhaling.
			return $findings;
		}

		self::send_findings_mail( $mailable );
		update_option( self::OPTION_LAST_MAIL_HASH, $hash );

		return $findings;
	}

	private static function findings_signature( array $findings ) {
		$keys = array_map( function ( $f ) {
			$severity = isset( $f['severity'] ) ? $f['severity'] : 'high';
			return $severity . '|' . $f['type'] . '|' . $f['path'];
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
			$severity = isset( $f['severity'] ) ? strtoupper( $f['severity'] ) : 'HIGH';
			$body    .= sprintf( "%d. [%s] %s\n", $i + 1, $severity, $f['reason'] );
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
	 * @return array{timestamp:int,findings:array,meta:array}|null
	 */
	public static function get_last_results() {
		$saved = get_option( self::OPTION_RESULTS, null );
		if ( ! is_array( $saved ) || ! isset( $saved['findings'] ) ) {
			return null;
		}
		if ( ! isset( $saved['meta'] ) || ! is_array( $saved['meta'] ) ) {
			$saved['meta'] = []; // Resultaat van vóór 1.21.0.
		}
		return $saved;
	}

	/**
	 * Labels voor de scan-niveaus, voor weergave in admin en mail.
	 *
	 * @return array<string,string>
	 */
	public static function location_labels() {
		return [
			'webroot'    => 'webroot',
			'uploads'    => 'uploads',
			'above_root' => 'boven webroot',
		];
	}
}
