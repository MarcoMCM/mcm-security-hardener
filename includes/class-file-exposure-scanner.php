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
 * Vier scan-niveaus (elk met eigen setting), samengevoegd in één resultaat:
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
 *   4. BACK-UPMAPPEN IN WP-CONTENT (recursief) — archieven in de mappen die
 *      back-upplugins direct in wp-content aanmaken (wpvividbackups, updraft,
 *      ai1wm-backups, …) plus elke andere map daar met "backup" in de naam.
 *      Aanleiding: op pensioenfonds-sagittarius.nl (2026-10-04) gaf
 *      wp-content/wpvividbackups/rollback/plugins/<slug>/<versie>/<slug>.zip
 *      200 application/zip: 262 MB oude plugin-versies, ook betaalde. Geen
 *      enkel niveau keek daar. Een publiek back-uparchief is HIGH (bevat
 *      meestal database en wp-config), behalve WPvivid's rollback/ (alleen
 *      plugin-/themacode): MEDIUM.
 *
 * Bereikbaar of niet — in twee stappen:
 *   a) .htaccess: een deny-.htaccess telt als afscherming, maar ALLEEN op
 *      Apache/LiteSpeed. Op nginx (en andere servers) wordt .htaccess
 *      genegeerd en zakt er niets meer naar LOW. De webserver komt uit
 *      SERVER_SOFTWARE; buiten een webrequest (WP-CLI, systeem-cron) uit de
 *      laatst geziene waarde.
 *   b) HTTP-controle: per groep bestanden die hetzelfde antwoord moeten geven
 *      één HEAD-verzoek (alleen kopregels, er wordt niets gedownload). Dat
 *      antwoord wint van stap a: 200 = publiek, 401/403/404/410 = niet. Nooit
 *      op PHP-bestanden (een HEAD-verzoek voert het script uit), en alleen
 *      als een controleverzoek naar een vast core-bestand 200 geeft — anders
 *      zou een 403 van een firewall als "afgeschermd" gelezen worden.
 *   Het vinden van bestanden blijft via het bestandssysteem (zie boven over
 *   Varnish); HTTP zegt alleen of een bestand dat op disk staat ook
 *   opvraagbaar is.
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
 *   - 'exposure_scan_backup_dirs'     bool  default true   (niveau 4)
 *   - 'block_risky_files_via_htaccess' bool default false  (extra .htaccess-block)
 *   - 'block_archives_in_uploads'     bool  default false  (.htaccess: 403 op
 *                                                           archieven in uploads)
 *
 * Filters:
 *   - mcm_exposure_archive_regex      — welke extensies gelden als archief/dump
 *   - mcm_exposure_uploads_skip_dirs  — mapnamen die de uploads-scan overslaat
 *   - mcm_exposure_backup_dirs        — bekende back-upmappen in wp-content
 *   - mcm_exposure_http_probe         — false zet de HTTP-controle uit
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

	// Niveau 4 (back-upmappen in wp-content). Meestal een paar honderd
	// bestanden; de tijdslimiet is een noodrem voor trage opslag.
	const MAX_BACKUP_DIRS_SECONDS = 10;

	// HTTP-controle. Eén verzoek per groep, dus 10 is ruim; het budget
	// (inclusief het controleverzoek) voorkomt dat een trage loopback de
	// cron-run opblaast.
	//
	// Slechtste geval voor de hele scan: 20 sec uploads + 10 sec back-upmappen
	// + 15 sec HTTP. Normaal is het samen ruim onder de seconde. Die tijd is
	// vrijwel helemaal wachten op disk en netwerk, en dat telt op Linux niet
	// mee voor max_execution_time (zie de PHP-handleiding bij
	// set_time_limit()); een wandklok-limiet zoals request_terminate_timeout
	// van PHP-FPM wel.
	const MAX_PROBES           = 10;
	const PROBE_TIMEOUT        = 5;
	const PROBE_BUDGET_SECONDS = 15;

	// Laatst geziene SERVER_SOFTWARE, voor scans buiten een webrequest om.
	const OPTION_SERVER = 'mcm_exposure_server_software';

	/**
	 * Telt een deny-.htaccess als afscherming tijdens deze scan? Alleen op
	 * Apache/LiteSpeed — zie server_honors_htaccess().
	 *
	 * @var bool
	 */
	private static $htaccess_counts = true;

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

		// Webserver onthouden voor scans die via WP-CLI of een systeem-cron
		// lopen: daar is SERVER_SOFTWARE leeg.
		add_action( 'admin_init', [ __CLASS__, 'remember_server_software' ] );
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
			// Schrijft deze plugin zelf weg (wpconfig-manager, db-prefix-manager).
			// Op een lokale Apache-kopie gaf een HEAD 200 met de volle grootte.
			'/^wp-config\.php\.mcm-backup$/i'                => 'wp-config-backup van MCM Security (bevat DB-credentials + salts)',
			'/\.sql(\.gz)?$/i'                               => 'SQL-dump',
			'/^dump.*\.sql$/i'                               => 'Database-dump',
			'/^backup.*\.(zip|tar\.gz|tgz)$/i'               => 'Backup-archief in webroot',
			'/^db.*\.(zip|sql|tar\.gz)$/i'                   => 'Database-backup in webroot',
			'/^debug\.log$/i'                                => 'WP debug.log in webroot',
		];
	}

	/**
	 * Archief- en dump-extensies. Gebruikt voor niveau 2 (uploads), 3 (boven
	 * de webroot) en 4 (back-upmappen) — daar kijken we niet naar specifieke
	 * bestandsnamen maar naar het TYPE bestand, want de naam van een
	 * achtergelaten zip is niet te voorspellen.
	 *
	 * wpress = All-in-One WP Migration, daf = Duplicator (beide volledige
	 * site-back-ups, inclusief database).
	 *
	 * @return string Case-insensitive regex op de bestandsnaam.
	 */
	public static function archive_regex() {
		$regex = '/\.(zip|rar|7z|tar|tgz|tar\.gz|gz|bz2|sql|sql\.gz|bak|old|sav|wpress|daf)$/i';
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
	 * Back-upmappen direct in wp-content die op deze site bestaan.
	 *
	 * Een vaste lijst bekende mappen, plus elke andere map in wp-content met
	 * "backup" in de naam: BackWPup (backwpup-<hash>-backups), een handmatig
	 * aangemaakte backups/, enz. Back-upmappen ín uploads (wp-migrate-db,
	 * mainwp, backwpup op nieuwere versies) vallen onder niveau 2.
	 *
	 * @return array<string,string> mapnaam => plugin (voor de melding)
	 */
	public static function backup_dirs() {
		$known = apply_filters( 'mcm_exposure_backup_dirs', [
			'wpvividbackups'   => 'WPvivid',
			'wpvivid_uploads'  => 'WPvivid',
			'updraft'          => 'UpdraftPlus',
			'ai1wm-backups'    => 'All-in-One WP Migration',
			'backups-dup-lite' => 'Duplicator',
			'backups-dup-pro'  => 'Duplicator Pro',
			'backup-guard'     => 'BackupGuard',
			'envato-backups'   => 'Envato Market',
		] );

		$content = untrailingslashit( WP_CONTENT_DIR );
		$dirs    = [];

		foreach ( (array) $known as $name => $plugin ) {
			if ( is_dir( $content . '/' . $name ) ) {
				$dirs[ $name ] = $plugin;
			}
		}

		foreach ( self::list_dir_entries( $content ) as $entry ) {
			if ( isset( $dirs[ $entry ] ) || ! preg_match( '/backup/i', $entry ) ) {
				continue;
			}
			if ( is_dir( $content . '/' . $entry ) ) {
				$dirs[ $entry ] = 0 === stripos( $entry, 'backwpup' ) ? 'BackWPup' : 'onbekende plugin';
			}
		}

		return $dirs;
	}

	/**
	 * Bevat dit archief alleen code, geen site-data? WPvivid's rollback/ bewaart
	 * de vorige versies van plugins en thema's — een lek (licenties, bekende
	 * versies), maar zonder database of wp-config, dus MEDIUM i.p.v. HIGH.
	 *
	 * @param string $relpath Pad relatief aan wp-content.
	 */
	private static function is_code_only_backup( $relpath ) {
		return (bool) preg_match( '#^wpvividbackups/rollback/#i', $relpath );
	}

	/**
	 * SERVER_SOFTWARE van dit request, of — buiten een webrequest — de laatst
	 * geziene waarde. Leeg = onbekend.
	 */
	public static function server_software() {
		$live = self::request_server_software();
		return '' !== $live ? $live : (string) get_option( self::OPTION_SERVER, '' );
	}

	private static function request_server_software() {
		if ( empty( $_SERVER['SERVER_SOFTWARE'] ) ) {
			return '';
		}
		return substr( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ), 0, 100 );
	}

	/**
	 * admin_init: webserver vastleggen. Alleen schrijven als hij verandert.
	 */
	public static function remember_server_software() {
		$live = self::request_server_software();
		if ( '' !== $live && get_option( self::OPTION_SERVER ) !== $live ) {
			update_option( self::OPTION_SERVER, $live, true );
		}
	}

	/**
	 * Leest deze webserver .htaccess? Apache en LiteSpeed wel (net als WP's
	 * $is_apache); nginx, IIS, Caddy niet.
	 *
	 * Onbekend telt als ja: dat is het gedrag van vóór 1.32.0, en de
	 * admin-pagina zegt er dan bij dat de server niet bekend was.
	 *
	 * Let op: ook "Apache" is geen garantie. Staat er een nginx vóór die
	 * statische bestanden zelf serveert, dan komt Apache (en dus .htaccess)
	 * er voor een zip niet aan te pas. Daarvoor is de HTTP-controle.
	 */
	public static function server_honors_htaccess( $software ) {
		if ( '' === (string) $software ) {
			return true;
		}
		return (bool) preg_match( '/apache|litespeed/i', $software );
	}

	/**
	 * Korte servernaam voor in een melding: "nginx/1.26.1" → "nginx".
	 */
	private static function server_name( $software ) {
		$name = strtok( (string) $software, '/ ' );
		return false !== $name && '' !== $name ? $name : 'deze server';
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
	 * Let op: dit zegt alleen iets over wat de .htaccess-bestanden zeggen. Of
	 * de server ze leest (op nginx niet) beslist de aanroeper — zie
	 * server_honors_htaccess() en prepare_reachability().
	 *
	 * @param string $dir       Absolute map.
	 * @param string $stop_at   Absolute map waar we stoppen met omhoog lopen.
	 * @return bool
	 */
	private static function dir_is_protected( $dir, $stop_at ) {
		$scope = self::htaccess_scope( $dir, $stop_at );
		return $scope['protected'];
	}

	/**
	 * Als dir_is_protected(), maar geeft ook de map terug waarvan de .htaccess
	 * de doorslag gaf (of $stop_at als geen enkele .htaccess iets zei).
	 * Bestanden met dezelfde scope krijgen van Apache hetzelfde antwoord; de
	 * HTTP-controle hoeft dan maar één ervan op te vragen.
	 *
	 * @return array{protected:bool,scope:string}
	 */
	private static function htaccess_scope( $dir, $stop_at ) {
		static $cache = [];

		$dir     = untrailingslashit( $dir );
		$stop_at = untrailingslashit( $stop_at );

		if ( isset( $cache[ $dir ] ) ) {
			return $cache[ $dir ];
		}

		$result  = [ 'protected' => false, 'scope' => $stop_at ];
		$current = $dir;
		$guard   = 0;

		while ( $current && $guard < self::MAX_UPLOADS_DEPTH + 2 ) {
			$guard++;
			$htaccess = $current . '/.htaccess';
			if ( is_readable( $htaccess ) ) {
				$verdict = self::htaccess_access_verdict(
					(string) @file_get_contents( $htaccess, false, null, 0, 4096 )
				);
				if ( 'deny' === $verdict ) {
					$result = [ 'protected' => true, 'scope' => $current ];
					break;
				}
				if ( 'allow' === $verdict ) {
					$result = [ 'protected' => false, 'scope' => $current ];
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

		$cache[ $dir ] = $result;
		return $result;
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
		$server = self::server_software();

		self::$htaccess_counts = self::server_honors_htaccess( $server );
		self::$scan_meta       = [
			'server'              => $server,
			'uploads_scanned'     => false,
			'uploads_files_seen'  => 0,
			'uploads_capped'      => false,
			'uploads_cap_reason'  => '',
			'above_root_scanned'  => false,
			'above_root_readable' => null,
			'above_root_path'     => '',
			'backup_dirs_scanned' => false,
			'backup_dirs'         => [],
			'backup_dirs_capped'  => false,
			'probe'               => [ 'status' => 'off' ],
		];

		$findings = self::scan_webroot();

		if ( self::setting_bool( 'exposure_scan_uploads' ) ) {
			$findings = array_merge( $findings, self::scan_uploads() );
		}

		if ( self::setting_bool( 'exposure_scan_backup_dirs' ) ) {
			$findings = array_merge( $findings, self::scan_backup_dirs() );
		}

		if ( self::setting_bool( 'exposure_scan_above_root' ) ) {
			$findings = array_merge( $findings, self::scan_above_root() );
		}

		$findings = self::probe_findings( $findings );

		// Hulpvelden voor de bereikbaarheid horen niet in het opgeslagen
		// resultaat.
		foreach ( $findings as $i => $f ) {
			unset( $findings[ $i ]['_open'], $findings[ $i ]['_closed_reason'], $findings[ $i ]['_htaccess_deny'], $findings[ $i ]['_probe_group'] );
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
		// Op nginx telt die regel niet (prepare_reachability), en een losse
		// niet-PHP-file gaat langs de HTTP-controle.
		foreach ( $findings as $i => $f ) {
			$is_file = is_file( $f['path'] );

			$findings[ $i ] = self::prepare_reachability(
				$f,
				$f['severity'],
				$f['reason'],
				$f['reason'],
				$is_file && self::file_is_blocked_by_htaccess( $f['path'], $abspath ),
				$is_file && self::probe_allowed( $f['path'] ) ? 'file|' . $f['path'] : null
			);
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

		self::$scan_meta['uploads_scanned'] = true;

		$walk     = self::find_archives( $basedir, self::uploads_skip_dirs(), self::MAX_UPLOADS_SECONDS );
		$findings = [];

		foreach ( $walk['hits'] as $hit ) {
			list( $dir, $entry ) = $hit;

			$path    = $dir . '/' . $entry;
			$scope   = self::htaccess_scope( $dir, $basedir );
			$is_dump = (bool) preg_match( '/\.(sql|sql\.gz)$/i', $entry );
			$what    = $is_dump ? 'Database-dump' : 'Archiefbestand';

			$findings[] = self::prepare_reachability(
				self::build_finding( 'archive_in_uploads', '', $path, $abspath, 'medium', 'uploads' ),
				$is_dump ? 'high' : 'medium',
				$what . ' publiek downloadbaar in uploads',
				$what . ' in uploads',
				$scope['protected'],
				self::probe_allowed( $path ) ? self::probe_group( 'uploads', $basedir, $dir, $scope['scope'], $entry ) : null
			);
		}

		self::$scan_meta['uploads_files_seen'] = $walk['seen'];
		self::$scan_meta['uploads_capped']     = '' !== $walk['capped'];
		self::$scan_meta['uploads_cap_reason'] = $walk['capped'];

		return $findings;
	}

	/**
	 * Niveau 4 — back-upmappen in wp-content, recursief, alleen archieven.
	 *
	 * @return array
	 */
	private static function scan_backup_dirs() {
		$content  = untrailingslashit( WP_CONTENT_DIR );
		$abspath  = untrailingslashit( ABSPATH );
		$dirs     = self::backup_dirs();
		$deadline = microtime( true ) + self::MAX_BACKUP_DIRS_SECONDS;
		$findings = [];

		self::$scan_meta['backup_dirs_scanned'] = true;
		self::$scan_meta['backup_dirs']         = array_keys( $dirs );

		foreach ( $dirs as $name => $plugin ) {
			$remaining = $deadline - microtime( true );
			if ( $remaining <= 0 ) {
				self::$scan_meta['backup_dirs_capped'] = true;
				break;
			}

			$walk = self::find_archives( $content . '/' . $name, [], $remaining );
			if ( '' !== $walk['capped'] ) {
				self::$scan_meta['backup_dirs_capped'] = true;
			}

			foreach ( $walk['hits'] as $hit ) {
				list( $dir, $entry ) = $hit;

				$path  = $dir . '/' . $entry;
				$scope = self::htaccess_scope( $dir, $content );

				if ( self::is_code_only_backup( substr( $path, strlen( $content ) + 1 ) ) ) {
					$severity = 'medium';
					$what     = sprintf( 'Oude plugin-/themaversie (%s rollback)', $plugin );
					$open     = $what . ' publiek downloadbaar';
				} else {
					$severity = 'high';
					$what     = sprintf( 'Back-uparchief (%s)', $plugin );
					$open     = $what . ' publiek downloadbaar — bevat meestal database en wp-config';
				}

				$findings[] = self::prepare_reachability(
					self::build_finding( 'backup_dir_archive', '', $path, $abspath, $severity, 'backup_dirs' ),
					$severity,
					$open,
					$what,
					$scope['protected'],
					self::probe_allowed( $path ) ? self::probe_group( 'backup_dirs', $content, $dir, $scope['scope'], $entry ) : null
				);
			}
		}

		return $findings;
	}

	/**
	 * Loopt breedte-eerst door $basedir en geeft elk bestand terug waarvan de
	 * naam op archive_regex() matcht.
	 *
	 * Bij het bereiken van een cap stopt de walk en zegt 'capped' welke dat
	 * was ('time' of 'files'), zodat de admin ziet dat het beeld incompleet is.
	 *
	 * @param string   $basedir Absolute map.
	 * @param string[] $skip    Lowercase mapnamen om over te slaan.
	 * @param float    $seconds Tijdslimiet.
	 * @return array{hits:array<int,array{0:string,1:string}>,seen:int,capped:string}
	 */
	private static function find_archives( $basedir, array $skip, $seconds ) {
		$regex    = self::archive_regex();
		$hits     = [];
		$seen     = 0;
		$capped   = '';
		$deadline = microtime( true ) + $seconds;

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

				if ( preg_match( $regex, $entry ) ) {
					$hits[] = [ $dir, $entry ];
				}
			}
		}

		return [ 'hits' => $hits, 'seen' => $seen, 'capped' => $capped ];
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
	 * Geeft een bevinding beide mogelijke uitkomsten mee (bereikbaar / niet
	 * bereikbaar) en kiest er alvast één op basis van .htaccess. De
	 * HTTP-controle kan die keuze daarna omdraaien — zie probe_findings().
	 *
	 * @param array       $f              Uit build_finding().
	 * @param string      $open_severity  Severity als het bestand bereikbaar is.
	 * @param string      $open_reason    Reden als het bestand bereikbaar is.
	 * @param string      $closed_reason  Reden zonder "afgeschermd"-staart.
	 * @param bool        $htaccess_deny  Weigert een .htaccess dit bestand?
	 * @param string|null $probe_group    Groepssleutel voor de HTTP-controle,
	 *                                    null = niet via HTTP opvragen.
	 * @return array
	 */
	private static function prepare_reachability( array $f, $open_severity, $open_reason, $closed_reason, $htaccess_deny, $probe_group ) {
		$f['_open']          = [ $open_severity, $open_reason ];
		$f['_closed_reason'] = $closed_reason;
		$f['_htaccess_deny'] = (bool) $htaccess_deny;
		$f['_probe_group']   = $probe_group;

		return self::set_reachable( $f, ! ( $htaccess_deny && self::$htaccess_counts ), null );
	}

	/**
	 * Zet severity, reden en 'Publiek?' van een bevinding.
	 *
	 * @param array    $f         Met de velden uit prepare_reachability().
	 * @param bool     $public    Bereikbaar?
	 * @param int|null $http_code HTTP-status van de controle, null = op basis
	 *                            van .htaccess bepaald.
	 * @return array
	 */
	private static function set_reachable( array $f, $public, $http_code ) {
		if ( $public ) {
			$f['severity'] = $f['_open'][0];
			$f['reason']   = $f['_open'][1];
			if ( $f['_htaccess_deny'] ) {
				$f['reason'] .= self::$htaccess_counts
					? ' — .htaccess weigert, maar de server levert het toch'
					: ' — .htaccess-blokkade telt niet op ' . self::server_name( self::$scan_meta['server'] );
			}
		} else {
			$f['severity'] = 'low';
			$f['reason']   = $f['_closed_reason'] . ( null === $http_code
				? ' — afgeschermd via .htaccess'
				: sprintf( ' — niet bereikbaar (HTTP %d)', $http_code ) );
		}

		$f['public_guess'] = (bool) $public;
		$f['http_code']    = $http_code;

		return $f;
	}

	/**
	 * Mag dit bestand via HTTP worden opgevraagd? Niet als PHP het kan
	 * uitvoeren: ook een HEAD-verzoek draait het script, en een achtergelaten
	 * test.php kan van alles doen. Apache voert met AddHandler ook "x.php.bak"
	 * uit, vandaar ".php" óók midden in de naam. Een wp-config-kopie mag wel:
	 * in het ergste geval laadt die WordPress, net als een paginaweergave.
	 */
	private static function probe_allowed( $path ) {
		$name = basename( $path );
		if ( ! preg_match( '/\.(php\d?|phtml|phar)(\.|$)/i', $name ) ) {
			return true;
		}
		return self::is_wpconfig_copy( $name );
	}

	/**
	 * Groepssleutel voor de HTTP-controle: bestanden die hetzelfde antwoord
	 * moeten krijgen. Dezelfde beslissende .htaccess (scope) is niet genoeg:
	 * op nginx kan een location-regel per map of per extensie gelden (een
	 * host die *.sql weigert maar *.zip niet). Daarom ook de bovenste map en
	 * de extensie.
	 */
	private static function probe_group( $location, $root, $dir, $scope, $entry ) {
		$rel = ltrim( (string) substr( $dir, strlen( $root ) ), '/' );
		$top = '' === $rel ? '' : (string) strtok( $rel, '/' );
		$ext = preg_match( '/\.(tar\.gz|sql\.gz|[^.]+)$/i', $entry, $m ) ? strtolower( $m[1] ) : '';

		return implode( '|', [ $location, $top, $scope, $ext ] );
	}

	/**
	 * HTTP-controle: per groep één HEAD-verzoek, en het antwoord geldt voor
	 * de hele groep.
	 *
	 * Eerst groepen waar een .htaccess "afgeschermd" zegt — daar zit de valse
	 * rust, zoals een deny-.htaccess op nginx — daarna op ernst.
	 *
	 * @param array $findings
	 * @return array
	 */
	private static function probe_findings( array $findings ) {
		$meta = [ 'status' => 'off', 'control' => null, 'done' => 0, 'inconclusive' => 0, 'skipped' => 0, 'other_host' => 0 ];

		if ( ! apply_filters( 'mcm_exposure_http_probe', true ) ) {
			self::$scan_meta['probe'] = $meta;
			return $findings;
		}

		$groups = [];
		foreach ( $findings as $i => $f ) {
			if ( ! empty( $f['_probe_group'] ) ) {
				$groups[ $f['_probe_group'] ][] = $i;
			}
		}

		if ( ! $groups ) {
			$meta['status']           = 'nothing';
			self::$scan_meta['probe'] = $meta;
			return $findings;
		}

		$rank   = [ 'high' => 0, 'medium' => 1, 'low' => 2 ];
		$weight = function ( array $indexes ) use ( $findings, $rank ) {
			$deny = 0;
			$best = 3;
			foreach ( $indexes as $i ) {
				if ( $findings[ $i ]['_htaccess_deny'] ) {
					$deny = 1;
				}
				$sev  = $findings[ $i ]['_open'][0];
				$best = min( $best, isset( $rank[ $sev ] ) ? $rank[ $sev ] : 3 );
			}
			return [ -$deny, $best ];
		};
		uasort( $groups, function ( $a, $b ) use ( $weight ) {
			return $weight( $a ) <=> $weight( $b );
		} );

		$deadline = microtime( true ) + self::PROBE_BUDGET_SECONDS;

		// Controleverzoek: een core-bestand dat altijd publiek is. Geeft dat
		// geen 200 (loopback dicht, Basic Auth, firewall op ons eigen IP), dan
		// zegt een 403 op een archief niets en blijft het bij .htaccess.
		$control         = self::own_origin_url( includes_url( 'css/dashicons.min.css' ) );
		$meta['control'] = '' !== $control ? self::http_status( $control ) : 0;
		if ( 200 !== $meta['control'] ) {
			$meta['status']           = 'control_failed';
			self::$scan_meta['probe'] = $meta;
			return $findings;
		}

		$meta['status'] = 'ok';

		foreach ( $groups as $indexes ) {
			// Eén controle kan twee verzoeken kosten (http↔https-redirect).
			if ( $meta['done'] >= self::MAX_PROBES || microtime( true ) + 2 * self::PROBE_TIMEOUT > $deadline ) {
				$meta['skipped']++;
				continue;
			}

			$url = self::path_to_url( $findings[ $indexes[0] ]['path'] );
			if ( '' === $url ) {
				$meta['other_host']++;
				continue;
			}

			$code = self::http_status( $url );
			$meta['done']++;

			$public = self::code_means_public( $code );
			if ( null === $public ) {
				$meta['inconclusive']++;
				continue;
			}

			foreach ( $indexes as $i ) {
				$findings[ $i ] = self::set_reachable( $findings[ $i ], $public, $code );
			}
		}

		self::$scan_meta['probe'] = $meta;
		return $findings;
	}

	/**
	 * 200 = publiek, 401/403/404/410 = niet, al het andere = onbekend (dan
	 * blijft het oordeel op basis van .htaccess staan).
	 *
	 * Een 404 op een bestand dat wél op disk staat telt als niet bereikbaar:
	 * de server levert het op dat adres niet uit.
	 *
	 * @return bool|null
	 */
	private static function code_means_public( $code ) {
		if ( 200 === $code ) {
			return true;
		}
		return in_array( $code, [ 401, 403, 404, 410 ], true ) ? false : null;
	}

	/**
	 * Publieke URL van een bestand onder uploads, wp-content of de webroot.
	 *
	 * @return string Leeg als het pad daar niet onder valt, of als de URL niet
	 *                op het eigen domein ligt (zie own_origin_url()).
	 */
	private static function path_to_url( $path ) {
		$uploads = wp_get_upload_dir();
		$map     = [];
		if ( ! empty( $uploads['basedir'] ) && ! empty( $uploads['baseurl'] ) ) {
			$map[] = [ $uploads['basedir'], $uploads['baseurl'] ];
		}
		$map[] = [ WP_CONTENT_DIR, content_url() ];
		$map[] = [ ABSPATH, site_url() ];

		$path = wp_normalize_path( $path );

		foreach ( $map as $pair ) {
			$dir = untrailingslashit( wp_normalize_path( $pair[0] ) );
			if ( 0 !== strpos( $path, $dir . '/' ) ) {
				continue;
			}
			$rel = substr( $path, strlen( $dir ) + 1 );
			return self::own_origin_url( untrailingslashit( $pair[1] ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $rel ) ) ) );
		}

		return '';
	}

	/**
	 * Alleen opvragen op het eigen domein, met het schema uit de siteurl-optie.
	 *
	 * baseurl en content_url() zijn filterbaar: bij een CDN of offload (S3,
	 * upload_url_path, WP_CONTENT_URL op een static-subdomein) wijst de URL
	 * naar een andere host. Een 404 daar zegt niets over het bestand op deze
	 * server, en zou een publiek archief als "niet bereikbaar" op LOW zetten.
	 * Zo'n groep wordt dus niet getest (het .htaccess-oordeel blijft staan).
	 *
	 * Het schema: content_url() volgt is_ssl() van het huidige request, en dat
	 * is onder WP-CLI of achter een TLS-proxy vaak http. Een canonieke
	 * redirect naar https+www volgen we niet (andere URL), dus zonder deze
	 * correctie zou elke controle "geen duidelijk antwoord" geven.
	 *
	 * @return string Leeg als de host afwijkt.
	 */
	private static function own_origin_url( $url ) {
		$site = wp_parse_url( (string) get_option( 'siteurl' ) );
		$host = wp_parse_url( $url, PHP_URL_HOST );

		if ( empty( $site['host'] ) || ! is_string( $host ) || 0 !== strcasecmp( $host, $site['host'] ) ) {
			return '';
		}

		return empty( $site['scheme'] ) ? $url : set_url_scheme( $url, $site['scheme'] );
	}

	/**
	 * HEAD-verzoek: alleen kopregels, er wordt niets gedownload.
	 *
	 * Redirects worden niet gevolgd, behalve een http↔https-redirect naar
	 * hetzelfde adres. Een redirect naar een andere pagina (bv. een plugin die
	 * 404's naar de homepage stuurt) zou anders een 200 opleveren die niets
	 * over dit bestand zegt.
	 *
	 * @return int HTTP-status, 0 bij een fout of time-out.
	 */
	private static function http_status( $url ) {
		$args = [
			'timeout'     => self::PROBE_TIMEOUT,
			'redirection' => 0,
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
			'user-agent'  => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128 Safari/537.36 MCM-Security-Exposure-Check',
		];

		$res = wp_remote_head( $url, $args );
		if ( is_wp_error( $res ) ) {
			return 0;
		}
		$code = (int) wp_remote_retrieve_response_code( $res );

		if ( $code >= 300 && $code < 400 ) {
			$location = wp_remote_retrieve_header( $res, 'location' );
			$location = is_array( $location ) ? (string) reset( $location ) : (string) $location;
			if ( '' !== $location && $location !== $url && set_url_scheme( $location, 'https' ) === set_url_scheme( $url, 'https' ) ) {
				$res = wp_remote_head( $location, $args );
				if ( is_wp_error( $res ) ) {
					return 0;
				}
				$code = (int) wp_remote_retrieve_response_code( $res );
			}
		}

		return $code;
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
	 * @param string $location webroot|uploads|backup_dirs|above_root
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
			// Wordt per niveau overschreven: prepare_reachability() of, boven
			// de webroot, altijd false.
			'public_guess' => true,
			// HTTP-status van de HEAD-controle; null = niet via HTTP getest.
			'http_code'    => null,
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
			$body .= sprintf( "   Publiek:       %s\n", self::public_label( $f ) );
			$body .= "\n";
		}

		foreach ( self::reachability_notes( self::$scan_meta ) as $note ) {
			$body .= wordwrap( $note[1], 72 ) . "\n\n";
		}

		$body .= "----\n";
		$body .= "ACTIE: controleer elk bestand en verwijder als het er niet hoort.\n";
		$body .= "De plugin verwijdert NIETS automatisch.\n\n";

		$locations = wp_list_pluck( $findings, 'location' );
		if ( in_array( 'backup_dirs', $locations, true ) ) {
			$body .= "Back-upmappen in wp-content: zet in de back-upplugin het lokaal\n";
			$body .= "bewaren uit (of laat hem buiten de webroot opslaan) en ruim de oude\n";
			$body .= "archieven op. WPvivid rollback/ bevat de vorige versies van plugins\n";
			$body .= "en thema's: zet die functie in WPvivid uit en verwijder de map.\n\n";
		}

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
			'webroot'     => 'webroot',
			'uploads'     => 'uploads',
			'backup_dirs' => 'back-upmap',
			'above_root'  => 'boven webroot',
		];
	}

	/**
	 * "ja" / "nee", met de HTTP-status erbij als die getest is en anders
	 * "geschat". Boven de webroot is "nee" geen schatting: daar is geen URL.
	 */
	public static function public_label( array $f ) {
		$label = ! empty( $f['public_guess'] ) ? 'ja' : 'nee';
		if ( ! empty( $f['http_code'] ) ) {
			$label .= sprintf( ' (HTTP %d)', (int) $f['http_code'] );
		} elseif ( ! isset( $f['location'] ) || 'above_root' !== $f['location'] ) {
			$label .= ' (geschat)';
		}
		return $label;
	}

	/**
	 * Hoe is "Publiek?" bepaald — voor onder de tabel en in de mail.
	 *
	 * @param array $meta Scan-meta.
	 * @return array<int,array{0:string,1:string}> [ 'info'|'warn', tekst ]
	 */
	public static function reachability_notes( array $meta ) {
		$notes = [];

		if ( ! array_key_exists( 'server', $meta ) ) {
			return $notes; // Resultaat van vóór 1.32.0.
		}

		$server = (string) $meta['server'];
		if ( '' === $server ) {
			$notes[] = [ 'warn', 'Webserver onbekend: de scan liep buiten een webrequest om (WP-CLI of systeem-cron) en de plugin had de server nog niet gezien. Een deny-.htaccess telt daarom als afscherming. Na één bezoek aan wp-admin is de server bekend.' ];
		} elseif ( ! self::server_honors_htaccess( $server ) ) {
			$notes[] = [ 'info', sprintf( 'Webserver: %s. Die leest geen .htaccess, dus een deny-.htaccess telt niet als afscherming.', $server ) ];
		}

		$probe  = isset( $meta['probe'] ) && is_array( $meta['probe'] ) ? $meta['probe'] : [];
		$status = isset( $probe['status'] ) ? $probe['status'] : '';

		if ( 'off' === $status ) {
			$notes[] = [ 'info', 'HTTP-controle staat uit (filter mcm_exposure_http_probe). "Publiek" is geschat op basis van .htaccess en de webserver.' ];
		} elseif ( 'control_failed' === $status ) {
			$notes[] = [ 'warn', sprintf(
				'HTTP-controle niet uitgevoerd: het controleverzoek naar een vast core-bestand gaf %s, verwacht was 200 (loopback geblokkeerd, Basic Auth of een firewall). "Publiek" is daarom geschat op basis van .htaccess.',
				! empty( $probe['control'] ) ? 'HTTP ' . (int) $probe['control'] : 'geen antwoord'
			) ];
		} elseif ( 'ok' === $status && ( ! empty( $probe['skipped'] ) || ! empty( $probe['inconclusive'] ) ) ) {
			$notes[] = [ 'warn', sprintf(
				'HTTP-controle onvolledig: %d groep(en) niet getest (limiet van %d verzoeken / %d sec) en %d zonder duidelijk antwoord. Daar is "Publiek" geschat op basis van .htaccess.',
				(int) $probe['skipped'],
				self::MAX_PROBES,
				self::PROBE_BUDGET_SECONDS,
				(int) $probe['inconclusive']
			) ];
		}

		if ( 'ok' === $status && ! empty( $probe['other_host'] ) ) {
			$notes[] = [ 'warn', sprintf(
				'%d groep(en) niet via HTTP getest: de URL ligt op een ander domein dan de site (CDN of offload), en een antwoord daar zegt niets over deze server. Daar is "Publiek" geschat op basis van .htaccess.',
				(int) $probe['other_host']
			) ];
		}

		return $notes;
	}
}
