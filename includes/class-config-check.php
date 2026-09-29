<?php
/**
 * wp-config-controle — eenmalige waarschuwing voor instellingen die de site
 * stilletjes kwetsbaarder of trager maken.
 *
 * Regels (alleen op productie; op staging zijn dit vaak bewuste keuzes):
 *  - AUTOMATIC_UPDATER_DISABLED       → ook beveiligingsupdates van core uit
 *  - WP_AUTO_UPDATE_CORE = false      → idem (deze plugin zet zelf 'minor'
 *                                       zolang "Auto-update minor" aan staat)
 *  - DISALLOW_FILE_MODS               → blokkeert ook de automatische
 *                                       core-updates. Deze plugin regelt de
 *                                       lockdown zelf, zonder die constante.
 *  - WP_HTTP_BLOCK_EXTERNAL           → updates, licenties en de checksums
 *                                       van de kernbestand-scan werken niet
 *  - SAVEQUERIES / SCRIPT_DEBUG       → trager, hoort niet op productie
 *  - dezelfde constante 2× in wp-config.php (niet bewaakt met defined())
 *
 * "Eenmalig": elke bevinding heeft een knop "Klopt, dit is bewust"
 * (MCM_Finding_Ignore, bron 'config'). De sleutel bevat de waarde, dus een
 * andere waarde = een nieuwe melding. Verdwijnt een bevinding, dan vervalt
 * ook de markering; komt hij later terug, dan volgt weer een melding.
 * Mail: alleen als er een bevinding bij komt (niet als de lijst korter
 * wordt), via de Notifier.
 *
 * Bewust NIET hier:
 *  - WP_DEBUG / WP_DEBUG_DISPLAY → MCM_Debug_Watchdog (blijft terugkomen).
 *  - DISABLE_WP_CRON → geen fout op zich. Of cron écht loopt, bewaakt
 *    MCM_Scan_Watchdog; een statische melding hier zou terecht worden
 *    weggeklikt en dan niets meer zeggen als de trigger later wegvalt.
 *
 * Uit te schakelen via:
 *  - Constant MCM_SECURITY_DISABLE_CONFIG_CHECK in wp-config.php
 *  - Filter 'mcm_security_config_check_enabled' → false
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Config_Check {

	const SOURCE                = 'config';
	const OPTION_MAILED_KEYS = 'mcm_config_check_mailed';

	/** @var array|null Bevindingen van dit request (vóór het filteren op "bewust"). */
	private static $raw = null;

	public function __construct() {
		add_action( 'admin_init', [ __CLASS__, 'maybe_notify' ] );
		add_action( 'admin_notices', [ __CLASS__, 'render_notice' ] );
	}

	public static function is_enabled() {
		if ( defined( 'MCM_SECURITY_DISABLE_CONFIG_CHECK' ) && MCM_SECURITY_DISABLE_CONFIG_CHECK ) {
			return false;
		}
		if ( class_exists( 'MCM_Staging_Detector' ) && MCM_Staging_Detector::is_staging() ) {
			return false;
		}
		return (bool) apply_filters( 'mcm_security_config_check_enabled', true );
	}

	/**
	 * Openstaande bevindingen (zonder de als bewust gemarkeerde).
	 *
	 * @return array<int,array{path:string,relpath:string,reason:string}>
	 */
	public static function findings() {
		$raw = self::raw_findings();
		if ( class_exists( 'MCM_Finding_Ignore' ) ) {
			return MCM_Finding_Ignore::filter( self::SOURCE, $raw );
		}
		return $raw;
	}

	private static function raw_findings() {
		if ( null !== self::$raw ) {
			return self::$raw;
		}
		if ( ! self::is_enabled() ) {
			self::$raw = [];
			return self::$raw;
		}

		$out = [];
		if ( self::is_on( 'AUTOMATIC_UPDATER_DISABLED' ) ) {
			$out[] = self::constant_finding( 'AUTOMATIC_UPDATER_DISABLED', 'Alle automatische updates staan uit, ook de beveiligingsupdates van WordPress zelf.' );
		}
		if ( defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE ) {
			$out[] = self::constant_finding( 'WP_AUTO_UPDATE_CORE', 'Automatische core-updates staan uit, dus ook de beveiligingsupdates (bv. 6.8.1 naar 6.8.2).' );
		}
		if ( self::is_on( 'DISALLOW_FILE_MODS' ) ) {
			$out[] = self::constant_finding( 'DISALLOW_FILE_MODS', 'Blokkeert naast installeren ook de automatische beveiligingsupdates van WordPress. Deze plugin regelt de plugin/theme-lockdown zelf, zonder deze constante.' );
		}
		if ( self::is_on( 'WP_HTTP_BLOCK_EXTERNAL' ) ) {
			$hosts = defined( 'WP_ACCESSIBLE_HOSTS' ) ? (string) WP_ACCESSIBLE_HOSTS : '';
			$out[] = self::constant_finding(
				'WP_HTTP_BLOCK_EXTERNAL',
				'Uitgaande verbindingen zijn geblokkeerd' . ( '' !== $hosts ? ' (behalve naar ' . $hosts . ')' : '' ) . '. Updates, licentiechecks en de kernbestand-scan werken dan niet.',
				$hosts
			);
		}
		if ( self::is_on( 'SAVEQUERIES' ) ) {
			$out[] = self::constant_finding( 'SAVEQUERIES', 'Elke databasequery wordt in het geheugen bewaard: trager, en debug-plugins kunnen de querylijst tonen. Hoort niet op productie.' );
		}
		if ( self::is_on( 'SCRIPT_DEBUG' ) ) {
			$out[] = self::constant_finding( 'SCRIPT_DEBUG', 'WordPress laadt de niet-verkleinde CSS en JavaScript: trager. Hoort niet op productie.' );
		}

		self::$raw = array_merge( $out, self::duplicate_findings() );
		return self::$raw;
	}

	private static function is_on( $name ) {
		return defined( $name ) && constant( $name );
	}

	/**
	 * @param string $name  Constante.
	 * @param string $why   Uitleg.
	 * @param string $extra Extra waarde die meetelt voor "opnieuw melden".
	 */
	private static function constant_finding( $name, $why, $extra = '' ) {
		$value = var_export( constant( $name ), true );
		return [
			'path'    => 'wpconfig:' . $name . ':' . md5( $value . '|' . $extra ),
			'relpath' => $name . ' = ' . $value,
			'reason'  => $why,
		];
	}

	/**
	 * Constanten die in wp-config.php opnieuw gedefinieerd worden: een
	 * onbewaakte define() nadat dezelfde constante al eerder (bewaakt of niet)
	 * gedefinieerd is. PHP geeft dan een waarschuwing en alleen de eerste
	 * waarde telt. Een bewaakte define() ná een andere is onschuldig.
	 *
	 * Werkt met PHP-tokens, dus commentaar (ook onze eigen
	 * "// MCM_DISABLED:"-regels) telt niet mee. Een define() telt als
	 * bewaakt als in hetzelfde statement defined() met dezelfde naam staat:
	 * `if ( ! defined( 'X' ) ) define( ... )`, `defined( 'X' ) || define( ... )`
	 * of `if ( ! defined( 'X' ) ) { define( ... ); }`. Een if/else met in elke
	 * tak een define() wordt niet herkend; daarvoor is de knop "bewust".
	 */
	private static function duplicate_findings() {
		$path = self::config_path();
		if ( ! $path || ! is_readable( $path ) || ! function_exists( 'token_get_all' ) ) {
			return [];
		}
		$tokens = token_get_all( (string) file_get_contents( $path ) );
		$defs   = []; // naam => [ [ regel, bewaakt ], ... ] in volgorde van het bestand
		$start  = 0;  // eerste token van het huidige statement
		$count  = count( $tokens );

		for ( $i = 0; $i < $count; $i++ ) {
			$t = $tokens[ $i ];
			if ( ';' === $t || '}' === $t ) {
				$start = $i + 1;
				continue;
			}
			if ( ! is_array( $t ) || T_STRING !== $t[0] || 'define' !== strtolower( $t[1] ) ) {
				continue;
			}
			$prev = self::meaningful( $tokens, $i, -1 );
			if ( null !== $prev && is_array( $tokens[ $prev ] ) && in_array( $tokens[ $prev ][0], [ T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION ], true ) ) {
				continue; // ->define(), ::define() of een functie die zo heet
			}
			$open = self::meaningful( $tokens, $i, 1 );
			$name = null !== $open ? self::meaningful( $tokens, $open, 1 ) : null;
			if ( null === $name || '(' !== $tokens[ $open ] || ! is_array( $tokens[ $name ] ) || T_CONSTANT_ENCAPSED_STRING !== $tokens[ $name ][0] ) {
				continue;
			}
			$constant = trim( $tokens[ $name ][1], '\'"' );

			$before = '';
			for ( $m = $start; $m < $i; $m++ ) {
				if ( is_array( $tokens[ $m ] ) && in_array( $tokens[ $m ][0], [ T_COMMENT, T_DOC_COMMENT ], true ) ) {
					continue;
				}
				$before .= is_array( $tokens[ $m ] ) ? $tokens[ $m ][1] : $tokens[ $m ];
			}
			$guarded = false !== stripos( $before, 'defined' ) && false !== strpos( $before, $constant );

			$defs[ $constant ][] = [ (int) $t[2], $guarded ];
		}

		$out = [];
		foreach ( $defs as $constant => $list ) {
			$redefined = false;
			foreach ( array_slice( $list, 1 ) as $def ) {
				if ( ! $def[1] ) {
					$redefined = true;
				}
			}
			if ( ! $redefined ) {
				continue;
			}
			$at = wp_list_pluck( $list, 0 );
			$out[] = [
				// Sleutel zonder regelnummers: die verschuiven bij elke
				// wijziging in wp-config.php (ook door deze plugin zelf).
				'path'    => 'wpconfig-dup:' . $constant . ':' . count( $at ),
				'relpath' => sprintf( '%s — %d× (regel %s)', $constant, count( $at ), implode( ', ', $at ) ),
				'reason'  => 'Meer dan één keer gedefinieerd in wp-config.php. PHP geeft een waarschuwing en alleen de eerste waarde telt.',
			];
		}
		return $out;
	}

	/**
	 * Index van het eerstvolgende (of vorige) token dat geen witruimte of
	 * commentaar is.
	 */
	private static function meaningful( array $tokens, $from, $step ) {
		for ( $i = $from + $step; $i >= 0 && $i < count( $tokens ); $i += $step ) {
			if ( is_array( $tokens[ $i ] ) && in_array( $tokens[ $i ][0], [ T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ], true ) ) {
				continue;
			}
			return $i;
		}
		return null;
	}

	/**
	 * Zelfde zoekvolgorde als WordPress (en MCM_WPConfig_Manager).
	 */
	private static function config_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		if ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
			return dirname( ABSPATH ) . '/wp-config.php';
		}
		return false;
	}

	/**
	 * admin_init: vervallen "bewust"-markeringen opruimen en mailen zodra er
	 * een bevinding bij komt. Wordt de lijst alleen korter (opgelost of als
	 * bewust gemarkeerd), dan volgt geen mail. Niet bij AJAX (heartbeat).
	 */
	public static function maybe_notify() {
		if ( wp_doing_ajax() || ! self::is_enabled() ) {
			return;
		}

		// Een markering geldt voor een bevinding zolang die bestaat. Is de
		// bevinding weg (waarde aangepast of regel verwijderd), dan vervalt
		// de markering, zodat hij bij terugkomst opnieuw gemeld wordt.
		if ( class_exists( 'MCM_Finding_Ignore' ) ) {
			$current = [];
			foreach ( self::raw_findings() as $f ) {
				$current[ MCM_Finding_Ignore::key( self::SOURCE, $f['path'] ) ] = true;
			}
			foreach ( array_keys( MCM_Finding_Ignore::all( self::SOURCE ) ) as $key ) {
				if ( ! isset( $current[ $key ] ) ) {
					MCM_Finding_Ignore::remove( $key );
				}
			}
		}

		$findings = self::findings();
		$keys     = wp_list_pluck( $findings, 'path' );
		sort( $keys );
		$mailed = get_option( self::OPTION_MAILED_KEYS, [] );
		$mailed = is_array( $mailed ) ? $mailed : [];
		if ( $keys === $mailed ) {
			return;
		}
		if ( empty( $keys ) ) {
			delete_option( self::OPTION_MAILED_KEYS );
			return;
		}
		update_option( self::OPTION_MAILED_KEYS, $keys, false );

		if ( array_diff( $keys, $mailed ) ) {
			self::send_mail( $findings );
		}
	}

	private static function send_mail( array $findings ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}
		$body = "In de configuratie van deze site staan instellingen die aandacht vragen:\n\n";
		foreach ( $findings as $i => $f ) {
			$body .= sprintf( "%d. %s\n   %s\n\n", $i + 1, $f['relpath'], $f['reason'] );
		}
		$body .= "----\n";
		$body .= "Is het bewust? Klik dan in wp-admin op \"Klopt, dit is bewust\" (Extra → MCM Security,\n";
		$body .= "sectie wp-config-controle). Je krijgt pas weer een melding als de waarde verandert.\n";
		$body .= "Deze mail komt alleen als er een bevinding bij komt.";

		MCM_Notifier::email( sprintf( 'wp-config: %d instelling(en) om te controleren', count( $findings ) ), $body );
	}

	public static function render_notice() {
		if ( ! self::is_enabled() || ! MCM_Notifier::should_show_admin_notice() ) {
			return;
		}
		$findings = self::findings();
		if ( empty( $findings ) ) {
			return;
		}
		$items = '';
		foreach ( $findings as $f ) {
			$items .= sprintf(
				'<li><code>%s</code> &mdash; %s <a href="%s" class="button button-small">Klopt, dit is bewust</a></li>',
				esc_html( $f['relpath'] ),
				esc_html( $f['reason'] ),
				esc_url( MCM_Finding_Ignore::ignore_url( self::SOURCE, $f ) )
			);
		}
		printf(
			'<div class="notice notice-warning"><p><strong>MCM Security: wp-config-instellingen om te controleren.</strong></p><ul style="list-style:disc;margin-left:1.5em">%s</ul></div>',
			$items
		);
	}
}
