<?php
/**
 * Vulnerable Versions — meldt een geïnstalleerde Avada/Avada Builder-versie
 * met een bekend, ernstig lek.
 *
 * Aanleiding: een MCM-site die niet in MainWP stond, draaide in oktober 2026
 * nog Avada 7.15.1 / Avada Builder 3.15.1 (stand van maart). Via
 * CVE-2026-18431 (onbevoegd bestanden schrijven, Avada ≤ 7.16 + Builder ≤ 3.16,
 * gepubliceerd 25 aug 2026) zette een geautomatiseerde aanval in vijftien
 * seconden een achterdeur op de site, zonder in te loggen. Daarna volgde
 * Japanse SEO-spam met cloaking. Avada-updates komen niet via WordPress.org,
 * dus WordPress zelf waarschuwt hier niet voor. De andere scanners melden een
 * inbraak achteraf; deze module meldt het open lek vooraf.
 *
 * Werkwijze:
 *   - Een vaste lijst bekende lekken (known_vulnerabilities()), uitbreidbaar
 *     via het filter 'mcm_security_known_vulnerabilities'. De lijst gaat mee
 *     met de plugin-updates; er is geen externe dienst nodig.
 *   - Vergelijkt de geïnstalleerde versie (ook als de plugin/het thema niet
 *     actief is: de bestanden staan er dan nog) met de versie waarin het lek
 *     is opgelost.
 *   - Dagelijkse wp-cron + direct na elke plugin-/thema-update, zodat de
 *     melding verdwijnt zodra de update erop staat.
 *   - Mail bij een nieuwe set bevindingen (anti-spam via hash, zoals de
 *     scanners), en een herinnering als dezelfde set na 7 dagen nog open
 *     staat. Rode melding op elke wp-adminpagina, alleen voor MCM-eigenaars.
 *   - 'requires' in een regel: alleen melden als die plugin actief is (het
 *     Avada-lek vraagt het thema én een actieve Builder).
 *   - Geen schakelaar: een bekend kritiek lek wil je altijd zien. Ook op
 *     staging, want een kwetsbare testsite onder dezelfde servergebruiker
 *     geeft toegang tot de live-site.
 *   - Werkt NOOIT zelf iets bij. Detectie + melding only.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Vulnerable_Versions {

	const CRON_HOOK             = 'mcm_security_vulnerable_versions_check';
	const ACTION_MANUAL_CHECK   = 'mcm_security_run_vulnerable_versions_check';
	const OPTION_RESULTS        = 'mcm_vulnerable_versions_results';
	const OPTION_LAST_MAIL_HASH = 'mcm_vulnerable_versions_last_mailed';
	const REMIND_AFTER          = 7 * DAY_IN_SECONDS;

	public function __construct() {
		add_action( self::CRON_HOOK, [ __CLASS__, 'run_and_maybe_notify' ] );
		add_action( 'admin_post_' . self::ACTION_MANUAL_CHECK, [ __CLASS__, 'handle_manual_check' ] );
		add_action( 'init', [ __CLASS__, 'maybe_schedule_cron' ] );
		// Na een update meteen opnieuw kijken: de melding moet verdwijnen
		// zodra de nieuwe versie erop staat (en verschijnen bij een downgrade).
		add_action( 'upgrader_process_complete', [ __CLASS__, 'run_and_maybe_notify' ], 99, 0 );
		add_action( 'admin_notices', [ __CLASS__, 'render_notice' ] );
	}

	public static function maybe_schedule_cron() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + 5 * MINUTE_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Bekende lekken. Per regel: wat (plugin-map of themamap), vanaf welke
	 * versie het is opgelost, en wat het lek is.
	 *
	 * Alleen opnemen: lekken die zonder inlog (of met een laag account) tot
	 * code-uitvoering of overname leiden. Kleinere lekken zijn een gewone
	 * update, geen alarm.
	 *
	 * @return array<int,array{id:string,type:string,slug:string,name:string,fixed_in:string,requires?:string,severity:string,summary:string,published:string,url:string}>
	 */
	public static function known_vulnerabilities() {
		$list = [
			[
				'id'        => 'CVE-2026-18431',
				'type'      => 'plugin',
				'slug'      => 'fusion-builder',
				'name'      => 'Avada Builder (fusion-builder)',
				'fixed_in'  => '3.16.1',
				'severity'  => 'critical',
				'summary'   => 'Onbevoegd bestanden schrijven en code uitvoeren, zonder in te loggen (CVSS 9,8). Geldt voor Avada ≤ 7.16 samen met Avada Builder ≤ 3.16.',
				'published' => '2026-08-25',
				'url'       => 'https://www.wordfence.com/threat-intel/vulnerabilities/detail/avada-716-and-fusion-builder-316-unauthenticated-remote-code-execution-via-arbitrary-file-write',
			],
			[
				'id'        => 'CVE-2026-18431',
				'type'      => 'theme',
				'slug'      => 'Avada',
				'name'      => 'Avada (thema)',
				'fixed_in'  => '7.16.1',
				// Het lek vraagt Avada én een actieve Builder.
				'requires'  => 'fusion-builder',
				'severity'  => 'critical',
				'summary'   => 'Onbevoegd bestanden schrijven en code uitvoeren, zonder in te loggen (CVSS 9,8). Geldt voor Avada ≤ 7.16 samen met Avada Builder ≤ 3.16.',
				'published' => '2026-08-25',
				'url'       => 'https://www.wordfence.com/threat-intel/vulnerabilities/detail/avada-716-and-fusion-builder-316-unauthenticated-remote-code-execution-via-arbitrary-file-write',
			],
		];

		/**
		 * Lekken toevoegen of weghalen zonder de plugin te wijzigen.
		 */
		return (array) apply_filters( 'mcm_security_known_vulnerabilities', $list );
	}

	/**
	 * Geïnstalleerde versie + status van een plugin-map, of null als hij er
	 * niet staat.
	 *
	 * @return array{version:string,active:bool}|null
	 */
	private static function plugin_state( $slug ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		// Alleen deze map uitlezen, niet alle plugins.
		$plugins = get_plugins( '/' . $slug );
		if ( empty( $plugins ) ) {
			return null;
		}
		foreach ( $plugins as $file => $data ) {
			if ( empty( $data['Version'] ) ) {
				continue;
			}
			return [
				'version' => (string) $data['Version'],
				'active'  => is_plugin_active( $slug . '/' . $file ) || ( is_multisite() && is_plugin_active_for_network( $slug . '/' . $file ) ),
			];
		}
		return null;
	}

	/**
	 * Geïnstalleerde versie + status van een thema-map, of null.
	 * Een child theme telt: dan is de parent "actief".
	 *
	 * @return array{version:string,active:bool}|null
	 */
	private static function theme_state( $slug ) {
		foreach ( array_unique( [ $slug, strtolower( $slug ) ] ) as $dir ) {
			$theme = wp_get_theme( $dir );
			if ( ! $theme->exists() || '' === (string) $theme->get( 'Version' ) ) {
				continue;
			}
			return [
				'version' => (string) $theme->get( 'Version' ),
				'active'  => in_array( $theme->get_stylesheet(), [ get_template(), get_stylesheet() ], true ),
			];
		}
		return null;
	}

	/**
	 * Vergelijk de geïnstalleerde versies met de lijst. Schrijft niets weg.
	 *
	 * @return array<int,array>
	 */
	public static function scan() {
		$findings = [];

		foreach ( self::known_vulnerabilities() as $vuln ) {
			if ( empty( $vuln['slug'] ) || empty( $vuln['fixed_in'] ) ) {
				continue;
			}
			$state = ( 'theme' === $vuln['type'] ) ? self::theme_state( $vuln['slug'] ) : self::plugin_state( $vuln['slug'] );
			if ( null === $state || ! version_compare( $state['version'], $vuln['fixed_in'], '<' ) ) {
				continue;
			}
			if ( ! empty( $vuln['requires'] ) ) {
				$required = self::plugin_state( $vuln['requires'] );
				if ( null === $required || ! $required['active'] ) {
					continue;
				}
			}

			$findings[] = array_merge( $vuln, [
				'installed' => $state['version'],
				'active'    => $state['active'],
			] );
		}

		return $findings;
	}

	/**
	 * Voert de controle uit, slaat het resultaat op en mailt bij een nieuwe
	 * set bevindingen.
	 *
	 * @return array De bevindingen.
	 */
	public static function run_and_maybe_notify() {
		$findings = self::scan();

		update_option( self::OPTION_RESULTS, [
			'timestamp' => time(),
			'findings'  => $findings,
		], false );

		if ( empty( $findings ) ) {
			delete_option( self::OPTION_LAST_MAIL_HASH );
			return $findings;
		}

		// Zelfde set als de vorige mail: alleen na REMIND_AFTER opnieuw, zodat
		// een open lek niet na één mail uit beeld raakt.
		$hash   = self::findings_signature( $findings );
		$mailed = get_option( self::OPTION_LAST_MAIL_HASH, [] );
		if ( is_array( $mailed ) && isset( $mailed['hash'], $mailed['time'] )
			&& $mailed['hash'] === $hash && time() - (int) $mailed['time'] < self::REMIND_AFTER ) {
			return $findings;
		}

		$is_reminder = is_array( $mailed ) && isset( $mailed['hash'] ) && $mailed['hash'] === $hash;
		self::send_findings_mail( $findings, $is_reminder );
		update_option( self::OPTION_LAST_MAIL_HASH, [ 'hash' => $hash, 'time' => time() ], false );

		return $findings;
	}

	private static function findings_signature( array $findings ) {
		$keys = array_map( function ( $f ) {
			return $f['id'] . '|' . $f['type'] . '|' . $f['slug'] . '|' . $f['installed'];
		}, $findings );
		sort( $keys );
		return md5( implode( "\n", $keys ) );
	}

	/**
	 * Eén regel per bevinding, voor mail en melding.
	 */
	public static function describe( array $f ) {
		return sprintf(
			'%s %s%s heeft %s (%s). Opgelost in %s.',
			$f['name'],
			$f['installed'],
			$f['active'] ? '' : ' (niet actief, bestanden staan er wel)',
			$f['id'],
			'critical' === $f['severity'] ? 'kritiek' : $f['severity'],
			$f['fixed_in']
		);
	}

	private static function send_findings_mail( array $findings, $is_reminder = false ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}

		$ids     = array_unique( wp_list_pluck( $findings, 'id' ) );
		$subject = sprintf( '%sKRITIEK LEK: Avada bijwerken (%s)', $is_reminder ? 'Herinnering: ' : '', implode( ', ', $ids ) );

		$body = '';
		if ( $is_reminder ) {
			$body .= "Herinnering: dit lek staat nog open sinds de vorige mail.\n\n";
		}
		$body .= "Op deze site staat een Avada-versie met een bekend, ernstig lek.\n";
		$body .= "Aanvallers zoeken hier geautomatiseerd naar; een inbraak kost hen\n";
		$body .= "seconden en vraagt geen wachtwoord.\n\n";

		$seen = [];
		foreach ( $findings as $i => $f ) {
			$body .= sprintf( "%d. %s\n", $i + 1, self::describe( $f ) );
			if ( ! isset( $seen[ $f['id'] ] ) ) {
				$body .= sprintf( "   Wat:  %s\n", $f['summary'] );
				$body .= sprintf( "   Info: %s\n", $f['url'] );
				$seen[ $f['id'] ] = true;
			}
			$body .= "\n";
		}

		$body .= "----\n";
		$body .= "ACTIE:\n";
		$body .= "1. Werk Avada, Avada Builder en Avada Core bij naar de nieuwste versie\n";
		$body .= "   (Avada › Plugins/Add-ons, of via MainWP). Staat de site niet in\n";
		$body .= "   MainWP, zet hem er dan in: anders komt de volgende update ook niet.\n";
		$body .= "2. Kijk daarna of er al iemand binnen is geweest: \"Nu scannen\" bij\n";
		$body .= "   Kernbestand-integriteit en bij Vreemde bestanden & mappen\n";
		$body .= "   (Extra → MCM Security). Via SSH: wp core verify-checksums.\n";
		$body .= "   Let op .htaccess-bestanden in veel mappen en .php-bestanden in\n";
		$body .= "   mappen met dezelfde naam als hun bovenliggende map (xml/xml/).\n";
		$body .= "De plugin werkt NIETS zelf bij.\n";

		MCM_Notifier::email( $subject, $body );
	}

	/**
	 * Rode melding op elke adminpagina, alleen voor MCM-eigenaars. Live
	 * berekend, zodat hij na een update direct weg is.
	 */
	public static function render_notice() {
		if ( ! class_exists( 'MCM_Notifier' ) || ! MCM_Notifier::should_show_admin_notice() ) {
			return;
		}
		$findings = self::scan();
		if ( empty( $findings ) ) {
			return;
		}
		$items = '';
		foreach ( $findings as $f ) {
			$items .= '<li>' . esc_html( self::describe( $f ) ) . '</li>';
		}
		printf(
			'<div class="notice notice-error"><p><strong>MCM Security: kritiek lek in Avada &mdash; nu bijwerken.</strong> Zonder inloggen kan een aanvaller hier code op de site zetten.</p><ul style="list-style:disc;margin-left:1.5em">%s</ul><p><a href="%s">Details in MCM Security</a></p></div>',
			$items,
			esc_url( admin_url( 'tools.php?page=mcm-security#mcm-vulnerable-versions' ) )
		);
	}

	public static function handle_manual_check() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::ACTION_MANUAL_CHECK );

		self::run_and_maybe_notify();

		wp_safe_redirect(
			add_query_arg(
				'mcm_status',
				'vulnerable_versions_check_done',
				wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' )
			)
		);
		exit;
	}

	/**
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
