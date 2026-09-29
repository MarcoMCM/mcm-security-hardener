<?php
/**
 * Scan-watchdog — merkt op wanneer de geplande scans van deze plugin niet
 * meer draaien.
 *
 * Aanleiding: op parre-deden.nl lag WP-Cron van 19 t/m 28 sep 2026 stil
 * (DISABLE_WP_CRON=true, de externe trigger viel weg). De scans van deze
 * plugin draaiden negen dagen niet en niemand merkte het.
 *
 * Gedrag:
 *  - Per scan wordt de laatste AUTOMATISCHE run vastgelegd, via een eigen
 *    callback op dezelfde cron-hook met prioriteit 999 (dus ná de scan zelf).
 *    Crasht de scan halverwege, dan wordt er niets vastgelegd. "Nu scannen"
 *    telt niet mee: die gaat niet via de cron-hook en zou een dode cron
 *    anders maskeren.
 *  - De controle loopt bewust NIET via cron, maar bij een gewone request
 *    (admin, frontend, MainWP-sync), hooguit 1× per 15 minuten. Alleen
 *    lezen van al geladen opties; schrijven alleen bij die controle.
 *  - Te laat = langer dan 2× het interval geen automatische run. Pas als dat
 *    30 minuten later nog zo is volgt alarm. Zonder die wachttijd geeft een
 *    rustige site met gewone WP-Cron vals alarm: de eerste bezoeker na een
 *    stille nacht ziet een oude run, maar start in datzelfde request de cron.
 *  - Alarm: admin-notice (alleen MCM-eigenaars), max 1 mail per dag via de
 *    Notifier, rode regel in het dashboard. Lopen de scans weer, dan
 *    verdwijnt alles vanzelf en telt een volgende storing als nieuw incident.
 *  - Niet op staging: daar draait cron vaak bewust niet.
 *
 * Bewust alleen de eigen scans. De mail vermeldt wel hoe cron is ingericht
 * en hoeveel andere taken achterstallig zijn, als hulp bij de diagnose;
 * algemene cron-bewaking hoort niet in deze plugin.
 *
 * Uit te schakelen via:
 *  - Constant MCM_SECURITY_DISABLE_SCAN_WATCHDOG in wp-config.php
 *  - Filter 'mcm_security_scan_watchdog_enabled' → false
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Scan_Watchdog {

	// Eén optie per scan (alleen geschreven door de cron-callback), los van
	// de watchdog-state (alleen geschreven door de controle). Zo kunnen twee
	// processen elkaars schrijfactie niet overschrijven.
	const RUN_OPTION_PREFIX = 'mcm_security_scan_run_';
	const STATE_OPTION      = 'mcm_security_scan_watchdog';

	const CHECK_INTERVAL = 15 * MINUTE_IN_SECONDS;
	const LATE_FACTOR    = 2;
	const DEBOUNCE       = 30 * MINUTE_IN_SECONDS;
	const MAIL_INTERVAL  = DAY_IN_SECONDS;

	public function __construct() {
		foreach ( self::scans() as $scan ) {
			add_action( $scan['hook'], [ __CLASS__, 'record_run' ], 999 );
		}
		add_action( 'init', [ __CLASS__, 'maybe_check' ], 99 );
		add_action( 'admin_notices', [ __CLASS__, 'render_notice' ] );
	}

	/**
	 * De bewaakte scans. 'setting' = de aan/uit-instelling van de scan zelf.
	 *
	 * @return array<string,array{label:string,hook:string,interval:int,setting:string}>
	 */
	public static function scans() {
		return [
			'php_error'      => [
				'label'    => 'PHP Error Watcher',
				'hook'     => MCM_PHP_Error_Watcher::CRON_HOOK,
				'interval' => HOUR_IN_SECONDS,
				'setting'  => 'php_error_watcher_enabled',
			],
			'exposure'       => [
				'label'    => 'Blootgestelde bestanden',
				'hook'     => MCM_File_Exposure_Scanner::CRON_HOOK,
				'interval' => WEEK_IN_SECONDS,
				'setting'  => 'exposure_scanner_enabled',
			],
			'anomaly'        => [
				'label'    => 'Vreemde bestanden & mappen',
				'hook'     => MCM_Anomaly_Scanner::CRON_HOOK,
				'interval' => WEEK_IN_SECONDS,
				'setting'  => 'anomaly_scanner_enabled',
			],
			'core_integrity' => [
				'label'    => 'Kernbestand-integriteit',
				'hook'     => MCM_Core_Integrity_Scanner::CRON_HOOK,
				'interval' => WEEK_IN_SECONDS,
				'setting'  => 'core_integrity_enabled',
			],
		];
	}

	public static function is_enabled() {
		if ( defined( 'MCM_SECURITY_DISABLE_SCAN_WATCHDOG' ) && MCM_SECURITY_DISABLE_SCAN_WATCHDOG ) {
			return false;
		}
		return (bool) apply_filters( 'mcm_security_scan_watchdog_enabled', true );
	}

	private static function is_staging() {
		return class_exists( 'MCM_Staging_Detector' ) && MCM_Staging_Detector::is_staging();
	}

	/**
	 * Staat een scan aan? Met fallback op de plugin-default, net als de
	 * scanners zelf (oudere sites missen de sleutel nog in de database).
	 */
	private static function scan_enabled( $key ) {
		$settings = get_option( 'mcm_security_settings', [] );
		if ( ! is_array( $settings ) || ! array_key_exists( $key, $settings ) ) {
			$defaults = MCM_Security_Hardener::get_defaults();
			return ! empty( $defaults[ $key ] );
		}
		return ! empty( $settings[ $key ] );
	}

	private static function state() {
		$state = get_option( self::STATE_OPTION, [] );
		return array_merge(
			[
				'checked'    => 0,  // laatste controle
				'seen'       => [], // scan-id => sinds wanneer we hem aan zien staan
				'late_since' => 0,  // eerste controle waarbij iets te laat was
				'mailed_at'  => 0,
			],
			is_array( $state ) ? $state : []
		);
	}

	/**
	 * Cron-callback (prioriteit 999): de scan op deze hook is afgerond.
	 */
	public static function record_run() {
		$hook = current_action();
		foreach ( self::scans() as $id => $scan ) {
			if ( $scan['hook'] === $hook ) {
				update_option( self::RUN_OPTION_PREFIX . $id, time(), true );
				return;
			}
		}
	}

	/**
	 * Controle bij een gewone request, hooguit 1× per CHECK_INTERVAL.
	 */
	public static function maybe_check() {
		if ( ! self::is_enabled() || wp_doing_cron() || wp_installing() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$state = self::state();
		if ( time() - (int) $state['checked'] < self::CHECK_INTERVAL ) {
			return;
		}
		self::check( $state );
	}

	private static function check( array $state ) {
		$now              = time();
		$state['checked'] = $now;

		// 'seen' voorkomt vals alarm direct na de update naar deze versie of
		// na het aanzetten van een scan: we rekenen vanaf het moment dat we de
		// scan aan zien staan. Uitzetten = vergeten, zodat opnieuw aanzetten
		// weer bij nul begint.
		foreach ( self::scans() as $id => $scan ) {
			if ( self::scan_enabled( $scan['setting'] ) ) {
				if ( empty( $state['seen'][ $id ] ) ) {
					$state['seen'][ $id ] = $now;
				}
			} else {
				unset( $state['seen'][ $id ] );
			}
		}

		$late = array_filter( self::status( $state, $now ), function ( $s ) {
			return $s['late'];
		} );

		if ( empty( $late ) ) {
			$state['late_since'] = 0;
			$state['mailed_at']  = 0; // volgende storing = nieuw incident
		} elseif ( empty( $state['late_since'] ) ) {
			$state['late_since'] = $now;
		}

		$alarm     = ! empty( $late ) && ( $now - (int) $state['late_since'] ) >= self::DEBOUNCE;
		$send_mail = $alarm && ! self::is_staging() && ( $now - (int) $state['mailed_at'] ) >= self::MAIL_INTERVAL;
		if ( $send_mail ) {
			$state['mailed_at'] = $now;
		}

		// Eerst opslaan: een trage mail mag geen tweede controle (en mail)
		// in een parallelle request uitlokken.
		update_option( self::STATE_OPTION, $state, true );

		if ( $send_mail ) {
			self::send_mail( $late );
		}
	}

	/**
	 * Stand per scan. Schrijft niets.
	 *
	 * @param array|null $state Watchdog-state; null = opgeslagen state.
	 * @param int|null   $now
	 * @return array<string,array{label:string,interval:int,enabled:bool,last_run:int,seen:int,next_run:int,late:bool,alarm:bool}>
	 */
	public static function status( $state = null, $now = null ) {
		$state = null === $state ? self::state() : $state;
		$now   = null === $now ? time() : $now;
		$alarm = ! empty( $state['late_since'] ) && ( $now - (int) $state['late_since'] ) >= self::DEBOUNCE;

		$out = [];
		foreach ( self::scans() as $id => $scan ) {
			$enabled  = self::scan_enabled( $scan['setting'] );
			$last_run = (int) get_option( self::RUN_OPTION_PREFIX . $id, 0 );
			// Nog nooit gecontroleerd = nog geen referentiepunt = niet te laat.
			$seen      = isset( $state['seen'][ $id ] ) ? (int) $state['seen'][ $id ] : $now;
			$reference = max( $last_run, $seen );
			$late      = $enabled && ( $now - $reference ) > self::LATE_FACTOR * $scan['interval'];

			$out[ $id ] = [
				'label'    => $scan['label'],
				'interval' => $scan['interval'],
				'enabled'  => $enabled,
				'last_run' => $last_run,
				'seen'     => $seen,
				'next_run' => (int) wp_next_scheduled( $scan['hook'] ),
				'late'     => $late,
				'alarm'    => $late && $alarm,
			];
		}
		return $out;
	}

	/**
	 * Is er nu alarm (te laat én langer dan de wachttijd)?
	 */
	public static function has_alarm() {
		if ( ! self::is_enabled() ) {
			return false;
		}
		foreach ( self::status() as $s ) {
			if ( $s['alarm'] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Hoe draait cron hier, en hoeveel geplande taken staan er open? Alleen
	 * als diagnose in mail en dashboard; hier wordt niets op gealarmeerd.
	 *
	 * @return array{mode:string,overdue:int,oldest:int,oldest_hook:string}
	 */
	public static function cron_context() {
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			$mode = 'extern (DISABLE_WP_CRON staat aan: een servercron of externe dienst moet wp-cron.php aanroepen)';
		} elseif ( defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON ) {
			$mode = 'ALTERNATE_WP_CRON (via een redirect bij een bezoek)';
		} else {
			$mode = 'WP-Cron via bezoekers (loopt alleen als er verkeer is)';
		}

		$now         = time();
		$overdue     = 0;
		$oldest      = 0;
		$oldest_hook = '';
		$crons       = function_exists( '_get_cron_array' ) ? _get_cron_array() : [];
		foreach ( (array) $crons as $timestamp => $hooks ) {
			// 10 minuten speling: een taak die net aan de beurt is, is niet achterstallig.
			if ( (int) $timestamp > $now - 10 * MINUTE_IN_SECONDS ) {
				continue;
			}
			foreach ( (array) $hooks as $hook => $events ) {
				$overdue += count( (array) $events );
				if ( ! $oldest || (int) $timestamp < $oldest ) {
					$oldest      = (int) $timestamp;
					$oldest_hook = (string) $hook;
				}
			}
		}

		return [
			'mode'        => $mode,
			'overdue'     => $overdue,
			'oldest'      => $oldest,
			'oldest_hook' => $oldest_hook,
		];
	}

	public static function interval_label( $seconds ) {
		if ( HOUR_IN_SECONDS === (int) $seconds ) {
			return 'elk uur';
		}
		if ( WEEK_IN_SECONDS === (int) $seconds ) {
			return 'elke week';
		}
		return 'elke ' . human_time_diff( 0, (int) $seconds );
	}

	/**
	 * "Laatste automatische run" als tekst. Zonder vastgelegde run: sinds
	 * wanneer we kijken (de registratie bestaat pas vanaf versie 1.31.0).
	 */
	private static function last_run_label( array $s ) {
		if ( $s['last_run'] ) {
			return wp_date( 'd-m-Y H:i', $s['last_run'] );
		}
		return 'geen sinds ' . wp_date( 'd-m-Y H:i', $s['seen'] );
	}

	private static function send_mail( array $late ) {
		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}
		$cron = self::cron_context();

		$body  = "De geplande scans van MCM Security draaien niet meer op tijd.\n";
		$body .= "Meestal betekent dat: WP-Cron loopt op deze site niet.\n\n";
		foreach ( $late as $s ) {
			$body .= sprintf(
				"- %s (%s): laatste automatische run %s, gepland voor %s\n",
				$s['label'],
				self::interval_label( $s['interval'] ),
				self::last_run_label( $s ),
				$s['next_run'] ? wp_date( 'd-m-Y H:i', $s['next_run'] ) : '—'
			);
		}
		$body .= "\nCron op deze site: {$cron['mode']}\n";
		$body .= sprintf( "Achterstallige geplande taken (alle plugins): %d\n", $cron['overdue'] );
		if ( $cron['oldest'] ) {
			$body .= sprintf( "Oudste: %s, gepland voor %s\n", $cron['oldest_hook'], wp_date( 'd-m-Y H:i', $cron['oldest'] ) );
		}
		$body .= "\n----\n";
		$body .= "ACTIE: controleer wat wp-cron.php aanroept (crontab, cron-job.org, host).\n";
		$body .= "Via SSH: wp cron event list  en  wp cron event run --due-now\n\n";
		$body .= "Deze melding komt maximaal 1× per dag zolang het probleem aanhoudt.";

		MCM_Notifier::email( 'Geplande scans lopen achter', $body );
	}

	public static function render_notice() {
		if ( ! self::is_enabled() || self::is_staging() || ! MCM_Notifier::should_show_admin_notice() ) {
			return;
		}
		$alarmed = array_filter( self::status(), function ( $s ) {
			return $s['alarm'];
		} );
		if ( empty( $alarmed ) ) {
			return;
		}

		$items = '';
		foreach ( $alarmed as $s ) {
			$items .= sprintf(
				'<li>%s (%s): laatste automatische run %s</li>',
				esc_html( $s['label'] ),
				esc_html( self::interval_label( $s['interval'] ) ),
				esc_html( self::last_run_label( $s ) )
			);
		}
		$cron = self::cron_context();

		printf(
			'<div class="notice notice-error"><p><strong>MCM Security: geplande scans lopen achter.</strong> Waarschijnlijk draait WP-Cron niet.</p><ul style="list-style:disc;margin-left:1.5em">%s</ul><p>Cron: %s. Achterstallige taken (alle plugins): %d. <a href="%s">Details</a></p></div>',
			$items,
			esc_html( $cron['mode'] ),
			(int) $cron['overdue'],
			esc_url( admin_url( 'tools.php?page=mcm-security#mcm-scan-watchdog' ) )
		);
	}

	/**
	 * Eén regel onder "Laatste scan" in een scanner-sectie van het dashboard.
	 *
	 * @param string $id Scan-id uit scans().
	 */
	public static function render_run_line( $id ) {
		$status = self::status();
		if ( ! self::is_enabled() || ! isset( $status[ $id ] ) || ! $status[ $id ]['enabled'] ) {
			return;
		}
		$s = $status[ $id ];
		if ( $s['alarm'] ) {
			$color = '#b32d2e';
			$text  = sprintf( '&#9888; Automatische scan loopt achter: laatst %s (hoort %s).', esc_html( self::last_run_label( $s ) ), esc_html( self::interval_label( $s['interval'] ) ) );
		} elseif ( $s['late'] ) {
			$color = '#bd8600';
			$text  = sprintf( 'Automatische scan over tijd: laatst %s (hoort %s). Nog even afwachten.', esc_html( self::last_run_label( $s ) ), esc_html( self::interval_label( $s['interval'] ) ) );
		} else {
			$color = '#646970';
			$text  = sprintf( 'Automatische scan: laatst %s (%s).', esc_html( self::last_run_label( $s ) ), esc_html( self::interval_label( $s['interval'] ) ) );
		}
		printf( '<p class="description" style="color:%s;">%s</p>', esc_attr( $color ), $text );
	}
}
