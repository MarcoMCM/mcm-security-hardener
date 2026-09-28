<?php
/**
 * Upgrade-routine: brengt bestaande sites na een plugin-update bij.
 *
 * Aanleiding: een update via WordPress/MainWP vervangt alleen de bestanden.
 * De .htaccess werd alleen herschreven bij activeren, opslaan, een profiel
 * kiezen of "Activeer alles", dus een gewijzigde of nieuwe regel (zoals de
 * robots.txt-fix in 1.30.0) bereikte bestaande sites nooit vanzelf.
 *
 * Gedrag:
 *  - Vergelijkt de opgeslagen versie met MCM_SECURITY_VERSION. Bij een
 *    verschil wordt één keer een wp-cron-event gepland, zodat de migratie
 *    niet in een bezoekersrequest draait.
 *  - Terugval: draait wp-cron niet (DISABLE_WP_CRON zonder servercron), dan
 *    start een admin-pageview de migratie zodra het event 10 minuten over
 *    tijd is.
 *  - Per versie een expliciete migratie (self::migrations()). Er worden
 *    bewust géén ontbrekende standaardwaarden aangevuld: dat kan onbedoeld
 *    regels aanzetten die iemand nooit heeft gekozen.
 *  - .htaccess wordt alleen herschreven als ons blok er al staat, en alleen
 *    met controle achteraf (loopback + automatisch terugzetten). wp-config.php
 *    wordt nooit aangeraakt.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Upgrader {

	const VERSION_OPTION = 'mcm_security_db_version';
	const RESULT_OPTION  = 'mcm_security_last_upgrade';
	const CRON_HOOK      = 'mcm_security_run_upgrade';
	const LOCK_KEY       = 'mcm_security_upgrade_lock';

	// Versie die we aannemen voor sites die al draaiden vóór deze routine bestond.
	const PRE_ROUTINE_VERSION = '1.29.0';

	public function __construct() {
		add_action( 'init', [ $this, 'maybe_schedule' ] );
		add_action( 'admin_init', [ $this, 'maybe_run_overdue' ] );
		add_action( self::CRON_HOOK, [ __CLASS__, 'run' ] );
		add_action( 'admin_notices', [ $this, 'render_failure_notice' ] );
	}

	/**
	 * Per versie: welke stappen zijn nodig om een site van de vorige versie
	 * bij te werken. 'settings' = callable die de instellingen aanpast
	 * (alleen ontbrekende sleutels!), 'htaccess' = .htaccess herschrijven.
	 */
	private static function migrations() {
		return [
			// robots.txt-fix in block_log_txt_files; geen nieuwe instellingen.
			'1.30.0' => [
				'htaccess' => true,
			],
		];
	}

	public static function stored_version() {
		$stored = get_option( self::VERSION_OPTION, '' );
		if ( '' !== $stored ) {
			return $stored;
		}
		// Bestaande installatie van vóór deze routine, of een verse installatie?
		return false === get_option( 'mcm_security_settings', false ) ? MCM_SECURITY_VERSION : self::PRE_ROUTINE_VERSION;
	}

	private static function is_pending() {
		return version_compare( self::stored_version(), MCM_SECURITY_VERSION, '<' );
	}

	public function maybe_schedule() {
		if ( '' === get_option( self::VERSION_OPTION, '' ) && ! self::is_pending() ) {
			// Verse installatie: versie vastleggen, niets te migreren.
			update_option( self::VERSION_OPTION, MCM_SECURITY_VERSION, true );
			return;
		}
		if ( self::is_pending() && ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_single_event( time(), self::CRON_HOOK );
		}
	}

	public function maybe_run_overdue() {
		if ( ! self::is_pending() || ! current_user_can( 'manage_options' ) || wp_doing_ajax() ) {
			return;
		}
		$next = wp_next_scheduled( self::CRON_HOOK );
		if ( $next && $next < time() - 10 * MINUTE_IN_SECONDS ) {
			wp_unschedule_event( $next, self::CRON_HOOK );
			self::run();
		}
	}

	/**
	 * Voer alle openstaande migraties uit.
	 */
	public static function run() {
		if ( ! self::is_pending() || get_transient( self::LOCK_KEY ) ) {
			return;
		}
		set_transient( self::LOCK_KEY, 1, 5 * MINUTE_IN_SECONDS );

		$from     = self::stored_version();
		$original = get_option( 'mcm_security_settings', [] );
		$settings = $original;
		$htaccess = false;
		$written  = null;

		foreach ( self::migrations() as $version => $steps ) {
			if ( version_compare( $from, $version, '>=' ) || version_compare( $version, MCM_SECURITY_VERSION, '>' ) ) {
				continue;
			}
			if ( ! empty( $steps['settings'] ) && is_callable( $steps['settings'] ) ) {
				$settings = call_user_func( $steps['settings'], $settings );
			}
			if ( ! empty( $steps['htaccess'] ) ) {
				$htaccess = true;
			}
		}

		if ( $settings !== $original ) {
			update_option( 'mcm_security_settings', $settings );
		}

		$result = [
			'from'    => $from,
			'to'      => MCM_SECURITY_VERSION,
			'time'    => time(),
			'status'  => 'ok',
			'message' => '',
		];

		if ( $htaccess ) {
			if ( ! MCM_Htaccess_Manager::is_active() ) {
				$result['message'] = '.htaccess overgeslagen: het MCM-blok staat niet in de .htaccess (bewust verwijderd of nooit toegepast).';
			} else {
				$written = MCM_Htaccess_Manager::write( $settings, true );
				if ( is_wp_error( $written ) ) {
					$result['status']  = 'failed';
					$result['message'] = $written->get_error_message();
				} else {
					$result['message'] = '.htaccess bijgewerkt en gecontroleerd.';
				}
			}
		}

		// Versie altijd ophogen, ook bij een mislukte .htaccess-stap: anders
		// probeert elke pageview het opnieuw (loopbacks + mails). De
		// mislukking blijft zichtbaar via mail en admin-melding; opnieuw
		// opslaan in de instellingen past de regels alsnog toe.
		update_option( self::VERSION_OPTION, MCM_SECURITY_VERSION, true );
		update_option( self::RESULT_OPTION, $result, false );
		delete_transient( self::LOCK_KEY );

		// Bij 'reverted' heeft de htaccess-manager zelf al gemaild.
		if ( 'failed' === $result['status'] && 'reverted' !== $written->get_error_code() ) {
			MCM_Notifier::email(
				sprintf( 'Upgrade naar %s: .htaccess niet bijgewerkt', MCM_SECURITY_VERSION ),
				"De automatische upgrade van MCM Security Hardener ({$from} → " . MCM_SECURITY_VERSION . ") kon de .htaccess niet bijwerken.\n\n" .
				'Reden: ' . $result['message'] . "\n\n" .
				"De oude regels staan er nog. Open Extra → MCM Security en klik \"Opslaan & Toepassen\" om ze handmatig bij te werken."
			);
		}
	}

	public function render_failure_notice() {
		if ( ! MCM_Notifier::should_show_admin_notice() ) {
			return;
		}
		$result = get_option( self::RESULT_OPTION, [] );
		if ( empty( $result['status'] ) || 'failed' !== $result['status'] || MCM_SECURITY_VERSION !== $result['to'] ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p><strong>MCM Security %s: .htaccess niet automatisch bijgewerkt.</strong> %s <a href="%s">Naar de instellingen</a> en klik &ldquo;Opslaan &amp; Toepassen&rdquo;.</p></div>',
			esc_html( MCM_SECURITY_VERSION ),
			esc_html( $result['message'] ),
			esc_url( admin_url( 'tools.php?page=mcm-security' ) )
		);
	}

	/**
	 * Na een geslaagde handmatige toepassing is een eerdere mislukte
	 * upgrade-stap achterhaald.
	 */
	public static function clear_failure() {
		$result = get_option( self::RESULT_OPTION, [] );
		if ( ! empty( $result['status'] ) && 'failed' === $result['status'] ) {
			$result['status'] = 'resolved';
			update_option( self::RESULT_OPTION, $result, false );
		}
	}
}
