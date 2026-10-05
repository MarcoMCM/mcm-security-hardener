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
 *    met controle achteraf (loopback + automatisch terugzetten).
 *  - wp-config.php wordt alleen aangeraakt voor de reparatie uit 1.31.1, en
 *    alleen als de foutsignatuur erin staat en ons blok actief is. Het
 *    bestaande blok gaat ongewijzigd terug (opgeslagen maar nog niet
 *    toegepaste instellingen worden niet meegenomen), met dezelfde
 *    syntaxcontrole en back-up als bij "Opslaan & Toepassen". Elke reparatie
 *    wordt gemaild.
 *  - 1.32.0 ruimt onze eigen achtergebleven kopie wp-config.php.mcm-backup
 *    op: die wordt verplaatst naar de afgeschermde back-upmap
 *    (MCM_Backup_Store::migrate_legacy()).
 *  - 1.33.0 trekt het MCM-veld "Admin e-mail" (en bij SecuPress de
 *    database) gelijk met het admin-adres dat de site nu gebruikt
 *    (MCM_Admin_Email_Lock::upgrade()). Dat adres zelf verandert niet.
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
	 * (alleen ontbrekende sleutels!), 'htaccess' = .htaccess herschrijven,
	 * 'wpconfig_repair' = wp-config.php herstellen als de fout uit
	 * comment_out_constants() (t/m 1.31.0) er sporen heeft achtergelaten,
	 * 'legacy_backups' = oude back-ups omzetten (MCM_Backup_Store),
	 * 'admin_email_lock' = MCM-veld "Admin e-mail" gelijktrekken
	 * (MCM_Admin_Email_Lock).
	 */
	private static function migrations() {
		return [
			// robots.txt-fix in block_log_txt_files; geen nieuwe instellingen.
			'1.30.0' => [
				'htaccess' => true,
			],
			// Dubbele define()s: een lege regel boven een define() kreeg de
			// MCM_DISABLED-markering en de define() bleef actief.
			'1.31.1' => [
				'wpconfig_repair' => true,
			],
			// Exposure-scanner: het nieuwe back-upmappen-niveau, plus de twee
			// niveaus uit 1.21.0 die op oudere sites nooit in de DB zijn gezet.
			// De scanner valt bij een ontbrekende sleutel al terug op "aan",
			// maar het dashboard toonde de schakelaar dan uit, en één keer
			// opslaan zette het niveau ongemerkt uit. Alleen detectie, dus
			// aanvullen zet geen regels aan.
			'1.32.0' => [
				'settings' => function ( $settings ) {
					if ( ! is_array( $settings ) ) {
						return $settings;
					}
					foreach ( [ 'exposure_scan_uploads', 'exposure_scan_above_root', 'exposure_scan_backup_dirs' ] as $key ) {
						if ( ! array_key_exists( $key, $settings ) ) {
							$settings[ $key ] = true;
						}
					}
					return $settings;
				},
				// wp-config.php.mcm-backup stond publiek in de webroot (platte
				// tekst: DB-credentials + salts). Verplaatsen naar de back-upmap,
				// samen met de oude .bak/.sql-back-ups daar (op nginx publiek).
				'legacy_backups' => true,
			],
			// "Vergrendel admin e-mail" werkt nu echt. Het slot bewaakt het
			// MCM-veld, dus dat moet eerst het adres zijn dat de site
			// gebruikt, anders zou een latere opslag het adres omzetten.
			'1.33.0' => [
				'admin_email_lock' => true,
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
		$wpconfig = false;
		$legacy   = false;
		$email    = false;

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
			if ( ! empty( $steps['wpconfig_repair'] ) ) {
				$wpconfig = true;
			}
			if ( ! empty( $steps['legacy_backups'] ) ) {
				$legacy = true;
			}
			if ( ! empty( $steps['admin_email_lock'] ) ) {
				$email = true;
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
		$messages = [];
		$mail     = []; // Alinea's voor de mail; leeg = geen mail.
		$subjects = []; // Onderwerp van die mail als niets mislukt is.

		if ( $htaccess ) {
			if ( ! MCM_Htaccess_Manager::is_active() ) {
				$messages[] = '.htaccess overgeslagen: het MCM-blok staat niet in de .htaccess (bewust verwijderd of nooit toegepast).';
			} else {
				$written = MCM_Htaccess_Manager::write( $settings, true );
				if ( is_wp_error( $written ) ) {
					$result['status'] = 'failed';
					$messages[]       = $written->get_error_message();
					// Bij 'reverted' heeft de htaccess-manager zelf al gemaild.
					if ( 'reverted' !== $written->get_error_code() ) {
						$mail[] = "De .htaccess kon niet worden bijgewerkt. De oude regels staan er nog.\nReden: " . $written->get_error_message();
					}
				} else {
					$messages[] = '.htaccess bijgewerkt en gecontroleerd.';
				}
			}
		}

		// Mislukt omzetten verandert de status niet: dan staat het oude
		// bestand er gewoon nog (en meldt de exposure-scanner het). Wel een
		// mail, want een wp-config-kopie in de webroot is een lek.
		$legacy_failed = [];
		if ( $legacy ) {
			$legacy_result = MCM_Backup_Store::migrate_legacy();
			$notes = [];
			if ( $legacy_result['moved'] ) {
				$notes[] = sprintf( '%d oude back-up(s) omgezet naar uploads/%s/.', $legacy_result['moved'], MCM_Backup_Store::DIR );
			}
			if ( $legacy_result['failed'] ) {
				$legacy_failed = $legacy_result['failed'];
				$notes[]       = 'Niet omgezet, staat er nog: ' . implode( ', ', $legacy_failed ) . '.';
			}
			$messages = array_merge( $messages, $notes );
		}

		if ( $wpconfig && MCM_WPConfig_Manager::needs_marker_repair() ) {
			if ( ! MCM_WPConfig_Manager::is_active() ) {
				// Kan alleen als iemand het blok met de hand heeft weggehaald.
				$messages[] = 'wp-config.php: lege MCM_DISABLED-regels gevonden, maar het MCM-blok staat er niet. Niet aangeraakt.';
				$mail[]     = "In wp-config.php staan lege \"// MCM_DISABLED: \"-regels, maar het MCM-blok staat er niet. Er is niets gewijzigd; kijk het bestand na.";
				$subjects[] = 'wp-config.php nakijken';
			} else {
				$repaired = MCM_WPConfig_Manager::repair_markers();
				if ( true === $repaired ) {
					$messages[] = 'wp-config.php hersteld: dubbele define()s uitgeschakeld.';
					$subjects[] = 'wp-config.php hersteld';
					$mail[]     = "wp-config.php is hersteld. Door een fout in eerdere versies stond een constante twee keer in het bestand (PHP-waarschuwing \"already defined\" bij elke request). De dubbele define() is nu uitgeschakeld; het MCM-blok is ongewijzigd. Vorige versie: de nieuwste wp-config-*.php in uploads/" . MCM_Backup_Store::DIR . "/ (herstellen = eerste regel weghalen).";
				} else {
					$reason           = is_wp_error( $repaired ) ? $repaired->get_error_message() : 'wp-config.php kon niet worden geschreven.';
					$result['status'] = 'failed';
					$messages[]       = 'wp-config.php niet hersteld: ' . $reason;
					$mail[]           = "wp-config.php kon niet worden hersteld (dubbele define()s uit eerdere versies). Er is niets gewijzigd.\nReden: " . $reason;
				}
			}
		}

		// Alleen bij een afwijking een mail; op een site waar alles al klopt
		// gebeurt er niets.
		if ( $email ) {
			$lock     = MCM_Admin_Email_Lock::upgrade();
			$messages = array_merge( $messages, $lock['messages'] );
			if ( $lock['mail'] ) {
				$mail       = array_merge( $mail, $lock['mail'] );
				$subjects[] = 'admin-e-mailadres nagelopen';
			}
		}

		$result['message'] = implode( ' ', $messages );

		// Versie altijd ophogen, ook bij een mislukte stap: anders probeert
		// elke pageview het opnieuw (loopbacks + mails). De mislukking blijft
		// zichtbaar via mail en admin-melding; opnieuw opslaan in de
		// instellingen past de regels alsnog toe.
		update_option( self::VERSION_OPTION, MCM_SECURITY_VERSION, true );
		update_option( self::RESULT_OPTION, $result, false );
		delete_transient( self::LOCK_KEY );

		if ( $mail ) {
			MCM_Notifier::email(
				sprintf( 'Upgrade naar %s: %s', MCM_SECURITY_VERSION, 'failed' === $result['status'] ? 'niet alles bijgewerkt' : implode( ', ', $subjects ) ),
				"Automatische upgrade van MCM Security Hardener ({$from} → " . MCM_SECURITY_VERSION . ").\n\n" .
				implode( "\n\n", $mail ) .
				( 'failed' === $result['status'] ? "\n\nOpen Extra → MCM Security en klik \"Opslaan & Toepassen\" om de regels handmatig bij te werken." : '' )
			);
		}

		if ( $legacy_failed ) {
			MCM_Notifier::email(
				sprintf( 'Upgrade naar %s: oude back-up niet opgeruimd', MCM_SECURITY_VERSION ),
				"De automatische upgrade van MCM Security Hardener kon deze oude back-up(s) niet verplaatsen:\n\n" .
				implode( "\n", $legacy_failed ) . "\n\n" .
				"Een wp-config.php.mcm-backup is publiek op te vragen en bevat de DB-gegevens en salts: verwijder die handmatig (FTP/SSH), " .
				"wp-config.php zelf staat er gewoon naast. Een .bak of .sql in uploads/" . MCM_Backup_Store::DIR . "/ is alleen op nginx publiek; " .
				"verwijder of verplaats die als je hem niet meer nodig hebt."
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
			'<div class="notice notice-warning"><p><strong>MCM Security %s: niet alles automatisch bijgewerkt.</strong> %s <a href="%s">Naar de instellingen</a> en klik &ldquo;Opslaan &amp; Toepassen&rdquo;.</p></div>',
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
