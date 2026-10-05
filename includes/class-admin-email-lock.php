<?php
/**
 * Vergrendel admin e-mail: het adres uit Instellingen → Algemeen ("E-mailadres
 * beheer", optie admin_email) is alleen nog via MCM te wijzigen.
 *
 * Aanleiding: tot en met 1.32.0 schreef deze instelling alleen
 * define( 'SECUPRESS_LOCKED_ADMIN_EMAIL', … ) in wp-config.php. Die constante
 * leest alleen SecuPress, dus zonder SecuPress deed het slot niets (5 okt 2026:
 * `wp option update admin_email` slaagde gewoon).
 *
 * Gedrag, alleen als lock_admin_email aan staat:
 *  - Het vergrendelde adres is het MCM-veld "Admin e-mail"
 *    ($settings['admin_email']). admin_email en new_admin_email (de wachtende
 *    wijziging waarvoor WordPress een bevestigingsmail stuurt) mogen alleen
 *    náár dat adres veranderen. Elke andere waarde wordt de oude waarde, via
 *    welke route ook: Instellingen → Algemeen, de bevestigingslink, WP-CLI,
 *    de REST API of code van een plugin.
 *  - Een ander adres in het MCM-veld gaat via WordPress' eigen
 *    bevestigingsmail naar het nieuwe adres. Pas na de klik gebruikt
 *    WordPress het, dus een tikfout verandert niets.
 *  - Het MCM-veld volgt WordPress: staat er geen bevestiging uit voor het
 *    MCM-adres, dan neemt opslaan het adres over dat WordPress gebruikt. De
 *    upgrade naar 1.33.0 doet dat één keer voor alle sites (upgrade()).
 *  - Bewust geen filter bij het lezen (pre_option_admin_email, zoals
 *    SecuPress): dat dwingt het adres af en zet een site die een ander adres
 *    gebruikt ongemerkt om.
 *  - Alleen het adres van de site, niet het netwerkadres van een multisite.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Admin_Email_Lock {

	const OPTION_KEY       = 'mcm_security_settings';
	const NOTICE_TRANSIENT = 'mcm_admin_email_notice_';

	public function __construct() {
		add_filter( 'pre_update_option_admin_email', [ __CLASS__, 'guard_admin_email' ], 10, 2 );
		add_filter( 'pre_update_option_new_admin_email', [ __CLASS__, 'guard_new_admin_email' ], 10, 2 );
		add_action( 'admin_notices', [ $this, 'render_notices' ] );
		add_action( 'admin_footer-options-general.php', [ $this, 'lock_general_field' ] );
	}

	/**
	 * Het vergrendelde adres.
	 *
	 * @return string|null null = slot uit; '' = slot aan maar geen geldig adres
	 *                     in MCM (dan blijft het huidige adres gewoon staan).
	 */
	public static function locked_address() {
		$settings = get_option( self::OPTION_KEY, [] );
		if ( empty( $settings['lock_admin_email'] ) ) {
			return null;
		}
		$email = isset( $settings['admin_email'] ) ? sanitize_email( $settings['admin_email'] ) : '';
		return is_email( $email ) ? $email : '';
	}

	/**
	 * pre_update_option_admin_email: alleen wijzigen naar het vergrendelde adres.
	 */
	public static function guard_admin_email( $value, $old_value ) {
		$locked = self::locked_address();
		if ( null === $locked || self::same( $value, $old_value ) || ( '' !== $locked && self::same( $value, $locked ) ) ) {
			return $value;
		}
		self::blocked( $value );
		return $old_value;
	}

	/**
	 * pre_update_option_new_admin_email: geen bevestigingsmail voor een ander
	 * adres. Het huidige adres mag altijd: Instellingen → Algemeen stuurt dat
	 * bij elke opslag mee, en WordPress doet er dan niets mee.
	 */
	public static function guard_new_admin_email( $value, $old_value ) {
		$locked = self::locked_address();
		if ( null === $locked
			|| self::same( $value, $old_value )
			|| self::same( $value, get_option( 'admin_email' ) )
			|| ( '' !== $locked && self::same( $value, $locked ) )
		) {
			return $value;
		}
		self::blocked( $value );
		return $old_value;
	}

	/**
	 * Vóór het opslaan van de MCM-instellingen: welk adres bewaart het veld?
	 *
	 * Het veld toont het adres dat WordPress gebruikt, of het adres waarvoor
	 * een bevestiging uitstaat. Staat er iets anders in en komt het uit het
	 * formulier, dan heeft iemand een nieuw adres ingevuld (after_save() vraagt
	 * de bevestiging aan). In alle andere gevallen volgt het veld WordPress,
	 * ook bij een profiel of "Activeer alles" zonder geldig adres.
	 *
	 * @param array $settings  Nieuwe instellingen.
	 * @param bool  $from_form Komt admin_email uit het formulier?
	 * @return array
	 */
	public static function reconcile( array $settings, $from_form ) {
		if ( empty( $settings['lock_admin_email'] ) ) {
			return $settings;
		}
		$current = (string) get_option( 'admin_email' );
		$wanted  = isset( $settings['admin_email'] ) ? sanitize_email( $settings['admin_email'] ) : '';

		if ( is_email( $wanted ) && ! self::same( $wanted, $current ) && ( $from_form || self::pending_for( $wanted ) ) ) {
			$settings['admin_email'] = $wanted;
		} else {
			$settings['admin_email'] = $current;
		}
		return $settings;
	}

	/**
	 * Na het opslaan: wijkt het MCM-adres af, laat WordPress dan een
	 * bevestigingsmail sturen. Is het gelijk, trek dan een wachtende wijziging
	 * naar een ander adres in (die kan toch niet meer doorgaan).
	 *
	 * Alleen vanuit wp-admin aanroepen: de mail komt van
	 * update_option_new_admin_email() uit admin-filters.php.
	 */
	public static function after_save() {
		$locked = self::locked_address();
		if ( ! $locked ) {
			return;
		}
		$current = (string) get_option( 'admin_email' );

		if ( self::same( $locked, $current ) ) {
			$pending = get_option( 'new_admin_email' );
			if ( $pending && ! self::same( $pending, $locked ) ) {
				delete_option( 'new_admin_email' );
			}
			$hash = get_option( 'adminhash' );
			if ( is_array( $hash ) && ! self::same( isset( $hash['newemail'] ) ? $hash['newemail'] : '', $locked ) ) {
				delete_option( 'adminhash' );
			}
			return;
		}

		if ( self::pending_for( $locked ) ) {
			return; // Mail is al onderweg; niet bij elke opslag opnieuw.
		}

		// Weghalen, anders telt dezelfde waarde als "niets gewijzigd" en
		// komt er geen mail.
		delete_option( 'new_admin_email' );
		update_option( 'new_admin_email', $locked );

		if ( self::pending_for( $locked ) ) {
			self::flash( 'info', sprintf( 'WordPress heeft een bevestigingsmail gestuurd naar %1$s. Tot er op de link in die mail geklikt is (ingelogd als beheerder), blijft %2$s het admin-e-mailadres.', $locked, $current ) );
		} else {
			self::flash( 'error', sprintf( 'Het admin-e-mailadres is niet gewijzigd: WordPress kon geen bevestigingsmail voor %s aanmaken. %s blijft het admin-e-mailadres.', $locked, $current ) );
		}
	}

	/**
	 * Wat het MCM-veld toont, en in welke toestand.
	 *
	 * @return array{state:string,value:string,current:string}
	 *               state: off | locked | pending | follow
	 */
	public static function field_state( $settings ) {
		$current = (string) get_option( 'admin_email' );
		$mcm     = is_array( $settings ) && isset( $settings['admin_email'] ) ? (string) $settings['admin_email'] : '';

		if ( ! is_array( $settings ) || empty( $settings['lock_admin_email'] ) ) {
			$state = 'off';
		} elseif ( self::same( $mcm, $current ) ) {
			$state = 'locked';
		} elseif ( is_email( $mcm ) && self::pending_for( $mcm ) ) {
			return [ 'state' => 'pending', 'value' => $mcm, 'current' => $current ];
		} else {
			$state = 'follow';
		}
		return [ 'state' => $state, 'value' => $current, 'current' => $current ];
	}

	/**
	 * Upgrade naar 1.33.0 (MCM_Upgrader): het MCM-veld en de database gelijk
	 * trekken met het adres dat de site nu echt gebruikt. Verandert dat adres
	 * zelf nooit.
	 *
	 * @return array{messages:string[],mail:string[]}
	 */
	public static function upgrade() {
		global $wpdb;

		$out      = [ 'messages' => [], 'mail' => [] ];
		$settings = get_option( self::OPTION_KEY, [] );
		if ( ! is_array( $settings ) || empty( $settings['lock_admin_email'] ) ) {
			return $out;
		}

		$effective = (string) get_option( 'admin_email' );
		$stored    = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", 'admin_email' ) );

		// SecuPress met de module "Lock Admin Email" geeft bij het lezen de
		// constante terug, niet de database. Die constante verdwijnt bij de
		// volgende "Opslaan & Toepassen"; zet het adres daarom nu in de
		// database, anders springt de site dan terug naar het oude adres.
		if ( is_email( $effective ) && ! self::same( $stored, $effective )
			&& defined( 'SECUPRESS_LOCKED_ADMIN_EMAIL' ) && self::same( SECUPRESS_LOCKED_ADMIN_EMAIL, $effective )
		) {
			$updated = $wpdb->update( $wpdb->options, [ 'option_value' => $effective ], [ 'option_name' => 'admin_email' ] );
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( 'admin_email', 'options' );
			if ( $updated ) {
				$out['messages'][] = sprintf( 'Admin-e-mailadres %s (via SecuPress) in de database gezet; daar stond %s.', $effective, $stored );
				$out['mail'][]     = sprintf( "Admin-e-mailadres: SecuPress gaf %s als admin-adres terug, maar in de database stond %s. MCM heeft %s in de database gezet, zodat het adres gelijk blijft als de SecuPress-constante uit wp-config.php verdwijnt.", $effective, $stored, $effective );
			} else {
				$out['messages'][] = sprintf( 'Admin-e-mailadres %s (via SecuPress) kon niet in de database worden gezet; daar staat %s.', $effective, $stored );
				$out['mail'][]     = sprintf( "Admin-e-mailadres: SecuPress geeft %s als admin-adres terug, maar in de database staat %s, en bijwerken lukte niet. Na de volgende \"Opslaan & Toepassen\" verdwijnt de SecuPress-constante en gebruikt WordPress %s. Zet het adres zo nodig met de hand goed.", $effective, $stored, $stored );
			}
		}

		$mcm = isset( $settings['admin_email'] ) ? (string) $settings['admin_email'] : '';
		if ( is_email( $effective ) && ! self::same( $mcm, $effective ) ) {
			$settings['admin_email'] = $effective;
			update_option( self::OPTION_KEY, $settings );
			if ( '' === $mcm ) {
				$out['messages'][] = sprintf( 'MCM-veld "Admin e-mail" was leeg; nu %s (het adres dat WordPress gebruikt).', $effective );
			} else {
				$out['messages'][] = sprintf( 'MCM-veld "Admin e-mail" van %s naar %s (het adres dat WordPress gebruikt).', $mcm, $effective );
				$out['mail'][]     = sprintf( "Admin-e-mailadres: het MCM-veld \"Admin e-mail\" zei %1\$s, maar WordPress gebruikt %2\$s. Het slot werkt vanaf nu echt en vergrendelt %2\$s; het MCM-veld is daarop aangepast. Moet het %1\$s zijn? Vul dat in bij Extra → MCM Security; WordPress stuurt dan eerst een bevestigingsmail naar %1\$s.", $mcm, $effective );
			}
		}

		if ( MCM_WPConfig_Manager::has_disabled_define( 'SECUPRESS_LOCKED_ADMIN_EMAIL' ) ) {
			$out['messages'][] = 'wp-config.php: uitgeschakelde SecuPress-regel voor het admin-e-mailadres gevonden; komt terug bij de volgende "Opslaan & Toepassen".';
			$out['mail'][]     = "In wp-config.php staat een door MCM uitgeschakelde regel \"// MCM_DISABLED: define( 'SECUPRESS_LOCKED_ADMIN_EMAIL', … )\". MCM beheert die constante niet meer, dus bij de volgende \"Opslaan & Toepassen\" wordt hij weer actief, zoals elke regel die MCM had uitgeschakeld. Zonder SecuPress doet hij niets; met SecuPress (module \"Lock Admin Email\") wordt dat adres het admin-adres. Gebruik je SecuPress niet meer, haal de regel dan weg.";
		}

		return $out;
	}

	public function render_notices() {
		$user_id = get_current_user_id();
		if ( $user_id ) {
			$notices = get_transient( self::NOTICE_TRANSIENT . $user_id );
			if ( is_array( $notices ) ) {
				delete_transient( self::NOTICE_TRANSIENT . $user_id );
				foreach ( $notices as $notice ) {
					printf(
						'<div class="notice notice-%s is-dismissible"><p><strong>MCM Security:</strong> %s</p></div>',
						esc_attr( $notice[0] ),
						esc_html( $notice[1] )
					);
				}
			}
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'options-general' !== $screen->id || null === self::locked_address() ) {
			return;
		}
		printf(
			'<div class="notice notice-info"><p>Het e-mailadres beheer (%s) is vergrendeld door MCM Security. Wijzigen kan via <a href="%s">Extra &rarr; MCM Security</a>; WordPress stuurt dan eerst een bevestigingsmail naar het nieuwe adres.</p></div>',
			esc_html( (string) get_option( 'admin_email' ) ),
			esc_url( admin_url( 'tools.php?page=mcm-security' ) )
		);
	}

	/**
	 * Het veld in Instellingen → Algemeen alleen-lezen maken. Gemak, geen
	 * beveiliging: die zit in de filters hierboven.
	 */
	public function lock_general_field() {
		if ( null === self::locked_address() ) {
			return;
		}
		?>
		<script>
		( function () {
			var field = document.getElementById( 'new_admin_email' );
			if ( field ) {
				field.readOnly = true;
				field.title = 'Vergrendeld door MCM Security';
			}
		} )();
		</script>
		<?php
	}

	/**
	 * Staat er een bevestiging uit (WordPress' adminhash) voor dit adres?
	 */
	private static function pending_for( $email ) {
		$hash = get_option( 'adminhash' );
		return is_array( $hash ) && ! empty( $hash['newemail'] ) && self::same( $hash['newemail'], $email );
	}

	private static function blocked( $attempted ) {
		$attempted = is_scalar( $attempted ) ? (string) $attempted : '';
		$message   = sprintf(
			'Het admin-e-mailadres is niet gewijzigd naar %s: het is vergrendeld. %s blijft het admin-e-mailadres. Wijzigen kan via Extra → MCM Security.',
			'' !== $attempted ? $attempted : '(leeg)',
			(string) get_option( 'admin_email' )
		);
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( 'WP_CLI' ) ) {
			WP_CLI::warning( $message );
		}
		self::flash( 'error', $message );
	}

	/**
	 * Melding voor de huidige gebruiker bij de volgende adminpagina.
	 */
	private static function flash( $type, $message ) {
		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			return;
		}
		$notices   = get_transient( self::NOTICE_TRANSIENT . $user_id );
		$notices   = is_array( $notices ) ? $notices : [];
		$notices[] = [ $type, $message ];
		set_transient( self::NOTICE_TRANSIENT . $user_id, $notices, 5 * MINUTE_IN_SECONDS );
	}

	private static function same( $a, $b ) {
		return is_string( $a ) && is_string( $b ) && '' !== trim( $a ) && strtolower( trim( $a ) ) === strtolower( trim( $b ) );
	}
}
