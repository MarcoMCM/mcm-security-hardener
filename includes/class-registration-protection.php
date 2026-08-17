<?php
/**
 * Registratiebescherming — honeypot + wegwerpdomein-filter.
 *
 * Verbreding van de powair-aanpak naar zowel WordPress-standaard registratie
 * als WooCommerce-registratie.
 *
 * - Honeypot: een verborgen veld dat echte bezoekers nooit zien maar bots wel
 *   invullen. Gevuld veld → registratie geweigerd.
 * - Wegwerpdomein-filter: weigert registratie met tijdelijke/wegwerp-emailadressen.
 *
 * Beide los aan/uit via instellingen. Werkt naast Human Verification (die doet
 * timing-validatie; deze doet honeypot + domein — complementair).
 *
 * Filters:
 *   - 'mcm_blocked_email_domains' → pas de domein-lijst programmatisch aan
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Registration_Protection {

	/** Veldnaam die voor bots als een echt veld oogt. */
	const HONEYPOT_FIELD = 'mcm_contact_url';

	private $settings = [];

	public function __construct() {
		$this->settings = get_option( 'mcm_security_settings', [] );

		// Gereserveerde gebruikersnamen blokkeren. Staat vóór de early return:
		// deze bescherming is onafhankelijk van honeypot/wegwerpdomein.
		if ( $this->reserved_logins_enabled() ) {
			add_filter( 'illegal_user_logins', [ $this, 'add_illegal_user_logins' ] );
		}

		$honeypot_on   = ! empty( $this->settings['registration_honeypot'] );
		$disposable_on = ! empty( $this->settings['block_disposable_email'] );

		if ( ! $honeypot_on && ! $disposable_on ) {
			return; // Niets meer te doen.
		}

		// Honeypot-veld renderen op beide registratieformulieren.
		if ( $honeypot_on ) {
			add_action( 'register_form', [ $this, 'render_honeypot' ] );
			add_action( 'woocommerce_register_form', [ $this, 'render_honeypot' ] );
		}

		// Validatie op beide registratie-flows. Eén functie, beide hooks hebben
		// dezelfde signature ($errors, $username, $email).
		add_filter( 'registration_errors', [ $this, 'validate' ], 10, 3 );
		add_filter( 'woocommerce_registration_errors', [ $this, 'validate' ], 10, 3 );
	}

	/**
	 * Staat de reserved-logins-bescherming aan?
	 *
	 * Met terugval op de plugin-default, zodat de bescherming ook werkt op
	 * sites die van een oudere versie updaten en de key nog niet in de DB
	 * hebben staan.
	 */
	private function reserved_logins_enabled() {
		if ( array_key_exists( 'block_reserved_logins', (array) $this->settings ) ) {
			return ! empty( $this->settings['block_reserved_logins'] );
		}
		$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
			? MCM_Security_Hardener::get_defaults()
			: [];
		return ! empty( $defaults['block_reserved_logins'] );
	}

	/**
	 * Voegt onze gereserveerde namen toe aan WordPress' eigen blokkeerlijst.
	 *
	 * WordPress past 'illegal_user_logins' toe in wp_insert_user() én in de
	 * registratievalidatie, dus dit dekt in één keer: WP-registratie,
	 * WooCommerce-klantregistratie (die loopt via wp_insert_user) én een
	 * handmatig aangemaakte gebruiker in de backend.
	 *
	 * Waarom preventie en niet alleen detectie: op susenso.nl had een bot in
	 * oktober 2025 de login 'admin' geclaimd (rol customer, geen orders, geen
	 * content). Achteraf opruimen kan altijd, maar dan is de naam al bezet en
	 * meldt elke beveiligingsscan hem terecht.
	 *
	 * BESTAANDE accounts worden hier niet door geraakt — een filter op
	 * registratie kan niets veranderen aan wat er al staat. Die staan in de
	 * user-audit op de instellingenpagina.
	 *
	 * Let op: dit blokkeert de naam ook voor jezelf in de backend. Aanpassen
	 * kan met het filter 'mcm_security_reserved_logins'.
	 *
	 * @param array $logins Bestaande verboden logins.
	 * @return array
	 */
	public function add_illegal_user_logins( $logins ) {
		if ( ! class_exists( 'MCM_User_Audit' ) ) {
			return $logins;
		}
		return array_values( array_unique( array_merge(
			(array) $logins,
			MCM_User_Audit::reserved_login_names()
		) ) );
	}

	/**
	 * Render het verborgen honeypot-veld. Off-screen + aria-hidden + tabindex -1
	 * zodat echte bezoekers (en screenreaders) het overslaan.
	 */
	public function render_honeypot() {
		$field = esc_attr( self::HONEYPOT_FIELD );
		?>
		<div class="mcm-regbescherming-veld" aria-hidden="true" style="position:absolute !important;left:-9999px !important;top:-9999px !important;height:0;width:0;overflow:hidden;">
			<label for="<?php echo $field; ?>">Vul dit veld niet in</label>
			<input type="text" name="<?php echo $field; ?>" id="<?php echo $field; ?>" value="" tabindex="-1" autocomplete="off" />
		</div>
		<?php
	}

	/**
	 * De wegwerpdomein-lijst: ingebouwde defaults + eigen domeinen uit de
	 * instellingen (textarea) + filter.
	 *
	 * @return string[] Lowercase domeinen.
	 */
	public function blocked_domains() {
		$defaults = [
			'a7gi.ru', 'mailinator.com', 'guerrillamail.com', 'guerrillamail.info',
			'sharklasers.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org',
			'trashmail.com', 'yopmail.com', 'getnada.com', 'dispostable.com',
			'maildrop.cc', 'fakeinbox.com', 'mailnesia.com', 'throwawaymail.com',
		];

		$custom_raw = ! empty( $this->settings['disposable_email_list'] )
			? (string) $this->settings['disposable_email_list']
			: '';
		$custom = array_filter( array_map( 'trim', explode( "\n", $custom_raw ) ) );

		$all = array_merge( $defaults, $custom );
		$all = apply_filters( 'mcm_blocked_email_domains', $all );

		return array_map( 'strtolower', (array) $all );
	}

	/**
	 * Validatie voor zowel WP- als WooCommerce-registratie.
	 *
	 * @param WP_Error $errors   Bestaande errors.
	 * @param string   $username Ingevulde username.
	 * @param string   $email    Ingevuld emailadres.
	 * @return WP_Error
	 */
	public function validate( $errors, $username, $email ) {
		if ( ! is_wp_error( $errors ) ) {
			$errors = new WP_Error();
		}

		// 1. Honeypot — gevuld = bot.
		if ( ! empty( $this->settings['registration_honeypot'] ) ) {
			$honeypot = isset( $_POST[ self::HONEYPOT_FIELD ] )
				? trim( wp_unslash( $_POST[ self::HONEYPOT_FIELD ] ) )
				: '';
			if ( '' !== $honeypot ) {
				$errors->add(
					'mcm_honeypot',
					__( 'Je registratie kon niet worden verwerkt. Probeer het opnieuw of neem contact met ons op.', 'mcm-security-hardener' )
				);
				return $errors; // Direct stoppen — duidelijke bot.
			}
		}

		// 2. Wegwerpdomein.
		if ( ! empty( $this->settings['block_disposable_email'] ) && ! empty( $email ) ) {
			$email_clean = strtolower( trim( $email ) );
			$at_pos      = strrpos( $email_clean, '@' );
			if ( false !== $at_pos ) {
				$domain = substr( $email_clean, $at_pos + 1 );
				if ( in_array( $domain, $this->blocked_domains(), true ) ) {
					$errors->add(
						'mcm_wegwerpdomein',
						__( 'Gebruik a.u.b. een geldig, persoonlijk e-mailadres. Tijdelijke of wegwerp-e-mailadressen worden niet geaccepteerd.', 'mcm-security-hardener' )
					);
				}
			}
		}

		return $errors;
	}
}
