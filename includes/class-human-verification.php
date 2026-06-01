<?php
/**
 * Human Verification — SecuPress-stijl.
 *
 * Een visuele "vink-checkbox" die via pure CSS-animatie na X seconden
 * vanzelf wordt aangevinkt. Geen JavaScript vereist.
 *
 * Server-side validatie kijkt alleen naar timing:
 *   - Form moet minimaal $delay seconden geleden gerenderd zijn
 *   - Form moet minder dan 1 uur geleden gerenderd zijn (replay-bescherming)
 *   - HMAC-signature op de timestamp moet kloppen (forgery-bescherming)
 *
 * Bots die direct submitten falen op de delay; bots die een willekeurige
 * timestamp meesturen falen op de signature.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Human_Verification {

	const FIELD_TS  = 'mcm_hv_ts';
	const FIELD_SIG = 'mcm_hv_sig';

	private $settings = [];
	private $delay    = 3;

	public function __construct() {
		$this->settings = get_option( 'mcm_security_settings', [] );

		if ( empty( $this->settings['human_verification'] ) ) {
			return;
		}

		$this->delay = max( 1, min( 30, (int) ( $this->settings['human_verification_delay'] ?? 3 ) ) );

		// Render veld op login-, registratie- en wachtwoord-vergeten-formulieren.
		// WordPress core (wp-login.php):
		add_action( 'login_form',            [ $this, 'render_field' ] );
		add_action( 'register_form',         [ $this, 'render_field' ] );
		add_action( 'lostpassword_form',     [ $this, 'render_field' ] );
		add_action( 'login_enqueue_scripts', [ $this, 'enqueue_styles' ] );

		// WooCommerce (my-account/login + lost-password). Zonder deze hooks
		// werd de validatie via 'authenticate' wél uitgevoerd maar het veld
		// niet getoond — klanten kregen dan "verificatie niet voltooid" zonder
		// dat ze ooit het vinkje gezien hadden.
		add_action( 'woocommerce_login_form',        [ $this, 'render_field' ] );
		add_action( 'woocommerce_register_form',     [ $this, 'render_field' ] );
		add_action( 'woocommerce_lostpassword_form', [ $this, 'render_field' ] );

		// Server-side validatie. Priority 30 = NA WP's eigen credential-check
		// (wp_authenticate_username_password staat op 20 en overschrijft een WP_Error
		// die eerder in de chain is gezet). Onze HV-error overrult dus altijd het
		// resultaat — ook als de credentials kloppen.
		add_filter( 'authenticate',        [ $this, 'validate_login' ], 30, 3 );
		add_filter( 'registration_errors', [ $this, 'validate_register' ], 10, 1 );
		add_action( 'lostpassword_post',   [ $this, 'validate_lostpassword' ], 10, 1 );
	}

	/**
	 * Render het verificatie-veld in een login-/register-/lostpw-formulier.
	 */
	public function render_field() {
		// Zorg dat de CSS aanwezig is, ook op pagina's waar login_enqueue_scripts
		// niet draait (zoals WooCommerce my-account). enqueue_styles() is
		// idempotent — print de stijl maar één keer per request.
		$this->enqueue_styles();

		$ts  = time();
		$sig = $this->sign( $ts );
		?>
		<div id="mcm-hv-row" class="mcm-hv-row">
			<span class="mcm-hv-box" aria-hidden="true">
				<svg class="mcm-hv-tick" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
					<path d="M5 12 L10 17 L19 7" />
				</svg>
			</span>
			<span class="mcm-hv-states">
				<span class="mcm-hv-state mcm-hv-wait">Even verifi&euml;ren&hellip;</span>
				<span class="mcm-hv-state mcm-hv-ok">Geverifieerd &mdash; je bent een mens.</span>
				<span class="mcm-hv-state mcm-hv-expired">Verlopen &mdash; ververs de pagina.</span>
			</span>
			<input type="hidden" name="<?php echo esc_attr( self::FIELD_TS ); ?>" value="<?php echo esc_attr( $ts ); ?>" />
			<input type="hidden" name="<?php echo esc_attr( self::FIELD_SIG ); ?>" value="<?php echo esc_attr( $sig ); ?>" />
		</div>
		<?php
	}

	/**
	 * Inline CSS — pure animaties, geen JS, geen externe assets.
	 *
	 * Idempotent: print de stijl maar één keer per request, ongeacht hoe
	 * vaak deze methode wordt aangeroepen (login_enqueue_scripts hook +
	 * render_field-fallback voor WooCommerce-context).
	 */
	public function enqueue_styles() {
		static $printed = false;
		if ( $printed ) {
			return;
		}
		$printed = true;

		$delay   = (int) $this->delay;
		$expires = (int) HOUR_IN_SECONDS;
		?>
		<style id="mcm-hv-css">
			#mcm-hv-row.mcm-hv-row {
				box-sizing: border-box;
				display: flex;
				align-items: center;
				gap: 14px;
				width: 100%;
				min-height: 48px;
				padding: 12px 16px;
				margin: 0 0 24px;
				background: #f6f7f7;
				border: 1px solid #8c8f94;
				border-radius: 4px;
				font-size: 14px;
				line-height: 1.4;
				color: #2c3338;
				transition: background 0.4s ease, border-color 0.4s ease;
				animation: mcm-hv-bg-ok 0s step-end forwards <?php echo $delay; ?>s,
				           mcm-hv-bg-expired 0s step-end forwards <?php echo $expires; ?>s;
			}
			#mcm-hv-row .mcm-hv-box {
				flex: 0 0 26px;
				width: 26px;
				height: 26px;
				border: 2px solid #8c8f94;
				border-radius: 4px;
				background: #fff;
				display: inline-flex;
				align-items: center;
				justify-content: center;
				transition: border-color 0.3s ease;
				animation: mcm-hv-border-ok 0s step-end forwards <?php echo $delay; ?>s,
				           mcm-hv-border-expired 0s step-end forwards <?php echo $expires; ?>s;
			}
			#mcm-hv-row .mcm-hv-tick {
				width: 20px;
				height: 20px;
				display: block;
			}
			#mcm-hv-row .mcm-hv-tick path {
				fill: none;
				stroke: #46b450;
				stroke-width: 3;
				stroke-linecap: round;
				stroke-linejoin: round;
				stroke-dasharray: 30;
				stroke-dashoffset: 30;
				animation: mcm-hv-draw 0.5s ease-out forwards <?php echo $delay; ?>s,
				           mcm-hv-undraw 0s step-end forwards <?php echo $expires; ?>s;
			}
			#mcm-hv-row .mcm-hv-states {
				position: relative;
				flex: 1 1 auto;
				height: 26px;
			}
			#mcm-hv-row .mcm-hv-state {
				position: absolute;
				inset: 0;
				display: flex;
				align-items: center;
				opacity: 0;
				visibility: hidden;
			}
			#mcm-hv-row .mcm-hv-wait {
				opacity: 1;
				visibility: visible;
				animation: mcm-hv-fade-out 0s step-end forwards <?php echo $delay; ?>s;
			}
			#mcm-hv-row .mcm-hv-ok {
				animation: mcm-hv-fade-in 0s step-end forwards <?php echo $delay; ?>s,
				           mcm-hv-fade-out 0s step-end forwards <?php echo $expires; ?>s;
			}
			#mcm-hv-row .mcm-hv-expired {
				color: #b32d2e;
				font-weight: 600;
				animation: mcm-hv-fade-in 0s step-end forwards <?php echo $expires; ?>s;
			}

			@keyframes mcm-hv-draw    { to { stroke-dashoffset: 0; } }
			@keyframes mcm-hv-undraw  { to { stroke-dashoffset: 30; } }
			@keyframes mcm-hv-fade-in   { to { opacity: 1; visibility: visible; } }
			@keyframes mcm-hv-fade-out  { to { opacity: 0; visibility: hidden; } }
			@keyframes mcm-hv-bg-ok       { to { background: #edfaef; border-color: #46b450; } }
			@keyframes mcm-hv-bg-expired  { to { background: #fdf2f2; border-color: #b32d2e; } }
			@keyframes mcm-hv-border-ok       { to { border-color: #46b450; } }
			@keyframes mcm-hv-border-expired  { to { border-color: #b32d2e; } }
		</style>
		<?php
	}

	/**
	 * Login-validatie. Draait vóór WP's eigen credential-check.
	 */
	public function validate_login( $user, $username, $password ) {
		// Geen daadwerkelijke loginpoging — niets te valideren.
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		if ( ! $this->is_valid_submission() ) {
			return new WP_Error(
				'mcm_hv_failed',
				'<strong>Inloggen mislukt</strong> &mdash; de menselijke verificatie was nog niet voltooid. Wacht tot het vinkje gezet is en probeer het opnieuw.'
			);
		}

		return $user;
	}

	/**
	 * Registratie-validatie.
	 */
	public function validate_register( $errors ) {
		if ( ! $this->is_valid_submission() ) {
			$errors->add(
				'mcm_hv_failed',
				'<strong>Registratie mislukt</strong> &mdash; de menselijke verificatie was nog niet voltooid. Wacht tot het vinkje gezet is en probeer het opnieuw.'
			);
		}
		return $errors;
	}

	/**
	 * Wachtwoord-vergeten-validatie.
	 */
	public function validate_lostpassword( $errors ) {
		if ( ! is_wp_error( $errors ) ) {
			return;
		}
		if ( ! $this->is_valid_submission() ) {
			$errors->add(
				'mcm_hv_failed',
				'<strong>Aanvraag mislukt</strong> &mdash; de menselijke verificatie was nog niet voltooid. Wacht tot het vinkje gezet is en probeer het opnieuw.'
			);
		}
	}

	/**
	 * Centrale check: signature klopt + timing klopt.
	 */
	private function is_valid_submission() {
		$ts  = isset( $_POST[ self::FIELD_TS ] ) ? (int) $_POST[ self::FIELD_TS ] : 0;
		$sig = isset( $_POST[ self::FIELD_SIG ] ) ? (string) wp_unslash( $_POST[ self::FIELD_SIG ] ) : '';

		if ( $ts <= 0 || empty( $sig ) ) {
			return false;
		}

		// Signature moet kloppen (voorkomt forgery met willekeurige timestamp).
		if ( ! hash_equals( $this->sign( $ts ), $sig ) ) {
			return false;
		}

		$age = time() - $ts;

		// Te snel = bot heeft geen tijd gehad om de animatie af te wachten.
		if ( $age < $this->delay ) {
			return false;
		}

		// Te oud = pagina meer dan een uur geleden geladen → mogelijk replay.
		if ( $age > HOUR_IN_SECONDS ) {
			return false;
		}

		return true;
	}

	/**
	 * HMAC over de timestamp met AUTH_KEY als secret.
	 */
	private function sign( $ts ) {
		$key = ( defined( 'AUTH_KEY' ) && AUTH_KEY ) ? AUTH_KEY : 'mcm-hv-fallback-key';
		return hash_hmac( 'sha256', 'mcm-hv:' . $ts, $key );
	}
}
