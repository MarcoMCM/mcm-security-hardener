<?php
/**
 * WP_DEBUG productie-watchdog.
 *
 * Waarschuwt als WP_DEBUG=true draait op een productie-omgeving. PHP-notices op
 * productie kunnen paden, queries en stack traces lekken — klassieke info disclosure.
 *
 * Gedrag:
 *  - Admin notice (rood/oranje) bovenaan elke admin-pagina, alleen voor MCM-eigenaars.
 *  - 1× per 24u e-mail naar de notify-recipient (zelfde adres als andere security mails).
 *  - Detecteert ook of WP_DEBUG_DISPLAY aan staat (= leak naar bezoekers, kritiek).
 *
 * Uit te schakelen via:
 *  - Filter 'mcm_security_debug_watchdog_enabled' → false
 *  - Constant MCM_SECURITY_DISABLE_DEBUG_WATCHDOG in wp-config.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Debug_Watchdog {

	const EMAIL_THROTTLE_KEY = 'mcm_security_debug_watchdog_mailed';
	const EMAIL_THROTTLE_TTL = DAY_IN_SECONDS;
	const ACTION_DISABLE     = 'mcm_disable_wp_debug';

	public function __construct() {
		add_action( 'admin_init', [ $this, 'check' ] );
		add_action( 'admin_post_' . self::ACTION_DISABLE, [ $this, 'handle_disable' ] );
	}

	/**
	 * "Zet WP_DEBUG uit"-knop uit de melding: zet de instelling op 'off' en
	 * schrijft wp-config.php direct weg.
	 */
	public function handle_disable() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::ACTION_DISABLE );

		$settings               = get_option( 'mcm_security_settings', MCM_Security_Hardener::get_defaults() );
		$settings['debug_mode'] = 'off';

		// Staat ons wp-config-blok nu niet actief (regels bewust verwijderd),
		// schrijf dan alléén de debug-regel — niet ongevraagd alle hardening
		// terugzetten.
		$to_write = MCM_WPConfig_Manager::is_active() ? $settings : [ 'debug_mode' => 'off' ];
		$result   = MCM_WPConfig_Manager::write( $to_write );

		if ( true === $result ) {
			update_option( 'mcm_security_settings', $settings );
			delete_transient( self::EMAIL_THROTTLE_KEY );
			$status = 'debug_off';
		} else {
			$status = 'debug_off_error';
		}

		wp_safe_redirect( add_query_arg( 'mcm-status', $status, admin_url( 'tools.php?page=mcm-security' ) ) );
		exit;
	}

	public function check() {
		if ( ! $this->is_enabled() ) {
			return;
		}

		if ( ! $this->is_debug_active_on_production() ) {
			return;
		}

		add_action( 'admin_notices', [ $this, 'render_notice' ] );
		$this->maybe_send_email();
	}

	private function is_enabled() {
		if ( defined( 'MCM_SECURITY_DISABLE_DEBUG_WATCHDOG' ) && MCM_SECURITY_DISABLE_DEBUG_WATCHDOG ) {
			return false;
		}
		return (bool) apply_filters( 'mcm_security_debug_watchdog_enabled', true );
	}

	private function is_debug_active_on_production() {
		if ( ! defined( 'WP_DEBUG' ) || true !== WP_DEBUG ) {
			return false;
		}

		$env = function_exists( 'wp_get_environment_type' ) ? wp_get_environment_type() : 'production';
		return 'production' === $env;
	}

	private function is_display_leaking() {
		return defined( 'WP_DEBUG_DISPLAY' ) && true === WP_DEBUG_DISPLAY;
	}

	public function render_notice() {
		if ( ! MCM_Notifier::should_show_admin_notice() ) {
			return;
		}

		$leaking = $this->is_display_leaking();
		$class   = $leaking ? 'notice notice-error' : 'notice notice-warning';
		$title   = $leaking
			? '⚠️ KRITIEK: WP_DEBUG_DISPLAY actief op productie'
			: 'WP_DEBUG staat aan op productie';

		$body = $leaking
			? 'PHP-fouten worden getoond aan bezoekers. Dit kan paden, queries en stack traces lekken. Zet <code>WP_DEBUG_DISPLAY</code> uit in <code>wp-config.php</code> of via deze plugin (instelling "Verberg foutmeldingen").'
			: 'Debug-modus draait op een productie-omgeving. Vergeet niet uit te zetten zodra je klaar bent met debuggen.';

		$buttons = '';
		if ( current_user_can( 'manage_options' ) ) {
			$buttons = sprintf(
				'<p><a href="%s" class="button button-primary">Zet WP_DEBUG uit</a> <a href="%s" class="button">Debug-instelling bekijken</a></p>',
				esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=' . self::ACTION_DISABLE ), self::ACTION_DISABLE ) ),
				esc_url( admin_url( 'tools.php?page=mcm-security#mcm-debug-mode' ) )
			);
		}

		printf(
			'<div class="%s"><p><strong>%s</strong></p><p>%s</p>%s</div>',
			esc_attr( $class ),
			esc_html( $title ),
			wp_kses_post( $body ),
			$buttons
		);
	}

	private function maybe_send_email() {
		if ( get_transient( self::EMAIL_THROTTLE_KEY ) ) {
			return;
		}

		set_transient( self::EMAIL_THROTTLE_KEY, 1, self::EMAIL_THROTTLE_TTL );

		$leaking = $this->is_display_leaking();
		$subject = $leaking
			? 'KRITIEK: WP_DEBUG_DISPLAY actief op productie'
			: 'WP_DEBUG actief op productie';

		$body  = "Op deze site draait WP_DEBUG=true op een productie-omgeving.\n\n";
		$body .= 'WP_DEBUG:         true' . "\n";
		$body .= 'WP_DEBUG_DISPLAY: ' . ( $leaking ? 'true (LEAKT NAAR BEZOEKERS)' : 'false' ) . "\n";
		$body .= 'WP_DEBUG_LOG:     ' . ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ? 'true' : 'false' ) . "\n";
		$body .= 'Environment:      ' . ( function_exists( 'wp_get_environment_type' ) ? wp_get_environment_type() : 'production (default)' ) . "\n\n";

		if ( $leaking ) {
			$body .= "ACTIE: Zet WP_DEBUG_DISPLAY uit. PHP-fouten worden nu getoond aan bezoekers.\n";
		} else {
			$body .= "Geen directe leak naar bezoekers (WP_DEBUG_DISPLAY staat uit), maar debug-modus hoort niet aan op productie.\n";
		}
		$body .= "\nDeze melding wordt maximaal 1× per 24u verstuurd zolang de situatie aanhoudt.";

		MCM_Notifier::email( $subject, $body );
	}
}
