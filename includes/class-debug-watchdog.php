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

	public function __construct() {
		add_action( 'admin_init', [ $this, 'check' ] );
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
			? 'PHP-fouten worden getoond aan bezoekers. Dit kan paden, queries en stack traces lekken. Zet <code>WP_DEBUG_DISPLAY</code> uit in <code>wp-config.php</code> of via deze plugin (instelling "Hide debug display").'
			: 'Debug-modus draait op een productie-omgeving. Vergeet niet uit te zetten zodra je klaar bent met debuggen.';

		printf(
			'<div class="%s"><p><strong>%s</strong></p><p>%s</p></div>',
			esc_attr( $class ),
			esc_html( $title ),
			wp_kses_post( $body )
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
