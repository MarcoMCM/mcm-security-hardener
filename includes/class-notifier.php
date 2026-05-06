<?php
/**
 * Centrale communicatie-helper.
 *
 * Alle mails en admin notices die deze plugin uitstuurt gaan via deze class,
 * zodat ze altijd naar Marco gaan en nooit naar de klant.
 *
 * Override-volgorde:
 *   1. Constante MCM_SECURITY_NOTIFY_EMAIL in wp-config.php
 *   2. Filter 'mcm_security_notify_email'
 *   3. Default: marco@mcmwebsites.nl
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Notifier {

	const DEFAULT_EMAIL = 'marco@mcmwebsites.nl';

	/**
	 * Naar welk adres mailen we?
	 */
	public static function notify_email() {
		if ( defined( 'MCM_SECURITY_NOTIFY_EMAIL' ) && MCM_SECURITY_NOTIFY_EMAIL ) {
			return MCM_SECURITY_NOTIFY_EMAIL;
		}
		return apply_filters( 'mcm_security_notify_email', self::DEFAULT_EMAIL );
	}

	/**
	 * Stuur een mail naar de eigenaar.
	 *
	 * @param string       $subject Onderwerpregel.
	 * @param string       $body    Body (plain text of HTML).
	 * @param string|array $headers Extra headers (default: text/plain).
	 * @return bool True bij succes.
	 */
	public static function email( $subject, $body, $headers = '' ) {
		$site_name = get_bloginfo( 'name' );
		$site_url  = home_url();

		$prefixed_subject = sprintf( '[MCM Security — %s] %s', $site_name, $subject );

		$footer  = "\n\n---\n";
		$footer .= "Site: {$site_name}\n";
		$footer .= "URL:  {$site_url}\n";
		$footer .= 'Datum: ' . wp_date( 'Y-m-d H:i' ) . "\n";

		return wp_mail(
			self::notify_email(),
			$prefixed_subject,
			$body . $footer,
			$headers
		);
	}

	/**
	 * Mag de huidige user een admin-notice van deze plugin zien?
	 *
	 * Strict: alleen MCM-eigenaars. Klanten met admin-rol zien onze notices niet.
	 */
	public static function should_show_admin_notice() {
		if ( ! class_exists( 'MCM_Lockdown_Manager' ) ) {
			return false;
		}
		return MCM_Lockdown_Manager::is_mcm_owner();
	}
}
