<?php
/**
 * New Admin Alert — mailt direct zodra een account de rol administrator
 * krijgt, ongeacht hoe (registratieformulier, wp-admin, wp-cli, of een
 * kwaadaardig script dat WordPress' eigen user-API gebruikt).
 *
 * Aanleiding: bij de tessaswinkels.com-hack (sept 2026) maakte een
 * backdoor-plugin gedurende 7 weken ongezien in totaal 11 rogue
 * administrator-accounts aan. Niemand keek in die periode op de
 * User Audit-pagina (Tools → MCM Security), die alleen een handmatig te
 * openen lijst is zonder cron of mail. Deze module is de real-time
 * tegenhanger daarvan: elke promotie naar administrator triggert direct
 * een mail naar de Notifier, ongeacht hoe het account is aangemaakt.
 *
 * Hook: 'set_user_role' vuurt zowel bij het aanmaken van een nieuwe user
 * mét rol (via wp_insert_user()) als bij het wijzigen van de rol van een
 * bestaande user (privilege-escalatie van een al gekaapt lager account —
 * ook een realistisch aanvalspad). Beide worden hier gedekt.
 *
 * wp2shell (sinds 1.34.0): past het account bij de wp2shell-aanval
 * (MCM_User_Audit::wp2shell_match()), dan krijgt de mail een eigen
 * onderwerp en begint hij met een waarschuwing en concrete stappen. Op een
 * MCM-site zonder deze plugin bleven drie zulke beheerders in juli 2026
 * drie maanden onopgemerkt; deze mail had ze op dag 1 gemeld.
 *
 * Grens: dit vangt alleen promoties die via WordPress' eigen PHP-API lopen
 * (wp_insert_user(), WP_User::set_role(), wp-cli, etc). Een aanvaller die
 * met een eigen script rechtstreeks in de database schrijft — buiten WP's
 * hooks om — blijft ongezien door deze module. Dat is een fundamentele
 * grens van elke in-WordPress hardening-plugin, geen bug hierin.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_New_Admin_Alert {

	public function __construct() {
		add_action( 'set_user_role', [ __CLASS__, 'maybe_alert' ], 10, 3 );
	}

	/**
	 * @param int      $user_id
	 * @param string   $role      Nieuwe (enige) rol na deze wijziging.
	 * @param string[] $old_roles Rollen vóór de wijziging (leeg bij een
	 *                            gloednieuw account).
	 */
	public static function maybe_alert( $user_id, $role, $old_roles ) {
		if ( 'administrator' !== $role || in_array( 'administrator', (array) $old_roles, true ) ) {
			return;
		}

		$user = get_user_by( 'ID', $user_id );
		if ( ! $user ) {
			return;
		}

		// MCM-eigenaars mogen zichzelf/elkaar promoten zonder alarm (bv. bij
		// oplevering van een nieuwe site of het toevoegen van een collega).
		$owners = class_exists( 'MCM_Lockdown_Manager' ) ? MCM_Lockdown_Manager::get_owners() : [];
		if ( in_array( $user->user_login, $owners, true ) ) {
			return;
		}

		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}

		// Past het account bij de wp2shell-aanval? Dan is dit geen vraag
		// meer maar een inbraak, en moet dat het eerste zijn wat je leest.
		$wp2shell = class_exists( 'MCM_User_Audit' )
			? MCM_User_Audit::wp2shell_match( $user->user_login, $user->user_email )
			: '';

		$subject = sprintf( 'Nieuw administrator-account: %s', $user->user_login );
		$body    = '';

		if ( '' !== $wp2shell ) {
			$subject = sprintf( 'WAARSCHUWING wp2shell-aanval — nieuw administrator-account: %s', $user->user_login );

			$body .= "!! WAARSCHUWING: dit account past bij de wp2shell-aanval\n";
			$body .= sprintf( "!! (%s).\n", $wp2shell );
			$body .= "!! wp2shell is een lek in WordPress zelf (CVE-2026-63030 +\n";
			$body .= "!! CVE-2026-60137, in 6.9.0–6.9.4 en 7.0.0–7.0.1) waarmee aanvallers\n";
			$body .= "!! sinds juli 2026 massaal beheerders aanmaken. Ga ervan uit dat de\n";
			$body .= "!! site NU is binnengedrongen.\n";
			$body .= sprintf( "!! WordPress-versie nu: %s (lek dicht vanaf 6.9.5 en 7.0.2)\n\n", get_bloginfo( 'version' ) );
		}

		$body .= "Er is zojuist een account gepromoveerd naar Administrator op deze site.\n\n";
		$body .= sprintf( "Gebruikersnaam:  %s\n", $user->user_login );
		$body .= sprintf( "E-mailadres:     %s\n", $user->user_email );
		$body .= sprintf( "Weergavenaam:    %s\n", $user->display_name );
		$body .= sprintf( "Was eerder:      %s\n", empty( $old_roles ) ? '(gloednieuw account)' : implode( ', ', $old_roles ) );
		$body .= sprintf( "Geregistreerd:   %s\n", $user->user_registered );
		$body .= sprintf( "Uitgevoerd door: %s\n", self::current_actor_label() );
		$body .= "\n----\n";
		if ( '' !== $wp2shell ) {
			$body .= "ACTIE, nu meteen:\n";
			$body .= "1. Zet dit account naar Abonnee: Tools → MCM Security → User Audit.\n";
			$body .= "   Verwijder het pas na onderzoek, met een backup vooraf.\n";
			$body .= "2. Werk WordPress bij als de versie hierboven nog lek is.\n";
			$body .= "3. Zoek naar meer: andere vreemde accounts, achterdeuren in plugins en\n";
			$body .= "   bestanden, code in de database. Klik op Tools → MCM Security bij\n";
			$body .= "   \"Vreemde bestanden & mappen\" op \"Nu scannen\".\n";
			$body .= "4. Vernieuw daarna wachtwoorden en salts.\n";
		} else {
			$body .= "Herken je dit account niet, of is de promotie onverwacht? Ga ervan uit\n";
			$body .= "dat het verdacht is. Tools → MCM Security → User Audit kan het account\n";
			$body .= "direct downgraden.\n";
		}

		MCM_Notifier::email( $subject, $body );
	}

	/**
	 * Best-effort omschrijving van wie/wat de promotie deed: ingelogde
	 * beheerder, WP-CLI, of onbekend (bv. een script buiten wp-admin om).
	 */
	private static function current_actor_label() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'WP-CLI';
		}
		$current = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		if ( $current && $current->ID ) {
			return sprintf( '%s (ID %d)', $current->user_login, $current->ID );
		}
		return 'Onbekend — geen ingelogde gebruiker (mogelijk een script)';
	}
}
