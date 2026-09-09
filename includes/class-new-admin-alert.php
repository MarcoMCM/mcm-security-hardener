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

		$subject = sprintf( 'Nieuw administrator-account: %s', $user->user_login );

		$body  = "Er is zojuist een account gepromoveerd naar Administrator op deze site.\n\n";
		$body .= sprintf( "Gebruikersnaam:  %s\n", $user->user_login );
		$body .= sprintf( "E-mailadres:     %s\n", $user->user_email );
		$body .= sprintf( "Weergavenaam:    %s\n", $user->display_name );
		$body .= sprintf( "Was eerder:      %s\n", empty( $old_roles ) ? '(gloednieuw account)' : implode( ', ', $old_roles ) );
		$body .= sprintf( "Geregistreerd:   %s\n", $user->user_registered );
		$body .= sprintf( "Uitgevoerd door: %s\n", self::current_actor_label() );
		$body .= "\n----\n";
		$body .= "Herken je dit account niet, of is de promotie onverwacht? Ga ervan uit\n";
		$body .= "dat het verdacht is. Tools → MCM Security → User Audit kan het account\n";
		$body .= "direct downgraden.\n";

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
