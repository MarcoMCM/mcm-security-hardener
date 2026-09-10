<?php
/**
 * Snippet Monitor — mailt direct zodra een WPCode/Insert Headers and
 * Footers-snippet wordt aangemaakt of inhoudelijk gewijzigd.
 *
 * Aanleiding: bij de tessaswinkels.com-hack (sept 2026) verstopte de
 * aanvaller twee webshells (een file-manager en een "NezukaBot"-uploader)
 * als WPCode-snippets in de database — niet als bestanden op schijf. Elke
 * bestandsscan (Anomaly Scanner, wp core verify-checksums, grep) mist dit
 * volledig: de payload staat in wp_posts/wp_postmeta, niet op filesystem-
 * niveau. Eén van de twee stond zelfs als "draft" (nooit gepubliceerd) en
 * was dus ook via WPCode's eigen actief/inactief-status niet als risico
 * zichtbaar — filteren op alleen 'publish' had 'm gemist.
 *
 * Hook: 'save_post_wpcode' — WordPress' eigen dynamische hook voor het
 * custom post type dat WPCode/Insert Headers and Footers gebruikt. Vuurt
 * bij aanmaken én bewerken, ongeacht publish/draft-status.
 *
 * Ruis-onderdrukking: alleen mailen als post_content daadwerkelijk is
 * veranderd t.o.v. de vorige keer dat deze module 'm zag (hash in
 * postmeta). WPCode's admin-UI bewaart soms ook bij het wijzigen van een
 * instelling (locatie, prioriteit) zonder dat de code zelf verandert —
 * dat hoeft geen mail te zijn.
 *
 * Owner-uitzondering: een ingelogde MCM-eigenaar die zelf een snippet
 * bewerkt, mailt niet (normaal onderhoudswerk). Een aanvallersscript dat
 * buiten wp-admin om post, is nooit als ingelogde eigenaar geauthenticeerd,
 * dus deze uitzondering verzwakt de detectie niet.
 *
 * Grens: dit vangt alleen wijzigingen die via WordPress' eigen post-API
 * lopen (wp_insert_post()/wp_update_post(), dus ook de normale WPCode-UI).
 * Een aanvaller die rechtstreeks in de database schrijft (ruwe SQL) vuurt
 * geen WordPress-hook en blijft hier ongezien — zie de aanvullende
 * wekelijkse controle in MCM_Anomaly_Scanner (scan_snippet_baseline), die
 * de actuele database-inhoud vergelijkt i.p.v. op events te wachten en
 * zulke gevallen wél kan opvangen.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Snippet_Monitor {

	const META_HASH = '_mcm_security_snippet_hash';
	const POST_TYPE  = 'wpcode';

	public function __construct() {
		add_action( 'save_post_' . self::POST_TYPE, [ __CLASS__, 'maybe_alert' ], 20, 3 );
	}

	/**
	 * @param int     $post_id
	 * @param WP_Post $post
	 * @param bool    $update Bestond de post al vóór deze save?
	 */
	public static function maybe_alert( $post_id, $post, $update ) {
		if ( wp_is_post_autosave( $post_id ) || wp_is_post_revision( $post_id ) ) {
			return;
		}

		$hash      = md5( (string) $post->post_content );
		$prev_hash = get_post_meta( $post_id, self::META_HASH, true );

		// Niets veranderd sinds de vorige keer dat wij 'm zagen: geen mail,
		// maar de hash blijft wel actueel staan (geen-op hieronder).
		if ( $prev_hash && $prev_hash === $hash ) {
			return;
		}
		update_post_meta( $post_id, self::META_HASH, $hash );

		// MCM-eigenaar die zelf bewerkt: geen ruis. Een aanvallersscript is
		// nooit als ingelogde eigenaar geauthenticeerd, dus dit verzwakt de
		// detectie niet.
		$owners  = class_exists( 'MCM_Lockdown_Manager' ) ? MCM_Lockdown_Manager::get_owners() : [];
		$current = wp_get_current_user();
		if ( $current && $current->ID && in_array( $current->user_login, $owners, true ) ) {
			return;
		}

		if ( ! class_exists( 'MCM_Notifier' ) ) {
			return;
		}

		$is_new  = ! $update;
		$title   = $post->post_title ?: '(zonder titel)';
		$subject = sprintf( $is_new ? 'Nieuwe code-snippet aangemaakt: %s' : 'Code-snippet gewijzigd: %s', $title );

		$body  = sprintf( "Er is zojuist een %s in de code-snippet-plugin (WPCode/Insert Headers and Footers).\n\n", $is_new ? 'nieuwe snippet aangemaakt' : 'bestaande snippet gewijzigd' );
		$body .= sprintf( "Titel:           %s\n", $title );
		$body .= sprintf( "Status:          %s (let op: ook een 'draft'-snippet is een risico — hij staat klaar om geactiveerd te worden)\n", $post->post_status );
		$body .= sprintf( "Bewerkt door:    %s\n", self::current_actor_label() );
		$body .= sprintf( "Bewerk-URL:      %s\n", admin_url( 'admin.php?page=wpcode-snippet-manager&edit=' . $post_id ) );
		$body .= "\n----\n";
		$body .= "Code-snippets draaien met volledige PHP/JS-rechten op de site. Herken\n";
		$body .= "je deze wijziging niet? Ga ervan uit dat het verdacht is en bekijk de\n";
		$body .= "inhoud direct via de bewerk-URL hierboven.\n";

		MCM_Notifier::email( $subject, $body );
	}

	/**
	 * Best-effort omschrijving van wie de wijziging deed.
	 */
	private static function current_actor_label() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'WP-CLI';
		}
		$current = wp_get_current_user();
		if ( $current && $current->ID ) {
			return sprintf( '%s (ID %d)', $current->user_login, $current->ID );
		}
		return 'Onbekend — geen ingelogde gebruiker (mogelijk een script)';
	}
}
