<?php
/**
 * Finding Ignore — gedeelde "markeer als veilig"-lijst voor de detectie-
 * modules (File Exposure Scanner, Anomaly Scanner). Eén centrale opslag
 * zodat een beoordeelde bevinding niet elke scan opnieuw terugkomt in de
 * admin-tabel én de mail.
 *
 * Aanleiding: Marco's eigen feedback na het opschonen van tessaswinkels.com
 * — een paar bevindingen (een oud Avada-demo-archief, een afgeschermde
 * database-dump) zijn eenmalig beoordeeld als onschuldig, maar bleven
 * daarna elke week terugkomen. Dit is geen whitelist-filter (die is voor
 * generieke, sitebrede patronen via de bestaande filters
 * 'mcm_anomaly_root_whitelist' e.d.) maar een per-site, per-bevinding
 * "ik heb dit gezien, dit is akkoord"-vinkje.
 *
 * Identificatie: elke bevinding krijgt een stabiele sleutel op basis van
 * bron (exposure/anomaly) + het 'path'-veld uit de finding — dat is een
 * filesystem-pad bij bestandsbevindingen, of een stabiele admin-URL (met
 * post-ID) bij database-bevindingen (WPCode-snippets). NIET op relpath of
 * titel, want die kunnen wijzigen zonder dat het om een ander item gaat.
 *
 * Gedrag: permanent tot iemand het expliciet weer intrekt via de
 * "Genegeerde bevindingen"-lijst in de admin. Werkt puur op het pad, niet
 * op inhoud/grootte — verandert een genegeerd bestand van omvang, dan
 * blijft het toch genegeerd (bewuste keuze: een eenmaal beoordeeld
 * bestand moet niet stiekem weer aanslaan bij een normale update).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Finding_Ignore {

	const OPTION           = 'mcm_security_ignored_findings';
	const ACTION_IGNORE    = 'mcm_security_ignore_finding';
	const ACTION_UNIGNORE  = 'mcm_security_unignore_finding';

	public function __construct() {
		add_action( 'admin_post_' . self::ACTION_IGNORE, [ __CLASS__, 'handle_ignore' ] );
		add_action( 'admin_post_' . self::ACTION_UNIGNORE, [ __CLASS__, 'handle_unignore' ] );
	}

	/**
	 * Stabiele sleutel voor een bevinding.
	 */
	public static function key( $source, $path ) {
		return md5( $source . '|' . $path );
	}

	/**
	 * @return array<string,array{source:string,path:string,relpath:string,reason:string,by:string,at:int}>
	 */
	private static function all_raw() {
		$stored = get_option( self::OPTION, [] );
		return is_array( $stored ) ? $stored : [];
	}

	/**
	 * @param string|null $source Beperk tot één bron ('exposure'|'anomaly'), of null voor alles.
	 * @return array<string,array>
	 */
	public static function all( $source = null ) {
		$all = self::all_raw();
		if ( null === $source ) {
			return $all;
		}
		return array_filter( $all, function ( $entry ) use ( $source ) {
			return isset( $entry['source'] ) && $entry['source'] === $source;
		} );
	}

	/**
	 * Filtert genegeerde items uit een findings-array. Elke finding moet
	 * een 'path'-veld hebben.
	 *
	 * @param string $source
	 * @param array  $findings
	 * @return array
	 */
	public static function filter( $source, array $findings ) {
		$all = self::all_raw();
		if ( empty( $all ) ) {
			return $findings;
		}
		return array_values( array_filter( $findings, function ( $f ) use ( $source, $all ) {
			if ( ! isset( $f['path'] ) ) {
				return true;
			}
			$key = self::key( $source, $f['path'] );
			return ! isset( $all[ $key ] );
		} ) );
	}

	/**
	 * Markeert een bevinding als veilig.
	 */
	public static function add( $source, $path, $relpath, $reason ) {
		$all  = self::all_raw();
		$key  = self::key( $source, $path );
		$user = wp_get_current_user();

		$all[ $key ] = [
			'source'  => $source,
			'path'    => $path,
			'relpath' => $relpath,
			'reason'  => $reason,
			'by'      => ( $user && $user->ID ) ? $user->user_login : 'onbekend',
			'at'      => time(),
		];

		update_option( self::OPTION, $all );
		return $key;
	}

	/**
	 * Trekt een "veilig"-markering weer in.
	 */
	public static function remove( $key ) {
		$all = self::all_raw();
		unset( $all[ $key ] );
		update_option( self::OPTION, $all );
	}

	/**
	 * Handler voor de "Markeer als veilig"-knop per bevindingsrij.
	 */
	public static function handle_ignore() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::ACTION_IGNORE );

		$source  = isset( $_POST['mcm_source'] ) ? sanitize_key( wp_unslash( $_POST['mcm_source'] ) ) : '';
		$path    = isset( $_POST['mcm_path'] ) ? wp_unslash( $_POST['mcm_path'] ) : '';
		$relpath = isset( $_POST['mcm_relpath'] ) ? sanitize_text_field( wp_unslash( $_POST['mcm_relpath'] ) ) : '';
		$reason  = isset( $_POST['mcm_reason'] ) ? sanitize_text_field( wp_unslash( $_POST['mcm_reason'] ) ) : '';

		if ( '' !== $source && '' !== $path ) {
			self::add( $source, $path, $relpath, $reason );
		}

		wp_safe_redirect( add_query_arg(
			'mcm_status',
			'finding_ignored',
			wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' )
		) );
		exit;
	}

	/**
	 * Handler voor de "Herstel" (un-ignore) knop.
	 */
	public static function handle_unignore() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::ACTION_UNIGNORE );

		$key = isset( $_POST['mcm_key'] ) ? sanitize_text_field( wp_unslash( $_POST['mcm_key'] ) ) : '';
		if ( $key ) {
			self::remove( $key );
		}

		wp_safe_redirect( add_query_arg(
			'mcm_status',
			'finding_unignored',
			wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' )
		) );
		exit;
	}
}
