<?php
/**
 * User Audit — toont users met "verhoogde" rol op de site, met de optie om
 * ze in één klik te downgraden naar de MCM Klant rol (of Subscriber als
 * MCM Klant niet bestaat).
 *
 * Verhoogde rollen: Administrator, Editor, Author, Contributor.
 *
 * Veiligheid:
 *   - MCM eigenaars (uit MCM_SECURITY_OWNERS) worden NOOIT in de lijst
 *     getoond en kunnen niet gedowngrade worden.
 *   - Super admins op multisite worden niet getoond.
 *   - Alleen users met de capability 'promote_users' kunnen downgraden.
 *   - Admin-users kunnen alleen worden gedowngrade door iemand met
 *     'manage_options' (= ook admin).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_User_Audit {

	const ACTION_DOWNGRADE = 'mcm_security_downgrade_user';
	const NONCE_KEY        = 'mcm_security_downgrade';
	const KLANT_ROLE_SLUG  = 'mcm_klant';

	const ELEVATED_ROLES = [ 'administrator', 'editor', 'author', 'contributor' ];

	public function __construct() {
		add_action( 'admin_post_' . self::ACTION_DOWNGRADE, [ $this, 'handle_downgrade' ] );
	}

	/**
	 * Lijst users met verhoogde rol, exclusief MCM eigenaars en super-admins.
	 *
	 * @return WP_User[]
	 */
	public static function get_elevated_users() {
		$users = get_users( [
			'role__in' => self::ELEVATED_ROLES,
			'orderby'  => 'user_login',
			'order'    => 'ASC',
		] );

		$owners = class_exists( 'MCM_Lockdown_Manager' )
			? MCM_Lockdown_Manager::get_owners()
			: [];

		$filtered = [];
		foreach ( $users as $user ) {
			if ( in_array( $user->user_login, $owners, true ) ) {
				continue;
			}
			if ( is_multisite() && is_super_admin( $user->ID ) ) {
				continue;
			}
			$filtered[] = $user;
		}

		return $filtered;
	}

	/**
	 * Naar welke rol downgraden we? Bij voorkeur MCM Klant, anders Subscriber.
	 */
	public static function downgrade_target_role() {
		if ( self::klant_role_available() ) {
			return self::KLANT_ROLE_SLUG;
		}
		return 'subscriber';
	}

	/**
	 * Bestaat de MCM Klant rol op deze site? (= site-optimizer geïnstalleerd)
	 */
	public static function klant_role_available() {
		return null !== get_role( self::KLANT_ROLE_SLUG );
	}

	/**
	 * Vriendelijke label voor de target role.
	 */
	public static function downgrade_target_label() {
		$slug = self::downgrade_target_role();
		$role = get_role( $slug );
		if ( ! $role ) {
			return $slug;
		}
		$names = wp_roles()->get_names();
		return isset( $names[ $slug ] ) ? translate_user_role( $names[ $slug ] ) : $slug;
	}

	/**
	 * Vriendelijke rol-namen voor weergave.
	 */
	public static function role_labels( WP_User $user ) {
		$names = wp_roles()->get_names();
		$out   = [];
		foreach ( (array) $user->roles as $slug ) {
			$out[] = isset( $names[ $slug ] ) ? translate_user_role( $names[ $slug ] ) : $slug;
		}
		return implode( ', ', $out );
	}

	/**
	 * Laatst-ingelogd datum (best-effort — gebruikt usermeta 'mcm_last_login'
	 * als die er is, anders user_registered).
	 */
	public static function last_seen_label( WP_User $user ) {
		$last = get_user_meta( $user->ID, 'mcm_last_login', true );
		if ( $last ) {
			return wp_date( 'd-m-Y', (int) $last );
		}
		if ( $user->user_registered ) {
			return 'geregistreerd: ' . wp_date( 'd-m-Y', strtotime( $user->user_registered ) );
		}
		return '—';
	}

	/**
	 * Handelt de downgrade-actie af.
	 */
	public function handle_downgrade() {
		if ( ! current_user_can( 'promote_users' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::NONCE_KEY );

		// Accepteer zowel GET als POST (admin-post URL met nonce-query).
		$user_id = isset( $_REQUEST['user_id'] ) ? absint( $_REQUEST['user_id'] ) : 0;
		$referer = wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' );

		if ( ! $user_id ) {
			wp_safe_redirect( add_query_arg( 'mcm_status', 'audit_invalid', $referer ) );
			exit;
		}

		$user = get_user_by( 'ID', $user_id );
		if ( ! $user ) {
			wp_safe_redirect( add_query_arg( 'mcm_status', 'audit_user_not_found', $referer ) );
			exit;
		}

		// MCM eigenaar nooit downgraden.
		$owners = class_exists( 'MCM_Lockdown_Manager' ) ? MCM_Lockdown_Manager::get_owners() : [];
		if ( in_array( $user->user_login, $owners, true ) ) {
			wp_safe_redirect( add_query_arg( 'mcm_status', 'audit_owner_protected', $referer ) );
			exit;
		}

		// Super-admin op multisite nooit downgraden.
		if ( is_multisite() && is_super_admin( $user->ID ) ) {
			wp_safe_redirect( add_query_arg( 'mcm_status', 'audit_super_protected', $referer ) );
			exit;
		}

		// Een admin downgraden mag alleen door een manage_options-user.
		if ( in_array( 'administrator', (array) $user->roles, true ) && ! current_user_can( 'manage_options' ) ) {
			wp_safe_redirect( add_query_arg( 'mcm_status', 'audit_no_admin_downgrade', $referer ) );
			exit;
		}

		$target = self::downgrade_target_role();
		$user->set_role( $target );

		wp_safe_redirect( add_query_arg( [
			'mcm_status'      => 'audit_downgraded',
			'mcm_audit_user'  => $user->user_login,
			'mcm_audit_role'  => $target,
		], $referer ) );
		exit;
	}
}
