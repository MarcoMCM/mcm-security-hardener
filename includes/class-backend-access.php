<?php
/**
 * Backend Access — twee gerelateerde backend-toegang-features:
 *
 *   1. Skip admin email confirmation
 *      Schakelt WordPress' periodieke "is dit nog je email?"-tussenscherm
 *      uit voor administrators. Standaard aan — universeel irritant.
 *
 *   2. Block non-admin backend access
 *      Redirect ingelogde users zonder admin/editor-rol weg van /wp-admin/
 *      naar een opgegeven URL (of home). Whitelist van rollen instelbaar.
 *      Standaard UIT — bewuste keuze per site (sommige sites willen klant-
 *      rollen wel in de backend).
 *
 * MCM-eigenaars (uit Lockdown_Manager::is_mcm_owner()) worden NOOIT
 * geblokkeerd, ongeacht hun rol.
 *
 * AJAX, REST, cron en WP-CLI worden altijd doorgelaten.
 *
 * Filters:
 *   - 'mcm_allowed_backend_roles' → past de toegestane rol-lijst aan
 *   - 'mcm_unauthorized_backend_redirect' → past de redirect-URL aan
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Backend_Access {

	private $settings = [];

	public function __construct() {
		$this->settings = get_option( 'mcm_security_settings', [] );

		if ( ! empty( $this->settings['skip_admin_email_confirmation'] ) ) {
			add_action( 'init', [ $this, 'skip_admin_email_confirmation' ], 1 );
		}

		if ( ! empty( $this->settings['block_non_admin_backend'] ) ) {
			add_action( 'admin_init', [ $this, 'block_non_admin_backend' ] );
		}
	}

	/**
	 * Schakelt het "controleer admin email"-tussenscherm uit voor admins.
	 * WordPress toont dit elke ~6 maanden als ingelogde admin → irritant
	 * voor terugkerende beheerders.
	 */
	public function skip_admin_email_confirmation() {
		if ( ! isset( $_GET['action'] ) || 'confirm_admin_email' !== $_GET['action'] ) {
			return;
		}
		if ( ! is_user_logged_in() ) {
			return;
		}
		if ( current_user_can( 'manage_options' ) ) {
			wp_safe_redirect( admin_url() );
			exit;
		}
	}

	/**
	 * Redirect non-admin users die /wp-admin/ benaderen.
	 */
	public function block_non_admin_backend() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		// Technische requests altijd doorlaten.
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return;
		}

		// MCM-eigenaars: nooit redirecten.
		if ( class_exists( 'MCM_Lockdown_Manager' ) && MCM_Lockdown_Manager::is_mcm_owner() ) {
			return;
		}

		$user       = wp_get_current_user();
		$user_roles = (array) $user->roles;

		$allowed_roles = $this->allowed_backend_roles();

		if ( ! empty( array_intersect( $user_roles, $allowed_roles ) ) ) {
			return; // Heeft minstens één toegestane rol.
		}

		$redirect_url = $this->unauthorized_redirect_url();
		wp_safe_redirect( $redirect_url );
		exit;
	}

	/**
	 * De whitelist van rollen die wp-admin mogen zien.
	 *
	 * @return string[] Rol-slugs.
	 */
	private function allowed_backend_roles() {
		$raw   = ! empty( $this->settings['allowed_backend_roles'] )
			? (string) $this->settings['allowed_backend_roles']
			: 'administrator';
		$roles = array_filter( array_map( 'trim', explode( "\n", $raw ) ) );
		if ( empty( $roles ) ) {
			$roles = [ 'administrator' ];
		}
		return (array) apply_filters( 'mcm_allowed_backend_roles', $roles );
	}

	/**
	 * Waar gaat een geblokkeerde non-admin heen?
	 */
	private function unauthorized_redirect_url() {
		$url = ! empty( $this->settings['unauthorized_backend_redirect'] )
			? (string) $this->settings['unauthorized_backend_redirect']
			: home_url( '/' );
		$url = (string) apply_filters( 'mcm_unauthorized_backend_redirect', $url );
		return esc_url_raw( $url );
	}
}
