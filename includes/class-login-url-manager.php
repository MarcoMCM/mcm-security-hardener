<?php
/**
 * Hides wp-login.php and provides a custom login slug.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Login_URL_Manager {

	private $custom_slug = '';

	public function __construct() {
		$settings          = get_option( 'mcm_security_settings', [] );
		$this->custom_slug = ! empty( $settings['login_slug'] ) ? sanitize_title( $settings['login_slug'] ) : '';

		if ( empty( $this->custom_slug ) || ! empty( $settings['hide_login_disabled'] ) ) {
			return;
		}

		// Don't run in wp-cli or during plugin activation/deactivation.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_installing() ) {
			return;
		}

		add_action( 'init', [ $this, 'handle_custom_slug' ], 1 );
		add_action( 'wp_loaded', [ $this, 'block_wp_login' ] );
		add_filter( 'login_url', [ $this, 'filter_login_url' ], 10, 3 );
		add_filter( 'logout_url', [ $this, 'filter_logout_url' ], 10, 2 );
		add_filter( 'lostpassword_url', [ $this, 'filter_lostpassword_url' ], 10, 2 );
		add_filter( 'site_url', [ $this, 'filter_site_url' ], 10, 4 );
		add_filter( 'wp_redirect', [ $this, 'filter_redirect' ], 10, 2 );
	}

	/**
	 * When visiting the custom slug, load wp-login.php.
	 */
	public function handle_custom_slug() {
		$request_uri = $this->get_request_path();

		if ( $request_uri === '/' . $this->custom_slug || $request_uri === '/' . $this->custom_slug . '/' ) {
			// Load wp-login.php internally.
			require_once ABSPATH . 'wp-login.php';
			exit;
		}
	}

	/**
	 * Block direct access to wp-login.php.
	 */
	public function block_wp_login() {
		// Allow POST requests to wp-login.php (form submissions, login actions).
		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			return;
		}

		$request_uri = $this->get_request_path();

		// Check if this is a wp-login.php request.
		if ( false === strpos( $request_uri, 'wp-login.php' ) ) {
			return;
		}

		// Allow specific actions that need wp-login.php (password reset confirmations, etc.).
		$allowed_actions = [ 'postpass', 'rp', 'resetpass', 'confirmaction' ];
		if ( isset( $_GET['action'] ) && in_array( $_GET['action'], $allowed_actions, true ) ) {
			return;
		}

		// Allow interim-login (modal login in admin).
		if ( isset( $_GET['interim-login'] ) ) {
			return;
		}

		// Return a 404 for everything else.
		$this->show_404();
	}

	/**
	 * Filter the login URL to use the custom slug.
	 */
	public function filter_login_url( $login_url, $redirect, $force_reauth ) {
		$login_url = $this->replace_login_url( $login_url );
		return $login_url;
	}

	/**
	 * Filter the logout URL.
	 */
	public function filter_logout_url( $logout_url, $redirect ) {
		return $this->replace_login_url( $logout_url );
	}

	/**
	 * Filter the lost password URL.
	 */
	public function filter_lostpassword_url( $lostpassword_url, $redirect ) {
		return $this->replace_login_url( $lostpassword_url );
	}

	/**
	 * Filter site_url when it points to wp-login.php.
	 */
	public function filter_site_url( $url, $path, $scheme, $blog_id ) {
		if ( false !== strpos( $path, 'wp-login.php' ) ) {
			$url = $this->replace_login_url( $url );
		}
		return $url;
	}

	/**
	 * Catch redirects to wp-login.php and rewrite them.
	 */
	public function filter_redirect( $location, $status ) {
		if ( false !== strpos( $location, 'wp-login.php' ) ) {
			$location = $this->replace_login_url( $location );
		}
		return $location;
	}

	/**
	 * Replace wp-login.php in a URL with the custom slug.
	 */
	private function replace_login_url( $url ) {
		return str_replace( 'wp-login.php', $this->custom_slug, $url );
	}

	/**
	 * Get the request path without query string.
	 */
	private function get_request_path() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( $_SERVER['REQUEST_URI'] ) : '';
		return rtrim( wp_parse_url( $request_uri, PHP_URL_PATH ), '/' ) ?: '/';
	}

	/**
	 * Show a WordPress 404 page.
	 */
	private function show_404() {
		status_header( 404 );
		nocache_headers();

		if ( file_exists( get_404_template() ) ) {
			include get_404_template();
		} else {
			wp_die( 'Pagina niet gevonden.', '404 Not Found', [ 'response' => 404 ] );
		}
		exit;
	}
}
