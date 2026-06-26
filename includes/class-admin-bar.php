<?php
/**
 * Admin Bar — snelkoppelingen in de WordPress-toolbar (boven, op front + admin).
 *
 * Doel: minder klikken én altijd-zichtbare status. Wanneer de anomalie-scan
 * UIT staat, kleurt de top-node rood ("scan UIT") zodat je het overal ziet en
 * niet vergeet 'm weer aan te zetten na een werksessie.
 *
 * Bevat:
 *   - Top-node "MCM Security" → klik = naar de instellingen.
 *   - 1-klik toggle voor de anomalie-scan (aan/uit, met nonce).
 *   - "Nu scannen" (anomalie) + "Instellingen openen".
 *   - Statusregel met de laatste scan-uitkomst.
 *
 * Alleen zichtbaar voor gebruikers met 'manage_options'.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Admin_Bar {

	public function __construct() {
		add_action( 'admin_bar_menu', [ __CLASS__, 'add_menu' ], 100 );
		add_action( 'admin_head', [ __CLASS__, 'print_styles' ] );
		add_action( 'wp_head', [ __CLASS__, 'print_styles' ] );
	}

	/**
	 * Bouw het toolbar-menu.
	 *
	 * @param WP_Admin_Bar $bar
	 */
	public static function add_menu( $bar ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! class_exists( 'MCM_Anomaly_Scanner' ) ) {
			return;
		}

		$active = MCM_Anomaly_Scanner::is_active();

		// Top-node — rood wanneer de scan uit staat.
		$label = $active ? 'MCM Security' : 'MCM Security — scan UIT';
		$bar->add_node( [
			'id'    => 'mcm-security',
			'title' => '<span class="ab-icon mcm-ab-shield">&#128737;</span><span class="ab-label">' . esc_html( $label ) . '</span>',
			'href'  => admin_url( 'tools.php?page=mcm-security' ),
			'meta'  => [ 'class' => $active ? 'mcm-ab-on' : 'mcm-ab-off' ],
		] );

		// 1-klik toggle.
		$toggle_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . MCM_Anomaly_Scanner::ACTION_TOGGLE ),
			MCM_Anomaly_Scanner::ACTION_TOGGLE
		);
		$bar->add_node( [
			'id'     => 'mcm-security-toggle',
			'parent' => 'mcm-security',
			'title'  => $active ? '⏸ Anomalie-scan UITzetten' : '▶ Anomalie-scan AANzetten',
			'href'   => $toggle_url,
		] );

		// Nu scannen.
		$scan_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . MCM_Anomaly_Scanner::ACTION_MANUAL_SCAN ),
			MCM_Anomaly_Scanner::ACTION_MANUAL_SCAN
		);
		$bar->add_node( [
			'id'     => 'mcm-security-scan-now',
			'parent' => 'mcm-security',
			'title'  => '🔍 Nu scannen (anomalie)',
			'href'   => $scan_url,
		] );

		// Laatste scan-uitkomst (alleen-lezen statusregel).
		$bar->add_node( [
			'id'     => 'mcm-security-status',
			'parent' => 'mcm-security',
			'title'  => self::status_line(),
			'href'   => admin_url( 'tools.php?page=mcm-security' ),
		] );

		// Instellingen.
		$bar->add_node( [
			'id'     => 'mcm-security-settings',
			'parent' => 'mcm-security',
			'title'  => '⚙ Instellingen openen',
			'href'   => admin_url( 'tools.php?page=mcm-security' ),
		] );
	}

	/**
	 * Korte tekstregel met de laatste anomalie-scan-uitkomst.
	 */
	private static function status_line() {
		$last = MCM_Anomaly_Scanner::get_last_results();
		if ( ! $last ) {
			return 'Laatste scan: nog niet uitgevoerd';
		}
		$findings = isset( $last['findings'] ) && is_array( $last['findings'] ) ? $last['findings'] : [];
		if ( empty( $findings ) ) {
			return 'Laatste scan: schoon ✓';
		}

		$counts = [ 'high' => 0, 'medium' => 0, 'low' => 0 ];
		foreach ( $findings as $f ) {
			$sev = isset( $f['severity'] ) ? $f['severity'] : 'low';
			if ( isset( $counts[ $sev ] ) ) {
				$counts[ $sev ]++;
			}
		}
		return sprintf(
			'Laatste scan: %d HIGH / %d MED / %d LOW',
			$counts['high'],
			$counts['medium'],
			$counts['low']
		);
	}

	/**
	 * Kleine CSS voor de rood/groen-status van de top-node.
	 */
	public static function print_styles() {
		if ( ! is_admin_bar_showing() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<style id="mcm-admin-bar-css">'
			. '#wpadminbar .mcm-ab-off > .ab-item{background:#d63638 !important;color:#fff !important;}'
			. '#wpadminbar .mcm-ab-off:hover > .ab-item,#wpadminbar .mcm-ab-off.hover > .ab-item{background:#b32d2e !important;color:#fff !important;}'
			. '#wpadminbar .mcm-ab-off .mcm-ab-shield{color:#fff !important;}'
			. '#wpadminbar .mcm-ab-on .mcm-ab-shield{color:#46d160 !important;}'
			. '</style>';
	}
}
