<?php
/**
 * WordPress major-update compatibility-check.
 *
 * Toont een waarschuwingstabel op de Updates-pagina (Dashboard → Updates)
 * vóór een major WordPress-update. Per actieve plugin wordt de "Tested up
 * to" uit de readme.txt vergeleken met de aankomende WP-versie.
 *
 * - 🟢 Compatibel       — readme.txt zegt: getest met deze WP-versie of nieuwer
 * - 🟡 Niet getest      — readme.txt zegt een oudere versie
 * - ⚪ Onbekend         — geen readme.txt of geen "Tested up to" gevonden
 *
 * WordPress staat de update gewoon toe — dit is een bewustwordings-laag,
 * geen blokkering.
 *
 * Toont alleen iets bij een major-update (minor-bumps overslaan).
 *
 * Zichtbaarheid: alleen voor MCM-eigenaars (via MCM_Notifier::should_show_admin_notice()).
 * Klanten zien deze technische tabel niet — past bij het beleid "alle
 * security-meldingen naar Marco, niet naar de klant".
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Update_Compat_Check {

	const STATUS_COMPATIBLE = 'compatible';
	const STATUS_RISKY      = 'risky';
	const STATUS_UNKNOWN    = 'unknown';

	public function __construct() {
		add_action( 'core_upgrade_preamble', [ $this, 'render_check' ] );
	}

	/**
	 * Render-callback boven aan de update-core.php pagina.
	 */
	public function render_check() {
		// Alleen MCM-eigenaars zien deze technische check — klanten niet.
		if ( ! class_exists( 'MCM_Notifier' ) || ! MCM_Notifier::should_show_admin_notice() ) {
			return;
		}

		$core_update = $this->get_available_core_update();
		if ( ! $core_update ) {
			return;
		}

		$current_version = get_bloginfo( 'version' );
		$target_version  = isset( $core_update->current ) ? $core_update->current : '';
		if ( empty( $target_version ) ) {
			return;
		}

		// Alleen tonen bij major-bump (major.minor verandert).
		if ( ! $this->is_major_bump( $current_version, $target_version ) ) {
			return;
		}

		$results = $this->scan_active_plugins( $target_version );
		if ( empty( $results ) ) {
			return;
		}

		$this->render_panel( $current_version, $target_version, $results );
	}

	/**
	 * Beschikbare core-update ophalen.
	 *
	 * @return object|false
	 */
	private function get_available_core_update() {
		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$update = get_preferred_from_update_core();
		if ( ! is_object( $update ) || empty( $update->response ) || 'upgrade' !== $update->response ) {
			return false;
		}
		return $update;
	}

	/**
	 * Major-bump (6.7 → 6.8 of 6.x → 7.x) vs minor/patch (6.7.1 → 6.7.2).
	 */
	private function is_major_bump( $current, $target ) {
		return $this->major_minor( $current ) !== $this->major_minor( $target );
	}

	private function major_minor( $version ) {
		$parts = explode( '.', (string) $version );
		return ( $parts[0] ?? '0' ) . '.' . ( $parts[1] ?? '0' );
	}

	/**
	 * Scan alle actieve plugins op compatibiliteit met de target-versie.
	 *
	 * @return array<int,array{name:string,version:string,tested:string,status:string,file:string}>
	 */
	private function scan_active_plugins( $target_version ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all_plugins = get_plugins();
		$active      = (array) get_option( 'active_plugins', [] );

		// Multisite network-active plugins erbij.
		if ( is_multisite() ) {
			$network_active = (array) get_site_option( 'active_sitewide_plugins', [] );
			$active         = array_unique( array_merge( $active, array_keys( $network_active ) ) );
		}

		$results = [];
		foreach ( $active as $file ) {
			if ( ! isset( $all_plugins[ $file ] ) ) {
				continue;
			}
			$data   = $all_plugins[ $file ];
			$tested = $this->extract_tested_up_to( $file );
			$status = $this->compare( $tested, $target_version );

			$results[] = [
				'file'    => $file,
				'name'    => $data['Name'] ?? $file,
				'version' => $data['Version'] ?? '',
				'tested'  => $tested,
				'status'  => $status,
			];
		}

		// Sorteer: risky eerst, dan unknown, dan compatible.
		$order = [ self::STATUS_RISKY => 0, self::STATUS_UNKNOWN => 1, self::STATUS_COMPATIBLE => 2 ];
		usort( $results, function ( $a, $b ) use ( $order ) {
			$cmp = ( $order[ $a['status'] ] ?? 9 ) <=> ( $order[ $b['status'] ] ?? 9 );
			if ( 0 !== $cmp ) {
				return $cmp;
			}
			return strcasecmp( $a['name'], $b['name'] );
		} );

		return $results;
	}

	/**
	 * Lees "Tested up to" uit de plugin's readme.txt (eerste 4 KB).
	 *
	 * @return string Lege string als niet gevonden.
	 */
	private function extract_tested_up_to( $plugin_file ) {
		$plugin_dir = WP_PLUGIN_DIR . '/' . dirname( $plugin_file );

		// Voor single-file plugins (geen subdir) — geen readme.txt naast.
		if ( '.' === dirname( $plugin_file ) ) {
			return '';
		}

		$readme = $plugin_dir . '/readme.txt';
		if ( ! file_exists( $readme ) ) {
			return '';
		}

		$content = @file_get_contents( $readme, false, null, 0, 4096 );
		if ( false === $content ) {
			return '';
		}

		if ( preg_match( '/^Tested up to:\s*([0-9.]+)/im', $content, $m ) ) {
			return trim( $m[1] );
		}
		return '';
	}

	private function compare( $tested, $target ) {
		if ( empty( $tested ) ) {
			return self::STATUS_UNKNOWN;
		}
		$tested_mm = $this->major_minor( $tested );
		$target_mm = $this->major_minor( $target );
		return version_compare( $tested_mm, $target_mm, '>=' )
			? self::STATUS_COMPATIBLE
			: self::STATUS_RISKY;
	}

	/**
	 * Render het waarschuwingsblok boven de update-knop.
	 */
	private function render_panel( $current_version, $target_version, array $results ) {
		$risky_count   = 0;
		$unknown_count = 0;
		$compat_count  = 0;
		foreach ( $results as $r ) {
			if ( self::STATUS_RISKY === $r['status'] ) {
				$risky_count++;
			} elseif ( self::STATUS_UNKNOWN === $r['status'] ) {
				$unknown_count++;
			} else {
				$compat_count++;
			}
		}

		// Helemaal groen? Korte success-melding.
		if ( 0 === $risky_count && 0 === $unknown_count ) {
			?>
			<div class="notice notice-success" style="margin: 16px 0; padding: 12px 16px;">
				<p style="margin: 0;">
					<strong>&#10003; MCM Security:</strong>
					Alle <?php echo (int) $compat_count; ?> actieve plugins zijn bevestigd compatibel met WordPress <?php echo esc_html( $target_version ); ?>.
				</p>
			</div>
			<?php
			return;
		}

		$panel_class = $risky_count > 0 ? 'notice-warning' : 'notice-info';
		?>
		<div class="notice <?php echo esc_attr( $panel_class ); ?>" style="margin: 16px 0; padding: 16px 20px;">
			<p style="margin: 0 0 12px; font-size: 14px;">
				<strong>MCM Security &mdash; Plugin-compatibiliteit met WordPress <?php echo esc_html( $target_version ); ?></strong>
			</p>
			<p style="margin: 0 0 12px;">
				Major-update van <code><?php echo esc_html( $current_version ); ?></code> &rarr; <code><?php echo esc_html( $target_version ); ?></code>.
				<?php if ( $risky_count > 0 ) : ?>
					<strong style="color: #b32d2e;"><?php echo (int) $risky_count; ?> plugin(s) niet getest</strong> met deze WP-versie.
				<?php endif; ?>
				<?php if ( $unknown_count > 0 ) : ?>
					<?php echo (int) $unknown_count; ?> plugin(s) geven geen compatibiliteits-info (geen <code>readme.txt</code> &mdash; vaak premium of custom plugins).
				<?php endif; ?>
				<?php if ( $compat_count > 0 ) : ?>
					<span style="color: #1e7e34;">&#10003; <?php echo (int) $compat_count; ?> bevestigd compatibel.</span>
				<?php endif; ?>
			</p>
			<table class="widefat striped" style="margin-top: 8px;">
				<thead>
					<tr>
						<th style="width: 90px;">Status</th>
						<th>Plugin</th>
						<th style="width: 100px;">Versie</th>
						<th style="width: 120px;">Getest tot</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $results as $r ) :
						list( $icon, $label, $color ) = $this->status_meta( $r['status'] );
					?>
					<tr>
						<td><span style="color: <?php echo esc_attr( $color ); ?>;"><?php echo esc_html( $icon . ' ' . $label ); ?></span></td>
						<td><?php echo esc_html( $r['name'] ); ?></td>
						<td><code><?php echo esc_html( $r['version'] ); ?></code></td>
						<td><?php echo $r['tested'] ? esc_html( $r['tested'] ) : '<em style="color:#646970;">&mdash;</em>'; ?></td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<p style="margin: 12px 0 0; color: #50575e; font-size: 13px;">
				WordPress staat de update gewoon toe. Dit is alleen een bewustwordings-check &mdash; controleer bij <strong>niet-geteste</strong> plugins of de leverancier al een nieuwere versie heeft uitgebracht voordat je doorgaat.
			</p>
		</div>
		<?php
	}

	private function status_meta( $status ) {
		switch ( $status ) {
			case self::STATUS_COMPATIBLE:
				return [ '&#10003;', 'Compatibel', '#1e7e34' ];
			case self::STATUS_RISKY:
				return [ '&#9888;', 'Niet getest', '#b32d2e' ];
			default:
				return [ '?', 'Onbekend', '#646970' ];
		}
	}
}
