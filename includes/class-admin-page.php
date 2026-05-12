<?php
/**
 * Admin settings page for MCM Security Hardener.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Admin_Page {

	const OPTION_KEY = 'mcm_security_settings';
	const NONCE      = 'mcm_security_nonce';

	public function __construct() {
		add_action( 'admin_menu', [ $this, 'add_menu' ] );
		add_action( 'admin_init', [ $this, 'handle_form' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_styles' ] );
		add_action( 'admin_notices', [ $this, 'render_mismatch_notice' ] );
	}

	public function add_menu() {
		add_management_page(
			'MCM Security Hardener',
			'MCM Security',
			'manage_options',
			'mcm-security',
			[ $this, 'render_page' ]
		);
	}

	public function enqueue_styles( $hook ) {
		if ( 'tools_page_mcm-security' !== $hook ) {
			return;
		}
		wp_add_inline_style( 'wp-admin', $this->get_inline_css() );
	}

	public function handle_form() {
		if ( ! isset( $_POST['mcm_security_action'] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! wp_verify_nonce( $_POST[ self::NONCE ], 'mcm_security_save' ) ) {
			wp_die( 'Ongeldige nonce.' );
		}

		$action = sanitize_key( $_POST['mcm_security_action'] );

		if ( 'save' === $action ) {
			$this->save_settings();
		} elseif ( 'apply' === $action ) {
			$this->apply_rules();
		} elseif ( 'remove' === $action ) {
			$this->remove_rules();
		} elseif ( 'enable_all' === $action ) {
			$this->enable_all();
		} elseif ( 'send_login_url_now' === $action ) {
			$this->send_login_url_now_action();
		} elseif ( 'quick_switch_profile' === $action ) {
			$target = isset( $_POST['target_profile'] ) ? sanitize_key( $_POST['target_profile'] ) : '';
			if ( $target ) {
				$result = MCM_Profiles::apply( $target );
				if ( is_wp_error( $result ) ) {
					$this->redirect( 'error' );
				} else {
					$this->redirect( 'profile_switched' );
				}
			} else {
				$this->redirect( 'error' );
			}
		} elseif ( 'reset_db_prefix_notice' === $action ) {
			delete_option( MCM_DB_Prefix_Manager::NOTICE_DISMISS_OPTION );
			$this->redirect( 'notice_reset' );
		} elseif ( 0 === strpos( $action, 'apply_profile_' ) ) {
			$profile = substr( $action, strlen( 'apply_profile_' ) );
			$result  = MCM_Profiles::apply( $profile );
			if ( is_wp_error( $result ) ) {
				$this->redirect( 'error' );
			} else {
				$this->redirect( 'profile_applied_' . $profile );
			}
		} elseif ( 'run_detection' === $action ) {
			set_transient( 'mcm_security_detection', MCM_Profiles::recommend_profile(), HOUR_IN_SECONDS );
			$this->redirect( 'detected' );
		}
	}

	private function save_settings() {
		$old_slug = $this->get_current_slug();
		$settings = $this->sanitize_input( $_POST );
		update_option( self::OPTION_KEY, $settings );
		$this->maybe_send_slug_change_mail( $old_slug, $settings );
		$this->redirect( 'saved' );
	}

	private function apply_rules() {
		$old_slug = $this->get_current_slug();
		$settings = $this->sanitize_input( $_POST );
		update_option( self::OPTION_KEY, $settings );

		$config_result   = MCM_WPConfig_Manager::write( $settings );
		$htaccess_result = MCM_Htaccess_Manager::write( $settings );

		$this->maybe_send_slug_change_mail( $old_slug, $settings );

		if ( is_wp_error( $config_result ) || is_wp_error( $htaccess_result ) ) {
			$this->redirect( 'error' );
		} else {
			$this->redirect( 'applied' );
		}
	}

	/**
	 * Huidige (opgeslagen) login-slug uit de DB.
	 */
	private function get_current_slug() {
		$current = get_option( self::OPTION_KEY, [] );
		return isset( $current['login_slug'] ) ? (string) $current['login_slug'] : '';
	}

	/**
	 * Wrapper: alleen mailen als de toggle aan staat én de slug daadwerkelijk
	 * is gewijzigd. Wordt aangeroepen na save/apply.
	 */
	private function maybe_send_slug_change_mail( $old_slug, $settings ) {
		if ( empty( $settings['mail_admins_on_slug_change'] ) ) {
			return;
		}
		$new_slug = isset( $settings['login_slug'] ) ? (string) $settings['login_slug'] : '';
		if ( $old_slug === $new_slug ) {
			return; // niets veranderd.
		}
		$recipient_ids = ! empty( $settings['mail_admins_recipients'] ) ? (array) $settings['mail_admins_recipients'] : [];
		if ( empty( $recipient_ids ) ) {
			return;
		}
		$this->send_login_url_mail( $recipient_ids, $new_slug, true );
	}

	/**
	 * Handler voor de "Verstuur nu" knop. Slaat eerst de huidige form-staat op
	 * (zodat zojuist aangevinkte ontvangers meetellen), verstuurt daarna,
	 * en redirect met een status die het aantal verzonden mails meegeeft.
	 */
	private function send_login_url_now_action() {
		// Sla eerst de form-staat op zodat aangevinkte recipients meetellen.
		$settings = $this->sanitize_input( $_POST );
		update_option( self::OPTION_KEY, $settings );

		$sent = $this->send_login_url_now();
		if ( 0 === $sent ) {
			$this->redirect( 'mail_none' );
		} else {
			wp_safe_redirect(
				add_query_arg(
					[
						'mcm-status' => 'mail_sent',
						'mcm-count'  => $sent,
					],
					admin_url( 'tools.php?page=mcm-security' )
				)
			);
			exit;
		}
	}

	/**
	 * Verstuur de login-URL nu naar de huidige geselecteerde admins,
	 * onafhankelijk van de toggle. Aangeroepen door de "Verstuur nu" knop.
	 *
	 * @return int Aantal verstuurde mails.
	 */
	private function send_login_url_now() {
		$settings      = get_option( self::OPTION_KEY, [] );
		$recipient_ids = ! empty( $settings['mail_admins_recipients'] ) ? (array) $settings['mail_admins_recipients'] : [];
		if ( empty( $recipient_ids ) ) {
			return 0;
		}
		$current_slug = isset( $settings['login_slug'] ) ? (string) $settings['login_slug'] : '';
		return $this->send_login_url_mail( $recipient_ids, $current_slug, false );
	}

	/**
	 * Pure mail-sender. Stuurt de login-URL naar opgegeven user IDs.
	 *
	 * Bewust via wp_mail() direct (NIET via MCM_Notifier): die mailt altijd
	 * naar de plugin-eigenaar (Marco). Deze feature mailt juist naar door
	 * Marco geselecteerde admins op die specifieke site.
	 *
	 * @param array  $recipient_ids User IDs (worden hier nogmaals tegen
	 *                              manage_options gevalideerd).
	 * @param string $slug          De login-slug (leeg = standaard wp-login.php).
	 * @param bool   $is_change     True = mail meldt een wijziging,
	 *                              False = mail meldt de huidige (handmatig verstuurd).
	 * @return int Aantal verstuurde mails.
	 */
	private function send_login_url_mail( $recipient_ids, $slug, $is_change ) {
		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$home_url  = home_url( '/' );
		$login_url = $slug ? home_url( '/' . $slug ) : home_url( '/wp-login.php' );

		$current_user = wp_get_current_user();
		$by_who       = $current_user && $current_user->exists()
			? sprintf( '%s (%s)', $current_user->display_name, $current_user->user_email )
			: 'onbekend';

		$timestamp = wp_date( 'd-m-Y H:i' );

		if ( $is_change ) {
			$subject = sprintf( '[%s] Login-URL is gewijzigd', $site_name );
			$intro   = sprintf( "De login-URL van %s is zojuist aangepast.\n\n", $site_name );
			$by_label = 'Gewijzigd door';
		} else {
			$subject = sprintf( '[%s] Je login-URL', $site_name );
			$intro   = sprintf( "Hierbij ter herinnering de login-URL van %s.\n\n", $site_name );
			$by_label = 'Verstuurd door';
		}

		$body  = "Beste,\n\n" . $intro;
		$body .= "Site: {$home_url}\n";
		$body .= "Login-URL: {$login_url}\n";
		if ( ! $slug ) {
			$body .= "(Let op: er is geen custom login-slug ingesteld — er wordt ingelogd via de standaard /wp-login.php.)\n";
		}
		$body .= "\n{$by_label}: {$by_who}\n";
		$body .= "Tijdstip: {$timestamp}\n\n";
		$body .= "Bewaar deze mail veilig. Je gebruikersnaam en wachtwoord zijn niet gewijzigd; gebruik gewoon je bestaande inloggegevens.\n\n";
		$body .= "— MCM Security Hardener\n";

		$headers = [ 'Content-Type: text/plain; charset=UTF-8' ];

		$sent = 0;
		foreach ( $recipient_ids as $user_id ) {
			$user = get_user_by( 'id', (int) $user_id );
			if ( ! self::user_is_eligible_recipient( $user ) || empty( $user->user_email ) ) {
				continue;
			}
			if ( wp_mail( $user->user_email, $subject, $body, $headers ) ) {
				$sent++;
			}
		}
		return $sent;
	}

	private function remove_rules() {
		MCM_WPConfig_Manager::remove();
		MCM_Htaccess_Manager::remove();
		$this->redirect( 'removed' );
	}

	private function enable_all() {
		$settings = MCM_Security_Hardener::get_defaults();
		// Preserve user-specific values.
		$settings['admin_email']      = isset( $_POST['admin_email'] ) ? sanitize_email( $_POST['admin_email'] ) : get_option( 'admin_email', '' );
		$settings['login_slug']       = isset( $_POST['login_slug'] ) && ! empty( $_POST['login_slug'] ) ? sanitize_title( $_POST['login_slug'] ) : 'inloggenwebsite';
		$settings['bad_referers_list'] = isset( $_POST['bad_referers_list'] ) ? sanitize_textarea_field( $_POST['bad_referers_list'] ) : '';
		$settings['human_verification_delay'] = isset( $_POST['human_verification_delay'] )
			? max( 1, min( 30, (int) $_POST['human_verification_delay'] ) )
			: 3;

		// Bewaar de mail-ontvangerslijst — anders raakt de eerder aangevinkte
		// selectie kwijt als per ongeluk op "Activeer Alles" geklikt wordt.
		$existing = get_option( self::OPTION_KEY, [] );
		if ( ! empty( $existing['mail_admins_recipients'] ) ) {
			$settings['mail_admins_recipients'] = $this->sanitize_recipient_ids( (array) $existing['mail_admins_recipients'] );
		}

		update_option( self::OPTION_KEY, $settings );

		MCM_WPConfig_Manager::write( $settings );
		MCM_Htaccess_Manager::write( $settings );

		$this->redirect( 'all_enabled' );
	}

	private function redirect( $status ) {
		wp_safe_redirect( add_query_arg( 'mcm-status', $status, admin_url( 'tools.php?page=mcm-security' ) ) );
		exit;
	}

	private function sanitize_input( $post ) {
		$checkboxes = [
			// wp-config
			'disallow_file_edit', 'disallow_unfiltered', 'skip_bundled',
			'no_concatenate', 'no_repair', 'no_relocate', 'no_db_error',
			'no_debug_display', 'lock_admin_email',
			'auto_update_minor', 'random_cookie_hash', 'secure_keys',
			// lockdown
			'disallow_file_mods', 'lockdown_plugins', 'lockdown_themes',
			// endpoints & version hiding
			'hide_wp_version', 'hide_php_version', 'robots_blackhole',
			'block_bad_urls',
			// bad behaviors
			'block_bad_user_agents', 'block_fake_seo_bots',
			'block_bad_referers', 'block_ai_bots',
			// malicious URLs
			'block_bad_url_content', 'block_php_404',
			// .htaccess
			'block_readme_files', 'block_sensitive_php', 'disable_directory_listing',
			'block_php_easter_eggs', 'block_script_concat', 'block_xmlrpc',
			'block_debug_log', 'block_log_txt_files', 'block_php_in_uploads',
			'block_wp_includes_php',
			// human verification
			'human_verification',
		];

		$settings = [];
		foreach ( $checkboxes as $key ) {
			$settings[ $key ] = ! empty( $post[ $key ] );
		}

		$settings['admin_email']      = isset( $post['admin_email'] ) ? sanitize_email( $post['admin_email'] ) : '';
		$settings['login_slug']       = isset( $post['login_slug'] ) ? sanitize_title( $post['login_slug'] ) : '';
		$settings['bad_referers_list'] = isset( $post['bad_referers_list'] ) ? sanitize_textarea_field( $post['bad_referers_list'] ) : '';
		$settings['human_verification_delay'] = isset( $post['human_verification_delay'] )
			? max( 1, min( 30, (int) $post['human_verification_delay'] ) )
			: 3;

		// Mail-bij-slug-wijziging.
		$settings['mail_admins_on_slug_change'] = ! empty( $post['mail_admins_on_slug_change'] );
		$settings['mail_admins_recipients']     = $this->sanitize_recipient_ids( isset( $post['mail_admins_recipients'] ) ? (array) $post['mail_admins_recipients'] : [] );

		return $settings;
	}

	/**
	 * Bron-van-waarheid: wie mag onze plugin-mails ontvangen?
	 *
	 * Administrators (volledige toegang) én MCM Klanten (custom rol uit de
	 * Site Optimizer plugin — die rol heeft géén manage_options maar moet
	 * wél staging-credentials & login-URL kunnen ontvangen).
	 *
	 * @return array van WP_User objecten.
	 */
	public static function get_eligible_mail_users() {
		return get_users(
			[
				'role__in' => [ 'administrator', 'mcm_klant' ],
				'orderby'  => 'display_name',
				'order'    => 'ASC',
			]
		);
	}

	/**
	 * Mag deze user mail ontvangen? Centrale check, gebruikt door zowel
	 * de UI-render als de sanitize-flow als de mail-sender.
	 */
	public static function user_is_eligible_recipient( $user ) {
		if ( ! $user || ! ( $user instanceof WP_User ) ) {
			return false;
		}
		if ( user_can( $user, 'manage_options' ) ) {
			return true;
		}
		if ( in_array( 'mcm_klant', (array) $user->roles, true ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Filter ingestuurde user IDs naar enkel users die mail mogen ontvangen
	 * (admins of MCM Klant rol).
	 */
	private function sanitize_recipient_ids( $ids ) {
		$clean = [];
		foreach ( $ids as $id ) {
			$id   = absint( $id );
			$user = $id ? get_user_by( 'id', $id ) : false;
			if ( self::user_is_eligible_recipient( $user ) ) {
				$clean[] = $id;
			}
		}
		return array_values( array_unique( $clean ) );
	}

	public function render_page() {
		$settings        = get_option( self::OPTION_KEY, MCM_Security_Hardener::get_defaults() );
		$config_active   = MCM_WPConfig_Manager::is_active();
		$htaccess_active = MCM_Htaccess_Manager::is_active();
		$status          = isset( $_GET['mcm-status'] ) ? sanitize_key( $_GET['mcm-status'] ) : '';
		?>
		<div class="wrap mcm-security-wrap">
			<h1>MCM Security Hardener <span class="mcm-version">v<?php echo esc_html( MCM_SECURITY_VERSION ); ?></span></h1>

			<?php $this->render_notice( $status ); ?>

			<div class="mcm-status-bar">
				<span class="mcm-badge <?php echo $config_active ? 'mcm-badge-active' : 'mcm-badge-inactive'; ?>">
					wp-config.php: <?php echo $config_active ? 'Actief' : 'Niet actief'; ?>
				</span>
				<span class="mcm-badge <?php echo $htaccess_active ? 'mcm-badge-active' : 'mcm-badge-inactive'; ?>">
					.htaccess: <?php echo $htaccess_active ? 'Actief' : 'Niet actief'; ?>
				</span>
			</div>

			<form method="post">
				<?php wp_nonce_field( 'mcm_security_save', self::NONCE ); ?>

				<?php $this->render_profiles_section(); ?>

				<?php $this->render_staging_detection(); ?>

				<?php $this->render_action_buttons(); ?>

				<!-- LOGIN URL -->
				<div class="mcm-section">
					<h2>Login URL Verbergen</h2>
					<p class="description">Verbergt <code>/wp-login.php</code> en maakt een custom login-slug aan.</p>
					<table class="form-table">
						<tr>
							<th scope="row"><label for="login_slug">Custom login slug</label></th>
							<td>
								<code><?php echo esc_html( home_url( '/' ) ); ?></code>
								<input type="text" id="login_slug" name="login_slug"
									value="<?php echo esc_attr( $settings['login_slug'] ?? '' ); ?>"
									class="regular-text" placeholder="inloggenwebsite"
									style="width: 200px;" />
								<p class="description">Laat leeg om uit te schakelen.</p>
								<?php if ( ! empty( $settings['login_slug'] ) ) : ?>
								<p class="description" style="margin-top: 8px;">
									<strong>Login URL:</strong>
									<a href="<?php echo esc_url( home_url( '/' . $settings['login_slug'] ) ); ?>" target="_blank">
										<?php echo esc_html( home_url( '/' . $settings['login_slug'] ) ); ?>
									</a>
								</p>
								<?php endif; ?>
							</td>
						</tr>
						<?php
						$this->render_toggle(
							'mail_admins_on_slug_change',
							'Mail nieuwe login-URL na opslaan',
							'Stuurt na een wijziging van de login-slug automatisch een e-mail met de nieuwe URL naar de hieronder geselecteerde beheerders. Het wachtwoord wordt nooit meegestuurd. Wordt niet getriggerd door de knop "Activeer Alles".',
							$settings
						);
						?>
						<tr>
							<th scope="row">Ontvangers (beheerders)</th>
							<td>
								<?php
								$selected_ids = isset( $settings['mail_admins_recipients'] ) && is_array( $settings['mail_admins_recipients'] )
									? array_map( 'intval', $settings['mail_admins_recipients'] )
									: [];

								$users = self::get_eligible_mail_users();

								if ( empty( $users ) ) {
									echo '<p class="description"><em>Geen beheerders of MCM Klanten gevonden.</em></p>';
								} else {
									echo '<fieldset style="border:1px solid #ddd; padding:8px 12px; max-height:220px; overflow:auto; border-radius:3px;">';
									foreach ( $users as $u ) {
										$checked = in_array( (int) $u->ID, $selected_ids, true ) ? 'checked' : '';
										// Rol-badge: admin of MCM Klant.
										if ( user_can( $u, 'manage_options' ) ) {
											$badge_html = '<span style="display:inline-block; padding:1px 6px; margin-left:6px; background:#e7f0fa; color:#0a4b78; border-radius:3px; font-size:10px; font-weight:600;">ADMIN</span>';
										} else {
											$badge_html = '<span style="display:inline-block; padding:1px 6px; margin-left:6px; background:#e8f5e9; color:#1b5e20; border-radius:3px; font-size:10px; font-weight:600;">MCM KLANT</span>';
										}
										printf(
											'<label style="display:block; padding:3px 0;"><input type="checkbox" name="mail_admins_recipients[]" value="%d" %s /> %s%s &nbsp;<code style="font-size:11px; color:#666;">%s</code></label>',
											(int) $u->ID,
											$checked,
											esc_html( $u->display_name ),
											$badge_html,
											esc_html( $u->user_email )
										);
									}
									echo '</fieldset>';
									echo '<p class="description">Vink aan welke ontvangers de mail moeten krijgen. Administrators &eacute;n MCM Klanten worden getoond.</p>';
								}
								?>
								<p style="margin-top:12px;">
									<button type="submit" name="mcm_security_action" value="send_login_url_now" class="button button-secondary">
										Verstuur login-URL nu naar geselecteerde admins
									</button>
									<span class="description" style="margin-left:8px;">Verstuurt direct (zonder slug-wijziging). Slaat eerst je huidige selectie op.</span>
								</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- DATABASE PREFIX -->
				<?php if ( ! is_multisite() ) : ?>
				<div class="mcm-section">
					<h2>Database Prefix</h2>
					<?php
					global $wpdb;
					$is_default = MCM_DB_Prefix_Manager::is_default_prefix();
					$dismissed  = get_option( MCM_DB_Prefix_Manager::NOTICE_DISMISS_OPTION );
					?>
					<table class="form-table">
						<tr>
							<th scope="row">Huidige prefix</th>
							<td>
								<code><?php echo esc_html( $wpdb->prefix ); ?></code>
								<?php if ( $is_default ) : ?>
									<span style="color: #b32d2e; margin-left: 10px;">&#9888; Onveilig (default)</span>
								<?php else : ?>
									<span style="color: #1e7e34; margin-left: 10px;">&#10003; Random / aangepast</span>
								<?php endif; ?>
							</td>
						</tr>
						<?php if ( $is_default ) : ?>
						<tr>
							<th scope="row">Migreren naar random prefix</th>
							<td>
								<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=mcm_change_db_prefix' ), MCM_DB_Prefix_Manager::NONCE_ACTION ) ); ?>"
									class="button button-primary"
									onclick="return confirm('Weet je zeker dat je de DB-prefix wilt veranderen? Maak EERST een volledige backup. Iedereen kan uitgelogd worden.');">
									Verander prefix nu
								</a>
								<p class="description">
									Hernoemt alle tabellen, patcht <code>wp-config.php</code>, en past <code>option_name</code> + <code>meta_key</code> rijen aan.
									Een SQL-backup van wijzigende rijen wordt opgeslagen in <code>wp-content/uploads/mcm-security-backups/</code>.
								</p>
							</td>
						</tr>
						<?php if ( $dismissed ) : ?>
						<tr>
							<th scope="row">Globale notice</th>
							<td>
								<button type="submit" name="mcm_security_action" value="reset_db_prefix_notice" class="button">
									Notice opnieuw tonen
								</button>
								<p class="description">De waarschuwingsbalk bovenaan admin pages weer aanzetten.</p>
							</td>
						</tr>
						<?php endif; ?>
						<?php endif; ?>
					</table>
				</div>
				<?php endif; ?>

				<!-- HUMAN VERIFICATION -->
				<div class="mcm-section">
					<h2>Human Verification</h2>
					<p class="description">SecuPress-stijl: een vinkje dat zichzelf na een paar seconden via CSS-animatie aanvinkt. Bots die het formulier direct submitten worden geblokkeerd. Werkt zonder JavaScript.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'human_verification', 'Activeer human verification', 'Toont een verificatie-vinkje op login-, registratie- en wachtwoord-vergeten-formulieren. Submissies binnen de vertraging worden geweigerd.', $settings );
						?>
						<tr>
							<th scope="row"><label for="human_verification_delay">Vertraging (seconden)</label></th>
							<td>
								<input type="number" id="human_verification_delay" name="human_verification_delay"
									value="<?php echo esc_attr( $settings['human_verification_delay'] ?? 3 ); ?>"
									min="1" max="30" step="1" style="width: 80px;" />
								<p class="description">Hoeveel seconden de animatie duurt voordat het vinkje gezet is. Aanrader: 2&ndash;5 seconden.</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- WP-CONFIG HARDENING -->
				<div class="mcm-section">
					<h2>WordPress Core Hardening</h2>
					<p class="description">Constanten die in wp-config.php worden ge&iuml;njecteerd.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'auto_update_minor', 'Auto-update minor versies', 'WP_AUTO_UPDATE_CORE=minor &mdash; automatische beveiligingsupdates voor WordPress.', $settings );
						$this->render_toggle( 'no_concatenate', 'Disable script concatenatie', 'CONCATENATE_SCRIPTS=false &mdash; voorkomt load-scripts.php DoS aanvallen.', $settings );
						$this->render_toggle( 'no_debug_display', 'Verberg foutmeldingen', 'WP_DEBUG_DISPLAY=false &mdash; toont geen PHP errors op de frontend.', $settings );
						$this->render_toggle( 'no_relocate', 'Blokkeer site relocatie', 'RELOCATE=false &mdash; voorkomt ongeautoriseerde site-verplaatsing.', $settings );
						$this->render_toggle( 'disallow_file_edit', 'Blokkeer bestandsbewerker', 'DISALLOW_FILE_EDIT &mdash; voorkomt bewerken van theme/plugin bestanden in WP admin.', $settings );
						$this->render_toggle( 'disallow_unfiltered', 'Filter bestandsuploads', 'ALLOW_UNFILTERED_UPLOADS=false &mdash; staat alleen veilige bestandstypen toe.', $settings );
						$this->render_toggle( 'no_db_error', 'Verberg database fouten', 'DIEONDBERROR=false &mdash; toont geen DB foutmeldingen aan bezoekers.', $settings );
						$this->render_toggle( 'no_repair', 'Blokkeer database repair', 'WP_ALLOW_REPAIR=false &mdash; voorkomt ongeautoriseerde DB reparatie.', $settings );
						$this->render_toggle( 'random_cookie_hash', 'Random cookie hash', 'COOKIEHASH &mdash; wijzigt de standaard cookie-naam naar een willekeurige waarde.', $settings );
						$this->render_toggle( 'secure_keys', 'Beveiligde sleutels genereren', 'Genereert sterke AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY en bijbehorende salts.', $settings );
						$this->render_toggle( 'skip_bundled', 'Skip gebundelde themes', 'CORE_UPGRADE_SKIP_NEW_BUNDLED &mdash; voegt geen nieuwe default themes toe bij core updates.', $settings );
						$this->render_toggle( 'lock_admin_email', 'Vergrendel admin e-mail', 'Voorkomt wijzigen van het admin e-mailadres.', $settings );
						?>
						<tr>
							<th scope="row"><label for="admin_email">Admin e-mail</label></th>
							<td>
								<input type="email" id="admin_email" name="admin_email"
									value="<?php echo esc_attr( $settings['admin_email'] ?? '' ); ?>"
									class="regular-text" />
								<p class="description">E-mailadres dat vergrendeld wordt.</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- PLUGINS & THEMES LOCKDOWN -->
				<div class="mcm-section">
					<h2>Plugins &amp; Themes Lockdown</h2>
					<p class="description">Vergrendelt alle plugin- en theme-acties.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'disallow_file_mods', 'Blokkeer bestandswijzigingen', 'DISALLOW_FILE_MODS &mdash; blokkeert uploaden, installeren, updaten en verwijderen op bestandsniveau.', $settings );
						$this->render_toggle( 'lockdown_plugins', 'Vergrendel alle plugin-acties', 'Blokkeert activeren, deactiveren, installeren, updaten, verwijderen en uploaden van plugins.', $settings );
						$this->render_toggle( 'lockdown_themes', 'Vergrendel alle theme-acties', 'Blokkeert installeren, updaten, verwijderen, wisselen en uploaden van themes.', $settings );
						?>
					</table>
					<?php if ( ! empty( $settings['lockdown_plugins'] ) || ! empty( $settings['lockdown_themes'] ) ) : ?>
					<p class="description" style="margin-top: 10px; padding: 8px 12px; background: #fff3cd; border-left: 4px solid #ffc107;">
						<strong>Let op:</strong> De MCM Security instellingenpagina blijft altijd bereikbaar.
					</p>
					<?php endif; ?>
				</div>

				<!-- SENSITIVE ENDPOINTS -->
				<div class="mcm-section">
					<h2>Gevoelige Endpoints &amp; Versie-info</h2>
					<p class="description">Verbergt versie-informatie en beschermt gevoelige endpoints.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'block_xmlrpc', 'Blokkeer XML-RPC', 'Blokkeert xmlrpc.php volledig (brute force / DDoS vector).', $settings );
						$this->render_toggle( 'robots_blackhole', 'Robots.txt blackhole', 'Voegt honeypot-URLs toe aan robots.txt om kwaadaardige bots te vangen.', $settings );
						$this->render_toggle( 'disable_directory_listing', 'Schakel directory listing uit', 'Options -Indexes &mdash; voorkomt dat mappeninhoud zichtbaar is.', $settings );
						$this->render_toggle( 'block_php_easter_eggs', 'Blokkeer PHP info disclosure', 'Blokkeert PHP Easter Eggs informatielekken.', $settings );
						$this->render_toggle( 'hide_php_version', 'Verwijder PHP versie', 'Verwijdert X-Powered-By header en ServerSignature.', $settings );
						$this->render_toggle( 'hide_wp_version', 'Verwijder WordPress versie', 'Verwijdert WP generator tag, ?ver= parameters en readme.html.', $settings );
						$this->render_toggle( 'block_readme_files', 'Blokkeer readme/changelog bestanden', 'Retourneert 404 voor readme.txt, changelog.md, debug.log, etc.', $settings );
						$this->render_toggle( 'block_sensitive_php', 'Blokkeer gevoelige PHP bestanden', 'Blokkeert directe toegang tot wp-config.php, install.php, en admin-includes.', $settings );
						$this->render_toggle( 'block_bad_urls', 'Blokkeer verdachte URLs', 'Blokkeert bekende aanvalspaden (.env, .git, backup bestanden, shells).', $settings );
						?>
					</table>
				</div>

				<!-- BAD BEHAVIORS -->
				<div class="mcm-section">
					<h2>Bad Behaviors</h2>
					<p class="description">Blokkeert kwaadaardige bots, fake crawlers en ongewenste referers.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'block_bad_user_agents', 'Blokkeer bad user agents', 'Blokkeert scanners, scrapers en bekende kwaadaardige user agents (SQLMap, Nikto, WPScan, etc).', $settings );
						$this->render_toggle( 'block_fake_seo_bots', 'Blokkeer fake SEO bots', 'Verifieert Googlebot, Bingbot, Yandex en Baidu via reverse DNS. Fakes worden geblokkeerd.', $settings );
						$this->render_toggle( 'block_ai_bots', 'Blokkeer AI bots', 'Blokkeert GPTBot, ClaudeBot, CCBot, Bytespider, PetalBot en andere AI crawlers.', $settings );
						$this->render_toggle( 'block_bad_referers', 'Blokkeer bad referers', 'Blokkeert bekende spam-referers + je eigen lijst.', $settings );
						?>
						<tr>
							<th scope="row"><label for="bad_referers_list">Bad referers lijst</label></th>
							<td>
								<textarea id="bad_referers_list" name="bad_referers_list" rows="5" class="large-text code"
									placeholder="spam-domain.com&#10;bad-referer.net"><?php echo esc_textarea( $settings['bad_referers_list'] ?? '' ); ?></textarea>
								<p class="description">E&eacute;n domein per regel. Wordt samengevoegd met de ingebouwde spam-lijst.</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- MALICIOUS URLs -->
				<div class="mcm-section">
					<h2>Malicious URLs</h2>
					<p class="description">Beschermt tegen SQL injection, XSS, path traversal en PHP-bestandsscanning.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'block_bad_url_content', 'Blokkeer kwaadaardige URL-content', 'Blokkeert SQL injection, XSS, path traversal en PHP wrapper pogingen in URLs.', $settings );
						$this->render_toggle( 'block_php_404', 'Blokkeer 404 op PHP bestanden', 'Retourneert 403 in plaats van 404 voor niet-bestaande .php bestanden (voorkomt scanning).', $settings );
						?>
					</table>
				</div>

				<!-- .HTACCESS HARDENING -->
				<div class="mcm-section">
					<h2>.htaccess Hardening</h2>
					<p class="description">Regels die in .htaccess worden geschreven voor server-niveau bescherming.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'block_script_concat', 'Blokkeer load-scripts DoS', 'Blokkeert load-scripts.php en load-styles.php (DoS vector).', $settings );
						$this->render_toggle( 'block_debug_log', 'Blokkeer debug.log toegang', 'Blokkeert publieke toegang tot debug.log.', $settings );
						$this->render_toggle( 'block_log_txt_files', 'Blokkeer .log en .txt bestanden', 'Blokkeert alle .log en .txt bestanden voor publieke toegang.', $settings );
						$this->render_toggle( 'block_php_in_uploads', 'Blokkeer PHP in uploads', 'Voorkomt uitvoering van PHP-bestanden in wp-content/uploads/.', $settings );
						$this->render_toggle( 'block_wp_includes_php', 'Blokkeer wp-includes PHP', 'Blokkeert directe PHP-toegang in wp-includes/ (behalve TinyMCE en JS).', $settings );
						?>
					</table>
				</div>

				<?php $this->render_action_buttons(); ?>
			</form>
		</div>
		<?php
	}

	private function render_profiles_section() {
		$profiles         = MCM_Profiles::get_profiles();
		$active_profile   = get_option( 'mcm_security_active_profile', '' );
		$detection        = get_transient( 'mcm_security_detection' );
		$detected_profile = MCM_Profiles::detect_current_profile();
		$force_show       = ! empty( $_GET['show_profiles'] );

		// Als settings exact matchen met een profiel: toon condensed banner.
		if ( $detected_profile && ! $force_show ) {
			$matched          = $profiles[ $detected_profile ];
			$scan_recommends_other = ( $detection && is_array( $detection ) && $detection['profile'] !== $detected_profile );
			?>
			<div class="mcm-section mcm-profile-confirmation">
				<h2>Profielen</h2>
				<div class="mcm-profile-matched">
					<span class="mcm-profile-check">&#10003;</span>
					<div>
						<p class="mcm-profile-matched-title">
							Profiel <strong><?php echo esc_html( $matched['label'] ); ?></strong> is actief
						</p>
						<p class="description">
							Alle instellingen kloppen exact volgens deze preset. <?php echo esc_html( $matched['description'] ); ?>
						</p>
					</div>
				</div>
				<p>
					<a href="<?php echo esc_url( add_query_arg( 'show_profiles', '1' ) ); ?>" class="button">
						Toon profielen om te wisselen
					</a>
					<button type="submit" name="mcm_security_action" value="run_detection" class="button">
						Opnieuw scannen
					</button>
				</p>

				<?php if ( $detection && is_array( $detection ) ) : ?>
					<div class="mcm-detection-results <?php echo $scan_recommends_other ? 'mcm-detection-mismatch' : ''; ?>">
						<h4>
							Laatste scan: aanbevolen profiel <code><?php echo esc_html( $profiles[ $detection['profile'] ]['label'] ); ?></code>
							<?php if ( $scan_recommends_other ) : ?>
								<span class="mcm-mismatch-badge">Wijkt af van actief profiel</span>
							<?php else : ?>
								<span class="mcm-match-badge">Komt overeen met actief profiel</span>
							<?php endif; ?>
						</h4>
						<?php if ( $scan_recommends_other ) : ?>
							<p>
								De scan beveelt <strong><?php echo esc_html( $profiles[ $detection['profile'] ]['label'] ); ?></strong> aan
								op basis van gedetecteerde integraties. Klik <em>Toon profielen om te wisselen</em> om aan te passen.
							</p>
						<?php endif; ?>

						<?php if ( ! empty( $detection['avoid'] ) ) : ?>
							<p class="description">
								Niet aanzetten: <code><?php echo esc_html( implode( '</code>, <code>', $detection['avoid'] ) ); ?></code>
							</p>
						<?php endif; ?>

						<?php if ( ! empty( $detection['detections'] ) ) : ?>
							<table class="widefat striped mcm-detection-table">
								<thead>
									<tr>
										<th>Gedetecteerd</th>
										<th>Risico</th>
										<th>Vermijden</th>
										<th>Reden</th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $detection['detections'] as $d ) : ?>
										<tr>
											<td><strong><?php echo esc_html( $d['name'] ); ?></strong></td>
											<td>
												<span class="mcm-risk mcm-risk-<?php echo esc_attr( $d['risk'] ); ?>">
													<?php echo esc_html( ucfirst( $d['risk'] ) ); ?>
												</span>
											</td>
											<td>
												<?php echo $d['avoid'] ? '<code>' . esc_html( implode( '</code>, <code>', $d['avoid'] ) ) . '</code>' : '&mdash;'; ?>
											</td>
											<td><?php echo esc_html( $d['reason'] ); ?></td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				<?php endif; ?>
			</div>
			<?php
			return;
		}
		?>
		<div class="mcm-section mcm-profiles-section">
			<h2>Profielen</h2>
			<p class="description">
				Kies een startpunt op basis van wat je site doet. Daarna kun je individuele instellingen nog aanpassen.
				Klik <strong>Scan deze site</strong> voor een aanbeveling op basis van actieve plugins.
			</p>

			<div class="mcm-profile-grid">
				<?php foreach ( $profiles as $key => $profile ) :
					$is_active = ( $active_profile === $key );
					?>
					<div class="mcm-profile-card <?php echo $is_active ? 'is-active' : ''; ?>">
						<div class="mcm-profile-header">
							<h3><?php echo esc_html( $profile['label'] ); ?></h3>
							<span class="mcm-profile-tagline"><?php echo esc_html( $profile['tagline'] ); ?></span>
							<?php if ( $is_active ) : ?>
								<span class="mcm-profile-active-badge">Actief</span>
							<?php endif; ?>
						</div>
						<p><?php echo esc_html( $profile['description'] ); ?></p>
						<p class="mcm-profile-safe-for"><strong>Geschikt voor:</strong> <?php echo esc_html( $profile['safe_for'] ); ?></p>
						<button type="submit" name="mcm_security_action" value="apply_profile_<?php echo esc_attr( $key ); ?>"
							class="button <?php echo $is_active ? 'button-secondary' : 'button-primary'; ?>"
							onclick="return confirm('Weet je zeker dat je profiel <?php echo esc_js( $profile['label'] ); ?> wilt toepassen? Dit overschrijft alle huidige toggle-instellingen.');">
							<?php echo $is_active ? 'Opnieuw toepassen' : 'Profiel toepassen'; ?>
						</button>
					</div>
				<?php endforeach; ?>
			</div>

			<div class="mcm-detection-block">
				<h3>Slim advies op basis van site-detectie</h3>
				<p class="description">Scant actieve plugins en theme om te bepalen welk profiel het beste past.</p>
				<button type="submit" name="mcm_security_action" value="run_detection" class="button button-secondary">
					Scan deze site
				</button>

				<?php if ( $detection && is_array( $detection ) ) : ?>
					<div class="mcm-detection-results">
						<h4>Aanbevolen profiel: <code><?php echo esc_html( $profiles[ $detection['profile'] ]['label'] ); ?></code></h4>
						<p class="description">
							Risiconiveau gedetecteerd: <strong><?php echo esc_html( $detection['reasoning'] ); ?></strong>.
							<?php if ( ! empty( $detection['avoid'] ) ) : ?>
								<br>Niet aanzetten: <code><?php echo esc_html( implode( '</code>, <code>', $detection['avoid'] ) ); ?></code>
							<?php endif; ?>
						</p>

						<?php if ( ! empty( $detection['detections'] ) ) : ?>
							<table class="widefat striped mcm-detection-table">
								<thead>
									<tr>
										<th>Gedetecteerd</th>
										<th>Risico</th>
										<th>Vermijden</th>
										<th>Reden</th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $detection['detections'] as $d ) : ?>
										<tr>
											<td><strong><?php echo esc_html( $d['name'] ); ?></strong></td>
											<td>
												<span class="mcm-risk mcm-risk-<?php echo esc_attr( $d['risk'] ); ?>">
													<?php echo esc_html( ucfirst( $d['risk'] ) ); ?>
												</span>
											</td>
											<td>
												<?php echo $d['avoid'] ? '<code>' . esc_html( implode( '</code>, <code>', $d['avoid'] ) ) . '</code>' : '&mdash;'; ?>
											</td>
											<td><?php echo esc_html( $d['reason'] ); ?></td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php else : ?>
							<p><em>Geen risicovolle integraties gedetecteerd. <code>Strict</code> is veilig toe te passen.</em></p>
						<?php endif; ?>
					</div>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Toont een admin notice als de detectie niet matcht met het actieve profiel.
	 * Voorbeelden:
	 *   - Site herkend als staging, maar Standard/Strict profiel actief → suggest Staging
	 *   - Site herkend als live, maar Staging-profiel actief → suggest Standard
	 *   - Geen actief profiel + staging detected → suggest Staging
	 *
	 * Toont alleen voor users met manage_options (niet voor MCM Klanten).
	 * Toont overal in admin (volgens Marco's voorkeur).
	 */
	public function render_mismatch_notice() {
		// Alleen voor admins.
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// Vereist dat de detector + profiles class geladen zijn.
		if ( ! class_exists( 'MCM_Staging_Detector' ) || ! class_exists( 'MCM_Profiles' ) ) {
			return;
		}

		$is_staging      = MCM_Staging_Detector::is_staging();
		$active_profile  = get_option( 'mcm_security_active_profile', '' );
		$suggested       = null;
		$reason          = '';

		if ( $is_staging && 'staging' !== $active_profile ) {
			$suggested = 'staging';
			$reason    = 'Deze site wordt herkend als <strong>staging</strong>'
				. ( $active_profile ? ', maar het profiel <strong>' . esc_html( ucfirst( $active_profile ) ) . '</strong> is actief.' : ', en er is nog geen profiel actief.' );
		} elseif ( ! $is_staging && 'staging' === $active_profile ) {
			$suggested = 'standard';
			$reason    = 'Deze site wordt herkend als <strong>live</strong>, maar het <strong>Staging</strong>-profiel is nog actief.';
		}

		if ( ! $suggested ) {
			return;
		}

		$profiles = MCM_Profiles::get_profiles();
		$label    = isset( $profiles[ $suggested ]['label'] ) ? $profiles[ $suggested ]['label'] : ucfirst( $suggested );
		?>
		<div class="notice notice-warning">
			<p>
				<strong>MCM Security &mdash; profiel-mismatch:</strong>
				<?php echo wp_kses_post( $reason ); ?>
				Aanbevolen: switchen naar het <strong><?php echo esc_html( $label ); ?></strong>-profiel.
			</p>
			<form method="post" style="margin: 0 0 12px 0;">
				<?php wp_nonce_field( 'mcm_security_save', self::NONCE ); ?>
				<input type="hidden" name="target_profile" value="<?php echo esc_attr( $suggested ); ?>" />
				<button type="submit" name="mcm_security_action" value="quick_switch_profile" class="button button-primary">
					Switch naar <?php echo esc_html( $label ); ?>-profiel
				</button>
				<a href="<?php echo esc_url( admin_url( 'tools.php?page=mcm-security' ) ); ?>" class="button button-secondary" style="margin-left:6px;">
					Bekijk MCM Security
				</a>
			</form>
		</div>
		<?php
	}

	/**
	 * Toont of de site als staging wordt herkend en welke signalen daarvoor zorgden.
	 * Voorbereiding voor de Basic-Auth-feature: die mag straks alleen op staging draaien.
	 */
	private function render_staging_detection() {
		$is_staging = MCM_Staging_Detector::is_staging();
		$signals    = MCM_Staging_Detector::get_signals();
		$explain    = MCM_Staging_Detector::explain();
		$badge_cls  = $is_staging ? 'mcm-badge-active' : 'mcm-badge-inactive';
		$badge_txt  = $is_staging ? 'Herkend als STAGING' : 'NIET herkend als staging (= live)';
		?>
		<div class="mcm-section">
			<h2>Omgevingsdetectie</h2>
			<p class="description">Voorbereidende detectie voor de Basic-Auth-feature (komt nog). Deze sectie activeert nog niets &mdash; laat alleen zien hoe de plugin deze site classificeert.</p>
			<p style="margin: 10px 0;">
				<span class="mcm-badge <?php echo esc_attr( $badge_cls ); ?>"><?php echo esc_html( $badge_txt ); ?></span>
			</p>
			<p class="description"><?php echo esc_html( $explain ); ?></p>
			<table class="form-table" style="margin-top: 8px;">
				<thead>
					<tr>
						<th style="width:30%;">Signaal</th>
						<th style="width:15%;">Match?</th>
						<th>Waarde</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $signals as $signal ) : ?>
					<tr>
						<td>
							<strong><?php echo esc_html( $signal['name'] ); ?></strong><br>
							<span class="description"><?php echo esc_html( $signal['description'] ); ?></span>
						</td>
						<td>
							<?php if ( ! empty( $signal['matched'] ) ) : ?>
								<span style="color:#155724; font-weight:600;">&#10004; ja</span>
							<?php else : ?>
								<span style="color:#666;">&minus; nee</span>
							<?php endif; ?>
						</td>
						<td><code><?php echo esc_html( $signal['value'] ); ?></code></td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<p class="description" style="margin-top:10px;">
				<strong>Override:</strong> via <code>define( 'MCM_IS_STAGING', true );</code> in <code>wp-config.php</code> kun je staging forceren, of met <code>false</code> nooit.
			</p>
			<p class="description">
				<strong>Nog niet ingebouwd:</strong> specifieke detectie voor Vivid Backup Pro &amp; MainWP staging clones. Maak een staging via een van die tools en kijk of bovenstaande signalen genoeg zijn. Zo niet &mdash; laten we specifieke detectie toevoegen.
			</p>
		</div>
		<?php
	}

	private function render_action_buttons() {
		?>
		<div class="mcm-actions">
			<button type="submit" name="mcm_security_action" value="enable_all" class="button button-primary mcm-btn-enable-all">
				Activeer Alles &amp; Toepassen
			</button>
			<button type="submit" name="mcm_security_action" value="apply" class="button button-primary">
				Opslaan &amp; Toepassen
			</button>
			<button type="submit" name="mcm_security_action" value="save" class="button button-secondary">
				Alleen Opslaan
			</button>
			<button type="submit" name="mcm_security_action" value="remove" class="button button-link-delete"
				onclick="return confirm('Weet je zeker dat je alle regels uit wp-config.php en .htaccess wilt verwijderen?');">
				Alles Verwijderen
			</button>
		</div>
		<?php
	}

	private function render_toggle( $name, $label, $description, $settings ) {
		$checked = ! empty( $settings[ $name ] ) ? 'checked' : '';
		?>
		<tr>
			<th scope="row"><?php echo esc_html( $label ); ?></th>
			<td>
				<label class="mcm-toggle">
					<input type="checkbox" name="<?php echo esc_attr( $name ); ?>" value="1" <?php echo $checked; ?> />
					<span class="mcm-toggle-slider"></span>
				</label>
				<p class="description"><?php echo $description; ?></p>
			</td>
		</tr>
		<?php
	}

	private function render_notice( $status ) {
		if ( ! $status ) {
			return;
		}
		$messages = [
			'saved'   => [ 'success', 'Instellingen opgeslagen. Klik "Opslaan & Toepassen" om ze te activeren in de bestanden.' ],
			'applied' => [ 'success', 'Regels zijn geschreven naar wp-config.php en .htaccess.' ],
			'all_enabled' => [ 'success', 'Alle beveiligingsopties zijn geactiveerd en toegepast op wp-config.php en .htaccess.' ],
			'removed' => [ 'warning', 'Alle MCM Security regels zijn verwijderd uit wp-config.php en .htaccess.' ],
			'notice_reset' => [ 'success', 'De DB-prefix notice wordt weer getoond op admin pages.' ],
			'detected' => [ 'info', 'Site-scan voltooid &mdash; bekijk de aanbeveling in de Profielen-sectie.' ],
			'profile_applied_basic' => [ 'success', 'Profiel <strong>Basic</strong> toegepast en geactiveerd.' ],
			'profile_applied_standard' => [ 'success', 'Profiel <strong>Standard</strong> toegepast en geactiveerd.' ],
			'profile_applied_strict' => [ 'success', 'Profiel <strong>Strict</strong> toegepast en geactiveerd. Test grondig.' ],
			'profile_applied_staging' => [ 'success', 'Profiel <strong>Staging</strong> toegepast. Lockdown is uit zodat je kunt testen. Login-slug is leeggemaakt &mdash; regel toegang via HTTP Basic Auth.' ],
			'profile_switched' => [ 'success', 'Profiel geswitcht via de mismatch-melding.' ],
			'error'   => [ 'error', 'Er is een fout opgetreden. Controleer of de bestanden schrijfbaar zijn.' ],
			'mail_none' => [ 'warning', 'Geen mail verstuurd: er zijn geen ontvangers aangevinkt of geen geldige beheerders gevonden.' ],
		];

		if ( 'mail_sent' === $status ) {
			$count = isset( $_GET['mcm-count'] ) ? absint( $_GET['mcm-count'] ) : 0;
			$msg   = sprintf(
				/* translators: %d = aantal verzonden mails */
				_n(
					'Login-URL verstuurd naar %d beheerder.',
					'Login-URL verstuurd naar %d beheerders.',
					$count,
					'mcm-security-hardener'
				),
				$count
			);
			printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html( $msg ) );
			return;
		}

		if ( ! isset( $messages[ $status ] ) ) {
			return;
		}
		list( $type, $message ) = $messages[ $status ];
		printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $type ), wp_kses_post( $message ) );
	}

	private function get_inline_css() {
		return '
			.mcm-security-wrap { max-width: 900px; }
			.mcm-security-wrap h1 .mcm-version { font-size: 13px; font-weight: 400; color: #50575e; background: #f0f0f1; padding: 3px 10px; border-radius: 3px; vertical-align: middle; margin-left: 10px; }
			.mcm-section { background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; padding: 15px 20px; margin: 20px 0; }
			.mcm-section h2 { margin-top: 5px; padding-bottom: 10px; border-bottom: 1px solid #eee; }
			.mcm-status-bar { display: flex; gap: 10px; margin: 15px 0; }
			.mcm-badge { display: inline-block; padding: 5px 12px; border-radius: 3px; font-size: 13px; font-weight: 600; }
			.mcm-badge-active { background: #d4edda; color: #155724; }
			.mcm-badge-inactive { background: #f8d7da; color: #721c24; }
			.mcm-actions { display: flex; gap: 10px; margin: 20px 0; align-items: center; }
			.mcm-actions .button { padding: 4px 16px; font-size: 13px; line-height: 2; }
			.mcm-actions .mcm-btn-enable-all { background: #155724; border-color: #155724; }
			.mcm-actions .mcm-btn-enable-all:hover, .mcm-actions .mcm-btn-enable-all:focus { background: #1e7e34; border-color: #1e7e34; }
			.mcm-toggle { position: relative; display: inline-block; width: 44px; height: 24px; vertical-align: middle; }
			.mcm-toggle input { opacity: 0; width: 0; height: 0; }
			.mcm-toggle-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .3s; border-radius: 24px; }
			.mcm-toggle-slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; }
			.mcm-toggle input:checked + .mcm-toggle-slider { background-color: #2271b1; }
			.mcm-toggle input:checked + .mcm-toggle-slider:before { transform: translateX(20px); }

			.mcm-profiles-section { background: #fff; }
			.mcm-profile-confirmation { background: #f0f9f0; border-color: #46b450; }
			.mcm-profile-matched { display: flex; align-items: flex-start; gap: 16px; margin: 8px 0; }
			.mcm-profile-check { display: inline-flex; align-items: center; justify-content: center; width: 36px; height: 36px; background: #46b450; color: #fff; border-radius: 50%; font-size: 20px; font-weight: bold; flex-shrink: 0; }
			.mcm-profile-matched-title { margin: 0 0 4px; font-size: 15px; }
			.mcm-profile-matched .description { margin: 0; }
			.mcm-match-badge, .mcm-mismatch-badge { display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 3px; margin-left: 8px; vertical-align: middle; font-weight: 600; }
			.mcm-match-badge { background: #d4edda; color: #155724; }
			.mcm-mismatch-badge { background: #fff3cd; color: #856404; }
			.mcm-detection-mismatch { border-left-color: #d4a017 !important; }
			.mcm-profile-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 16px 0; }
			.mcm-profile-card { border: 2px solid #c3c4c7; border-radius: 4px; padding: 16px; background: #fafafa; display: flex; flex-direction: column; }
			.mcm-profile-card.is-active { border-color: #2271b1; background: #f0f6fc; }
			.mcm-profile-card h3 { margin: 0 0 4px; font-size: 16px; }
			.mcm-profile-tagline { display: block; font-size: 12px; color: #50575e; margin-bottom: 10px; font-style: italic; }
			.mcm-profile-active-badge { display: inline-block; background: #2271b1; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 3px; margin-left: 8px; vertical-align: middle; }
			.mcm-profile-card p { margin: 8px 0; flex: 1; font-size: 13px; line-height: 1.5; }
			.mcm-profile-safe-for { font-size: 12px; color: #50575e; }
			.mcm-profile-card .button { margin-top: 10px; width: 100%; text-align: center; }
			.mcm-detection-block { margin-top: 24px; padding-top: 16px; border-top: 1px solid #e0e0e0; }
			.mcm-detection-block h3 { margin-top: 0; }
			.mcm-detection-results { margin-top: 16px; padding: 16px; background: #f6f7f7; border-left: 4px solid #2271b1; border-radius: 0 3px 3px 0; }
			.mcm-detection-results h4 { margin: 0 0 8px; }
			.mcm-detection-table { margin-top: 12px; }
			.mcm-detection-table th, .mcm-detection-table td { padding: 8px 12px; vertical-align: top; }
			.mcm-risk { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
			.mcm-risk-low { background: #d4edda; color: #155724; }
			.mcm-risk-medium { background: #fff3cd; color: #856404; }
			.mcm-risk-high { background: #f8d7da; color: #721c24; }
		';
	}
}
