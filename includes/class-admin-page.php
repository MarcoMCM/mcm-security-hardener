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
		} elseif ( 'basic_auth_activate' === $action ) {
			$this->basic_auth_activate_action();
		} elseif ( 'basic_auth_deactivate' === $action ) {
			$this->basic_auth_deactivate_action();
		} elseif ( 'basic_auth_regenerate' === $action ) {
			$this->basic_auth_regenerate_action();
		} elseif ( 'send_access_mail' === $action ) {
			$this->send_access_mail_action();
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

	// ─── BASIC AUTH HANDLERS ──────────────────────────────────────────────

	private function basic_auth_activate_action() {
		$user   = isset( $_POST['basic_auth_user'] ) ? MCM_Basic_Auth::sanitize_user( $_POST['basic_auth_user'] ) : 'staging';
		$result = MCM_Basic_Auth::activate( $user ?: 'staging' );
		if ( is_wp_error( $result ) ) {
			$this->redirect_with( [ 'mcm-status' => 'basic_auth_error', 'mcm-error' => rawurlencode( $result->get_error_message() ) ] );
		} else {
			$this->redirect_with( [ 'mcm-status' => 'basic_auth_activated' ] );
		}
	}

	private function basic_auth_deactivate_action() {
		MCM_Basic_Auth::deactivate();
		$this->redirect( 'basic_auth_deactivated' );
	}

	private function basic_auth_regenerate_action() {
		$result = MCM_Basic_Auth::regenerate_password();
		if ( is_wp_error( $result ) ) {
			$this->redirect_with( [ 'mcm-status' => 'basic_auth_error', 'mcm-error' => rawurlencode( $result->get_error_message() ) ] );
		} else {
			$this->redirect_with( [ 'mcm-status' => 'basic_auth_regenerated' ] );
		}
	}

	/**
	 * Verstuur één gecombineerde toegangsmail naar geselecteerde admins/MCM Klanten.
	 * Bevat Basic Auth gegevens (als actief + plain bekend) + login-URL.
	 */
	private function send_access_mail_action() {
		// Sla eerst de form-staat op zodat zojuist aangevinkte recipients meetellen.
		$settings = $this->sanitize_input( $_POST );
		update_option( self::OPTION_KEY, $settings );

		$recipient_ids = ! empty( $settings['mail_admins_recipients'] ) ? (array) $settings['mail_admins_recipients'] : [];
		if ( empty( $recipient_ids ) ) {
			$this->redirect( 'mail_none' );
			return;
		}

		$ba_active = MCM_Basic_Auth::is_active();
		$ba_plain  = $ba_active ? MCM_Basic_Auth::get_plain_password() : null;
		$ba_user   = $ba_active && isset( $settings[ MCM_Basic_Auth::SETTING_USER ] )
			? $settings[ MCM_Basic_Auth::SETTING_USER ]
			: null;

		// Als BA actief is maar plain niet meer beschikbaar → blokkeer (anders mail zonder wachtwoord = nutteloos).
		if ( $ba_active && ! $ba_plain ) {
			$this->redirect( 'basic_auth_no_plain' );
			return;
		}

		$slug = isset( $settings['login_slug'] ) ? (string) $settings['login_slug'] : '';

		$sent = $this->send_full_access_mail( $recipient_ids, $slug, $ba_user, $ba_plain );
		if ( 0 === $sent ) {
			$this->redirect( 'mail_none' );
		} else {
			$this->redirect_with( [ 'mcm-status' => 'access_mail_sent', 'mcm-count' => $sent ] );
		}
	}

	/**
	 * Helper: redirect met meerdere query-args.
	 */
	private function redirect_with( $args ) {
		wp_safe_redirect( add_query_arg( $args, admin_url( 'tools.php?page=mcm-security' ) ) );
		exit;
	}

	/**
	 * Stuur EEN gecombineerde toegangsmail naar opgegeven user IDs.
	 * Bevat Basic Auth gegevens (als $ba_user/$ba_plain meegegeven) + login-URL.
	 */
	private function send_full_access_mail( $recipient_ids, $slug, $ba_user, $ba_plain ) {
		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$site_url  = home_url( '/' );
		$login_url = $slug ? home_url( '/' . $slug ) : home_url( '/wp-login.php' );

		$current = wp_get_current_user();
		$by_who  = $current && $current->exists()
			? sprintf( '%s (%s)', $current->display_name, $current->user_email )
			: 'onbekend';
		$timestamp = wp_date( 'd-m-Y H:i' );

		$has_ba = $ba_user && $ba_plain;

		$subject = sprintf( '[%s] Toegangsgegevens', $site_name );

		$body  = "Beste,\n\n";
		$body .= sprintf( "Hieronder de toegangsgegevens voor %s.\n\n", $site_name );

		if ( $has_ba ) {
			$body .= "═══ STAP 1: Sitebeveiliging (browser pop-up) ═══\n\n";
			$body .= "Bij het openen van de site verschijnt eerst een pop-up van je browser.\n";
			$body .= "Vul daar in:\n\n";
			$body .= "Site: {$site_url}\n";
			$body .= "Gebruikersnaam: {$ba_user}\n";
			$body .= "Wachtwoord:    {$ba_plain}\n\n";
			$body .= "═══ STAP 2: WordPress login ═══\n\n";
			$body .= "Pas daarna verschijnt de normale WordPress-login. Gebruik je eigen WP-account.\n";
		} else {
			$body .= "═══ WordPress login ═══\n\n";
		}

		$body .= "Login-URL: {$login_url}\n";
		if ( ! $slug ) {
			$body .= "(standaard wp-login.php — geen custom slug ingesteld)\n";
		}
		$body .= "\nGebruik je bestaande WordPress gebruikersnaam en wachtwoord.\n\n";

		$body .= "─────────────────────────────────────\n";
		$body .= "Verstuurd door: {$by_who}\n";
		$body .= "Tijdstip: {$timestamp}\n\n";

		if ( $has_ba ) {
			$body .= "Bewaar deze mail veilig en verwijder hem zodra je de gegevens hebt\n";
			$body .= "opgeslagen — wachtwoorden in e-mail zijn nooit helemaal ideaal.\n\n";
		}
		$body .= "— MCM Security Hardener\n";

		$headers = [ 'Content-Type: text/plain; charset=UTF-8' ];

		$sent = 0;
		foreach ( $recipient_ids as $uid ) {
			$u = get_user_by( 'id', (int) $uid );
			if ( ! self::user_is_eligible_recipient( $u ) || empty( $u->user_email ) ) {
				continue;
			}
			if ( wp_mail( $u->user_email, $subject, $body, $headers ) ) {
				$sent++;
			}
		}
		return $sent;
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

		$timestamp = wp_date( 'd-m-Y \o\m H:i' );

		if ( $is_change ) {
			$subject  = sprintf( '[%s] Inlog-URL gewijzigd', $site_name );
			$title    = sprintf( 'De inlog-URL van %s is bijgewerkt', $site_name );
			$lead     = sprintf( 'De inlog-URL voor <strong>%s</strong> is zojuist aangepast voor extra beveiliging. Hieronder vind je de nieuwe link — bewaar deze mail goed.', esc_html( $site_name ) );
			$by_label = 'Gewijzigd door';
		} else {
			$subject  = sprintf( '[%s] Inlog-URL', $site_name );
			$title    = sprintf( 'Inloggen op %s', $site_name );
			$lead     = sprintf( 'Hierbij de inlog-URL voor <strong>%s</strong>. Bewaar deze mail veilig zodat je de link altijd bij de hand hebt.', esc_html( $site_name ) );
			$by_label = 'Verstuurd door';
		}

		$headers = [ 'Content-Type: text/html; charset=UTF-8' ];

		$sent = 0;
		foreach ( $recipient_ids as $user_id ) {
			$user = get_user_by( 'id', (int) $user_id );
			if ( ! self::user_is_eligible_recipient( $user ) || empty( $user->user_email ) ) {
				continue;
			}

			// Persoonlijke aanhef per ontvanger.
			$first    = trim( (string) get_user_meta( $user->ID, 'first_name', true ) );
			$display  = trim( (string) $user->display_name );
			$greet_to = $first ?: $display;
			$greeting = $greet_to ? sprintf( 'Hallo %s,', $greet_to ) : 'Hallo,';

			// HTML body — inline styles voor brede mail-client compatibility.
			ob_start();
			?>
			<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 28px 24px; color: #1d2327; line-height: 1.55; font-size: 15px;">
				<h1 style="margin: 0 0 18px; font-size: 22px; color: #1d2327; font-weight: 600;">
					<?php echo esc_html( $title ); ?>
				</h1>
				<p style="margin: 0 0 20px;">
					<?php echo esc_html( $greeting ); ?><br>
					<?php echo wp_kses( $lead, [ 'strong' => [] ] ); ?>
				</p>
				<div style="background: #f0f6fc; border-left: 4px solid #2271b1; padding: 18px 22px; margin: 22px 0; border-radius: 4px;">
					<p style="margin: 0 0 6px; color: #50575e; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px;">
						Jouw inlog-URL
					</p>
					<p style="margin: 0 0 16px; font-size: 15px; word-break: break-all;">
						<a href="<?php echo esc_url( $login_url ); ?>" style="color: #2271b1; text-decoration: none;"><?php echo esc_html( $login_url ); ?></a>
					</p>
					<a href="<?php echo esc_url( $login_url ); ?>" style="display: inline-block; background: #2271b1; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-size: 14px; font-weight: 500;">
						Naar inlogpagina &rarr;
					</a>
				</div>
				<?php if ( ! $slug ) : ?>
				<p style="margin: 0 0 18px; padding: 12px 16px; background: #fff8e5; border-left: 4px solid #dba617; border-radius: 4px; font-size: 14px;">
					<strong>Let op:</strong> er is momenteel geen aangepaste inlog-slug ingesteld &mdash; er wordt ingelogd via de standaard <code>/wp-login.php</code>.
				</p>
				<?php endif; ?>
				<p style="margin: 0 0 20px;">
					Je gebruikersnaam en wachtwoord zijn <strong>niet</strong> gewijzigd &mdash; gebruik gewoon je bestaande inloggegevens.
				</p>
				<hr style="border: 0; border-top: 1px solid #e0e0e0; margin: 28px 0;">
				<p style="margin: 0 0 4px; color: #646970; font-size: 12px;">
					<?php echo esc_html( $by_label ); ?>: <?php echo esc_html( $by_who ); ?><br>
					Verstuurd op <?php echo esc_html( $timestamp ); ?> via <?php echo esc_html( $site_name ); ?>
				</p>
				<p style="margin: 8px 0 0; color: #646970; font-size: 12px;">
					Vragen? Stuur een mail naar <a href="mailto:marco@mcmwebsites.nl" style="color: #646970;">marco@mcmwebsites.nl</a>.
				</p>
			</div>
			<?php
			$html = ob_get_clean();

			// Plain-text fallback voor mail-clients die geen HTML renderen.
			$plain  = "{$greeting}\n\n";
			$plain .= $is_change
				? sprintf( "De inlog-URL voor %s is zojuist bijgewerkt voor extra beveiliging.\n\n", $site_name )
				: sprintf( "Hierbij de inlog-URL voor %s.\n\n", $site_name );
			$plain .= "Jouw inlog-URL:\n  {$login_url}\n\n";
			if ( ! $slug ) {
				$plain .= "Let op: er is geen aangepaste inlog-slug ingesteld — er wordt ingelogd via de standaard /wp-login.php.\n\n";
			}
			$plain .= "Je gebruikersnaam en wachtwoord blijven hetzelfde.\n\n";
			$plain .= "---\n";
			$plain .= "{$by_label}: {$by_who}\n";
			$plain .= "Verstuurd op {$timestamp} via {$site_name}\n";
			$plain .= "Vragen? Stuur een mail naar marco@mcmwebsites.nl\n";

			// Plain-text alt-body via PHPMailer voor multipart-mail.
			$alt_body_setter = function ( $phpmailer ) use ( $plain ) {
				$phpmailer->AltBody = $plain;
			};
			add_action( 'phpmailer_init', $alt_body_setter );

			if ( wp_mail( $user->user_email, $subject, $html, $headers ) ) {
				$sent++;
			}

			remove_action( 'phpmailer_init', $alt_body_setter );
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
		$settings['disposable_email_list'] = isset( $_POST['disposable_email_list'] ) ? sanitize_textarea_field( $_POST['disposable_email_list'] ) : '';
		$settings['allowed_backend_roles'] = isset( $_POST['allowed_backend_roles'] ) ? sanitize_textarea_field( $_POST['allowed_backend_roles'] ) : "administrator\neditor";
		$settings['unauthorized_backend_redirect'] = isset( $_POST['unauthorized_backend_redirect'] ) ? esc_url_raw( trim( $_POST['unauthorized_backend_redirect'] ) ) : '';
		$settings['human_verification_delay'] = isset( $_POST['human_verification_delay'] )
			? max( 1, min( 30, (int) $_POST['human_verification_delay'] ) )
			: 3;
		$settings['php_error_warning_threshold_per_hour'] = isset( $_POST['php_error_warning_threshold_per_hour'] )
			? max( 1, min( 5000, (int) $_POST['php_error_warning_threshold_per_hour'] ) )
			: 50;
		$settings['php_error_post_upgrade_threshold_per_hour'] = isset( $_POST['php_error_post_upgrade_threshold_per_hour'] )
			? max( 1, min( 5000, (int) $_POST['php_error_post_upgrade_threshold_per_hour'] ) )
			: 10;

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
			// registratiebescherming
			'registration_honeypot', 'block_disposable_email',
			// backend access
			'skip_admin_email_confirmation', 'block_non_admin_backend',
			// file exposure scanner
			'exposure_scanner_enabled', 'block_risky_files_via_htaccess',
			// php error watcher
			'php_error_watcher_enabled',
		];

		$settings = [];
		foreach ( $checkboxes as $key ) {
			$settings[ $key ] = ! empty( $post[ $key ] );
		}

		$settings['admin_email']      = isset( $post['admin_email'] ) ? sanitize_email( $post['admin_email'] ) : '';
		$settings['login_slug']       = isset( $post['login_slug'] ) ? sanitize_title( $post['login_slug'] ) : '';
		$settings['bad_referers_list'] = isset( $post['bad_referers_list'] ) ? sanitize_textarea_field( $post['bad_referers_list'] ) : '';
		$settings['disposable_email_list'] = isset( $post['disposable_email_list'] ) ? sanitize_textarea_field( $post['disposable_email_list'] ) : '';
		$settings['allowed_backend_roles'] = isset( $post['allowed_backend_roles'] ) ? sanitize_textarea_field( $post['allowed_backend_roles'] ) : "administrator\neditor";
		$settings['unauthorized_backend_redirect'] = isset( $post['unauthorized_backend_redirect'] ) ? esc_url_raw( trim( $post['unauthorized_backend_redirect'] ) ) : '';
		$settings['human_verification_delay'] = isset( $post['human_verification_delay'] )
			? max( 1, min( 30, (int) $post['human_verification_delay'] ) )
			: 3;
		$settings['php_error_warning_threshold_per_hour'] = isset( $post['php_error_warning_threshold_per_hour'] )
			? max( 1, min( 5000, (int) $post['php_error_warning_threshold_per_hour'] ) )
			: 50;
		$settings['php_error_post_upgrade_threshold_per_hour'] = isset( $post['php_error_post_upgrade_threshold_per_hour'] )
			? max( 1, min( 5000, (int) $post['php_error_post_upgrade_threshold_per_hour'] ) )
			: 10;

		// Mail-bij-slug-wijziging.
		$settings['mail_admins_on_slug_change'] = ! empty( $post['mail_admins_on_slug_change'] );
		$settings['mail_admins_recipients']     = $this->sanitize_recipient_ids( isset( $post['mail_admins_recipients'] ) ? (array) $post['mail_admins_recipients'] : [] );

		// Basic Auth — user-veld via form, enabled via dedicated handler.
		$existing = get_option( self::OPTION_KEY, [] );
		$settings[ MCM_Basic_Auth::SETTING_USER ]    = isset( $post['basic_auth_user'] )
			? MCM_Basic_Auth::sanitize_user( $post['basic_auth_user'] )
			: ( isset( $existing[ MCM_Basic_Auth::SETTING_USER ] ) ? $existing[ MCM_Basic_Auth::SETTING_USER ] : 'staging' );
		$settings[ MCM_Basic_Auth::SETTING_ENABLED ] = ! empty( $existing[ MCM_Basic_Auth::SETTING_ENABLED ] );

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

				<?php
				// Volgorde + zichtbaarheid afhankelijk van de werkelijkheid (detection):
				// - Op staging:  Staging wachtwoordbeveiliging BOVENAAN, daarna Login URL, daarna Klantmail
				// - Op live:     Login URL bovenaan, Klantmail daaronder, Basic Auth NIET getoond
				$is_staging_site = class_exists( 'MCM_Staging_Detector' ) && MCM_Staging_Detector::is_staging();

				if ( $is_staging_site ) {
					$this->render_basic_auth_section( $settings );
					$this->render_login_url_section( $settings );
					$this->render_klantmail_section( $settings );
				} else {
					$this->render_login_url_section( $settings );
					$this->render_klantmail_section( $settings );
					// Basic Auth wordt op live niet getoond — staging-only feature.
				}

				$this->render_user_audit_section();
				?>

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

				<!-- BLOOTGESTELDE BESTANDEN -->
				<div class="mcm-section">
					<h2>Blootgestelde bestanden</h2>
					<p class="description">
						Wekelijkse filesystem-scan naar losse "test"-bestanden die per ongeluk publiek bereikbaar zijn (info.php met phpinfo(), .env, wp-config-backups, SQL-dumps, Adminer, phpMyAdmin, etc.). Detecteert ook .php-bestanden die <code>phpinfo()</code> aanroepen.
					</p>
					<p class="description">
						<strong>Geen automatisch verwijderen</strong> &mdash; alleen melden via admin-notice + mail naar de notify-bestemming. Verwijderen blijft een bewuste handeling.
					</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'exposure_scanner_enabled', 'Wekelijkse scan inschakelen', 'Plant een wp-cron-job die wekelijks de webroot scant. Bij nieuwe bevindingen krijg je een mail.', $settings );
						$this->render_toggle( 'block_risky_files_via_htaccess', 'Risico-bestanden ook via .htaccess blokkeren', 'Voegt een Apache FilesMatch-blok toe dat directe HTTP-toegang tot info.php, *.sql, .env, wp-config backups, etc. weigert. Werkt alleen op Apache &mdash; op nginx geen effect.', $settings );
						?>
					</table>
					<?php
					$last = MCM_File_Exposure_Scanner::get_last_results();
					if ( $last ) {
						$findings = isset( $last['findings'] ) && is_array( $last['findings'] ) ? $last['findings'] : [];
						$when     = isset( $last['timestamp'] ) ? wp_date( 'd-m-Y H:i', (int) $last['timestamp'] ) : '—';
						?>
						<p>
							<strong>Laatste scan:</strong> <?php echo esc_html( $when ); ?>
							&mdash;
							<?php if ( empty( $findings ) ) : ?>
								<span style="color:#1e7e34;">&#10003; Geen bevindingen.</span>
							<?php else : ?>
								<span style="color:#b32d2e;">&#9888; <?php echo (int) count( $findings ); ?> bevinding(en)</span>
							<?php endif; ?>
						</p>
						<?php if ( ! empty( $findings ) ) : ?>
						<table class="widefat striped" style="margin-top:8px;">
							<thead>
								<tr>
									<th>Reden</th>
									<th>Pad (relatief)</th>
									<th style="width:90px;">Grootte</th>
									<th style="width:120px;">Laatst gew.</th>
									<th style="width:80px;">Publiek?</th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ( $findings as $f ) : ?>
								<tr>
									<td><?php echo esc_html( $f['reason'] ); ?></td>
									<td><code><?php echo esc_html( $f['relpath'] ); ?></code></td>
									<td><?php echo (int) $f['size']; ?></td>
									<td><?php echo $f['mtime'] ? esc_html( wp_date( 'd-m-Y', (int) $f['mtime'] ) ) : '—'; ?></td>
									<td><?php echo ! empty( $f['public_guess'] ) ? '<span style="color:#b32d2e;">ja</span>' : '<span style="color:#646970;">nee</span>'; ?></td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
						<p class="description" style="margin-top:8px;">
							<strong>Let op (Xel):</strong> ná het verwijderen van een bestand moet de Varnish-cache gepurged worden, anders blijft de URL publiek 200 geven. Vanaf de server:
							<code>curl -X PURGE -H 'Host: &lt;domein&gt;' http://127.0.0.1/&lt;pad&gt;</code>
						</p>
						<?php endif; ?>
						<?php
					} else {
						?>
						<p><em>Nog geen scan uitgevoerd.</em></p>
						<?php
					}
					?>
					<p>
						<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=' . MCM_File_Exposure_Scanner::ACTION_MANUAL_SCAN ), MCM_File_Exposure_Scanner::ACTION_MANUAL_SCAN ) ); ?>"
							class="button button-secondary">
							Nu scannen
						</a>
					</p>
				</div>

				<!-- PHP ERROR WATCHER -->
				<div class="mcm-section">
					<h2>PHP Error Watcher</h2>
					<p class="description">
						Uurlijkse monitor van <code>wp-content/debug.log</code> op nieuwe fatal/parse/warning/deprecated entries. Mailt direct bij fatal of parse error; bij warnings/deprecations alleen boven drempel.
					</p>
					<p class="description">
						Detecteert automatisch een PHP-versie-wissel en zet de eerste 7 dagen na de upgrade in extra gevoelige modus &mdash; precies wat je nodig hebt tijdens een PHP-major upgrade.
					</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'php_error_watcher_enabled', 'PHP error watcher inschakelen', 'Plant een uurlijkse wp-cron die nieuwe entries in debug.log vergelijkt met de vorige check.', $settings );
						?>
						<tr>
							<th scope="row"><label for="php_error_warning_threshold_per_hour">Drempel (normaal)</label></th>
							<td>
								<input type="number" id="php_error_warning_threshold_per_hour" name="php_error_warning_threshold_per_hour"
									value="<?php echo esc_attr( $settings['php_error_warning_threshold_per_hour'] ?? 50 ); ?>"
									min="1" max="5000" step="1" style="width: 100px;" />
								<p class="description">Boven dit aantal warnings+deprecations sinds vorige check &rarr; mail. Standaard: 50.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="php_error_post_upgrade_threshold_per_hour">Drempel (post-PHP-upgrade)</label></th>
							<td>
								<input type="number" id="php_error_post_upgrade_threshold_per_hour" name="php_error_post_upgrade_threshold_per_hour"
									value="<?php echo esc_attr( $settings['php_error_post_upgrade_threshold_per_hour'] ?? 10 ); ?>"
									min="1" max="5000" step="1" style="width: 100px;" />
								<p class="description">Strenger in de 7 dagen na een gedetecteerde PHP-versie-wissel. Standaard: 10.</p>
							</td>
						</tr>
					</table>
					<?php
					$st = MCM_PHP_Error_Watcher::get_status();
					?>
					<p style="margin-top:8px;">
						<strong>Status</strong> &mdash;
						PHP nu: <code><?php echo esc_html( $st['current_version'] ); ?></code>;
						laatst gezien: <code><?php echo esc_html( $st['last_version'] ?: '—' ); ?></code>;
						<?php if ( $st['post_upgrade'] ) : ?>
							<span style="color:#b32d2e;">🚨 in post-upgrade window (extra gevoelig)</span>;
						<?php endif; ?>
						debug.log: <?php echo $st['log_exists'] ? '<span style="color:#1e7e34;">aanwezig</span>' : '<span style="color:#646970;">ontbreekt (WP_DEBUG_LOG niet aan?)</span>'; ?>;
						volgende cron: <?php echo $st['cron_next_run'] ? esc_html( wp_date( 'd-m-Y H:i', (int) $st['cron_next_run'] ) ) : '—'; ?>.
					</p>
				</div>

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

				<!-- BACKEND TOEGANG -->
				<div class="mcm-section">
					<h2>Backend toegang</h2>
					<p class="description">Twee instellingen rond wp-admin toegang. MCM-eigenaars worden nooit geblokkeerd.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'skip_admin_email_confirmation', 'Skip admin email confirmation', 'Schakelt het "controleer admin email"-tussenscherm uit dat WordPress periodiek toont. Universeel irritant voor terugkerende beheerders.', $settings );
						$this->render_toggle( 'block_non_admin_backend', 'Blokkeer non-admin backend toegang', 'Redirect ingelogde users zonder toegestane rol weg van /wp-admin/. Aan wanneer klant-rollen niet in de backend horen.', $settings );
						?>
						<tr>
							<th scope="row"><label for="allowed_backend_roles">Toegestane backend-rollen</label></th>
							<td>
								<textarea id="allowed_backend_roles" name="allowed_backend_roles" rows="4" class="large-text code"
									placeholder="administrator&#10;editor&#10;shop_manager"><?php echo esc_textarea( $settings['allowed_backend_roles'] ?? "administrator\neditor" ); ?></textarea>
								<p class="description">&Eacute;&eacute;n rol-slug per regel. Voorbeelden: <code>administrator</code>, <code>editor</code>, <code>shop_manager</code> (WooCommerce), <code>wpamelia-manager</code> (Amelia).</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="unauthorized_backend_redirect">Redirect-URL bij blokkade</label></th>
							<td>
								<input type="url" id="unauthorized_backend_redirect" name="unauthorized_backend_redirect"
									value="<?php echo esc_attr( $settings['unauthorized_backend_redirect'] ?? '' ); ?>"
									class="regular-text" placeholder="<?php echo esc_attr( home_url( '/' ) ); ?>" />
								<p class="description">Waar geblokkeerde users heen gaan. Leeg = homepage.</p>
							</td>
						</tr>
					</table>
				</div>

				<!-- REGISTRATIEBESCHERMING -->
				<div class="mcm-section">
					<h2>Registratiebescherming</h2>
					<p class="description">Honeypot-veld en wegwerpdomein-filter op registratieformulieren (WordPress &eacute;n WooCommerce). Werkt naast Human Verification.</p>
					<table class="form-table">
						<?php
						$this->render_toggle( 'registration_honeypot', 'Honeypot bij registratie', 'Voegt een verborgen veld toe dat alleen bots invullen. Gevuld veld &rarr; registratie geweigerd. Echte bezoekers zien het nooit.', $settings );
						$this->render_toggle( 'block_disposable_email', 'Blokkeer wegwerp-e-mailadressen', 'Weigert registratie met tijdelijke/wegwerp-emailadressen (mailinator, yopmail, 10minutemail, etc.).', $settings );
						?>
						<tr>
							<th scope="row"><label for="disposable_email_list">Eigen wegwerpdomeinen</label></th>
							<td>
								<textarea id="disposable_email_list" name="disposable_email_list" rows="5" class="large-text code"
									placeholder="extra-spam-domein.com&#10;nog-een-wegwerp.net"><?php echo esc_textarea( $settings['disposable_email_list'] ?? '' ); ?></textarea>
								<p class="description">&Eacute;&eacute;n domein per regel. Deze komen bovenop de ingebouwde lijst.</p>
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
			<?php $this->render_collapsible_script(); ?>
		</div>
		<?php
	}

	/**
	 * Configuratie voor stappen + auto-open per profiel.
	 *
	 * sections_open = section IDs die JS auto-open bij eerste bezoek
	 * (matchen de slug die JS uit h2-tekst genereert).
	 */
	private function steps_config() {
		return [
			'staging' => [
				'title'         => 'Staging-profiel actief — volg deze stappen om je klant toegang te geven:',
				'steps'         => [
					'Open <strong>Staging wachtwoordbeveiliging</strong> &rarr; klik <em>Activeer &amp; genereer wachtwoord</em>',
					'Open <strong>Klant toegang &amp; mail</strong> &rarr; vink admins en MCM Klanten aan in de ontvangerslijst',
					'Klik in <strong>Klant toegang &amp; mail</strong> op <em>Verstuur toegangsmail (Basic Auth + login-URL)</em>',
				],
				'sections_open' => [ 'staging-wachtwoordbeveiliging-http-basic', 'klant-toegang-mail' ],
			],
			'basic' => [
				'title'         => 'Basic-profiel actief — voorgestelde vervolgstap:',
				'steps'         => [
					'(Optioneel) Open <strong>Login URL Verbergen</strong> als je <code>wp-login.php</code> wilt verbergen.',
				],
				'sections_open' => [],
			],
			'standard' => [
				'title'         => 'Standard-profiel actief — voor verborgen WP-login:',
				'steps'         => [
					'Open <strong>Login URL Verbergen</strong> &rarr; vul een unieke <code>Custom login slug</code> in',
					'(Optioneel) Open <strong>Klant toegang &amp; mail</strong>, vink ontvangers aan en klik <em>Verstuur alleen login-URL</em>',
				],
				'sections_open' => [ 'login-url-verbergen', 'klant-toegang-mail' ],
			],
			'strict' => [
				'title'         => 'Strict-profiel actief — voor verborgen WP-login:',
				'steps'         => [
					'Open <strong>Login URL Verbergen</strong> &rarr; vul een unieke <code>Custom login slug</code> in',
					'Test de site grondig &mdash; Strict blokkeert ook bepaalde user-agents en URL-patronen',
				],
				'sections_open' => [ 'login-url-verbergen', 'klant-toegang-mail' ],
			],
		];
	}

	/**
	 * Login URL Verbergen sectie — alleen slug-input + URL preview.
	 * Mail-instellingen staan in de aparte "Klant toegang & mail" sectie.
	 */
	private function render_login_url_section( $settings ) {
		?>
		<div class="mcm-section">
			<h2>Login URL Verbergen</h2>
			<p class="description">
				Verbergt <code>/wp-login.php</code> en maakt een custom login-slug aan.
				Voor mail-instellingen: zie de sectie <strong>Klant toegang &amp; mail</strong>.
			</p>
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
			</table>
		</div>
		<?php
	}

	/**
	 * Centrale "Klant toegang & mail" sectie. Bevat:
	 *   - Auto-mail toggle (mail bij slug-wijziging)
	 *   - Recipients lijst (admins + MCM Klanten met badge)
	 *   - Knop "Verstuur login-URL nu" — alleen URL
	 *   - Knop "Verstuur toegangsmail (Basic Auth + login-URL)" — combo,
	 *     alleen zichtbaar als Basic Auth actief is + plain in cache
	 *
	 * Was eerder verspreid over Login URL sectie (recipients) en Basic Auth
	 * sectie (combo-knop). Centraal is duidelijker.
	 */
	private function render_klantmail_section( $settings ) {
		$selected_ids = isset( $settings['mail_admins_recipients'] ) && is_array( $settings['mail_admins_recipients'] )
			? array_map( 'intval', $settings['mail_admins_recipients'] )
			: [];
		$users    = self::get_eligible_mail_users();
		$ba_active = MCM_Basic_Auth::is_active();
		$ba_plain  = $ba_active ? MCM_Basic_Auth::get_plain_password() : null;
		?>
		<div class="mcm-section">
			<h2>Klant toegang &amp; mail</h2>
			<p class="description">
				Selecteer wie de toegangsmails ontvangt. Werkt voor zowel de
				<strong>login-URL mail</strong> (na slug-wijziging) als de
				<strong>combo-mail</strong> (Basic Auth + login-URL voor staging-klanten).
			</p>

			<table class="form-table">
				<tr>
					<th scope="row">Ontvangers</th>
					<td>
						<?php if ( empty( $users ) ) : ?>
							<p class="description"><em>Geen beheerders of MCM Klanten gevonden.</em></p>
						<?php else : ?>
							<fieldset style="border:1px solid #ddd; padding:8px 12px; max-height:220px; overflow:auto; border-radius:3px;">
							<?php foreach ( $users as $u ) :
								$checked = in_array( (int) $u->ID, $selected_ids, true ) ? 'checked' : '';
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
							endforeach; ?>
							</fieldset>
							<p class="description">Administrators &eacute;n MCM Klanten worden getoond. MCM Klant rol komt uit de Site Optimizer plugin.</p>
						<?php endif; ?>
					</td>
				</tr>

				<?php
				$this->render_toggle(
					'mail_admins_on_slug_change',
					'Auto-mail bij wijziging login-slug',
					'Stuurt automatisch de nieuwe login-URL naar bovenstaande ontvangers wanneer de slug verandert (alleen bij <em>Opslaan</em> of <em>Opslaan &amp; Toepassen</em>, niet bij <em>Activeer Alles</em>).',
					$settings
				);
				?>
			</table>

			<div class="mcm-actions" style="margin-top:10px;">
				<?php if ( $ba_active && $ba_plain ) : ?>
					<button type="submit" name="mcm_security_action" value="send_access_mail" class="button button-primary">
						Verstuur toegangsmail (Basic Auth + login-URL)
					</button>
				<?php elseif ( $ba_active && ! $ba_plain ) : ?>
					<span class="description" style="display:inline-block; padding:6px 10px; background:#fff3cd; border-left:3px solid #ffc107;">
						Basic Auth wachtwoord >30 min uit cache &mdash; ga naar <strong>Staging wachtwoordbeveiliging</strong> en klik <em>Regenereer</em> om opnieuw te kunnen mailen.
					</span>
				<?php endif; ?>
				<button type="submit" name="mcm_security_action" value="send_login_url_now" class="button <?php echo $ba_active ? 'button-secondary' : 'button-primary'; ?>">
					Verstuur alleen login-URL
				</button>
			</div>
			<?php if ( ! $ba_active ) : ?>
				<p class="description" style="margin-top:8px;">
					Basic Auth staat uit &mdash; alleen de WordPress login-URL kan worden gemaild.
					Activeer Basic Auth in de sectie hierboven als je staging-toegangsgegevens wilt versturen.
				</p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * UI sectie voor HTTP Basic Auth (staging).
	 */
	/**
	 * User Audit sectie — toont users met verhoogde rechten (Admin/Editor/
	 * Author/Contributor), met de optie om ze in één klik te downgraden.
	 */
	private function render_user_audit_section() {
		$users           = MCM_User_Audit::get_elevated_users();
		$target_label    = MCM_User_Audit::downgrade_target_label();
		$klant_available = MCM_User_Audit::klant_role_available();
		?>
		<div class="mcm-section">
			<h2>Users met verhoogde rechten</h2>
			<p class="description">
				Lijst van alle gebruikers met rol Administrator, Editor, Author of Contributor.
				MCM-eigenaars en super-admins zijn uitgesloten.
				Downgrade gaat naar <strong><?php echo esc_html( $target_label ); ?></strong>
				<?php if ( $klant_available ) : ?>
					(MCM Klant rol beschikbaar via Site Optimizer).
				<?php else : ?>
					(Site Optimizer niet geïnstalleerd &mdash; downgrade gaat naar Subscriber).
				<?php endif; ?>
			</p>

			<?php if ( empty( $users ) ) : ?>
				<p style="color:#1e7e34;"><strong>&#10003; Geen gebruikers met verhoogde rechten gevonden.</strong></p>
			<?php else : ?>
				<table class="widefat striped" style="margin-top: 8px;">
					<thead>
						<tr>
							<th>Gebruiker</th>
							<th>E-mail</th>
							<th>Rol</th>
							<th>Laatst gezien</th>
							<th style="width: 240px;">Actie</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $users as $user ) :
							$is_admin      = in_array( 'administrator', (array) $user->roles, true );
							$can_downgrade = $is_admin
								? current_user_can( 'manage_options' )
								: current_user_can( 'promote_users' );
							$downgrade_url = wp_nonce_url(
								add_query_arg(
									[
										'action'  => MCM_User_Audit::ACTION_DOWNGRADE,
										'user_id' => $user->ID,
									],
									admin_url( 'admin-post.php' )
								),
								MCM_User_Audit::NONCE_KEY
							);
						?>
						<tr>
							<td><strong><?php echo esc_html( $user->user_login ); ?></strong></td>
							<td><?php echo esc_html( $user->user_email ); ?></td>
							<td>
								<?php echo esc_html( MCM_User_Audit::role_labels( $user ) ); ?>
								<?php if ( $is_admin ) : ?>
									<span title="Administrator" style="color:#b32d2e; margin-left: 4px;">&#9888;</span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( MCM_User_Audit::last_seen_label( $user ) ); ?></td>
							<td>
								<?php if ( $can_downgrade ) : ?>
									<a href="<?php echo esc_url( $downgrade_url ); ?>"
										class="button button-small"
										onclick="return confirm('Weet je zeker dat je <?php echo esc_js( $user->user_login ); ?> wilt downgraden naar <?php echo esc_js( $target_label ); ?>?');">
										Downgrade naar <?php echo esc_html( $target_label ); ?>
									</a>
								<?php else : ?>
									<em style="color:#646970;">geen rechten</em>
								<?php endif; ?>
							</td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
				<p class="description" style="margin-top: 8px;">
					Totaal: <?php echo (int) count( $users ); ?> gebruiker(s) met verhoogde rechten.
				</p>
			<?php endif; ?>
		</div>
		<?php
	}

	private function render_basic_auth_section( $settings ) {
		$is_staging = class_exists( 'MCM_Staging_Detector' ) ? MCM_Staging_Detector::is_staging() : false;
		$is_active  = MCM_Basic_Auth::is_active();
		$user       = isset( $settings[ MCM_Basic_Auth::SETTING_USER ] ) ? $settings[ MCM_Basic_Auth::SETTING_USER ] : 'staging';
		$plain      = MCM_Basic_Auth::get_plain_password();
		?>
		<div class="mcm-section">
			<h2>Staging wachtwoordbeveiliging (HTTP Basic Auth)</h2>
			<p class="description">
				Schermt de hele site af met een browser-popup vóór WordPress laadt.
				Werkt <strong>alleen op staging</strong> &mdash; voorkomt dat je live-site per ongeluk dichtgaat.
				Override mogelijk via <code>define( 'MCM_IS_STAGING', true );</code> in wp-config.
			</p>

			<?php if ( ! $is_staging ) : ?>
				<p style="background:#f8d7da; color:#721c24; padding:10px 14px; border-radius:3px; border-left:4px solid #dc3545;">
					<strong>Niet beschikbaar:</strong> deze site wordt niet als staging herkend.
					Activeren is geblokkeerd om te voorkomen dat je per ongeluk je live-site afsluit.
					Bekijk de Omgevingsdetectie-sectie hierboven of gebruik de override-constant.
				</p>
			<?php endif; ?>

			<table class="form-table">
				<tr>
					<th scope="row">Status</th>
					<td>
						<?php if ( $is_active ) : ?>
							<span class="mcm-badge mcm-badge-active">ACTIEF</span>
							<span class="description" style="margin-left:8px;">Bezoekers krijgen eerst een wachtwoord-popup.</span>
						<?php else : ?>
							<span class="mcm-badge mcm-badge-inactive">NIET ACTIEF</span>
						<?php endif; ?>
					</td>
				</tr>

				<tr>
					<th scope="row"><label for="basic_auth_user">Gebruikersnaam</label></th>
					<td>
						<input type="text" id="basic_auth_user" name="basic_auth_user"
							value="<?php echo esc_attr( $user ); ?>"
							class="regular-text" maxlength="64" style="width: 200px;"
							<?php echo $is_active ? 'readonly' : ''; ?> />
						<p class="description">
							Alleen letters, cijfers, <code>_</code> en <code>-</code>. Standaard: <code>staging</code>.
							<?php if ( $is_active ) : ?>
								<br><em>Vergrendeld zolang Basic Auth actief is &mdash; eerst uitschakelen om te wijzigen.</em>
							<?php endif; ?>
						</p>
					</td>
				</tr>

				<?php if ( $plain ) : ?>
				<tr>
					<th scope="row">Plain wachtwoord</th>
					<td>
						<code style="display:inline-block; padding:6px 12px; background:#fff3cd; border:1px solid #ffc107; border-radius:3px; font-size:14px; user-select:all;"><?php echo esc_html( $plain ); ?></code>
						<button type="button" class="button button-small" onclick="navigator.clipboard.writeText('<?php echo esc_js( $plain ); ?>'); this.textContent='Gekopieerd!'; setTimeout(()=>this.textContent='Kopieer',2000);">Kopieer</button>
						<p class="description">
							<strong>Bewaar nu</strong> &mdash; dit wachtwoord is nog max 30 minuten zichtbaar (in transient), daarna alleen via "Regenereer" een nieuwe maken.
						</p>
					</td>
				</tr>
				<?php endif; ?>
			</table>

			<?php if ( $is_staging ) : ?>
			<div class="mcm-actions" style="margin-top:10px;">
				<?php if ( ! $is_active ) : ?>
					<button type="submit" name="mcm_security_action" value="basic_auth_activate" class="button button-primary">
						Activeer &amp; genereer wachtwoord
					</button>
				<?php else : ?>
					<button type="submit" name="mcm_security_action" value="basic_auth_regenerate" class="button button-secondary">
						Regenereer wachtwoord
					</button>
					<button type="submit" name="mcm_security_action" value="basic_auth_deactivate" class="button button-link-delete"
						onclick="return confirm('Basic Auth uitschakelen? De staging site is daarna voor iedereen toegankelijk.');">
						Uitschakelen
					</button>
				<?php endif; ?>
			</div>
			<p class="description" style="margin-top:8px;">
				<?php if ( $is_active ) : ?>
					Mail de toegangsgegevens via de sectie <strong>Klant toegang &amp; mail</strong> hieronder.
				<?php endif; ?>
				<?php if ( $is_active && ! $plain ) : ?>
					<br><strong>Wachtwoord niet meer in cache</strong> &mdash; klik <em>Regenereer</em> voor een nieuwe (oude wordt ongeldig).
				<?php endif; ?>
			</p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * JS dat alle .mcm-section elementen omvormt naar collapsible blokken.
	 *
	 * - Default: dicht
	 * - State per sectie onthouden in localStorage
	 * - Profielen-sectie krijgt extra header-knoppen: "Toon profielen" + "Scan opnieuw"
	 * - "mcm-profile-confirmation" wordt overgeslagen (= tijdelijke feedback-melding)
	 */
	private function render_collapsible_script() {
		$active = get_option( 'mcm_security_active_profile', '' );
		$cfg = $this->steps_config();
		$auto_open = ( $active && ! empty( $cfg[ $active ]['sections_open'] ) )
			? $cfg[ $active ]['sections_open']
			: [];
		?>
		<script>
		(function () {
			var STORE_KEY = 'mcm_security_open_sections_v1';
			// Versioned profile-key: als profile verandert, opnieuw auto-openen.
			var PROFILE_APPLIED_KEY = 'mcm_security_profile_auto_open';
			var activeProfile = <?php echo wp_json_encode( $active ); ?>;
			var autoOpenSlugs = <?php echo wp_json_encode( $auto_open ); ?>;
			var state = {};
			try { state = JSON.parse(localStorage.getItem(STORE_KEY) || '{}'); } catch (e) {}
			function save() {
				try { localStorage.setItem(STORE_KEY, JSON.stringify(state)); } catch (e) {}
			}

			// Bij profiel-wissel: pas auto-open eenmalig toe (overschrijft state).
			var lastProfile = '';
			try { lastProfile = localStorage.getItem(PROFILE_APPLIED_KEY) || ''; } catch (e) {}
			var applyAutoOpen = ( activeProfile && activeProfile !== lastProfile );
			if ( applyAutoOpen ) {
				autoOpenSlugs.forEach(function (slug) { state[slug] = true; });
				try { localStorage.setItem(PROFILE_APPLIED_KEY, activeProfile); } catch (e) {}
				save();
			}

			var sections = document.querySelectorAll('.mcm-security-wrap .mcm-section');
			sections.forEach(function (section, idx) {
				if (section.classList.contains('is-collapsible')) return;
				if (section.classList.contains('mcm-profile-confirmation')) return;
				var h2 = section.querySelector('h2');
				if (!h2) return;

				var slug = h2.textContent.trim().toLowerCase()
					.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').substring(0, 40);
				var sectionId = slug || ('sec-' + idx);
				section.dataset.sectionId = sectionId;
				section.classList.add('is-collapsible');

				var header = document.createElement('div');
				header.className = 'mcm-section-header';
				header.tabIndex = 0;
				header.setAttribute('role', 'button');
				header.setAttribute('aria-expanded', 'false');
				header.appendChild(h2);

				if (section.classList.contains('mcm-profiles-section')) {
					var actions = document.createElement('div');
					actions.className = 'mcm-section-actions';

					var toonBtn = document.createElement('button');
					toonBtn.type = 'button';
					toonBtn.className = 'button button-primary';
					toonBtn.textContent = 'Toon profielen';
					toonBtn.addEventListener('click', function (e) {
						e.stopPropagation();
						openSection(section);
					});
					actions.appendChild(toonBtn);

					var existing = section.querySelector('button[value="run_detection"]');
					if (existing) {
						var clone = existing.cloneNode(true);
						clone.textContent = 'Scan opnieuw';
						clone.className = 'button button-secondary';
						clone.addEventListener('click', function (e) { e.stopPropagation(); });
						actions.appendChild(clone);
					}
					header.appendChild(actions);
				}

				var chev = document.createElement('span');
				chev.className = 'mcm-chevron';
				chev.innerHTML = '▼';
				header.appendChild(chev);

				var body = document.createElement('div');
				body.className = 'mcm-section-body';
				while (section.firstChild) {
					body.appendChild(section.firstChild);
				}

				section.appendChild(header);
				section.appendChild(body);

				if (state[sectionId]) {
					section.classList.add('is-open');
					header.setAttribute('aria-expanded', 'true');
				}

				header.addEventListener('click', function (e) {
					if (e.target.tagName === 'BUTTON' || e.target.closest('button')) return;
					if (e.target.tagName === 'A' || e.target.closest('a')) return;
					toggleSection(section);
				});
				header.addEventListener('keydown', function (e) {
					if (e.key === 'Enter' || e.key === ' ') {
						e.preventDefault();
						toggleSection(section);
					}
				});
			});

			function toggleSection(section) {
				var isOpen = section.classList.toggle('is-open');
				var hdr = section.querySelector('.mcm-section-header');
				if (hdr) hdr.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
				state[section.dataset.sectionId] = isOpen;
				save();
			}
			function openSection(section) {
				section.classList.add('is-open');
				var hdr = section.querySelector('.mcm-section-header');
				if (hdr) hdr.setAttribute('aria-expanded', 'true');
				state[section.dataset.sectionId] = true;
				save();
			}
		})();
		</script>
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

						<?php
						// Stappen voor het actieve profiel (bron: steps_config).
						$steps_cfg = $this->steps_config();
						if ( ! empty( $steps_cfg[ $detected_profile ]['steps'] ) ) :
							$block = $steps_cfg[ $detected_profile ];
						?>
						<p style="margin-top:14px; margin-bottom:6px;">
							<strong>📋 <?php echo esc_html( $block['title'] ); ?></strong>
						</p>
						<ol style="margin:0; padding-left:20px;">
							<?php foreach ( $block['steps'] as $step ) : ?>
								<li style="margin:4px 0;"><?php echo wp_kses_post( $step ); ?></li>
							<?php endforeach; ?>
						</ol>
						<?php endif; ?>
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
			'basic_auth_activated' => [ 'success', '<strong>Basic Auth geactiveerd</strong> &mdash; staging is nu wachtwoord-beveiligd. Bewaar het wachtwoord direct, of mail het naar je admins.' ],
			'basic_auth_deactivated' => [ 'warning', 'Basic Auth uitgeschakeld &mdash; staging is weer voor iedereen toegankelijk.' ],
			'basic_auth_regenerated' => [ 'success', 'Nieuw wachtwoord gegenereerd. Oude wachtwoord werkt niet meer.' ],
			'basic_auth_no_plain' => [ 'warning', 'Plain wachtwoord niet meer in cache (>30 min). Klik <em>Regenereer wachtwoord</em> voor een nieuwe.' ],
			'basic_auth_error' => [ 'error', 'Basic Auth fout' ],
			'audit_invalid' => [ 'error', 'User audit: ongeldige aanvraag.' ],
			'audit_user_not_found' => [ 'error', 'User audit: gebruiker niet gevonden.' ],
			'audit_owner_protected' => [ 'warning', 'User audit: MCM-eigenaar wordt niet gedowngrade.' ],
			'audit_super_protected' => [ 'warning', 'User audit: super-admin (multisite) wordt niet gedowngrade.' ],
			'audit_no_admin_downgrade' => [ 'error', 'User audit: alleen een administrator mag een administrator downgraden.' ],
			'exposure_scan_done' => [ 'success', 'File-exposure scan is uitgevoerd. Zie de "Blootgestelde bestanden"-sectie voor het resultaat.' ],
		];

		if ( 'audit_downgraded' === $status ) {
			$user  = isset( $_GET['mcm_audit_user'] ) ? sanitize_user( wp_unslash( $_GET['mcm_audit_user'] ) ) : '?';
			$role  = isset( $_GET['mcm_audit_role'] ) ? sanitize_key( wp_unslash( $_GET['mcm_audit_role'] ) ) : '?';
			$names = wp_roles()->get_names();
			$label = isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : $role;
			printf(
				'<div class="notice notice-success is-dismissible"><p>Gebruiker <strong>%s</strong> is gedowngrade naar <strong>%s</strong>.</p></div>',
				esc_html( $user ),
				esc_html( $label )
			);
			return;
		}

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

		if ( 'access_mail_sent' === $status ) {
			$count = isset( $_GET['mcm-count'] ) ? absint( $_GET['mcm-count'] ) : 0;
			$msg   = sprintf(
				_n(
					'Toegangsmail (Basic Auth + login-URL) verstuurd naar %d ontvanger.',
					'Toegangsmail (Basic Auth + login-URL) verstuurd naar %d ontvangers.',
					$count,
					'mcm-security-hardener'
				),
				$count
			);
			printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html( $msg ) );
			return;
		}

		if ( 'basic_auth_error' === $status ) {
			$err = isset( $_GET['mcm-error'] ) ? sanitize_text_field( rawurldecode( $_GET['mcm-error'] ) ) : 'Onbekende fout.';
			printf( '<div class="notice notice-error is-dismissible"><p><strong>Basic Auth fout:</strong> %s</p></div>', esc_html( $err ) );
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

			/* Stappen-blok bovenaan (per actief profiel) */
			.mcm-steps-block { background: #f0f6fc; border-left: 4px solid #2271b1; padding: 14px 20px; margin: 20px 0; border-radius: 4px; }
			.mcm-steps-block h3 { margin: 0 0 10px; font-size: 14px; font-weight: 600; }
			.mcm-steps-block ol { margin: 0; padding-left: 22px; }
			.mcm-steps-block li { margin: 6px 0; line-height: 1.5; }

			/* Collapsible sections (JS voegt is-collapsible toe na page load) */
			.mcm-section.is-collapsible { padding: 0; }
			.mcm-section.is-collapsible .mcm-section-header {
				display: flex; align-items: center; gap: 12px;
				padding: 14px 20px; cursor: pointer; user-select: none;
				border-bottom: 1px solid transparent;
			}
			.mcm-section.is-collapsible.is-open .mcm-section-header { border-bottom-color: #eee; }
			.mcm-section.is-collapsible .mcm-section-header h2 {
				margin: 0; padding: 0; border: none; flex: 1; font-size: 16px; font-weight: 600;
			}
			.mcm-section.is-collapsible:hover .mcm-section-header h2 { color: #2271b1; }
			.mcm-section.is-collapsible .mcm-section-actions { display: flex; gap: 6px; }
			.mcm-section.is-collapsible .mcm-section-actions .button {
				padding: 2px 10px; font-size: 12px; line-height: 1.8; min-height: 0;
			}
			.mcm-section.is-collapsible .mcm-chevron {
				transition: transform 0.2s ease; font-size: 10px; color: #50575e; width: 14px; text-align: center;
			}
			.mcm-section.is-collapsible.is-open .mcm-chevron { transform: rotate(180deg); }
			.mcm-section.is-collapsible .mcm-section-body { display: none; padding: 0 20px 15px; }
			.mcm-section.is-collapsible.is-open .mcm-section-body { display: block; }

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
