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

	const ACTION_DOWNGRADE   = 'mcm_security_downgrade_user';
	const NONCE_KEY          = 'mcm_security_downgrade';
	const KLANT_ROLE_SLUG    = 'mcm_klant';
	const ACTION_FIX_DISPLAY = 'mcm_security_fix_display_name';
	const NONCE_FIX_DISPLAY  = 'mcm_security_fix_display';

	const ELEVATED_ROLES = [ 'administrator', 'editor', 'author', 'contributor' ];

	// Kenmerken van de accounts die de wp2shell-aanval aanmaakt (lowercase).
	// Zie wp2shell_match().
	const WP2SHELL_LOGIN_PREFIXES = [ 'wp2_', 'w2s_' ];
	const WP2SHELL_LOGINS         = [ 'wpenginebot' ];
	const WP2SHELL_EMAIL_DOMAINS  = [ 'wp2shell.invalid', 'wp2shell.shellcode.lol', 'wpengine.com' ];

	public function __construct() {
		add_action( 'admin_post_' . self::ACTION_DOWNGRADE, [ $this, 'handle_downgrade' ] );
		add_action( 'admin_post_' . self::ACTION_FIX_DISPLAY, [ $this, 'handle_fix_display_name' ] );
	}

	/**
	 * Gebruikersnamen die zó voorspelbaar zijn dat ze geblokkeerd mogen worden
	 * bij registratie. Harde lijst: hier zit geen naam tussen die een echte
	 * klant redelijkerwijs zou kiezen.
	 *
	 * Aanleiding: de Xel-beveiligingsscan meldt "Er is een gebruikersnaam
	 * gevonden met de naam 'admin'". Dat is geen theoretisch risico — het is
	 * de helft van een brute-force-aanval die al klaar is. Op susenso.nl bleek
	 * dat een bot-registratie te zijn die de naam 'admin' had geclaimd.
	 *
	 * Deze lijst wordt gebruikt door MCM_Registration_Protection om nieuwe
	 * registraties te weigeren, en om bestaande accounts te signaleren.
	 *
	 * @return string[] Lowercase logins.
	 */
	public static function reserved_login_names() {
		$names = [
			'admin', 'administrator', 'administrateur', 'root', 'test',
			'demo', 'wordpress', 'wp', 'webmaster', 'beheer', 'beheerder',
			'sysadmin', 'superadmin',
		];

		$names = apply_filters( 'mcm_security_reserved_logins', $names );

		return array_values( array_unique( array_map( 'strtolower', (array) $names ) ) );
	}

	/**
	 * Bredere lijst voor de AUDIT van accounts met verhoogde rechten.
	 *
	 * Bevat namen die voor een beheerdersaccount voorspelbaar zijn maar voor
	 * een klantaccount gewoon een keuze kunnen zijn ('info', 'support'), plus
	 * de domeinnaam van de site: op susenso.nl is 'susenso' voor een beheerder
	 * net zo voorspelbaar als 'admin'.
	 *
	 * Bewust NIET gebruikt voor klantaccounts of voor het blokkeren van
	 * registraties — op susenso bleek 'susenso' een echte klant te zijn
	 * (Hendrik van Manen), en die hoort niet in een risicolijst.
	 *
	 * @return string[] Lowercase logins.
	 */
	public static function risky_login_names() {
		$names = array_merge(
			self::reserved_login_names(),
			[ 'tester', 'user', 'gebruiker', 'support', 'info', 'guest', 'owner', 'editor' ]
		);

		// Domeinnaam zonder tld + www: 'susenso.nl' → 'susenso'.
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( $host ) {
			$host  = preg_replace( '/^www\./i', '', $host );
			$parts = explode( '.', $host );
			if ( ! empty( $parts[0] ) && strlen( $parts[0] ) > 2 ) {
				$names[] = strtolower( $parts[0] );
			}
		}

		$names = apply_filters( 'mcm_security_risky_login_names', $names );

		return array_values( array_unique( array_map( 'strtolower', (array) $names ) ) );
	}

	/**
	 * Past een account bij de wp2shell-aanval?
	 *
	 * Aanleiding: op een MCM-site maakten aanvallers op 19 juli 2026 drie
	 * beheerders aan via wp2shell, een lek in WordPress zelf (CVE-2026-63030
	 * + CVE-2026-60137, in WordPress 6.9.0–6.9.4 en 7.0.0–7.0.1): wp2_3ab049
	 * en wp2_66a992 (@wp2shell.invalid) en wpenginebot (@wpengine.com,
	 * terwijl de site niet bij WP Engine staat). Dat bleef drie maanden
	 * onopgemerkt.
	 *
	 * Bewust ongeacht de rol: na ontdekking worden zulke accounts vaak naar
	 * Abonnee gezet in plaats van verwijderd, en dan vallen ze buiten elke
	 * controle die alleen naar beheerders kijkt.
	 *
	 * Grens: @wpengine.com is alleen verdacht als de site niet bij WP Engine
	 * staat. Geen enkele MCM-site staat daar.
	 *
	 * @param string $login
	 * @param string $email
	 * @return string Waarom het account verdacht is, of '' als het niet past.
	 */
	public static function wp2shell_match( $login, $email ) {
		$login   = strtolower( (string) $login );
		$email   = strtolower( (string) $email );
		$reasons = [];

		foreach ( self::WP2SHELL_LOGIN_PREFIXES as $prefix ) {
			if ( 0 === strpos( $login, $prefix ) ) {
				$reasons[] = sprintf( 'gebruikersnaam begint met "%s"', $prefix );
			}
		}
		if ( in_array( $login, self::WP2SHELL_LOGINS, true ) ) {
			$reasons[] = sprintf( 'gebruikersnaam "%s"', $login );
		}

		$at = strrpos( $email, '@' );
		if ( false !== $at && in_array( substr( $email, $at + 1 ), self::WP2SHELL_EMAIL_DOMAINS, true ) ) {
			$reasons[] = sprintf( 'e-mailadres op @%s', substr( $email, $at + 1 ) );
		}

		return implode( ' en ', $reasons );
	}

	/**
	 * Alle accounts die bij de wp2shell-aanval passen, met welke rol dan ook.
	 *
	 * Rechtstreeks uit de users-tabel, niet via get_users(): een
	 * achterdeur-plugin kan WP_User_Query filteren (pre_user_query) en zo zijn
	 * eigen account verbergen.
	 *
	 * @return array<int,array{user:WP_User,reason:string}> Op user-ID.
	 */
	public static function get_wp2shell_users() {
		global $wpdb;

		$where = [];
		$args  = [];
		foreach ( self::WP2SHELL_LOGIN_PREFIXES as $prefix ) {
			$where[] = 'user_login LIKE %s';
			$args[]  = $wpdb->esc_like( $prefix ) . '%';
		}
		foreach ( self::WP2SHELL_LOGINS as $login ) {
			$where[] = 'user_login = %s';
			$args[]  = $login;
		}
		foreach ( self::WP2SHELL_EMAIL_DOMAINS as $domain ) {
			$where[] = 'user_email LIKE %s';
			$args[]  = '%@' . $wpdb->esc_like( $domain );
		}

		$ids = $wpdb->get_col( $wpdb->prepare(
			"SELECT ID FROM {$wpdb->users} WHERE " . implode( ' OR ', $where ) . ' ORDER BY ID',
			$args
		) );

		$out = [];
		foreach ( (array) $ids as $id ) {
			$user = get_user_by( 'id', (int) $id );
			if ( ! $user ) {
				continue;
			}
			// De SQL is ruim; wp2shell_match() beslist en levert de reden.
			$reason = self::wp2shell_match( $user->user_login, $user->user_email );
			if ( '' === $reason ) {
				continue;
			}
			$out[ (int) $user->ID ] = [
				'user'   => $user,
				'reason' => $reason,
			];
		}

		return $out;
	}

	/**
	 * Bevinding voor een wp2shell-account, in het formaat van get_risky_users().
	 */
	private static function wp2shell_issue( $reason ) {
		return [
			'code'     => 'wp2shell',
			'severity' => 'high',
			'label'    => sprintf( 'Aanvallersaccount (wp2shell): %s', $reason ),
			'advice'   => 'Dit account past bij de wp2shell-aanval op WordPress zelf (sinds juli 2026), welke rol het nu ook heeft. Ga ervan uit dat de site is binnengedrongen: controleer dat WordPress minstens 6.9.5 of 7.0.2 is, kijk bij "Vreemde bestanden & mappen" naar andere sporen en verwijder het account pas na onderzoek, met een backup vooraf. Vernieuw daarna wachtwoorden en salts. De plugin verwijdert niets.',
			'fixable'  => false,
		];
	}

	/**
	 * Gebruikers met een risico op hun naam of weergavenaam.
	 *
	 * Vier soorten bevindingen:
	 *   - wp2shell      : account past bij de wp2shell-aanval (altijd HIGH,
	 *                     ongeacht de rol — zie wp2shell_match())
	 *   - risky_login   : voorspelbare gebruikersnaam ('admin' & co)
	 *   - display_login : weergavenaam is gelijk aan de login, waardoor de
	 *                     login onder elke post/reactie publiek staat
	 *   - slug_login    : de auteurs-slug is de login, dus /author/<login>/
	 *                     verklapt hem (alleen gemeld bij gepubliceerde posts)
	 *
	 * Alleen accounts met VERHOOGDE RECHTEN. Klantaccounts blijven hier buiten:
	 * die horen bij de nep-/botaccountmodule van de Site Optimizer, met zijn
	 * eigen veiligheidsslot en CSV-backup. Deze plugin doet security, niet het
	 * beheren of opruimen van klantenbestanden.
	 *
	 * Uitzondering: wp2shell-accounts staan er met elke rol in, en bovenaan.
	 * Dat is geen klantenbeheer maar een inbraakspoor.
	 *
	 * Klantaccounts met een gereserveerde naam ('admin' & co) worden wél
	 * geteld — zie get_reserved_login_accounts() — maar als doorverwijzing,
	 * niet als iets om hier op te lossen.
	 *
	 * @return array<int,array{user:WP_User,issues:array<int,array{code:string,severity:string,label:string,advice:string,fixable:bool}>}>
	 */
	public static function get_risky_users() {
		// get_elevated_users() sluit MCM-eigenaars en super-admins al uit.
		$risky_names = self::risky_login_names();
		$wp2shell    = self::get_wp2shell_users();
		$attack      = []; // wp2shell-accounts, komen bovenaan
		$out         = [];

		foreach ( self::get_elevated_users() as $user ) {
			$issues   = [];
			$is_admin = in_array( 'administrator', (array) $user->roles, true );

			if ( isset( $wp2shell[ $user->ID ] ) ) {
				$issues[] = self::wp2shell_issue( $wp2shell[ $user->ID ]['reason'] );
			}

			if ( in_array( strtolower( $user->user_login ), $risky_names, true ) ) {
				$issues[] = [
					'code'     => 'risky_login',
					'severity' => $is_admin ? 'high' : 'medium',
					'label'    => sprintf( 'Voorspelbare gebruikersnaam: %s', $user->user_login ),
					'advice'   => 'Maak een nieuw account met een niet te raden naam, draag de content over (Gebruikers → Verwijderen → "Alle content toewijzen aan") en verwijder dit account. WordPress kan een login niet hernoemen; de plugin doet dat bewust niet met een directe database-update.',
					'fixable'  => false,
				];
			}

			if ( $user->display_name === $user->user_login ) {
				$issues[] = [
					'code'     => 'display_login',
					'severity' => 'medium',
					'label'    => 'Weergavenaam is gelijk aan de login',
					'advice'   => 'Hierdoor staat de gebruikersnaam onder elke post en reactie, en in de auteursnaam van feeds. Los te maken met één klik.',
					'fixable'  => true,
				];
			}

			if ( $user->user_nicename === sanitize_title( $user->user_login )
				&& (int) count_user_posts( $user->ID ) > 0 ) {
				$issues[] = [
					'code'     => 'slug_login',
					'severity' => 'low',
					'label'    => 'Auteurs-slug is de login',
					'advice'   => sprintf( 'De URL /author/%s/ bevat de gebruikersnaam. Aan te passen op het gebruikersprofiel (veld "Bijnaam" + "Naam openbaar weergeven"), of laat het zo als de auteurspagina niet wordt gebruikt.', $user->user_nicename ),
					'fixable'  => false,
				];
			}

			if ( isset( $wp2shell[ $user->ID ] ) ) {
				$attack[] = [
					'user'   => $user,
					'issues' => $issues,
				];
				unset( $wp2shell[ $user->ID ] );
			} elseif ( $issues ) {
				$out[] = [
					'user'   => $user,
					'issues' => $issues,
				];
			}
		}

		// De overige wp2shell-accounts hebben geen verhoogde rol (meestal al
		// naar Abonnee gezet). Alleen de wp2shell-bevinding: de rest van de
		// checks gaat over accounts die je wilt houden.
		foreach ( $wp2shell as $match ) {
			$attack[] = [
				'user'   => $match['user'],
				'issues' => [ self::wp2shell_issue( $match['reason'] ) ],
			];
		}

		return array_merge( $attack, $out );
	}

	/**
	 * Accounts ZONDER verhoogde rechten die toch een gereserveerde naam hebben.
	 *
	 * Dit is de categorie die op susenso.nl opdook: een bot-registratie met de
	 * login 'admin', rol customer, geen orders, geen content. Geen beheerrisico
	 * (die rol kan niets), maar het bezet wel de meest geraden gebruikersnaam
	 * van de site — en het is de bevinding waar de Xel-scan op afgaat.
	 *
	 * Opruimen gebeurt NIET hier: dat is klantaccount-beheer en dus werk voor
	 * de nep-/botaccountmodule van de Site Optimizer. Deze methode levert
	 * alleen het signaal + de doorverwijzing.
	 *
	 * @return WP_User[]
	 */
	public static function get_reserved_login_accounts() {
		$reserved = self::reserved_login_names();
		if ( empty( $reserved ) ) {
			return [];
		}

		$users = get_users( [
			'login__in' => $reserved,
			'orderby'   => 'user_login',
			'order'     => 'ASC',
		] );

		$owners = class_exists( 'MCM_Lockdown_Manager' )
			? MCM_Lockdown_Manager::get_owners()
			: [];

		$out = [];
		foreach ( $users as $user ) {
			if ( in_array( $user->user_login, $owners, true ) ) {
				continue;
			}
			if ( is_multisite() && is_super_admin( $user->ID ) ) {
				continue;
			}
			// Verhoogde rollen staan al in de hoofdtabel hierboven.
			if ( array_intersect( (array) $user->roles, self::ELEVATED_ROLES ) ) {
				continue;
			}
			$out[] = $user;
		}

		return $out;
	}

	/**
	 * Zwaarste severity uit een lijst bevindingen.
	 */
	public static function worst_severity( array $issues ) {
		foreach ( [ 'high', 'medium', 'low' ] as $level ) {
			foreach ( $issues as $issue ) {
				if ( $level === $issue['severity'] ) {
					return $level;
				}
			}
		}
		return 'low';
	}

	/**
	 * Bedenk een weergavenaam die niet de login is.
	 *
	 * Voorkeur: echte naam → bijnaam → rolnaam. Nooit de login, en nooit leeg
	 * (WordPress valt dan terug op de login).
	 */
	public static function suggest_display_name( WP_User $user ) {
		$first = trim( (string) get_user_meta( $user->ID, 'first_name', true ) );
		$last  = trim( (string) get_user_meta( $user->ID, 'last_name', true ) );

		$full = trim( $first . ' ' . $last );
		if ( '' !== $full && strtolower( $full ) !== strtolower( $user->user_login ) ) {
			return $full;
		}

		$nickname = trim( (string) get_user_meta( $user->ID, 'nickname', true ) );
		if ( '' !== $nickname && strtolower( $nickname ) !== strtolower( $user->user_login ) ) {
			return $nickname;
		}

		$roles = (array) $user->roles;
		$names = wp_roles()->get_names();
		$slug  = ! empty( $roles ) ? reset( $roles ) : '';
		if ( $slug && isset( $names[ $slug ] ) ) {
			return translate_user_role( $names[ $slug ] );
		}

		return 'Redactie';
	}

	/**
	 * Maakt de weergavenaam los van de login.
	 */
	public function handle_fix_display_name() {
		if ( ! current_user_can( 'edit_users' ) ) {
			wp_die( 'Geen toegang.', 'MCM Security', [ 'response' => 403 ] );
		}
		check_admin_referer( self::NONCE_FIX_DISPLAY );

		$user_id = isset( $_REQUEST['user_id'] ) ? absint( $_REQUEST['user_id'] ) : 0;
		$referer = wp_get_referer() ?: admin_url( 'tools.php?page=mcm-security' );

		$user = $user_id ? get_user_by( 'ID', $user_id ) : null;
		if ( ! $user ) {
			wp_safe_redirect( add_query_arg( 'mcm_status', 'audit_user_not_found', $referer ) );
			exit;
		}

		$new_name = self::suggest_display_name( $user );
		$result   = wp_update_user( [
			'ID'           => $user->ID,
			'display_name' => $new_name,
		] );

		if ( is_wp_error( $result ) ) {
			wp_safe_redirect( add_query_arg( 'mcm_status', 'audit_display_failed', $referer ) );
			exit;
		}

		wp_safe_redirect( add_query_arg( [
			'mcm_status'      => 'audit_display_fixed',
			'mcm_audit_user'  => $user->user_login,
			'mcm_audit_value' => rawurlencode( $new_name ),
		], $referer ) );
		exit;
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
