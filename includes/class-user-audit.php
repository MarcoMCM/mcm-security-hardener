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

	public function __construct() {
		add_action( 'admin_post_' . self::ACTION_DOWNGRADE, [ $this, 'handle_downgrade' ] );
		add_action( 'admin_post_' . self::ACTION_FIX_DISPLAY, [ $this, 'handle_fix_display_name' ] );
	}

	/**
	 * Gebruikersnamen die een aanvaller als eerste probeert.
	 *
	 * Aanleiding: de Xel-beveiligingsscan meldt "Er is een gebruikersnaam
	 * gevonden met de naam 'admin'". Dat is geen theoretisch risico — het is
	 * de helft van een brute-force-aanval die al klaar is.
	 *
	 * De sitenaam en het domein worden er automatisch bij gezet: op een site
	 * susenso.nl is 'susenso' net zo voorspelbaar als 'admin'.
	 *
	 * @return string[] Lowercase logins.
	 */
	public static function risky_login_names() {
		$names = [
			'admin', 'administrator', 'administrateur', 'root', 'test', 'tester',
			'demo', 'user', 'gebruiker', 'wordpress', 'wp', 'webmaster', 'beheer',
			'beheerder', 'support', 'info', 'sysadmin', 'guest', 'owner', 'editor',
		];

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
	 * Gebruikers met een risico op hun naam of weergavenaam.
	 *
	 * Drie soorten bevindingen:
	 *   - risky_login   : voorspelbare gebruikersnaam ('admin' & co)
	 *   - display_login : weergavenaam is gelijk aan de login, waardoor de
	 *                     login onder elke post/reactie publiek staat
	 *   - slug_login    : de auteurs-slug is de login, dus /author/<login>/
	 *                     verklapt hem (alleen gemeld bij gepubliceerde posts)
	 *
	 * Twee gerichte queries in plaats van alle users doorlopen: op een webshop
	 * met tienduizenden klantaccounts is dat laatste geen optie.
	 *
	 * @return array<int,array{user:WP_User,issues:array<int,array{code:string,severity:string,label:string,advice:string,fixable:bool}>}>
	 */
	public static function get_risky_users() {
		$owners = class_exists( 'MCM_Lockdown_Manager' )
			? MCM_Lockdown_Manager::get_owners()
			: [];

		// 1. Users met verhoogde rechten (die zijn de moeite van een aanval waard).
		$candidates = self::get_elevated_users();

		// 2. Users met een voorspelbare login, ongeacht rol — een 'admin'-account
		//    dat is gedegradeerd naar subscriber blijft een geldige login.
		$by_name = get_users( [
			'login__in' => self::risky_login_names(),
			'orderby'   => 'user_login',
			'order'     => 'ASC',
		] );

		$merged = [];
		foreach ( array_merge( $candidates, $by_name ) as $user ) {
			if ( in_array( $user->user_login, $owners, true ) ) {
				continue;
			}
			if ( is_multisite() && is_super_admin( $user->ID ) ) {
				continue;
			}
			$merged[ $user->ID ] = $user;
		}

		$risky_names = self::risky_login_names();
		$out         = [];

		foreach ( $merged as $user ) {
			$issues   = [];
			$is_admin = in_array( 'administrator', (array) $user->roles, true );

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

			if ( $issues ) {
				$out[] = [
					'user'   => $user,
					'issues' => $issues,
				];
			}
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
