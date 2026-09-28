<?php
/**
 * User Delete Guard — een gebruiker verwijderen verwijdert nooit meer
 * zijn inhoud. Die gaat naar een beheerder.
 *
 * Aanleiding: op powair.nl (juni 2026) werd bij het opruimen van oude
 * beheeraccounts het account van de directie verwijderd zonder de inhoud
 * toe te wijzen. WordPress verwijderde daarmee 171 items van dat account:
 * o.a. Privacybeleid, Algemene voorwaarden, Over ons, vijf productpagina's
 * en 151 media-items. Niemand merkte het, tot een klant naar kapotte
 * links vroeg. Terughalen kon alleen uit een toevallig bewaarde snapshot.
 *
 * Werking: wp_delete_user() zonder $reassign vraagt via de filter
 * 'post_types_to_delete_with_user' welke berichttypes mee weg moeten.
 * Zou daarbij echte inhoud verdwijnen, dan geven we een lege lijst terug:
 * WordPress verwijdert dan alleen het account. Na het verwijderen
 * ('deleted_user') krijgen precies de berichten die WordPress had willen
 * verwijderen een nieuwe auteur: de beheerder die de actie uitvoerde, of
 * anders een MCM-eigenaar of de eerste administrator.
 *
 * Bewust GEEN wp_die(): de nep-/botaccountmodule van de Site Optimizer
 * verwijdert soms honderden accounts in één verzoek. Afbreken zou die
 * batch halverwege stoppen. Inhoud bewaren is altijd veilig.
 *
 * Telt niet als "echte inhoud" (die mogen gewoon mee weg): revisies,
 * automatische concepten en berichten in de prullenbak. Heeft een account
 * alleen dat, dan doet deze module niets.
 *
 * Grens: dit vangt alleen verwijderingen via wp_delete_user() (wp-admin,
 * WP-CLI, REST, plugins). Rechtstreekse database-queries buiten WordPress
 * om ziet geen enkele plugin. Multisite (wpmu_delete_user) valt erbuiten.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_User_Delete_Guard {

	/** Post-types die niet als echte inhoud tellen. */
	const IGNORE_TYPES = [ 'revision', 'customize_changeset', 'oembed_cache', 'user_request' ];

	/** Statussen die niet als echte inhoud tellen. */
	const IGNORE_STATUSES = [ 'auto-draft', 'trash' ];

	/**
	 * Per verwijderde gebruiker: welke post-ID's we hebben tegengehouden en
	 * aan wie ze gaan. [ user_id => [ 'ids' => int[], 'to' => int, 'types' => [type => n], 'user' => WP_User ] ]
	 *
	 * @var array<int,array>
	 */
	private static $pending = [];

	/** Samenvatting voor de ene mail/notice aan het eind van het verzoek. */
	private static $report = [];

	public function __construct() {
		add_filter( 'post_types_to_delete_with_user', [ __CLASS__, 'filter_post_types' ], 999999, 2 );
		add_action( 'deleted_user', [ __CLASS__, 'reassign_after_delete' ], 10, 3 );
		add_action( 'shutdown', [ __CLASS__, 'send_report' ] );
		add_action( 'admin_notices', [ __CLASS__, 'admin_notices' ] );
	}

	/**
	 * Staat de bewaking aan voor deze gebruiker?
	 */
	public static function is_enabled( $user_id ) {
		if ( defined( 'MCM_SECURITY_ALLOW_USER_CONTENT_DELETE' ) && MCM_SECURITY_ALLOW_USER_CONTENT_DELETE ) {
			return false;
		}
		return (bool) apply_filters( 'mcm_user_delete_guard_enabled', true, (int) $user_id );
	}

	/**
	 * Echte inhoud van een gebruiker die WordPress zou meeverwijderen, per type.
	 * Ook bruikbaar voor andere modules (bv. de nep-accountscan) om vooraf te
	 * tonen wat er aan een account hangt.
	 *
	 * @param int      $user_id
	 * @param string[] $post_types Types die WordPress zou verwijderen.
	 * @return array<string,int> type => aantal
	 */
	public static function content_counts( $user_id, array $post_types ) {
		global $wpdb;
		$types = array_values( array_diff( $post_types, self::IGNORE_TYPES ) );
		if ( empty( $types ) ) {
			return [];
		}
		$type_in   = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$status_in = implode( ',', array_fill( 0, count( self::IGNORE_STATUSES ), '%s' ) );
		$sql       = "SELECT post_type, COUNT(*) AS n FROM {$wpdb->posts}
		              WHERE post_author = %d AND post_type IN ($type_in) AND post_status NOT IN ($status_in)
		              GROUP BY post_type";
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, array_merge( [ (int) $user_id ], $types, self::IGNORE_STATUSES ) ) );
		$out  = [];
		foreach ( (array) $rows as $r ) {
			$out[ $r->post_type ] = (int) $r->n;
		}
		return $out;
	}

	/**
	 * Filter in wp_delete_user(): houd de verwijdering tegen als er echte
	 * inhoud mee zou gaan.
	 */
	public static function filter_post_types( $post_types, $user_id ) {
		global $wpdb;
		$user_id = (int) $user_id;

		if ( empty( $post_types ) || ! self::is_enabled( $user_id ) ) {
			return $post_types;
		}

		$counts = self::content_counts( $user_id, (array) $post_types );
		if ( empty( $counts ) ) {
			return $post_types; // Alleen revisies/concepten/prullenbak: mag weg.
		}

		// Precies de ID's die WordPress had willen verwijderen (alle statussen,
		// ook revisies), zodat niets als wees achterblijft.
		$type_in = implode( ',', array_fill( 0, count( $post_types ), '%s' ) );
		$ids     = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT ID FROM {$wpdb->posts} WHERE post_author = %d AND post_type IN ($type_in)",
				array_merge( [ $user_id ], array_values( $post_types ) )
			)
		);

		self::$pending[ $user_id ] = [
			'ids'    => array_map( 'intval', $ids ),
			'to'     => self::fallback_author( $user_id ),
			'counts' => $counts,
			'user'   => get_userdata( $user_id ),
		];

		return []; // WordPress verwijdert nu geen enkel bericht van deze gebruiker.
	}

	/**
	 * Na het verwijderen: tegengehouden inhoud aan de nieuwe auteur geven.
	 */
	public static function reassign_after_delete( $user_id, $reassign = null, $user = null ) {
		global $wpdb;
		$user_id = (int) $user_id;
		if ( ! isset( self::$pending[ $user_id ] ) ) {
			return;
		}
		$p = self::$pending[ $user_id ];
		unset( self::$pending[ $user_id ] );

		if ( $p['to'] && $p['ids'] ) {
			foreach ( array_chunk( $p['ids'], 500 ) as $chunk ) {
				$in = implode( ',', array_map( 'intval', $chunk ) );
				$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->posts} SET post_author = %d WHERE ID IN ($in) AND post_author = %d", $p['to'], $user_id ) );
			}
			foreach ( $p['ids'] as $post_id ) {
				clean_post_cache( $post_id );
			}
		}

		$u = $p['user'] ? $p['user'] : $user;
		self::$report[] = [
			'login'  => $u ? $u->user_login : '#' . $user_id,
			'email'  => $u ? $u->user_email : '',
			'roles'  => $u ? implode( ', ', (array) $u->roles ) : '',
			'id'     => $user_id,
			'counts' => $p['counts'],
			'to'     => $p['to'],
		];

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( 'WP_CLI' ) ) {
			\WP_CLI::warning( sprintf(
				'MCM Security: inhoud van gebruiker %d niet verwijderd maar toegewezen aan %s (%s).',
				$user_id,
				$p['to'] ? 'gebruiker ' . $p['to'] : 'niemand — auteur blijft leeg',
				self::counts_label( $p['counts'] )
			) );
		}
	}

	/**
	 * Aan wie gaat de inhoud? De uitvoerende beheerder, anders een
	 * MCM-eigenaar, anders de eerste administrator. Nooit de gebruiker zelf.
	 */
	private static function fallback_author( $deleting_id ) {
		$current = get_current_user_id();
		if ( $current && $current !== $deleting_id && user_can( $current, 'edit_others_posts' ) ) {
			return $current;
		}

		$owners = class_exists( 'MCM_Lockdown_Manager' ) ? MCM_Lockdown_Manager::get_owners() : [];
		foreach ( (array) $owners as $login ) {
			$u = get_user_by( 'login', $login );
			if ( $u && (int) $u->ID !== $deleting_id ) {
				return (int) $u->ID;
			}
		}

		$admins = get_users( [
			'role'    => 'administrator',
			'exclude' => [ $deleting_id ],
			'orderby' => 'ID',
			'order'   => 'ASC',
			'number'  => 1,
			'fields'  => 'ID',
		] );
		return $admins ? (int) $admins[0] : 0;
	}

	private static function counts_label( array $counts ) {
		$parts = [];
		foreach ( $counts as $type => $n ) {
			$obj     = get_post_type_object( $type );
			$label   = $obj ? $obj->labels->name : $type;
			$parts[] = $n . ' ' . $label;
		}
		return implode( ', ', $parts );
	}

	private static function author_label( $user_id ) {
		if ( ! $user_id ) {
			return 'niemand (geen beheerder gevonden) — de auteur blijft leeg, de inhoud bestaat nog';
		}
		$u = get_userdata( $user_id );
		return $u ? sprintf( '%s (ID %d)', $u->user_login, $user_id ) : 'ID ' . $user_id;
	}

	/**
	 * Eén mail + één admin-notice per verzoek, ook bij een batch.
	 */
	public static function send_report() {
		if ( empty( self::$report ) ) {
			return;
		}
		$rows         = self::$report;
		self::$report = [];

		$total = 0;
		$lines = [];
		foreach ( $rows as $r ) {
			$total  += array_sum( $r['counts'] );
			$lines[] = sprintf(
				"- %s (ID %d, %s, %s): %s → toegewezen aan %s",
				$r['login'], $r['id'], $r['email'], $r['roles'] ?: 'geen rol',
				self::counts_label( $r['counts'] ), self::author_label( $r['to'] )
			);
		}

		$actor = self::actor_label();

		// Notice voor wie het deed (terug in wp-admin na de redirect).
		$current = get_current_user_id();
		if ( $current ) {
			$prev = get_transient( 'mcm_udg_notice_' . $current );
			$prev = is_array( $prev ) ? $prev : [];
			set_transient( 'mcm_udg_notice_' . $current, array_merge( $prev, $lines ), 10 * MINUTE_IN_SECONDS );
		}

		if ( class_exists( 'MCM_Notifier' ) ) {
			$subject = sprintf( 'Gebruiker verwijderd — %d items bewaard i.p.v. verwijderd', $total );
			$body    = "Er is een gebruiker verwijderd met de keuze \"alle inhoud verwijderen\" (of via code zonder\n";
			$body   .= "toewijzing). De MCM Security Hardener heeft die inhoud NIET laten verwijderen, maar\n";
			$body   .= "aan een beheerder toegewezen:\n\n";
			$body   .= implode( "\n", $lines ) . "\n\n";
			$body   .= sprintf( "Uitgevoerd door: %s\n", $actor );
			$body   .= "\n----\n";
			$body   .= "Moest die inhoud echt weg? Verwijder de berichten/pagina's/media dan los.\n";
			$body   .= "Wil je dit op deze site uitzetten: define( 'MCM_SECURITY_ALLOW_USER_CONTENT_DELETE', true );\n";
			MCM_Notifier::email( $subject, $body );
		}
	}

	public static function admin_notices() {
		$current = get_current_user_id();
		if ( ! $current || ! current_user_can( 'list_users' ) ) {
			return;
		}

		$lines = get_transient( 'mcm_udg_notice_' . $current );
		if ( is_array( $lines ) && $lines ) {
			delete_transient( 'mcm_udg_notice_' . $current );
			echo '<div class="notice notice-warning is-dismissible"><p><strong>MCM Security:</strong> ';
			echo esc_html__( 'de inhoud van de verwijderde gebruiker is bewaard en toegewezen aan een beheerder:', 'mcm-security-hardener' );
			echo '</p><ul style="list-style:disc;margin-left:1.5em">';
			foreach ( $lines as $l ) {
				echo '<li>' . esc_html( ltrim( $l, '- ' ) ) . '</li>';
			}
			echo '</ul></div>';
		}

		// Op het bevestigscherm "Gebruikers verwijderen": vooraf uitleggen wat er gebeurt.
		global $pagenow;
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( 'users.php' === $pagenow && in_array( $action, [ 'delete', 'dodelete' ], true ) && self::is_enabled( 0 ) ) {
			echo '<div class="notice notice-info"><p><strong>MCM Security:</strong> ';
			echo esc_html__( 'inhoud (pagina\'s, berichten, media) wordt op deze site nooit met een gebruiker meeverwijderd. Kies je "Alle inhoud verwijderen", dan wordt die inhoud aan jou toegewezen. Kies liever zelf aan wie.', 'mcm-security-hardener' );
			echo '</p></div>';
		}
	}

	private static function actor_label() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'WP-CLI';
		}
		$current = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		if ( $current && $current->ID ) {
			return sprintf( '%s (ID %d)', $current->user_login, $current->ID );
		}
		return 'Onbekend — geen ingelogde gebruiker (cron of script)';
	}
}
