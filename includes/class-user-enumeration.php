<?php
/**
 * User Enumeration — dicht de plekken waar WordPress gebruikersnamen
 * publiek weggeeft.
 *
 * Aanleiding: de Xel-beveiligingsscan meldt "De WordPress gebruikersnamen zijn
 * publiekelijk op te vragen" met als advies "neem contact op met support om
 * onze plugin bij te werken". Dat werkt alleen op Xel-hosting; deze module
 * doet het in onze eigen plugin, dus op elke site en zonder afhankelijkheid
 * van de host.
 *
 * Waarom dit uitmaakt: met een geldige gebruikersnaam is een brute-force of
 * credential-stuffing-aanval de helft van het werk kwijt. WordPress lekt die
 * namen standaard via vier routes:
 *
 *   1. ?author=1  → redirect naar /author/<naam>/ (loop de ID's af en je hebt
 *                   alle logins van de site)
 *   2. REST API   → /wp-json/wp/v2/users geeft anoniem de hele userlijst
 *   3. oEmbed     → /wp-json/oembed/1.0/embed?url=... zet author_name erin
 *   4. Sitemap    → /wp-sitemap-users-1.xml somt auteurs op
 *
 * En na een mislukte login zegt WordPress het verschil tussen "onbekende
 * gebruikersnaam" en "wachtwoord onjuist" — daarmee kun je logins verifiëren
 * zonder ooit binnen te komen.
 *
 * Elke route heeft een eigen toggle, want ze hebben verschillende
 * neveneffecten. Standaard staan ze alle vijf aan; op een site met echte
 * auteursarchieven (blog met meerdere schrijvers) kun je punt 1 uitzetten.
 *
 * Bewust NIET gedaan:
 *   - Auteursarchieven volledig uitschakelen. Dat breekt themes die
 *     /author/-links renderen. We blokkeren de enumeratie-vector (?author=ID),
 *     niet het archief zelf.
 *   - De REST-userlijst ook voor ingelogde gebruikers dichtzetten. De
 *     blok-editor heeft die lijst nodig (auteur kiezen, @-mentions); dat
 *     slopen levert een onbruikbare backend op. Anoniem = dicht, ingelogd =
 *     open, want dan is de naam al bekend.
 *
 * Settings (in mcm_security_settings):
 *   - 'block_author_enumeration' bool default true
 *   - 'restrict_rest_users'      bool default true
 *   - 'hide_authors_in_oembed'   bool default true
 *   - 'remove_users_sitemap'     bool default true
 *   - 'generic_login_errors'     bool default true
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_User_Enumeration {

	/**
	 * Generieke loginfout — zegt niet of de gebruikersnaam bestond.
	 */
	const GENERIC_LOGIN_ERROR = 'De combinatie van gebruikersnaam en wachtwoord is niet juist.';

	public function __construct() {
		if ( self::enabled( 'block_author_enumeration' ) ) {
			// Priority 1: vóór redirect_canonical (priority 10), die ?author=1
			// juist omzet naar de URL met de gebruikersnaam erin.
			add_action( 'template_redirect', [ $this, 'block_author_query' ], 1 );
		}

		if ( self::enabled( 'restrict_rest_users' ) ) {
			add_filter( 'rest_endpoints', [ $this, 'restrict_rest_users_endpoint' ] );
		}

		if ( self::enabled( 'hide_authors_in_oembed' ) ) {
			add_filter( 'oembed_response_data', [ $this, 'strip_oembed_author' ] );
		}

		if ( self::enabled( 'remove_users_sitemap' ) ) {
			add_filter( 'wp_sitemaps_add_provider', [ $this, 'remove_users_sitemap_provider' ], 10, 2 );
		}

		if ( self::enabled( 'generic_login_errors' ) ) {
			add_filter( 'login_errors', [ $this, 'generic_login_error' ] );
		}
	}

	/**
	 * Setting uitlezen met terugval op de plugin-default.
	 *
	 * Sites die van een oudere versie updaten hebben deze keys nog niet in de
	 * DB staan. Zonder terugval zou de bescherming uit blijven staan tot
	 * iemand handmatig op Opslaan drukt.
	 */
	public static function enabled( $key ) {
		$settings = get_option( 'mcm_security_settings', [] );
		if ( array_key_exists( $key, (array) $settings ) ) {
			return ! empty( $settings[ $key ] );
		}
		$defaults = method_exists( 'MCM_Security_Hardener', 'get_defaults' )
			? MCM_Security_Hardener::get_defaults()
			: [];
		return ! empty( $defaults[ $key ] );
	}

	/**
	 * ?author=<id> → 404 in plaats van een redirect die de login prijsgeeft.
	 *
	 * Alleen voor niet-ingelogde bezoekers: ingelogd is de gebruikersnaam
	 * geen geheim meer, en een 404 op /author/ zou de backend-preview van
	 * auteurspagina's onnodig breken.
	 */
	public function block_author_query() {
		if ( is_user_logged_in() ) {
			return;
		}

		// Alleen de ID-vector. Een nette /author/<slug>/-URL laten we staan:
		// die is al publiek en soms deel van het thema.
		$has_author_param = isset( $_GET['author'] ) && '' !== $_GET['author']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! $has_author_param ) {
			return;
		}

		global $wp_query;
		if ( $wp_query instanceof WP_Query ) {
			$wp_query->set_404();
		}
		status_header( 404 );
		nocache_headers();
	}

	/**
	 * Haal de user-routes uit de REST API voor anonieme requests.
	 *
	 * /wp/v2/users/me blijft staan: die vereist authenticatie en lekt dus
	 * niets, maar wordt wél door de editor gebruikt.
	 */
	public function restrict_rest_users_endpoint( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		unset( $endpoints['/wp/v2/users'] );
		unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );

		return $endpoints;
	}

	/**
	 * Auteursnaam uit de oEmbed-respons halen.
	 *
	 * De rest van de respons (titel, thumbnail, iframe) blijft intact, dus
	 * embeds van deze site op andere sites blijven werken.
	 */
	public function strip_oembed_author( $data ) {
		if ( ! is_array( $data ) ) {
			return $data;
		}
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	/**
	 * Verwijder de users-provider uit de WordPress-sitemap.
	 */
	public function remove_users_sitemap_provider( $provider, $name ) {
		if ( 'users' === $name ) {
			return false;
		}
		return $provider;
	}

	/**
	 * Vervang loginfouten die verklappen of een gebruikersnaam bestaat.
	 *
	 * Alleen de foutcodes die daadwerkelijk lekken worden vervangen. Andere
	 * meldingen (bv. "cookies zijn geblokkeerd", 2FA-fouten van een andere
	 * plugin) blijven ongemoeid — die helpen de gebruiker en lekken niets.
	 */
	public function generic_login_error( $error ) {
		global $errors;

		$leaky_codes = [
			'invalid_username',
			'invalid_email',
			'incorrect_password',
			'empty_password',
			'invalidcombo',
		];

		if ( is_wp_error( $errors ) ) {
			$codes = $errors->get_error_codes();
			if ( array_intersect( $codes, $leaky_codes ) ) {
				return self::GENERIC_LOGIN_ERROR;
			}
			return $error;
		}

		// Geen $errors-object beschikbaar (andere plugin filtert eerder, of
		// een custom loginformulier). Val terug op tekst-detectie zodat de
		// standaardmeldingen van WordPress alsnog worden afgevangen.
		$needles = [ 'gebruikersnaam', 'username', 'e-mailadres', 'email address', 'wachtwoord', 'password' ];
		foreach ( $needles as $needle ) {
			if ( false !== stripos( (string) $error, $needle ) ) {
				return self::GENERIC_LOGIN_ERROR;
			}
		}

		return $error;
	}

	/**
	 * Status per lek-route, voor weergave op de admin-pagina.
	 *
	 * @return array<int,array{key:string,label:string,active:bool,detail:string}>
	 */
	public static function status() {
		return [
			[
				'key'    => 'block_author_enumeration',
				'label'  => '?author=1 geeft geen gebruikersnaam',
				'active' => self::enabled( 'block_author_enumeration' ),
				'detail' => 'Zonder dit stuurt WordPress een redirect naar /author/&lt;login&gt;/ — de ID\'s aflopen levert alle gebruikersnamen op.',
			],
			[
				'key'    => 'restrict_rest_users',
				'label'  => 'REST API geeft anoniem geen userlijst',
				'active' => self::enabled( 'restrict_rest_users' ),
				'detail' => '/wp-json/wp/v2/users is standaard voor iedereen leesbaar. Ingelogde gebruikers houden toegang (de blok-editor heeft die nodig).',
			],
			[
				'key'    => 'hide_authors_in_oembed',
				'label'  => 'oEmbed noemt geen auteursnaam',
				'active' => self::enabled( 'hide_authors_in_oembed' ),
				'detail' => 'De oEmbed-respons van elke post bevat standaard author_name en author_url.',
			],
			[
				'key'    => 'remove_users_sitemap',
				'label'  => 'Sitemap somt geen auteurs op',
				'active' => self::enabled( 'remove_users_sitemap' ),
				'detail' => 'WordPress publiceert standaard /wp-sitemap-users-1.xml met alle auteurs.',
			],
			[
				'key'    => 'generic_login_errors',
				'label'  => 'Loginfout verklapt niets',
				'active' => self::enabled( 'generic_login_errors' ),
				'detail' => 'Standaard meldt WordPress het verschil tussen een onbekende gebruikersnaam en een onjuist wachtwoord — daarmee zijn logins te verifiëren.',
			],
		];
	}
}
