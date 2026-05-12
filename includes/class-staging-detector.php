<?php
/**
 * Staging-detectie helper.
 *
 * Detecteert of de site op een staging/test-omgeving draait. Wordt gebruikt
 * door de Basic Auth-feature: die mag alleen activeren op staging, om te
 * voorkomen dat live-sites per ongeluk op slot gaan.
 *
 * Detectie via meerdere signalen — als minstens één positief is, telt het als
 * staging. De `MCM_IS_STAGING` constant overrult alles (zowel forceren als
 * uitschakelen).
 *
 * Override-volgorde:
 *   - define( 'MCM_IS_STAGING', true );  → altijd staging
 *   - define( 'MCM_IS_STAGING', false ); → nooit staging (ook al detecteren we 't)
 *   - geen constant                       → automatische detectie
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Staging_Detector {

	/**
	 * Hoofdvraag: draait deze site op staging?
	 *
	 * @return bool
	 */
	public static function is_staging() {
		// Expliciete override — sterkste signaal.
		if ( defined( 'MCM_IS_STAGING' ) ) {
			return (bool) MCM_IS_STAGING;
		}

		$signals = self::get_signals();
		foreach ( $signals as $signal ) {
			if ( ! empty( $signal['matched'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Lijst van detectie-signalen + of ze matchen.
	 *
	 * Gebruikt door de admin-readout zodat zichtbaar is waarom we wel/niet
	 * denken dat het staging is.
	 *
	 * @return array<int, array{name:string, description:string, matched:bool, value:string}>
	 */
	public static function get_signals() {
		$signals = [];

		// 1. WordPress' eigen environment type (5.5+).
		$wp_env  = function_exists( 'wp_get_environment_type' ) ? wp_get_environment_type() : 'production';
		$wp_match = in_array( $wp_env, [ 'staging', 'development' ], true );
		$signals[] = [
			'name'        => 'wp_get_environment_type()',
			'description' => 'WordPress\' eigen omgevingstype (gezet via WP_ENVIRONMENT_TYPE constant of $_SERVER).',
			'matched'     => $wp_match,
			'value'       => $wp_env,
		];

		// 2. URL-patronen.
		$home   = home_url();
		$host   = wp_parse_url( $home, PHP_URL_HOST );
		$host   = $host ? strtolower( $host ) : '';
		$url_match_pattern = self::match_url_pattern( $host );
		$signals[] = [
			'name'        => 'URL-patroon',
			'description' => 'Bekende staging/dev/local-patronen in de hostname (staging., -staging, dev., .test, .local, localhost, 127.0.0.1).',
			'matched'     => (bool) $url_match_pattern,
			'value'       => $url_match_pattern ? sprintf( '%s — match: %s', $host, $url_match_pattern ) : $host,
		];

		return $signals;
	}

	/**
	 * Welk URL-patroon matcht (indien een)? Return false of een korte beschrijving.
	 *
	 * @param string $host hostname (lowercase).
	 * @return string|false
	 */
	private static function match_url_pattern( $host ) {
		if ( '' === $host ) {
			return false;
		}

		$exact = [ 'localhost', '127.0.0.1' ];
		if ( in_array( $host, $exact, true ) ) {
			return $host;
		}

		$suffixes = [ '.test', '.local', '.localhost' ];
		foreach ( $suffixes as $suffix ) {
			if ( substr( $host, -strlen( $suffix ) ) === $suffix ) {
				return 'suffix ' . $suffix;
			}
		}

		// Zoek bekende staging/dev/test/acceptatie-prefixes als label in de host.
		// \w* aan het eind dekt ook samenstellingen als testsite, testserver, devomgeving.
		// Voorbeelden die matchen: staging.site.nl, site-staging.nl, dev.site.nl,
		// testsite.site.nl, site.dev, acceptatie.site.nl, acc.site.nl
		$patterns = [
			'/(^|[.\-])staging\w*($|[.\-])/i'    => 'staging',
			'/(^|[.\-])dev\w*($|[.\-])/i'        => 'dev',
			'/(^|[.\-])test\w*($|[.\-])/i'       => 'test',
			'/(^|[.\-])acceptatie($|[.\-])/i'    => 'acceptatie',
			'/(^|[.\-])acc($|[.\-])/i'           => 'acc',
			'/(^|[.\-])preview($|[.\-])/i'       => 'preview',
		];
		foreach ( $patterns as $regex => $label ) {
			if ( preg_match( $regex, $host ) ) {
				return $label;
			}
		}

		return false;
	}

	/**
	 * Hoe is de detectie tot stand gekomen? Voor de admin-readout.
	 *
	 * @return string
	 */
	public static function explain() {
		if ( defined( 'MCM_IS_STAGING' ) ) {
			return MCM_IS_STAGING
				? 'Forceer-staging via constant MCM_IS_STAGING = true in wp-config.php.'
				: 'Forceer-NIET-staging via constant MCM_IS_STAGING = false in wp-config.php.';
		}
		return self::is_staging()
			? 'Automatische detectie: minstens één signaal hieronder is positief.'
			: 'Automatische detectie: geen enkel signaal is positief.';
	}
}
