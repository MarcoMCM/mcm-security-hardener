<?php
/**
 * Back-ups die de plugin zelf maakt: wp-config.php, .htaccess en de
 * SQL-back-up van de DB-prefix-migratie.
 *
 * Alles staat in uploads/mcm-security-backups/ als .php-bestand met één
 * guard-regel bovenaan (self::GUARD). Een HTTP-verzoek voert het bestand
 * dus uit en stopt meteen: lege pagina, de inhoud komt niet mee. Dat werkt
 * ook op nginx, waar de deny-.htaccess van deze map niet telt; op Apache
 * blijft die .htaccess als extra laag. Lokaal getest (Apache): zonder
 * .htaccess HTTP 200 met 0 bytes, in deze map 403.
 *
 * Herstellen = de eerste regel weghalen, de rest is byte voor byte het
 * origineel. Bijvoorbeeld: tail -n +2 wp-config-20261005-101500-123456.php > wp-config.php
 *
 * Aanleiding (4 okt 2026): tot 1.32.0 zette de plugin een kopie
 * wp-config.php.mcm-backup naast wp-config.php. Onbekende extensie, dus
 * Apache en nginx serveerden hem als platte tekst: DB-credentials en salts
 * publiek. De .bak- en .sql-back-ups in deze map leunden alleen op de
 * .htaccess en waren op nginx ook publiek.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Backup_Store {

	const DIR = 'mcm-security-backups';

	// Eén regel, zodat herstellen altijd "eerste regel weghalen" is.
	// __halt_compiler() zorgt dat PHP de rest niet eens parseert.
	const GUARD = "<?php /* MCM Security back-up. Herstellen: verwijder alleen deze eerste regel. */ exit; __halt_compiler(); ?>\n";

	// Elke kopie bevat DB-credentials en salts: niet meer dan nodig.
	const KEEP_WPCONFIG = 5;

	/**
	 * Back-up van wp-config.php; houdt de laatste 5.
	 *
	 * Is de inhoud gelijk aan de nieuwste back-up, dan komt er geen nieuwe
	 * bij. Anders duwt elke "Opslaan" zonder wijziging in wp-config.php een
	 * oudere, echt andere versie eruit.
	 *
	 * @return string|false Pad van de back-up.
	 */
	public static function wpconfig( $config_path ) {
		$content = is_readable( $config_path ) ? file_get_contents( $config_path ) : false;
		if ( false === $content ) {
			return false;
		}

		$dir = self::dir();
		if ( ! $dir ) {
			return false;
		}
		$existing = glob( $dir . '/wp-config-*.php' );
		if ( $existing ) {
			sort( $existing );
			$latest = end( $existing );
			if ( @file_get_contents( $latest ) === self::GUARD . $content ) {
				return $latest;
			}
		}

		return self::save( 'wp-config', '.php', $content, self::KEEP_WPCONFIG );
	}

	/**
	 * Sla $content op als <prefix>-<datum>-<microseconden><ext> en houd de
	 * laatste $keep. De microseconden zorgen dat twee schrijfacties in
	 * dezelfde seconde toch chronologisch sorteren; opruimen gaat op naam.
	 * Met alleen "-2" erachter sorteerde de nieuwste vóór de oudste en ruimde
	 * het opruimen juist de nieuwste op (lokaal zo gezien).
	 *
	 * @param string $prefix Bv. 'htaccess'.
	 * @param string $ext    Eindigt op .php, bv. '.php' of '.sql.php'.
	 * @param string $content
	 * @param int    $keep   0 = niets opruimen.
	 * @return string|false Pad van de back-up.
	 */
	public static function save( $prefix, $ext, $content, $keep ) {
		$dir = self::dir();
		if ( ! $dir ) {
			return false;
		}

		list( $usec, $sec ) = explode( ' ', microtime() );
		$stamp = gmdate( 'Ymd-His', (int) $sec ) . '-' . substr( $usec, 2, 6 );
		$path  = self::free_path( $dir . '/' . $prefix . '-' . $stamp, $ext );
		if ( ! self::write( $path, $content ) ) {
			return false;
		}

		if ( $keep > 0 ) {
			$backups = glob( $dir . '/' . $prefix . '-*' . $ext );
			if ( $backups && count( $backups ) > $keep ) {
				sort( $backups );
				foreach ( array_slice( $backups, 0, count( $backups ) - $keep ) as $old ) {
					@unlink( $old );
				}
			}
		}

		return $path;
	}

	/**
	 * Eenmalig, vanuit de upgrade-routine (1.32.0): oude back-ups naar het
	 * nieuwe formaat.
	 *
	 *  - wp-config.php.mcm-backup naast wp-config.php (in ABSPATH of de map
	 *    erboven) → wp-config-<datum>-oud.php in de back-upmap.
	 *  - .htaccess.mcm-backup in ABSPATH (Basic Auth, 1.8.0-1.8.1) →
	 *    htaccess-<datum>-oud.php.
	 *  - htaccess-*.bak en db-prefix-backup-*.sql in de back-upmap → zelfde
	 *    naam, als .php met guard.
	 *
	 * <datum> is de wijzigingsdatum van het oude bestand. Het origineel gaat
	 * pas weg als de nieuwe kopie is teruggelezen en klopt; lukt iets niet,
	 * dan blijft het origineel staan (de exposure-scanner meldt het dan nog).
	 * wp-config.php zelf wordt niet aangeraakt.
	 *
	 * @return array{moved:int, failed:string[]}
	 */
	public static function migrate_legacy() {
		$result  = [ 'moved' => 0, 'failed' => [] ];
		$abspath = untrailingslashit( ABSPATH );

		$sources = [];
		foreach ( array_unique( [ $abspath, dirname( $abspath ) ] ) as $root ) {
			$sources[ $root . '/wp-config.php.mcm-backup' ] = 'wp-config';
		}
		$sources[ $abspath . '/.htaccess.mcm-backup' ] = 'htaccess';

		$jobs = [];
		foreach ( $sources as $src => $prefix ) {
			if ( self::is_plain_file( $src ) ) {
				$jobs[ $src ] = [ $prefix . '-' . gmdate( 'Ymd-His', (int) @filemtime( $src ) ) . '-oud', '.php' ];
			}
		}

		$dir = self::dir();
		if ( ! $dir ) {
			$result['failed'] = array_keys( $jobs );
			return $result;
		}

		foreach ( (array) glob( $dir . '/htaccess-*.bak' ) as $src ) {
			$jobs[ $src ] = [ basename( $src, '.bak' ), '.php' ];
		}
		foreach ( (array) glob( $dir . '/db-prefix-backup-*.sql' ) as $src ) {
			$jobs[ $src ] = [ basename( $src ), '.php' ];
		}

		foreach ( $jobs as $src => $target ) {
			if ( ! self::is_plain_file( $src ) ) {
				continue;
			}
			$content = @file_get_contents( $src );
			$path    = self::free_path( $dir . '/' . $target[0], $target[1] );
			if ( false === $content || ! self::write( $path, $content ) ) {
				$result['failed'][] = $src;
				continue;
			}
			if ( ! @unlink( $src ) ) {
				// Kopie staat er, maar het origineel ook nog.
				$result['failed'][] = $src;
				continue;
			}
			$result['moved']++;
		}

		return $result;
	}

	/**
	 * De back-upmap, aangemaakt en met deny-.htaccess + index.php.
	 *
	 * @return string|false
	 */
	public static function dir() {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) ) {
			return false;
		}
		$dir = trailingslashit( $uploads['basedir'] ) . self::DIR;
		if ( ! wp_mkdir_p( $dir ) ) {
			return false;
		}
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			@file_put_contents( $dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
		}
		if ( ! file_exists( $dir . '/index.php' ) ) {
			@file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" );
		}
		return $dir;
	}

	/**
	 * Schrijf GUARD + $content en lees terug ter controle.
	 */
	private static function write( $path, $content ) {
		$data = self::GUARD . $content;
		if ( false === @file_put_contents( $path, $data, LOCK_EX ) ) {
			return false;
		}
		if ( @file_get_contents( $path ) !== $data ) {
			@unlink( $path );
			return false;
		}
		return true;
	}

	/**
	 * $base . $ext, of $base-2 . $ext enz. als die al bestaat (alleen bij
	 * het omzetten van oude back-ups met dezelfde wijzigingsseconde).
	 */
	private static function free_path( $base, $ext ) {
		$path = $base . $ext;
		for ( $i = 2; file_exists( $path ); $i++ ) {
			$path = $base . '-' . $i . $ext;
		}
		return $path;
	}

	/**
	 * Gewoon bestand, geen symlink. Met @: boven ABSPATH kan open_basedir
	 * de controle blokkeren.
	 */
	private static function is_plain_file( $path ) {
		return @is_file( $path ) && ! @is_link( $path );
	}
}
