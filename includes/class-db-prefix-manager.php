<?php
/**
 * Database Prefix Manager
 *
 * Detecteert default 'wp_' prefix en biedt een knop om naar een random prefix
 * te migreren. Renamed alle WP-tabellen, patcht wp-config.php $table_prefix,
 * en past option_name + meta_key rijen aan die de oude prefix bevatten.
 *
 * Maakt een SQL-backup van te wijzigen data VOORDAT migratie start, zodat
 * handmatige rollback mogelijk is. Roll-backt automatisch bij rename-failure.
 *
 * Wordt niet ondersteund op multisite (te complex).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_DB_Prefix_Manager {

	const NONCE_ACTION          = 'mcm_db_prefix_change';
	const NOTICE_DISMISS_OPTION = 'mcm_db_prefix_notice_dismissed';
	const BACKUP_DIR            = 'mcm-security-backups';

	public function __construct() {
		add_action( 'admin_notices', [ $this, 'maybe_show_notice' ] );
		add_action( 'admin_post_mcm_change_db_prefix',          [ $this, 'handle_change' ] );
		add_action( 'admin_post_mcm_dismiss_db_prefix_notice',  [ $this, 'handle_dismiss' ] );
	}

	/**
	 * Is de huidige prefix nog de WP-default?
	 */
	public static function is_default_prefix() {
		global $wpdb;
		return 'wp_' === $wpdb->prefix;
	}

	/**
	 * Toont een notice op admin pages als de prefix nog 'wp_' is.
	 */
	public function maybe_show_notice() {
		// Alleen MCM-eigenaars zien deze waarschuwing — niet de klant.
		if ( ! MCM_Notifier::should_show_admin_notice() ) {
			return;
		}
		if ( is_multisite() ) {
			return;
		}
		if ( ! self::is_default_prefix() ) {
			return;
		}
		if ( get_option( self::NOTICE_DISMISS_OPTION ) ) {
			return;
		}

		$change_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=mcm_change_db_prefix' ),
			self::NONCE_ACTION
		);
		$dismiss_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=mcm_dismiss_db_prefix_notice' ),
			self::NONCE_ACTION
		);
		?>
		<div class="notice notice-warning">
			<p>
				<strong>MCM Security:</strong>
				Je database gebruikt nog de standaard prefix <code>wp_</code>.
				Dit is een bekend doelwit voor SQL-injection-aanvallen.
			</p>
			<p>
				<a href="<?php echo esc_url( $change_url ); ?>" class="button button-primary"
					onclick="return confirm('Weet je zeker dat je de DB-prefix wilt veranderen? Maak eerst een volledige backup. Iedereen wordt mogelijk uitgelogd.');">
					Verander prefix nu
				</a>
				<a href="<?php echo esc_url( $dismiss_url ); ?>" class="button">
					Niet nu (verbergen)
				</a>
			</p>
		</div>
		<?php
	}

	/**
	 * Verbergt de notice permanent (kan altijd weer aan via instellingen).
	 */
	public function handle_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.' );
		}
		check_admin_referer( self::NONCE_ACTION );
		update_option( self::NOTICE_DISMISS_OPTION, time() );
		wp_safe_redirect( wp_get_referer() ?: admin_url() );
		exit;
	}

	/**
	 * Handelt klik op "Verander prefix nu" af.
	 */
	public function handle_change() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Geen toegang.' );
		}
		check_admin_referer( self::NONCE_ACTION );
		if ( is_multisite() ) {
			wp_die( 'DB-prefix wijzigen wordt niet ondersteund op multisite.' );
		}
		if ( ! self::is_default_prefix() ) {
			wp_die( 'Prefix is al gewijzigd.' );
		}

		$result = self::migrate();

		if ( is_wp_error( $result ) ) {
			$msg = '<h1>Migratie mislukt</h1>';
			$msg .= '<p>' . esc_html( $result->get_error_message() ) . '</p>';
			$msg .= '<p>Controleer je site en herstel zo nodig handmatig vanaf de backup.</p>';
			wp_die( wp_kses_post( $msg ), 'MCM Security', [ 'response' => 500 ] );
		}

		// Success page.
		$login_url = wp_login_url();
		?>
		<!DOCTYPE html>
		<html lang="nl">
		<head>
			<meta charset="utf-8">
			<title>MCM Security &mdash; DB-prefix gewijzigd</title>
			<style>
				body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 640px; margin: 60px auto; padding: 24px; color: #2c3338; line-height: 1.5; }
				.success { background: #edfaef; border-left: 4px solid #46b450; padding: 16px 20px; margin: 24px 0; border-radius: 3px; }
				code { background: #f6f7f7; padding: 2px 8px; border-radius: 3px; font-size: 0.95em; }
				.btn { display: inline-block; background: #2271b1; color: #fff; text-decoration: none; padding: 8px 16px; border-radius: 3px; }
				.btn:hover { background: #135e96; }
				ul { padding-left: 20px; }
			</style>
		</head>
		<body>
			<h1>DB-prefix succesvol gewijzigd</h1>
			<div class="success">
				<ul>
					<li>Nieuwe prefix: <code><?php echo esc_html( $result['new_prefix'] ); ?></code></li>
					<li><?php echo (int) $result['tables_renamed']; ?> tabellen hernoemd</li>
					<li><?php echo (int) $result['rows_updated']; ?> rijen bijgewerkt (option_name &amp; meta_key)</li>
					<li>SQL-backup opgeslagen in: <code><?php echo esc_html( $result['backup_path'] ); ?></code></li>
				</ul>
			</div>
			<p>
				Het kan zijn dat je opnieuw moet inloggen omdat je sessie-tokens en capabilities-keys
				zijn verplaatst. Klik hieronder om naar de inlogpagina te gaan.
			</p>
			<p>
				<a href="<?php echo esc_url( $login_url ); ?>" class="btn">Naar inlogpagina</a>
			</p>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Voert de eigenlijke migratie uit.
	 *
	 * @return array|WP_Error
	 */
	private static function migrate() {
		global $wpdb;

		$old_prefix = $wpdb->prefix;
		$new_prefix = self::generate_prefix();

		// Pre-flight: wp-config bereikbaar?
		$config_path = self::get_config_path();
		if ( ! $config_path ) {
			return new WP_Error( 'no_config', 'wp-config.php niet gevonden.' );
		}
		if ( ! is_writable( $config_path ) ) {
			return new WP_Error( 'config_not_writable', 'wp-config.php is niet schrijfbaar. Pas chmod aan en probeer opnieuw.' );
		}

		// Pre-flight: $table_prefix-regel aanwezig?
		$config_content = file_get_contents( $config_path );
		if ( ! preg_match( '/\$table_prefix\s*=\s*[\'"][^\'"]+[\'"]\s*;/', $config_content ) ) {
			return new WP_Error( 'no_prefix_var', '$table_prefix-regel niet gevonden in wp-config.php.' );
		}

		// Verzamel alle tabellen met de oude prefix.
		$tables = $wpdb->get_col(
			$wpdb->prepare(
				'SHOW TABLES LIKE %s',
				$wpdb->esc_like( $old_prefix ) . '%'
			)
		);
		if ( empty( $tables ) ) {
			return new WP_Error( 'no_tables', 'Geen tabellen gevonden met prefix ' . $old_prefix );
		}

		// Maak SQL-backup van alles wat gewijzigd gaat worden.
		$backup_path = self::create_backup( $old_prefix, $tables );
		if ( is_wp_error( $backup_path ) ) {
			return $backup_path;
		}

		// Rename alle tabellen, met automatische rollback bij failure.
		$renamed_pairs = [];
		foreach ( $tables as $old_name ) {
			$new_name = $new_prefix . substr( $old_name, strlen( $old_prefix ) );
			$result   = $wpdb->query( "RENAME TABLE `{$old_name}` TO `{$new_name}`" );
			if ( false === $result ) {
				$err = $wpdb->last_error;
				// Rollback alles wat we al hernoemd hebben.
				foreach ( array_reverse( $renamed_pairs ) as $pair ) {
					$wpdb->query( "RENAME TABLE `{$pair['new']}` TO `{$pair['old']}`" );
				}
				return new WP_Error( 'rename_failed', "Kon tabel {$old_name} niet hernoemen: {$err}. Wijzigingen teruggedraaid." );
			}
			$renamed_pairs[] = [ 'old' => $old_name, 'new' => $new_name ];
		}

		// Vanaf hier werkt $wpdb met de oude prefix nog. Switch naar nieuwe.
		$wpdb->set_prefix( $new_prefix );

		$rows_updated = 0;

		// 1. wp_options: row met option_name = 'wp_user_roles' → '{new}user_roles'
		$rows_updated += (int) $wpdb->update(
			"{$new_prefix}options",
			[ 'option_name' => "{$new_prefix}user_roles" ],
			[ 'option_name' => "{$old_prefix}user_roles" ]
		);

		// 2. wp_usermeta: alle meta_keys die met de oude prefix beginnen.
		$meta_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT umeta_id, meta_key FROM {$new_prefix}usermeta WHERE meta_key LIKE %s",
				$wpdb->esc_like( $old_prefix ) . '%'
			)
		);
		foreach ( $meta_rows as $row ) {
			$new_key = $new_prefix . substr( $row->meta_key, strlen( $old_prefix ) );
			$updated = $wpdb->update(
				"{$new_prefix}usermeta",
				[ 'meta_key' => $new_key ],
				[ 'umeta_id' => $row->umeta_id ]
			);
			if ( $updated ) {
				$rows_updated++;
			}
		}

		// 3. wp-config.php patchen.
		$config_result = self::update_config_prefix( $config_path, $new_prefix );
		if ( is_wp_error( $config_result ) ) {
			// We zitten nu in een gevaarlijke staat: tabellen zijn hernoemd maar
			// wp-config wijst nog naar de oude. Op de volgende request faalt WP.
			return new WP_Error(
				'config_update_failed',
				'Tabellen zijn hernoemd maar wp-config.php kon niet worden bijgewerkt. ' .
				'Pas handmatig aan: $table_prefix = \'' . $new_prefix . '\'; ' .
				'(Backup beschikbaar in ' . $backup_path . ')'
			);
		}

		// Markeer notice als afgehandeld.
		update_option( self::NOTICE_DISMISS_OPTION, time() );

		return [
			'new_prefix'     => $new_prefix,
			'tables_renamed' => count( $renamed_pairs ),
			'rows_updated'   => $rows_updated,
			'backup_path'    => $backup_path,
		];
	}

	/**
	 * Genereer een nieuwe random prefix in de vorm wp_xxxxxx_.
	 */
	private static function generate_prefix() {
		return 'wp_' . bin2hex( random_bytes( 3 ) ) . '_';
	}

	/**
	 * Vind wp-config.php (zelfde logica als WPConfig_Manager).
	 */
	private static function get_config_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		if ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) ) {
			return dirname( ABSPATH ) . '/wp-config.php';
		}
		return false;
	}

	/**
	 * Update $table_prefix in wp-config.php.
	 */
	private static function update_config_prefix( $path, $new_prefix ) {
		$content = file_get_contents( $path );
		$pattern = '/(\$table_prefix\s*=\s*)([\'"])[^\'"]+\2(\s*;)/';
		if ( ! preg_match( $pattern, $content ) ) {
			return new WP_Error( 'no_prefix_var', '$table_prefix niet gevonden.' );
		}
		$replaced = preg_replace( $pattern, "$1'{$new_prefix}'$3", $content );
		if ( null === $replaced ) {
			return new WP_Error( 'regex_failed', 'Kon $table_prefix niet vervangen.' );
		}
		if ( false === file_put_contents( $path, $replaced ) ) {
			return new WP_Error( 'write_failed', 'Kon wp-config.php niet schrijven.' );
		}
		return true;
	}

	/**
	 * Schrijf een SQL-backup van wijzigende rijen weg in wp-content/uploads/mcm-security-backups/.
	 */
	private static function create_backup( $old_prefix, array $tables ) {
		global $wpdb;

		$upload_dir = wp_upload_dir();
		$backup_dir = trailingslashit( $upload_dir['basedir'] ) . self::BACKUP_DIR;
		if ( ! wp_mkdir_p( $backup_dir ) ) {
			return new WP_Error( 'mkdir_failed', 'Kon backup-directory niet aanmaken: ' . $backup_dir );
		}

		// Beveilig directory tegen publieke toegang.
		$htaccess = $backup_dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			@file_put_contents( $htaccess, "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
		}
		$index = $backup_dir . '/index.php';
		if ( ! file_exists( $index ) ) {
			@file_put_contents( $index, "<?php\n// Silence is golden.\n" );
		}

		$filename = sprintf( 'db-prefix-backup-%s.sql', gmdate( 'Ymd-His' ) );
		$filepath = $backup_dir . '/' . $filename;

		$sql  = "-- MCM Security Hardener — DB Prefix Migration Backup\n";
		$sql .= '-- Datum: ' . gmdate( 'c' ) . "\n";
		$sql .= "-- Oude prefix: {$old_prefix}\n";
		$sql .= '-- Hernoemde tabellen: ' . count( $tables ) . "\n";
		$sql .= "--\n-- Voor handmatige rollback: rename tabellen terug en herstel onderstaande rijen.\n\n";

		$sql .= "-- === Hernoemde tabellen ===\n";
		foreach ( $tables as $t ) {
			$sql .= "--   {$t}\n";
		}

		// Backup wp_options row(s).
		$sql .= "\n-- === Wijzigende rijen in {$old_prefix}options ===\n";
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM `{$old_prefix}options` WHERE option_name = %s",
				$old_prefix . 'user_roles'
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$sql .= self::row_to_insert( $old_prefix . 'options', $row );
		}

		// Backup wp_usermeta rows.
		$sql .= "\n-- === Wijzigende rijen in {$old_prefix}usermeta ===\n";
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM `{$old_prefix}usermeta` WHERE meta_key LIKE %s",
				$wpdb->esc_like( $old_prefix ) . '%'
			),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			$sql .= self::row_to_insert( $old_prefix . 'usermeta', $row );
		}

		if ( false === file_put_contents( $filepath, $sql ) ) {
			return new WP_Error( 'backup_write_failed', 'Kon backup-bestand niet schrijven: ' . $filepath );
		}

		return $filepath;
	}

	/**
	 * Bouw een INSERT-statement voor een rij. Gebruikt voor backup-bestand.
	 */
	private static function row_to_insert( $table, array $row ) {
		global $wpdb;
		$cols = [];
		$vals = [];
		foreach ( $row as $col => $val ) {
			$cols[] = "`{$col}`";
			if ( null === $val ) {
				$vals[] = 'NULL';
			} else {
				$vals[] = "'" . esc_sql( $val ) . "'";
			}
		}
		return 'INSERT INTO `' . $table . '` (' . implode( ', ', $cols ) . ') VALUES (' . implode( ', ', $vals ) . ");\n";
	}
}
