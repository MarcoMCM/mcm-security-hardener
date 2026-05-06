<?php
/**
 * Runtime security hooks: version hiding, robots blackhole, bad URL blocking,
 * bot blocking, malicious content filtering, PHP 404 blocking.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class MCM_Runtime_Security {

	private $settings = [];

	public function __construct() {
		$this->settings = get_option( 'mcm_security_settings', [] );

		// Suppress PHP warnings/notices on the frontend when no_debug_display is on.
		// Catches warnings that PHP emits before WP's own debug-display logic kicks in
		// (zoals wp-login.php's $user_login warning op PHP 8+).
		if ( ! empty( $this->settings['no_debug_display'] ) ) {
			@ini_set( 'display_errors', '0' );
		}

		// Remove WordPress version.
		if ( ! empty( $this->settings['hide_wp_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', [ $this, 'remove_version_query' ], 9999 );
			add_filter( 'script_loader_src', [ $this, 'remove_version_query' ], 9999 );
		}

		// Remove PHP version header.
		if ( ! empty( $this->settings['hide_php_version'] ) ) {
			add_action( 'send_headers', [ $this, 'remove_php_header' ] );
		}

		// Robots.txt blackhole.
		if ( ! empty( $this->settings['robots_blackhole'] ) ) {
			add_filter( 'robots_txt', [ $this, 'add_blackhole' ], 99, 2 );
		}

		// Early request filtering (runs before WordPress loads fully).
		add_action( 'init', [ $this, 'early_request_filter' ], 0 );
	}

	/**
	 * Remove ?ver= from enqueued scripts and styles.
	 */
	public function remove_version_query( $src ) {
		if ( strpos( $src, 'ver=' ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Remove X-Powered-By header.
	 */
	public function remove_php_header() {
		if ( function_exists( 'header_remove' ) ) {
			header_remove( 'X-Powered-By' );
		}
	}

	/**
	 * Add blackhole trap to robots.txt.
	 */
	public function add_blackhole( $output, $public ) {
		$trap_paths = [
			'/mcm-honeypot/',
			'/admin-secret/',
			'/backup/',
			'/db-backup/',
			'/old-site/',
		];

		$output .= "\n# MCM Security Blackhole - trap for bad bots\n";
		foreach ( $trap_paths as $path ) {
			$output .= "Disallow: {$path}\n";
		}

		return $output;
	}

	/**
	 * Early request filtering: bots, referers, URLs, PHP 404s.
	 */
	public function early_request_filter() {
		// Skip admin and AJAX.
		if ( is_admin() || wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
		$referer    = isset( $_SERVER['HTTP_REFERER'] ) ? $_SERVER['HTTP_REFERER'] : '';
		$request    = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';

		// Block bad user agents.
		if ( ! empty( $this->settings['block_bad_user_agents'] ) && $this->is_bad_user_agent( $user_agent ) ) {
			$this->block_request( 'Bad user agent' );
		}

		// Block fake SEO bots.
		if ( ! empty( $this->settings['block_fake_seo_bots'] ) && $this->is_fake_seo_bot( $user_agent ) ) {
			$this->block_request( 'Fake SEO bot' );
		}

		// Block AI bots.
		if ( ! empty( $this->settings['block_ai_bots'] ) && $this->is_ai_bot( $user_agent ) ) {
			$this->block_request( 'AI bot' );
		}

		// Block bad referers.
		if ( ! empty( $this->settings['block_bad_referers'] ) && $this->is_bad_referer( $referer ) ) {
			$this->block_request( 'Bad referer' );
		}

		// Block malicious content in URLs.
		if ( ! empty( $this->settings['block_bad_url_content'] ) && $this->has_malicious_content( $request ) ) {
			$this->block_request( 'Malicious URL' );
		}

		// Block disallowed URLs (honeypot, scanner paths).
		if ( ! empty( $this->settings['block_bad_urls'] ) && $this->is_blocked_url( $request ) ) {
			$this->block_request( 'Blocked URL' );
		}

		// Block 404 on PHP files.
		if ( ! empty( $this->settings['block_php_404'] ) ) {
			add_action( 'template_redirect', [ $this, 'block_php_404' ] );
		}
	}

	/**
	 * Check for bad/empty/malicious user agents.
	 */
	private function is_bad_user_agent( $ua ) {
		if ( empty( $ua ) ) {
			return true;
		}

		$bad_agents = [
			'sqlmap', 'nikto', 'nessus', 'openvas', 'w3af', 'nmap',
			'masscan', 'zgrab', 'gobuster', 'dirbuster', 'wpscan',
			'havij', 'acunetix', 'appscan', 'netsparker', 'qualys',
			'webinspect', 'arachni', 'burpsuite', 'owasp',
			'python-requests/', 'python-urllib', 'go-http-client',
			'curl/', 'wget/', 'libwww-perl', 'lwp-trivial',
			'scrapy', 'mechanize', 'httpclient', 'java/',
			'winhttp', 'sitesucker', 'webcopier', 'httrack',
			'harvest', 'emailmagnet', 'emailsiphon', 'emailwolf',
			'extractorpro', 'webbandit', 'webzip', 'teleport',
		];

		$ua_lower = strtolower( $ua );
		foreach ( $bad_agents as $bad ) {
			if ( false !== strpos( $ua_lower, $bad ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Detect fake SEO bots (claiming to be Google/Bing but not from their IPs).
	 */
	private function is_fake_seo_bot( $ua ) {
		$ua_lower = strtolower( $ua );

		$seo_bots = [
			'googlebot'     => [ '.googlebot.com', '.google.com' ],
			'bingbot'       => [ '.search.msn.com' ],
			'yandexbot'     => [ '.yandex.com', '.yandex.ru', '.yandex.net' ],
			'baiduspider'   => [ '.baidu.com', '.baidu.jp' ],
		];

		foreach ( $seo_bots as $bot_name => $valid_hosts ) {
			if ( false !== strpos( $ua_lower, $bot_name ) ) {
				$ip   = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
				$host = gethostbyaddr( $ip );

				if ( $host === $ip ) {
					return true; // No reverse DNS = fake.
				}

				$is_valid = false;
				foreach ( $valid_hosts as $valid_host ) {
					if ( substr( $host, -strlen( $valid_host ) ) === $valid_host ) {
						$is_valid = true;
						break;
					}
				}

				if ( ! $is_valid ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check for AI crawler bots.
	 */
	private function is_ai_bot( $ua ) {
		$ai_bots = [
			'gptbot', 'chatgpt-user', 'oai-searchbot',
			'claudebot', 'claude-web', 'anthropic-ai',
			'ccbot', 'google-extended',
			'bytespider', 'amazonbot',
			'facebookbot', 'meta-externalagent',
			'cohere-ai', 'diffbot', 'perplexitybot',
			'youbot', 'applebot-extended',
			'omgili', 'omgilibot',
			'friendlycrawler', 'timpibot',
			'ia_archiver', 'archive.org_bot',
			'isscyberriskcrawler',
			'petalbot',
			'semrushbot',
		];

		$ua_lower = strtolower( $ua );
		foreach ( $ai_bots as $bot ) {
			if ( false !== strpos( $ua_lower, $bot ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check for bad referers.
	 */
	private function is_bad_referer( $referer ) {
		if ( empty( $referer ) ) {
			return false;
		}

		// Built-in spam referers.
		$built_in = [
			'semalt.com', 'buttons-for-website.com', 'darodar.com',
			'priceg.com', 'blackhatworth.com', 'hulfingtonpost.com',
			'kambasoft.com', 'screentoolkit.com', 'o-o-6-o-o.com',
		];

		// User-defined referers.
		$custom_list = ! empty( $this->settings['bad_referers_list'] ) ? $this->settings['bad_referers_list'] : '';
		$custom      = array_filter( array_map( 'trim', explode( "\n", $custom_list ) ) );

		$all_bad     = array_merge( $built_in, $custom );
		$ref_lower   = strtolower( $referer );

		foreach ( $all_bad as $bad ) {
			$bad = strtolower( trim( $bad ) );
			if ( ! empty( $bad ) && false !== strpos( $ref_lower, $bad ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check for malicious content in URL (SQL injection, XSS, path traversal, etc.).
	 */
	private function has_malicious_content( $request ) {
		$patterns = [
			// SQL injection.
			'/(\%27)|(\')|(\-\-)|(\%23)|(#)/i',
			'/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i',
			'/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i',
			'/union\s+(all\s+)?select/i',
			// XSS.
			'/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/i',
			'/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/i',
			'/javascript\s*:/i',
			'/vbscript\s*:/i',
			'/on(error|load|click|mouse|focus|blur)\s*=/i',
			// Path traversal.
			'/\.\.\//i',
			'/\.\.\\\/i',
			'/(etc\/passwd|proc\/self|boot\.ini)/i',
			// PHP wrappers / RFI.
			'/php:\/\/input/i',
			'/php:\/\/filter/i',
			'/data:\/\/text/i',
			'/expect:\/\//i',
			// WordPress specific.
			'/wp-config\.php\.(bak|old|save|txt|tmp|orig)/i',
		];

		$full_uri = $request;
		if ( ! empty( $_SERVER['QUERY_STRING'] ) ) {
			$full_uri .= '?' . $_SERVER['QUERY_STRING'];
		}

		$decoded = urldecode( $full_uri );

		foreach ( $patterns as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check for blocked URLs (honeypot, scanner paths).
	 */
	private function is_blocked_url( $request ) {
		$request_lower = strtolower( $request );

		$blocked = [
			// Honeypot trap.
			'/mcm-honeypot/', '/admin-secret/',
			// Common attack paths.
			'/.env', '/.git/', '/.svn/', '/.htpasswd',
			'/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php.save',
			'/wp-config.txt', '/wp-config.php~',
			// Known shells/backdoors.
			'/eval-stdin.php', '/wp-plain.php', '/wso.php',
			'/shell.php', '/c99.php', '/r57.php', '/alfa.php',
		];

		foreach ( $blocked as $pattern ) {
			if ( false !== strpos( $request_lower, $pattern ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Block 404 requests on PHP files (prevent scanning).
	 */
	public function block_php_404() {
		if ( ! is_404() ) {
			return;
		}

		$request = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
		$path    = wp_parse_url( $request, PHP_URL_PATH );

		if ( $path && preg_match( '/\.php$/i', $path ) ) {
			status_header( 403 );
			nocache_headers();
			exit;
		}
	}

	/**
	 * Block a request with 403.
	 */
	private function block_request( $reason = '' ) {
		status_header( 403 );
		nocache_headers();
		header( 'X-MCM-Block-Reason: ' . sanitize_text_field( $reason ) );
		exit;
	}
}
