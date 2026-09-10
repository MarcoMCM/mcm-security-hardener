# MCM Security Hardener

WordPress security-hardening plugin voor de klantensites van **MCM Websites**. Verzamelt WordPress-best-practices (SecuPress-stijl) plus MCM-specifieke automatiseringen achter één centraal admin-paneel.

> **Interne plugin** — niet bedoeld voor publieke distributie of forks.
> Zie [LICENSE](LICENSE).

---

## Wat doet het?

### 🛡️ Voorkomen (security-hardening)

| Feature | Wat |
|---|---|
| **wp-config / .htaccess hardening** | `DISALLOW_FILE_EDIT`, blokkade van PHP-execution in `/uploads/`, `XML-RPC` dicht, geen directory listing, etc. |
| **Plugin/theme lockdown** | Voorkomt dat klant-admins onverwacht plugins installeren of de theme-editor gebruiken |
| **Custom login URL** | Verbergt `/wp-login.php` achter een eigen slug |
| **Human Verification** | CSS-checkbox die zichzelf aanvinkt; blokkeert bots die direct submitten — werkt op login, register, lost-password én op WooCommerce my-account |
| **Registratiebescherming** | Honeypot-veld + wegwerpdomein-filter op registratieformulieren (WP + WooCommerce), plus blokkade van gereserveerde gebruikersnamen (`admin`, `root`, `beheerder`, …) via WordPress' eigen `illegal_user_logins` — dekt ook WooCommerce-registratie en handmatig aanmaken |
| **HTTP Basic Auth voor staging** | Een laag wachtwoord vóór de hele site, alleen actief op staging-omgevingen |
| **Gebruikersnamen afschermen** | Zet de vier routes dicht waarlangs WordPress logins weggeeft (`?author=1`, REST `/wp/v2/users`, oEmbed, users-sitemap) + een generieke loginfout, zodat een mislukte login niet verklapt of de gebruikersnaam bestaat. Auteursarchieven blijven werken |
| **Archieven in uploads blokkeren** | Optionele `.htaccess`-regel: 403 op directe download van zip/rar/7z/tar.gz/sql/bak uit `/uploads/`, met uitzondering van `woocommerce_uploads` en AVG-exports |
| **Database prefix-migratie** | Detecteert default `wp_` + biedt veilige random-prefix-migratie incl. SQL-backup en rollback |

### 🔎 Detecteren & rapporteren

| Feature | Wat |
|---|---|
| **WP_DEBUG productie-watchdog** | Detecteert `WP_DEBUG=true` op productie-omgevingen → admin-notice + 1×/24u mail naar de eigenaar |
| **File Exposure Scanner** | Wekelijkse filesystem-scan op drie niveaus: **webroot** (info.php/phpinfo(), `.env`, wp-config-backups, SQL-dumps, Adminer, phpMyAdmin), **uploads recursief** (archieven en dumps — vindt de vergeten plugin-zip in `uploads/2023/01/`) en **boven de webroot** (achtergelaten `.bak`/`.tar.gz`/scripts). Herkent een deny-`.htaccess` als afscherming, dus een correct afgeschermde backup-map is geen lek. Severity-tiers, mail alleen bij HIGH/MEDIUM, detectie-only |
| **Anomaly Scanner** | Wekelijkse scan van root + `wp-content` (top-level) op onbekende bestanden/mappen via whitelist, plús baseline-diff (geen whitelist — verschilt per site) voor `wp-content/plugins`, `wp-content/mu-plugins` én PHP-type WPCode-snippets in de database. Severity-tiers (HIGH = los `.php`/shell, nieuw mu-plugin-item of nieuwe PHP-snippet, MEDIUM = onbekende root-map of nieuw item in `plugins/`, LOW = info). Mailt alleen bij HIGH/MEDIUM, detectie-only |
| **New Admin Alert** | Real-time mail zodra een account de rol Administrator krijgt (hook `set_user_role`) — ongeacht of dat via het registratieformulier, wp-admin, wp-cli of een script gaat dat WordPress' eigen user-API gebruikt. MCM-eigenaars uitgezonderd. Vangt geen rechtstreekse database-writes buiten die API om |
| **Snippet Monitor** | Real-time mail bij elke nieuwe of gewijzigde WPCode/Insert Headers and Footers-snippet (hook `save_post_wpcode`), ongeacht publish/draft-status — code-snippets zijn onzichtbaar voor bestandsscans, want ze staan in de database. MCM-eigenaars uitgezonderd. No-op zonder die plugin |
| **Core Integrity Scanner** | Wekelijkse checksum-vergelijking van élk WordPress-kernbestand (root, `wp-admin/`, `wp-includes/`) tegen de officiële versie van WordPress.org — zelfde principe als `wp core verify-checksums`, automatisch. Elke afwijking of ontbrekend bestand is HIGH, direct gemaild. Detectie-only; de mail bevat het herstel-commando |
| **PHP Error Watcher** | Uurlijkse monitor van `debug.log`; mailt direct bij fatal/parse. Warning/deprecated tellen alleen mee voor de drempel als ze uit eigen code komen (core/systeem = ruis, alarmeert niet). Extra gevoelig 7 dagen na een PHP-versie-wissel |
| **Toolbar-snelkoppeling** | "MCM Security" in de WP-adminbar (front + admin, alleen admins); kleurt rood als de anomalie-scan uit staat, met 1-klik aan/uit-toggle |
| **User Audit** | Lijst van alle users met rol Administrator/Editor/Author/Contributor met 1-klik downgrade naar de MCM Klant-rol (mits Site Optimizer aanwezig) of naar Subscriber |
| **Risico op gebruikersnamen** | Voor accounts met **verhoogde rechten**: vlagt voorspelbare logins (`admin`, `test`, de domeinnaam van de site, …) en profielen waarvan de weergavenaam gelijk is aan de login — die staat anders onder elke post. Weergavenaam met 1 klik los te maken; hernoemen doet de plugin bewust niet. Klantaccounts met zo'n naam worden alleen gesignaleerd, met doorverwijzing naar de nep-/botaccountmodule van de Site Optimizer |
| **WP major-update compat-check** | Bij een aankomende major WP-update: vergelijkt de "Tested up to" van alle actieve plugins en toont per plugin Compatibel / Niet getest / Onbekend |
| **Notifier** | Alle plugin-mails en admin-notices gaan naar het centrale notificatie-adres (default `marco@mcmwebsites.nl`), niet naar de klant |
| **Markeer als veilig** | Knop per bevindingsrij in File Exposure Scanner en Anomaly Scanner — verwijdert 'm permanent uit tabel én mail, tot je 'm terugzet via "Genegeerde bevindingen" onderaan de tabel. Identificatie op het volledige pad, dus een normale update van hetzelfde bestand zet de markering niet stilzwijgend weer aan |

### 🚀 Distributie

- **GitHub self-update**: de plugin pakt nieuwe releases automatisch op via [`plugin-update-checker`](https://github.com/YahnisElsts/plugin-update-checker). Geen wp.org-account nodig, geen handmatig verspreiden. Beheer via MainWP werkt zoals bij elke andere WP-plugin.

---

## Installatie

1. Download de laatste zip via de [Releases-pagina](https://github.com/MarcoMCM/mcm-security-hardener/releases)
2. WP-admin → **Plugins → Nieuwe plugin → Bestand uploaden** (of via MainWP voor meerdere sites tegelijk)
3. Activeer
4. **Tools → MCM Security** → kies een profiel (Basic / Standard / Strict / Staging) of stel handmatig in

Toekomstige updates verschijnen automatisch in WP-admin (Dashboard → Updates) en in MainWP.

---

## Configuratie

### Owner-detectie

Een "MCM-eigenaar" omzeilt de plugin/theme-lockdown en ziet alle interne admin-notices. Drie manieren om iemand als owner te herkennen — gerangschikt op preferentie:

**1. `MCM_SECURITY_OWNERS`-constante** in `wp-config.php`:
```php
define( 'MCM_SECURITY_OWNERS', [ 'beheerder_login_1', 'beheerder_login_2' ] );
```

**2. Email-match** (sinds v1.11.0): een ingelogde user met email gelijk aan `MCM_Notifier::notify_email()` (default `marco@mcmwebsites.nl`) telt automatisch als owner — handig op sites zonder de constante.

**3. Filter** voor maatwerk:
```php
add_filter( 'mcm_security_is_owner', function( $is_owner, $user ) {
    return $is_owner || str_ends_with( $user->user_email, '@mcmwebsites.nl' );
}, 10, 2 );
```

### Optionele constanten

```php
// Email-adres waar alle plugin-notificaties heen gaan
define( 'MCM_SECURITY_NOTIFY_EMAIL', 'marco@mcmwebsites.nl' );

// Schakel de WP_DEBUG productie-watchdog uit (bv. op dev-omgevingen waar WP_DEBUG bewust aan staat)
define( 'MCM_SECURITY_DISABLE_DEBUG_WATCHDOG', true );
```

### Beschikbare filters

| Filter | Doel |
|---|---|
| `mcm_security_owners` | Owners-lijst programmatisch aanvullen |
| `mcm_security_is_owner` | Custom owner-bepaling per user |
| `mcm_security_notify_email` | Notificatie-email override |
| `mcm_blocked_email_domains` | Wegwerpdomein-lijst uitbreiden |
| `mcm_security_debug_watchdog_enabled` | WP_DEBUG-watchdog uitschakelen |
| `mcm_anomaly_root_whitelist` | Bekende root-items voor de anomalie-scan (lowercase namen) |
| `mcm_anomaly_wpcontent_whitelist` | Bekende `wp-content`-items voor de anomalie-scan |
| `mcm_exposure_archive_regex` | Welke extensies gelden als archief/dump in de uploads- en boven-webroot-scan |
| `mcm_exposure_uploads_skip_dirs` | Mapnamen die de uploads-scan overslaat (default: `woocommerce_uploads` + cache-mappen) |
| `mcm_security_risky_login_names` | Gebruikersnamen die als voorspelbaar gelden (default: `admin` & co + de domeinnaam) |
| `mcm_security_reserved_logins` | Gebruikersnamen die geweigerd worden bij registratie (harde lijst, zonder de domeinnaam) |
| `mcm_php_error_watcher_own_paths` | Pad-fragmenten die als "eigen code" gelden voor de error-drempel |
| `mcm_php_error_watcher_max_read_bytes` | Max bytes per check uit `debug.log` (default 1 MiB) |

---

## Architectuur

Elke feature is een eigen class in `includes/`. Bootstrap in `mcm-security-hardener.php`.

```
mcm-security-hardener/
├── mcm-security-hardener.php          ← Bootstrap, laadt alle classes
├── changelog.txt
├── README.md
├── LICENSE
├── includes/
│   ├── class-admin-page.php           Tools → MCM Security UI
│   ├── class-wpconfig-manager.php     Schrijft constants naar wp-config.php
│   ├── class-htaccess-manager.php     Schrijft regels naar .htaccess
│   ├── class-lockdown-manager.php     Plugin/theme lockdown + owner-detectie
│   ├── class-login-url-manager.php    Custom login slug
│   ├── class-human-verification.php   Anti-bot via CSS-checkbox
│   ├── class-registration-protection.php  Honeypot + wegwerpdomein-filter
│   ├── class-basic-auth.php           HTTP Basic Auth voor staging
│   ├── class-staging-detector.php     Productie vs staging detectie
│   ├── class-runtime-security.php     User-agent / referer / URL-filtering
│   ├── class-db-prefix-manager.php    Random DB-prefix migratie + backup
│   ├── class-debug-watchdog.php       WP_DEBUG productie-detector
│   ├── class-user-audit.php           Users met verhoogde rechten
│   ├── class-new-admin-alert.php      Real-time mail bij nieuw administrator-account
│   ├── class-update-compat-check.php  WP-update plugin-compat tabel
│   ├── class-backend-access.php       Skip email-confirm + non-admin backend-block
│   ├── class-file-exposure-scanner.php  Scan op blootgestelde bestanden (webroot + uploads + boven webroot)
│   ├── class-user-enumeration.php       Gebruikersnamen afschermen (author/REST/oEmbed/sitemap/loginfout)
│   ├── class-anomaly-scanner.php      Scan op vreemde bestanden/mappen (whitelist + plugin-/snippet-baseline-diff)
│   ├── class-snippet-monitor.php      Real-time mail bij nieuwe/gewijzigde WPCode-snippet
│   ├── class-core-integrity-scanner.php  Checksum-vergelijking kernbestanden vs. WordPress.org
│   ├── class-admin-bar.php            Toolbar-snelkoppeling + scan aan/uit-toggle
│   ├── class-php-error-watcher.php    debug.log-monitor met herkomst-filtering
│   ├── class-profiles.php             Basic/Standard/Strict/Staging-profielen
│   ├── class-finding-ignore.php        "Markeer als veilig" — gedeelde ignore-lijst
│   └── class-notifier.php             Centrale email/notice-helper
└── vendor/plugin-update-checker/      GitHub self-update (YahnisElsts/PUC v5)
```

---

## WooCommerce-compatibiliteit

Sinds v1.12 (Registratiebescherming) en v1.13 (Human Verification fix) draaien de anti-bot-features ook op de WooCommerce my-account formulieren, niet alleen op `wp-login.php`. Hooks: `woocommerce_login_form`, `woocommerce_register_form`, `woocommerce_lostpassword_form`.

---

## Verschil met Site Optimizer

| Plugin | Verantwoordelijk voor |
|---|---|
| **MCM Security Hardener** (deze) | **Voorkomen** — hardening, lockdown, anti-bot, monitoring |
| **MCM Site Optimizer** | **Opruimen** — database-cleanup, MCM Klant rol, dashboard-widgets |

Beide kunnen los van elkaar draaien. Sommige features werken samen — bv. de User Audit downgradet bij voorkeur naar de MCM Klant-rol uit Site Optimizer.

---

## Changelog

Zie [changelog.txt](changelog.txt) voor de versie-historie.

---

## License

Internal use only — Copyright © MCM Websites. Zie [LICENSE](LICENSE) voor de details.

---

Vragen of toegang nodig? Stuur een mail naar **marco@mcmwebsites.nl**.
