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
| **Registratiebescherming** | Honeypot-veld + wegwerpdomein-filter op registratieformulieren (WP + WooCommerce) |
| **HTTP Basic Auth voor staging** | Een laag wachtwoord vóór de hele site, alleen actief op staging-omgevingen |
| **Database prefix-migratie** | Detecteert default `wp_` + biedt veilige random-prefix-migratie incl. SQL-backup en rollback |

### 🔎 Detecteren & rapporteren

| Feature | Wat |
|---|---|
| **WP_DEBUG productie-watchdog** | Detecteert `WP_DEBUG=true` op productie-omgevingen → admin-notice + 1×/24u mail naar de eigenaar |
| **User Audit** | Lijst van alle users met rol Administrator/Editor/Author/Contributor met 1-klik downgrade naar de MCM Klant-rol (mits Site Optimizer aanwezig) of naar Subscriber |
| **WP major-update compat-check** | Bij een aankomende major WP-update: vergelijkt de "Tested up to" van alle actieve plugins en toont per plugin Compatibel / Niet getest / Onbekend |
| **Notifier** | Alle plugin-mails en admin-notices gaan naar het centrale notificatie-adres (default `marco@mcmwebsites.nl`), niet naar de klant |

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
│   ├── class-update-compat-check.php  WP-update plugin-compat tabel
│   ├── class-profiles.php             Basic/Standard/Strict/Staging-profielen
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
