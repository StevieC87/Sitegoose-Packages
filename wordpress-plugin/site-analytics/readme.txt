=== Site Analytics ===
Requires at least: 5.6
Requires PHP: 7.4
Stable tag: 2.5.2
License: MIT

Your analytics in WordPress: the tracker, WooCommerce orders sent from your server, a firewall, error monitoring and logins.

== Description ==

* **Tracker:** added to every page for you, locked to one version by its fingerprint (an integrity hash), so the browser runs that file and nothing else, even if someone took over the server it comes from. New versions come in on their own within a day, and only when they carry our signature, made with a key that is never on a server.
* **Ad blockers:** the tracker is served from your own domain, so blockers have no address or name of ours to recognise and your visitors are counted. Nothing to set up: the plugin is already running on your domain, so it does the forwarding itself. If it can't on your server, it says so and loads the tracker from us instead.
* **WooCommerce:** each paid order is sent from your server as a purchase, with the order number, total, currency, coupon and first product, linked to the visit. Refunds too. Ad blockers can't stop it.
* **Firewall:** block addresses and ranges, rate-limit visitors, and turn away known criminal networks (Spamhaus DROP) and addresses other sites reported. Start in monitor mode.
* **Attack patterns:** besides blocking addresses, the firewall checks every request against the attack patterns your dashboard sends — path traversal, PHP in the uploads folder, known web shell names, scanners that name themselves, SQL in a parameter — so an attack is turned away before WordPress runs the plugin it aims at. A plugin with a known hole stays safe until you update it. Patterns a real visitor might trip only watch until you promote them (Security → Firewall → Attack patterns).
* **Browser check:** with flood protection's browser check on in your dashboard (paid plans), a visitor's first page each day is a small page that sets a cookie with JavaScript and reloads into your site. It stops cheap floods — scripts that fetch your pages without running JavaScript — not a real or headless browser, and it doesn't protect forms or logins. Only page loads are checked: never a form or login post, ajax, the REST API, WP-Cron, feeds read without asking for a web page, the paths your dashboard skips, your allowed addresses, or the search engines' and AI crawlers' published addresses. Logged-in users see it too (one reload a day): the check runs before WordPress knows who is logged in. Pages a caching plugin serves before WordPress loads aren't checked. The cookie, `__sg_pass`, holds a day number and a signature of the visitor's address, lasts a day and identifies no one: it is strictly necessary for security, so it needs no consent.
* **Crawlers & AI bots:** which search engines and AI systems read your pages — GPTBot, ClaudeBot, ChatGPT-User, PerplexityBot, Googlebot and the rest — page by page, in Off-site → Crawlers. Your tracker cannot see any of them, because crawlers don't run JavaScript, and a crawler using Googlebot's name without its address is reported as what it is.
* **Database queries:** with Server speed, every query's time, grouped by page type, in Health → Server speed → Queries: which page runs forty small queries, and which one slow one. Values are taken out on your server before anything is counted, so no customer data leaves it. On activation the plugin writes a `wp-content/db.php` that times each query (only when there is none already and the folder can be written; it is removed on deactivation). Otherwise it uses WordPress's own query log, which misses the queries before plugins load and can't tell a failed query. `define('SITE_ANALYTICS_QUERIES', false);` in wp-config.php turns it off. Redis commands aren't timed: an object-cache drop-in has no hook a command passes through.
* **Calls to other sites:** with Server speed, how long each page type waited on the services WordPress called — a payment provider, a mail API, wordpress.org's update checks — by the site it called, with how many failed (no answer, or a server error), in Health → Server speed → Calls. Only the site's name is sent, never the address, its query string or what was sent. A call that doesn't wait for its answer isn't counted, and WordPress reads the whole answer before it returns, so the time includes it. `define('SITE_ANALYTICS_CALLS', false);` in wp-config.php turns it off.
* **Error monitoring:** PHP errors and crashes in your Errors report, next to the browser's.
* **Logins:** links a visit to the WordPress user ID that logs in (optional).
* **Set-up checks:** once a day the plugin looks at how your site is set up and the dashboard says what to change: code editable from wp-admin, debug output shown to visitors, example security keys still in wp-config.php, registration open with a privileged role, an account called "admin", no second step at login, PHP showing errors, files anyone on the server can write — and files in your web folder that shouldn't be there (a database dump, a `.env`, a `wp-config.php.bak`), which the dashboard then tries to download from the internet to tell you whether they really are public. It also reports who has administrator rights (login names only) and your scheduled jobs, so a new administrator or a job with no plugin behind it is alerted within minutes. It only reads: the plugin changes nothing, and never sends a file's contents. Run it now with `wp site-analytics posture`.
* **File monitoring:** every hour your site's code is compared with the version you accepted. Changed files, backdoors (like PHP in your uploads folder), core files that differ from WordPress.org's and defaced pages are alerted. Updates WordPress makes itself are taken in. After a deploy: `wp site-analytics accept-files`.

Rules, reports and module switches are in your analytics dashboard. Your site never waits on our service: everything is sent after the page has gone out, and the firewall checks requests against rules kept on your server. If our service can't be reached, every request passes.

The rate limit needs the APCu PHP extension or a persistent object cache (Redis, Memcached).

== Installation ==

1. Upload the plugin and activate it. It replaces the tracker-only Site Analytics plugin if you have it.
2. Settings → Site Analytics: enter your site ID, collector URL and site secret (Site settings in your dashboard).
   The collector URL must be https on a public address (for one on your own server or network, add `define('SITE_ANALYTICS_PRIVATE_ENDPOINT', true);` to wp-config.php). On a network, only a network administrator can change it.
3. If your site is behind Cloudflare or a load balancer, choose it under Proxy.
