# Software inventory protocol (v1)

What each server package reports about the software the site runs, so the
dashboard's Security check (backend `Sections/CustomerDash/security/securityScan.js`)
can match it against known security holes, and Health → Updates
(`packageUpdates.js`) against the latest release of each: OSV.dev for npm,
Packagist, PyPI, RubyGems, Maven, NuGet and Go packages (the latest releases
from each registry: npm, PyPI, Packagist, RubyGems, Maven Central, NuGet and
the Go module proxy); Wordfence Intelligence and wordpress.org for WordPress
plugins and themes; endoflife.date for the releases and support dates of PHP,
Node.js, Python, Ruby, Java (Eclipse Temurin's dates), .NET, Go and WordPress
(`osReleases.js`, the same feed and cache the operating system's row uses). The `runtime` versions below are read twice over: once as
a security finding when the one a server reports has stopped getting fixes,
and once as an Updates row — with the date its fixes stop — while it still
does.

Clients: the Node package (`sdk/platform-node`), the Python package
(`sdk/platform-python`), the PHP package (`sdk/platform-php`, Composer), the
Ruby, Java, .NET and Go packages (`sdk/platform-ruby`, `sdk/platform-java`,
`sdk/platform-dotnet`, `sdk/platform-go`), the WordPress plugin (`sdk/wordpress-plugin`, plugins, themes and core) and the
build-time reporter (`sdk/report-packages`, for sites with nothing running
server-side: a static build, or Next.js on Vercel or Netlify). The collector
side is `expresscollect/Analytics/inventory.js`.

## Authentication

Like the firewall and file integrity: the site's ID and its secret,
`Authorization: Bearer <secret>`, and a `User-Agent` naming the client and its version.

## When

Once soon after start (within a few minutes, in the background), then every
`every` seconds from the last answer (a day by default). Never in a visitor's
request; never slow the site.

The build-time reporter is the exception: it runs once, during the site's
build, and there is no schedule. A build is the only moment a site with no
server has its packages in one place, and the only moment they change.

## What to list

| client | `ecosystem` | from |
|---|---|---|
| Node | `npm` | The first of `npm-shrinkwrap.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` next to the app's `package.json` (the working directory, or an option). Production packages only. npm: lockfile v2/v3 `packages` (skip `"dev": true`; name from the last `node_modules/` segment, scoped names kept), v1 `dependencies` (an alias's `"npm:real@1.2.3"` version split into name and version); an entry whose `resolved` is git, `file:` or a tarball that isn't a registry's (`/-/name-1.2.3.tgz`) is left out, since its `version` is the package's own. pnpm: lockfile 5.x/6.0 skip `dev: true`; 9.0 has no dev flag, so walk `snapshots` from the importers' `dependencies`/`optionalDependencies`; peer suffixes (`(react@19.0.0)`, `_react@19.0.0`) are not part of the version. yarn (1 and 2+) and bun: walk from the production dependencies (yarn: the project's and each workspace's `package.json`; bun: `workspaces`). `direct` only on the copy the project itself resolves, and on the real name of an alias (`"my-react": "npm:react@^18"` marks `react`). Versions that aren't releases (file:, link:, workspace:, git, tarballs) are left out. The binary `bun.lockb` is not read. |
| Python | `PyPI` | the installed distributions (`importlib.metadata.distributions()`), name as published. |
| PHP | `Packagist` | `composer.lock` (`packages`, not `packages-dev`) in the project root (Laravel `base_path()`, or an option). |
| Ruby (`sitegoose` gem) | `RubyGems` | the gems loaded in the process (Bundler's: what `Gemfile.lock` pins, in the groups the app runs with), `direct` when the Gemfile names the gem; with no Bundler loaded, `Gemfile.lock` next to the app. |
| Java (`com.sitegoose:sitegoose`) | `Maven` | name `groupId:artifactId`, read from each jar's `pom.properties` (also inside Spring Boot fat jars and wars), else from the jar's file name when the group is known, or from a CycloneDX SBOM. |
| .NET (`SiteGoose` NuGet package) | `NuGet` | the app's `deps.json` (what `dotnet publish` and `dotnet run` resolve), `direct` for the packages a project of the site references by name; where a host strips it, the loaded assemblies by their informational version, none marked direct. The shared frameworks (`Microsoft.NETCore.App`, `Microsoft.AspNetCore.App`) are the runtime, not packages. |
| Go (`github.com/sitegoose/sitegoose-go`) | `Go` | the modules compiled into the binary (`runtime/debug.ReadBuildInfo`): name = module path, version without the leading `v` (pseudo-versions such as `0.0.0-20240101120000-abcdef123456` included), a replaced module under its replacement; plus `stdlib` at the Go version, OSV's name for Go itself. |
| WordPress | `wordpress-plugin`, `wordpress-theme` | `get_plugins()` (the slug is the plugin's folder, or the file name without `.php` for single-file plugins; `active`: is it on) and `wp_get_themes()` (the slug is the stylesheet folder). Must-use plugins too. |

`runtime`: the versions the site runs on, as known: `php` (`PHP_VERSION`),
`node` (`process.versions.node`), `python` (`platform.python_version()`),
`ruby` (`RUBY_VERSION`), `java` (the `java.version` property, as it reads:
`21.0.5`, or `1.8.0_392` on Java 8), `dotnet` (`Environment.Version`, `8.0.11`),
`go` (the Go release the binary was built with, `1.23.4`),
`wordpress` (`get_bloginfo('version')`). Leave out what doesn't apply. A
build-time report sends none of it: the build machine's Node is not the site's,
and a static site runs no Node at all, so reporting CI's version would have the
dashboard call an unsupported runtime a problem on a site that has no runtime.

## POST /events/inventory

```json
{
  "site_id": "<id>",
  "host": "web-1",
  "at": "2026-10-18T12:00:00.000Z",
  "runtime": { "php": "8.1.27", "wordpress": "6.4.3" },
  "packages": [
    { "ecosystem": "wordpress-plugin", "name": "contact-form-7", "version": "5.8.4", "active": true },
    { "ecosystem": "Packagist", "name": "guzzlehttp/guzzle", "version": "7.8.1", "direct": true }
  ],
  "truncated": false
}
```

- `host`: the server's name, as for file integrity. The build-time reporter
  sends `build` unless told otherwise.
- `source`: optional, `build` for a report sent from a site's build rather
  than by something running on a server; anything else (and absent) means
  `server`. It decides how long the report counts: a server that stops
  reporting is telling us nothing about today and ages out after 30 days,
  while a build report stays true until the next deploy, however long that is,
  so it never expires (`backend/.../packageUpdates.js`). The collector never
  accepts a third value, but `site_inventory` holds one: `page`, under the
  host `your website`, written by the backend from the weekly site check's
  read of the home page (`backend/.../security/pageStack.js`). The space in
  that host is what keeps any client's report from landing on it.
- `packages`: at most 5,000; `truncated: true` past that. `ecosystem` is one
  of `npm`, `PyPI`, `Packagist`, `RubyGems`, `Maven`, `NuGet`, `Go`,
  `wordpress-plugin`, `wordpress-theme`, spelt as OSV spells it (anything else
  is dropped). `name` as published, with no whitespace, 214 characters at
  most (`/` and `:` are fine: `github.com/gin-gonic/gin`,
  `org.springframework:spring-core`). `version` as the lock file or the
  software gives it, without a leading `v`: letters, digits and `.+_~:-`, so
  `1.2.3-SNAPSHOT`, `5.3.9.RELEASE` and `24.0.7+incompatible` are kept.
- `active`: WordPress only; inactive plugins still count (their files can
  still be reached), but say so.
- `direct`: optional, `true` for a package the site asks for by name in its
  own manifest (`package.json` `dependencies`/`optionalDependencies`,
  `composer.json` `require`, `requirements.txt`, the `Gemfile`, a `.csproj`
  `PackageReference`, a `pom.xml` dependency), as opposed to one pulled in
  as a dependency of those. On npm that is the one copy at the top of
  `node_modules`: an older copy nested under another package keeps its own
  version whatever the site installs, so it stays unmarked even when the site
  asks for that name. A client that can't tell leaves it off every
  package; the dashboard then shows the whole list rather than guessing. Never
  sent for WordPress plugins and themes, which are always a choice someone
  made. This is what keeps Health → Updates down to the few dozen packages
  an owner picked instead of the thousand under them.

The answer (`200`): `{ "v": 1, "enabled": true, "every": 86400 }`.
`enabled: false`: the owner turned the module (`inventory`) off on the
dashboard; ask again after `every` seconds.

## Must

- Names and versions only: never file contents, paths outside the project, or
  settings.
- A missing lock file is not an error: send what there is (the runtime alone).

### Dashboard-requested inventory refresh

The Updates check can set `user_sites.inventory_refresh` with an opaque 24-hex
`id` and server timestamp `at`. The authenticated platform config includes
`inventory_refresh: { id, at }` (or null when inventory is disabled). This field
participates in the config ETag. Node clients supporting this extension reread
their production lockfile on the next config poll and include `refresh_id` in
the inventory POST. The collector stores that acknowledgement per host.

A client handles each request once after successful delivery, retries failed
delivery on subsequent config polls, and ignores requests older than two
minutes. It must respect the inventory module switch. This does not install
packages or restart the application; the lockfile still describes dependency
versions, not proof of versions loaded in a running process.

The dashboard polls the check endpoint with `refresh_id`, waiting up to 90
seconds for each live inventory host before checking releases. Missing
acknowledgements are explicitly reported as stale; older clients and other
language integrations that do not implement this extension keep their usual
report schedule. Build inventories refresh at deployment time. Registry results
retain their existing cache policy.

Deploy the backend, collector, and frontend changes together, and release/install
the updated `analytics-platform` Node package on monitored servers to enable
on-demand reports. Existing installed SDK releases do not gain this behavior
from a dashboard deployment alone.
