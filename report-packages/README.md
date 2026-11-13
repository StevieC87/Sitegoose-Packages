# analytics-report-packages

Reports your project's packages to your analytics dashboard once per build, so
**Health → Updates** can tell you which ones have a newer release.

For any JavaScript front end with a lock file:

- a static build (Vite, Astro, Gatsby…),
- Next.js, Nuxt or SvelteKit on Vercel or Netlify, where nothing lives between
  requests and the lock file isn't in the deployment,
- a separate front end on your own server, beside a backend that has its own
  `package.json`. A server package installed in the backend reads only the
  backend's lock file, so the front end's packages need this.

If your whole site is one Node, PHP or Python server, the server package for
your language already reports it, daily, and this isn't needed.

## Add it to your build

One line on the end of whatever you already run.

**package.json**

```json
"scripts": {
  "build": "vite build && npx analytics-report-packages"
}
```

**Vercel or Netlify**, in the Build command box:

```
npm run build && npx analytics-report-packages
```

**GitHub Actions**

```yaml
- run: npm run build
- run: npx analytics-report-packages
  env:
    ANALYTICS_SITE_ID: ${{ secrets.ANALYTICS_SITE_ID }}
    ANALYTICS_SECRET: ${{ secrets.ANALYTICS_SECRET }}
    ANALYTICS_ENDPOINT: ${{ secrets.ANALYTICS_ENDPOINT }}
```

**Your own server**, in `package.json`, so every `npm run build` reports:

```json
"scripts": {
  "build": "next build",
  "postbuild": "analytics-report-packages --host frontend"
}
```

with `npm install --save-dev analytics-report-packages`.

Then set three values. Health → Updates in your dashboard shows all three with
copy buttons. Put them in your CI's environment or secret store, or in a `.env`
file beside the lock file that git ignores: it reads `.env`, `.env.production`,
`.env.local` and `.env.production.local` itself (a later one wins, a real
environment variable wins over all of them), and takes only these keys from
them.

| | |
|---|---|
| `ANALYTICS_SITE_ID` | The site's ID |
| `ANALYTICS_SECRET` | The site's secret (`ANALYTICS_SITE_SECRET`, the server packages' name for it, works too). **A secret — your CI's secret store or a git-ignored `.env`, never committed.** |
| `ANALYTICS_ENDPOINT` | Your collector's address |

## It will not break your build

No network, wrong key, collector down, no lock file: it says so on one line and
exits 0. A lock file it can't parse is passed over for the next one, and a
broken `package.json` only means none of the packages are marked as yours. Nothing about your deploy depends on our reporting working.

Pass `--strict` if you want the opposite.

## What it sends

The names and versions in your lock file, production packages only, and
which of them `package.json` asks for by name — that last part is what keeps
the dashboard showing the few dozen packages you chose instead of the several
hundred underneath them.

It reads whichever lock file your package manager writes, the first of these
it finds:

| Lock file | Written by |
|---|---|
| `npm-shrinkwrap.json`, `package-lock.json` | npm (the shrinkwrap first, as npm itself prefers it) |
| `pnpm-lock.yaml` | pnpm 7 and later (lockfile 5.x, 6.0 and 9.0) |
| `yarn.lock` | yarn 1, and yarn 2 and later |
| `bun.lock` | bun 1.2 and later |

`yarn.lock` doesn't say which packages are only for development, so yarn
projects need `package.json` beside it: the production packages are the ones
its `dependencies` and `optionalDependencies` lead to, and each workspace's
too (yarn 2+ lists the workspaces in the lock file; for yarn 1 they come from
`workspaces` in `package.json`, written as a folder or `folder/*`). bun's older binary
`bun.lockb` can't be read; `bun install --save-text-lockfile` writes `bun.lock`
beside it.

It sends nothing else. Not your code, not your environment, not the build
machine's Node version (a static site runs no Node, and your CI's version
isn't your site's).

Check before you trust it:

```sh
npx analytics-report-packages --dry-run
```

## Why the build and not a schedule

A static site has no server, so there is nothing to report from. The build is
the only moment the packages exist in one place — and the only moment they
change, so once per deploy is exactly right. The dashboard keeps a build report
however long it is between deploys, because a site that hasn't been rebuilt is
still running exactly these packages.

## Options

```
--site <id>        Site ID        (or ANALYTICS_SITE_ID)
--secret <secret>  Site secret    (or ANALYTICS_SECRET, or ANALYTICS_SITE_SECRET)
--endpoint <url>   Collector URL  (or ANALYTICS_ENDPOINT)
--dir <path>       Where the lock file is (default: this folder): npm-shrinkwrap.json,
                   package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock
--host <name>      What to call this report in the dashboard (default: build,
                   or ANALYTICS_HOST)
--dry-run          Print what would be sent, send nothing
--strict           Exit non-zero on failure (default: never fail the build)
--quiet            Say nothing unless something is wrong
--help
```

Use `--dir` for a monorepo, and `--host` to tell two builds of one site apart:
a site with a shop front end and an admin front end reports each under its own
name, or the second build's report replaces the first.

## Tests

```sh
npm test
```

`test/parity.test.js` runs this package's lock-file parsing and
`sdk/platform-node`'s over the same files and fails if they disagree. There are
deliberately two copies — this one has to work installed on its own — so that
test is what keeps them the same. Change one, change both.
