# Deploys protocol (v1)

How a new version of a site going live reaches the dashboard, so the charts,
errors, vitals and uptime can say what changed just before something moved.
The design and the readers are in `backend/docs/DEPLOYS.md`; this file is the
wire format for the two endpoints a client calls itself. Webhooks from GitHub,
GitLab, Vercel and Netlify need no client and are described there.

The collector side is `expresscollect/Analytics/deploys.js`; deploys are kept
in Mongo `site_deploys`, one document per version that went live.

## Authentication

Like the other server protocols: the site's ID in the body and
`Authorization: Bearer <secret>`. Two secrets are accepted on
`/events/deploy`:

- the **site secret** (Site settings): records the deploy and, as before,
  accepts every server's file changes (`files.md`), unless `accept_files` is
  `false`;
- the **deploy key** (Site settings → Integrations → Deploys): records the
  deploy only. It is what to give a CI pipeline, because a leaked deploy key
  can add a marker but can never hide a tampered file.

`/events/apps` takes the site secret only.

## POST /events/deploy

One call when a version has gone live, from the end of a CI pipeline, a
Docker entrypoint, or by hand. Every field but `site_id` is optional; a bare
call still marks the time.

```json
{
  "site_id": "…",
  "version": "a1b2c3d4e5f6…",
  "message": "Fix checkout",
  "author": "sam",
  "url": "https://github.com/acme/shop/commit/a1b2c3d",
  "environment": "production",
  "repo": "acme/shop",
  "accept_files": true
}
```

- `version`: the commit SHA, tag or build number, at most 100 characters. A
  40-character hex value is taken as the commit.
- `environment`: anything other than the site's production environment
  (`production` by default; `production`, `prod`, `prd` and `live` are one
  name) is answered `{ "recorded": false, "reason": "environment" }` and no
  deploy is stored, so a pipeline that also deploys staging can call this
  every time. The site secret still accepts the files whatever the
  environment, as it always did (`"accepted": true` in the answer).
- `url` is kept only when it is `https`.

Answer: `{ "recorded": true, "deploy": "<id>", "merged": false }`. `merged` is
`true` when another source already reported the same version going live
(GitHub said so, then the pipeline did): it is one deploy, not two.

Examples:

```sh
# GitHub Actions, after the deploy step
curl -fsS -X POST "$COLLECTOR/events/deploy" \
  -H "Authorization: Bearer $DEPLOY_KEY" -H "Content-Type: application/json" \
  -d "{\"site_id\":\"$SITE_ID\",\"version\":\"$GITHUB_SHA\",\"repo\":\"$GITHUB_REPOSITORY\"}"

# GitLab CI
curl -fsS -X POST "$COLLECTOR/events/deploy" \
  -H "Authorization: Bearer $DEPLOY_KEY" -H "Content-Type: application/json" \
  -d "{\"site_id\":\"$SITE_ID\",\"version\":\"$CI_COMMIT_SHA\",\"message\":\"$CI_COMMIT_TITLE\"}"
```

## POST /events/apps

The server agent's report of the apps it can see on the machine, every few
minutes when something changed and at least hourly otherwise. The collector
compares each app's `version` with the last report from the same host: a
changed version is a deploy (`source: "agent"` for git and copied folders,
`"docker"` for a container). The first report from a host only sets the baseline.

```json
{
  "v": 1,
  "site_id": "…",
  "host": "web-1",
  "client": "vps-agent/0.5.0",
  "apps": [
    {
      "name": "shop",
      "kind": "git",
      "path": "/var/www/shop",
      "version": "a1b2c3d4…(40 hex)",
      "branch": "main",
      "repo": "acme/shop",
      "repo_host": "github.com",
      "message": "Fix checkout",
      "committed_at": "2026-11-03T09:12:00Z",
      "remote": { "version": "f0e1d2…(40 hex)", "checked_at": "2026-11-03T10:00:00Z" },
      "state": "behind",
      "behind": 3
    },
    {
      "name": "api",
      "kind": "docker",
      "version": "sha256:…",
      "image": "ghcr.io/acme/api:1.4.2",
      "revision": "a1b2c3d4…",
      "digest": "sha256:…",
      "started_at": "2026-11-03T09:40:00Z"
    }
  ]
}
```

- At most 50 apps. `name` at most 100 characters, `[A-Za-z0-9._/-]`.
- `repo` is `owner/name` (or `group/sub/name` on GitLab), never a URL: a
  remote like `https://token@github.com/acme/shop.git` carries a credential,
  and a client must reduce it to `acme/shop` before it leaves the machine.
- `repo_host` is the remote's host name alone (`github.com`), lowercased, no
  user, password or port. With `repo` it lets the dashboard link to the
  repository. Optional.
- `state` (git only): `current`, `behind` (`behind` counts the commits),
  `ahead` (the server has commits the branch doesn't), `diverged`,
  `newer_remote` (the branch moved and the server never fetched it, so the
  count is unknown; the dashboard counts it from GitHub/GitLab pushes when
  it has them) or `unknown` (the check failed or the folder has no upstream).
  `remote` is null when the check didn't run.
- `kind` is `git`, `docker` or `folder`: a running app that isn't in git,
  copied to the server by a deploy. A `folder` app has `path`, `runtime`
  (the program running it, `node`, `python3.12`…), `changed_at` (its newest
  top-level file) and a `version` of 24 hex: a fingerprint of its top-level
  files, never shaped like a commit.
- `revision` (docker only): the image's `org.opencontainers.image.revision`
  label, the commit it was built from, when it has one.
- `digest` (docker only): the registry digest the image was pulled as
  (`sha256:` and 64 hex, from `docker image inspect`'s `RepoDigests`, the one
  for the repository `image` names). Health → Updates compares it with what
  the tag points at now, to tell a newer build of the same tag. Optional:
  an image built on the server has none.

Answer: `{ "v": 1, "every": 3600 }`, the seconds to wait before reporting
again when nothing changed. A change is reported at the next read regardless.

### Must

- **Only read.** `git rev-parse`, `git symbolic-ref`, `git config --get`,
  `git ls-remote`, `git log -1`, `git cat-file -e`,
  `git merge-base --is-ancestor` and `git rev-list --count` on objects already
  there, with `GIT_NO_LAZY_FETCH=1` and `GIT_OPTIONAL_LOCKS=0` so a partial
  clone can't fetch and a read never touches the index. Never `git fetch` or `pull`: that writes into the customer's
  repository.
- Run git **as the folder's owner**, with their `HOME`, so it uses their keys
  and never needs `safe.directory`. Never prompt: `GIT_TERMINAL_PROMPT=0`,
  `ssh -o BatchMode=yes`, and a timeout on every call. A failure is
  `state: "unknown"`, not a stuck agent.
- `ls-remote` at most hourly per folder; reading `HEAD` is local and can run
  every few minutes, which is what makes a deploy's time right to the minute.
- Send no file contents and no credential: paths, hashes, names and commit
  subjects only.
