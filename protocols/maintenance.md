# Maintenance protocol (v1)

Pausing a site's alerts from a script while planned work runs: a deploy, a
server's update run, a database migration. Opening a window at the start and
closing it at the end means the people doing the work aren't emailed "site
down" about it. What a pause holds back and what is sent after is in
`backend/docs/ALERTS.md` ("Pausing alerts and quiet hours"); the collector side
is `expresscollect/Analytics/alertPause.js`.

In short: email and webhooks wait, the dashboard's notifications get everything
at once. When the window closes, anything still wrong is sent; something that
went down and came back inside it is only listed. Nothing waits more than a
day, whatever is left open.

## Authentication

The site's ID in the body and `Authorization: Bearer <site secret>`. **Only the
site secret**, not the deploy key: a pause holds back security alerts too, for
up to a day, and that is more than a key handed to a CI pipeline is trusted
with. A pipeline that should open windows gets the site secret as a protected
variable, or doesn't open them.

## POST /events/maintenance

Open a window from now:

```json
{ "site_id": "…", "minutes": 30, "note": "Deploy v2.4" }
```

- `minutes`: a whole number from 1 to 1440. Default 60.
- `note`: up to 200 characters, shown on the dashboard beside the window.

```json
{ "paused": true, "until": "2026-11-07T15:30:00.000Z" }
```

Close it early, when the work is done:

```json
{ "site_id": "…", "end": true }
```

```json
{ "paused": false }
```

Closing ends every window a script opened that is under way. Windows set on the
dashboard, a weekly window, and maintenance mode are left as they are.

Errors: `400` for a bad `site_id` or `minutes`, `401` for a wrong secret, `429`
past the rate limits (`MAINTENANCE_IP_RATE_LIMIT`, 60 a minute per address;
`MAINTENANCE_SITE_RATE_LIMIT`, 30 a minute per site), `503` with
`Retry-After: 30` when the collector can't reach its database.

## In a deploy script

```sh
pause() { curl -fsS -m 10 -X POST "$COLLECTOR/events/maintenance" \
  -H "Authorization: Bearer $SITE_SECRET" -H 'Content-Type: application/json' -d "$1" || true; }
pause "{\"site_id\":\"$SITE_ID\",\"minutes\":30,\"note\":\"deploy $VERSION\"}"
trap "pause '{\"site_id\":\"$SITE_ID\",\"end\":true}'" EXIT
# … the deploy …
```

The `|| true` matters: a pause that couldn't be opened must not stop the
deploy, and one left open closes itself when its minutes are up.
