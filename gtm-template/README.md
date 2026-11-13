# SiteGoose tag template for Google Tag Manager

A tag template for Google Tag Manager's Community Template Gallery. One template
does four things, picked in the tag:

| What this tag does | Fire it on |
| --- | --- |
| Track pages | Window Loaded, All Pages. Once. |
| Send an event (or a purchase) | Any trigger |
| Identify a signed-in user | Any trigger once the user ID is in the dataLayer |
| Forget the signed-in user | Sign-out |

Track pages sets `window.analyticsConfig` (the script tag's `data-` settings,
which a template can't set as attributes) and injects
`https://t.sitegoose.com/v1/track.js`. Events, identify and sign-out call
`window.analytics.*`, or wait in `window.analytics.q` until the tracker has
loaded, like the code pasted from the dashboard.

What the template can't do, and the pasted code can:

- **Lock the script.** GTM gives an injected script no integrity hash, so the
  template always loads the newest `v1` release.
- **Load from the site's own domain** (the first-party proxy). Its permission
  names `t.sitegoose.com` only.

## Files

- `template.tpl`: the template, as GTM exports it. Its `___TESTS___` run in GTM.
- `metadata.yaml`, `LICENSE` (Apache 2.0): what the gallery asks for.
- `test/template.test.js`: runs the template's code against fake GTM APIs, and
  checks the copy the dashboard offers for download is this file.

```sh
cd sdk/gtm-template && node --test
```

## Changing it

1. Edit `template.tpl`, then copy it to the dashboard's download:
   `cp template.tpl ../../frontend/public/downloads/sitegoose-gtm-template.tpl`
   (the test fails until the two match).
2. Import it into a GTM workspace (Templates → Tag Templates → New → ⋮ →
   Import), run its tests on the Tests tab, and try it in Preview.
3. Push, then add the new commit's SHA at the top of `versions` in
   `metadata.yaml`, and push that too. The gallery picks up a new version by
   itself from that list.

## Putting it in the gallery (once)

1. Make this folder a public GitHub repository with `template.tpl`,
   `metadata.yaml` and `LICENSE` at its root.
2. Fill in the commit SHA in `metadata.yaml` and push.
3. Submit the repository at
   https://developers.google.com/tag-platform/tag-manager/templates/gallery
   (the submission form is linked there).
