# Publication checklist

## Before submission

- [ ] Run `npm test`.
- [ ] Run `python tools/build.py --skip-train --skip-psl`.
- [ ] Run `npx --yes web-ext lint -s dist/web-safe`.
- [ ] Check that CI is green on GitHub.
- [ ] Confirm that no API keys are stored in the repository.
- [ ] Replace draft screenshots with real PNG screenshots from Firefox/Chrome.
- [ ] Review `store/privacy-policy.md`.
- [ ] Review permission explanations in `store/listing.md`.
- [ ] Confirm that `manifest.json` version was increased before release.

## Chrome Web Store

- [ ] Create or open Chrome Web Store developer account.
- [ ] Upload `dist/web-safe.zip`.
- [ ] Fill out Privacy practices accurately.
- [ ] Add permission justifications.
- [ ] Add screenshots and icon.
- [ ] Add privacy policy URL or hosted privacy policy page.
- [ ] Submit for review.

## Firefox Add-ons

- [ ] Open Add-ons Developer Hub.
- [ ] Submit a new listed add-on or unlisted add-on for signing.
- [ ] Upload `dist/web-safe.zip`.
- [ ] Confirm data collection/transmission disclosure.
- [ ] Confirm `browser_specific_settings.gecko.data_collection_permissions`.
- [ ] Add screenshots and listing text.
- [ ] Submit for review/signing.

## Notes

Chrome and Firefox store policies can change. Re-check official documentation before final publication.
