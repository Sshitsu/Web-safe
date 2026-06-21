# Web Safe store listing draft

Use this file as the source text for Chrome Web Store and Firefox Add-ons.

Official references checked:

- Chrome Web Store review process: https://developer.chrome.com/docs/webstore/review-process
- Chrome Web Store best practices and privacy disclosure: https://developer.chrome.com/docs/webstore/best-practices
- Chrome privacy fields: https://developer.chrome.com/docs/webstore/cws-dashboard-privacy
- Firefox add-on submission: https://extensionworkshop.com/documentation/publish/submitting-an-add-on/
- Firefox add-on policies: https://extensionworkshop.com/documentation/publish/add-on-policies/
- Firefox built-in data consent: https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/

## Extension name

Web Safe

## Short description

Checks the active website for phishing-like risk signals and explains why a page may be suspicious.

## Full description

Web Safe is a browser extension that helps users estimate the risk level of the active website. It combines several independent signals instead of relying on one simple keyword rule.

The extension checks:

- URL structure: HTTPS usage, IP address hostnames, punycode, long URLs, suspicious keywords, deep paths, many hyphens and high digit ratio.
- Page structure: password fields, sensitive inputs, forms, external form targets, iframes, external scripts and external links.
- Domain and network signals: registrable domain detection through Public Suffix List, DNS records and RDAP domain age.
- Threat intelligence: OpenPhish and Phishing.Database community feeds.
- Optional Google Safe Browsing check through a backend proxy, so the API key is not stored inside the extension.
- A trained linear risk model that combines URL, DOM, DNS and RDAP features.

The result is shown as a score from 0 to 100 with a low, medium or high risk label. Web Safe also explains the reasons that affected the score, so the user can understand the warning instead of seeing only a black-box verdict.

## Key features

- One-click analysis of the active tab.
- Explainable risk score from 0 to 100.
- DOM, DNS, RDAP and threat-feed checks.
- Machine-learning model with URL, page and network features.
- Local history of recent checks.
- Safe UI rendering with textContent instead of unsafe HTML insertion.
- Google Safe Browsing integration through a backend proxy.

## Suggested category

Privacy & Security

## Suggested tags

security, phishing, safe browsing, anti-phishing, web protection, browser safety

## Permission justification

### tabs

Required to read the URL of the active tab selected by the user for analysis.

### activeTab

Required to analyze the current page after user interaction with the extension.

### scripting

Required to collect structural page signals such as forms, password fields, iframes and external links. The extension does not read values typed into input fields.

### storage

Required to store local analysis history and cache downloaded threat feeds.

### host permissions: all URLs

Required because the extension is designed to analyze arbitrary websites opened by the user.

## Data disclosure draft

Web Safe may process the URL of the active tab and structural page signals for risk analysis. It does not collect values typed into forms, passwords, payment card numbers, cookies or browsing history.

Threat-feed, DNS and RDAP checks may contact external services. Optional Google Safe Browsing checks are sent through the configured backend proxy. If the Safe Browsing backend is disabled, the extension continues to work with the remaining local and public-source checks.

## Screenshots to prepare

Recommended screenshots:

- Low-risk result on a well-known website.
- High-risk result on the local phishing test page.
- Reasons list showing explainable scoring.
- History section.
- Optional architecture/flow diagram for the listing or project page.

Draft SVG screenshots are included in `store/screenshots/`. For final publication, export or replace them with real PNG screenshots captured from Firefox/Chrome.

## Reviewer notes

See `store/review-notes.md`.
