# Web Safe privacy policy draft

Last updated: 2026-06-21

Web Safe is a browser extension that estimates the risk level of the active website and explains suspicious signals to the user.

## Data processed by the extension

When the user runs an analysis, Web Safe processes:

- the URL of the active tab;
- hostname and registrable domain;
- structural page signals such as the number of forms, password fields, iframes, links and scripts;
- form action hostnames;
- DNS and RDAP metadata for the domain;
- results from public phishing feeds;
- optional Google Safe Browsing result through a backend proxy.

## Data not collected

Web Safe does not collect:

- passwords typed by the user;
- values entered into forms;
- cookies;
- payment card numbers;
- full browsing history;
- personal files;
- personal messages.

The extension detects whether sensitive fields exist, but it does not read what the user enters into those fields.

## External services

Web Safe may contact:

- OpenPhish Community Feed;
- Phishing.Database active domain feed;
- Cloudflare DNS over HTTPS;
- rdap.org;
- the configured Web Safe Safe Browsing backend.

The Google Safe Browsing API key is not stored in the extension. It must be configured on the backend side through an environment variable.

## Local storage

Web Safe stores recent analysis history and threat-feed cache in the browser local extension storage. This data is used only to display recent checks and reduce repeated downloads.

## Contact

Project repository: https://github.com/Sshitsu/Web-safe
