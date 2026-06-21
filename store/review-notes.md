# Reviewer notes

Web Safe is a Manifest V3 browser extension for phishing-risk analysis.

## How to test

1. Build the extension:

   `python tools/build.py --skip-train --skip-psl`

2. Load `dist/web-safe/manifest.json` as an unpacked extension.

3. Open a normal website such as `https://google.com/` and run the popup check.

4. For a high-risk local test, run:

   `python -m http.server 8088 --directory tests/pages`

   Then open:

   `http://127.0.0.1:8088/external_password_form.html`

## Privacy and data handling

The extension does not read values entered into forms. It only checks page structure, for example whether a password field exists or whether a form submits to an external host.

The Google Safe Browsing API key is not embedded in the extension. The extension calls a configurable backend proxy at `http://127.0.0.1:8787` by default. If the backend is unavailable, the extension reports Safe Browsing as unavailable and continues with the remaining checks.

## Permissions

- `tabs`: read active tab URL.
- `activeTab`: user-initiated access to the active page.
- `scripting`: collect structural DOM signals.
- `storage`: store local history and feed cache.
- `<all_urls>` host permission: analyze arbitrary sites opened by the user.

## Validation

The project includes CI checks for:

- functional Node.js tests;
- Python syntax checks;
- extension build;
- Mozilla web-ext lint;
- Bandit;
- detect-secrets;
- Semgrep.
