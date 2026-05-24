#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
CLIENT_ID = "web-safe"
CLIENT_VERSION = "0.1.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


class Handler(BaseHTTPRequestHandler):
    server_version = "WebSafeSafeBrowsingProxy/0.1"

    def do_OPTIONS(self):
        self.send_empty(204)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(
                {
                    "ok": True,
                    "service": "web-safe-safe-browsing-proxy",
                    "configured": bool(api_key()),
                }
            )
            return

        self.send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self):
        if self.path != "/safe-browsing/check":
            self.send_json({"ok": False, "error": "not found"}, status=404)
            return

        try:
            payload = self.read_json()
            url = payload.get("url")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                self.send_json({"ok": False, "error": "invalid url"}, status=400)
                return

            key = api_key()
            if not key:
                self.send_json(
                    {
                        "ok": True,
                        "configured": False,
                        "checked": False,
                        "isUnsafe": False,
                        "matches": [],
                        "error": "GOOGLE_SAFE_BROWSING_API_KEY is not set",
                    }
                )
                return

            response = check_url(key, url)
            matches = response.get("matches", [])
            self.send_json(
                {
                    "ok": True,
                    "configured": True,
                    "checked": True,
                    "isUnsafe": len(matches) > 0,
                    "matches": matches,
                }
            )
        except urllib.error.HTTPError as error:
            self.send_json(
                {
                    "ok": False,
                    "error": f"Google Safe Browsing HTTP {error.code}",
                    "details": error.read().decode("utf-8", errors="replace"),
                },
                status=502,
            )
        except Exception as error:
            self.send_json({"ok": False, "error": str(error)}, status=500)

    def read_json(self):
        length = int(self.headers.get("content-length", "0"))
        data = self.rfile.read(length).decode("utf-8")
        return json.loads(data or "{}")

    def send_empty(self, status):
        self.send_response(status)
        self.add_common_headers()
        self.end_headers()

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.add_common_headers()
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def add_common_headers(self):
        self.send_header("access-control-allow-origin", "*")
        self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        self.send_header("access-control-allow-headers", "content-type")
        self.send_header("cache-control", "no-store")

    def log_message(self, format, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), format % args))


def check_url(key, url):
    query = urllib.parse.urlencode({"key": key})
    request = urllib.request.Request(
        f"{API_URL}?{query}",
        data=json.dumps(build_request_body(url)).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "user-agent": "WebSafeSafeBrowsingProxy/0.1",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def build_request_body(url):
    return {
        "client": {
            "clientId": CLIENT_ID,
            "clientVersion": CLIENT_VERSION,
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }


def api_key():
    return os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()


def main():
    host = os.environ.get("WEB_SAFE_BACKEND_HOST", DEFAULT_HOST)
    port = int(os.environ.get("WEB_SAFE_BACKEND_PORT", DEFAULT_PORT))
    server = ThreadingHTTPServer((host, port), Handler)

    print(f"Web Safe Safe Browsing proxy listening on http://{host}:{port}")
    print("Set GOOGLE_SAFE_BROWSING_API_KEY to enable Google checks.")
    server.serve_forever()


if __name__ == "__main__":
    main()
