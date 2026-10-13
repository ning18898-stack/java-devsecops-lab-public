"""Read-only scope firewall. Runs only in the project's disposable Docker network."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import json
import os
from pathlib import Path
import socket
import sys
sys.path.insert(0, "/code/automation/src")
from labscan.boundary import PATHS, check_address, check_url, reject_redirect, resolve_exact


def exchange(path, host, address, subnet):
    check_url("http://" + host + ":8080" + path, host)
    check_address(address, subnet)
    resolve_exact(host, address)
    connection = http.client.HTTPConnection(address, 8080, timeout=5)
    try:
        connection.request("GET", path, headers={"Host": host + ":8080", "Connection": "close"})
        response = connection.getresponse()
        reject_redirect(response.status, response.getheader("Location"))
        content = response.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("Response size limit")
        return response.status, response.getheaders(), content
    finally:
        connection.close()


class Guard(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def deny(self):
        self.send_error(403)
        print(json.dumps({"blocked": True, "reason": "method"}), flush=True)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_CONNECT = do_HEAD = do_OPTIONS = deny

    def do_GET(self):
        self.connection.settimeout(5)
        try:
            if self.requestline.split(' ')[1] != self.path:
                raise ValueError("Request path normalization refused")
            if self.headers.get("Host") != Path('/tmp/scan-address').read_text() + ":8080":
                raise ValueError("Host header mismatch")
            if self.headers.get("Authorization") or self.headers.get("Cookie"):
                raise ValueError("Credentials not accepted")
            status, headers, body = exchange(self.path, "application", os.environ["APP_ADDRESS"], os.environ["APP_SUBNET"])
            self.send_response_only(status)
            for key, value in headers:
                if key.lower() not in ("connection", "transfer-encoding", "content-length", "location", "set-cookie"):
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print(json.dumps({"path": self.path, "method": "GET", "status": status, "blocked": False}), flush=True)
        except (ValueError, OSError, http.client.HTTPException) as error:
            self.send_error(502)
            print(json.dumps({"blocked": True, "reason": type(error).__name__}), flush=True)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Guard).serve_forever()
