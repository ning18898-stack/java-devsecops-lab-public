"""Exercise core APIs on this lab's fixed local address, without logging credentials."""

import http.cookiejar
import json
import logging
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:8080"


class Client:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.token = None

    def request(self, method, path, expected, data=None, form=False):
        headers = {}
        if self.token:
            headers["X-CSRF-TOKEN"] = self.token
        if data is None:
            payload = None
        elif form:
            payload = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            payload = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(BASE + path, data=payload, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            status = response.code
        if status != expected:
            raise AssertionError(f"{method} {path} expected {expected}, received {status}")
        logging.info("PASS %s %s -> %s", method, path, status)
        return json.loads(body) if body else None

    def csrf(self):
        self.token = self.request("GET", "/api/auth/csrf", 200)["token"]


def main():
    (ROOT / "artifacts").mkdir(exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(
                            ROOT / "artifacts/api-smoke.log", encoding="utf-8")])
    run = uuid.uuid4().hex[:12]
    logging.info("Starting local baseline HTTP verification; run %s", run)
    alice, bob, anonymous = Client(), Client(), Client()
    assert anonymous.request("GET", "/actuator/health", 200)["status"] == "UP"
    anonymous.request("GET", "/api/users/me", 401)
    for client, prefix in [(alice, "alice"), (bob, "bob")]:
        client.csrf()
        name = prefix + "_" + run
        password = secrets.token_urlsafe(24)
        registered = client.request("POST", "/api/auth/register", 201,
                                    {"username": name, "email": name + "@example.test", "password": password})
        assert "password" not in registered and "passwordHash" not in registered
        client.request("POST", "/api/auth/login", 200, {"username": name, "password": password}, form=True)
        client.csrf()  # Authentication rotates the token and session identifier.
    me = alice.request("GET", "/api/users/me", 200)
    alice.request("PUT", "/api/users/me", 200, {"username": me["username"], "email": me["email"]})
    article = alice.request("POST", "/api/articles", 201, {"title": "Baseline " + run, "content": "Synthetic local sample"})
    assert article["userId"] == me["id"]
    path = "/api/articles/" + str(article["id"])
    bob.request("GET", path, 200)
    bob.request("GET", "/api/articles", 200)
    results = bob.request("GET", "/api/articles/search?q=" + run, 200)
    assert any(item["id"] == article["id"] for item in results)
    bob.request("PUT", path, 403, {"title": "Denied", "content": "Denied"})
    bob.request("DELETE", path, 403)
    alice.request("PUT", path, 200, {"title": "Updated " + run, "content": "Synthetic update"})
    alice.request("DELETE", path, 204)
    alice.request("GET", path, 404)
    for client in [alice, bob]:
        client.request("POST", "/api/auth/logout", 200)
        client.request("GET", "/api/users/me", 401)
    logging.info("Local HTTP verification complete; synthetic users retained for run %s; exit code 0", run)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        logging.error("Local HTTP verification failed: %s; exit code 1", detail)
        sys.exit(1)
