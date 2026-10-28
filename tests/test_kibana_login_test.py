"""Tests du script court kibana-login-test.py (URL /login, LDAP, SSO)."""

from __future__ import annotations

import html
import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import requests
import urllib3

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kibana_login_test", ROOT / "kibana-login-test.py")
MOD = importlib.util.module_from_spec(SPEC)
sys.modules["kibana_login_test"] = MOD
SPEC.loader.exec_module(MOD)

BASE = "https://proxy.exemple/outils/kibana"
LOGIN = BASE + "/login"
ORIGIN_LOGIN = "https://proxy.exemple/login"


def metadata_html(payload: dict) -> str:
    raw = json.dumps(payload).replace("&", "&amp;").replace('"', "&quot;")
    return f'<html><kbn-injected-metadata data="{raw}"></kbn-injected-metadata></html>'


class Resp:
    def __init__(self, status=200, headers=None, body=None, text="", cookies=None):
        self.status_code = status
        self.headers = dict(headers or {})
        self._body = body
        self.text = json.dumps(body) if body is not None else text
        if body is not None:
            self.headers.setdefault("Content-Type", "application/json")
        self.cookies = requests.cookies.RequestsCookieJar()
        for name, value in (cookies or {}).items():
            self.cookies.set(name, value)
            self.headers.setdefault("Set-Cookie", f"{name}={value}")

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


class FakeSession:
    def __init__(self, handler):
        self.verify = True
        self.headers = {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.calls = []
        self.handler = handler

    def request(self, method, url, **kwargs):
        self.calls.append((method.lower(), url, kwargs))
        outcome = self.handler(method.lower(), url, kwargs)
        if isinstance(outcome, Exception):
            raise outcome
        for cookie in outcome.cookies:
            self.cookies.set(cookie.name, cookie.value)
        return outcome


def run(argv, handler):
    session = FakeSession(handler)
    stdout, stderr = io.StringIO(), io.StringIO()

    def factory(verify_ssl):
        session.verify = verify_ssl
        return session

    with patch.object(MOD, "make_session", side_effect=factory), redirect_stdout(stdout), redirect_stderr(stderr):
        code = MOD.main(argv)
    return code, stdout.getvalue(), stderr.getvalue(), session


def login_posts(session):
    posts = []
    for method, url, kwargs in session.calls:
        if method == "post" and url.endswith("/internal/security/login") and "json" in kwargs:
            body = kwargs["json"]
            posts.append((body["providerType"], body["providerName"], body.get("params")))
    return posts


class TestDeriveUrls(unittest.TestCase):
    def test_custom_reverse_proxy_login(self) -> None:
        base, login = MOD.derive_urls("https://proxy.exemple/outils/kibana/login")
        self.assertEqual(base, BASE)
        self.assertEqual(login, LOGIN)

    def test_trailing_slash_and_query_are_stripped(self) -> None:
        base, login = MOD.derive_urls("https://proxy.exemple/outils/kibana/login/?next=/app")
        self.assertEqual((base, login), (BASE, LOGIN))

    def test_login_suffix_is_case_insensitive(self) -> None:
        base, login = MOD.derive_urls("https://proxy.exemple/Outils/Login")
        self.assertEqual(base, "https://proxy.exemple/Outils")
        self.assertEqual(login, "https://proxy.exemple/Outils/Login")

    def test_base_without_login_gets_a_login_url(self) -> None:
        base, login = MOD.derive_urls("https://proxy.exemple/outils/kibana")
        self.assertEqual(base, BASE)
        self.assertEqual(login, LOGIN)

    def test_root_login(self) -> None:
        self.assertEqual(MOD.derive_urls("https://kibana.exemple:5601/login"), ("https://kibana.exemple:5601", "https://kibana.exemple:5601/login"))

    def test_scheme_is_required(self) -> None:
        with self.assertRaises(ValueError):
            MOD.derive_urls("proxy.exemple/login")


class TestMetadataAndSsl(unittest.TestCase):
    def test_injected_metadata_data_attribute(self) -> None:
        html_doc = metadata_html({"basePath": "/outils/kibana", "auth": {"type": "saml", "name": "okta"}})
        meta = MOD.metadata_from_html(html_doc)
        self.assertEqual(meta["basePath"], "/outils/kibana")
        found = []
        MOD.harvest(meta, found)
        self.assertEqual(found[0]["type"], "saml")

    def test_injected_metadata_script_tag(self) -> None:
        raw = html.escape(json.dumps({"serverBasePath": "/kibana"}))
        meta = MOD.metadata_from_html(f'<script id="kbn-injected-metadata">{raw}</script>')
        self.assertEqual(meta["serverBasePath"], "/kibana")

    def test_proxy_prefix_is_kept_when_basepath_is_a_suffix(self) -> None:
        self.assertEqual(MOD.align_base(BASE, {"basePath": "/kibana"}), BASE)

    def test_metadata_basepath_replaces_a_root_guess(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            base = MOD.align_base("https://proxy.exemple", {"basePath": "/outils/kibana"})
        self.assertEqual(base, BASE)
        self.assertIn("/outils/kibana", stdout.getvalue())

    def test_insecure_disables_warnings_and_verification(self) -> None:
        with patch.object(MOD.urllib3, "disable_warnings") as mocked, redirect_stdout(io.StringIO()):
            session = MOD.make_session(False)
        self.assertFalse(session.verify)
        mocked.assert_called_once_with(urllib3.exceptions.InsecureRequestWarning)
        session.close()
        plain = MOD.make_session(True)
        self.assertTrue(plain.verify)
        plain.close()

    def test_raw_sid_and_cookie_header(self) -> None:
        raw = requests.Session()
        MOD.plant_cookie(raw, "Fe26.2**abc=**def")
        self.assertEqual(raw.cookies.get("sid"), "Fe26.2**abc=**def")
        header = requests.Session()
        MOD.plant_cookie(header, "sid=abc; other=xyz")
        self.assertEqual(header.cookies.get("sid"), "abc")
        self.assertEqual(header.cookies.get("other"), "xyz")


class TestLoginFlow(unittest.TestCase):
    def _page(self, status=200, location="", html_doc="", redirects=False):
        if status in {301, 302, 303, 307, 308} and not redirects:
            return Resp(status, {"Location": location, "Content-Type": "text/html"}, text="")
        return Resp(200, {"Content-Type": "text/html"}, text=html_doc or "<html></html>")

    def test_ldap_and_basic_then_success_and_sso_url(self) -> None:
        html_doc = metadata_html({"basePath": "/kibana"})

        def handler(method, url, kwargs):
            self.assertFalse(kwargs.get("allow_redirects"))
            if method == "get" and url == LOGIN:
                return self._page(html_doc=html_doc)
            if method == "get" and url.endswith("/internal/security/login_state"):
                return Resp(200, body={"selector": {"providers": [
                    {"type": "basic", "name": "ldap1", "usesLoginForm": True},
                    {"type": "saml", "name": "okta", "usesLoginForm": False},
                ]}})
            if method == "post" and url.endswith("/internal/security/login"):
                body = kwargs["json"]
                if body["providerType"] == "saml":
                    return Resp(200, body={"location": "https://idp.exemple/sso/saml?SAMLRequest=1"})
                if (body["providerType"], body["providerName"]) == ("basic", "basic"):
                    return Resp(200, body={"location": "/"}, cookies={"sid": "abc"})
                return Resp(401, body={"message": "unauthorized"})
            if method == "get" and url.endswith("/internal/security/me"):
                return Resp(200, body={"username": "ada", "authentication_provider": {"type": "basic", "name": "basic"}})
            raise AssertionError((method, url))

        code, stdout, _stderr, session = run(
            ["--url", LOGIN + "/", "--username", "ada", "--password", "secret", "-k"],
            handler,
        )
        self.assertEqual(code, 0)
        self.assertFalse(session.verify)
        self.assertIn("URL de base déduite", stdout)
        self.assertIn(BASE, stdout)
        self.assertIn("kbn-injected-metadata trouvé", stdout)
        self.assertIn("HTTP 401", stdout)
        self.assertIn("HTTP 200", stdout)
        self.assertIn("LDAP / mot de passe : succès via basic/basic.", stdout)
        self.assertIn("URL SSO (saml/okta) : https://idp.exemple/sso/saml?SAMLRequest=1", stdout)
        self.assertIn("SSO : succès", stdout)
        password_posts = [item[:2] for item in login_posts(session) if item[2].get("username")]
        self.assertEqual(password_posts, [("basic", "ldap"), ("ldap", "ldap"), ("basic", "basic")])

    def test_discovered_ldap_provider_is_used(self) -> None:
        def handler(method, url, kwargs):
            if method == "get" and url == LOGIN:
                return self._page()
            if method == "get" and url.endswith("/login_state"):
                return Resp(200, body={"providers": [{"type": "basic", "name": "ldap1", "usesLoginForm": True}]})
            if method == "post" and url.endswith("/internal/security/login"):
                body = kwargs["json"]
                if (body["providerType"], body["providerName"]) == ("basic", "ldap1"):
                    return Resp(200, cookies={"sid": "abc"}, body={"ok": True})
                return Resp(401, body={"message": "no"})
            if method == "get" and url.endswith("/internal/security/me"):
                return Resp(200, body={"username": "ada"})
            raise AssertionError((method, url))

        code, stdout, _stderr, session = run(
            ["--url", "https://proxy.exemple/outils/kibana/login", "--username", "ada", "--password", "secret"],
            handler,
        )
        self.assertEqual(code, 0)
        self.assertIn("succès via basic/ldap1", stdout)
        names = [item[1] for item in login_posts(session) if item[2].get("username")]
        self.assertIn("ldap1", names)

    def test_http_basic_fallback(self) -> None:
        def handler(method, url, kwargs):
            if method == "get" and url == LOGIN:
                return self._page()
            if method == "get" and url.endswith("/login_state"):
                return Resp(200, body={})
            if method == "post":
                return Resp(401, body={"message": "no"})
            if method == "get" and url.endswith("/internal/security/me") and kwargs.get("auth"):
                self.assertEqual(kwargs["auth"], ("ada", "secret"))
                return Resp(200, body={"username": "ada"})
            raise AssertionError((method, url, kwargs.get("auth")))

        code, stdout, _stderr, session = run(
            ["--url", LOGIN, "--username", "ada", "--password", "secret"],
            handler,
        )
        self.assertEqual(code, 0)
        self.assertIn("Secours HTTP Basic", stdout)
        self.assertIn("succès via HTTP Basic", stdout)
        self.assertTrue(any(url == LOGIN and method == "post" and "data" in kwargs for method, url, kwargs in session.calls))

    def test_password_failure_exits_1(self) -> None:
        def handler(method, url, kwargs):
            if method == "get" and url == LOGIN:
                return self._page()
            if method == "get" and url.endswith("/login_state"):
                return Resp(200, body={})
            if method == "post":
                return Resp(401, body={"message": "no"})
            if method == "get" and url.endswith("/me"):
                return Resp(401, body={"message": "unauthorized"})
            raise AssertionError((method, url))

        code, stdout, _stderr, _session = run(
            ["--url", LOGIN, "--username", "ada", "--password", "mauvais"],
            handler,
        )
        self.assertEqual(code, 1)
        self.assertIn("LDAP / mot de passe : échec", stdout)

    def test_sso_redirect_from_login(self) -> None:
        def handler(method, url, kwargs):
            if method == "get" and url == ORIGIN_LOGIN:
                if kwargs.get("allow_redirects"):
                    return self._page(redirects=True, html_doc="<html><p>login</p></html>")
                return self._page(302, "https://idp.exemple/oauth/authorize?client_id=kibana")
            if method == "get" and url == "https://proxy.exemple/internal/security/login_state":
                return Resp(200, body={"selector": {"providers": []}})
            raise AssertionError((method, url, kwargs.get("allow_redirects")))

        code, stdout, _stderr, _session = run(["--url", ORIGIN_LOGIN, "--test-sso"], handler)
        self.assertEqual(code, 0)
        self.assertIn("Redirection SSO observée sur /login : https://idp.exemple/oauth/authorize?client_id=kibana", stdout)
        self.assertIn("Relecture de /login pour le HTML", stdout)
        self.assertIn("SSO : succès", stdout)

    def test_internal_redirect_is_not_sso_success(self) -> None:
        def handler(method, url, kwargs):
            if method == "get" and url == ORIGIN_LOGIN:
                if kwargs.get("allow_redirects"):
                    return self._page(redirects=True)
                return self._page(302, "/app/home")
            if method == "get" and "login_state" in url:
                return Resp(200, body={})
            raise AssertionError((method, url))

        code, stdout, _stderr, _session = run(["--url", ORIGIN_LOGIN, "--test-sso"], handler)
        self.assertEqual(code, 1)
        self.assertIn("Redirection /login (hors SSO)", stdout)
        self.assertIn("SSO : échec", stdout)

    def test_cookie_success_and_failure(self) -> None:
        def handler(method, url, kwargs, me_status):
            if method == "get" and url == LOGIN:
                return self._page()
            if method == "get" and url.endswith("/login_state"):
                return Resp(200, body={})
            if method == "get" and url.endswith("/internal/security/me"):
                if me_status >= 400:
                    return Resp(me_status, body={"message": "no"})
                return Resp(me_status, body={"username": "ada"})
            raise AssertionError((method, url))

        code, stdout, _stderr, session = run(
            ["--url", LOGIN, "--cookie", "sid=abc"],
            lambda method, url, kwargs: handler(method, url, kwargs, 200),
        )
        self.assertEqual(code, 0)
        self.assertEqual(session.cookies.get("sid"), "abc")
        self.assertIn("Cookie navigateur posé", stdout)
        self.assertIn("Cookie SSO/session : succès.", stdout)

        code, stdout, _stderr, _session = run(
            ["--url", LOGIN, "--cookie", "sid=expire"],
            lambda method, url, kwargs: handler(method, url, kwargs, 401),
        )
        self.assertEqual(code, 1)
        self.assertIn("Cookie SSO/session : échec.", stdout)

    def test_username_without_password_is_rejected(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = MOD.main(["--url", LOGIN, "--username", "ada"])
        self.assertEqual(code, 1)
        self.assertIn("--password", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
