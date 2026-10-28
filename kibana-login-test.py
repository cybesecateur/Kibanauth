#!/usr/bin/env python3
"""Test minimal Kibana (LDAP/mot de passe et SSO) depuis une URL /login."""

from __future__ import annotations

import argparse
import json
import re
import sys
from html import unescape
from urllib.parse import urlparse

import requests
import urllib3

SSO = {"saml", "oidc", "kerberos", "pki"}
PASSWORD = {"basic", "ldap"}
KNOWN = SSO | PASSWORD | {"token", "anonymous"}
PAIR_RE = re.compile(
    r'"type"\s*:\s*"([A-Za-z]+)"[^}]{0,160}?"name"\s*:\s*"([^"]+)"'
    r'|"name"\s*:\s*"([^"]+)"[^}]{0,160}?"type"\s*:\s*"([A-Za-z]+)"'
)


def derive_urls(url: str) -> tuple[str, str]:
    """Retire /login final. Le préfixe de reverse-proxy reste dans la base."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("L'URL doit commencer par http:// ou https://")
    path, origin = (parsed.path or "").rstrip("/"), f"{parsed.scheme}://{parsed.netloc}"
    if path.lower().endswith("/login"):
        base_path, login_path = path[: -len("/login")], path
    else:
        base_path, login_path = path, (path + "/login" if path else "/login")
    return (origin + base_path).rstrip("/"), origin + login_path


def make_session(verify_ssl: bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify_ssl
    session.headers.update({"kbn-xsrf": "true", "elastic-api-version": "1"})
    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("Attention : la vérification du certificat SSL est désactivée.")
    return session


def call(session, method, url, step, **kwargs):
    print(f"\n{step}\nAppel {method.upper()} {url}")
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("allow_redirects", False)
    try:
        response = session.request(method, url, **kwargs)
    except requests.RequestException as exc:
        print(f"Erreur réseau : {exc}")
        return None
    print(f"HTTP {response.status_code}")
    for header in ("Location", "Content-Type", "WWW-Authenticate", "Set-Cookie"):
        value = response.headers.get(header)
        if value:
            print(f"  {header}: {value.splitlines()[0][:200]}")
    names = [cookie.name for cookie in response.cookies]
    if names:
        print("  Cookies reçus : " + ", ".join(names))
    return response


def metadata_from_html(html: str) -> dict:
    text, raw = html or "", ""
    tag = re.search(r"<kbn-injected-metadata\b([^>]*)>", text, re.I | re.S)
    attr = re.search(r"""\bdata=(["'])(.*?)\1""", tag.group(1), re.S) if tag else None
    if attr:
        raw = unescape(attr.group(2))
    if not raw:
        script = re.search(r"""id=["']kbn-injected-metadata["'][^>]*>(.*?)</script>""", text, re.I | re.S)
        raw = unescape(script.group(1)).strip() if script else ""
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def align_base(base: str, meta: dict) -> str:
    announced = meta.get("basePath") or meta.get("serverBasePath") or ""
    if not isinstance(announced, str) or not announced.startswith("/"):
        return base
    parsed = urlparse(base)
    candidate = f"{parsed.scheme}://{parsed.netloc}{announced}".rstrip("/")
    if base.rstrip("/").endswith(announced.rstrip("/")):
        return base.rstrip("/")
    print(f"basePath kbn-injected-metadata {announced} -> {candidate}")
    return candidate


def harvest(node, found: list) -> None:
    if isinstance(node, dict):
        kind, name = node.get("type"), node.get("name")
        if isinstance(kind, str) and isinstance(name, str) and kind.lower() in KNOWN:
            if (kind.lower(), name) not in {(item["type"].lower(), item["name"]) for item in found}:
                found.append({"type": kind, "name": name, "usesLoginForm": node.get("usesLoginForm")})
        for value in node.values():
            harvest(value, found)
    elif isinstance(node, list):
        for item in node:
            harvest(item, found)
    elif isinstance(node, str):
        for kind, name, name2, kind2 in PAIR_RE.findall(node):
            harvest({"type": kind or kind2, "name": name or name2}, found)


def redirect_of(response) -> str:
    if response is None:
        return ""
    if response.headers.get("Location"):
        return response.headers["Location"]
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        for key in ("location", "redirect", "redirectURL", "authorizationUrl"):
            if isinstance(body.get(key), str):
                return body[key]
    return ""


def sso_url(url: str, base: str) -> bool:
    if not url:
        return False
    target, origin = urlparse(url), urlparse(base)
    external = target.scheme in {"http", "https"} and target.netloc not in {"", origin.netloc}
    markers = ("saml", "oidc", "oauth", "authorize")
    return external or any(marker in url.lower() for marker in markers)


def plant_cookie(session, raw: str) -> None:
    value = raw.strip().strip("'\"")
    if value.lower().startswith("cookie:"):
        value = value.split(":", 1)[1].strip()
    if "=" not in value or value.startswith("Fe26"):
        session.cookies.set("sid", value)
        return
    for part in value.split(";"):
        if "=" in part:
            name, cookie = part.strip().split("=", 1)
            session.cookies.set(name.strip(), cookie.strip())


def sid_value(session) -> str | None:
    value = session.cookies.get("sid")
    return value if isinstance(value, str) and value else None


def confirm(session, base: str, planted_sid: str | None = None) -> bool:
    names = sorted({cookie.name for cookie in session.cookies})
    if names:
        print("Cookies de session : " + ", ".join(names))
    me = call(session, "get", f"{base}/internal/security/me", "Contrôle GET /internal/security/me")
    html = me is not None and "html" in me.headers.get("Content-Type", "").lower()
    if me is not None and me.status_code < 400 and not html:
        try:
            user = me.json().get("username")
        except ValueError:
            user = None
        print(f"Session confirmée{(' : ' + str(user)) if user else ''}.")
        return True
    received = sid_value(session)
    if received and received != planted_sid:
        print("Cookie sid reçu, mais /internal/security/me ne confirme pas la session.")
        return True
    print("Session non confirmée.")
    return False


def is_sso(provider: dict) -> bool:
    kind = provider["type"].lower()
    if kind in SSO:
        return True
    return kind not in PASSWORD | {"anonymous", "token"} and provider.get("usesLoginForm") is False


def post_login(session, base, kind, name, params):
    return call(
        session, "post", f"{base}/internal/security/login",
        f"POST /internal/security/login providerType={kind} providerName={name}",
        json={"providerType": kind, "providerName": name, "currentURL": "/", "params": params},
    )


def test_password(session, base, login_url, providers, username, password, planted_sid=None) -> bool:
    print("\n=== Test LDAP / mot de passe ===")
    attempts = [("basic", "ldap"), ("ldap", "ldap"), ("basic", "basic")]
    attempts += [(p["type"], p["name"]) for p in providers if p["type"].lower() in PASSWORD or p.get("usesLoginForm")]
    seen, creds = set(), {"username": username, "password": password}
    for kind, name in attempts:
        if (kind.lower(), name) in seen:
            continue
        seen.add((kind.lower(), name))
        response = post_login(session, base, kind, name, creds)
        fresh_sid = sid_value(session) not in {None, planted_sid}
        if response is not None and (fresh_sid or response.status_code < 400) and confirm(session, base, planted_sid):
            print(f"LDAP / mot de passe : succès via {kind}/{name}.")
            return True
    direct = call(session, "post", login_url, "POST direct du formulaire vers l'URL de login", data=creds)
    fresh_sid = sid_value(session) not in {None, planted_sid}
    if direct is not None and (fresh_sid or direct.status_code < 400) and confirm(session, base, planted_sid):
        print("LDAP / mot de passe : succès via POST direct.")
        return True
    basic = call(
        session, "get", f"{base}/internal/security/me",
        "Secours HTTP Basic sur GET /internal/security/me", auth=(username, password),
    )
    if basic is not None and basic.status_code < 400 and "html" not in basic.headers.get("Content-Type", "").lower():
        print("LDAP / mot de passe : succès via HTTP Basic.")
        return True
    print("LDAP / mot de passe : échec.")
    return False


def test_sso(session, base, providers, login_redirect: str) -> bool:
    print("\n=== Test SSO ===")
    ok = sso_url(login_redirect, base)
    if login_redirect:
        print(("Redirection SSO observée sur /login : " if ok else "Redirection /login (hors SSO) : ") + login_redirect)
    found = [provider for provider in providers if is_sso(provider)]
    if not found and not ok:
        print("Aucun fournisseur SSO (saml, oidc, kerberos, pki) détecté.")
    for provider in found:
        target = redirect_of(post_login(session, base, provider["type"], provider["name"], {}))
        if target:
            print(f"URL SSO ({provider['type']}/{provider['name']}) : {target}")
            ok = True
        else:
            print(f"Pas d'URL de redirection pour {provider['type']}/{provider['name']}.")
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test minimal de login Kibana (LDAP et SSO) depuis une URL /login.")
    parser.add_argument("--url", required=True, help="URL de login, ex. https://hôte/chemin/login")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--cookie", default="", help="Cookie sid ou en-tête Cookie du navigateur")
    parser.add_argument("--test-sso", action="store_true", help="Exiger une redirection SSO ou un cookie valide")
    parser.add_argument("-k", "--insecure", action="store_true", help="Ne pas vérifier le certificat SSL")
    args = parser.parse_args(argv)
    if bool(args.username) ^ bool(args.password):
        print("--username et --password vont ensemble.", file=sys.stderr)
        return 1
    try:
        base, login_url = derive_urls(args.url)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"URL de login fournie : {args.url}")
    print(f"URL de login utilisée : {login_url}")
    print(f"URL de base déduite (suffixe /login retiré) : {base}")
    session = make_session(not args.insecure)
    if args.cookie:
        plant_cookie(session, args.cookie)
        print("Cookie navigateur posé sur la session.")
    first = call(session, "get", login_url, "Lecture de /login sans suivre les redirections")
    login_redirect = redirect_of(first) if first is not None and first.status_code in {301, 302, 303, 307, 308} else ""
    page = first if first is not None and first.status_code < 300 else call(
        session, "get", login_url, "Relecture de /login pour le HTML", allow_redirects=True,
    )
    html = getattr(page, "text", "") or ""
    meta = metadata_from_html(html)
    print("kbn-injected-metadata trouvé." if meta else "Pas de kbn-injected-metadata dans /login.")
    base = align_base(base, meta)
    providers: list = []
    harvest(meta, providers)
    harvest(html, providers)
    state = call(session, "get", f"{base}/internal/security/login_state", "Lecture GET /internal/security/login_state")
    if state is not None:
        try:
            harvest(state.json(), providers)
        except ValueError:
            print("login_state n'est pas du JSON.")
        harvest(state.text or "", providers)
    if providers:
        print("Fournisseurs : " + ", ".join(f"{item['type']}/{item['name']}" for item in providers))
    else:
        print("Aucun fournisseur découvert (ldap et basic seront essayés).")
    if args.username:
        planted = sid_value(session)
        password_ok = test_password(
            session, base, login_url, providers, args.username, args.password, planted,
        )
    else:
        password_ok = False
        print("\nPas d'identifiants : test LDAP/mot de passe ignoré.")
    sso_ok = test_sso(session, base, providers, login_redirect)
    cookie_ok = False
    if args.cookie:
        print("\n=== Vérification du cookie navigateur ===")
        cookie_ok = confirm(session, base, sid_value(session))
        print("Cookie SSO/session : " + ("succès." if cookie_ok else "échec."))
        sso_ok = sso_ok or cookie_ok
    print("\n=== Résultat ===")
    print("LDAP / mot de passe : " + ("succès" if password_ok else "échec" if args.username else "non testé"))
    print("SSO : " + ("succès" if sso_ok else "échec"))
    failed = (args.username and not password_ok) or (args.cookie and not cookie_ok) or (args.test_sso and not sso_ok)
    return 1 if failed or (first is None and page is None) else 0


if __name__ == "__main__":
    sys.exit(main())
