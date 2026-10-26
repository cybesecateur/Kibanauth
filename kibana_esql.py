"""Authentification Kibana et requêtes ES|QL via /internal/bsearch.

Le module ouvre une session avec le formulaire de connexion Kibana
(POST /internal/security/login) ou, en secours, avec l'authentification
HTTP Basic (GET /internal/security/me). Une requête ES|QL est envoyée à
POST /internal/bsearch (strategy "esql") et les tableaux columns/values
sont convertis en liste de dictionnaires.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

import requests

_SSO_PROVIDER_TYPES = frozenset({"saml", "oidc", "kerberos", "pki"})
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_DEFAULT_TIMEOUT = 30
_QUERY_TIMEOUT = 120


class KibanaAuthError(Exception):
    """La connexion à Kibana a échoué."""


class EsqlQueryError(Exception):
    """La requête ES|QL a été rejetée ou la réponse est inexploitable."""


def _normalize_base_url(base_url: str) -> str:
    url = base_url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ValueError("L'URL Kibana doit commencer par http:// ou https://")
    return url


def _kbn_headers() -> dict[str, str]:
    return {
        "kbn-xsrf": "true",
        "elastic-api-version": "1",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _content_type(response: requests.Response) -> str:
    headers = getattr(response, "headers", None) or {}
    getter = getattr(headers, "get", None)
    if getter is None:
        return ""
    value = getter("Content-Type", None)
    if value is None:
        value = getter("content-type", "")
    return str(value or "")


def _http_ok(response: requests.Response) -> bool:
    try:
        status = int(response.status_code)
    except (TypeError, ValueError):
        return False
    if status >= 400:
        return False
    if "text/html" in _content_type(response).lower():
        return False
    return True


def _response_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except ValueError as exc:
        snippet = (getattr(response, "text", "") or "")[:300]
        raise KibanaAuthError(
            f"Réponse Kibana non JSON (HTTP {response.status_code}) : {snippet}"
        ) from exc


def _apply_cookie(session: requests.Session, cookie: str) -> None:
    """Pose un cookie `sid` brut, `sid=...`, ou un en-tête Cookie complet."""
    value = cookie.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()
    if value.lower().startswith("cookie:"):
        value = value.split(":", 1)[1].strip()
    if not value:
        return

    parts = [part.strip() for part in value.split(";") if part.strip()]
    pairs: list[tuple[str, str]] = []
    for part in parts:
        if "=" not in part:
            pairs = []
            break
        name, raw = part.split("=", 1)
        name = name.strip()
        if not _COOKIE_NAME_RE.fullmatch(name) or name.startswith("Fe26"):
            pairs = []
            break
        pairs.append((name, raw.strip()))

    if pairs:
        for name, raw in pairs:
            session.cookies.set(name, raw)
        return
    session.cookies.set("sid", value)


def _prepare_session(
    session: requests.Session | None,
    cookie: str = "",
) -> tuple[requests.Session, bool]:
    owns_session = session is None
    if session is None:
        session = requests.Session()
    if cookie:
        _apply_cookie(session, cookie)
    return session, owns_session


def test_kibana_login(base_url: str, username: str, password: str) -> requests.Session:
    """Teste la connexion Kibana et renvoie une session authentifiée.

    Essaie d'abord POST /internal/security/login (providerType et
    providerName « basic », en-tête kbn-xsrf). Si cet appel échoue,
    bascule sur l'authentification HTTP Basic validée par
    GET /internal/security/me.
    """
    base_url = _normalize_base_url(base_url)
    session = requests.Session()
    session.headers.update(
        {
            "kbn-xsrf": "true",
            "elastic-api-version": "1",
        }
    )

    login_url = f"{base_url}/internal/security/login"
    payload = {
        "providerType": "basic",
        "providerName": "basic",
        "currentURL": "/",
        "params": {
            "username": username,
            "password": password,
        },
    }
    web_login_ok = False
    try:
        response = session.post(
            login_url,
            json=payload,
            headers=_kbn_headers(),
            timeout=_DEFAULT_TIMEOUT,
        )
        web_login_ok = _http_ok(response)
    except requests.RequestException:
        web_login_ok = False

    if web_login_ok:
        session.kibana_auth_method = "web_login"  # type: ignore[attr-defined]
        return session

    session.auth = (username, password)
    me_url = f"{base_url}/internal/security/me"
    try:
        me_response = session.get(
            me_url,
            headers=_kbn_headers(),
            timeout=_DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise KibanaAuthError(f"Authentification Kibana impossible : {exc}") from exc

    if not _http_ok(me_response):
        detail = (getattr(me_response, "text", "") or "")[:500]
        status = getattr(me_response, "status_code", "?")
        raise KibanaAuthError(
            f"Authentification Kibana refusée (HTTP {status}). {detail}".rstrip()
        )

    session.kibana_auth_method = "basic"  # type: ignore[attr-defined]
    return session


def _is_sso_provider(provider: dict[str, Any]) -> bool:
    provider_type = str(provider.get("type", "")).strip().lower()
    if provider_type in _SSO_PROVIDER_TYPES:
        return True
    if provider_type in {"basic", "anonymous", "token", ""}:
        return False
    return provider.get("usesLoginForm") is False


def _extract_providers(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []

    candidates: list[Any] = []
    selector = payload.get("selector")
    if isinstance(selector, dict):
        candidates.append(selector.get("providers"))
    candidates.append(payload.get("providers"))
    login_state = payload.get("loginState")
    if isinstance(login_state, dict):
        nested = login_state.get("selector")
        if isinstance(nested, dict):
            candidates.append(nested.get("providers"))
        candidates.append(login_state.get("providers"))

    for candidate in candidates:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return []


def _normalize_providers(providers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for provider in providers:
        item: dict[str, Any] = {
            "type": provider.get("type"),
            "name": provider.get("name"),
            "sso": _is_sso_provider(provider),
        }
        if "usesLoginForm" in provider:
            item["usesLoginForm"] = provider.get("usesLoginForm")
        if provider.get("description"):
            item["description"] = provider.get("description")
        normalized.append(item)
    return normalized


def _login_state_from_me(session: requests.Session, base_url: str) -> dict[str, Any]:
    response = session.get(
        f"{base_url}/internal/security/me",
        headers=_kbn_headers(),
        timeout=_DEFAULT_TIMEOUT,
    )
    if not _http_ok(response):
        status = getattr(response, "status_code", "?")
        raise KibanaAuthError(
            "Impossible de lire /internal/security/login_state, et "
            f"/internal/security/me a répondu HTTP {status}. "
            "Passez --username/--password ou --cookie."
        )
    payload = _response_json(response)
    if not isinstance(payload, dict):
        raise KibanaAuthError("Réponse /internal/security/me inattendue.")
    provider = payload.get("authentication_provider") or {}
    if not isinstance(provider, dict):
        provider = {}
    providers = _normalize_providers([provider] if provider else [])
    return {
        "endpoint": "/internal/security/me",
        "sso": any(item["sso"] for item in providers),
        "providers": providers,
        "username": payload.get("username"),
    }


def get_login_state(
    base_url: str,
    session: requests.Session | None = None,
    cookie: str = "",
) -> dict[str, Any]:
    """Indique si le SSO est proposé et liste les fournisseurs de connexion.

    Interroge GET /internal/security/login_state. Si ce point de
    terminaison répond 404, bascule sur GET /internal/security/me.
    """
    base_url = _normalize_base_url(base_url)
    session, owns_session = _prepare_session(session, cookie)
    try:
        response = session.get(
            f"{base_url}/internal/security/login_state",
            headers=_kbn_headers(),
            timeout=_DEFAULT_TIMEOUT,
        )
        status = getattr(response, "status_code", 0)
        if status == 404:
            return _login_state_from_me(session, base_url)
        if not _http_ok(response):
            return _login_state_from_me(session, base_url)
        payload = _response_json(response)
        providers = _normalize_providers(_extract_providers(payload))
        return {
            "endpoint": "/internal/security/login_state",
            "sso": any(item["sso"] for item in providers),
            "providers": providers,
        }
    finally:
        if owns_session:
            session.close()


def fetch_current_user(base_url: str, session: requests.Session) -> dict[str, Any]:
    """Lit le profil renvoyé par GET /internal/security/me."""
    base_url = _normalize_base_url(base_url)
    response = session.get(
        f"{base_url}/internal/security/me",
        headers=_kbn_headers(),
        timeout=_DEFAULT_TIMEOUT,
    )
    if not _http_ok(response):
        status = getattr(response, "status_code", "?")
        raise KibanaAuthError(f"/internal/security/me a répondu HTTP {status}.")
    payload = _response_json(response)
    if not isinstance(payload, dict):
        raise KibanaAuthError("Réponse /internal/security/me inattendue.")
    provider = payload.get("authentication_provider") or {}
    if not isinstance(provider, dict):
        provider = {}
    return {
        "authenticated": True,
        "method": getattr(session, "kibana_auth_method", None),
        "username": payload.get("username"),
        "roles": payload.get("roles"),
        "authentication_provider": provider,
        "sso": _is_sso_provider(provider),
    }


def _column_names(columns: list[Any]) -> list[str]:
    names: list[str] = []
    seen: dict[str, int] = {}
    for index, column in enumerate(columns):
        if isinstance(column, dict):
            raw_name = column.get("name")
            name = str(raw_name) if raw_name else f"column_{index}"
        elif column:
            name = str(column)
        else:
            name = f"column_{index}"
        count = seen.get(name, 0)
        seen[name] = count + 1
        if count:
            name = f"{name}_{count}"
        names.append(name)
    return names


def rows_from_raw_response(raw: Any) -> list[dict[str, Any]]:
    """Transforme columns + values d'une rawResponse ES|QL en dictionnaires."""
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, dict):
        raise EsqlQueryError("rawResponse ES|QL inattendue.")

    payload = raw
    if "columns" not in payload and isinstance(payload.get("body"), dict):
        payload = payload["body"]

    columns = payload.get("columns") or []
    values = payload.get("values") or []
    if not isinstance(columns, list) or not isinstance(values, list):
        raise EsqlQueryError("Les champs columns et values doivent être des tableaux.")

    names = _column_names(columns)
    rows: list[dict[str, Any]] = []
    for row in values:
        if isinstance(row, dict):
            rows.append(row)
            continue
        if not isinstance(row, (list, tuple)):
            raise EsqlQueryError("Chaque ligne ES|QL doit être un tableau.")
        if not names:
            names = [f"column_{index}" for index in range(len(row))]
        item = {
            name: (row[index] if index < len(row) else None)
            for index, name in enumerate(names)
        }
        rows.append(item)
    return rows


def _documents_from_body(body: str) -> list[Any]:
    text = body.lstrip("\ufeff").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        if isinstance(parsed, list):
            return parsed
        return [parsed]

    documents: list[Any] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            documents.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise EsqlQueryError(
                f"Ligne NDJSON {line_number} illisible : {exc.msg}"
            ) from exc
    return documents


def _error_message(error: Any) -> str:
    if isinstance(error, dict):
        message = error.get("message") or error.get("error") or error
        status = error.get("statusCode")
        if status:
            return f"HTTP {status} : {message}"
        return str(message)
    return str(error)


def parse_bsearch_body(body: str) -> list[dict[str, Any]]:
    """Extrait les lignes ES|QL d'une réponse JSON ou NDJSON de /internal/bsearch.

    Kibana peut renvoyer plusieurs résultats partiels. La dernière réponse
    dont isRunning est faux est retenue.
    """
    documents = _documents_from_body(body)
    chosen: list[dict[str, Any]] | None = None
    finished = False
    errors: list[str] = []

    for document in documents:
        if not isinstance(document, dict):
            continue
        if document.get("error"):
            errors.append(_error_message(document["error"]))
            continue

        nested_result = document.get("result")
        result = nested_result if isinstance(nested_result, dict) else document
        if not isinstance(result, dict):
            continue
        if result.get("error"):
            errors.append(_error_message(result["error"]))
            continue

        raw = result.get("rawResponse")
        if raw is None and "columns" in result and "values" in result:
            raw = result
        if raw is None:
            continue

        rows = rows_from_raw_response(raw)
        if isinstance(nested_result, dict):
            is_running = bool(nested_result.get("isRunning"))
        else:
            is_running = bool(result.get("isRunning"))
        if not is_running:
            chosen = rows
            finished = True
        elif not finished:
            chosen = rows

    if finished and chosen is not None:
        return chosen
    if errors:
        raise EsqlQueryError("Requête ES|QL en erreur : " + " | ".join(errors))
    if chosen is not None:
        return chosen
    return []


def run_esql(
    query: str,
    kibana_url: str,
    session: requests.Session | None = None,
    cookie: str = "",
) -> list[dict[str, Any]]:
    """Exécute une requête ES|QL via POST /internal/bsearch.

    La requête utilise strategy « esql ». columns et values de rawResponse
    sont renvoyés comme une liste de dictionnaires JSON.
    """
    if not query or not query.strip():
        raise ValueError("La requête ES|QL est vide.")

    kibana_url = _normalize_base_url(kibana_url)
    session, owns_session = _prepare_session(session, cookie)
    body = {
        "batch": [
            {
                "request": {
                    "id": "esql",
                    "params": {"query": query},
                },
                "options": {"strategy": "esql"},
            }
        ]
    }
    try:
        try:
            response = session.post(
                f"{kibana_url}/internal/bsearch",
                json=body,
                headers=_kbn_headers(),
                params={"compress": "false"},
                timeout=_QUERY_TIMEOUT,
            )
        except requests.RequestException as exc:
            raise EsqlQueryError(f"Appel /internal/bsearch impossible : {exc}") from exc

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            detail = (response.text or "")[:500]
            raise EsqlQueryError(
                f"/internal/bsearch a répondu HTTP {response.status_code}. {detail}".rstrip()
            ) from exc

        return parse_bsearch_body(response.text or "")
    finally:
        if owns_session:
            session.close()


def _dump(payload: Any) -> None:
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Tester l'authentification Kibana (mot de passe ou cookie sid) "
            "et exécuter une requête ES|QL."
        )
    )
    parser.add_argument(
        "--url",
        required=True,
        help="URL de base de Kibana, par exemple https://kibana.exemple:5601",
    )
    parser.add_argument("--username", help="Nom d'utilisateur Kibana")
    parser.add_argument("--password", help="Mot de passe Kibana")
    parser.add_argument(
        "--cookie",
        default="",
        help="Cookie de session navigateur : valeur sid, sid=..., ou en-tête Cookie",
    )
    parser.add_argument("--query", help="Requête ES|QL à exécuter")
    parser.add_argument(
        "--login-state",
        action="store_true",
        help=(
            "Afficher les fournisseurs de connexion "
            "(GET /internal/security/login_state, ou /internal/security/me)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        _normalize_base_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    if args.username and not args.password:
        parser.error("--password est requis avec --username.")
    if args.password and not args.username:
        parser.error("--username est requis avec --password.")
    if not any([args.login_state, args.query, args.username, args.cookie]):
        parser.error("Indiquez --login-state, --username/--password, --cookie ou --query.")
    if args.query and not (args.username or args.cookie):
        parser.error("Une requête ES|QL exige --username/--password ou --cookie.")

    try:
        session: requests.Session | None = None
        if args.username and args.password:
            session = test_kibana_login(args.url, args.username, args.password)

        if args.query:
            rows = run_esql(
                args.query,
                args.url,
                session=session,
                cookie=args.cookie,
            )
            _dump(rows)
            return 0

        if args.login_state:
            report = get_login_state(args.url, session=session, cookie=args.cookie)
            if session is not None or args.cookie:
                profile_session = session
                owns_profile_session = False
                if profile_session is None:
                    profile_session, owns_profile_session = _prepare_session(None, args.cookie)
                try:
                    report["current_user"] = fetch_current_user(args.url, profile_session)
                except KibanaAuthError as exc:
                    report["current_user_error"] = str(exc)
                finally:
                    if owns_profile_session and profile_session is not None:
                        profile_session.close()
            _dump(report)
            return 0

        if session is None:
            parser.error("Avec --cookie seul, ajoutez --query ou --login-state.")
        _dump(fetch_current_user(args.url, session))
        return 0
    except (KibanaAuthError, EsqlQueryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if "session" in locals() and session is not None:
            session.close()


if __name__ == "__main__":
    sys.exit(main())
