"""Tests de la connexion Kibana et du décodage des réponses ES|QL."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Any
from unittest.mock import MagicMock, patch

import requests
import urllib3

from kibana_esql import (
    EsqlQueryError,
    KibanaAuthError,
    fetch_current_user,
    get_login_state,
    main,
    parse_bsearch_body,
    rows_from_raw_response,
    run_esql,
    test_kibana_login,
)

KIBANA_URL = "https://kibana.exemple:5601"


def _load_json_document(text: str) -> Any:
    """Retourne le premier document JSON d'une sortie mêlée à des messages."""
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        while index < len(text) and text[index] not in "{[":
            index += 1
        if index >= len(text):
            break
        try:
            found, _end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        return found
    raise AssertionError(f"JSON introuvable dans : {text!r}")


def _response(
    status_code: int = 200,
    text: str = "",
    headers: dict[str, str] | None = None,
    json_body: object | None = None,
) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    if json_body is not None:
        text = json.dumps(json_body)
    response.text = text
    response.headers = headers or {"Content-Type": "application/json"}
    try:
        response.json.return_value = json.loads(text) if text else None
    except json.JSONDecodeError:
        response.json.side_effect = json.JSONDecodeError("Expecting value", text, 0)

    def raise_for_status() -> None:
        if status_code >= 400:
            error = requests.HTTPError(f"HTTP {status_code}")
            error.response = response
            raise error

    response.raise_for_status.side_effect = raise_for_status
    return response


class TestKibanaLogin(unittest.TestCase):
    @patch("kibana_esql.requests.Session")
    def test_web_login_returns_authenticated_session(self, session_cls: MagicMock) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.post.return_value = _response(
            200,
            json_body={"location": "/app/home"},
        )

        result = test_kibana_login("https://kibana.exemple:5601/", "elastic", "secret")

        self.assertIs(result, session)
        self.assertEqual(session.kibana_auth_method, "web_login")
        session.get.assert_not_called()

        url = session.post.call_args.args[0]
        kwargs = session.post.call_args.kwargs
        self.assertEqual(url, "https://kibana.exemple:5601/internal/security/login")
        self.assertEqual(kwargs["headers"]["kbn-xsrf"], "true")
        self.assertEqual(kwargs["json"]["providerType"], "basic")
        self.assertEqual(kwargs["json"]["providerName"], "basic")
        self.assertEqual(kwargs["json"]["params"]["username"], "elastic")
        self.assertEqual(kwargs["json"]["params"]["password"], "secret")

    @patch("kibana_esql.requests.Session")
    def test_basic_auth_fallback_when_web_login_is_rejected(self, session_cls: MagicMock) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.post.return_value = _response(401, text='{"message":"unauthorized"}')
        session.get.return_value = _response(200, json_body={"username": "elastic"})

        result = test_kibana_login("https://kibana.exemple:5601", "elastic", "secret")

        self.assertIs(result, session)
        self.assertEqual(session.auth, ("elastic", "secret"))
        self.assertEqual(session.kibana_auth_method, "basic")
        me_url = session.get.call_args.args[0]
        self.assertEqual(me_url, "https://kibana.exemple:5601/internal/security/me")
        self.assertEqual(session.get.call_args.kwargs["headers"]["kbn-xsrf"], "true")

    @patch("kibana_esql.requests.Session")
    def test_html_login_page_falls_back_to_basic_auth(self, session_cls: MagicMock) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.post.return_value = _response(
            200,
            text="<html>login</html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
        session.get.return_value = _response(200, json_body={"username": "elastic"})

        result = test_kibana_login("https://kibana.exemple:5601", "user", "pw")

        self.assertIs(result, session)
        self.assertEqual(session.kibana_auth_method, "basic")

    @patch("kibana_esql.requests.Session")
    def test_connection_error_then_basic_auth_failure_raises(self, session_cls: MagicMock) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.post.side_effect = requests.ConnectionError("injoignable")
        session.get.return_value = _response(401, text="unauthorized")

        with self.assertRaises(KibanaAuthError):
            test_kibana_login("https://kibana.exemple:5601", "user", "pw")

        self.assertEqual(session.auth, ("user", "pw"))

    def test_login_rejects_url_without_scheme(self) -> None:
        with self.assertRaises(ValueError):
            test_kibana_login("kibana.exemple:5601", "user", "pw")


class TestEsqlParsing(unittest.TestCase):
    def test_columns_and_values_become_dicts(self) -> None:
        raw = {
            "took": 4,
            "columns": [
                {"name": "host", "type": "keyword"},
                {"name": "count", "type": "long"},
            ],
            "values": [["web-1", 3], ["web-2", None]],
        }

        self.assertEqual(
            rows_from_raw_response(raw),
            [
                {"host": "web-1", "count": 3},
                {"host": "web-2", "count": None},
            ],
        )

    def test_parse_bsearch_object(self) -> None:
        body = json.dumps(
            {
                "id": 0,
                "result": {
                    "rawResponse": {
                        "columns": [
                            {"name": "@timestamp", "type": "date"},
                            {"name": "message", "type": "text"},
                        ],
                        "values": [["2024-05-01T12:00:00.000Z", "démarrage"]],
                    },
                    "isPartial": False,
                    "isRunning": False,
                },
            }
        )

        self.assertEqual(
            parse_bsearch_body(body),
            [{"@timestamp": "2024-05-01T12:00:00.000Z", "message": "démarrage"}],
        )

    def test_parse_ndjson_keeps_last_completed_result(self) -> None:
        partial = {
            "id": 0,
            "result": {
                "rawResponse": {
                    "columns": [{"name": "n", "type": "long"}],
                    "values": [[1]],
                },
                "isPartial": True,
                "isRunning": True,
            },
        }
        final = {
            "id": 0,
            "result": {
                "rawResponse": {
                    "columns": [{"name": "n", "type": "long"}],
                    "values": [[1], [2]],
                },
                "isPartial": False,
                "isRunning": False,
            },
        }

        rows = parse_bsearch_body(json.dumps(partial) + "\n" + json.dumps(final) + "\n")

        self.assertEqual(rows, [{"n": 1}, {"n": 2}])

    def test_parse_nested_body_and_duplicate_column_names(self) -> None:
        body = json.dumps(
            {
                "result": {
                    "rawResponse": {
                        "body": {
                            "columns": [
                                {"name": "host", "type": "keyword"},
                                {"name": "host", "type": "keyword"},
                            ],
                            "values": [["a", "b"]],
                        }
                    },
                    "isRunning": False,
                }
            }
        )

        self.assertEqual(parse_bsearch_body(body), [{"host": "a", "host_1": "b"}])

    def test_query_error_payload_raises(self) -> None:
        body = json.dumps(
            {
                "id": 0,
                "error": {"message": "Unknown column [nope]", "statusCode": 400},
            }
        )

        with self.assertRaises(EsqlQueryError) as caught:
            parse_bsearch_body(body)
        self.assertIn("Unknown column [nope]", str(caught.exception))

    def test_partial_result_followed_by_error_raises(self) -> None:
        partial = {
            "id": 0,
            "result": {
                "rawResponse": {
                    "columns": [{"name": "n", "type": "long"}],
                    "values": [[1]],
                },
                "isRunning": True,
            },
        }
        error = {"id": 0, "error": {"message": "search failed", "statusCode": 500}}
        body = json.dumps(partial) + "\n" + json.dumps(error)

        with self.assertRaises(EsqlQueryError) as caught:
            parse_bsearch_body(body)
        self.assertIn("search failed", str(caught.exception))

    def test_short_row_is_padded_with_none(self) -> None:
        raw = {
            "columns": [{"name": "a"}, {"name": "b"}],
            "values": [["seul"]],
        }
        self.assertEqual(rows_from_raw_response(raw), [{"a": "seul", "b": None}])


class TestRunEsql(unittest.TestCase):
    def test_posts_esql_strategy_and_parses_rows(self) -> None:
        session = MagicMock()
        session.post.return_value = _response(
            200,
            json_body={
                "id": "esql",
                "result": {
                    "rawResponse": {
                        "columns": [{"name": "ok", "type": "boolean"}],
                        "values": [[True]],
                    },
                    "isRunning": False,
                },
            },
        )

        rows = run_esql(
            "FROM logs-* | LIMIT 1",
            "https://kibana.exemple:5601/",
            session=session,
        )

        self.assertEqual(rows, [{"ok": True}])
        self.assertEqual(
            session.post.call_args.args[0],
            "https://kibana.exemple:5601/internal/bsearch",
        )
        kwargs = session.post.call_args.kwargs
        self.assertEqual(kwargs["params"], {"compress": "false"})
        self.assertEqual(kwargs["headers"]["kbn-xsrf"], "true")
        batch = kwargs["json"]["batch"]
        self.assertEqual(batch[0]["options"]["strategy"], "esql")
        self.assertEqual(batch[0]["request"]["params"]["query"], "FROM logs-* | LIMIT 1")
        session.close.assert_not_called()

    def test_cookie_header_is_applied_to_a_new_session(self) -> None:
        session = MagicMock()
        session.post.return_value = _response(
            200,
            json_body={
                "result": {
                    "rawResponse": {"columns": [{"name": "n"}], "values": [[1]]},
                    "isRunning": False,
                }
            },
        )

        with patch("kibana_esql.requests.Session", return_value=session):
            rows = run_esql(
                "FROM a | LIMIT 1",
                "https://kibana.exemple:5601",
                cookie="sid=Fe26.2**abc=**def; security_authentication=xyz",
            )

        self.assertEqual(rows, [{"n": 1}])
        session.cookies.set.assert_any_call("sid", "Fe26.2**abc=**def")
        session.cookies.set.assert_any_call("security_authentication", "xyz")
        session.close.assert_called_once()

    def test_raw_sid_value_with_equals_stays_intact(self) -> None:
        session = MagicMock()
        session.post.return_value = _response(
            200,
            json_body={
                "result": {
                    "rawResponse": {"columns": [], "values": []},
                    "isRunning": False,
                }
            },
        )
        raw_sid = "Fe26.2**abc=**def"

        with patch("kibana_esql.requests.Session", return_value=session):
            run_esql("FROM a", "https://kibana.exemple:5601", cookie=raw_sid)

        session.cookies.set.assert_called_once_with("sid", raw_sid)

    def test_http_error_raises_esql_query_error(self) -> None:
        session = MagicMock()
        session.post.return_value = _response(400, text='{"message":"bad query"}')

        with self.assertRaises(EsqlQueryError):
            run_esql("FROM", "https://kibana.exemple:5601", session=session)


class TestLoginState(unittest.TestCase):
    @patch("kibana_esql.requests.Session")
    def test_saml_provider_is_reported_as_sso(self, session_cls: MagicMock) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.get.return_value = _response(
            200,
            json_body={
                "allowLogin": True,
                "selector": {
                    "enabled": True,
                    "providers": [
                        {"type": "basic", "name": "basic", "usesLoginForm": True},
                        {"type": "saml", "name": "okta", "usesLoginForm": False},
                    ],
                },
            },
        )

        report = get_login_state("https://kibana.exemple:5601")

        self.assertEqual(report["endpoint"], "/internal/security/login_state")
        self.assertTrue(report["sso"])
        self.assertEqual(
            [item["type"] for item in report["providers"]],
            ["basic", "saml"],
        )
        self.assertFalse(report["providers"][0]["sso"])
        self.assertTrue(report["providers"][1]["sso"])

    @patch("kibana_esql.requests.Session")
    def test_missing_login_state_falls_back_to_me(self, session_cls: MagicMock) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.get.side_effect = [
            _response(404, text="not found"),
            _response(
                200,
                json_body={
                    "username": "ada",
                    "authentication_provider": {"type": "oidc", "name": "entra"},
                },
            ),
        ]

        report = get_login_state("https://kibana.exemple:5601", cookie="sid=abc")

        self.assertEqual(report["endpoint"], "/internal/security/me")
        self.assertTrue(report["sso"])
        self.assertEqual(report["username"], "ada")
        self.assertEqual(report["providers"][0]["type"], "oidc")
        session.cookies.set.assert_called_once_with("sid", "abc")


class TestCli(unittest.TestCase):
    @patch("kibana_esql.get_login_state")
    def test_login_state_flag_prints_json(self, get_login_state_mock: MagicMock) -> None:
        get_login_state_mock.return_value = {
            "endpoint": "/internal/security/login_state",
            "sso": False,
            "providers": [],
        }
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = main(["--url", "https://kibana.exemple:5601", "--login-state"])

        self.assertEqual(code, 0)
        self.assertFalse(_load_json_document(stdout.getvalue())["sso"])
        self.assertIn("Kibana ciblé", stdout.getvalue())
        get_login_state_mock.assert_called_once()
        self.assertTrue(get_login_state_mock.call_args.kwargs["verify_ssl"])

    def test_query_without_credentials_is_rejected(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit):
            main(
                [
                    "--url",
                    "https://kibana.exemple:5601",
                    "--query",
                    "FROM logs-* | LIMIT 1",
                ]
            )
        self.assertIn("--cookie", stderr.getvalue())

    @patch("kibana_esql.run_esql")
    @patch("kibana_esql.test_kibana_login")
    def test_query_uses_password_session(
        self,
        login_mock: MagicMock,
        run_mock: MagicMock,
    ) -> None:
        session = MagicMock()
        login_mock.return_value = session
        run_mock.return_value = [{"count": 2}]
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = main(
                [
                    "--url",
                    "https://kibana.exemple:5601",
                    "--username",
                    "elastic",
                    "--password",
                    "secret",
                    "--query",
                    "FROM logs-* | STATS count = COUNT(*)",
                ]
            )

        self.assertEqual(code, 0)
        self.assertEqual(_load_json_document(stdout.getvalue()), [{"count": 2}])
        self.assertIn("Une requête ES|QL sera exécutée.", stdout.getvalue())
        login_mock.assert_called_once_with(
            "https://kibana.exemple:5601",
            "elastic",
            "secret",
            verify_ssl=True,
        )
        self.assertIs(run_mock.call_args.kwargs["session"], session)
        self.assertTrue(run_mock.call_args.kwargs["verify_ssl"])


class TestVerifySsl(unittest.TestCase):
    @patch("kibana_esql.urllib3.disable_warnings")
    @patch("kibana_esql.requests.Session")
    def test_login_verify_ssl_false_disables_verification(
        self,
        session_cls: MagicMock,
        disable_warnings: MagicMock,
    ) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.post.return_value = _response(200, json_body={"location": "/"})
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            result = test_kibana_login(
                KIBANA_URL,
                "elastic",
                "secret",
                verify_ssl=False,
            )

        self.assertIs(result, session)
        self.assertFalse(session.verify)
        disable_warnings.assert_called_with(urllib3.exceptions.InsecureRequestWarning)
        self.assertIn("vérification du certificat SSL est désactivée", stdout.getvalue())
        self.assertIn("Connexion web réussie !", stdout.getvalue())

    @patch("kibana_esql.urllib3.disable_warnings")
    def test_run_esql_verify_ssl_false(self, disable_warnings: MagicMock) -> None:
        session = MagicMock()
        session.post.return_value = _response(
            200,
            json_body={
                "result": {
                    "rawResponse": {
                        "columns": [{"name": "n"}],
                        "values": [[1], [2]],
                    },
                    "isRunning": False,
                }
            },
        )
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            rows = run_esql(
                "FROM logs-* | LIMIT 2",
                KIBANA_URL,
                session=session,
                verify_ssl=False,
            )

        self.assertEqual(rows, [{"n": 1}, {"n": 2}])
        self.assertFalse(session.verify)
        disable_warnings.assert_called_with(urllib3.exceptions.InsecureRequestWarning)
        text = stdout.getvalue()
        self.assertIn("Envoi de la requête ES|QL à POST /internal/bsearch", text)
        self.assertIn("Réponse reçue : 2 ligne(s) extraite(s).", text)
        self.assertIn("vérification du certificat SSL est désactivée", text)

    @patch("kibana_esql.urllib3.disable_warnings")
    @patch("kibana_esql.requests.Session")
    def test_get_login_state_verify_ssl_false(
        self,
        session_cls: MagicMock,
        disable_warnings: MagicMock,
    ) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.get.return_value = _response(
            200,
            json_body={
                "selector": {
                    "providers": [
                        {"type": "basic", "name": "basic", "usesLoginForm": True},
                    ]
                }
            },
        )

        report = get_login_state(KIBANA_URL, verify_ssl=False)

        self.assertFalse(report["sso"])
        self.assertFalse(session.verify)
        disable_warnings.assert_called_with(urllib3.exceptions.InsecureRequestWarning)

    @patch("kibana_esql.urllib3.disable_warnings")
    def test_fetch_current_user_verify_ssl_false(self, disable_warnings: MagicMock) -> None:
        session = MagicMock()
        session.kibana_auth_method = "web_login"
        session.get.return_value = _response(
            200,
            json_body={
                "username": "elastic",
                "roles": ["superuser"],
                "authentication_provider": {"type": "basic", "name": "basic"},
            },
        )
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            profile = fetch_current_user(KIBANA_URL, session, verify_ssl=False)

        self.assertFalse(session.verify)
        self.assertTrue(profile["authenticated"])
        self.assertEqual(profile["username"], "elastic")
        self.assertFalse(profile["sso"])
        disable_warnings.assert_called_with(urllib3.exceptions.InsecureRequestWarning)
        self.assertIn("Vérification du profil via GET /internal/security/me", stdout.getvalue())
        session.get.assert_called_once()
        self.assertIn("/internal/security/me", session.get.call_args.args[0])


class TestTestLoginCli(unittest.TestCase):
    @patch("kibana_esql.run_esql")
    @patch("kibana_esql.fetch_current_user")
    @patch("kibana_esql.test_kibana_login")
    def test_password_login_succeeds(
        self,
        login_mock: MagicMock,
        fetch_mock: MagicMock,
        run_mock: MagicMock,
    ) -> None:
        session = MagicMock()
        login_mock.return_value = session
        fetch_mock.return_value = {
            "authenticated": True,
            "username": "elastic",
            "method": "web_login",
        }
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = main(
                [
                    "--url",
                    KIBANA_URL,
                    "--username",
                    "elastic",
                    "--password",
                    "secret",
                    "--test-login",
                ]
            )

        self.assertEqual(code, 0)
        run_mock.assert_not_called()
        login_mock.assert_called_once_with(
            KIBANA_URL,
            "elastic",
            "secret",
            verify_ssl=True,
        )
        fetch_mock.assert_called_once_with(KIBANA_URL, session, verify_ssl=True)
        text = stdout.getvalue()
        self.assertIn("Mode --test-login", text)
        self.assertIn("Authentification réussie.", text)
        self.assertEqual(_load_json_document(text)["username"], "elastic")

    @patch("kibana_esql.fetch_current_user")
    @patch("kibana_esql.requests.Session")
    def test_cookie_login_with_insecure_flag(
        self,
        session_cls: MagicMock,
        fetch_mock: MagicMock,
    ) -> None:
        session = MagicMock()
        session_cls.return_value = session
        fetch_mock.return_value = {"authenticated": True, "username": "ada"}
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            code = main(
                [
                    "--url",
                    KIBANA_URL,
                    "-k",
                    "--cookie",
                    "sid=abc",
                    "--test-login",
                ]
            )

        self.assertEqual(code, 0)
        self.assertFalse(session.verify)
        session.cookies.set.assert_called_once_with("sid", "abc")
        fetch_mock.assert_called_once_with(KIBANA_URL, session, verify_ssl=False)
        text = stdout.getvalue()
        self.assertIn("vérification du certificat SSL est désactivée", text)
        self.assertIn("Authentification réussie.", text)
        self.assertEqual(_load_json_document(text)["username"], "ada")

    @patch("kibana_esql.fetch_current_user")
    @patch("kibana_esql.test_kibana_login")
    def test_insecure_long_flag_is_forwarded(
        self,
        login_mock: MagicMock,
        fetch_mock: MagicMock,
    ) -> None:
        session = MagicMock()
        login_mock.return_value = session
        fetch_mock.return_value = {"authenticated": True, "username": "elastic"}

        code = main(
            [
                "--url",
                KIBANA_URL,
                "--insecure",
                "--username",
                "elastic",
                "--password",
                "secret",
                "--test-login",
            ]
        )

        self.assertEqual(code, 0)
        self.assertFalse(login_mock.call_args.kwargs["verify_ssl"])
        self.assertFalse(fetch_mock.call_args.kwargs["verify_ssl"])

    @patch("kibana_esql.test_kibana_login", side_effect=KibanaAuthError("identifiants refusés"))
    def test_password_failure_returns_exit_code_1(self, _login_mock: MagicMock) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(
                [
                    "--url",
                    KIBANA_URL,
                    "--username",
                    "elastic",
                    "--password",
                    "mauvais",
                    "--test-login",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("identifiants refusés", stderr.getvalue())

    @patch(
        "kibana_esql.fetch_current_user",
        side_effect=KibanaAuthError("/internal/security/me a répondu HTTP 401."),
    )
    @patch("kibana_esql.requests.Session")
    def test_cookie_failure_returns_exit_code_1(
        self,
        session_cls: MagicMock,
        _fetch_mock: MagicMock,
    ) -> None:
        session_cls.return_value = MagicMock()
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            code = main(
                [
                    "--url",
                    KIBANA_URL,
                    "--cookie",
                    "sid=expire",
                    "--test-login",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("HTTP 401", stderr.getvalue())

    def test_test_login_rejects_a_query(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit):
            main(
                [
                    "--url",
                    KIBANA_URL,
                    "--username",
                    "elastic",
                    "--password",
                    "secret",
                    "--test-login",
                    "--query",
                    "FROM a",
                ]
            )
        self.assertIn("--query", stderr.getvalue())

    @patch("kibana_esql.requests.Session")
    def test_basic_fallback_prints_french_steps(self, session_cls: MagicMock) -> None:
        session = MagicMock()
        session_cls.return_value = session
        session.post.return_value = _response(401, text='{"message":"no"}')
        session.get.return_value = _response(200, json_body={"username": "elastic"})
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            test_kibana_login(KIBANA_URL, "elastic", "secret")

        text = stdout.getvalue()
        self.assertIn("[1/3] Tentative de connexion via POST /internal/security/login", text)
        self.assertIn("Bascule sur HTTP Basic Auth", text)
        self.assertIn("Vérification du profil via GET /internal/security/me", text)
        self.assertIn("Connexion HTTP Basic réussie !", text)


if __name__ == "__main__":
    unittest.main()
