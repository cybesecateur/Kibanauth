# Kibanauth

Client Python pour vérifier l'authentification Kibana et exécuter des requêtes ES|QL via le point de terminaison interne `POST /internal/bsearch`.

Le programme sait :

- interroger les fournisseurs de connexion pour voir si un SSO (SAML, OIDC, Kerberos ou PKI) est proposé ;
- ouvrir une session avec le formulaire de connexion Kibana (`POST /internal/security/login`), puis, en secours, avec l'authentification HTTP Basic (`GET /internal/security/me`) ;
- réutiliser un cookie de session navigateur `sid` ;
- tester uniquement la connexion, sans lancer de requête ;
- envoyer une requête ES|QL et renvoyer les lignes en JSON ;
- désactiver la vérification du certificat SSL lorsqu'un certificat interne ou auto-signé bloque la connexion.

Pour un Kibana dont vous n'avez que l'URL `/login` (chemin ou reverse-proxy non standard), utilisez le script court [`kibana-login-test.py`](kibana-login-test.py). Il ne fait pas d'ES|QL : il teste le mot de passe LDAP et le SSO.

## Prérequis

- Python 3.10 ou plus récent
- Un Kibana joignable sur le réseau (8.11 ou plus récent pour ES|QL)

La vérification TLS reste activée par défaut. Si Kibana présente un certificat d'une autorité interne, exportez `REQUESTS_CA_BUNDLE` vers le fichier de certificats correspondant. Si l'erreur SSL persiste en production (certificat auto-signé, nom d'hôte différent, chaîne incomplète), ajoutez `--insecure` ou `-k` : la vérification du certificat est alors désactivée, l'avertissement `InsecureRequestWarning` d'urllib3 est masqué, et un message le signale clairement.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Script court : `kibana-login-test.py`

`python kibana-login-test.py` part de l'URL de login réelle, par exemple `https://proxy.exemple/outils/kibana/login`. Le suffixe `/login` est retiré pour obtenir la base (`https://proxy.exemple/outils/kibana`), y compris quand un reverse-proxy ajoute un préfixe. Si le HTML contient `kbn-injected-metadata` avec un `basePath`, ce chemin est repris quand il ne contredit pas le préfixe déjà présent.

À chaque appel, le script affiche l'URL, le code HTTP, les en-têtes utiles (`Location`, `Content-Type`, `WWW-Authenticate`, `Set-Cookie`) et les cookies reçus.

```bash
python kibana-login-test.py \
  --url https://proxy.exemple/outils/kibana/login \
  --username ada \
  --password 'mot-de-passe' \
  --insecure
```

Ordre des essais mot de passe :

1. `POST /internal/security/login` avec les couples `providerType` / `providerName` `basic`/`ldap`, `ldap`/`ldap` et `basic`/`basic`.
2. Les fournisseurs `basic` ou `ldap` découverts dans `/login` (`kbn-injected-metadata`) ou `GET /internal/security/login_state`.
3. POST direct du formulaire vers l'URL `/login`.
4. Secours HTTP Basic sur `GET /internal/security/me`.

La connexion est acceptée si un cookie `sid` est posé ou si `/internal/security/me` répond correctement.

Le SSO est inspecté ensuite (ou seul, avec `--test-sso`) : redirection de `GET /login`, fournisseurs `saml`, `oidc`, `kerberos` ou `pki`, puis `POST /internal/security/login` pour afficher l'URL d'autorisation. `--test-sso` termine avec le code `1` si aucune URL SSO n'est obtenue.

Un cookie de navigateur déjà établi se vérifie sans mot de passe :

```bash
python kibana-login-test.py \
  --url https://proxy.exemple/outils/kibana/login \
  --cookie 'sid=Fe26.2**....' \
  --insecure
```

`-k` est l'équivalent court de `--insecure` (certificat non vérifié, avertissement urllib3 masqué).

## Vérifier si le SSO est utilisé

Cette commande interroge `GET /internal/security/login_state`, accessible sans session. Si ce point de terminaison est absent, le programme se rabat sur `GET /internal/security/me`, qui exige une session déjà ouverte.

```bash
python kibana_esql.py --url https://kibana.exemple:5601 --login-state
```

Exemple de réponse lorsque seul le fournisseur basic est actif :

```json
{
  "endpoint": "/internal/security/login_state",
  "sso": false,
  "providers": [
    {
      "type": "basic",
      "name": "basic",
      "usesLoginForm": true,
      "sso": false
    }
  ]
}
```

`sso` vaut `true` dès qu'un fournisseur `saml`, `oidc`, `kerberos` ou `pki` est présent. Un fournisseur de type inconnu qui n'affiche pas de formulaire de connexion est aussi traité comme du SSO.

Avec un mot de passe ou un cookie, la même commande ajoute `current_user`, lu sur `/internal/security/me`. Le champ `authentication_provider` indique alors le fournisseur qui a réellement authentifié la session.

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --cookie 'sid=VOTRE_COOKIE' \
  --login-state
```

## Désactiver la vérification SSL

À n'utiliser que contre un Kibana dont vous maîtrisez le certificat, par exemple un certificat auto-signé en production.

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --insecure \
  --username elastic \
  --password 'mot-de-passe' \
  --test-login
```

`-k` est l'équivalent court de `--insecure`. Le programme affiche alors : « la vérification du certificat SSL est désactivée ».

En bibliothèque, passez `verify_ssl=False` à `test_kibana_login`, `get_login_state`, `fetch_current_user` ou `run_esql`.

## Tester uniquement la connexion

`--test-login` vérifie que l'authentification fonctionne et s'arrête là : aucune requête ES|QL n'est envoyée. La session est contrôlée avec `GET /internal/security/me`. Le code de sortie vaut `0` si le profil est renvoyé, `1` si la connexion échoue.

Avec un mot de passe :

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --username elastic \
  --password 'mot-de-passe' \
  --test-login
```

Avec le cookie `sid` du navigateur :

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --cookie 'sid=Fe26.2**....' \
  --test-login
```

Le déroulé s'affiche au fur et à mesure (`Tentative de connexion via POST /internal/security/login`, `Connexion web réussie !` ou `Bascule sur HTTP Basic Auth`, puis `Vérification du profil via GET /internal/security/me`). Le JSON du profil suit ces messages sur la sortie standard.

La même vérification a lieu sans `--test-login` lorsque seul un nom d'utilisateur et un mot de passe sont fournis. `--test-login` rend l'intention explicite et accepte aussi un cookie seul.

## Tester un mot de passe

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --username elastic \
  --password 'mot-de-passe' \
  --test-login
```

Ordre des essais :

1. `POST /internal/security/login` avec le corps `providerType: "basic"`, `providerName: "basic"` et l'en-tête `kbn-xsrf: true`. Kibana pose alors le cookie de session `sid`.
2. Si cette connexion échoue, envoi de `GET /internal/security/me` avec l'authentification HTTP Basic.

La sortie JSON contient `authenticated`, la méthode utilisée (`web_login` ou `basic`) et le profil renvoyé par `/internal/security/me`.

Le mot de passe apparaît dans la liste des processus du système. Sur un poste partagé, préférez le cookie de session décrit ci-dessous.

## Utiliser un cookie de session (`sid`)

Quand le SSO est obligatoire, le formulaire basic ne suffit pas. Connectez-vous dans le navigateur, puis copiez le cookie `sid`.

1. Ouvrez les outils de développement (F12), onglet Application / Cookies, ou l'onglet Réseau.
2. Sélectionnez le cookie nommé `sid` pour l'origine Kibana.
3. Passez sa valeur à `--cookie`. Les formes suivantes sont acceptées : la valeur brute, `sid=...`, ou un en-tête `Cookie` complet (`sid=...; autre=...`).

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --cookie 'sid=Fe26.2**....' \
  --query 'FROM logs-* | STATS count = COUNT(*)'
```

## Exécuter une requête ES|QL

La requête est envoyée à `POST /internal/bsearch` avec `strategy: "esql"` et `compress=false`. Les tableaux `columns` et `values` de `rawResponse` sont convertis en liste d'objets JSON, écrite sur la sortie standard. Si Kibana renvoie plusieurs résultats partiels (NDJSON), la dernière réponse terminée est utilisée.

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --username elastic \
  --password 'mot-de-passe' \
  --query 'FROM logs-* | KEEP @timestamp, message | LIMIT 5'
```

Le programme annonce l'envoi (`Envoi de la requête ES|QL à POST /internal/bsearch`) puis le nombre de lignes (`Réponse reçue : X ligne(s) extraite(s)`). Ajoutez `--insecure` si le certificat TLS est refusé.

Exemple de résultat :

```json
[
  {
    "@timestamp": "2024-05-01T12:00:00.000Z",
    "message": "démarrage"
  },
  {
    "@timestamp": "2024-05-01T12:00:01.000Z",
    "message": "prêt"
  }
]
```

La même requête avec un cookie de navigateur :

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --cookie 'sid=Fe26.2**....' \
  --query 'FROM logs-* | KEEP @timestamp, message | LIMIT 5'
```

## Utilisation comme bibliothèque

```python
from kibana_esql import run_esql, test_kibana_login

session = test_kibana_login(
    "https://kibana.exemple:5601",
    "elastic",
    "mot-de-passe",
    verify_ssl=False,  # certificat auto-signé
)

lignes = run_esql(
    "FROM logs-* | LIMIT 10",
    "https://kibana.exemple:5601",
    session=session,
    verify_ssl=False,
)

# Session navigateur, sans mot de passe :
lignes = run_esql(
    "FROM logs-* | LIMIT 10",
    "https://kibana.exemple:5601",
    cookie="sid=Fe26.2**....",
)
```

`test_kibana_login` renvoie une `requests.Session` déjà authentifiée. `run_esql` renvoie une `list[dict]`.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

Les tests simulent les réponses HTTP : aucun Kibana réel n'est contacté.
