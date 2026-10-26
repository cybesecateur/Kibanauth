# Kibanauth

Client Python pour vérifier l'authentification Kibana et exécuter des requêtes ES|QL via le point de terminaison interne `POST /internal/bsearch`.

Le programme sait :

- interroger les fournisseurs de connexion pour voir si un SSO (SAML, OIDC, Kerberos ou PKI) est proposé ;
- ouvrir une session avec le formulaire de connexion Kibana (`POST /internal/security/login`), puis, en secours, avec l'authentification HTTP Basic (`GET /internal/security/me`) ;
- réutiliser un cookie de session navigateur `sid` ;
- envoyer une requête ES|QL et renvoyer les lignes en JSON.

## Prérequis

- Python 3.10 ou plus récent
- Un Kibana joignable sur le réseau (8.11 ou plus récent pour ES|QL)

La vérification TLS reste activée. Si Kibana présente un certificat d'une autorité interne, exportez `REQUESTS_CA_BUNDLE` vers le fichier de certificats correspondant.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

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

## Tester un mot de passe

```bash
python kibana_esql.py \
  --url https://kibana.exemple:5601 \
  --username elastic \
  --password 'mot-de-passe'
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
)

lignes = run_esql(
    "FROM logs-* | LIMIT 10",
    "https://kibana.exemple:5601",
    session=session,
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
