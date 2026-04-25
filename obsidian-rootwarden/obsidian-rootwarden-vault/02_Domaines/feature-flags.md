---
type: domain
layer: L2
tags: [feature-flags, infra]
permissions: []
tables: []
routes: []
modules: []
version_introduced: 1.18.0
last_reviewed: 2026-04-25
status: stable
---

# Domaine - Feature flags

## Intention

Activer/desactiver des modules complets de RootWarden via une simple variable d'environnement, sans toucher au code ni aux permissions RBAC. Permet d'avoir un binaire unique deploye partout, avec une selection de modules adaptee a chaque instance (ex: une instance pour les serveurs prod ne veut peut-etre pas Wazuh, une autre pour le test ne veut pas Graylog).

## Variables actuelles

| Flag | Default | Effet quand `false` |
|------|---------|---------------------|
| `WAZUH_ENABLED` | `true` | Backend : `wazuh_bp` non enregistre (404 sur `/wazuh/*`). Frontend : sidebar/dashboard cachent l'entree, `/wazuh/index.php` abort en 404. |

## Implementation

### Backend Python

`backend/config.py` expose la valeur :
```python
WAZUH_ENABLED = os.getenv('WAZUH_ENABLED', 'true').lower() == 'true'
```

`backend/server.py` enregistre conditionnellement :
```python
if Config.WAZUH_ENABLED:
    app.register_blueprint(wazuh_bp)
else:
    print("[INFO] WAZUH_ENABLED=false - blueprint Wazuh non enregistre", flush=True)
```

Quand le blueprint n'est pas enregistre, Flask retourne nativement 404 (ou 405 si le catchall OPTIONS preflight matche) sur les routes /wazuh/*. Aucun code de garde explicite necessaire dans la logique metier.

### Frontend PHP

`www/includes/feature_flags.php` :
```php
function feature_enabled(string $name): bool
{
    $envKey = strtoupper($name) . '_ENABLED';
    $val = getenv($envKey);
    if ($val === false || $val === '') return true;  // default ON
    return strtolower($val) === 'true';
}
```

`www/menu.php`, `www/index.php`, `www/wazuh/index.php` consomment via `feature_enabled('wazuh')`.

### Defense-in-depth

3 couches independantes pour qu'un module disable ne fuite jamais :
1. Backend : blueprint non enregistre.
2. PHP page : early-return 404 dans `<module>/index.php` (au cas ou un user contourne le menu cache).
3. Menu : entree cachee partout (sidebar desktop + drawer mobile + grille shortcuts dashboard).

L'`api_proxy.php` propage les status HTTP du backend (404 -> 404) sur GET aussi (bug fixe en v1.18).

## Ajouter un nouveau flag

1. Ajouter dans `backend/config.py` : `XXX_ENABLED = os.getenv('XXX_ENABLED', 'true').lower() == 'true'`.
2. Dans `backend/server.py` : `if Config.XXX_ENABLED: app.register_blueprint(xxx_bp)`.
3. Dans `www/menu.php` : `if (feature_enabled('xxx') && ...)`.
4. Dans `www/index.php` : meme chose pour les shortcuts.
5. Dans `www/<xxx>/index.php` : early-return 404 si `!feature_enabled('xxx')`.
6. Dans `srv-docker.env.example` : ajouter `XXX_ENABLED=true` avec un commentaire.
7. Tester avec `tests/e2e/go-<xxx>-toggle.mjs` (copier `go-wazuh-toggle.mjs`).

## Voir aussi

- [[02_Domaines/wazuh]] - module concerne par le 1er flag.
- [[Code/www/includes/feature_flags.php]] - helper PHP.
- [[Code/tests/e2e/go-wazuh-toggle.mjs]] - test de validation cross-stack.
- [[12_Journal/v1.18]] - release note.
