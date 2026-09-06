# Les formes d'invocation — où vit la cible d'une requête

Relevé de session 4, 2026-09-06, demandé après E-456. Chaque chiffre porte sa
commande de remesure.

**La question n'est pas « quelles syntaxes émettent une requête » mais
« OÙ VIT LA CIBLE ».** Classer par syntaxe produit une liste qu'il faut
maintenir ; classer par lieu produit un critère qui se vérifie.

| forme | où vit la cible | trouvable par `grep` du nom ? |
|---|---|---|
| 1. appel direct | au site d'appel | oui |
| 2. appel par helper | au site d'appel | oui |
| 3. URL construite | **en partie** au site d'appel | partiellement |
| 4. **interception** | dans la **RÉPONSE** | **non** |
| 5. **attribut déclaratif** | dans le **BALISAGE** | **non** |
| 6. **formulaire sans `action`** | dans le **CHEMIN DU FICHIER** | **non** |

> **Un relevé doit énumérer les LIEUX où une cible peut vivre, pas les syntaxes
> qui en nomment une.** Les formes 4, 5 et 6 n'ont aucun site d'appel : aucune
> recherche par nom ne peut les rendre, quelle que soit sa finesse.

---

## Forme 4 — l'interception : la cible vit dans la RÉPONSE

C'est le mécanisme d'E-456. Un enrobage du transport agit sur une réponse et
déclenche une requête que rien n'a nommée.

    grep -rnE "window\.fetch *=|XMLHttpRequest\.prototype|new Proxy\(|sendBeacon|serviceWorker" \
      legacy/js/*.js laravel/public/js/*.js legacy/*/js/*.js   # hors *.min.js

**Résultat : UNE seule occurrence dans tout le JS non minifié** —
`legacy/js/utils.js:19`, celle qu'E-456 a traitée. **Pas d'override de
`XMLHttpRequest.prototype`, pas de `Proxy`, pas de `sendBeacon`, pas de service
worker.** *Négatif à population définie : la surface d'interception est close.*

⚠ **Exclure les fichiers minifiés est indispensable** : `legacy/js/htmx.min.js`
tient sur une ligne et fait déborder toute sonde qui ne l'écarte pas.

---

## Forme 5 — l'attribut déclaratif : la cible vit dans le BALISAGE

**htmx 2.0.4 est chargé** (`legacy/js/htmx.min.js`, référencé par `head.php`).
htmx émet des requêtes depuis des attributs HTML — **aucun JS ne les nomme**.

    grep -rnoE "\b(data-)?hx-(post|get|put|patch|delete)=\"[^\"]*\"" \
      legacy/ laravel/resources/ --include=*.php --include=*.blade.php

**Résultat : 2 sites, tous deux dans `legacy/menu.php`** (`:179`, `:380`) :

    <button hx-post="/adm/api/notifications.php"
            hx-vals='{"action":"read_all"}' hx-swap="none">
    <button hx-post="/adm/api/notifications.php"
            hx-vals='{"action":"read","id":N}' hx-swap="none">

**`menu.php` est inclus par toutes les pages servies : ces deux POST existent sur
tout le portail.** Déclencheur : le clic (défaut htmx pour un `<button>`).

### ✅ Et cette cible est correctement gardée — mesuré, pas supposé

    legacy/adm/api/notifications.php:15   checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])
                                   :27   checkCsrfToken()
    ecritures :91 :107  UPDATE notifications SET read_at ... WHERE (user_id = ? OR user_id = 0)
              :126      DELETE FROM notifications        WHERE ... AND (user_id = ? OR user_id = 0)

**Authentifiée, protégée en CSRF, et bornée aux lignes du demandeur ou aux
globales.** *Ce n'est pas un trou — mais aucun relevé fondé sur le JS ne pouvait
la compter.*

---

## Forme 6 — le formulaire sans `action` : la cible vit dans le CHEMIN DU FICHIER

Un `<form method="POST">` **sans attribut `action`** soumet vers **l'URL de la
page courante**. La cible n'est donc écrite ni en JS, ni en attribut : elle est
donnée par l'emplacement du fichier.

    python3 - <<'PY'
    import re, pathlib
    for f in pathlib.Path('legacy').rglob('*.php'):
        if '_deprecated' in str(f) or '/vendor/' in str(f): continue
        for m in re.finditer(r'<form[^>]*>', f.read_text(errors='replace'), re.I):
            b = m.group(0)
            if 'action=' not in b.lower() and re.search(r'method\s*=\s*["\']?post', b, re.I):
                print(f)
    PY

**Résultat : 11 `<form>` servis, 9 sans `action`, dont 8 en `method=POST`.**

    legacy/auth/login.php        x1
    legacy/auth/verify_2fa.php   x1
    legacy/privacy.php           x1
    legacy/profile.php           x5

**Ces huit cibles sont des PAGES, déjà inventoriées comme pages.** *Le point
aveugle est donc de MÉTHODE, pas de conséquence : un inventaire « qui produit une
requête » les manque, un inventaire « quelles pages existent » les tient.*

⚠ **Et c'est la forme de la remarque du banc de cette nuit** — *« une cible
désignée par sa POSITION n'est pas une cible : elle devient ce que la liste
devient »* — appliquée non à une liste mais à une **arborescence** : déplacer le
fichier déplace la cible, silencieusement.

---

## ⚠ Une erreur de mesure commise en écrivant ce relevé

Ma première sonde a rendu **34** `<form>` là où il y en a **11** : le `grep`
balayait `legacy/vendor/`. **C'est le piège exact signalé le matin même sur le
comptage des fichiers métier (83 contre 850), et j'y suis retombé le jour où on
me l'avait décrit.**

    toute mesure sur `legacy/` exclut `/vendor/` ET `_deprecated`
    et le desaccord de DEUX instruments est ce qui l'a revele —
    aucun des deux ne se serait denonce seul.
