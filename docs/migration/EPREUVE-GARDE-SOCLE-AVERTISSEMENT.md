# ÉPREUVE de la garde — exécutée, et les trois états mordent

    Session   5 — securite. Execute le 2026-09-09 dans `rootwarden_laravel`.
    Correction du commit precedent, qui declarait la garde NON EPROUVEE.

---

## 1. Le verdict

```
php -l /tmp/SocleAvertissementRetireTest.php     No syntax errors detected
vendor/bin/phpunit  (contre le depot reel)       OK (3 tests, 64 assertions)
```

## 2. La contre-épreuve — les trois états, sur le VRAI runner

**Arbres forgés dans `/tmp` du conteneur, `base_path()` redirigé par `sed` :**

```
cas AVEC la cle (+ le temoin)   ->  FAILURES!      la garde MORD
cas SANS la cle (+ le temoin)   ->  OK (3 tests, 6 assertions)
cas VIDE (aucun fichier)        ->  FAILURES!      l'etat MUET refuse
```

**Le troisième est celui qui compte** : *une universelle négative est vraie à
vide, et la garde refuse au lieu de passer.*

## 3. ⛔ Pourquoi rien n'a été écrit dans l'arbre partagé

**`laravel/tests/` n'est pas mon périmètre, et `laravel/` est monté en BIND.**
*Un `git checkout` de cette branche aurait roulé l'arbre en arrière de **2
commits** — donc retiré du disque le travail en cours de deux autres sessions.*

**Le fichier a donc été poussé dans `/tmp` DU CONTENEUR, qui est sur l'overlay et
n'est pas monté** (vérifié : seuls `laravel/` et `certs/` le sont).

```
empreinte du listing tests/Feature   AVANT  606e32d92b58ce4c7194d242e35ee1ef
                                     APRES  606e32d92b58ce4c7194d242e35ee1ef
modifications suivies dans laravel/         aucune
fichier temporaire du conteneur             supprime
```

> ⚠ **Et la preuve est dans un avertissement** : PHPUnit a rendu
> *« `file_put_contents(/var/www/html/.phpunit.result.cache)` : Permission
> denied »*. **Mon exécution ne POUVAIT pas écrire dans l'arbre partagé — c'est
> ce qui l'atteste.**

## 4. ⚠ CONSTAT INCIDENT — un `phpunit` a tourné en ROOT

```
laravel/.phpunit.result.cache   proprietaire root   mtime 2026-09-09 08:15:08
```

**Ce n'est pas moi** : *mon exécution a échoué sur ce fichier précisément parce
qu'il appartient à root et que je tournais en `www-data`.*

> **C'est exactement le danger signalé : `docker exec … php artisan` en root
> laisse des artefacts root dans un répertoire `www-data`.** *Ce fichier-là est
> `gitignore`, donc inoffensif. Mais le même geste produit les compilés Blade
> root — et sept en portent déjà la marque, dont deux dans le socle.*

**La parade est dans la commande, pas dans la vigilance** : `-u www-data`.

## 5. Ce qui reste

    la branche n'est PAS fusionnee — laravel/tests/ n'est pas mon perimetre
    la CI n'a pas tourne sur le SHA : j'ai execute le FICHIER, pas le pipeline
