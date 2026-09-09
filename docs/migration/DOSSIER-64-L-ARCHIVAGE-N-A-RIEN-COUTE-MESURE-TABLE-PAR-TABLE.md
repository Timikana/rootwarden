# DOSSIER-64 — L'archivage n'a rien coûté, mesuré TABLE PAR TABLE

**Mesuré le 2026-09-09 entre 07:30 et 08:00 CEST.** Aucun geste exercé sur une
machine. Le legacy a été éteint le matin même, sur le mot de l'exploitant.

> Six tours ont établi que la file des 11 portables n'a plus d'objet, **item par
> item**. Ce dossier l'établit autrement : **par les TABLES que l'archive
> écrivait.** Un item peut être oublié d'une liste ; une écriture en base ne
> s'oublie pas — elle laisse une trace dans le schéma.

---

## 1. La mesure

```
tables reelles, DERIVEES de mysql/*.sql            63
   (avec la parenthese exigee : un commentaire citant CREATE TABLE
    ne la suit pas — piege paye deux fois sur ce chantier)
ecrites par les 178 .php archives                  20
   (lignes de commentaire PHP ecartees, et intersection avec les 63 :
    sans ce filtre mon extracteur rendait 46 « tables », dont `si`,
    `une`, `pour`, `watch`, `for` — des mots de PROSE)
dont avec un ecrivain VIVANT                       18   ✅
sans ecrivain vivant                                2
```

**Témoin** : `machines` doit avoir un écrivain vivant → **6**. Sans lui, « 18/20 »
serait indiscernable d'un détecteur qui ne trouve rien.

---

## 2. Les deux sans écrivain vivant sont MORTES, et différemment

### `linux_versions` — un cache mort dont la capacité est vivante

```
table en base                           0 ligne
mentions dans le code vivant            0
ecrite par                              legacy/_deprecated/update/functions/machines.php
```

**Mais la capacité qu'elle servait est portée en entier** :

```
detection    POST /linux_version   -> backend/routes/monitoring.py:126
stockage     machines.linux_version — colonne PEUPLEE :
                 id 2  Debian GNU/Linux 12 (bookworm)   2026-07-25
                 id 3  Debian GNU/Linux 13 (trixie)     2026-09-05
lecture      supervision.py:829-848 en DERIVE les commandes d'installation
affichage    mises-a-jour.js:188 rend la cellule · :284 appelle la route
passerelle   RoutesBackend.php:34 · ClesApi.php:56 l'autorisent
```

*Le legacy avait DEUX stockages — la table `linux_versions` **et** la colonne
`machines.linux_version`. Le portage n'a gardé que la colonne. La table est le
doublon abandonné, pas la capacité.*

### `update_schedules` — un vestige que le code déclare lui-même

`backend/routes/updates.py:805-834` le dit avant moi : *« `update_schedules` est
un vestige à retirer ou une intention jamais tenue »*. Table **vide**, et le
seul écrivain était `legacy/_deprecated/update/functions/scheduling.php`.

**Ce n'est pas une capacité perdue : c'est une capacité qui n'a jamais existé du
côté vivant, et qui est documentée comme telle.**

---

## 3. ⛔ LA LIMITE DE CETTE MESURE, et c'est la partie qui compte

Mon prédicat était : *« existe-t-il, quelque part dans `laravel/app` ou
`backend/`, un `INSERT`/`UPDATE`/`DELETE` sur cette table ? »*

Il répond **oui** sur 18 tables. Et il ne dit **rien** de la couverture.

> **Un écrivain vivant sur la même table peut porter UN geste là où l'archive en
> portait SIX. C'est une question d'ARITÉ, pas de présence — et mon vert est une
> borne inférieure déguisée en verdict.**

Le déséquilibre le montre :

```
users                  archive 19 fichiers  ·  vivant 6
active_sessions        archive  9           ·  vivant 3
remember_tokens        archive  8           ·  vivant 2
permissions            archive  6           ·  vivant 1
user_logs              archive  6           ·  vivant 2
login_attempts         archive  5           ·  vivant 3
user_machine_access    archive  4           ·  vivant 1
machines               archive  4           ·  vivant 6
```

**`machines` est la seule où le vivant en a PLUS que l'archive.** Les sept
autres sont des candidates, et trois sessions les qualifient geste par geste —
avec la consigne de distinguer **retiré exprès** de **perdu** : `Permissions.php:305-320`
documente une capacité *retirée* (la case `sudo_nopasswd` indépendante du
préréglage, que le legacy offrait et qui autorisait une paire incohérente).

⚠ **Et un axe que ce dossier ne couvre pas du tout** : les gestes qui n'écrivent
dans **aucune** table — un `ssh`, un `systemctl`, une lecture de fichier. Ils
sont hors de portée d'une mesure par tables, et c'est la file des 11 qui les a
couverts, item par item. **Les deux méthodes se complètent ; ni l'une ni l'autre
ne suffit.**

---

## 4. ⛔ TROIS FAUSSES ALARMES EN UNE HEURE, TOUTES ARRÊTÉES AVANT PUBLICATION

Elles ont la même cause, et elle n'est pas la hâte.

```
① « aucun DELETE sur user_machine_access cote portage »
   FAUX — Permissions.php:329, sur une requete etalee sur TROIS lignes
          DB::table('user_machine_access')
              ->where('user_id', $id)->where('machine_id', $machine)
              ->delete();
   cause : grep oriente LIGNE sur un objet MULTILIGNE

② « l'amorcage de la machine de test est une capacite perdue »
   FAUX — ses deux moities sont portees SEPAREMENT :
          Serveurs.php:294    insere la machine
          Permissions.php:300 l'attribue a un compte
   cause : j'ai cherche UN site pour une capacite qui en a DEUX

③ « le portage n'affiche pas la version d'OS »
   FAUX — mises-a-jour.js:188 rend la cellule, :284 appelle la route
   cause : le tableau est bati en JS, pas en Blade — j'ai greppe la VUE
```

> **Les trois viennent de mesurer le mauvais OBJET** : une requête multiligne,
> une capacité en deux moitiés, un tableau bâti côté client. Aucune des trois
> n'est une erreur de raisonnement — ce sont trois fois le même défaut de grain.

**Et les trois ALARMAIENT.** C'est ce qui les a sauvées : j'ai continué à
mesurer parce qu'annoncer une capacité perdue engage. *Trois dédouanements du
même genre seraient partis.*

---

## 5. Ce que je tranche

**E-550 — La file des 11 est close pour la SEPTIÈME fois, et cette fois par un
autre instrument.** Six clôtures item par item, une par tables. *Deux méthodes,
un seul résultat, aucun code partagé — c'est la configuration qui vaut, pas le
verdict.*

**E-551 — Je ne déclare PAS les 18 tables « couvertes ».** Je déclare qu'elles
ont un écrivain vivant, ce qui est une borne inférieure. La couverture geste par
geste est assignée à trois sessions, et **je ne la reprendrai pas à mon compte
sans leur mesure** — c'est exactement ce que j'ai fait de travers trois fois
cette heure.

**E-552 — Rien ne revient à l'exploitant de ce dossier.** Aucun geste, aucune
signature, aucun arbitrage. C'est un constat, et il vaut par sa méthode plus que
par son résultat.
