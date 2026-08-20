# Parite legacy / Laravel — ecarts assumes

Le portage vise la parite de comportement. Quand il s'en ecarte, c'est une decision, elle
est ecrite ici, et le test de caracterisation porte une attente **par cible** : ecart connu
cote legacy, exigence cote Laravel.

Un ecart non ecrit ici est une regression, pas un choix.

---

## E-01 — Le rejeu d'un code TOTP doit etre refuse

**Cible legacy : accepte (defaut). Cible Laravel : REFUSE — corrige le 2026-08-17.**
Releve et mesure le 2026-08-17 · `tests/e2e/go-socle-auth.mjs`, bloc D.

> Etat : le portage refuse desormais le rejeu. Meme test, meme code, meme fenetre de 30 s,
> session neuve : `cible=laravel : 14 PASS / 0 FAIL / 0 ecart`. Le legacy, lui, l'accepte
> toujours — le correctif cote legacy attend une decision de l'exploitant.

### Ce qui a ete mesure

Sur `rw-test-super` (role 3, `can_admin_portal`), le **meme code TOTP** a servi a ouvrir
**deux sessions authentifiees** dans la meme fenetre de 30 secondes, depuis deux contextes
de navigateur distincts. La seconde connexion aboutit sur `/terms.php` exactement comme la
premiere.

Ce n'est pas une deduction de lecture : c'est le resultat du test.

### Pourquoi le garde existant ne protege pas

`legacy/auth/verify_2fa.php` porte bien une garde anti-rejeu :

```php
} elseif (isset($_SESSION['last_totp_hash']) && $_SESSION['last_totp_hash'] === $codeHash) {
    $error = t('2fa.error_reused');          // ligne 92
} elseif ($totp->verify($code, null, 1)) {
    $_SESSION['last_totp_hash'] = $codeHash; // ligne 96
    ...
    unset(..., $_SESSION['last_totp_hash']); // ligne 126
```

Deux defauts se cumulent :

1. **La cle n'est posee que dans la branche de succes (96) et supprimee onze lignes plus
   bas (126), dans la MEME requete.** Elle n'est jamais posee sur un echec. La condition de
   la ligne 92 ne peut donc jamais etre vraie : le garde est **inerte**.
2. **Meme corrige, il resterait sans effet.** Un garde porte par la *session* ne peut rien
   contre un rejeu venu d'une session *neuve* — or c'est exactement le scenario d'attaque :
   un tiers qui detient le mot de passe et a observe un code (hameconnage, epaule, journal
   mal purge) l'utilise depuis son propre navigateur.

C'est le motif « trois pieces justes, resultat inerte » : la comparaison est correcte, le
hachage est correct, le message d'erreur existe et est traduit — et rien ne se declenche.

### Ce qu'a fait le portage

`App\Services\Totp` determine **a quelle fenetre** appartient le code presente — un simple
booleen de validite ne suffisait pas, la garde a besoin du numero de fenetre — puis retient
la derniere fenetre consommee **par compte** et refuse toute fenetre deja consommee ou
anterieure.

Le stockage retenu est le **cache applicatif** (pilote fichier), et non une colonne en base.
Motif : le schema appartient au backend Python, et une migration SQL pour cette seule garde
aurait engage un schema partage. Contrepartie assumee : la garde est propre au frontend
Laravel et ne survit pas a une purge du cache. Elle couvre le scenario reel — un rejeu se
joue en moins de 30 secondes.

Si l'exploitant prefere une garde partagee entre les deux frontends, il faudra une colonne
cote Python, par une migration SQL. Aucune migration Laravel dans les deux cas.

### Portee cote production

Le defaut est present sur `main`, donc en production. Il n'est pas corrige cote legacy a ce
jour : la decision appartient a l'exploitant. Signale le 2026-08-17.

---

## E-02 — Le filtrage des routes backend compare des SEGMENTS, pas des prefixes

**Cible legacy : compare par debut de chaine. Cible Laravel : compare par segment.**
Mesure le 2026-08-18 · `tests/e2e/go-socle-passerelle.mjs`.

### Ce que fait le legacy

`legacy/api_proxy.php` tient une liste blanche de 48 prefixes et une liste de 26 prefixes
reserves a l'administration. Les deux sont comparees ainsi :

```php
if ($path === $prefix || strpos($path, $prefix) === 0) { ... }
```

C'est un filtrage par DEBUT DE CHAINE. Consequence : `/search` etant autorise, `/searchall`
l'est aussi ; `/groups` autorise `/groupsecret` ; `/tickets` autorise `/ticketsdebug`. Et
surtout, **toute route Python future dont le nom commence par un prefixe autorise devient
publique sans que personne ne l'ait decide**.

Mesure : sur le legacy, `POST /api_proxy.php/searchall` rend **405** — c'est-a-dire que la
passerelle l'a TRANSMIS au backend, qui n'a simplement pas de route de ce nom.

### Ce que fait le portage

`App\Support\RoutesBackend` lit chaque entree selon sa FORME :

| Forme | Sens | Exemple |
|---|---|---|
| finit par `/` | espace de noms | `/fail2ban/` couvre tout ce qui commence ainsi |
| finit par `_` ou `-` | racine deliberee | `/cve_` couvre `/cve_scan` |
| sinon | route exacte | `/search` couvre `/search` et `/search/xyz`, **pas** `/searchall` |

Meme requete cote portage : **403**, refusee avant d'atteindre le backend.

### Pourquoi le resserrement ne casse rien

Verifie AVANT de le faire, sur les **201 routes reellement declarees** dans `backend/` :
les deux filtres rendent le **meme verdict**, zero difference — pour la liste blanche comme
pour la liste reservee a l'administration. Le resserrement ne retire donc aucun acces
existant ; il refuse en plus des chemins comme `/searchall`, `/command_logger`, `/updateXYZ`.

Resserrer sans mesurer aurait ete une regression silencieuse : c'est la mesure qui autorise
le changement, pas l'intuition qu'il est plus sur.

### Une difference qui n'en est pas une

La re-authentification ponctuelle (step-up) n'est pas encore portee. La passerelle **refuse**
les routes qui l'exigent (`/policy/(sudo|sftp)/(deploy|remove)`, `/policy/rollback`) au lieu
de les transmettre. Ce n'est pas un ecart de parite mais un manque assume : accorder une
action qui donne root sans le second controle que le legacy exige serait un recul.

---

## E-03 — Les chargements du journal des commandes sont sequences

**Cible legacy : aucun sequencement. Cible Laravel : le dernier chargement gagne.**
2026-08-18 · `tests/e2e/go-page-commandlog.mjs`.

`legacy/commandlog/js/main.js` relance un chargement a chaque changement de filtre, sans
ordonner les reponses. Rien n'empeche donc, en principe, deux requetes rapprochees d'arriver
dans le desordre : l'utilisateur verrait alors le resultat d'un filtre qu'il vient de quitter.

**Ce qui a ete observe, et ce qui ne l'a pas ete.** Un premier passage a bien montre le
tableau conservant deux lignes la ou le filtre demandait zero. Mais le comportement **ne se
reproduit pas de facon fiable** : les executions suivantes, sur le legacy comme sur le portage,
donnent le bon resultat. L'ordre d'arrivee des reponses depend du reseau et de la charge.

Ce qui est donc affirme ici est mesure, et rien de plus :

- l'absence de sequencement dans le legacy est un **fait lisible dans son code** ;
- un resultat perime a ete observe **une fois**, sans reproduction fiable ;
- le portage numerote ses chargements et **seul le dernier ecrit** dans le tableau, ce qui
  retire la possibilite par construction plutot que par chance.

Le test porte l'attente sur les deux cibles ; elle passe des deux cotes aujourd'hui. Elle est
la pour attraper une regression du portage, pas pour accuser le legacy d'un defaut qu'on n'a
pas su reproduire.

---

## E-04 — Une décision d'approbation se prend **dans la page**, pas dans une boîte native

**Écart voulu.** Sur la page des approbations, le legacy demande le motif de rejet par
`prompt()` et confirme par `confirm()`. Le portage ouvre à la place une ligne de confirmation
**sous la demande concernée**, avec un champ de motif, un bouton *Annuler* et un bouton
*Confirmer*.

### Ce qui a motivé la divergence

Trois raisons, dans l'ordre où elles pèsent :

1. **La boîte native masque ce sur quoi on décide.** `confirm()` s'affiche au centre de la
   fenêtre, par-dessus le tableau, et recouvre précisément la ligne qu'on est en train de
   juger. On confirme une suppression de compte distant en lisant « Confirmer ? » sans plus
   voir sur quelle machine ni pour quel utilisateur.
2. **Elle ne se style pas.** Aucune des règles d'interface du portage — largeur, contraste,
   thème sombre, hiérarchie des boutons — ne s'applique à une boîte dessinée par le
   navigateur. Sur la seule action irréversible de la page, l'action destructrice et l'action
   d'annulation ont exactement le même poids visuel.
3. **Elle bloque tout pilotage.** Un dialogue natif suspend l'exécution JavaScript ; un script
   qui ne l'écoute pas reste bloqué jusqu'au délai d'expiration. Le test de cette page ne
   pouvait pas rejeter réellement une demande — il ne pouvait que constater que le bouton
   existe.

Le panneau en ligne lève les trois : la demande reste lisible pendant qu'on décide, le bouton
de confirmation porte la couleur de danger et le bouton d'annulation reste discret, et le test
peut mener un rejet réel de bout en bout.

### Ce que ça change pour qui utilise la page

Un geste de plus dans le cas du rejet — ouvrir le panneau, saisir le motif, confirmer — là où
le legacy enchaînait deux boîtes. L'approbation, elle, reste à un seul clic : elle n'est pas
destructrice et le backend applique de toute façon la règle des quatre yeux.

### Ce qui est mesuré

`tests/e2e/go-page-approvals.mjs` conduit un rejet **réel** sur une demande **réelle**, produite
par un `POST /reboot_server` du compte `rw-test-admin` (rôle 2) sur la machine `id=2`. Il vérifie
que la demande quitte l'onglet « en attente » et se retrouve dans l'onglet « rejetées ».

Le premier jet de ce test avait employé l'en-tête `X-User-Role: 3`. Le superadministrateur
**contourne la garde par conception** : aucune demande n'était créée, et les deux redémarrages
partaient directement vers la machine. Une sonde peut mesurer autre chose que ce qu'elle croit.

---

## E-05 — La règle des quatre yeux est **rendue visible**, pas seulement appliquée

**Écart voulu.** Le backend refuse qu'une personne approuve sa propre demande. Le legacy laisse
le bouton *Approuver* actif et affiche le refus après le clic. Le portage désactive le bouton et
porte l'explication dans son infobulle.

La règle ne change pas — elle reste appliquée côté backend, seul endroit où elle a une valeur.
Ce qui change, c'est le moment où on l'apprend : avant le geste plutôt qu'après.

### Ce qui n'est pas prouvé

**Cette branche n'est pas exercée par le test.** Elle exige un compte qui soit à la fois
demandeur d'une action soumise à approbation et porteur de `can_admin_portal`. Aucun des trois
comptes de test ne réunit les deux : `rw-test-admin` produit les demandes mais n'a pas la
permission d'ouvrir la page, `rw-test-super` a la page mais contourne la garde.

Aucun droit n'a été modifié pour forcer le cas. Accorder `can_admin_portal` au compte demandeur
changerait ce que mesurent toutes les autres attentes de la suite, et un test qui déplace les
droits pour se satisfaire ne mesure plus l'application réelle. Le comportement est donc **lisible
dans le code et non mesuré** — dit ici, plutôt que passé sous silence.

---

## E-06 — Le détail d'un écart est **affiché**, pas caché dans une infobulle

**Écart voulu.** Sur la page de dérive, le legacy met le détail de chaque écart dans l'attribut
`title` de la pastille. Le portage l'affiche sous la pastille, en petit — et uniquement pour les
catégories **qui ne sont pas conformes**.

### Pourquoi

Ce détail est la seule information actionnable de la page. « Fail2ban installé mais arrêté » ne
demande pas la même chose que « Fail2ban non installé », et « 3 politiques désirées, 1 déployée —
redéploiement requis » dit exactement quoi faire. Une infobulle ne s'ouvre ni au doigt, ni au
clavier, ni pour un lecteur d'écran : sur un téléphone, l'information n'existe tout simplement
pas.

Elle n'est montrée que pour les catégories en écart ou jamais évaluées. Une machine conforme n'a
rien à lire, et afficher « 0 politique sudo déployée » sur chaque ligne saine noierait les trois
lignes qui demandent une action.

### Ce que ça coûte

Des lignes plus hautes quand une machine cumule les écarts. Le compromis est assumé : la page
existe pour montrer ce qui ne va pas.

### Au passage — deux libellés qui ne disaient rien

Le legacy affiche `?` pour une catégorie jamais évaluée et `—` pour une catégorie absente. Le
portage écrit « Jamais évalué » et « Non évalué ». Un point d'interrogation dans un tableau de
conformité se lit aussi bien comme « inconnu » que comme « erreur ».

---

## E-07 — Le résultat d'un scan est **annoncé durablement**, pas dans une bulle fugace

**Écart voulu.** Le legacy signale la fin d'un scan par un `toast` qui s'efface au bout de
quelques secondes. Le portage écrit dans une région d'annonce (`role="status"`,
`aria-live="polite"`) qui reste jusqu'à l'action suivante.

Un scan modifie ce qui est affiché à l'écran. Une bulle qui disparaît avant qu'on ait fini de
relire le tableau ne dit pas si les valeurs qu'on regarde sont celles d'avant ou celles d'après.
La région persistante répond à cette question, et `aria-live` la fait annoncer aux lecteurs
d'écran — ce qu'aucune bulle du legacy ne fait.

Elle est vide au chargement et n'occupe alors aucune place (`:empty { display: none }`).

### Mesure

`tests/e2e/go-page-drift.mjs` relève l'annonce après chaque action (« Machine re-scannée. »,
« Scan terminé (3) »). Le relevé est un **constat**, pas une attente : le legacy n'a rien de
durable à annoncer, et exiger la même chose des deux cibles ferait échouer le test sur la cible
qu'il est censé caractériser.

---

## E-08 — La confirmation d'une restauration **empêche** l'erreur au lieu de la reprocher

**Écart voulu.** Le legacy demande le nom du fichier par `prompt()`, compare **après** la
saisie, et affiche « le nom ne correspond pas, restauration annulée ». Le portage ouvre une
confirmation sous la ligne concernée, avec le nom attendu en indication, et **le bouton de
confirmation reste inactif tant que la saisie diffère**.

### Pourquoi ce n'est pas cosmétique

La restauration fait un `DROP TABLE` sur la base partagée par le legacy, par Laravel et par le
backend Python. Une confirmation dont le seul rôle est de reprocher après coup ne protège de
rien : le geste a déjà été fait, et rien n'empêche de recommencer distraitement une seconde plus
tard. Un bouton inerte tant que le nom ne correspond pas transforme la confirmation en garde-fou
plutôt qu'en réprimande.

S'y ajoutent les trois raisons déjà énoncées pour E-04 : la boîte native masque la ligne sur
laquelle on décide, ne se style pas, et bloque tout pilotage — ce dernier point comptant double
ici, puisqu'il rendait le chemin d'erreur **intestable**.

### Ce que le test fait, et ne fait pas

`tests/e2e/go-page-backups.mjs` ouvre la confirmation, saisit un nom **volontairement faux** et
vérifie que le bouton reste désactivé et que rien ne change. Il ne mène **jamais** une
restauration à son terme : elle détruirait les sessions et les données des autres suites en
cours d'exécution. La restauration réelle reste donc non couverte, ce qui est dit ici plutôt que
laissé à supposer.

Côté legacy, le chemin d'erreur n'est pas mesurable : `prompt()` est refusé par le gestionnaire
de dialogue, ce qui annule l'action avant toute saisie. C'est un **constat**, pas un échec.

---

## E-09 — Le contrôle d'une sauvegarde dit **ce qu'il vérifie**, et ce qu'il ne prouve pas

**Écart voulu.** Le legacy nomme l'action « Vérifier » et l'explique ainsi, en trois endroits :

> Test de restauration non destructif : recharge la sauvegarde dans une base temporaire pour
> confirmer qu'elle est exploitable.

`backend/db_backup.py`, fonction `verify_backup()`, ne fait rien de tel. Il :

1. compare l'empreinte `sha256` au fichier `.sha256` posé à côté, s'il existe ;
2. décompresse le dump et le découpe en instructions ;
3. compte celles qui commencent par `CREATE TABLE` ;
4. déclare la sauvegarde valide si ce compte est supérieur à zéro.

**Aucune instruction n'est exécutée. Aucune base temporaire n'est créée.** Un dump qui se lit
parfaitement mais échouerait à se réappliquer — contrainte violée, ordre de tables incorrect,
moteur absent — passe ce contrôle sans réserve.

### Ce que le portage change

Rien au comportement : le portage appelle exactement la même route. Ce qui change, ce sont les
mots. L'action s'appelle « Contrôler », son aide dit ce qu'elle compare, et le verdict est
formulé « Sauvegarde lisible et intacte — 63 tables, 5 368 instructions, empreinte conforme »
plutôt que « valide ».

Un libellé qui promet plus qu'il ne tient est un défaut de sécurité à part entière : il conduit
à ne pas faire le contrôle que l'on croit déjà fait. Le seul moyen de savoir qu'une sauvegarde
se réapplique reste de la réappliquer — sur une base jetable, ce que ni le legacy ni le portage
ne proposent aujourd'hui.

### Ce qui n'est pas fait ici

Le backend n'est pas touché : ajouter une vraie restauration d'essai dans une base temporaire est
un chantier backend, hors périmètre de cette migration. Le défaut est consigné parmi ceux du
legacy ; l'arbitrage revient à l'exploitant.

---

## E-10 — Une erreur ne s'avale pas : montrer moins plutôt que montrer faux

**Écart voulu.** Quand un appel échoue, le legacy ne fait rien — il n'écrit pas le tableau, et les
lignes précédentes restent affichées. Le portage vide le tableau et dit pourquoi.

### Ce que cela produit sur le centre de tâches

`/tasks/list?status=<x>` répond **500 pour tout statut**. La cause est lisible dans les journaux
du backend :

```
ERROR:rootwarden:tasks_list: 1052 (23000): Column 'status' in where clause is ambiguous
```

La requête filtrée joint `machines`, qui porte elle aussi une colonne `status`, et la clause
`WHERE status = %s` n'est pas qualifiée. La requête de comptage, qui ne joint rien, passe — d'où
une erreur qui n'apparaît qu'à la seconde requête et laisse le total juste.

Conséquence sur le legacy, mesurée : sélectionner « Échec » laisse à l'écran **cent tâches
« Réussie »**, sans un mot. La page présente des données exactes comme si elles répondaient à une
question qu'on ne lui a pas posée. C'est pire qu'un tableau vide — un tableau vide se remarque.

### Ce que fait le portage

Il appelle la même route, obtient le même 500, et alors :

- vide le tableau ;
- écrit dans la région d'annonce que **le filtrage a échoué côté serveur**, en nommant le statut
  demandé ;
- explique que la liste a été vidée plutôt que de montrer des tâches hors sujet.

La règle générale : **montrer moins est préférable à montrer faux.** Un `if (réussi)` sans `else`
fabrique un écran rassurant et faux, exactement comme un `catch` vide fabrique un rapport
rassurant et faux.

### Ce qui n'est pas fait ici

Le correctif tient en un mot — `t.status = %s` au lieu de `status = %s` dans
`backend/routes/tasks.py` — mais il touche le backend, que cette migration laisse intact, et il
ferait passer le filtre de « toujours en erreur » à « fonctionnel ». C'est un changement de
comportement : il revient à l'exploitant de l'autoriser. En attendant, le portage ne prétend pas
que le filtre marche.

### Au passage — un état vide qui nomme son filtre

Le legacy affiche « Aucune tâche enregistrée » lorsqu'un filtre ne rend rien, ce qui est faux :
il y en a quatre cents, aucune ne porte ce statut. Le portage écrit « Aucune tâche avec le statut
« Échec » », et rappelle que revenir à « Tous les statuts » les fera réapparaître. Ce chemin
n'est pas atteignable aujourd'hui sur ce parc — le filtre échoue avant — mais le code le porte et
le libellé existe dans les deux langues.

---

## E-11 — La déduplication est annoncée **avant** le clic, et sur sa vraie clé

**Écart voulu.** Le legacy laisse créer un ticket, puis annonce « Ticket déjà existant
(dédoublonné) » dans une bulle. Le portage détecte la collision au moment où l'on choisit la
machine et l'affiche dans le formulaire, en citant le ticket concerné.

### Ce que le legacy annonce, et ce que le code fait

L'encart d'aide de la page dit :

> Les doublons sont **dédoublonnés** automatiquement pour ne pas créer plusieurs tickets pour la
> même alerte.

`create_or_get_ticket()` dédoublonne sur le triplet `(source, ref, machine_id)`. Pour un ticket
créé depuis le formulaire manuel, `source` vaut toujours `manual` et `ref` toujours `NULL` : **la
clé se réduit à la machine**. Deux tickets de sujets entièrement différents sur la même machine
sont donc fusionnés — ce qui n'a rien à voir avec « la même alerte ».

Conséquence, mesurée en direct : **le formulaire manuel ne peut créer qu'un ticket par machine,
une fois pour toutes.** Sur un parc de trois machines, il existe quatre créations possibles
(les trois machines, plus « aucune ») et ensuite plus aucune. Toute soumission ultérieure renvoie
`deduped: true`, et le legacy l'annonce dans une bulle qui s'efface.

Les tickets nés d'une CVE, eux, portent la référence du CVE : leur dédoublonnage se fait bien par
alerte, comme l'aide le laisse entendre. Le défaut ne concerne que le chemin manuel.

### Ce que fait le portage

- l'encart d'aide énonce la **vraie** clé, et la conséquence ;
- choisir une machine déjà pourvue affiche un avertissement **avant** le clic, avec le résumé du
  ticket existant ;
- le message de retour dit « aucun ticket créé » — pas « dédoublonné » — et rappelle la clé.

La règle reste appliquée par le backend. Le portage ne fait que la rendre lisible au moment où
elle compte.

### Ce que le test a dû apprendre

La première version du test créait toujours sur la machine 2. Elle a réussi une fois, puis a
rapporté deux échecs dès la cible suivante : la clé étant la machine, le premier passage avait
consommé le seul créneau. Le test choisit désormais une machine **sans** ticket manuel, exclut la
machine de production, et si aucun créneau n'est libre il le dit et joue la branche de fusion.
Les deux branches mesurent quelque chose.

---

## E-12 — Un libellé de champ n'est pas une pastille

**Défaut du portage lui-même, trouvé à l'image.** `.rw-etiquette` était défini **deux fois** dans
la feuille de style : d'abord comme libellé de champ, ensuite comme pastille de catégorie. La
seconde règle l'emportant, **tous les libellés de formulaire du portail étaient rendus en pastille
bleue** — y compris « Identifiant » et « Mot de passe » sur l'écran de connexion, le tout premier
écran du produit.

Aucune assertion ne l'a vu : les libellés étaient présents, corrects, traduits, et associés à leur
champ. Seule la capture le montrait. C'est exactement le défaut `escHtml()` défini deux fois
relevé dans le legacy, reproduit ici — et il aura vécu plusieurs vagues.

La pastille s'appelle désormais `.rw-badge`. Le libellé garde `.rw-etiquette`.

---

## E-13 — Les liens des résultats de recherche sont **traduits**, pas recopiés

**Écart voulu.** Le backend Python ne connaît qu'un frontend : l'ancien. `GET /search` renvoie,
pour chaque résultat, un lien de navigation écrit en dur — `/tickets/index.php`,
`/adm/audit_log.php`, `/update/index.php`. Le legacy les affiche tels quels. Le portage les fait
passer par `App\Support\LiensLegacy`.

### Le défaut que la migration fabrique elle-même

Chaque partie archivée transforme un de ces liens en **404**. Mesuré sur le legacy pendant cette
vague : une recherche sur « Ticket » rend trois résultats dont le lien `/tickets/index.php`
répond **404** — la page ayant été archivée à la vague précédente. La recherche est devenue un
menu qui mène à une page disparue, ce qui est exactement le défaut relevé dans le legacy — sept
404 ont vécu dans un menu que personne ne suivait — sauf qu'ici c'est le portage qui le crée.

Ce n'est pas un défaut du backend : il fait ce pour quoi il a été écrit. C'est au frontend de
décider où envoyer la personne, et c'est ce que fait le portage.

### Comment

`LiensLegacy::REMPLACEMENTS` associe chaque partie archivée à sa route Laravel. Un chemin est
normalisé (`/tickets/index.php` et `/tickets/` désignent la même partie), cherché dans la table,
puis :

- **trouvé** → lien interne vers la route portée, sans marqueur ;
- **absent** → lien vers l'ancien portail, avec la **même flèche que le menu**, `target="_blank"`
  et un `title` qui l'explique. Changer de portail sans le dire trahit la personne qui clique.

La table est la même en PHP et dans le navigateur : `pourLeNavigateur()` la construit à partir de
la constante, de sorte qu'il n'en existe jamais deux versions.

**Tenir cette table à jour est désormais une étape du cycle d'archivage**, et le test la garde :
il suit chaque lien rendu et vérifie qu'aucun ne répond 404.

### Ce que le test mesure exactement

Il ne se contente pas de compter des liens marqués — première version de l'attente, et elle était
fausse : une recherche dont tous les résultats sont portés n'en produit aucun, et l'attente
échouait alors que le comportement était juste. Ce qui est exigé est une **implication** : tout
lien sortant porte le marqueur, aucun lien interne ne le porte.

### Ce qui n'est pas mesuré

**La latence.** Le montage de fichiers de ce poste est ~258× plus lent que le système du
conteneur ; tout chiffre relevé ici dirait surtout combien de fichiers chaque cible charge. L'écart
relevé précédemment (2,2 s contre 24 ms) reste donc à re-mesurer sur un hôte Linux avant d'être
traité comme un défaut.

---

## E-14 — Rafraîchir la liste ne perd plus de colonnes

**Écart voulu.** La page des mises à jour affiche treize colonnes, rendues au chargement depuis la
base. Le legacy les recharge ensuite depuis `update/functions/list_machines.php`, qui n'en
`SELECT`ionne que **onze** : `maj_secu_date`, `maj_secu_last_exec_date` et `last_reboot` en sont
absentes.

`populateMachineTable()` les lit pourtant, avec un repli `?? "N/A"`. Cliquer « Rafraîchir »
remplace donc trois colonnes renseignées par « N/A », sans qu'on l'ait demandé et sans rien
annoncer.

### Mesuré

`tests/e2e/go-page-update-u1.mjs` compte les cellules renseignées avant et après le clic :

```
avant  {"majSecu":0,"majSecuExec":0,"redemarrage":1,"environnement":1}
après  {"majSecu":0,"majSecuExec":0,"redemarrage":0,"environnement":3}
COLONNES PERDUES : redemarrage
```

Seule `redemarrage` est mesurablement perdue sur ce parc — les deux autres colonnes étaient déjà
vides, et une colonne vide qui reste vide ne prouve rien. C'est écrit ainsi plutôt que d'affirmer
une perte de trois colonnes qui n'a pas été observée.

### Ce que fait le portage

Le rafraîchissement **et** le filtrage passent tous deux par `/filter_servers`, qui rend les
quatorze colonnes, exclut les machines archivées et applique le même cloisonnement par rôle. Un
rafraîchissement ne peut donc plus appauvrir ce qui était affiché — l'attente le vérifie sur la
cible portée.

### Au passage — la même donnée par deux chemins

`list_machines` existe deux fois : point d'entrée PHP dans `legacy/update/functions/` et route du
backend Python. Le legacy appelle le PHP ; la version backend, elle, exclut les machines
archivées. Deux implémentations de la même intention, qui ont divergé — c'est ce que le portage
évite en n'en gardant qu'une.

---

## Note de portage — un module porté par morceaux le DIT

`update/` est le premier module découpé (`MODULE-UPDATE.md`). U1 porte le tableau, les filtres et
les relevés par machine ; le lancement des mises à jour, la planification et le redémarrage
restent servis par l'ancien portail jusqu'à U6.

La page portée l'annonce dans un encart, avec un lien marqué vers la page complète. Faire
disparaître des capacités sans un mot ferait croire qu'elles n'existent plus — et l'entrée de menu
ne peut pas encore être redirigée, puisque la page legacy reste la seule complète.

---

## E-15 — Le journal a **un seul** point d'entrée, et sa zone générale sert vraiment

**Défaut du legacy, mesuré.** `appendLog` est défini **deux fois** :

| Fichier | Signature | Écrit dans |
|---|---|---|
| `update/js/domManipulation.js:34` | `appendLog(message)` | `#logs`, la zone générale |
| `update/js/apiCalls.js:645` | `appendLog(message, type, serverName)` | `#logs-container` ou un panneau |

Les deux sont des déclarations globales, et `index.php` charge `domManipulation.js` **puis**
`apiCalls.js` : la seconde définition gagne, la première est du code mort.

Conséquences, toutes deux mesurées :

- **`#logs` n'est alimentée par personne.** La page rend un cadre — 12 rem de haut dans le
  legacy — qui reste vide quoi qu'il arrive.
- **Les messages généraux se déposent parmi les panneaux de serveur.** `appendToLogs(msg)` appelle
  `appendLog(msg)` sans nom de serveur, donc la version d'`apiCalls.js`, qui écrit un `<p>` nu dans
  `#logs-container` — le conteneur des panneaux. Relevé du test : après un message général, `#logs`
  est vide et un élément hors panneau porte le texte.
- **`clearLog()` vide une zone toujours vide.** Cinq fonctions l'appellent.

C'est la troisième fois que ce défaut apparaît dans ce projet : `escHtml()` défini deux fois dans
le legacy, `.rw-etiquette` défini deux fois dans notre propre feuille de style (E-12), et
maintenant `appendLog`. Une déclaration globale ne signale jamais qu'elle en écrase une autre.

### Ce que fait le portage

Un point d'entrée **unique et nommé**, `window.rwJournal.ajoute(message, type, serveur)`, déclaré
dans une fermeture : rien ne peut l'écraser par mégarde, et les sous-lots U3 à U6 s'y adosseront.

Un message sans serveur va dans la zone générale, qui est réellement affichée et qui **dit qu'elle
est vide** quand elle l'est. Les panneaux de serveur restent séparés.

### Ce qui est repris à l'identique

Le contrat de rendu, vérifié par le même test sur les deux cibles :

- un panneau par serveur, créé à la première ligne et **réutilisé** ensuite ;
- un en-tête fixe portant le nom du serveur et une case « Suivre » ;
- une ligne de type `progress` qui **remplace** la précédente au lieu de s'empiler ;
- le type du message porté par la classe de la ligne ;
- un suivi automatique qui se désactive quand on remonte lire, et se réactive quand on redescend —
  avec le drapeau de défilement programmatique qui empêche la case de clignoter.

### Ce que le portage ajoute

Un bouton « Vider le journal ». Le legacy n'expose `clearLogs()` qu'aux actions internes : rien ne
permet de repartir d'un journal propre à la main. L'infobulle précise que cela n'efface **aucune
trace enregistrée** — la traçabilité durable vit dans le journal des commandes, pas ici.

---

## Invariants verifies identiques sur les deux cibles

Ceux-ci ne sont pas des ecarts : ils doivent se comporter **de la meme facon** avant et
apres portage. Ils sont mesures par `go-socle-auth.mjs`.

| Reference | Invariant |
|---|---|
| A | Une page protegee sans session renvoie vers la connexion (`/index.php`, `/profile.php`, `/adm/admin_page.php`) |
| B | Un mot de passe correct **seul** n'authentifie pas — il n'existe aucun chemin sans second facteur, pour aucun des trois roles |
| B | Entre le mot de passe et le second facteur, une page protegee reste refusee |
| C | Un mauvais mot de passe n'authentifie pas |
| E | L'identifiant de session **change** apres authentification complete (anti-fixation) |
| F | Apres le second facteur, on passe par les conditions d'utilisation |

Etat au 2026-08-17, cible legacy : **13 PASS / 0 FAIL / 1 ecart connu**.

---

## E-16 — « Aucun paquet en attente » ne veut pas dire « la machine est à jour »

**Défaut du legacy, mesuré.** `/pending_packages` lance sur la machine, en root :

```
apt-get update -qq 2>/dev/null; apt list --upgradable 2>/dev/null | grep -v '^Listing'
```

Deux choix, dans une seule ligne, font qu'un échec ne se voit pas :

- la **stderr** d'`apt-get update` part dans `/dev/null` — c'est là que vont les avertissements de
  dépôt injoignable ;
- les deux commandes sont séparées par un **point-virgule**, pas par `&&` : `apt list` s'exécute
  même quand le rafraîchissement a échoué, et rend alors l'ancien index.

La réponse vaut donc `{"success": true, "count": 0}` aussi bien pour une machine à jour que pour
une machine dont l'index n'a pas pu être rafraîchi. Le legacy affiche « Aucun paquet en attente. »
dans les deux cas.

**Mesuré sur la machine 2**, à quelques minutes d'intervalle :

| Appel | Ce qui remonte |
|---|---|
| `/pending_packages` | `{"count":0,"packages":[],"success":true}` |
| `/dry_run_update` (même machine, même moment) | `W: Failed to fetch http://deb.debian.org/... Temporary failure resolving 'deb.debian.org'` puis `W: Some index files failed to download. They have been ignored, or old ones used instead.` |

Le rafraîchissement avait échoué, et le constat annonçait quand même « rien à faire ».

### Ce que fait le portage

Il ne peut pas rendre l'information que le backend a jetée — le backend reste intact. Il cesse en
revanche de **promettre plus que ce que la fonction fait** : l'état vide porte une seconde ligne,

> Ce constat lit l'index local de la machine. Il ne garantit pas que cet index a pu être
> rafraîchi : un dépôt injoignable donne le même résultat qu'un système à jour.

C'est la même règle que pour `verify_backup()` et pour « Vérifier » (E-09) : un libellé ne promet
jamais plus que ce que la fonction fait, et on le sait en **lisant la fonction**.

**Ce qui reste à arbitrer** : faire dire au backend la différence entre « à jour » et « je n'ai pas
pu regarder » tient en deux caractères — `&&` au lieu de `;` — plus la remontée de la stderr. C'est
une modification du backend Python : elle n'est pas faite.

---

## E-17 — La simulation n'est **pas** portée : son flux porte le mot de passe root

**Défaut du legacy, mesuré, mécanisme établi.**

`/dry_run_update` ne collecte rien côté serveur : elle rend `Response(generate(), 'text/plain')`,
c'est-à-dire le flux SSH **tel quel**. Le legacy, lui, découpe ce flux sur `\n` et dépose **chaque
ligne non vide** dans le journal (`apiCalls.js`, `dryRunUpdate()`). Ce qui sort de la machine
s'affiche donc à l'écran sans filtre.

**Mesure**, machine 2, `service_account_deployed = 0` :

```
L1  "Début de l'exécution..."      <- ligne émise par le générateur
L2  <mot de passe root>            <- écho PTY, en clair
L3  W: Failed to fetch http://deb.debian.org/...
```

### Le mécanisme

`execute_as_root_stream()` porte un correctif — commentaire « Patch A09 » — qui jette **tout ce qui
précède le premier `\n`**, en supposant que l'écho du mot de passe est la première ligne renvoyée.

Reproduction du même enchaînement (`sudo -S -p '' sh -c 'id -u'`, PTY, écriture immédiate du mot de
passe), morceaux bruts lus sur le canal :

```
morceau 1 : '<mot de passe>\r\n'
morceau 2 : '<mot de passe>\r\n'
morceau 3 : '0\r\n'
```

**Le mot de passe est écho­té deux fois.** Le correctif n'en jette qu'un ; le second traverse. La
supposition « l'écho est la PREMIÈRE ligne » est juste — c'est « il n'y en a qu'une » qui est
fausse.

Le mode `service_account` (branche `NOPASSWD`) n'envoie aucun mot de passe et n'est pas concerné :
seule `srv-zabbix` porte `service_account_deployed = 1`. **Toutes les autres machines du parc sont
dans le cas qui fuit.**

### Ce que fait le portage

Rien : **la simulation n'est pas portée**. Porter une capacité dont on vient de mesurer qu'elle
affiche un mot de passe root reviendrait à la republier. La page renvoie vers l'ancien portail par
l'encart de portage partiel, qui nomme la simulation, et le test vérifie qu'aucune partie du
portage n'appelle `/dry_run_update`.

### CORRIGÉ le 2026-08-19, sur décision de l'exploitant

`execute_as_root_stream()` ne filtre plus sur une **position** mais sur le **contenu** : toute ligne
complète égale au secret est jetée, quel que soit son rang. Détail, tests et mesures dans le
CHANGELOG (v1.37.17) ; onze cas unitaires dans `backend/tests/test_ssh_echo_mot_de_passe.py`.

Mesuré après correctif sur la machine 2, quatre essais sur quatre : plus aucune trace du mot de
passe dans le flux, pas même un fragment de six caractères, et la sortie de la commande intacte.

**Le correctif vaut pour les deux portails** — ils consomment la même fonction. Il reste à le
reporter sur `main`.

Les trois points posés ici sont donc clos :

1. ~~corriger `execute_as_root_stream()`~~ — fait ;
2. `/dry_run_update` reste dans `RoutesBackend::LISTE_BLANCHE`, qui demeure un relevé **fidèle** de
   `ALLOWED_PROXY_PREFIXES` : la route ne fuit plus, la question de l'en retirer tombe ;
3. ~~`/security_updates` fuit de la même façon~~ — la même correction le couvre, **U6 est
   débloqué**.

La simulation reste toutefois **non portée à ce jour** : c'est un reste de portage, plus un
problème de sécurité. Elle rejoindra le portage avec U6.

---

## E-18 — La planification générale du legacy n'a jamais rien planifié

**Défaut du legacy, mesuré.** `saveAdvancedSchedule()` (`update/js/domManipulation.js`) envoie

```json
{"machine_id": 2, "date": "2026-09-15", "time": "03:30", "repeat": "weekly"}
```

à **`/schedule_update`**, qui lit `int(data.get('interval_minutes', 0))` et exige
`1 <= interval_minutes <= 10080`. La clé n'est pas dans le corps : la validation échoue **avant
toute session SSH**, et la route rend un 400.

Mesuré sur la machine 2, depuis la page legacy :

| Ce qui a été observé | Valeur |
|---|---|
| Route appelée | `schedule_update` |
| Statut rendu | `400` |
| `/etc/cron.d/auto_update_advanced` après le geste | `ABSENT` |

La route qui correspond au formulaire existe — **`/schedule_advanced_update`**, qui lit
`date`, `time` et `repeat` — et **personne ne l'appelle**.

Symétriquement, la fonction qui respecte le contrat de `/schedule_update`, `scheduleUpdate()`
(`update/js/apiCalls.js:401`), lit `document.getElementById('update-interval').value` : **cet
élément n'existe nulle part dans la page**, et la fonction elle-même **n'a aucun appelant**. Les
deux moitiés du mécanisme sont là ; elles ne se rejoignent pas.

### Ce que fait le portage

Il appelle `/schedule_advanced_update` — la route dont le contrat correspond au formulaire. C'est
une divergence assumée : porter fidèlement aurait porté un bouton qui échoue à chaque clic.

Le test vérifie les deux comportements, chacun sur sa cible : côté legacy, que la réponse est un
400 et qu'aucun fichier n'est écrit ; côté portage, que le cron attendu se trouve **sur la
machine**.

---

## E-19 — La récurrence promet ce que cron ne sait pas exprimer

**Défaut du legacy, mesuré.** Les deux formulaires offrent les mêmes quatre choix — ne pas
répéter, tous les jours, toutes les semaines, tous les mois. Ce que le backend en fait :

| Choix | `/schedule_advanced_update` (générale) | `/schedule_advanced_security_update` (sécurité) |
|---|---|---|
| `daily` | `mm hh * * *` | `mm hh * * *` |
| `weekly` | `mm hh * * 1` — **toujours lundi** | `mm hh * * <jour de la date choisie>` |
| `monthly` | `mm hh 1 * *` — **toujours le 1er** | `mm hh <jour de la date> * *` |
| `none` | `mm hh JJ MM *` | `mm hh JJ MM *` |

Deux écarts entre le mot et l'effet :

- **« Ne pas répéter » ne s'arrête jamais.** cron n'a pas de champ année : `mm hh JJ MM *` revient
  **chaque année** à la même date. Le seul choix qui promet une exécution unique est celui qui en
  programme une infinité.
- **La planification générale ignore la date choisie** pour l'hebdomadaire et le mensuel : elle
  écrit lundi, et le premier du mois. La planification de sécurité, elle, suit la date. Le même
  mot ne veut donc pas dire la même chose selon le formulaire.

**Mesuré** sur la machine 2, date du **mardi** 15/09/2026, 03:30, « toutes les semaines » :

| Formulaire | Fichier écrit | Expression |
|---|---|---|
| Générale | `/etc/cron.d/auto_update_advanced` | `30 03 * * 1` (lundi) |
| Sécurité | `/etc/cron.d/auto_security_update_advanced` | `30 03 * * 2` (mardi) |

### Ce que fait le portage

Il affiche, **avant le geste**, l'expression cron que le backend écrira et sa lecture en clair :

> Tous les lundis a 03:30 — 30 03 * * 1 — la planification generale place toujours l'hebdomadaire
> le lundi, quelle que soit la date choisie.

La réserve n'apparaît que lorsqu'elle s'applique : rien si la date choisie est déjà un lundi. Elle
se distingue par la teinte du liseré — ce n'est pas une erreur, c'est un écart entre le mot de la
liste et ce que cron sait dire.

Le test compare **l'aperçu affiché** au **fichier posé sur la machine** : deux artefacts
indépendants, l'un promesse d'écran, l'autre réalité de la machine. Une divergence entre les deux
serait un défaut du portage.

---

## E-20 — Avant l'action la plus destructive, le legacy affiche **la clé de traduction**

**Défaut du legacy, mesuré.** `rebootSelected()` pose deux `confirm()` natifs :

```js
if (!confirm(__('updates.reboot_confirm1').replace('%count', machineIds.length))) return;
if (!confirm(__('updates.reboot_confirm2').replace('%count', machineIds.length))) return;
```

Les deux textes existent, longs et soignés, dans `legacy/lang/fr/updates.php` — ils énumèrent les
conséquences (sessions SSH coupées, services interrompus 30-60 s, connexions clients perdues) et
annoncent qu'aucun retour en arrière n'est possible. Mais ils vivent dans le catalogue **PHP**, lu
par `t()`, alors que `__()` lit le catalogue **`js.`**. La clé n'y est pas.

**Relevé du test**, dialogues capturés au vol sur la page legacy :

```
boite 1 : « updates.reboot_confirm1 »
boite 2 : « updates.reboot_confirm2 »
```

L'opérateur voit donc, deux fois d'affilée, un identifiant technique. Aucune conséquence, aucun nom
de machine, aucun décompte — devant l'action la plus destructive du module.

Deux remarques supplémentaires, **lues** et non mesurées :

- même atteignable, le texte ne s'afficherait pas comme prévu : il contient `\n\n` dans une chaîne
  PHP à guillemets **simples**, où ces deux caractères restent littéraux ;
- `%count` est remplacé par `.replace()`, mais les catalogues du projet utilisent `:nombre` — la
  substitution vise une convention que ce fichier est seul à employer.

### La deuxième confirmation ne demande rien de plus que la première

Les deux boîtes posent la **même** question. Deux « OK » d'affilée ne sont pas deux décisions :
c'est un réflexe, et une confirmation qui se franchit par réflexe n'empêche rien. C'est le même
défaut que E-08, aggravé par le fait que le texte est illisible.

---

## E-21 — Le portage empêche l'erreur au lieu de la répéter

**Ce que fait le portage.** La décision se prend **en ligne**, sous l'action, dans un panneau qui :

- **nomme les machines** concernées (`1 machine(s) : Test-Server-Debian`) ;
- dit ce qui sera interrompu ;
- annonce **avant le geste** que la règle des quatre yeux s'applique : la demande sera mise en
  attente, pas exécutée — et qu'une demande déjà en attente pour la même machine n'est pas
  dupliquée et **garde le délai qu'elle portait** (le rapprochement se fait sur la cible `reboot`,
  qui ignore `delay_minutes`) ;
- naît avec son bouton de confirmation **désactivé**, et ne l'active que si le nombre de machines
  est **recopié**. Mesuré : une machine retenue, « 2 » saisi → bouton toujours désactivé ; « 1 »
  saisi → bouton actif.

**Le délai est offert.** `/reboot_server` accepte `delay_minutes` de 0 à 1440 et lance alors
`shutdown -r +N`, qui prévient les sessions ouvertes. Le legacy envoie **toujours** `0`. Le portage
propose immédiat, 5 min, 15 min, 1 heure — une capacité que le backend avait et que l'interface
cachait.

**Une demande d'approbation n'est pas une erreur.** Le backend rend `202` avec
`{'success': false, 'pending_approval': true, 'request_id': N}`. Le legacy ne regarde que `success`
et peint donc en **rouge** le fonctionnement nominal de la règle des quatre yeux. Le portage lit
`pending_approval` et annonce la demande pour ce qu'elle est, avec son numéro. Mesuré : zéro ligne
d'erreur dans le panneau du serveur après la demande.

**Le journal range la ligne sous le nom de la machine.** Le legacy cherche
`document.getElementById('server-' + id)` pour retrouver ce nom ; cet élément **n'existe pas** dans
la page — seul `#server-table-body` existe — et le nom retombe sur `#<id>`. Mesuré sur les deux
cibles, après la même demande :

| Cible | Panneau créé dans le journal |
|---|---|
| legacy | `#2` |
| portage | `Test-Server-Debian` |

### Ce que le test prouve, et comment

Un test de redémarrage qui redémarre vraiment est un accident : deux l'ont été le 2026-08-18, et
leurs traces sont encore dans `command_log`. Le test de U5 ne joue donc jamais de redémarrage, et
le prouve plutôt que de l'affirmer :

- il se connecte en **rôle 2**, jamais en rôle 3 — `approvals.gate()` laisse passer le superadmin ;
- il **vérifie avant de cliquer** qu'aucune demande *approuvée* n'attend d'être consommée, et
  s'arrête sans rien faire si ce n'est pas le cas ;
- il compte les traces `command_log` de contexte `reboot` **avant et après**. Elles ne s'écrivent
  qu'après l'exécution SSH : inchangées, la commande n'est jamais partie. Relevé : `2` avant, `2`
  après, sur les deux cibles ;
- il efface la demande qu'il a créée, si elle est encore en attente.

---

## E-22 — Deux routes du serveur que l'ancienne page n'atteignait pas

**Constat mesuré, sur la cible legacy.** `/apt_update` et `/custom_update` existent côté backend et
sont même autorisées par la passerelle, mais l'ancienne page ne les appelle **jamais** :

| Fonction | Fichier | Appelants | Éléments lus, absents de la page |
|---|---|---|---|
| `aptUpdate()` | `update/js/apiCalls.js:444` | **aucun** | `#apt-method`, `#specific-packages`, `#excluded-packages` |
| `customUpdate()` | `update/js/apiCalls.js:490` | **aucun** | `#update-packages`, `#exclude-packages` |

Chacune lèverait un `TypeError` dès sa première ligne si un bouton l'atteignait. Le bouton
`index.php:222`, libellé « mise à jour », appelle `updateLinux()` → **`/update`**, une autre route.

Relevé du test, côté legacy : aucun attribut `onclick` de la page ne nomme `aptUpdate` ni
`customUpdate`, et les cinq éléments sont introuvables dans tout `legacy/`.

C'est la troisième fois dans ce seul module : `scheduleUpdate()` lit `#update-interval`, absent
(E-18) ; `rebootSelected()` lit `#server-<id>`, absent (E-21). Un frontend accumule des demi-branchements que rien ne signale.

### Ce que fait le portage

Il ne les porte pas. Porter une capacité que l'ancienne page n'offrait pas, ce n'est plus migrer,
c'est concevoir — et cela mérite une décision, pas un effet de bord. La page le **dit** plutôt que
de les faire disparaître en silence : l'encart, qui annonçait un portage partiel, énumère
maintenant ce qui n'est pas repris et pourquoi.

**À arbitrer** : faut-il offrir la mise à jour de paquets choisis et l'exclusion de paquets ? Le
serveur sait les faire ; personne n'a jamais pu les demander.

---

## E-33 — L'export CSV du legacy n'est pas un CSV, en dev et en préprod

**Constat mesuré, sur la cible legacy, le 2026-08-20.** L'export d'un scan CVE rend un fichier dont
**1 465 blocs HTML** sont mêlés au contenu :

```
<b>Deprecated</b>:  fputcsv(): the $escape parameter must be provided as its
default value will change in <b>/var/www/html/security/cve_export.php</b> on line <b>83</b><br />
```

La chaîne complète, dans l'ordre :

1. `cve_export.php:9` requiert `auth/verify.php` ;
2. `verify.php:23-27` pose `error_reporting(E_ALL)` et `display_errors=1` **quand
   `DEBUG_MODE=true`** ;
3. le conteneur tourne sous **PHP 8.4.24**, où `fputcsv()` appelé sans son argument `$escape` lève
   un `E_DEPRECATED` ;
4. le fichier appelle `fputcsv()` **1 465 fois** (5 métadonnées + 1 ligne vide + 1 en-tête +
   1 458 vulnérabilités) — et chaque appel écrit son avertissement **dans `php://output`**, c'est-à-dire
   dans le fichier téléchargé.

Mesures croisées, même scan, même machine :

| | legacy | portage |
|---|---|---|
| blocs d'avertissement PHP dans le fichier | **1 465** | 0 |
| enregistrements après l'en-tête | **4 374** | **1 458** |
| dont porteurs d'un identifiant CVE | 1 458 | 1 458 |
| enregistrements étrangers au tableau | **2 916** (= 2 × 1 458) | 0 |
| taille | 788 096 o | 521 466 o |
| ligne vide entre métadonnées et en-tête | **un avertissement** | une ligne vide |

Le BOM UTF-8 est bien écrit **avant** la première ligne, des deux côtés — c'est ce qui le suit
immédiatement qui diffère. Lire le corps décodé donnait `<` en premier caractère parce que
`Response.text()` **retire le BOM** ; lire les octets bruts donne `EF BB BF` sur les deux cibles.
Les deux mesures disaient vrai, elles ne regardaient pas le même octet.

**Ce que ce défaut n'est PAS.** `srv-docker.env.example` pose `DEBUG_MODE=false` : une installation
de production neuve n'est pas touchée, `error_reporting(0)` supprimant l'avertissement. La
corruption est propre au **dev et à la préprod**. Elle n'en est pas moins réelle, et elle vaut pour
les trois fichiers de l'application qui appellent `fputcsv` — `security/cve_export.php`,
`security/compliance_report.php` (sous-lot S2) et `adm/audit_log.php` (module `adm/`, non porté).

### Ce que fait le portage

**Deux corrections, dont une structurelle.**

La charge utile est **assemblée en mémoire puis rendue d'un bloc**, au lieu d'être écrite au fil de
l'eau dans `php://output`. Rien ne part avant que tout soit écrit : aucun avertissement, quelle
qu'en soit la cause, ne peut plus s'y glisser. C'est la propriété à retenir — **un téléchargement ne
doit jamais hériter de `display_errors`**, et le seul moyen fiable de le garantir est que la sortie
ne soit pas ouverte pendant qu'on la calcule.

Et `$escape` est passé **explicitement, à sa valeur historique** (`'\\'`). La dépréciation de
PHP 8.4 porte sur l'*absence* de l'argument, pas sur sa valeur : le passer tait l'avertissement sans
changer un octet de la sortie. Basculer sur `''`, la valeur conforme à la RFC 4180 qui deviendra le
défaut, modifierait le rendu des cellules contenant un antislash — **c'est une décision, pas un
effet de bord de portage.**

Le test vérifie les deux propriétés côté portage (`verifiePortage`) et **mesure** le legacy sans rien
lui exiger : une suite qui échouerait en permanence sur la cible qu'elle caractérise finit par ne
plus être lue.

---

## E-34 — La branche de cloisonnement de l'export n'est mesurable par aucun compte de test

**Constat mesuré en base, le 2026-08-20.** `cve_export.php` porte un contrôle IDOR explicite : un
rôle < 2 ne peut exporter que les scans des machines de `user_machine_access`, et le refus rend
**404** — pas 403 — pour ne pas divulguer l'existence de la machine. Le portage le reproduit à
l'identique, avec **le même corps de réponse** que « aucun scan trouvé », vérifié par le test : deux
corps différents renseigneraient à eux seuls.

Cette branche exige un rôle 1 **portant `can_scan_cve`**. Aucun compte de test ne l'est :

| compte | rôle | `can_scan_cve` | ce qui se passe |
|---|---|---|---|
| `rw-test-user` | 1 | **0** | refusé par la permission, **avant** d'atteindre la branche |
| `rw-test-admin` | 2 | 1 | autorisé, mais le rôle 2 **saute** le cloisonnement |
| `rw-test-super` | 3 | 0 | autorisé par le contournement superadmin, **saute** aussi |

S'ajoute une seconde contrainte : `user_machine_access` ne porte que deux lignes (comptes 1 et 2),
donc **aucun compte de test n'a de machine attribuée**.

Le test le **constate** et le dit, plutôt que de déplacer les droits d'un compte pour se satisfaire :
`rw-test-user` est la référence « rôle 1, zéro permission » de toutes les autres suites, et lui
accorder une permission changerait silencieusement ce qu'elles mesurent.

**À arbitrer** : créer un quatrième compte de fixture — rôle 1, `can_scan_cve` seul, une ligne dans
`user_machine_access` sur la machine 2 — rendrait la branche mesurable sans toucher aux trois
existants. C'est un compte porteur d'une permission : la décision revient à l'exploitant.

---

## E-35 — L'export n'est atteignable qu'en tapant son adresse

Le legacy déclenche l'export depuis un bouton de `security/index.php`, page qui appartient au
sous-lot **S3**. La route `/export-cve` existe donc, est gardée et se teste, mais **aucune entrée de
menu et aucun bouton ne la désignent** dans le portage — c'est normal à ce stade, et dit ici pour que
personne ne cherche l'entrée manquante dans `App\Support\Navigation`.

Ce n'est pas un oubli : c'est la conséquence du découpage. S3 posera le bouton, et
`docs/migration/MODULE-SECURITY.md` le porte au tableau de ses sous-lots.
