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

---

## E-36 — Le portage restreint le rapport de conformité à `role >= 2`, et cela ne se mesure pas

**Décision D-1, prise par l'exploitant le 2026-08-20.** `compliance_report.php` annonce dans son
en-tête « Acces : admin (2) et superadmin (3) » et sa garde réelle est
`checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`. Aucune de ses sept collectes ne filtre par
utilisateur. Un rôle 1 porteur de `can_view_compliance` obtenait donc, en HTML comme en CSV et en
PDF : tout le parc avec IP, port et utilisateur SSH ; tous les comptes avec e-mail, présence de 2FA
et âge de clé ; **la posture par serveur avec les écarts en clair** — « sshd non audité »,
« N CVE critique(s) », « fail2ban absent » —, soit une liste de cibles priorisée ; et les dix
dernières modifications de pare-feu avec leur auteur.

C'est le **commentaire faux** qui a rendu le défaut durable : une relecture de l'en-tête ne pouvait
pas le voir. La route du portage porte `role:2` + `perm:can_view_compliance`.

**Cette divergence n'est mesurable par aucun compte de test**, et il faut le dire plutôt que de
laisser croire qu'elle est couverte. Elle exige un rôle 1 **portant** `can_view_compliance` :

| compte | rôle | `can_view_compliance` | legacy | portage |
|---|---|---|---|---|
| `rw-test-user` | 1 | **0** | 403 (par la permission) | 403 (par le rôle) |
| `rw-test-admin` | 2 | 1 | 200 | 200 |
| `rw-test-super` | 3 | 0 | 200 (superadmin) | 200 (superadmin) |

Le même résultat des deux côtés, pour deux raisons différentes — le test ne peut pas les
distinguer. Même manque de fixture que **E-34**, et le même arbitrage en attente.

### Ce que S2a mesure en revanche, et que rien ne mesurait encore dans ce module

`rw-test-admin` porte `can_view_compliance` et **pas** `can_admin_portal`. Il entre sur le rapport
et reste refusé sur `journal-commandes` : c'est cette paire, et elle seule, qui prouve qu'une
PERMISSION est lue et non un rôle.

**Le premier jet de cette assertion était un faux vert.** Elle visait `/commandlog/` côté legacy —
une partie **archivée**, qui rend 404 — et se contentait de « pas 200 ». Elle passait donc sans rien
mesurer. Corrigée : la page témoin doit être **vivante** (`groups/` côté legacy) et l'assertion exige
**403**, pas « autre chose que 200 ».

---

## E-37 — L'empreinte d'intégrité est reprise telle quelle, et elle est identique à l'octet

Le legacy calcule `hash('sha256', json_encode(compact('servers','users','remStats','date')))`.
L'antécédent porte les colonnes `totp_secret` et `ssh_key`, **qui ne figurent nulle part dans le
rapport** — elles n'en sortent qu'en booléen, vérifié aux trois rendus. Le lecteur ne peut donc pas
recalculer l'empreinte à partir de ce qu'il tient : une preuve d'intégrité invérifiable vaut autant
que pas de preuve. Le legacy énonce d'ailleurs la règle à l'endroit où il la viole — son commentaire
dit que les mots de passe chiffrés n'ont rien à faire « ni dans le hash SHA-256 d'integrite ».

**Le portage reproduit le calcul sans le corriger**, parce que le corriger change la valeur de
l'empreinte : les rapports déjà émis ne se vérifieraient plus. C'est la décision **D-2**, en attente.

**Mesure faite pour que cette décision se prenne sans risque** : à date figée, les deux
implémentations produisent **4 480 octets d'antécédent** et **le même SHA-256**
(`fdb844d0f497e8a6…`). Le portage n'introduit donc aucune dérive ; ce qui différait entre deux
lectures n'était que la date, arrondie à la minute. Mesure ponctuelle, pas propriété couverte par une
suite : la comparer en continu demanderait de figer la date des deux côtés.

---

## E-38 — Six libellés d'écarts échappaient à la parité FR/EN

Le calcul de posture du legacy construit ses motifs d'écart **en français, en dur**, dans le PHP :
`'sshd non audite'`, `"$crit CVE critique(s)"`, `"$high CVE haute(s)"`, `'fail2ban absent'`,
`"$dc derive(s) config"`, `'conforme'`. La colonne « Écarts » du rapport restait donc en français
quelle que soit la langue choisie — et c'est la colonne qui dit quoi faire.

Le portage en fait six clés, `conformite.ecart_*`, présentes en FR et en EN.

---

## E-39 — Les exports CSV et PDF restent servis par l'ancien portail, et la page le dit

Le rapport porte trois actions : imprimer, exporter en CSV, exporter en PDF. Seule l'impression est
portée — elle appartient au navigateur. Les deux exports sont les sous-lots **S2c** et **S2b**.

Plutôt que de faire disparaître deux boutons, la page les garde et les **marque** : même flèche que
le menu, `target="_blank"`, et une infobulle qui dit où ils mènent. Une annonce persistante en tête
de page le répète. Changer de portail sans le dire trahit la personne qui clique.

---

## Deux constats relevés pendant S2a, qui ne sont pas des divergences de portage

**Cinq comptes de test abandonnés faussent la posture du rapport.**
`tests/e2e/02-admin-users.test.mjs` crée des comptes `e2e_test_<horodatage>` et n'en supprime pas :
`e2e_test_1784983218694`, `…768927`, `…865542`, `…179068`, `…939393`, créés entre le 2026-07-25 et le
2026-08-12, tous actifs, rôle 1, **sans 2FA**. Le rapport annonce donc « 2FA activée : 4 / 10 » là où
le parc réel compte cinq comptes. Une page dont la raison d'être est de révéler une posture faible
la mesure faussement, à cause d'une suite qui produit ce qu'elle consomme sans nettoyer ce qu'elle
pose. Rien n'a été supprimé : ce sont des lignes d'une base partagée.

**Le garde anti-rejeu TOTP traverse les suites.** Il est par compte et en base : deux suites
consécutives qui ouvrent une session avec le même compte dans la même fenêtre de 30 s rejouent le
même code, la seconde est refusée, la session reste anonyme, et chaque appel rend **la page de
connexion en 200** — d'où des assertions « refusée » qui échouent sur un 200 sans qu'aucun compte ne
soit verrouillé. `go-socle-passerelle` a rougi ainsi une fois sur deux, et `go-page-update-u3`
mourait sur un `null` faute de trouver un bouton : ce n'était pas de la flakiness, c'était cela. Le
lanceur du LOT attend désormais le basculement de la fenêtre entre deux suites.

---

## E-40 — L'export CSV du rapport de conformité est corrompu, et une moitié du défaut était déjà corrigée

**E-33 se rejoue, à l'identique.** `compliance_report.php` écrit son CSV au fil de l'eau dans
`php://output` ; `verify.php` pose `display_errors=1` sous `DEBUG_MODE=true` ; PHP 8.4 déprécie
`fputcsv()` appelé sans son argument `$escape`. Mesure, même rapport, même instant :

| | legacy | portage |
|---|---|---|
| blocs d'avertissement PHP dans le fichier | **34** | 0 |
| premier enregistrement | **`<br />`** | son titre |
| section « posture par serveur » | **13 lignes** | **3** |
| section « serveurs » | **13 lignes** | **3** |
| section « utilisateurs » | **34 lignes** | **10** |

Le parc compte 3 machines et la base 10 comptes : le portage rend exactement la source, le legacy la
multiplie par les avertissements intercalés.

**Ce qui rend ce défaut remarquable, c'est qu'il était déjà connu.** La branche PDF **du même
fichier** porte cette parade, avec son commentaire :

```php
// Patch : purger tout output parasite (notices PHP captures par ob_start en
// mode debug) avant d'emettre le binaire PDF -> evite un PDF corrompu prefixe
// de "<br />..." selon les donnees.
while (ob_get_level() > 0) { ob_end_clean(); }
```

Quelqu'un a rencontré exactement ce défaut, l'a nommé précisément, et n'a protégé **qu'une branche
sur deux**. C'est le troisième « à moitié corrigé » relevé dans ce seul fichier, après l'en-tête qui
annonce une garde plus stricte que le code (E-36) et la règle du hash énoncée à l'endroit où elle est
violée (E-37).

### Ce que fait le portage

La charge utile est **assemblée en mémoire puis rendue d'un bloc** — rien ne part avant que tout soit
écrit, donc aucun avertissement, quelle qu'en soit la cause future, ne peut s'y glisser. Et `$escape`
est passé **explicitement, à sa valeur historique** : la dépréciation porte sur l'*absence* de
l'argument, pas sur sa valeur.

Le BOM part par `fwrite` et non par `fprintf`. Le legacy écrit
`fprintf($out, chr(0xEF).chr(0xBB).chr(0xBF))` — le deuxième argument de `fprintf` est un **format**.
Les trois octets du BOM n'en contiennent aucun de spécial, donc il s'en sort — par chance, pas par
construction.

---

## E-41 — Le CSV et la page ne couvrent pas la même population de comptes

Le CSV parcourt **tous** les comptes (`compliance_report.php:173`) ; le tableau de la page saute les
inactifs (`:457`, `if (!$u['active']) continue;`). Deux vues du même rapport, deux périmètres.

**Repris tel quel.** Restreindre l'un ou élargir l'autre change ce que le rapport *dit* — c'est une
décision, pas un effet de bord de portage. Le service nomme donc les deux populations séparément
(`comptes` et `comptesActifs`) pour qu'on ne les confonde pas, et le test l'asserte : la section du
CSV doit porter **10** comptes quand la base en a 10, actifs ou non.

**Complété en S2b : le PDF suit le CSV, pas la page.** La boucle des comptes du PDF
(`compliance_report.php:262`) n'a elle non plus **aucun filtre** — vérifié en lisant la branche, puis
mesuré : les 10 comptes de la base sont nommés dans le PDF. Ce sont donc les **deux exports** qui
couvrent tous les comptes et la **page seule** qui saute les inactifs. Le périmètre reste repris tel
quel des deux côtés.

---

## E-42 — Une même donnée, un seul calcul

La page et l'export présentent les mêmes chiffres. `Conformite::rapport()` les calcule **une fois**,
les deux contrôleurs s'y adossent. La date est passée par l'appelant et non calculée dans le service :
elle entre dans l'antécédent de l'empreinte, et deux appels à une minute d'intervalle produiraient
deux empreintes pour un même rapport.

Ce n'est pas une divergence avec le legacy — c'est la prévention de celle qui a été trouvée sur la
page des mises à jour, où le premier rendu et les relectures venaient de deux requêtes qui ne
s'accordaient ni sur les machines archivées ni sur le format des dates. Deux calculs séparés
finissent par ne plus dire la même chose.

---

## Deux suites corrigées, pour la même raison

**`go-page-search` écrivait l'adresse du legacy en dur** (`const LEGACY = 'https://localhost:8443'`).
Dès que `LEGACY_URL` a pointé sur l'adresse de la VM, les liens legacy ont cessé de commencer par la
constante, ont été classés comme **internes**, et leur `target="_blank"` a fait tomber « aucun lien
interne n'est marqué ». **Deuxième suite atteinte** après `go-socle-navigation` : un test ne doit pas
écrire en dur une valeur de *déploiement*, il doit la lire à la même source que la page — sinon il la
contredit. Les deux lisent désormais `app.url_legacy`.

**`go-page-update-u3` mourait sur un `null`** vingt lignes après l'assertion qui le détectait :
`TypeError` non rattrapée, `lignes` jamais imprimé, « 0 PASS » rapporté. L'échec a été diagnostiqué
trois fois de suite comme de la flakiness, faute de savoir ce que la page contenait. Elle sort
maintenant par le chemin normal, en disant l'URL réellement atteinte, le titre de la page, et si
c'est l'écran de connexion ou le bouton qui manque. **Une suite qui meurt sur un `null` ne dit pas ce
qu'elle a mesuré.**

---

## E-43 — La branche PDF portait la moitié corrigée du défaut, et le portage n'a rien à purger

`compliance_report.php` commet E-33/E-40 dans sa branche CSV et s'en protège dans sa branche PDF, à
douze lignes d'écart :

```php
while (ob_get_level() > 0) { ob_end_clean(); }   // avant $dompdf->stream()
```

Son commentaire nomme le défaut mot pour mot — « évite un PDF corrompu préfixé de `<br />...` ».
**C'est la seule des cinq occurrences du motif « le legacy documente son défaut là où il le commet »
où la moitié protégée l'était vraiment**, et la mesure le confirme : côté legacy, le PDF commence
bien par `%PDF-` en tout premier octet et ne porte aucun fragment HTML. La suite exige la propriété
**des deux côtés** — c'est ce qui en fait une mesure et non une hypothèse.

L'`ob_start()` de la ligne 276 est en revanche **vestigial** : le HTML est monté par concaténation de
chaînes, rien n'est capturé. Il n'existe que pour donner quelque chose à purger à `ob_end_clean()`.

**Le portage ne le reproduit pas.** Il n'ouvre aucun tampon, donc il n'a rien à purger : la charge
utile est assemblée en mémoire puis rendue d'un bloc, comme en S1 et S2c. Reproduire la purge aurait
été reproduire le remède d'une maladie qu'on n'a pas — et un lecteur aurait cru le portage exposé.

---

## E-44 — Le PDF du portage en dit plus que celui du legacy : une section et une colonne

Le PDF du legacy porte **six** sections, sa page en porte sept ; le tableau de ses comptes porte cinq
colonnes, celui de sa page six. **Ce qu'on imprime en dit donc moins que ce qu'on regarde**, alors que
c'est la version imprimée qu'on archive et qu'on transmet à un auditeur.

Le portage aligne le PDF sur la page :

| Ajout | Ce qu'il rend visible |
|---|---|
| section **pare-feu** | l'historique des règles appliquées, absent du PDF du legacy |
| colonne **âge de la clé (jours)** | la tuile « clés de plus de 90 jours » compte, sans jamais dire *lesquelles* |

**Divergence voulue, et assumée comme telle** : elle ne change aucun calcul, elle expose des données
que le rapport possédait déjà. Les deux sections conditionnelles du portage — pare-feu et supervision
— suivent la même règle que le legacy pour la seconde : *pas de donnée, pas de section*. Sur le parc
actuel les deux collections sont vides, donc **ni l'une ni l'autre n'apparaît** ; l'ajout ne se lira
que sur un parc qui a de l'historique. Dit autrement : cette entrée décrit une capacité, pas un
changement visible aujourd'hui.

---

## E-45 — Un tableau qui change de page perdait son en-tête, et aucune assertion ne pouvait le voir

Le legacy monte tous les tableaux de son PDF en `<table><tr><th>`, **sans `<thead>`** — zéro
occurrence dans les 105 lignes de la branche. dompdf ne répète alors aucun en-tête d'une page à
l'autre. Mesuré sur le document réel :

| | pages | lignes de comptes | en-tête sur la page qui les porte |
|---|---|---|---|
| legacy | 2 | **les 10, page 2** | **absent** — resté page 1 |
| portage | 2 | 7 page 1, 3 page 2 | présent sur les deux |

Côté legacy le tableau des comptes arrive donc **en entier** sur une page où rien ne nomme ses
colonnes : dix lignes de « Oui / Non / — ». Sur un rapport de conformité, dont la raison d'être est
d'être lu par quelqu'un qui ne connaît pas l'outil, la colonne anonyme ne dit rien.

**Le portage enveloppe ses six en-têtes dans `<thead>`** (plus `display: table-header-group`, écrit
explicitement pour que l'intention ne dépende pas d'un défaut de feuille de style). Divergence voulue.

Deux choses à retenir de la façon dont ce défaut a été trouvé :

1. **Aucune assertion de texte ne pouvait le voir.** Sur le document aplati, l'en-tête est présent —
   une fois. Il a fallu **rendre les pages en images** (`pdftoppm`) et les regarder. C'est le
   quatrième défaut d'affichage que seule l'image révèle.
2. **La mesure a donc dû devenir page par page** pour être ancrée dans un test : `pdfinfo` donne le
   nombre de pages, `pdftotext -f N -l N` le texte de chacune, et l'assertion exige que toute page
   portant au moins deux noms de comptes *lus en base* porte aussi l'en-tête. Une propriété de mise
   en page ne se mesure pas sur un document aplati.

Côté legacy la propriété est **mesurée et rendue en constat** (`verifiePortage`), pas en échec : le
rejeu du LOT compte tout `FAIL` comme une régression, et un écart assumé n'en est pas une.

---

## Trois constats relevés pendant S2b, qui ne sont pas des divergences de portage

**L'empreinte d'intégrité n'est pas reproductible, et c'est mesuré.** E-42 l'annonçait comme une
hypothèse (« deux appels à une minute d'intervalle produiraient deux empreintes ») : deux générations
du même rapport, à 17 h 11 et 17 h 16, donnent bien deux empreintes différentes. L'instant de
génération entre dans l'antécédent. Conséquence : **l'empreinte ne peut pas servir à vérifier que deux
exports décrivent le même état** — elle ne prouve que la non-altération d'un fichier donné. Comportement
du legacy, repris tel quel ; à trancher avec **D-2**, qui porte déjà sur le contenu de cet antécédent.

**Le mot de passe root de la base sortait dans les messages d'échec des suites.** `mysql` ne prend son
mot de passe que par la ligne de commande, et `execFileSync` recopie tout l'argv dans le message quand
la commande échoue : une suite qui tombait imprimait `docker exec ... mysql -uroot -p<le mot de passe>`.
C'est le défaut corrigé côté SSH en **v1.37.17**, réapparu dans l'outillage de test. Les trois suites
du module `security/` lisent désormais la base par `tests/e2e/lib-base.mjs`, qui expurge l'erreur.
**Trois suites plus anciennes portent encore le motif** (`07-maintenance`, `08-approvals`,
`09-docker-idor`) : hors périmètre de S2b, signalé.

**Le même lecteur de base était recopié cinq fois** dans les trois suites du module. Cinq copies d'un
accès à la base divergent : la première qui apprend quelque chose ne l'apprend pas aux autres. C'est
la même raison qui a fait retirer la copie des prérequis du LOT de `rw-pieges`.

---

## E-46 — Le filtre des machines archivées manquait dans la branche du rôle le moins privilégié

`legacy/security/index.php` liste les machines par deux requêtes selon le rôle :

| Branche | Filtre `lifecycle_status != 'archived'` |
|---|---|
| `role >= 2` (`:42-45`) | **présent** |
| `role 1` (`:47-54`) | **ABSENT** |
| la requête de S4 (`:292-296`) | présent |

Deux moitiés sur trois corrigées, et l'oubli tombe **précisément sur la branche de l'utilisateur le
moins privilégié** : un lecteur voit — et peut faire scanner — une machine qu'un administrateur ne voit
plus. Le module CVE du backend ne compense rien : `grep -c lifecycle_status` rend **0** sur
`backend/routes/cve.py` **et** sur `backend/cve_scanner.py`, alors que dix autres fichiers du backend
l'appliquent.

**Le portage pose le filtre UNE FOIS, avant le branchement de rôle**
(`ScansCve::machinesVisibles()`). Il ne peut plus manquer dans une moitié.

---

## E-47 — Le résumé de parc fuyait ce que la liste juste en dessous filtrait

`index.php:196-207` n'est joint **ni à `machines` ni à `user_machine_access`**. Il agrège le dernier
scan complet de **toutes** les machines de la base, archivées comprises, et s'affiche dès que le compte
en voit deux. Conséquences, chacune mesurée :

- un rôle 1 avec deux machines attribuées lit les compteurs CVE de **la flotte entière** ;
- un administrateur y voit des machines **absentes du tableau qui suit**, puisque la liste exclut les
  archivées et que l'agrégat les inclut.

**Le portage calcule le résumé SUR LA LISTE QU'IL AFFICHE** (`ScansCve::resumeParc($ids)`), avec les
mêmes identifiants que les cartes en dessous. Précédent accepté : `Conformite::serveurs()` en S2a a
ajouté le filtre de cycle de vie que le legacy n'avait pas.

**Un agrégat doit porter le même périmètre que la liste qu'il résume.**

---

## E-48 — La permission ne gardait que la page ; dans le portage elle garde la requête

Sixième occurrence du motif, et la plus large mesurée à ce jour.

| Endroit | Ce qui est appliqué |
|---|---|
| la **page** `index.php:37-38` | `checkAuth([USER,ADMIN,SUPERADMIN])` + `checkPermission('can_scan_cve')` |
| le **proxy** `api_proxy.php` | rôle ≥ 1, `/cve_` en liste blanche (`:119`), **absent** de `$ADMIN_ONLY_PREFIXES`, et `checkPermission` n'y figure pas une seule fois |
| la **passerelle** `RoutesBackend.php:35` | `/cve_` en liste blanche, **absent** de `ADMIN_SEULEMENT` — relevé fidèle du legacy, défaut inclus |
| le **backend** `cve.py` | `cve_results` et `cve_compare` : `require_api_key` + `require_machine_access` + `threaded_route`. **Ni rôle, ni permission.** |

`grep -c require_permission backend/routes/cve.py` rend **0** sur 19 routes, et `can_scan_cve`
n'existe dans tout le backend **que dans une fixture de test**. Un rôle 1 sans la permission peut donc
lire les CVE de ses machines, **déclencher un scan SSH**, et lire les tendances de la flotte ; un rôle 2
sans la permission a l'accès CVE complet, lecture **et** écriture, sur toutes les machines.

**Le portage ne passe pas par la passerelle.** Il lit la base derrière `role:1` + `perm:can_scan_cve`,
comme S1. La permission garde donc enfin la requête, sans qu'une ligne du backend Python soit touchée.
Cela referme du même coup un second écart : `require_machine_access` résout l'identifiant de machine
par le **corps JSON** d'abord (`helpers.py:331-332`) alors que les trois routes GET lisent
**exclusivement** `request.args` — le garde autoriserait une machine et la route en servirait une
autre. Aucune des deux passerelles ne relaie le corps d'un GET, donc c'est fermé aujourd'hui, **mais
par accident et non par décision**. Les deux doivent être dits.

**Ce que le portage ne corrige PAS** : les routes backend restent telles quelles, et un appel direct à
`/api/gateway/cve_results` reste ouvert à un rôle 1 sans permission. Il faut une décision de
l'exploitant sur le backend — elle est en attente.

---

## E-49 — Le tableau des vulnérabilités se désalignait dès qu'on l'utilisait

L'en-tête du legacy porte **six** colonnes — CVE, Package, Version, Severite, Resume, Suivi — et
**un seul** de ses quatre générateurs de lignes en produit six. Mesuré dans le navigateur, sur la
machine réellement scannée :

| geste | ce que devient le tableau |
|---|---|
| chargement | 50 lignes, **toutes à 6 cellules** |
| « Voir plus » | 100 lignes : **50 à 6 cellules ET 50 à 5** |
| recherche | 9 lignes, toutes à **5** |
| filtre | 100 lignes, toutes à **5** |

Le même tableau mélange donc les deux formes après une pagination, l'en-tête ne correspond plus aux
lignes, et la colonne de suivi disparaît dès qu'on filtre — **sans aucune erreur JS**. Et le
commentaire de `sevCell` (`js/main.js:45-48`) revendique précisément d'avoir « centralisé pour rester
coherent entre buildRows et la pagination » : il a centralisé **une colonne sur six**, et la jumelle
non protégée est justement celle qui manque.

**Dans le portage il n'existe qu'UN générateur de lignes**, appelé par tous les gestes, et l'en-tête
est rendu par le gabarit — traduit, une seule fois. Les trois assertions correspondantes passent au
vert côté portage et sont rendues en constat côté legacy.

Deux effets de bord refermés au passage :

- **le compteur « n / m » existe même en dessous de 50 CVE.** Le legacy ne le crée que s'il y a une
  page suivante, alors que sa recherche et ses filtres l'écrivent dans tous les cas — gardé par un
  `if`, donc silencieusement sans effet. Non mesurable sur ce parc, la seule machine scannée en portant
  1458 : dit ici plutôt que prouvé ;
- **le bouton « Voir plus » se cache au lieu de quitter le DOM** : un élément qui disparaît et
  réapparaît fait perdre le focus.

---

## E-50 — Aucune donnée CVE n'était rendue par `textContent`

Tout le tableau du legacy est assemblé par interpolation dans `innerHTML`, et son `esc()`
(`js/main.js:739`) échappe `& < > "` **mais pas l'apostrophe**, alors que son docblock affirme
« éviter toute injection XSS via les données CVE ». Sur 32 appels, **deux** interpolent dans une chaîne
JS délimitée par apostrophes à l'intérieur d'un attribut (`:485` `onchange`, `:492` `onclick`) et tous
deux ne reçoivent que `f.cve_id`. Un identifiant CVE ne porte pas d'apostrophe : **le défaut est latent,
pas armé**, et ces deux sites appartiennent à la colonne « Suivi », donc à S5.

**Le portage rend tout par `textContent`**, et le lien reçoit son adresse par propriété avec
`encodeURIComponent`. Rien n'est interpolé : la question ne se pose plus.

---

## Quatre constats de S3, dont trois choses que ce sous-lot ne peut pas prouver

**Ce qui n'est pas mesurable, et pourquoi c'est dit plutôt que contourné.**

1. **Le diff de deux scans.** La base ne porte qu'**un** scan complet ; seul l'état « moins de deux
   scans » est mesurable, et la suite l'exige. Fabriquer un second scan changerait les chiffres que les
   suites de conformité assertent déjà — le remède serait pire.
2. **Le compteur absent en dessous de 50 CVE** (voir E-49) : la seule machine scannée en porte 1458.
3. **La branche rôle 1** — donc E-46 et E-47 — exige un compte de fixture portant `can_scan_cve` **et**
   une ligne `user_machine_access` (**D-5**). Sans lui, le cloisonnement du portage est écrit et relu,
   pas mesuré. Un test qui déplacerait des droits pour se satisfaire ne mesurerait plus l'application
   réelle.

**Et un constat de mise en page, trouvé à l'image et nulle part ailleurs.** Le premier rendu du
portage était correct au test et fautif à l'œil : l'identifiant CVE se coupait sur **trois lignes**
(« CVE- / 2026- / 53046 »), et le résumé, en s'étalant, poussait le tableau à **1789 px** dans un cadre
de 1048 — chassant hors du champ la colonne « Suivi », celle dont l'absence était justement le défaut
du legacy. La rétablir puis la chasser de l'écran n'aurait rien réglé. Corrigé en trois temps, chacun
re-mesuré : l'identifiant ne se coupe plus, le résumé se tronque en gardant son texte entier en
infobulle (1048 px, le cadre exact), et sous 720 px le préfixe `CVE-` s'efface avec des cellules
resserrées — **367 px au lieu de 427**, ce qui ramène la sévérité, la donnée qui décide, dans le champ
sans défilement. À 390 px la colonne de suivi demande encore un petit défilement, que le cadre
indique : elle ne porte aujourd'hui qu'un tiret, et devra être revue quand S5 la rendra actionnable.

---

## E-51 — Le garde anti-fréquence n'était pas rejoué à la modification

**Le défaut central de S4, et le seul de la migration mesuré d'abord dans le code puis PROUVÉ EN
FONCTIONNEMENT.**

À la création, `backend/routes/cve.py:500-517` valide l'expression, calcule **deux** occurrences
successives et refuse en dessous de 600 s. Son commentaire nomme le risque :

> Patch A04-INSEC-N1 […] refuse les schedules plus frequents que 10 minutes. Sans ce clamp,
> `* * * * *` lancait un scan par minute → ban OpenCVE upstream + DoS interne + abus admin malveillant

Au `PUT` (`cve.py:549-566`), `cron_expression` est ajouté à la requête **ligne 556, avant toute
validation**. Le bloc suivant ne recalcule que `next_run` — ni `is_valid`, ni comparaison de deux
occurrences — et un `except Exception: pass` avale l'échec : l'`UPDATE` de la ligne 570 écrit
l'expression quand même.

Mesuré par `go-page-cve-planification`, sur la pile réelle :

| geste | legacy | portage |
|---|---|---|
| création `* * * * *` | **400**, « Fréquence cron trop élevée », rien écrit | **400** |
| **modification** vers `* * * * *` | **200**, et la base porte `* * * * *` | **400**, base intacte |
| modification vers `pas du cron` | **200**, et la base porte `pas du cron` | **400**, base intacte |

**Neuvième « à moitié corrigé » du projet**, et le plus coûteux : le commentaire qui nomme le risque
est quarante lignes au-dessus de la branche non protégée. Conséquence si elle était exploitée — un
scan SSH par minute sur les machines ciblées, `srv-zabbix` en production comprise, plus un
bannissement probable côté OpenCVE.

**Dans le portage, la même fonction valide les deux chemins** (`PlanificationsCve::valide()`, avec un
paramètre `$creation` qui ne change **que la liste des champs obligatoires**, jamais la sévérité des
contrôles). Il n'existe plus d'endroit où le clamp puisse manquer.

**Le correctif backend, lui, n'est pas fait** : les cinq routes Python restent telles quelles, et un
rôle 2 sans `can_scan_cve` peut encore les appeler. C'est une décision de l'exploitant, en attente.

---

## E-52 — Les routes de planification du portage remplacent celles du backend

Cinq routes internes — liste, création, modification, suppression, aperçu — sous `role:2` +
`perm:can_scan_cve`, au lieu de relayer `cve_schedules` et `cron_preview` par la passerelle. Même
décision qu'en S3 (E-48) et pour les mêmes trois mesures : `require_permission` apparaît **zéro** fois
sur les 19 routes CVE du backend, le garde d'accès ne lit pas le même paramètre que sa route, et il ne
refuse pas quand aucun identifiant n'est trouvé.

`role:2` **et non `role:1`** : le bloc du legacy vit sous `if ($role >= 2)`
(`legacy/security/index.php:231`) et ses cinq routes portent `require_role(2)`. La consultation reste
ouverte au rôle 1, l'écriture non — la garde est reprise cran par cran.

Conséquence sur la caractérisation : **le même test vise deux surfaces différentes**, par une table de
chemins par cible. C'est assumé — la propriété mesurée est le **comportement**, pas l'adresse. Aucune
dépendance ajoutée : `dragonmantank/cron-expression`, déjà présent comme dépendance du framework, sait
valider une expression et calculer deux occurrences successives, et rend la **même échéance** que
`croniter` côté Python (vérifié : `0 3 * * *` → `2026-08-21 03:00:00` des deux côtés).

---

## E-53 — La phrase de récurrence était produite en Python, donc intraduisible

Le legacy rend, à côté des prochaines dates, une **phrase en français** fabriquée par
`cve.py:460-474` : « Tous les jours a 03:00 », « Toutes les N minutes », avec ses abréviations de jours
`dim/lun/mar/…`. Elle traverse le proxy et s'affiche telle quelle : **aucun mécanisme du portage ne
peut la traduire**, et elle restera française pour un utilisateur anglais.

**Le portage ne la reprend pas.** Il affiche les **cinq prochaines exécutions réelles**, calculées en
PHP et mises en forme dans la langue de la session. Elles disent la même chose et davantage — et elles
disent aussi, en rouge et au fil de la saisie, quand la fréquence est refusée, ce que le legacy ne
signale qu'au moment de l'envoi.

---

## E-54 — Une planification n'avait pas d'auteur

La colonne `created_by` existe (`mysql/init.sql:317`, clé étrangère vers `users(id)`) et le legacy
**ne l'écrit jamais** : `cve.py:522-526` insère sept colonnes, pas celle-là. Toute planification créée
par l'API reste donc sans auteur, alors que `get_current_user()` fournit l'identifiant juste à côté.

Ce n'est pas le défaut d'attribution habituel — la valeur ne vient pas du client, elle est simplement
**absente**. Aucune planification ne se reproche à personne.

**Le portage la remplit depuis la session.** Mesuré : `created_by = NULL` côté legacy, `15` côté
portage — l'identifiant du compte qui a créé la ligne. La liste affiche la colonne « Créé par ».

---

## E-55 — Trois validations manquaient, et l'une rendait un 500 au lieu d'un 400

| champ | legacy | portage |
|---|---|---|
| `target_type` | **aucune liste blanche**, alors que la colonne est un `ENUM('all','tag','machines')` — une valeur hors liste remonte l'erreur MySQL 1265 nue, donc un **500 avec une page HTML** (mesuré) | liste blanche → **400** avec un motif nommé |
| `min_cvss` | `float()` sans borne à la création, **aucune conversion** au `PUT` ; la colonne est un `DECIMAL(3,1)`, donc `999` remonte une erreur MySQL | borné 0-10, converti aux deux chemins |
| `name` | non vide exigé à la création, **pas au `PUT`** — un renommage en chaîne vide passe ; aucune borne contre le `VARCHAR(100)` | non vide et ≤ 100 aux deux chemins |

`scan_source`, juste à côté dans le même code, **a** sa liste blanche et elle est rejouée au `PUT`.
C'est le motif « à moitié corrigé » à l'échelle d'une même boucle de champs.

Et un contrôle que le portage **ajoute** parce que le scheduler l'exige : une cible `machines` dont la
liste est vide ou illisible est **refusée**. Ce n'est pas du zèle — côté scheduler
(`scheduler.py:198-209`), une telle cible **retombe sur tout le parc**. Accepter la ligne, c'est armer
un scan complet sans que personne l'ait demandé.

---

## E-56 — Deux gestes que le portage ne reproduit pas

**Le `confirm()` natif de la suppression** (`js/main.js:865`). Le portage ouvre une confirmation **en
ligne**, sous la ligne concernée, avec ses deux boutons et leurs `data-rw`. Trois raisons, déjà
écrites pour les sept pages portées : la boîte native recouvre précisément la ligne sur laquelle on
décide, elle ne se style pas — action destructrice et annulation au même poids —, et elle bloque
Puppeteer, donc un test ne peut pas mener l'action au bout. La caractérisation cherche le bouton par
l'un **ou** l'autre contrat, et **dit lequel elle a joué** : « confirmation EN LIGNE » côté portage,
« native » côté legacy.

**L'appel émis pour un rôle qui n'a pas le bloc.** Le legacy branche `loadSchedules` sur
`DOMContentLoaded` pour **tous** les rôles (`js/main.js:991`) alors que son bloc vit sous
`$role >= 2` : un rôle 1 émet donc un `GET /cve_schedules` à chaque affichage de page, refusé en 403 et
avalé par un `if (!d.success) return;`. Le portage ne rend le bloc **ni ne charge son script** en
dessous du rôle 2 — ne pas charger le script est la seule façon de ne pas émettre l'appel.

---

## Trois constats de S4

**Un intitulé de colonne qui nommait autre chose que son contenu.** La dernière colonne du tableau des
planifications portait « Suivi », parce que j'avais réemployé la clé de S5 — or elle contient les
boutons. Vu à la capture, corrigé en `planif.col_actions`. **Un en-tête doit nommer ce que la colonne
contient**, et c'est le défaut que ce même document reproche au legacy ailleurs.

**Une référence se mesure, elle ne se déduit pas.** J'avais annoncé 21 assertions côté portage — 16
plus les cinq propriétés que le legacy ne tient pas. La mesure en donne **20** : il n'y a que **quatre**
`verifiePortage`, le clamp *à la création* tenant des deux côtés. L'arithmétique était fausse, la mesure
l'a corrigée.

**Le test lui-même a dû être rendu sûr par construction, et c'est le point le plus important de ce
sous-lot.** Une planification arme le scheduler, démarré **sans condition** par
`backend/server.py:240-247` — aucune variable d'environnement ne le gouverne, donc il tourne comme
thread dans le conteneur, invisible à `ps`, se réveille toutes les 60 s et prend toute ligne active dont
l'échéance est passée. Un test qui crée une planification par minute peut donc déclencher un vrai scan
SSH. La parade n'est pas un nettoyage rapide : toutes les planifications créées visent un **tag qui
n'existe pas**, dont la branche fait une jointure interne sur `machine_tags` — zéro machine, zéro SSH.
Vérifié après coup : la base porte toujours **un seul** scan CVE, celui du 25/07, et zéro planification.
`all` et `machines` sont interdits comme cibles de test, et l'en-tête de la suite dit pourquoi.

---

## E-57 — Le suivi d'une vulnérabilité n'affichait jamais son état, et un changement l'effaçait

Trois défauts d'une même colonne, tous mesurés sur la pile réelle.

**L'état stocké n'était jamais affiché.** Le générateur du legacy ne pose aucune option `selected`, et
son JS ne fait **aucun** `GET /cve_remediation` — sa seule occurrence est le POST. La cellule montrait
donc un tiret même quand une remédiation existait en base, et après un rechargement le choix qu'on
venait de faire disparaissait de l'écran alors qu'il était bien enregistré.

**Un changement de statut effaçait trois champs.** Le client n'envoie que `{cve_id, machine_id,
status}` ; côté backend `assigned_to`, `deadline` et `resolution_note` retombent à leur défaut, et
l'`ON DUPLICATE KEY UPDATE` réaffecte les **cinq** colonnes. Mesure, avec une remédiation complète
posée avant l'appel :

| | statut | assignataire | échéance | note |
|---|---|---|---|---|
| avant | `open` | 16 | 2026-12-31 | « note a preserver » |
| après, **legacy** | `in_progress` | **vide** | **vide** | **vide** |
| après, **portage** | `in_progress` | 16 | 2026-12-31 | « note a preserver » |

Déplacer une CVE de « à traiter » à « en cours » effaçait donc l'assignataire, l'échéance et la note —
et défaisait en silence l'auto-résolution du scanner (`cve_scanner.py:1092`). Le portage n'écrit **que
la colonne demandée**.

**Le statut n'était contrôlé par rien.** La colonne est un `ENUM` ; une valeur inventée remontait
l'erreur MySQL 1265 nue, donc un **500 avec une page HTML** au lieu d'un 400. Le portage refuse par un
400 qui nomme le statut reçu.

Un choix de portage à signaler : l'ENUM contient `resolved`, que l'interface **ne propose pas** — il
est posé par le scanner seul quand une CVE disparaît d'un scan suivant. Le portage l'**affiche** en
clair, avec son explication en infobulle, mais ne le met pas dans le sélecteur : proposer à quelqu'un
de « résoudre » ce que le scanner constate brouillerait les deux gestes.

---

## E-58 — La création de ticket passe par la passerelle, contrairement au reste du module

S3 et S4 lisent et écrivent la base directement (E-48, E-52). **La création de ticket ne le peut pas** :
`POST /tickets` appelle un **fournisseur ITSM externe** quand il est configuré
(`backend/routes/tickets.py`, `ticketing.create_ticket`). Le réimplémenter côté portage dupliquerait
une intégration et ses identifiants — c'est-à-dire le contraire de ce que la migration cherche.

Elle passe donc par la passerelle, où la chaîne de gardes est **déjà** en place : `/tickets` figure
dans `ADMIN_SEULEMENT` de `RoutesBackend`, donc la passerelle exige le rôle 2, et le backend exige
`can_admin_portal`.

**Ce que le portage ajoute, c'est l'honnêteté de l'écran.** La page exige `can_scan_cve` ; le ticket
exige `can_admin_portal`. `rw-test-admin` porte la première et pas la seconde : le legacy lui offre
donc un bouton cliquable dont l'appel rend **403**. Mesuré. Dans le portage le bouton est
**désactivé**, avec l'explication en infobulle — et la règle n'est pas déplacée côté navigateur : c'est
toujours le backend qui refuse.

---

## E-59 — La whitelist n'est PAS portée, et c'est une décision

**La table `cve_whitelist` n'a aucun lecteur.** Hors tests, deux requêtes en tout : son propre listing
(`cve.py:604`) et sa suppression (`cve.py:658`). Le scanner ne la consulte jamais, `expires_at` n'est
évalué nulle part. Blanchir une CVE n'a donc **aucun effet observable** — ni exclusion du scan suivant,
ni marquage, ni filtrage d'affichage.

Sa seule fonction d'appel côté legacy, `whitelistCve` (`js/main.js:1013-1026`), est du **code mort** :
`grep` sur tout le dépôt ne rend que sa déclaration. C'est elle qui porte le seul `prompt()` du
périmètre, et la seule consommatrice de `window._cveConfig.username`.

**Décision de l'exploitant : ne pas la porter.** Le portage ne propose donc pas de blanchiment. Porter
l'écran livrerait une capacité inerte — un bouton qui enregistre une ligne que rien ne lit —, ce qui est
exactement ce que la v2.0 doit cesser de faire. Rendre la fonctionnalité opérante demande une décision
sur le scanner, pas un portage d'interface.

À noter : un correctif de la branche `security/backend-cve` rend l'attribution de ce blanchiment honnête
(`whitelisted_by` pris de la session au lieu du client). Il **ne rend pas** la fonctionnalité opérante.

---

## E-60 — L'attribution d'un changement de statut reste impossible

`cve_remediation` porte `id, cve_id, machine_id, status, assigned_to, deadline, resolution_note,
opened_at, resolved_at`. **Aucune colonne d'auteur.** `assigned_to` est un *assignataire* — à qui le
travail revient —, pas un auteur — qui a décidé du statut.

Le schéma appartient au backend Python et la migration est interdite au portage (base partagée). Le
portage ne peut donc pas enregistrer qui change un statut, quel que soit le soin qu'on y mette, et
aucune des écritures du module n'est journalisée par ailleurs (`grep log_action` sur `cve.py` : une
seule ligne, et elle appartient au scan).

**Dit plutôt que contourné.** Poser l'auteur dans `resolution_note` serait détourner une colonne de
son sens et rendre la note inutilisable. La correction demande une migration SQL côté backend, donc une
décision.

---

## Trois constats de S5

**Le rendu a coûté trois mesures, et la colonne d'appoint a dû céder.** Ajouter un sélecteur et un
bouton à la sixième colonne a élargi le tableau : de 1048 px — le cadre exact obtenu en S3 — à 1102,
puis à **1203** quand j'ai empêché l'empilement, avec le bouton de ticket **hors du champ**. La règle du
projet a tranché : *une colonne d'appoint s'efface pour que l'actionnable revienne dans le champ*. Le
résumé est passé de 46 à **28 caractères** de largeur maximale, son texte entier restant en infobulle,
et la version a reçu un `nowrap` — elle se coupait sur deux lignes, ce qui **doublait la hauteur de
chaque ligne** (78 px au lieu de 41). Résultat mesuré : 1568 px pour un cadre de 1568 à 1920 px, et le
bouton dans le champ à 1400 px.

**Et à 390 px, le défilement reste nécessaire, ce qui est dit plutôt que masqué.** Sous 720 px les deux
colonnes d'appoint sont déjà cachées ; il ne reste que l'identifiant, le paquet, la sévérité et le
suivi — toutes décisionnelles. Le bouton de ticket s'efface aussi (l'action première est le sélecteur,
et pour un compte sans la permission le bouton est de toute façon désactivé), ce qui ramène le tableau
de 561 à **498 px** pour un cadre de 306. Cacher le paquet ou la sévérité retirerait des données
nécessaires pour agir : le cadre défile donc, et il l'indique.

**Un défaut de ma propre caractérisation, qui aurait pu faire condamner un portage correct.** La
première version posait la remédiation de fixture sur un identifiant **inventé**. Il n'apparaissait donc
dans aucune ligne du tableau, et l'assertion « le suivi affiche l'état stocké » lisait le sélecteur
d'une **autre** ligne — pour laquelle « vide » est la bonne réponse. Le test échouait sur le portage
alors que le portage avait raison. La fixture porte désormais sur la **première CVE réellement
affichée**, et le repérage se fait par le texte de la ligne, ce qui marche sur les deux portails.

## E-61 — Ce qui est réellement exploité passe désormais devant ce qui est grave en théorie

**Le portage de S3 triait par sévérité, et enterrait les cinq vulnérabilités les plus dangereuses du
parc.** Les cinq findings marqués KEV — le catalogue CISA des vulnérabilités dont l'exploitation est
*constatée* — sont tous de sévérité **HIGH** (CVSS 7,1 à 7,8). Un tri par sévérité puis par score les
place donc **derrière les 103 CRITICAL à 9,8**, en 104ᵉ position d'une page qui en montre cinquante :
invisibles. C'est tout l'écart entre « la plus grave sur le papier » et « celle qu'on exploite
aujourd'hui ».

Le legacy, lui, trie bien — `backend/cve_scanner.py:1230-1241` ordonne par `kev DESC, priority_score
DESC, FIELD(severity,…), cvss_score DESC`, et son script retrie par-dessus. **Le défaut était donc dans
mon portage, pas dans le legacy**, et la caractérisation le dit : l'assertion « les vulnérabilités
réellement exploitées sont affichées en tête » est un `verifie` plein, vert sur le legacy et **rouge sur
le portage** avant ce sous-lot. Mesure de départ : 0 des 5 premières lignes étaient KEV côté portage,
5 sur 5 côté legacy.

L'ordre est maintenant établi **une seule fois, en SQL** (`ScansCve::resultats()`), et le script ne fait
plus que filtrer : aucun geste ne peut le défaire. MySQL classant `NULL` comme la plus petite valeur, un
finding non enrichi arrive en `DESC` après tous les autres — exactement ce que le legacy obtenait par
`priority_score ?? -1`. Le comportement est identique ; ce qui change, c'est que **la page l'explique
désormais**, par une ligne au-dessus du tableau. Sans elle, un HIGH au-dessus d'un CRITICAL ressemble à
un défaut, et le legacy ne l'annonce jamais.

Le `priority_label` (URGENT, HIGH, MEDIUM, LOW) était calculé, stocké, et **jamais montré** — le même
défaut que l'état de suivi de S5 (E-57). Il apparaît en infobulle de la sévérité, donc sans ajouter de
colonne.

**Une colonne reste stockée et affichée par aucun des deux portails : `epss_percentile`.** La route en
écrit six, le portage en sélectionne cinq. Le percentile est pourtant plus parlant qu'un score brut pour
un humain — « plus exposée que 99 % des CVE connues » se comprend mieux que « 0,0008 ». Elle n'est pas
portée parce que le legacy ne l'affiche pas non plus et que l'afficher élargirait encore la cellule de
sévérité, dont E-63 raconte précisément le coût. **Décision à prendre par l'exploitant**, pas par le
portage : l'ajouter demande de retirer autre chose.

## E-62 — La pastille KEV du legacy est invisible : contraste mesuré 1,06:1

**Le signal le plus important de la page n'est pas peint.** Le legacy rend la pastille avec
`class="… bg-rose-600 text-white"`. Or `bg-rose-600` **n'est pas dans le CSS compilé** : Tailwind est
compilé localement avec PurgeCSS, qui ne garde que les classes qu'il a vues. Le fond reste donc
transparent et le texte blanc sur le fond clair de la ligne.

**Aucune assertion sur le DOM ne pouvait le voir** : la pastille *est* dans le HTML, son texte *est*
« KEV », et un test qui cherche la marque la trouve. Seul le style **calculé** le dit. Mesure au
navigateur, sur les deux portails :

| Cible | Fond calculé | Texte | Contraste |
|---|---|---|---|
| legacy | `rgba(0, 0, 0, 0)` | `rgb(255, 255, 255)` | **1,06:1** |
| portage | `rgb(185, 28, 28)` | `rgb(255, 255, 255)` | **6,47:1** |

Le seuil retenu par l'assertion est 4,5:1. Le couple du portage est celui de `.rw-bouton--danger`,
défini **par thème dans les deux sens** : rouge foncé sur blanc en clair, rose clair sur bleu nuit en
sombre — une pastille rouge est strictement invisible sur un fond sombre, et c'était déjà la cause de la
première version de l'ombre de défilement.

C'est la troisième fois que ce projet paie une classe Tailwind purgée. La leçon est dans
`rw-pieges` : **une classe utilitaire peut exister dans le source et manquer dans le binaire.**

## E-63 — Deux marques de plus ont rouvert le défaut que S5 venait de fermer

**Ajouter la pastille KEV et le pourcentage EPSS a élargi la cellule de sévérité de 86 px, et le bouton
de ticket de S5 est ressorti du champ.** C'est exactement le défaut que S5 avait fermé en ramenant le
résumé de 46ch à 28ch. Un sous-lot peut donc rouvrir ce que le précédent a corrigé, et seule la mesure
le voit.

Trois défauts, trois mesures, trois corrections :

1. **La cellule de sévérité se repliait sur deux lignes.** Portant désormais trois marques, elle passait
   à 63 px de haut à 1400 px et 85 px à 390 px — soit 1458 lignes rallongées pour un repli. Elle reçoit
   un `nowrap` et prend la largeur qu'il lui faut : **54 px aux trois largeurs**.
2. **Le tableau débordait de sa propre boîte sans que le cadre le sache.** Avec `width: 100%`, un
   tableau dont les cellules exigent plus que la place offerte déborde en gardant `scrollWidth ==
   clientWidth` : l'ombre de bord de S5 ne peut pas s'afficher et la dernière colonne devient
   **littéralement inatteignable** — ni visible, ni accessible par défilement. `.rw-tableau` passe donc
   à `min-width: 100%`.
3. **Le résumé s'effaçait déjà de fait.** À 24ch il affichait « In the Linux kernel, the … » sur les
   1458 lignes du parc : un début de phrase identique partout, qui ne distinguait plus rien. Il est
   **entièrement caché sous 1500 px**, ce qui rend 183 px à la colonne actionnable. À 1920 px il revient
   en entier, et l'identifiant CVE reste un lien vers la description complète à toutes les largeurs.

Mesures après correction — le cadre visé est celui **du tableau des findings**, et non le premier
`.rw-tableau-cadre` de la page, qui appartient aux planifications (erreur de mesure payée en route : le
sondage annonçait 78 px de rognage contre 73 px réels, et un défilement absent là où il existait) :

| Largeur | Cadre | Tableau | Défile | Hauteur de ligne | Colonne de suivi |
|---|---|---|---|---|---|
| 1920 px | 1568 | 1568 | non | 54 px | entière |
| 1400 px | 1048 | 1048 | non | 54 px | entière, bouton de ticket compris |
| 390 px | 306 | 536 | **oui, et indiqué** | 54 px | atteignable par défilement |

**À 390 px, la pastille KEV était coupée en deux au bord du cadre** — le signal le plus important réduit
à un liseré rouge tant qu'on n'avait pas défilé. Elle passe donc **devant** la sévérité sous 720 px, par
un `order: -1` dans un conteneur souple. « KEV HIGH 7.8 » se lit moins bien que « HIGH 7.8 KEV » sur un
grand écran ; sur un petit, ce qui compte est ce qu'on voit **sans** défiler. Le conteneur est un `span`
et non la cellule : une `td` doit rester `table-cell`, la passer en `flex` la sortirait de la
disposition du tableau.

Le pourcentage EPSS s'efface aussi sous 720 px : c'est un affinage de la priorité, quand la pastille KEV
est un **constat** d'exploitation. L'appoint cède, le constat reste.

## E-64 — La re-priorisation demande avant d'agir, et le test prouve qu'aucune requête n'est partie

`POST /cve_reprioritize` réécrit les **six** colonnes d'enrichissement de **tous** les findings du dernier
scan de la machine — 1458 lignes sur le parc mesuré — après dix-neuf appels à FIRST.org et un au
catalogue CISA. Il n'y a **pas de retour en arrière**, et une coupure réseau en cours de route remet
`kev` à zéro partout (défaut mesuré, corrigé sur la branche `security/backend-cve`). **Le legacy
déclenche cela sur un simple clic.**

Côté portage, le clic **ouvre une décision en ligne** qui nomme le nombre de lignes réécrites et
l'absence de retour, selon la convention du module : jamais de `confirm()` — la boîte native recouvre
précisément ce sur quoi on décide, ne se style pas, et bloque Puppeteer.

L'appel passe par la **passerelle**, deuxième et dernière exception du module après le ticket de S5, et
pour la même raison : il interroge deux services **externes**. Le portage n'a aucune raison d'embarquer
un client HTTP vers l'extérieur.

**Ce que la caractérisation mesure, et ce qu'elle refuse de mesurer.** La propriété qui compte n'est pas
« la requête était bornée », c'est **« il n'y a pas eu de requête »** — et elle se mesure au réseau, pas
au DOM : un panneau peut s'ouvrir *et* l'appel partir quand même. La suite interpose donc un compteur
sur `/cve_reprioritize` et exige zéro.

**Le geste lui-même est conditionnel, pas seulement l'assertion.** Sur le legacy, ce bouton appelle la
route au premier clic : cliquer « pour mesurer qu'il ne se passe rien » réécrirait les 1458 findings du
seul scan complet du parc. Un `verifiePortage` n'aurait protégé que le verdict, pas les données. La
suite déclare donc explicitement, côté legacy, que la propriété est **non mesurable sans détruire ce
qu'elle mesure**.

**Non porté, et dit :** l'attribution d'une re-priorisation. La table ne porte aucune colonne d'auteur,
et une migration est interdite au portage — même limite que E-60.
