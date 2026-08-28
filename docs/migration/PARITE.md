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

## E-65 — Le déclenchement d'un scan existe enfin sur le portage, et l'écran ne prétend plus le contraire

Jusqu'à S7a, le portage affichait les résultats d'un scan sans jamais pouvoir en lancer un : l'état
vide d'une machine jamais scannée disait *« Le déclenchement d'un scan reste sur l'ancien portail »*.
Le bouton existe désormais, **avec ou sans scan précédent** — c'est précisément une machine jamais
scannée qu'on veut pouvoir scanner, et le legacy le rend dans les deux cas.

**Le texte de l'état vide a été corrigé dans le même mouvement**, et il ne l'a pas été par un test :
il a été vu à l'image. Une assertion sur le DOM n'a aucun moyen de savoir qu'une phrase juste hier est
devenue fausse aujourd'hui. C'est la même famille que les commentaires du legacy qui affirment un accès
plus strict que leur code.

Les deux paramètres du scan — seuil CVSS et source des données — vivent dans le panneau de décision et
non dans l'en-tête de la carte : on les choisit au moment où on décide, et la carte ne s'élargit pas
(la leçon d'E-63 a coûté assez cher pour être appliquée d'avance).

## E-66 — Un scan refusé se dit. Le legacy en avalait deux sortes en silence

**Silence n° 1 : le statut HTTP n'est jamais lu.** `runScan` fait `resp.body.getReader()` sans regarder
`resp.status`. Or le corps d'un refus — 429 du garde-fou de débit, 403 d'accès machine, 400 de
paramètre — est un JSON sur **une seule ligne, sans saut final**. Le lecteur le met dans son tampon,
`split('\n')` rend un unique élément que `pop()` remet dans le tampon, et le tampon est abandonné à la
sortie de la boucle. **Rien n'est jamais parsé.** Les boutons reviennent au repos, aucun message
n'apparaît : cliquer « Scanner » et être refusé est *indiscernable de ne rien faire*.

**Silence n° 2 : un événement d'erreur sans `machine_id`.** C'est le cas de « Aucun serveur trouvé »,
que le backend émet quand l'identifiant demandé n'existe pas. `handleEvent` lit `ev.machine_id`, donc
`id` vaut `undefined`, et `showError` cherche `results-undefined` : `getElementById` ne trouve rien et
la fonction sort sans écrire. Le message existe, traverse le réseau, est parsé — et disparaît.

Mesures, sur les deux portails :

| | legacy | portage |
|---|---|---|
| erreur sans `machine_id` | RIEN | « Le scan a échoué : Aucun serveur trouvé » |
| scan refusé (429) | RIEN | « Patientez 53s avant un nouveau scan CVE. » |

Le portage lit **le statut d'abord** et n'ouvre le flux que si la réponse est bonne ; un événement sans
`machine_id` retombe sur l'annonce globale de la page. Il traite aussi **le reste du tampon** à la fin
de la boucle plutôt que de le jeter — c'est exactement le mécanisme du silence n° 1 — et dit qu'un flux
terminé sans `done` ni `error` laisse un résultat incertain, au lieu de rester muet.

## E-67 — Un scan est précédé d'une décision qui nomme son coût, courriel compris

Le legacy déclenche le scan **au clic** : `onclick="scanServer(id)"` appelle `runScan` directement. Un
clic de travers sur une machine de **production** suffit — et `srv-zabbix`, `PROD`/`CRITIQUE`, porte ce
bouton comme les autres.

Ce qu'un scan engage, et que le legacy n'annonce nulle part :

- une session SSH vers la machine, et neuf commandes de **lecture seule** — rien n'est modifié sur la
  cible, ce qui mérite d'être dit aussi, pour ne pas faire craindre plus que ce qui a lieu ;
- plusieurs **minutes** (l'enrichissement NVD tourne sans clé d'API, à 5 requêtes / 30 s) ;
- un nouveau résultat en base, qui **remplace le précédent à l'affichage** ;
- **un rapport par courriel** (`send_cve_report`, appelé dès que l'événement `done` porte des
  findings). Dans cet environnement, `MAIL_ENABLED=true` avec un SMTP et un destinataire réels : le
  courriel part pour de bon, et rien ne le rappelle.

Le portage ouvre donc un panneau de décision en ligne qui nomme les quatre, selon la convention du
module — jamais de `confirm()`. Une **jauge d'avancement** a été ajoutée : le flux émet un paquet
courant sur un total, et sans zone pour les rendre, un scan de plusieurs minutes n'a aucun signe de
vie. Le legacy en a une, faite de classes Tailwind ; le portage n'en avait aucune.

`srv-zabbix` garde son bouton, comme sur le legacy : la garde n'est pas déplacée, elle est **annoncée
plus tôt**. Restreindre le scan des machines critiques serait un changement de droits, donc une
décision de l'exploitant.

## E-68 — Le garde-fou de débit et le verrou du scan sont par PROCESSUS, et un test l'a payé

`backend/hypercorn_config.py` déclare `workers = 4`. Or `cve.py` porte deux garde-fous **en mémoire de
processus** :

- `_user_scan_throttle`, censé refuser un second scan dans les 60 s par utilisateur — son commentaire
  dit le poser pour empêcher « un user role=1 de spammer /cve_scan, chaque tentative consommant un
  thread+DB ». Il autorise en réalité **un scan par processus** avant de mordre. Motif mesuré sur douze
  appels consécutifs : `200 200 429 429 200 429 429 429 429 429 429 429` ;
- `_scan_lock`, le verrou « un seul scan à la fois », qui autorise donc **jusqu'à quatre scans
  simultanés**, sur un conteneur borné à 512 Mo et 1 CPU.

C'est le défaut déjà corrigé pour le scheduler en v1.37.5 par un verrou `GET_LOCK` en base. Le scan CVE
ne l'a pas reçu. **Le backend n'est pas touché** : c'est une décision de l'exploitant.

**Ce que la caractérisation a payé pour l'apprendre.** La première version saturait le garde-fou puis
cliquait le vrai bouton, en tenant trois refus consécutifs pour la preuve qu'aucun scan ne pouvait
partir. La prémisse était fausse : la boucle s'arrêtait au troisième refus sans avoir forcément touché
le quatrième processus, dont la fenêtre était libre. **Deux vrais scans de `Test-Server-Debian` ont
démarré** — un par portail. Tous deux ont été interrompus avant leur événement `done`, donc avant
`send_cve_report` ; vérifié : aucune ligne `cve_scans` pour la machine 2, 1458 findings inchangés,
aucune trace SMTP.

La correction n'est pas de renforcer le garde-fou, c'est de **retirer la cible** : plus aucun geste de
la suite ne vise une machine scannable. Le bouton réel est cliqué uniquement là où le clic est local
(il ouvre un panneau), puis **annulé**, et l'absence d'appel est mesurée au réseau. Les refus se
mesurent sur un identifiant de machine **inexistant**, qui traverse le garde d'accès pour un rôle ≥ 2
et ne peut rien produire d'autre qu'une erreur. Et l'absence de panneau de décision côté legacy se lit
dans le DOM, **sans cliquer** : un portail qui déclenche au clic ne se teste pas en cliquant.

**Contrainte de LOT, nouvelle :** ce garde-fou de débit **traverse les suites**, comme le garde
anti-rejeu TOTP. Il est posé par utilisateur, et `rw-test-admin` est partagé. La suite attend donc la
fenêtre — le délai est lu dans le refus lui-même — et attend 63 s avant de piloter le client, parce
qu'une sonde acceptée ferme la fenêtre de son processus et que le processus suivant n'est pas choisi.

## E-69 — « Clés SSH » : le premier sous-lot du module le plus dangereux du dépôt, et il ne touche aucune route

Le module `ssh/` fait 458 lignes — le plus petit des restants — mais un seul de ses boutons lance
`configure_servers.py` (1 015 lignes) **en root, sur chaque machine cochée, cinq en parallèle** :
`apt-get install -y sudo`, `useradd`, **écrasement** d'`authorized_keys`, installation d'une politique
sudoers, et **révocation** des clés de tout compte ayant perdu son habilitation. `srv-zabbix`,
`PROD`/`CRITIQUE`, porte ce bouton comme les autres. Aucune ligne n'entre dans `command_log` : la seule
trace est `deployment.log`, **tronqué à chaque déploiement**.

D'où le découpage en quatre : **K1** la page nue (aucune route, aucun SSH, rien d'écrit), **K2** le
constat avant déploiement (`POST /preflight_check`, lecture seule), **K3** la lecture du flux SSE, **K4**
le déploiement. K1 d'abord, précisément parce qu'il ne peut rien casser tout en portant les deux tiers
du travail réutilisable.

**Ce que K1 ferme.**

| | legacy | portage |
|---|---|---|
| jeton de substitution à l'écran | **« 3 :count serveur(s) disponible(s) »** | « 3 serveur(s) disponible(s) » |
| bouton de déploiement à l'arrivée | **actif, sans aucune sélection** | désactivé |
| déclenchement | `onclick="deploySSH()"`, cascade immédiate | ouvre une décision qui **nomme les machines** |
| vocabulaire de filtrage | tags **non cloisonnés** | dérivé des machines visibles |

**Le `:count` échappait à tous les contrôles.** Le gabarit écrit `count($machines)` **puis**
`t('ssh.servers_available')`, dont la valeur est « :count serveur(s) disponible(s) » : le jeton n'est
jamais substitué et s'affiche en clair. `go-socle-i18n` ne pouvait pas le voir — il cherche des
identifiants de la forme `module.cle`, pas des jetons `:xxx`. La suite de K1 mesure désormais **tout
jeton de la forme `:mot`** visible dans le corps de la page.

**Le cloisonnement du vocabulaire, corrigé sans être mesurable.** `index.php:61` fait un
`SELECT DISTINCT tag FROM machine_tags` **sans le moindre filtre**, deux lignes au-dessus d'un
`$allEnvs` qui, lui, dérive de la liste déjà cloisonnée : une ligne cloisonnée, sa voisine non. Un
rôle 1 lirait donc le vocabulaire de tags de machines qu'il ne peut pas voir. Le portage dérive les
**deux** listes du même ensemble de machines.

Mesure : **aucun compte de rôle 1 ne porte `can_deploy_keys`** (seuls `superadmin` et
`rw-test-admin`), donc aucun rôle 1 ne peut ouvrir cette page et la fuite n'est pas exerçable. La suite
le **dit**, et vérifie que c'est bien la cause — elle ne prétend pas l'avoir mesurée. Même limite que
D-5 : **corriger un défaut non exerçable reste correct ; prétendre l'avoir mesuré ne l'est pas.**

**La garde est REPRISE DU LEGACY, l'écart est déclaré, la décision reste ouverte.** L'en-tête de
`ssh/index.php` annonce depuis toujours « Accès refusé pour les utilisateurs standards (role_id = 1) » ;
son `checkAuth` autorise `[ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]` + `can_deploy_keys`. Même nature que
E-36, avec une conséquence plus lourde : `POST /deploy` n'a **ni rôle ni permission**, donc un rôle 1
habilité pourrait déclencher le déploiement, et `GET /logs` étant `@require_role(2)` il ne pourrait
**pas en lire le résultat**. Le portage applique donc `role:1` + `perm:can_deploy_keys` — restreindre
serait un changement de droits, à trancher avec D-1 pour ne pas laisser deux pages en désaccord.

**K4 n'est pas porté, et la page ne fait pas semblant.** Le panneau de décision explique ce qu'un
déploiement engage, nomme les machines cochées, puis offre comme action principale un lien vers l'ancien
portail, avec le marqueur `↗` et une nouvelle fenêtre. Un panneau dont la seule issue serait « Annuler »
ne serait pas une décision.

**Deux défauts de mon propre fait, tous deux vus autrement que par une assertion.** Le nom de la machine
affiché dans la décision ramassait la pastille d'environnement (« OpenCVE-Test-OnPrem DEV ») — vu **à
l'image**. Et l'attribut `data-rw="machine-nom"` que j'ai ajouté a été attrapé par le sélecteur
`[data-rw^="machine-"]` de la suite, qui comptait alors **six lignes pour trois machines** : un sélecteur
par préfixe finit toujours par attraper autre chose, et cette fois j'ai fourni l'autre chose moi-même.
La suite s'ancre désormais sur la classe `.machine-item`, que les deux portails portent.

Enfin, un `<a>` stylé en `.rw-bouton` gardait son soulignement de lien — il se lisait comme un bouton
*et* comme un lien. Le défaut existait déjà sur « Exporter en CSV » du scan CVE ; un bouton-lien de plus
l'a simplement rendu visible.

## E-70 — Le constat avant déploiement devient un geste à part, et il ne l'était pas

C'est la propriété centrale de K2. Côté legacy, `preflight_check` et `deploy` vivent dans **la même
chaîne `fetch`** (`ssh/js/main.js:110-200`) : si le constat passe, le déploiement part **immédiatement**,
sans reprise de main. Il n'existe donc **aucun moyen de vérifier sans risquer d'écrire** — et écrire, ici,
veut dire `apt-get install sudo`, `useradd`, l'écrasement d'`authorized_keys` et la **révocation** de
clés, en root, sur chaque machine cochée.

Le portage offre un bouton **« Vérifier les prérequis »** qui n'appelle que `preflight_check` et
n'enchaîne rien. C'est ce qui rend le geste testable : la suite peut le cliquer, le legacy non.

| | legacy | portage |
|---|---|---|
| vérifier sans déployer | **impossible** | bouton dédié |
| forme du constat | une fenêtre de texte monospace unique | un bloc par machine, en grille |
| « accès qui seront RÉVOQUÉS » | une ligne parmi l'inventaire, l'OS et le disque | en rouge, distinguée |
| statut HTTP du refus | jamais lu (`.then(r => r.json())`) | lu **d'abord** |
| lien vers le prérequis manquant | `/adm/server_users.php` en dur | lien inter-portails avec `↗` |

**Ce que la mesure a donné.** `preflight_check` porte quatre portes avant d'ouvrir quoi que ce soit :
serveur jamais scanné, utilisateurs en attente de classification, ni mot de passe ni keypair, port
injoignable. Le parc réel en offre deux **sans aucune session SSH** :

- `Test-Server-Debian` (id 2) a `users_scanned_at` à `NULL` → première porte, `scan_required` ;
- `OpenCVE-Test-OnPrem` (id 3) est scannée mais porte **un utilisateur en `pending_review`** → deuxième
  porte.

Seule la machine 1 irait jusqu'à la session SSH, et c'est `srv-zabbix`, en **production** : elle n'est
jamais visée. La suite n'ouvre donc **aucune session SSH** et n'a pas besoin d'en ouvrir.

**Une donnée que le constat rend et qui décide de tout : `users_with_keys`.** Mesure du jour : **zéro
compte actif ne porte de clé SSH**. Un déploiement ne déploierait donc rien, et le legacy en fait — à
juste titre — un motif d'échec du constat. Le portage l'énonce en clair (« aucun compte actif ne porte de
clé SSH — un déploiement ne déploierait rien ») plutôt que par un « 0 » au milieu d'un journal.

**Non mesurable, et dit tel quel** : `preflight_check` n'a **aucune garde de rôle** — seulement
`@require_api_key` + `@threaded_route` — alors qu'elle énumère les comptes UNIX distants, ce que
`/scan_server_users` réserve au rôle 2 **et** place dans `ADMIN_ONLY_PREFIXES` du proxy. C'est donc un
contournement. Aucun compte de rôle 1 ne porte à la fois `can_deploy_keys` et un accès machine, donc le
contournement n'est pas exerçable avec les comptes existants. Même limite que D-5. Le fermer demanderait
`@require_permission` sur la route, donc **modifier le backend** : décision de l'exploitant.

**Deux défauts de mes propres tests, tous deux catalogués et payés quand même.** La précondition de la
première porte était lue par `COALESCE(CAST(users_scanned_at AS CHAR), '')` : `litEnBase` fait un `trim()`
puis un `.filter(Boolean)`, donc **la chaîne vide disparaît** et la valeur arrivait à `undefined`. La
suite annonçait « la machine 2 porte désormais un scan (« undefined ») » et **sautait la porte qu'elle
venait mesurer**. Une sentinelle explicite (`'JAMAIS'`) règle cela. Et la sonde qui relève
`users_with_keys` visait la machine 2 **sans reprendre le garde de précondition** appliqué juste au-dessus
— deux poids, deux mesures pour le même risque ; elle vise désormais un identifiant valide mais
inexistant, qui ne franchit aucune porte.

Enfin, une assertion exigeait le **chiffre** `0` dans le rapport là où le portage énonce l'absence en
mots. Elle condamnait le meilleur des deux rendus : elle mesure maintenant la propriété, pas la forme.

**Vu à l'image** : les blocs du rapport portaient `.rw-carte`, plafonnée à 420 px, et restaient étroits
sur une page de 1400. Ils sont désormais rangés en `.rw-grille` (`auto-fit`, minimum 280 px) et prennent
la largeur disponible.

## E-71 — Le journal du déploiement : un marqueur qu'il ne faut pas traduire, un statut illisible, et une XSS stockée

K3 ne déploie rien : `GET /logs` ouvre `deployment.log`, envoie son contenu, puis suit le fichier pendant
**30 secondes d'inactivité** avant d'émettre son marqueur de fin. Aucune machine n'est jointe — ce qui
rend le sous-lot entièrement mesurable.

**Le marqueur de fin est un JETON DE PROTOCOLE, pas un libellé.** Le backend émet en dur
`data: [Fin du flux de logs]` et le client compare `event.data` à cette chaîne, littéralement. **Le
traduire côté portage ferait que le flux ne se termine jamais** : le bouton resterait figé, et seul le
gestionnaire d'erreur finirait par le rendre — donc par le chemin d'échec, sans message de succès. Il est
donc posé en **constante dans le contrôleur**, hors des fichiers de langue, précisément pour qu'aucune
relecture de traduction ne le change.

**Un `EventSource` ne peut pas lire un statut HTTP.** `GET /logs` est `@require_role(2)` ; pour un rôle 1
il rend **403**, ce qui déclenche `onerror` — où le legacy écrit « [Fin du flux] », rend le bouton et **ne
dit rien**. Or `POST /deploy` n'a ni rôle ni permission : un rôle 1 peut donc déclencher le déploiement et
conclure que tout s'est bien passé. Le portage lit le flux par `fetch`, dont le statut **est** lisible, et
annonce le refus.

| | legacy | portage |
|---|---|---|
| type de requête | `eventsource` (statut invisible) | `fetch` (statut lu **d'abord**) |
| une ligne de journal | **interprétée comme du balisage** | rendue comme du **texte** |
| marqueur de fin | comparé littéralement, non affiché | idem, en **constante** hors i18n |
| flux interrompu sans marqueur | rien | « le flux s'est interrompu… c'est incomplet » |
| état final du bouton | **deux libellés selon le chemin** | un seul chemin de sortie |

**L'XSS stockée, démontrée par la mesure.** `main.js:264` fait `logWindow.innerHTML += event.data` et son
commentaire affirme « pas de données utilisateur non maîtrisées ». C'est faux :
`configure_servers.py:112` injecte `machines.name` dans **chaque** ligne sans validation, et `:785`
journalise verbatim les noms d'utilisateur refusés. La branche preflight du **même fichier** échappe tout
par `_escHtml` — une moitié traitée, l'autre pas.

La suite pose dans le journal une balise **bénigne** — `<b data-rw="k3-balise">` — et compte les éléments
correspondants dans la fenêtre. Mesure : **1 sur le legacy** (la balise est devenue un nœud du document,
le texte affiché ne montre pas les chevrons), **0 sur le portage**, qui affiche la chaîne littérale. La
propriété mesurée est « est-ce interprété », pas « peut-on exécuter » : écrire une charge exécutable
n'aurait rien prouvé de plus et aurait laissé une trace inutile.

**Un quatrième défaut, non annoncé par l'inventaire.** Les deux chemins de sortie du legacy ne laissent
pas la page dans le même état : le succès remet le libellé « Deployer les cles » et affiche un toast,
l'échec écrit « Lancer le Deploiement » et n'affiche rien. L'état de la page dépend donc de la façon dont
le flux s'est terminé. Le portage n'a qu'un seul chemin de sortie.

**La fixture, et sa restauration.** Mesurer le rendu d'une ligne demande une ligne. `deployment.log` est
vide, ignoré par git, et tronqué par l'application elle-même à chaque déploiement : la suite y ajoute une
ligne via le conteneur — seul propriétaire du fichier — puis **le remet à zéro dans un `finally`**, et le
journal l'annonce (`journal restauré : 0 octet(s)`). Vérifié après chaque exécution.

**Non mesurable, et dit tel quel** : ce que le legacy fait du 403 sur sa propre page. Un rôle 1 n'a pas
`can_deploy_keys`, donc il ne peut pas ouvrir `/ssh/` et n'atteint jamais le client. La route, elle,
refuse bien — c'est vérifié. Même limite que D-5.

**Un défaut de ma suite, corrigé** : le collecteur de types de requêtes comptait aussi la sonde `fetch`
de la suite elle-même, si bien que l'assertion « pas d'`EventSource` » aurait réussi même si le client de
la page n'avait rien demandé. Il est remis à zéro juste avant de piloter le client.

## E-72 — « Supervision » : la page se peint sans rien demander, et une clé technique quitte l'écran

**Module `supervision/`, sous-lot V1 : la page et ses quatre onglets.** Route du portage `/supervision`.
Suite : `tests/e2e/go-page-supervision-onglets.mjs` — **11 PASS sur le legacy, 14 sur le portage**
(base rouge relevée avant portage : **6 PASS / 7 FAIL**). Les trois assertions supplémentaires sont
celles que le legacy ne peut pas satisfaire, rendues en INFO chez lui.

**La garde est reprise telle quelle, et pour une fois il n'y a aucun écart à déclarer.**
`supervision/index.php:17-18` fait `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis
`checkPermission('can_manage_supervision')`, et l'en-tête du fichier annonce exactement cela :
« Permissions : admin (2) + superadmin (3) + can_manage_supervision ». La route porte donc `role:2` +
`perm:can_manage_supervision`. Contrairement à `ssh/` (E-69) et à `security/` (E-36 / D-1), il n'y a rien
à arbitrer ici. Mesuré : un rôle 1 sans la permission reçoit **403**, un rôle 2 habilité **200**.

**LE DÉCOUPAGE ÉTAIT OPTIMISTE : V1 N'EST PAS « AUCUNE ROUTE ».** L'inventaire (§7 de MODULE-SUPERVISION)
annonçait un premier sous-lot sans aucun appel. Mesuré au navigateur : la page legacy émet **deux**
requêtes backend dès son chargement — `GET /supervision/profiles?platform=zabbix` et
`GET /supervision/profiles/assignments?platform=zabbix` — puis les **rejoue à chaque bascule d'onglet**
(`profiles` 1 appel, `deploy` 2, `editor` 0). Le catalogue de profils arrive donc d'emblée : la frontière
V1/V2 n'existe pas côté legacy. Les deux routes sont en lecture, donc V1 reste inoffensif, mais
l'affirmation était fausse et c'est la mesure qui l'a dit.

**Le portage, lui, n'appelle rien du tout** : ni au chargement, ni au changement d'onglet, ni au
changement de plateforme. Tout est peint côté serveur (décision S3/S4) et le script ne fait que montrer
et cacher des panneaux déjà rendus. Mesuré à `resourceType()` : **0 requête**, contre 2 puis 1 ou 2 par
bascule.

**UNE CLÉ DE TRADUCTION QUITTE L'ÉCRAN.** `head.php:76-78` charge `getJsTranslations('js.')` puis rend
`_i18n['js.' + cle] || _i18n[cle] || cle` : une clé absente est **retournée telle quelle**. Comme c'est
une chaîne non vide, l'idiome `__('x') || 'repli'` **ne déclenche jamais son repli** — la panne est
silencieuse. Onze clés du module sont dans ce cas, présentes dans `supervision.php` en FR et en EN mais
absentes de `js.php`. **Une seule est atteignable sans joindre une machine** : `editor_select_server`, le
garde qui refuse de lire une configuration quand aucun serveur n'est choisi. Mesuré : le legacy affiche
`editor_select_server` en clair dans son toast ; le portage affiche la phrase traduite, et **aucune des
onze** n'apparaît dans son corps de page.

**Neuf clés à déplacer, deux à REMPLACER.** Ce que l'inventaire ne disait pas : `confirm_deploy` et
`confirm_uninstall` sont consommées dans des `confirm()` **natifs** (`main.js:468` et `:488`). La
convention du portage les interdit — une boîte native recouvre la ligne sur laquelle on décide, ne se
style pas, et bloque le test qui doit mener le geste au bout. Ces deux-là ne seront donc pas déplacées
mais remplacées par un panneau de décision, en V11 et V12.

**Ce que V1 ne porte pas, il le DIT.** Les quatre panneaux portent un état vide nommé « Pas encore porté
sur ce portail », l'explication de ce qui arrive plus tard, et un lien vers l'ancien portail avec le
marqueur des entrées non portées. Trois onglets sur quatre sont dans ce cas ; le quatrième porte le
garde de l'éditeur, seul geste réel du sous-lot.

**Défauts du backend constatés, NON corrigés — ils demanderaient de modifier le backend.**
Les quatre routes de profils (`1734` GET, `1760` POST, `1801` DELETE, `1817` assignments) portent
`@require_api_key` + `@require_permission('can_manage_supervision')` et **aucun `@require_role`** ; la
cinquième (`machines/<mid>/profile`, `1846`) porte bien `@require_role(2)` avec son commentaire
« Patch A01 » — le correctif a été appliqué à une route et pas à ses quatre voisines. Et `/supervision/`
est **absent** des 25 préfixes de `$ADMIN_ONLY_PREFIXES` du proxy legacy. Un rôle 1 porteur de
`can_manage_supervision` ne peut donc pas ouvrir la page mais pourrait appeler
`DELETE /supervision/profiles/<id>`. Décision d'exploitant.

**Trois défauts vus À L'IMAGE, qu'aucune assertion DOM ne voit** — et corrigés :
- `.rw-vide p { margin: 0 }` est juste pour du texte et faux dès qu'un bouton s'y trouve : la hauteur de
  ligne du bouton **recouvrait** la dernière ligne du paragraphe au-dessus, qui se lisait barrée.
  L'action a désormais son bloc (`.rw-vide__action`) ;
- `.rw-etiquette-champ` est en `flex: 1` : sur 1920 px le menu des plateformes traversait la moitié de la
  page. Borner le `<select>` seul ne suffisait pas — l'enveloppe gardait la place et renvoyait le bouton
  voisin à l'autre bout de la carte. C'est l'enveloppe qui se borne (`--borne`), **et la règle doit
  rester après celle qu'elle surcharge** : à spécificité égale, c'est l'ordre du fichier qui tranche, et
  la première version, écrite 380 lignes plus haut, n'avait aucun effet ;
- un `<a class="rw-bouton">` est un élément **en ligne** : à 390 px son libellé passait à la ligne mais sa
  boîte sortait du cadre par la droite, remplissage compris. `display: inline-block` la replie. Ce
  correctif est dans le socle : il vaut pour toutes les pages qui portent un bouton-lien.

**Un défaut de ma suite, corrigé avant de l'inscrire.** L'assertion « aucune clé ne s'affiche en
identifiant » réussissait aussi pour un garde qui n'aurait **rien** affiché : ne rien dire, c'est ne dire
aucun identifiant. La suite mesure donc d'abord que le refus est **énoncé à l'écran**, en comparant au
texte que chaque cible déclare comme son refus — côté portage lu dans l'îlot de données de la page, pour
ne pas recopier un catalogue de traduction dans un test.

**Non porté, et dit tel quel** : le catalogue de profils (V2), la lecture et l'écriture de la
configuration globale (V3, V4), l'assignation (V5), tout ce qui passe par SSH (V6 à V12). Et **hors
lot** : les *overrides* par machine, qui n'ont jamais eu d'interface — les porter, c'est concevoir, pas
migrer. À arbitrer **avant V10**, car la précédence documentée du module en dépend.

## E-73 — `next_run` est calculé en UTC et lu en heure locale : deux heures d'écart, et un test qui échouait chaque nuit

**Découvert par le LOT du 2026-08-22 à 03:07**, pas par une relecture. `go-page-cve-planification` est
tombée à **15 PASS / 1 FAIL** sur le legacy alors qu'elle était verte depuis S4 : « `next_run` est posé et
strictement dans le futur — next_run=2026-08-22 03:00:00 », pour une planification `0 3 * * *` créée à
03:07.

**Mesuré, pas déduit.** L'hôte est en `CEST +0200`, le conteneur `rootwarden_python` en `UTC +0000` :

```
hôte    : 2026-08-22 03:21:34 CEST +0200
backend : 2026-08-22 01:21:34 UTC  +0000
croniter dans le conteneur : next('0 3 * * *') = 2026-08-22 03:00:00
```

`cve.py:504` fait `croniter(cron_expr).get_next(datetime)` — donc **la prochaine occurrence est correcte
dans le repère du conteneur**, et elle est stockée **sans fuseau** dans `cve_scan_schedules.next_run`.

**Le scheduler n'est PAS en défaut**, et c'est important : il tourne dans le même conteneur et compare
`next_run <= now` avec la même horloge (`scheduler.py:614`). Les deux valeurs sont dans le même repère,
donc rien ne se déclenche trop tôt. **Aucun scan n'a été lancé en avance** — vérifié à la lecture du
code, et la suite nettoie ses lignes de toute façon.

**Ce qui EST en défaut** : tout lecteur qui compare cette valeur à l'heure locale. Les deux portails
l'affichent telle quelle — un exploitant en CEST lit donc un prochain déclenchement **deux heures avant
l'heure réelle**, et en hiver une heure. Le même raisonnement vaut pour `ssh_audit_schedules`, pour
`last_run`, et pour toute colonne d'horodatage écrite par le backend. **Non corrigé** : la corriger
demande de choisir entre poser le fuseau du conteneur, stocker en UTC assumé et convertir à l'affichage,
ou aligner les deux horloges — un choix d'exploitant qui touche le backend et l'affichage de plusieurs
modules.

**Et un défaut de la suite, lui, corrigé.** L'assertion comparait la valeur stockée à `new Date()` de
l'hôte : elle ne mesurait donc pas « le prochain déclenchement est à venir » mais **« les deux horloges
concordent »**. Elle réussissait 22 heures sur 24 et échouait entre 03:00 et 05:00, sans qu'aucun défaut
de planification n'existe — un faux rouge qui, répété, apprend à ne plus lire les rouges. Elle compare
désormais à l'heure **du conteneur qui a calculé la valeur**, et la suite **constate l'écart en clair**
(`decalage horaire hote / conteneur backend : 2 h`) pour que le défaut réel reste visible plutôt
qu'absorbé par le correctif. Références inchangées : legacy 16, portage 20.

**La leçon, au-delà de ce cas** : une assertion qui compare deux valeurs venues de deux horloges mesure
les horloges, pas la propriété. Le repère se choisit — et c'est celui qui a produit la valeur.

## E-74 — Le catalogue de profils : deux libellés hors de toute traduction, un enregistrement entier dans un attribut `onclick`

**Module `supervision/`, sous-lot V2 : le catalogue de profils, en lecture.** Suite :
`tests/e2e/go-page-supervision-profils.mjs` — **14 PASS sur le legacy, 18 sur le portage** (base rouge
relevée avant portage : **12 PASS / 6 FAIL**).

**LE SCHÉMA A ÉTÉ MESURÉ AVANT D'ÉCRIRE UNE SEULE REQUÊTE, et il a corrigé deux suppositions du brief.**
La table s'appelle **`supervision_metadata_profiles`**, pas `supervision_profiles`. Et le « nombre de
machines » du tableau ne vient d'aucune colonne de `machines` : il vient de
**`machine_supervision_profile`**, dont la clé primaire est `(machine_id, platform)` — une machine porte
donc **un profil par plateforme**, et le compte se filtre par plateforme. Déduire ces deux points de
l'affichage aurait produit une requête fausse qui *semblait* juste sur ce parc.

**Vérifié, comme E-72 le demandait** : `fk_msp_profile` porte bien un `ON DELETE CASCADE` vers
`supervision_metadata_profiles`. La conséquence annoncée tient donc mot pour mot :
`DELETE /supervision/profiles/<id>`, qui n'a **aucun `@require_role`**, emporte les assignations avec le
profil.

**Défaut 1 — deux libellés écrits en dur dans le JS, donc hors de toute parité FR/EN.**
`profiles.js:43-46` construit chaque ligne avec `>Editer<` et `>Supprimer<` en clair. Mesuré en
demandant la page en anglais : le catalogue rend **`Editer, Supprimer`** en français. Aucun contrôle
d'i18n ne le voyait — ils cherchent des identifiants `module.cle`, pas du français. La suite mesure ces
mots **dans le catalogue**, pas dans la page : « Supprimer » apparaît ailleurs dans les deux portails, et
une recherche sur `body` accuserait le tableau de ce que fait son voisin.

**Défaut 2 — le profil ENTIER est sérialisé dans un attribut `onclick`.**
`editProfile(${JSON.stringify(p)...})` : le document porte, dans un attribut de gestionnaire
d'événement, toutes les colonnes de la ligne — `notes` comprise, qui contient les consignes
d'exploitation Zabbix. **Mesuré** : deux attributs de **652 et 671 caractères** sur deux profils. Le
portage n'a aucun gestionnaire en attribut : la mesure est donc « zéro attribut », pas « un attribut
court ».

**Défaut 3 — la route backend fait `SELECT *`.** `list_profiles` renvoie au navigateur `notes`,
`tls_connect`, `tls_accept`, `created_at` et `updated_at` alors que le tableau n'affiche que cinq
colonnes. Le portage nomme ses colonnes : la page ne reçoit que ce qu'elle montre. **Non corrigé côté
backend** — la route reste inchangée.

**Défaut 4, non annoncé par l'inventaire, et découvert par la mesure du réseau.** Changer de plateforme
émet **quatre** requêtes sur le legacy — `config/<p>`, `profiles?platform=<p>` **deux fois**, et
`profiles/assignments?platform=<p>`. La même requête est donc jouée en double : le gestionnaire
`onchange` de la page et le crochet `DOMContentLoaded` de `profiles.js` la déclenchent tous les deux.

**Le portage n'émet RIEN**, et c'est ce que V1 a rendu possible : les quatre catalogues sont peints côté
serveur, le script n'en montre qu'un. Ouvrir l'onglet : **0 appel**. Changer de plateforme : **0 appel**.

**Une divergence assumée, et c'est une amélioration.** Le legacy écrit `-` dans les colonnes Serveur et
Mandataire quand la valeur est `NULL`. `-` n'apprend rien ; `NULL` veut dire ici « la configuration
globale s'applique », et c'est ce que le portage écrit. La suite ne cherche donc pas `-` : elle asserte
qu'aucune valeur absente n'est rendue par un **mot de code** (`null`, `undefined`, `NaN`,
`[object Object]`) — la propriété, pas la forme.

**Un défaut de ma suite, corrigé entre la mesure du legacy et le portage.** Elle comptait les `tr` du
corps du tableau **sans regarder s'ils étaient visibles**. Sur le legacy cela passait — il vide son
`tbody` à chaque bascule — mais un portage qui peint les quatre plateformes et en cache trois aurait fait
mesurer le catalogue de Zabbix en croyant mesurer celui de Centreon. La suite prend maintenant le
catalogue **visible** et ses lignes **visibles** : `textContent` mesure la présence, pas la visibilité.
Corrigée puis re-mesurée sur le legacy — 14 PASS, inchangé.

**Deux défauts d'affichage vus À L'IMAGE :** la description d'un profil, rendue en ligne, étirait la
colonne du nom à 780 px sur un écran de 1920 et poussait les quatre autres à droite (`.rw-cellule-note`
la met sous le nom) ; et l'astuce sur `{machine.name}` s'affichait même sur une plateforme sans aucun
profil, où elle décrivait un contenu absent — elle est désormais dans la branche garnie.

**Non porté, et dit tel quel** : la création, la modification et la suppression d'un profil, ainsi que
son assignation à une machine (V5). Le panneau le dit et mène à l'ancien portail. `notes` n'est affiché
par aucun des deux portails hors de la boîte de modification : il reste donc hors de V2.

## E-75 — « La » configuration globale n'existe pas : c'est la plus récente. Et un `UPDATE` sans `WHERE platform`

**Module `supervision/`, sous-lot V3 : la configuration globale, en lecture.** Suite :
`tests/e2e/go-page-supervision-config.mjs` — **15 PASS sur le legacy, 17 sur le portage**.

**LA TABLE EST VIDE, ET C'EST LA PREMIÈRE MESURE.** `supervision_config` ne porte **aucune ligne**, pour
aucune des quatre plateformes. Un sous-lot de lecture sur une table vide ne mesurerait qu'un écran
d'absence : la suite pose donc une **fixture**, nettoyée à l'entrée et dans un `finally`, et elle
**annonce l'état restauré**. Vérifié avant de l'écrire : `backend/scheduler.py` ne lit **jamais**
`supervision_config` (zéro occurrence) — seuls un déploiement ou une reconfiguration la lisent, et
aucun des deux ne part sans un clic. La fixture n'arme donc aucun déclencheur.

**AUCUNE CONTRAINTE D'UNICITÉ SUR `platform`.** La clé primaire est `id` seul. Or `_get_global_config()`
(`supervision.py:132`) et la page legacy lisent tous deux `ORDER BY id DESC LIMIT 1` : « la »
configuration globale d'une plateforme est en réalité **la plus récemment enregistrée**, et rien
n'empêche d'en accumuler. Ce n'est pas la même chose. **Mesuré** : la suite pose **deux** lignes Zabbix
et vérifie que c'est la seconde qui s'affiche — sur les deux portails. Le portage reproduit ce choix,
parce que le corriger serait une migration, mais il le **nomme** à l'écran plutôt que de laisser croire à
un enregistrement unique.

**UN `UPDATE` SANS `WHERE platform`, et c'est le défaut que V4 devra corriger.** `supervision.py:508`
fait `SELECT id, tls_psk_value FROM supervision_config ORDER BY id DESC LIMIT 1` — **sans filtre de
plateforme** — puis `UPDATE ... WHERE id = %s`. Enregistrer le formulaire Zabbix peut donc écraser une
ligne **Centreon** si celle-ci est la plus récente. Localisé par lecture, non exercé : V3 est en lecture,
et l'exercer voudrait dire écrire. À corriger en V4.

**LE SECRET NE FUIT PAS — mesuré, et c'est une bonne nouvelle qu'il faut dire telle quelle.** La
suspicion portée par le suivi de chantier était que `tls_psk_value` pouvait sortir en clair. **Faux** :
le legacy rend `'********'` dans son `<input type="password">`, et la valeur réelle posée en fixture
(`rw-e2e-v3-PSK-…`) **n'apparaît nulle part dans le source servi** — recherche faite dans
`page.content()`, pas dans le texte visible, précisément parce qu'un attribut peut porter autre chose que
ce que l'œil lit. Le backend est correct lui aussi : `POST /supervision/config` refuse d'écrire
`'********'` par-dessus le vrai PSK (`if psk_value == '********' or not psk_value: psk_final =
existing[...]`).

**Le portage va plus loin, structurellement : il ne LIT pas les deux secrets.**
`configurationParPlateforme()` ne sélectionne ni `tls_psk_value` ni `telegraf_output_token` — elle rend
deux **booléens** de présence. Masquer une valeur déjà chargée la laisse en mémoire, dans la vue, et à
portée du premier gabarit qui l'affichera par mégarde ; ne pas la lire ferme la question.

**Une asymétrie du legacy, mesurée deux fois.** La configuration **Zabbix** est rendue côté serveur
(`$globalConfig` dans `index.php`) ; les **trois autres** sont rendues avec des valeurs par défaut en dur
puis remplies par un appel client `GET /supervision/config/<plateforme>` (`main.js:159`). Deux chemins
pour une même donnée, et **3 requêtes** mesurées à la bascule vers Centreon. Le portage peint les quatre
côté serveur : **0 appel**.

**Un défaut latent, dit avec ses deux moitiés.** `GET /supervision/config` (`supervision.py:455`) masque
`tls_psk_value` mais **pas** `telegraf_output_token`, alors que sa voisine par plateforme
(`supervision.py:1602`) masque les deux — un garde posé sur une sonde et pas sur l'autre. En pratique
cette route ne lit que la ligne `zabbix`, où la colonne du jeton est normalement `NULL`, donc **la fuite
n'est pas vive** : elle est à un enregistrement de l'être. Le seul appelant est
`legacy/adm/health_check.php`. Non corrigé — c'est du backend.

**Deux défauts d'affichage vus À L'IMAGE.** `.rw-tableau` ne stylait que les `th` du `thead` : un
`th scope="row"` retombait sur le défaut du navigateur — **centré** — et sur une colonne de 690 px
l'étiquette se retrouvait au milieu du vide, à l'autre bout de la valeur qu'elle nomme. Puis, le
correctif appliqué, **à 390 px l'étiquette en `nowrap` prenait 215 des 350 px disponibles et repoussait
la VALEUR hors du cadre** : on gardait le mot et on perdait la donnée. Elle se replie désormais sous
700 px. Aucune assertion DOM ne voyait ni l'un ni l'autre.

**Non affiché délibérément** : `updated_at` et `updated_by`. `updated_at` est écrit par MySQL, donc dans
le fuseau du conteneur de base, et l'afficher ferait entrer dans cette page le décalage déclaré en
**E-73**. V3 montre la configuration, pas sa piste d'audit.

**Non porté, et dit tel quel** : l'écriture de la configuration (V4), qui corrigera le `WHERE platform`
manquant. Le panneau le dit et mène à l'ancien portail.

## E-76 — Enregistrer la configuration Zabbix écrivait dans la ligne Centreon. Mesuré.

**Module `supervision/`, sous-lot V4 : l'écriture de la configuration globale** — le premier sous-lot du
module qui écrit. Suite : `tests/e2e/go-page-supervision-config-ecriture.mjs` — **11 PASS sur le legacy,
16 sur le portage** (base rouge relevée avant portage : **11 PASS / 3 FAIL**).

**LE DÉFAUT N'EST PLUS DÉDUIT, IL EST MESURÉ.** E-75 l'avait localisé par lecture :
`supervision.py:508` fait `SELECT id, tls_psk_value FROM supervision_config ORDER BY id DESC LIMIT 1` —
sans `WHERE platform` — puis `UPDATE ... WHERE id = %s`. La suite pose une ligne `zabbix`, **puis** une
ligne `centreon` (id plus grand), tape une valeur dans le formulaire Zabbix, enregistre, et lit la base :

```
apres enregistrement — ligne zabbix   : zabbix_server=rw-e2e-v4-zbx-avant.example   ← INCHANGÉE
apres enregistrement — ligne centreon : zabbix_server=rw-e2e-v4-zbx-tape.example    ← la valeur tapée
```

L'exploitant voit un succès, **sa configuration Zabbix n'a pas bougé**, et **la ligne Centreon porte
désormais des réglages Zabbix**. Le même effet est visible sur la colonne du secret : le nouveau blob
`sodium:` atterrit dans la ligne Centreon tandis que la ligne Zabbix garde l'ancien.

**Le portage écrit avec `WHERE platform = ?`** et n'hérite donc pas du défaut. Mesuré : la ligne Zabbix
prend la valeur tapée (`zbx-tape`, port `10077`) et la ligne Centreon est **intacte**. La propriété
assertée a **deux moitiés** — la ligne visée a changé, ET la voisine n'a pas bougé : mesurer seulement la
première laisserait passer un `UPDATE` qui écrit au bon endroit *et* à côté.

**LA COMPATIBILITÉ DU CHIFFREMENT A ÉTÉ MESURÉE, PAS SUPPOSÉE — et c'est ce qui a permis d'écrire en
base.** La consigne était : si l'interopérabilité PHP↔Python n'est pas démontrable, faire passer
l'écriture du PSK par la passerelle. Aller-retour exécuté le 2026-08-22 : un blob produit depuis le
conteneur `laravel` (HKDF-SHA256 `rootwarden-aes` + `secretbox`, préfixe `sodium:`) a été déchiffré par
`Encryption().decrypt_password()` dans `rootwarden_python` et a rendu la chaîne d'origine. L'écriture
directe est donc tenable, et `App\Support\SecretSupervision` porte cette mesure en commentaire.
**L'étiquette HKDF n'est pas celle du TOTP** (`rootwarden-totp`, dans `TotpCrypto`) : les usages sont
séparés des deux côtés, et les mélanger rendrait les secrets illisibles par le portail qui ne les a pas
écrits. **Il n'y a délibérément aucune méthode de déchiffrement** dans cette classe : V3 a pris soin de ne
pas charger le PSK, un `dechiffre()` l'offrirait à la première vue distraite.

**UNE DOUZIÈME CLÉ CASSÉE, non répertoriée, et elle n'était atteignable qu'ici.** `main.js:294` appelle
`__('supervision.zabbix_server')` — avec son préfixe de module. Or `__()` préfixe **déjà** par `js.` et
cherche dans `js.php` : la clé ne peut pas être trouvée. Mesuré en soumettant le formulaire avec un
serveur vide, l'écran rend **`supervision.zabbix_server`** suivi du mot **« requis »**, écrit en dur en
français — et il reste français quand la page est demandée en anglais.

**`config_saved` confirmée** : le message de succès du legacy affiche l'identifiant brut. C'est l'une des
onze, et seul V4 la rendait atteignable.

**Une mesure fausse, corrigée.** La première version de la suite déclarait le refus « non énoncé » alors
qu'il l'était : elle ne lisait que le bloc de configuration, or le legacy passe ce message à `toast()`,
qui écrit dans `#toast-container`, très loin dans le document. Chercher dans le seul bloc concerné est la
bonne règle quand on cherche **ce que le bloc affiche** ; ici on cherchait un **message**, et c'est la
cible qui décide où elle le met. La suite lit désormais le bloc **et** le porte-messages — et rien
d'autre : `body` entier ramènerait le menu et les libellés du gabarit.

**Le secret non retapé est préservé, des deux côtés.** Le legacy y arrive parce que son backend reconnaît
son propre masque (`if psk_value == '********'`). Le portage n'a pas besoin de cette gymnastique : son
champ part **toujours vide**, et vide veut dire « ne change rien ». La différence n'est pas cosmétique —
le legacy doit deviner l'intention, le portage la lit.

**Et un PSK réellement saisi arrive chiffré**, mesuré sur **toute la table** et non sur la ligne visée :
sur le legacy l'écriture atterrit dans la ligne d'à côté, donc une assertion visant la seule ligne Zabbix
n'aurait rien vu. Zéro ligne porte la valeur en clair ; le blob stocké porte bien le préfixe `sodium:`.

**Un défaut de mon propre portage, vu À L'IMAGE et corrigé.** La première version du formulaire rendait
`tls_connect` et `tls_accept` en **champs de texte libre** — par-dessus des colonnes
`enum('unencrypted','psk','cert')`. Une valeur hors liste aurait produit une **erreur d'écriture** là où
l'utilisateur attendait un enregistrement. Ce sont désormais des listes fermées, et **la liste est
revalidée côté serveur** : un `<select>` empêche la faute à l'écran, il n'empêche rien dans une requête
forgée. Hors liste, la valeur déjà en base est conservée.

**Ce que le portage corrige au passage** : `savePlatformConfig()` (`main.js:186`) force
`hostname_pattern: '{machine.name}'` et `extra_config: null` pour les trois plateformes non-Zabbix,
quelles que soient les valeurs à l'écran — deux champs que l'utilisateur remplit et que l'enregistrement
jette. Ici, ce qui est affiché est ce qui est écrit.

**Non porté, et dit tel quel** : l'écriture du `telegraf_output_token`. Elle vit dans une route à part du
backend, et l'inventer ici serait concevoir. La ligne du jeton affiche sa présence et renvoie à l'ancien
portail.

**Non corrigé — c'est du backend** : le `WHERE platform` manquant de `:508` reste en place pour tout
appelant du legacy. Le portage ne passe simplement plus par là.

## E-77 — Le CRUD des profils : sept chaînes en dur, deux boîtes natives, et deux mesures qui DÉDOUANENT

**Module `supervision/`, sous-lot V5 : créer, modifier et supprimer un profil.** Suite :
`tests/e2e/go-page-supervision-profils-crud.mjs` — **16 PASS sur le legacy, 19 sur le portage** (base
rouge relevée avant portage : **10 PASS / 9 FAIL**).

**DEUX FAITS MESURÉS QUI EXONÈRENT LE CODE EXISTANT, et il faut le dire aussi clairement qu'une
accusation.**

1. **`upsert_profile` porte bien `WHERE id=%s AND platform=%s`** (`supervision.py:1780`). Le défaut mesuré
   en V4 — un `UPDATE` dérivé d'un `SELECT ... ORDER BY id DESC LIMIT 1` **sans** filtre de plateforme —
   **n'est pas généralisé**. C'est une route particulière qui l'a, pas une habitude du module.
2. **La contrainte d'unicité EXISTE** : `UNIQUE KEY uk_platform_name (platform, name)`, lue au
   `SHOW CREATE TABLE`. Le message d'erreur du backend doute de lui-même — « nom déjà pris **?** », avec
   un point d'interrogation — mais il a raison sur le fond. Deux profils homonymes ne peuvent pas
   coexister sur une même plateforme, donc l'assignation n'est pas ambiguë. Le point d'interrogation
   était une hésitation de rédaction, pas un trou. Au passage : la contrainte porte sur le **couple**,
   donc deux profils de même nom sur deux plateformes différentes sont légitimes — et c'est voulu.

**TOUT EST MESURÉ AU CLIC, PAS PAR APPEL DE FONCTION — et c'est une correction de méthode.** La première
version de la suite déclenchait le legacy par `saveProfile()`, `editProfile()`, `deleteProfile()`. Cela
prouve que la fonction marche ; cela ne prouve pas que **le bouton l'atteint**. Un bouton non câblé, câblé
au mauvais gestionnaire, ou recouvert par un autre élément est **invisible** à un appel de fonction — et
cette famille de défaut a déjà coûté cher ici : un bouton déplacé faisait cliquer « Refuser et se
déconnecter » au lieu d'« Accepter ». La suite part désormais du **nom affiché** dans le tableau, descend
jusqu'au bouton de **sa** ligne, et clique. Cela vérifie en outre qu'un bouton agit sur la ligne où il se
trouve, ce qu'aucune autre mesure n'attrape si un `onclick` porte le mauvais identifiant.

**SEPT CHAÎNES FRANÇAISES ÉCRITES EN DUR dans `profiles.js`** — invisibles à tout contrôle d'i18n, qui
cherche des identifiants `module.cle` et la parité des jeux de clés, pas du français parfaitement
lisible : `Editer` (`:43`), `Supprimer` (`:45`), `Nouveau profil` (`:60`), `Editer profil : ` (`:79`),
`Le nom est obligatoire.` (`:96`), le texte entier du `confirm` de suppression (`:111`) et
`Erreur reseau` (`:105`, `:118`). Mesuré en anglais : le catalogue rend **`Editer`, `Supprimer`,
`Nouveau profil`** en français.

**DEUX BOÎTES NATIVES, dont une TROISIÈME confirmation non répertoriée.** Mesuré : un `alert()` — « Erreur
interne (nom deja pris ?) » — et un `confirm()` : « Supprimer le profil "…" ? Les serveurs assignés
perdront leur profil. » Ce `confirm` n'est **ni `confirm_deploy` ni `confirm_uninstall`** : c'est une
troisième confirmation native, absente des douze clés cassées — et pour cause, elle n'utilise même pas le
catalogue. La convention du portage les interdit toutes deux : elles recouvrent la ligne sur laquelle on
décide, ne se stylent pas, et bloquent le test qui doit mener le geste au bout.

**DIX ATTRIBUTS `onclick` dans le catalogue, jusqu'à 671 caractères.** Le portage : **zéro**. « Modifier »
y est une **adresse** — `?profil=<id>` — et le serveur pré-remplit le formulaire : l'enregistrement n'est
jamais dans la page deux fois, ni dans un attribut de gestionnaire, et il n'y a aucun gabarit JavaScript.

**LA CASCADE EST EXERCÉE, PAS DÉDUITE.** `machine_supervision_profile` est vide dans ce parc : la
conséquence la plus lourde d'une suppression — les serveurs perdent leur profil — ne se mesurerait pas
sans fixture. La suite pose une assignation sur la machine 2 (DEV, seule cible mutante autorisée),
supprime le profil, et constate **0 assignation orpheline**. Le portage **annonce ce coût avant le
geste**, dans le panneau de décision et chiffré (« :machines serveur(s) perdront ce profil ») ; le legacy
le dit dans un `confirm()` natif au texte français en dur.

**Une propriété d'écriture a deux moitiés, ici encore** : la ligne visée a changé **et** le profil témoin
— posé en base, pas par l'interface — n'a pas bougé. Vrai des deux côtés, puisque `upsert_profile` porte
son filtre.

**L'ASSIGNATION N'EST PAS PORTÉE, et c'est une décision, pas un oubli.** Son unique point d'entrée est le
*dropdown* du tableau de déploiement (`profiles.js:loadDeployProfileSelectors`), que le portage ne porte
pas encore. Côté legacy on choisit **un profil pour une machine** ; assigner depuis le catalogue
inverserait la relation — on choisirait **des machines pour un profil** — et comme la clé primaire de
`machine_supervision_profile` est `(machine_id, platform)`, une machine ne porte qu'un profil par
plateforme : l'inversion aurait l'effet non évident de **retirer la machine de son profil précédent**. Ce
serait concevoir, pas migrer. La page dit donc où se fait l'assignation, et la colonne « Machines » du
catalogue rend l'absence visible plutôt que muette.

**Ce qui reste au backend, et attend une décision** : les quatre routes de profils (`1734`, `1760`,
`1801`, `1817`) portent `@require_permission` mais **aucun `@require_role`**, alors que la cinquième
(`machines/<mid>/profile`, `1846`) porte `@require_role(2)` avec un commentaire « Patch A01 » — le
correctif a été appliqué à une route et pas à ses quatre voisines. Et `/supervision/` reste absent de
`$ADMIN_ONLY_PREFIXES`. Le portage écrit en base derrière la garde de la page, donc **chez lui la
permission garde enfin la requête** ; le legacy, lui, reste tel quel.

**Deux mesures fausses de ma suite, corrigées.** Le refus du doublon était déclaré « non énoncé » alors
qu'il l'était : le legacy le passe à `alert()`, **hors du document**, donc invisible à `innerText` — les
boîtes natives sont désormais jointes au texte cherché, et leur ouverture reste un écart mesuré à part.
Et le geste de modification était écrit en un seul `page.evaluate` : côté portage « Modifier » **navigue**,
et une navigation détruit le contexte d'exécution. Le geste se fait maintenant en trois temps — cliquer,
attendre une navigation *éventuelle* dehors, puis remplir et enregistrer — ce qui marche pour la boîte de
dialogue du legacy comme pour l'adresse du portage.

**Un défaut d'affichage vu À L'IMAGE** : le titre du formulaire se collait au dernier paragraphe du
catalogue, et les deux se lisaient d'un bloc. Le formulaire porte désormais un séparateur (`.rw-note`).

## E-78 — La détection de version : premier SSH du module, et un message qui disparaît avant son effet

**Module `supervision/`, sous-lot V6 : la détection de version d'agent.** Suite :
`tests/e2e/go-page-supervision-version.mjs` — **12 PASS sur le legacy, 14 sur le portage** (base rouge
relevée avant portage : **8 PASS / 5 FAIL**). **Premier sous-lot du module qui ouvre une session SSH
réelle**, sur Test-Server-Debian (id 2, DEV). `srv-zabbix` (id 1, PRODUCTION) n'est jamais jointe.

**LA COMMANDE DISTANTE A ÉTÉ LUE MOT POUR MOT AVANT LE MOINDRE CLIC**, et c'est ce qui a autorisé le
geste : `command -v zabbix_agent2 … && zabbix_agent2 -V | head -1 || … || echo 'NOT_INSTALLED'`. Rien
n'installe, rien n'écrit à distance, rien ne redémarre. `command -v` évite même le « sh: not found » qui
polluerait la sortie.

**DEUX EXONÉRATIONS, et une correction de supposition.**
- **La route est bien gardée** : `zabbix_version` (`:732`) et `generic_version` (`:1293`) portent
  `@require_api_key` + **`@require_role(2)`** (« Patch A01 : aligné sur les autres routes supervision »)
  + `@require_permission` + `@require_machine_access`. Contrairement aux quatre routes de profils (E-77),
  celles-ci ont bien reçu le correctif.
- **La détection écrit `supervision_agents` SEULEMENT.** La question posée était : cette table,
  `machines.zabbix_agent_version`, ou les deux ? Mesuré : la seconde existe, la page la lit dans son
  `SELECT`, et **personne ne l'écrit ici**.

**LA PROPRIÉTÉ CENTRALE, EXERCÉE : une détection qui ne trouve rien SUPPRIME l'agent enregistré.**
`_remove_agent` fait un `DELETE FROM supervision_agents WHERE machine_id AND platform`. Aucun agent n'est
installé sur Test-Server-Debian : la suite pose une ligne d'agent en fixture, clique, et constate **0
ligne** après. L'inventaire suit donc l'état réel des machines, y compris quand un agent a été désinstallé
hors du portail — et cela ne se mesure qu'en base.

**AUCUN APPEL DANGEREUX N'A PU PARTIR, et c'est mesuré, pas supposé.** Sur le legacy, le bouton de
détection partage sa barre d'outils avec « Déployer la sélection », « Reconfigurer » et
« Désinstaller » : la suite collecte les requêtes émises et assert qu'aucune ne contient `deploy`,
`uninstall` ni `reconfigure`. Une seule requête part : `POST …/supervision/zabbix/version`.

**LE PORTAGE REND L'ERREUR DE MASSE STRUCTURELLEMENT IMPOSSIBLE.** Le legacy fonctionne par cases à
cocher plus une barre partagée, avec un « Tout cocher » qui embarque **srv-zabbix, en PRODUCTION**. Le
portage donne à chaque ligne **son** bouton et n'a **aucune case** — mesuré : 0. On ne compte pas sur la
prudence de qui clique.

**UN MESSAGE ÉPHÉMÈRE NE SE LIT PAS APRÈS COUP, et ici c'est structurel.** `toast()` s'effacé au bout de
4 s (`head.php:172`) alors qu'une session SSH en demande 9 : le verdict a **toujours** disparu au moment
où son effet devient mesurable. Ma première mesure lisait le DOM après l'attente et déclarait « verdict
non énoncé » un verdict parfaitement affiché. Un `MutationObserver` installé **avant** le clic accumule
désormais le porte-messages, et la propriété devient « le verdict a été énoncé » — non « il est encore à
l'écran à l'instant où je regarde ». Côté portage, le verdict s'écrit dans la page **et y reste**.

**Et une seconde version fausse de la même mesure, corrigée.** L'observateur lisait le nœud ajouté :
`toast()` insère un `<div>` puis y met deux `<span>`, si bien qu'il voyait passer l'**icône seule** (« ℹ »)
avant que le texte existe. Avec un motif assez lâche, l'assertion passait alors pour une raison qui
n'était pas la bonne — pire qu'un échec. Elle relit désormais le porte-messages entier, le motif exige le
verdict lui-même, et **le fragment retenu est imprimé** dans le journal :
`« Aucun agent » dans « Aucun agent installe sur Test-Server-Debian… »`.

**LE PORTAGE FERME, CHEZ LUI, LE TROU DÉCLARÉ EN E-72.** `App\Support\RoutesBackend::ADMIN_SEULEMENT`
était le relevé fidèle de `ADMIN_ONLY_PREFIXES` — il recopiait donc l'absence de `/supervision/`. Or la
page exige `role:2` des deux côtés : personne de légitime ne perd un accès en l'ajoutant, et un rôle 1
porteur de `can_manage_supervision` cesse de pouvoir appeler `/api/gateway/supervision/profiles`, que le
backend ne garde par aucun `@require_role`. C'est la défense en profondeur que le commentaire de cette
classe annonce. **Le legacy garde son trou**, et il reste déclaré.

**Un client qui ne lit pas `resp.status` avale tous les refus** : le portage lit le statut **d'abord** et
dit « la lecture a été refusée (statut N), aucune conclusion ne peut en être tirée » — un 403 ne se
confond pas avec « aucun agent installé ».

**Deux défauts trouvés à la lecture, déclarés et non corrigés** — c'est du backend :
- **une LECTURE passe par `execute_as_root`** : relever un numéro de version n'exige aucun privilège ;
- **`agent_type` est calculé puis jeté** : la route distingue `zabbix-agent2` de `zabbix-agent`, le
  renvoie au client, et `_upsert_agent` ne prend que la version. Aucune colonne ne reçoit le type.

**Un texte devenu faux, vu À L'IMAGE.** Le bloc « Pas encore porté » annonçait que « le tableau du parc
arrive avec les sous-lots suivants » — alors que V6 vient de le porter. Il ne parle plus que de ce qui
reste : installer, reconfigurer, désinstaller, et le relevé du parc entier.

**Non porté, et dit tel quel** : le déploiement, la reconfiguration, la désinstallation (V10 à V12) et le
relevé de tout le parc en une fois (V8, à reconcevoir en tâche de fond — `scanAllAgents` lance quatre
requêtes par serveur en parallèle). Aucun de ces boutons n'existe dans le portage : un bouton présent mais
inerte serait pire qu'absent.

## E-79 — L'éditeur distant : la page nommait un fichier, le portail en lisait un autre

**Module `supervision/`, sous-lot V7 : l'éditeur de configuration distant, en lecture.** Deuxième
sous-lot SSH. Suite : `tests/e2e/go-page-supervision-editeur.mjs` — **12 PASS sur le legacy, 16 sur le
portage** (base rouge relevée avant portage : **10 PASS / 5 FAIL**).

**LES DEUX COMMANDES DISTANTES ONT ÉTÉ LUES MOT POUR MOT AVANT LE MOINDRE CLIC** :
`cat <chemin> 2>/dev/null || echo 'FILE_NOT_FOUND'` et
`LC_ALL=C ls -la <dir>/<fichier>.bak.* 2>/dev/null || echo 'NONE'`. Rien n'écrit, rien ne redémarre.
`LC_ALL=C` fixe le format de `ls` — sans lui, la locale du serveur changerait les colonnes que le backend
analyse.

**TROIS EXONÉRATIONS, et la troisième d'affilée dans ce module.** Les deux routes portent
`@require_api_key` + `@require_role(2)` + `@require_permission` + `@require_machine_access`. Un fichier
absent rend **404 en nommant le chemin** — le backend distingue donc « absent » d'« erreur interne ». Et
`supervisionFetch` lit `res.ok` : le refus n'est pas avalé.

**LE DÉFAUT CENTRAL : DEUX CHEMINS À L'ÉCRAN, DONT UN FAUX.** L'écran affiche
`CONFIG_PATHS[plateforme]`, **écrit en dur côté client** (`main.js:27-32`) — pour Zabbix, toujours
`/etc/zabbix/zabbix_agent2.conf`. Le backend, lui, calcule `_config_file_path(agent_type)` depuis
`supervision_config.agent_type` **en base** (`supervision.py:281-287`) : `zabbix-agent` →
`/etc/zabbix/zabbix_agentd.conf`. Dès que la configuration globale désigne l'agent historique, **la page
nomme un fichier et le portail en lit un autre**.

Mesuré, avec `agent_type = 'zabbix-agent'` en base et le fichier posé sur la machine de test :

```
legacy  : /etc/zabbix/zabbix_agent2.conf | /etc/zabbix/zabbix_agentd.conf   ← DEUX, dont un faux
portage : /etc/zabbix/zabbix_agentd.conf                                    ← celui qui a ete lu
```

**La propriété assertée est NÉGATIVE, et c'est ce qui la rend utile.** « Le chemin lu est affiché quelque
part » ne suffirait pas : le legacy le fait aussi, dans `#editor-path`. Ce qui le trahit, c'est que son
badge **continue** d'annoncer l'autre. La suite collecte donc **tous** les chemins visibles du panneau et
assert qu'aucun ne diffère de celui de la fixture — le seul que le backend pouvait lire.

**Côté portage, le chemin vient du SERVEUR et de la même source que la lecture.** C'est un doublon assumé
de `_config_file_path`, et **le test en fait la condition** : un doublon mesuré vaut mieux qu'une valeur
en dur que rien ne confronte. La même dérive vaudrait pour la liste des sauvegardes, qui dérive du même
chemin.

**CE QU'UN ÉDITEUR MONTRE LÉGITIMEMENT — et il faut le dire ainsi plutôt que d'accuser.** Le fichier de
fixture porte un `TLSPSKIdentity` : un `.conf` d'agent **peut** contenir un secret, et un éditeur existe
pour montrer le fichier qu'on édite. Le cacher le rendrait inutile. Ce qui se mesure est donc la **seconde
copie** : la suite compte les occurrences de l'identité PSK dans le source servi et exige **au plus une**.
Côté legacy le contenu arrive par JavaScript dans la `value` d'un `<textarea>`, donc zéro dans le source ;
côté portage, un rendu ne l'y mettrait qu'une fois. Ce que la borne interdit, c'est l'îlot de données,
l'attribut, le champ caché.

**TROIS CAS SÉPARÉS, LÀ OÙ LE LEGACY EN MÊLE DEUX.** Le portage distingue « le fichier n'existe pas »
(404 — une **réponse**, pas une panne), « la lecture a été refusée (statut N) » et « la lecture n'a pas
abouti ». Le legacy, lui, jette `HTTP 404: {"success":false,"message":…}` à l'écran : lisible pour qui
développe, pas pour qui exploite. La suite le mesure comme une **trace technique** dans les messages.

**`config_loaded` est désormais EXERCÉE, pas seulement repérée.** V4 l'avait trouvée dans le catalogue ;
ici l'écran rend `✓ config_loaded`. C'est un écart déclaré du legacy — l'assertion est donc réservée au
portage. En faire une exigence des deux côtés ferait échouer une suite qui mesure exactement ce qu'elle
doit.

**DEUX DÉFAUTS DE MON PROPRE PORTAGE, vus À L'IMAGE et corrigés :**
- **une variable de boucle utilisée hors de sa boucle.** Le panneau de l'éditeur n'est pas dans le
  `@foreach` des plateformes : y écrire `$plateforme` reprenait la **dernière** valeur laissée par la
  boucle — donc Telegraf — et l'éditeur annonçait le chemin d'une plateforme qu'on n'avait pas choisie.
  Blade laisse fuiter la variable sans broncher. Le chemin part maintenant de Zabbix et le script le suit
  au changement de plateforme, depuis les quatre valeurs posées en données ;
- **la page disait « Fichier lu » avant toute lecture.** Deux libellés désormais : « Fichier à lire »
  jusqu'au premier succès, « Fichier lu » ensuite. Même famille qu'un texte qui devient faux — sauf qu'ici
  il l'était dès le départ.

**Non porté, et dit tel quel** : l'écriture du fichier distant et la restauration d'une sauvegarde (V9,
qui **modifient** la machine). La zone d'édition est en lecture seule — un champ modifiable dont
l'enregistrement n'existe pas laisserait croire qu'on peut éditer. La liste des sauvegardes se lit ; le
bouton « Restaurer » n'existe pas.

**Un huitième français en dur, relevé au passage** : `saveRemoteConfig` (`main.js:539`) porte
`'Configuration vide'`. Il appartient au chemin de V9.

## E-80 — Le relevé de parc : le filtre borne une action de masse et pas sa voisine, et la production est dans le lot

**Module `supervision/`, sous-lot V8 : le relevé de tout le parc.** **Aucun portage n'a été écrit** — la
mesure a montré que ce n'était pas un portage à faire mais une décision d'exploitation à prendre. Ce qui
suit a été établi **par lecture du code et observation du réseau, sans jamais déclencher le geste** :
`scanAllAgents` joint `srv-zabbix` (id 1, PRODUCTION) par construction.

**CE QU'UN CLIC ENVOIE, COMPTÉ.** `scanAllAgents` (`main.js:88`) itère
`#deploy-table-body tr[data-machine-id]` et, pour chaque ligne, boucle sur les **quatre** plateformes.
Le parc compte **3 machines non archivées** — la requête de la page est
`WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived'`, donc `srv-zabbix` en fait partie.
Un clic ouvre donc **3 × 4 = 12 sessions SSH**, toutes lancées dans la **même boucle synchrone**, sans
étalement, sans plafond, sans file.

**LE DÉFAUT LE PLUS CONCRET : LE FILTRE NE BORNE PAS LE RELEVÉ.** Mesuré sur la page, l'onglet actif,
avec le filtre saisi sur `Test-Server` :

```
lignes réellement visibles          : 1   (Test-Server-Debian)
lignes visées par scanAllAgents     : 3   (OpenCVE-Test-OnPrem, srv-zabbix, Test-Server-Debian)
requêtes émises par la mesure       : 0   (prouvé au réseau — le bouton n'a pas été cliqué)
```

`filterDeployTable` pose `row.style.display = 'none'` mais laisse `data-machine-id` : le sélecteur du
relevé ne regarde pas la visibilité. Or **« Tout cocher », dans la même barre d'actions, la regarde** —
son sélecteur est `tr:not([style*="display: none"])`. Deux actions de masse voisines, sur le même
tableau, avec deux périmètres opposés, et rien à l'écran ne le dit. Quelqu'un qui filtre son parc pour
n'agir que sur une machine touche une machine par le chemin des cases, et **trois — dont la
production — par celui du relevé**.

**LE BACKEND CONDAMNE LUI-MÊME CE CHEMIN, TEXTUELLEMENT.** Le pool partagé par toutes les routes
`@threaded_route` porte ce commentaire (`routes/helpers.py:24-30`) : *« les operations longues de parc
(ex. /ssh-audit/scan-all) doivent elles passer en tache de fond (centre de taches), **jamais monopoliser
ce pool** »*. Il y est écrit parce que le sinistre a déjà eu lieu : le fix v1.37.13 relate qu'une boucle
SSH de parc **dans la requête HTTP** a produit des 504 en cascade sur toute l'interface. `ssh-audit` a
été corrigé dans cette vague ; **`supervision/` ne l'a pas été.** Et `threaded_route` bloque sur
`future.result()` **sans timeout** : au-delà des 32 slots, les requêtes ne tombent pas, elles s'empilent,
connexion HTTP tenue ouverte.

**IL N'EXISTE AUCUNE ROUTE DE PARC CÔTÉ BACKEND.** Les 30 routes du blueprint `supervision` sont toutes
par machine ; le relevé de parc n'existe **que** dans le JS du navigateur. Le porter « en tâche de fond »
n'est donc pas un portage : c'est **écrire une route backend qui n'a jamais existé**.

**DEUX CLÉS i18n CASSÉES, ET LA CAUSE RACINE EST L'IMAGE MIROIR DE CELLE DE V4.** Mesuré en résolvant
les clés dans la page, sans déclencher le relevé :

```
__('scan_all_running')  ->  "scan_all_running"                              ← l'identifiant à l'écran
__('scan_all_done')     ->  "scan_all_done"                                 ← l'identifiant à l'écran
__('select_machine')    ->  "Veuillez selectionner au moins une machine."    ← EXONÉRÉE
```

`window._i18n = getJsTranslations('js.')` (`head.php:76`) ne contient **que** l'espace `js.`. Les deux
clés existent bel et bien — mais dans `lang/{fr,en}/supervision.php`, sous `supervision.scan_all_running`,
que le JS ne peut pas atteindre. Symétrique de `supervision.zabbix_server` (V4), où la clé était appelée
**avec** son préfixe : ici elle est **écrite avec** et appelée **sans**. Et comme `__()` rend la clé
telle quelle, le repli `|| 'Scan en cours...'` **ne se déclenche jamais**. Treizième et quatorzième.

**UN NEUVIÈME FRANÇAIS EN DUR, celui-là toujours affiché.** `updateAgentCounter` (`main.js:84`) construit
`count + '/' + total + ' avec ' + currentPlatform`. Mesuré à l'écran : **`0/3 avec zabbix`**. Ce n'est pas
un repli inatteignable comme les précédents — c'est le texte que la page rend en anglais comme en français,
à chaque chargement et à chaque bascule de plateforme.

**UNE ACCUSATION QUE LA MESURE RETIRE.** Le suivi de chantier soupçonnait `updateAgentCounter` de
confondre les plateformes, parce qu'il compte par `b.textContent.trim().startsWith(letter)`. Vérifié :
les quatre lettres sont `Z`, `C`, `P`, `T`, les badges valent `letter + ' ' + version`, et
`.deploy-agents` ne contient aucun autre élément arrondi. **Aucune confusion possible avec le jeu de
badges actuel.** Le sélecteur reste fragile — il tient à ce que les quatre initiales restent
distinctes — mais il ne produit pas de faux compte aujourd'hui, et le dire est aussi net que l'accuser.

**LA DÉCISION N'EST PAS « COMMENT PORTER » MAIS « FAUT-IL UN RELEVÉ DE PARC ».** Les trois options
étudiées — ne pas porter, porter en tâche de fond, porter en séquentiel borné — **joignent toutes la
production** dès lors que le parc est « toutes les machines non archivées ». Reconcevoir le relevé change
sa charge, pas sa cible. Arbitrage porté à l'exploitant ; **rien n'a été porté sans lui**.

> **SUITE DONNÉE — cette entrée s'arrête à la mesure, elle n'est pas la conclusion.** L'exploitant a
> tranché pour la **tâche de fond**, avec autorisation explicite d'écrire la route backend manquante.
> L'écart signalé — cette option joint la production en usage réel — a été redit avant de commencer, et
> la décision maintenue. Le portage est décrit en **E-82**.

## E-81 — Le `@threaded_route` imbriqué n'existe pas. Huit branches mortes l'arment pour le jour où l'on nettoiera.

**Mesure faite en marge de V8**, parce que la question portait sur le pool que le relevé de parc allait
solliciter. Elle **referme** un point listé « à mesurer » depuis le début du module, par une réfutation
suivie d'un constat plus gênant que la supposition.

**LA SUPPOSITION ÉTAIT : Werkzeug pourrait router `/supervision/zabbix/version` vers le handler
générique**, qui délègue par `if platform == 'zabbix': return zabbix_version()`. Comme les deux fonctions
portent `@threaded_route`, chaque lecture Zabbix aurait consommé **deux** slots du pool partagé —
l'externe bloquée sur `future.result()` en attendant l'interne, dans le même pool. Sous un relevé de parc,
c'est un interblocage, pas un ralentissement.

**RÉFUTÉ, ET DANS LES DEUX ORDRES DE DÉCLARATION.** Mesuré avec le Werkzeug du conteneur, sur les deux
règles seules :

```
/supervision/zabbix/version    -> ('zabbix_version', {})                        ← la règle STATIQUE gagne
/supervision/centreon/version  -> ('generic_version', {'platform': 'centreon'})
ordre de déclaration inversé   -> ('zabbix_version', {})                        ← inchangé
```

Werkzeug trie ses règles par complexité, pas par ordre d'écriture : une règle sans variable passe devant.
**Aucune imbrication aujourd'hui.** Une lecture de version prend un slot, pas deux ; les 12 sessions d'un
relevé de parc prennent 12 slots sur 32.

**MAIS LES BRANCHES DE DÉLÉGATION SONT DU CODE MORT, ET ELLES SONT HUIT.** Toutes les paires
statique/générique du module sont dans ce cas, et **les deux côtés de chacune portent
`@threaded_route`** :

```
/supervision/zabbix/deploy        <->  /supervision/<platform>/deploy
/supervision/zabbix/version       <->  /supervision/<platform>/version
/supervision/zabbix/uninstall     <->  /supervision/<platform>/uninstall
/supervision/zabbix/reconfigure   <->  /supervision/<platform>/reconfigure
/supervision/zabbix/config/read   <->  /supervision/<platform>/config/read
/supervision/zabbix/config/save   <->  /supervision/<platform>/config/save
/supervision/zabbix/backups       <->  /supervision/<platform>/backups
/supervision/zabbix/restore       <->  /supervision/<platform>/restore
```

Le `if platform == 'zabbix'` de chaque handler générique est **inatteignable par HTTP**. C'est exactement
ce qui rend le piège dangereux : la règle statique ressemble à un doublon de la générique, et la supprimer
est le geste de nettoyage le plus naturel du monde. **Le jour où on la supprime, la branche morte devient
vivante et chaque appel Zabbix prend deux slots du même pool** — l'externe attendant l'interne. Avec 32
slots, un relevé de 16 machines sur 4 plateformes demanderait 128 slots : les externes prendraient les 32,
et aucune interne n'obtiendrait jamais le sien. Le pool ne ralentit pas, il se bloque.

**Ce n'est pas un défaut à corriger pendant un portage** : le code mort est inerte, et le retirer touche
le backend. Il est nommé ici pour que la suppression du « doublon » ne se fasse jamais sans retirer
d'abord le `@threaded_route` de l'un des deux étages.


## E-82 — Le relevé de parc porté en tâche de fond : la rafale devient une tâche, et le coût s'énonce avant le geste

**Module `supervision/`, sous-lot V8 : le relevé des agents de tout le parc.** Suite :
`tests/e2e/go-page-supervision-releve.mjs` — **11 PASS sur le legacy, 28 sur le portage** (base rouge
relevée avant portage : **3 PASS / 4 FAIL**). Plus **12 tests backend** neufs.
**PREMIÈRE ROUTE PYTHON ÉCRITE PENDANT CETTE MIGRATION**, sur autorisation explicite de l'exploitant
(voir E-80) : `POST /supervision/scan-all`.

**CE QUE LA ROUTE REMPLACE.** Le relevé n'existait que dans le navigateur. Mesuré :
`3 machines × 4 plateformes = 12 requêtes` lancées dans la même boucle synchrone, chacune ouvrant sa
session SSH, chacune `@threaded_route` — donc chacune consommant un slot du pool **partagé par toutes
les routes du backend**, celui dont le commentaire interdit précisément cet usage. Désormais : une
réponse immédiate `{queued, background, task_id}`, puis un **unique thread démon** qui balaie le parc
**séquentiellement**. Le pool partagé n'est plus touché du tout.

**UNE SEULE SESSION SSH PAR MACHINE, ET C'EST MESURÉ AU JOURNAL PARAMIKO.** Le legacy ouvre une session
par plateforme, puisqu'il envoie une requête par plateforme. Ici les quatre lectures partagent la
session de la machine :

```
INFO  paramiko.transport: Authentication (password) successful!
DEBUG paramiko.transport: Secsh channel 0 opened.   zabbix_agent2 -V
DEBUG paramiko.transport: Secsh channel 1 opened.   centreon-monitoring-agent --version
DEBUG paramiko.transport: Secsh channel 2 opened.   node_exporter --version
DEBUG paramiko.transport: Secsh channel 3 opened.   telegraf --version
DEBUG paramiko.transport: EOF in transport thread
```

Un transport authentifié, quatre canaux. Sur le parc courant : **3 sessions au lieu de 12**. La mesure a
aussi levé un doute qu'elle **exonère** : l'échec `Authentication (publickey) failed` visible avant le
mot de passe n'est pas un drapeau de compte de service périmé — `service_account_deployed = 0` pour cette
machine, la base dit donc la vérité, c'est la négociation normale de paramiko.

**LE COÛT S'ÉNONCE AVANT LE GESTE, ET LA PRODUCTION EST NOMMÉE.** Le bouton n'envoie rien : il ouvre un
panneau de décision rendu par le serveur — `3 machine(s), 4 plateforme(s), 3 session(s) SSH — une par
machine, pas une par plateforme` et, en dessous, `Machines de PRODUCTION concernées : srv-zabbix.`
**Nommer plutôt que compter est le point** : « 3 machines » ne prévient personne, « dont srv-zabbix (PROD) »
prévient. Le legacy n'annonce ni le nombre de machines, ni le nombre de sessions, ni que la production
est dans le lot — et son relevé ignore le filtre de la table, donc les machines jointes ne sont même pas
celles qui sont à l'écran (E-80).

**LE CORPS DE LA REQUÊTE EST VIDE, ET LE TEST EN FAIT UNE PROPRIÉTÉ.** La portée vient du **serveur**.
Envoyer une liste d'identifiants lue dans le tableau, c'est exactement le défaut du legacy : sa liste ne
correspond plus à ce qui est affiché dès qu'on filtre. La suite assert que le POST part avec `{}`.

**COMMENT ON CLIQUE UN BOUTON QUI JOINDRAIT LA PRODUCTION.** C'était la difficulté de ce sous-lot. La
suite clique le vrai déclencheur, puis le vrai bouton de confirmation — et **la requête de confirmation
est interceptée et avortée**. Le geste est exercé de bout en bout, la requête est mesurée (méthode,
chemin, corps), et aucune machine n'est jointe. Les deux règles tiennent ensemble : *cliquer le bouton,
pas appeler la fonction* et *ne jamais joindre srv-zabbix*. Le contrat de mise en file, lui, se mesure
sur une **portée explicite** (`machine_ids: [2]`, DEV) : **200 en 230 ms**, là où le legacy tient la
connexion ouverte pendant tout le balayage.

**ET LE CHEMIN « TOUT LE PARC » N'EST PAS LAISSÉ SANS MESURE.** Une suite de navigateur ne peut pas le
déclencher. Les **12 tests backend** le peuvent, parce que `_spawn_scan_all_thread` est isolé pour être
patchable — jamais `threading.Thread` globalement, dont le `ThreadPoolExecutor` de `@threaded_route`
dépend pour créer ses workers. Le thread patché, on lit **quelles machines auraient été balayées**.

**UN GARDE SANS OBJET NE GARDE RIEN, ET CETTE ROUTE EN FAISAIT UN CAS D'ÉCOLE.**
`@require_machine_access` lit `machine_id`/`machine_ids` dans le corps et fail-close sur tout identifiant
refusé — mais un corps vide ne lui donne **rien à refuser**. Sur une route dont le corps vide *signifie
tout le parc*, il aurait eu l'apparence d'un garde sans en être un. Le parc implicite est donc filtré
dans le handler, par `check_machine_access`, machine par machine — et un test le prouve en refusant
l'accès à la machine 1. Ce filtre **ne retire rien aujourd'hui** (la route exige le rôle 2, et
`check_machine_access` rend vrai dès le rôle 2) : c'est dit plutôt que sous-entendu.

**AUCUNE NOTIFICATION, DÉLIBÉRÉMENT.** `/ssh-audit/scan-all`, le modèle suivi par ailleurs, appelle
`notify_subscribed` pour chaque machine auditée. Un relevé de version n'est ni une alerte ni un verdict :
rien ne part. Un effet sortant ne se défait pas, et il n'y a rien à signaler à personne quand on constate
qu'un agent est en 7.0.

**LE PRIVILÈGE DE LA COMMANDE N'A PAS ÉTÉ CHANGÉ.** La lecture passe par `execute_as_root`, comme les
routes par machine. Lire un numéro de version n'exige aucun privilège — défaut déjà déclaré (E-78) — mais
changer le niveau de privilège d'une commande distante est un **changement de droits**, qui ne se fait pas
au détour d'un portage ; et une lecture qui échouerait sans root produirait un écart de comportement avec
les routes existantes.

**DEUX DÉFAUTS DE MON PROPRE PORTAGE, VUS À L'IMAGE :**
- **le coût s'affichait en vert de réussite** (`rw-confirmation`) à l'intérieur d'un panneau à bordure
  rouge. Le vert invite à cliquer alors que la phrase énonce un **coût** — passé en encart neutre. Aucune
  assertion DOM ne voit une incohérence de sens ;
- **le bouton était à plus de mille pixels de la phrase qui l'explique.** La convention « action
  principale à droite » vaut pour un **pied de formulaire**, où l'œil descend une colonne de champs ; pour
  une action unique attachée à une explication, elle rompt la chaîne. Ramené sous son texte.

**UN DÉFAUT DE MA PROPRE SUITE, trouvé par la suite elle-même.** Son premier nettoyage supprimait les
tâches **par type** : il aurait effacé l'historique d'un relevé lancé par un exploitant, sans que rien ne
le signale. Elle ne supprime plus que la tâche dont elle a retenu l'identifiant, et sa propriété de sortie
est un **delta**, pas un zéro — compter les tâches préexistantes comme un échec la ferait échouer sur
l'historique de quelqu'un d'autre.

**UN TEXTE QUI ALLAIT DEVENIR FAUX, corrigé dans le même commit.** Le bloc « pas encore porté » annonçait
« le relevé de tout le parc en une fois » parmi les gestes à venir. V8 le porte : la phrase est réduite aux
trois gestes qui **modifient** les serveurs.

**UN NEUVIÈME FRANÇAIS EN DUR, relevé et non porté** : `updateAgentCounter` (`main.js:84`) rend
`0/3 avec zabbix`. Le portage n'a pas de compteur d'agents ; l'assertion correspondante est une garde
tournée vers l'avenir, et elle le dit — la prendre pour une mesure serait se tromper.

**DEUX AUTRES DÉFAUTS DE MA SUITE, TROUVÉS PAR LE LOT ET PAS PAR L'EXÉCUTION ISOLÉE.** Elle passait
25/0 seule et **24/1 dans le LOT** — la marque d'un défaut de la suite, pas du portage :

- **une attente FIXE après un geste.** Le clic d'onglet était suivi de `dors(1200)`. Seule, la suite
  avait le temps ; sous la charge des autres suites, le script de la page n'avait pas encore pris la
  main, **le clic ne faisait rien**, le panneau restait caché, et son texte anglais n'existait donc pas
  dans `innerText`. Une assertion juste échouait pour une raison étrangère à ce qu'elle mesure. On attend
  maintenant la PROPRIÉTÉ — le panneau est visible — avec une borne, et on **re-clique** tant qu'elle
  n'est pas obtenue : c'est le geste qui peut être perdu, pas seulement son effet ;

- **le garde anti-rejeu TOTP traverse les contextes de navigateur, et c'était le vrai coupable.** Cette
  suite est la première du module à se connecter **deux fois** (une passe FR, une passe EN). Le garde
  étant par COMPTE et EN BASE, la seconde connexion dans la même fenêtre de 30 s rejoue un code déjà
  consommé : la session n'est pas authentifiée et **la page servie est celle de connexion**. Or les deux
  contrôles d'i18n *passaient* sur cet écran — qui ne porte évidemment aucun identifiant de traduction.
  **Un PASS dont on ne sait pas pourquoi il passe ne vaut rien.** Correction en trois pièces : attendre le
  basculement de la fenêtre avant la seconde connexion, **asserter que la session a tenu** (sans quoi tout
  ce qui suit mesure la mauvaise page), et proposer une seule fois un code neuf si le second facteur est
  refusé. Quatre exécutions consécutives à 28/0, puis conforme dans le LOT complet — plutôt que de
  déclarer la suite instable, ce qui a déjà été fait à tort pour deux autres suites de ce dépôt.

**ET UN CHIFFRE HÉRITÉ QUI N'ÉTAIT PAS UNE MESURE.** Le suivi de chantier annonçait « 65 suites » depuis
plusieurs sous-lots. Compté dans le journal du rejeu : **74 exécutions de suite** (38 portage, 36 legacy)
pour **974 assertions**, donc 72 avant V8. Même règle que pour les références de suite — on compte, on ne
reconduit pas.

## E-83 — Trois plateformes sur quatre annoncent une réussite qu'elles n'ont pas vérifiée

**Module `supervision/`, sous-lot V9 : l'écriture du fichier distant et la restauration d'une
sauvegarde.** Mesures faites sur **Test-Server-Debian (id 2, DEV)** ; `srv-zabbix` jamais jointe. La
machine de test a `/etc/zabbix/` mais **ni agent ni `systemctl`** : le cas nominal y est donc « écriture
réussie, redémarrage impossible », exactement celui qu'il fallait mesurer. État rendu à l'identique en
sortie (répertoire vide, comme à l'entrée).

**LE DÉFAUT CENTRAL, MESURÉ SUR UNE ÉCRITURE QUI NE POUVAIT PAS ABOUTIR.** `POST
/supervision/telegraf/config/save` vers un répertoire `/etc/telegraf/` **qui n'existe pas** :

```
reponse : 200 {"success":true,"message":"Config telegraf sauvegardee et agent redemarre."}
realite : ls: cannot access '/etc/telegraf/': No such file or directory
```

Rien n'a été écrit. Aucun agent n'a été redémarré. Le portail affirme les deux. Cause :
`generic_config_save` **jette les trois codes de retour** — celui de la sauvegarde, celui de l'écriture,
celui du redémarrage — et rend un succès inconditionnel. `generic_restore` fait de même pour le `cp` et
le redémarrage. Cela vaut pour **Centreon, Prometheus et Telegraf**, soit trois des quatre plateformes de
la page.

**LA ROUTE ZABBIX, ELLE, DIT LA VÉRITÉ — et c'est ce qui rend l'écart si net.** Sur la MÊME machine, avec
le MÊME `systemctl` manquant :

```
zabbix    : 200 {"success":true,"message":"Config sauvegardee mais restart echoue: sh: 1: systemctl: not found"}
telegraf  : 200 {"success":true,"message":"Config telegraf sauvegardee et agent redemarre."}
```

Même page, même bouton, même échec : une réponse exacte et une réponse fabriquée. `zabbix_config_save`
vérifie le `rc` de l'écriture, **restaure la sauvegarde si elle échoue**, et distingue explicitement le
troisième cas (« sauvegardée mais restart échoué »). Trois protections que ses trois voisines n'ont pas.

**MAIS `zabbix_restore` MENT AUSSI, ET C'EST LE CHEMIN DE SECOURS.** Mesuré :

```
POST /supervision/zabbix/restore  ->  200 {"success":true,
    "message":"Backup zabbix_agent2.conf.bak.20260822_171737 restaure et agent redemarre."}
```

Sur une machine **sans `systemctl`**. Le redémarrage n'a pas pu avoir lieu ; la route jette son code de
retour, là où sa jumelle `config/save` le vérifie. La restauration est précisément le geste qu'on fait
quand quelque chose est déjà cassé : c'est la pire des quatre routes où placer une affirmation non
vérifiée. Le `cp` de restauration, lui, EST vérifié — seul le redémarrage est passé sous silence.

**UN `A && B || C` QUI EFFACE LA DIFFÉRENCE ENTRE « RIEN À SAUVEGARDER » ET « SAUVEGARDE ÉCHOUÉE ».**
`_backup_agent_config` exécute `test -f X && cp X Y || echo 'NO_FILE'`. Mesuré sur la machine de test, les
trois cas :

```
fichier absent                 -> sortie [NO_FILE]  rc=0     (comportement voulu)
fichier present, cp reussi     -> sortie []         rc=0
fichier present, cp ECHOUE     -> sortie [NO_FILE]  rc=0     <- INDISCERNABLE du premier
```

Un `cp` en échec emprunte donc la branche « pas de fichier » : la fonction rend `None`, l'écriture
continue **sans sauvegarde**, et comme le rollback est gardé par `if backup_path:`, **il est désarmé au
moment précis où il servirait**. Le `>` tronquant le fichier avant d'écrire, un échec à ce stade laisse
une configuration tronquée et rien pour la rétablir.

**CINQ EXONÉRATIONS, dites aussi nettement qu'une accusation :**
- **la traversée de chemin est refusée.** `_BACKUP_NAME_RE = ^[\w.-]+\.bak\.\d{8}_\d{6}$` interdit le
  `/` : rien ne sort du répertoire. Mesuré — `{"backup_name":"../../etc/passwd"}` rend
  `{"message":"Nom de backup invalide"}`. La même expression interdit espaces, guillemets, `$` et `;`,
  donc l'interpolation de `backup_path` dans `cp` n'est pas injectable non plus ;
- **le chemin de configuration n'est jamais choisi par le client** : `_config_file_path` rend deux
  littéraux, et les plateformes non-Zabbix le lisent dans `AGENT_REGISTRY` ;
- **le contenu voyage en base64**, et le transport est fidèle à l'octet. Vérifié à `od -c` : les sauts de
  ligne arrivent réels, le `\r\n` est normalisé avant l'encodage ;
- **la sauvegarde est faite AVANT l'écriture, et elle contient bien l'ancienne version.** Mesuré : une
  seconde écriture a produit `zabbix_agent2.conf.bak.20260822_171737` de 35 octets — la version
  précédente — pendant que le fichier passait à 39 ;
- **les quatre routes portent les quatre gardes** : `@require_api_key`, `@require_role(2)`,
  `@require_permission('can_manage_supervision')`, `@require_machine_access`. Et le `restore` vérifie
  l'existence du backup avant d'agir (404 en le nommant).

**LE CLIENT PERD LE SEUL AVERTISSEMENT QUE LE BACKEND AVAIT PRIS LA PEINE D'ÉMETTRE.** `saveRemoteConfig`
fait `toast(__('config_remote_saved') || res.message, 'success')`. Comme `__()` rend la clé absente
**telle quelle** — donc non vide — `res.message` **n'est jamais lu**. Le message
« sauvegardée mais restart échoué », que la route Zabbix construit exprès, n'atteint donc **jamais
l'écran** ; et ce que l'écran affiche est la chaîne littérale `config_remote_saved`, en toast **vert**.
La dette i18n ne fait pas que défigurer un libellé : ici elle **supprime un avertissement**.
`restoreBackup` a la même forme et affiche `backup_restored`.

**TROIS CLÉS DE PLUS DANS LA MÊME FAMILLE — 15e, 16e, 17e.** `config_remote_saved`, `backup_restored` et
`btn_restore` existent sous `supervision.*` et **dans aucun des deux `js.php`** : mesuré nominativement,
`fr=1 en=1` côté module, `fr=0 en=0` côté JS. Le bouton de restauration affiche donc l'identifiant
`btn_restore`. `no_backups` avait déjà été relevée en V7, même cause.

**ET LA RESTAURATION N'A AUCUNE CONFIRMATION.** La liste des sauvegardes s'ouvre dans une fenêtre
modale ; chaque ligne porte un bouton qui, **d'un seul clic**, écrase la configuration courante et
redémarre l'agent. Ni `confirm()` natif, ni panneau : rien. C'est le même trou que `reconfigure` (V10).

**LE HUITIÈME FRANÇAIS EN DUR est bien là où il était annoncé** : `saveRemoteConfig` (`main.js:539`)
porte `'Configuration vide'`. À noter que le backend rend lui aussi ses messages en français seulement, et
que les deux portails les affichent tels quels — un écran en anglais annonce donc
« Config sauvegardee mais restart echoue » en français.

**CE QUE CETTE MESURE POSE COMME QUESTION.** Le portage passe par la passerelle vers le backend (décision
V6→V12 : le SSH appartient au backend). Porter l'écriture sur les quatre plateformes, c'est donc **hériter
de l'affirmation fabriquée** pour trois d'entre elles — le portage annoncerait à son tour une réussite
qu'il n'a pas vérifiée. Arbitrage porté à l'exploitant : corriger les trois routes génériques (elles
mentent aujourd'hui aux DEUX portails) ou porter l'écriture pour Zabbix seul et dire pourquoi.

## E-84 — L'écriture distante portée : le troisième cas dit, et un défaut de mon propre portage de V7

**Module `supervision/`, sous-lot V9 : l'écriture du fichier distant et la restauration.** **PREMIER
SOUS-LOT DU MODULE QUI MODIFIE UNE MACHINE.** Suite :
`tests/e2e/go-page-supervision-ecriture.mjs` — **18 PASS sur le legacy, 38 sur le portage** (base rouge
relevée avant portage : **5 PASS / 4 FAIL**). Plus **10 tests backend** neufs ; **318 pytest** au total.

**POURQUOI CETTE SUITE PEUT CLIQUER, LÀ OÙ CELLE DE V8 NE POUVAIT PAS.** Le geste de V8 joignait
`srv-zabbix` **par construction** ; il fallait intercepter et avorter. Ici le geste porte sur **une**
machine, celle qu'on choisit dans la liste : **Test-Server-Debian (id 2, DEV)**. La production n'est
jamais sélectionnée, donc jamais jointe, et le vrai bouton est cliqué des deux côtés. Ce que le geste
écrit et rien de plus : `/etc/zabbix/zabbix_agent2.conf` et ses copies datées, nettoyés à l'entrée et dans
un `finally`, et l'état rendu est **relu pour être prouvé** plutôt qu'affirmé.

**LE CORRECTIF BACKEND, AUTORISÉ PAR L'EXPLOITANT** (voir E-83). `generic_config_save` et
`generic_restore` vérifient désormais leurs codes de retour, restaurent la sauvegarde si l'écriture échoue,
et distinguent le troisième cas. Mesuré sur l'appel qui mentait :

```
avant : 200 {"success":true,  "message":"Config telegraf sauvegardee et agent redemarre."}
apres : 500 {"success":false, "message":"Ecriture echouee: cannot create /etc/telegraf/telegraf.conf: Directory nonexistent"}
```

`zabbix_restore` a été corrigé **par cohérence, au-delà de la lettre de l'autorisation** : elle portait le
même défaut — le code de retour du redémarrage jeté, un « agent redémarré » non vérifié — et laisser la
route générique plus honnête que sa jumelle Zabbix aurait recréé l'incohérence à l'envers. C'est un choix
de jugement, il est dit ici pour pouvoir être défait seul. **`restarted` est un booléen ajouté aux quatre
routes** : un client n'a pas à deviner l'issue en analysant une phrase française. Ajout purement additif.
**`_backup_agent_config` n'a PAS été touché** : la correction du `A && B || C` n'a pas été autorisée, et
six routes en dépendent, dont le déploiement. Le défaut reste déclaré en E-83.

**LE TROISIÈME CAS EST DIT, ET C'EST TOUTE LA DIFFÉRENCE.** La machine de test n'a ni agent ni
`systemctl` : l'écriture réussit, le redémarrage échoue. Mesuré des deux côtés, sur le même geste :

```
legacy  : ✓ config_remote_saved                       ← coche verte, clé cassée, pas un mot du redémarrage
portage : Fichier ecrit, mais l'agent n'a PAS redemarre. La configuration est en place
          et le service ne tourne pas : verifiez-le avant de compter sur la supervision
          de ce serveur.
```

Le legacy ne cache pas l'avertissement par négligence d'affichage : **la dette i18n le supprime**. Son
`toast(__('config_remote_saved') || res.message, 'success')` n'atteint jamais `res.message`, puisqu'une clé
absente est rendue telle quelle donc non vide. Le portage lit le **booléen** et dit l'issue, traduite —
sans jeter à l'écran la sortie d'erreur brute de la commande distante, que le test vérifie absente.

**UN DÉFAUT DE MON PROPRE PORTAGE DE V7, TROUVÉ EN LISANT UN TEXTE DEVENU FAUX.** Le bloc « pas encore
porté » de l'éditeur annonçait encore « la lecture et l'écriture arrivent avec les sous-lots suivants »
alors que la lecture était portée depuis V7. En le corrigeant, la question s'est posée : la route suit-elle
la plateforme ? **Non.** Les quatre URL étaient **figées** sur `/supervision/zabbix/...` pendant que le
chemin affiché suivait le sélecteur. La base rouge le prouve :

```
FAIL  aucune plateforme ne voit la route et le chemin divergents
      — centreon: route vise zabbix | prometheus: route vise zabbix | telegraf: route vise zabbix
```

Choisir Telegraf annonçait `/etc/telegraf/telegraf.conf` et lisait `/etc/zabbix/zabbix_agent2.conf` :
**exactement le défaut E-79 que V7 reprochait au legacy**, revenu par la ROUTE au lieu du CHEMIN. V7 avait
raisonné sur la bonne source pour le chemin et n'avait pas regardé l'adresse. Et sa suite ne pouvait pas
le voir : elle n'exerçait que Zabbix, la seule plateforme où l'URL figée se trouvait être la bonne.
Chemins et routes viennent maintenant de la **même** table serveur, indexée par la même clé, et la
propriété est mesurée **sur les quatre plateformes** — par interception, donc sans une seule session SSH.

**UN AUTRE DÉFAUT DE MON PORTAGE, SURGI D'UNE ERREUR DE MA SUITE.** La suite échouait à ouvrir le panneau ;
le portage avait raison. Changer de serveur **vide la zone d'édition** (mon code de V7), et j'avais rempli
avant de choisir. Vider est correct — la configuration d'un serveur n'a aucun sens pour un autre — mais
V7 laissait ce champ en **lecture seule**, donc vider ne perdait rien. Depuis que V9 le rend modifiable, le
même geste peut effacer ce que quelqu'un vient de taper : un effacement silencieux devient une **perte de
travail**. Il est désormais annoncé, et une assertion le mesure.

**LE COÛT S'ÉNONCE, ET LES TROIS EFFETS SONT ÉNUMÉRÉS.** Le bouton n'envoie rien : il ouvre un panneau qui
nomme le chemin exact et liste, un par un, la copie datée créée avant, le remplacement du fichier, et le
redémarrage du service. « Enregistrer » cache deux effets sur trois. Le legacy n'annonce rien du tout.

**LA RESTAURATION CESSE D'ÊTRE UN CLIC SANS FILET.** Côté legacy, la liste s'ouvre dans une fenêtre modale
et chaque ligne porte un bouton qui, d'un seul clic, écrase la configuration courante et redémarre
l'agent — ni `confirm()`, ni panneau, rien. Ici le bouton **ouvre** un panneau qui nomme la sauvegarde
visée **et** le fichier qui sera écrasé, et le test assert qu'ouvrir n'émet aucune requête. Son bouton
affichait par ailleurs l'identifiant `btn_restore`.

**LA PROPRIÉTÉ DE LA SAUVEGARDE A DEUX MOITIÉS, et les deux sont mesurées** : elle existe, **et elle porte
l'ancienne version** — la suite écrit `10.0.0.1`, réécrit `10.0.0.2`, et vérifie que la copie datée
contient `10.0.0.1` et pas `10.0.0.2`.

**UNE ASSERTION QUI PASSAIT POUR LA MAUVAISE RAISON, resserrée.** Le contrôle du message de restauration
lisait tout le panneau visible : le message de l'**écriture**, encore à l'écran, le satisfaisait. Il lit
maintenant le porte-messages de la restauration et exige qu'il **nomme la sauvegarde**.

**TROIS CLÉS DE PLUS FERMÉES** — `config_remote_saved`, `backup_restored`, `btn_restore` (15e, 16e, 17e).
**Le huitième français en dur** (`'Configuration vide'`, `main.js:539`) est mesuré à l'écran du legacy.
L'onglet de l'éditeur est **complet** : son bloc « pas encore porté » a été retiré, et la clé devenue
inutile avec lui. Le libellé du chemin dit désormais « Fichier cible » et non « Fichier à lire » —
l'éditeur écrit aussi.

## E-85 — La valeur d'un override devient une ligne de configuration à elle seule

**Module `supervision/`, sous-lot V10 : la reconfiguration.** Mesures faites sur **Test-Server-Debian
(id 2, DEV)** ; `srv-zabbix` jamais jointe. Deux fixtures posées (une ligne `supervision_config`, un
override), supprimées ensuite, et l'état **relu pour être prouvé** : 0 ligne dans les deux tables,
`/etc/zabbix/` vide.

**LE DÉFAUT CENTRAL : LA CLÉ D'UN OVERRIDE EST VALIDÉE, SA VALEUR NE L'EST PAS.**
`_build_config_lines` traite huit paramètres nommés (`Hostname`, `Server`, `ServerActive`,
`HostMetadata`, `ListenPort`, `TLSConnect`, `TLSAccept`, `TLSPSKIdentity`) puis — c'est le point — boucle
sur **tout le reste** :

```python
# Overrides libres non pris en charge ci-dessus : injection directe avec interpolation.
for key, value in overrides.items():
    if key in _handled or not value: continue
    if not _SAFE_PARAM_RE.match(key): continue   # <- la CLE est validee
    lines[key] = _interpolate(value, machine_row)  # <- la VALEUR ne l'est pas
```

`_interpolate` ne fait que deux remplacements de chaîne. La valeur part ensuite en
`line = f"{key}={value}\n"`, encodée en base64 et **ajoutée au fichier**. Une valeur portant un saut de
ligne produit donc **une directive supplémentaire**, que personne n'a demandée par aucun paramètre nommé.

**MESURÉ DE BOUT EN BOUT, avec une charge délibérément INOFFENSIVE.**
`POST /supervision/overrides/2` avec `{"overrides":{"Timeout":"3\nLIGNE_INJECTEE_PAR_LA_MESURE=temoin"}}`
rend `{"success":true,"message":"Overrides sauvegardes"}`. Ce que la base retient, en hexadécimal :

```
Timeout -> 33 0A 4C49474E455F494E4A45435445455F5041525F4C415F4D45535552453D74656D6F696E
            3  \n  L  I  G  N  E  _  I  N  J  E  C  T  E  E …
```

Un saut de ligne **brut**, accepté par l'API. Puis `POST /supervision/zabbix/reconfigure` sur la machine
DEV, et le fichier écrit :

```
     1  Server=10.0.0.250
     …
     7  Timeout=3
     8  LIGNE_INJECTEE_PAR_LA_MESURE=temoin      ← directive autonome, demandee par personne
```

Le flux l'annonce lui-même : `INFO: Cle 'Timeout' definie a '3⏎LIGNE_INJECTEE_PAR_LA_MESURE=temoin'.`
**Sur un agent Zabbix réel, cette ligne peut être un `UserParameter`** — c'est-à-dire l'exécution d'une
commande arbitraire par l'agent, sur la machine supervisée. Le témoin employé ici n'exécute rien ; le
mécanisme est identique.

**QUI PEUT LE FAIRE.** La route d'écriture porte `@require_api_key` + `@require_role(2)` +
`@require_permission('can_manage_supervision')` — donc **un rôle 2 qui n'est PAS administrateur du
portail** suffit (`rw-test-admin` a exactement ce profil). Et elle est **la seule route du module touchant
une machine à ne pas porter `@require_machine_access`** : son `machine_id` vient du chemin d'URL et n'est
confronté à aucun contrôle d'accès. Ce garde est inerte au rôle 2 (`check_machine_access` rend vrai dès
ce niveau) — c'est dit plutôt que sous-entendu — mais son absence est réelle.

**POURQUOI PERSONNE NE L'A FAIT : IL N'Y A AUCUNE INTERFACE.** `supervision_overrides` a **0 ligne**, et
aucune page des deux portails n'écrit dedans. Le trou est atteignable **par l'API**, pas par un écran.
**Porter une interface d'overrides, c'est donc mettre ce mécanisme derrière un formulaire.** C'est
exactement la décision qui attendait l'exploitant avant V10, et elle n'est pas de nature technique.

**LE GESTE DE V10 EST AUJOURD'HUI INATTEIGNABLE POUR ZABBIX.** `zabbix_reconfigure` commence par
`if not global_cfg: return 400 'Aucune configuration globale.'` — et `supervision_config` a **0 ligne**.
Le cas nominal de la reconfiguration Zabbix sur cette installation est donc **un refus**, et il a fallu
poser une fixture de configuration globale pour atteindre le chemin réel.

**MAIS `generic_reconfigure` NE REFUSE PAS**, et c'est la même famille que le défaut corrigé en V9 : son
`if global_cfg:` **saute simplement l'écriture**, redémarre le service, puis annonce
`SUCCESS_MACHINE::… Reconfiguration reussie`. Sur les trois plateformes non-Zabbix et sans configuration
globale, la reconfiguration ne fait donc **que redémarrer** — en annonçant qu'elle a reconfiguré.

**LE MARQUEUR TERMINAL DU FLUX MENT, LUI AUSSI.** Mesuré, à la suite immédiate :

```
Début de l'exécution...
sh: 1: systemctl: not found
Exécution terminée (code 127).
SUCCESS_MACHINE::2::Reconfiguration reussie pour Test-Server-Debian.
```

Le redémarrage a échoué avec le code 127 et le flux conclut à la réussite. V9 a appris au portage à
distinguer « écrit mais pas redémarré » ; ici l'information existe dans le flux — deux lignes plus haut —
et le marquer que les clients lisent l'ignore.

**QUATRE EFFETS, PAS TROIS.** Le découpage annonçait sauvegarde + écriture + redémarrage. La mesure en
trouve un quatrième : si la configuration globale porte un PSK, la route **écrit une clé secrète** dans
`/etc/zabbix/zabbix_agent2.d/server.key` (`chmod 640`). Et si son déchiffrement échoue, l'échec n'est que
**journalisé** : `psk_value` reste `None`, la clé n'est pas écrite, et rien ne le dit à l'écran — alors
que le fichier de configuration continue, lui, de référencer `TLSPSKFile`.

**UNE DIFFÉRENCE DE FOND AVEC `config/save`, QUI N'EST PAS UN DÉFAUT MAIS QUI SE DÉCLARE.**
`_write_config_stream` procède **clé par clé** : `sed -i -E '/^[#[:space:]]*CLE[[:space:]]*=/d'` puis
ajout en fin de fichier. La reconfiguration **fusionne** donc dans le fichier existant et **préserve** les
lignes qu'elle ne connaît pas ; `config/save`, lui, **tronque** (`>`) et les détruit. Deux gestes voisins,
deux sémantiques opposées sur le même fichier.

**TROIS EXONÉRATIONS :** la **clé** d'un override est bien validée (`^[a-zA-Z0-9_.:-]+$`), donc ni espace
ni `;` ni `$` dans le nom, et le `sed` l'échappe par `re.escape` — aucune injection de commande par la clé ;
le chemin du fichier reste un littéral ; le contenu voyage en base64. Et côté Zabbix, un échec de
sauvegarde est **annoncé dans le flux** (`WARN: Backup echoue`) — plus honnête que le `None` silencieux de
`config/save` — même si l'écriture continue quand même. La version générique, elle, ignore ce retour.

## E-86 — Les réglages par machine, portés avec une liste FERMÉE : ne pas offrir d'entrée libre plutôt que la valider

**Module `supervision/`, sous-lot V10a : les réglages par machine
(`supervision_overrides`).** **CE N'EST PAS UN PORTAGE, C'EST UNE CONCEPTION AUTORISÉE.** La table n'avait
**jamais eu d'interface**, dans aucun des deux portails : la priorité `overrides > profil > globale`
existait avec son étage le plus fort **inatteignable**. Suite :
`tests/e2e/go-page-supervision-reglages.mjs` — **8 PASS sur le legacy, 32 sur le portage** (base rouge
relevée : **5 PASS / 8 FAIL**). Côté legacy, la suite ne mesure qu'une chose : qu'il n'y a rien.

**LA DÉCISION DE DESSIN, ET SA RAISON MESURÉE.** E-85 avait établi qu'un saut de ligne dans la valeur d'un
override produisait une **directive autonome** dans le fichier de configuration — sur un agent Zabbix, un
`UserParameter`, donc l'exécution d'une commande arbitraire. Le backend valide désormais la valeur
(v1.37.41). **Le portage va plus loin : il n'offre pas d'entrée libre du tout.** Huit champs, huit noms
fixes, aucun neuvième, et **aucun champ où saisir un NOM de paramètre**. Valider une entrée libre et ne
pas en offrir ne se valent pas : la seconde ne se contourne pas par une requête forgée.

Ces huit noms sont **exactement** ceux que `_build_config_lines` traite par leur nom : `Hostname`,
`Server`, `ServerActive`, `HostMetadata`, `ListenPort`, `TLSConnect`, `TLSAccept`, `TLSPSKIdentity`.

**LE FORMULAIRE POSTE VERS LE PORTAGE, PAS VERS LA PASSERELLE — et le test en fait une propriété.**
`POST /supervision/overrides/<id>` est la seule route du module touchant une machine **sans**
`@require_machine_access` (E-85, déclaré et non corrigé, hors du périmètre autorisé). Écrire en base avec
une liste fermée, c'est ne pas hériter de cette laxité — même raison qu'en V4 pour la configuration
globale.

**CE GESTE NE JOINT AUCUNE MACHINE, ET LA PAGE LE DIT.** Ces valeurs vivent en base et ne partiront qu'à
la prochaine reconfiguration. Le taire laisserait croire qu'enregistrer modifie le serveur. La suite le
**mesure** : zéro requête vers la passerelle pendant l'enregistrement. C'est ce qui distingue ce sous-lot
de V9.

**VIDER UN CHAMP SUPPRIME LE RÉGLAGE, il ne l'enregistre pas vide** — un `param_value` vide serait relu
comme une ligne `Clé=`, donc une directive sans valeur.

**UN DÉFAUT DE MON PROPRE PORTAGE, TROUVÉ PAR MA PROPRE SUITE, ET SA CAUSE EST DANS LE CADRE.** Le premier
jet ne supprimait **jamais** rien. Laravel place `ConvertEmptyStringsToNull` dans le groupe `web` : une
chaîne vide arrive donc en `null`, **exactement comme un champ absent**. Or les deux ne veulent pas dire la
même chose — vide signifie « supprime ce réglage », absent signifie « ne le touche pas ». Mesuré :

```
POST a="" b="v"   ->  input('a') = NULL     has('a') = true     input('b') = "v"
```

Le code testait `input(...) === null` et sautait donc les champs vidés. Corrigé par `has()`. **Un
intergiciel du cadre avait rendu deux choses différentes identiques**, et seule la suite l'a vu — pas la
relecture.

**UNE ASSERTION QUI ÉCHOUAIT SUR UN CHAMP JUSTE.** Pour prouver qu'aucun champ ne saisit un NOM de
paramètre, un premier jet cherchait `/nom|name|param/` dans les noms de champs — et `override_Hostname`
contient « name ». L'assertion tombait sur un champ légitime, et **elle ne disait rien de plus** que celle
qui compare à la liste fermée. Remplacée par une propriété qui n'était pas mesurée : le formulaire poste
vers la route du portage.

**UNE NAVIGATION REFERME L'ONGLET, et la suite l'a payé.** Les panneaux arrivent `hidden` et c'est le
script qui en ouvre un : après chaque aller-retour de formulaire, le bouton suivant vit dans un panneau
caché et n'est pas cliquable. L'échec apparaissait **deux gestes plus loin**, sous la forme « Node is
either not clickable ».

**ON N'AFFICHE PAS SEULEMENT CE QU'ON SAIT ÉCRIRE.** Un réglage posé hors de la liste fermée — par l'API,
ou avant ce portage — **existe et agit**. Le cacher laisserait croire qu'il n'y en a pas : l'écran
l'annonce, en le nommant, tout en disant qu'il ne peut pas le modifier. Mesuré avec une fixture `Timeout`.

**LE STYLE DE L'AIDE, VU À L'IMAGE.** `.rw-etiquette-champ` met **toute** l'étiquette en capitales gras —
juste pour un intitulé, illisible pour une phrase. Seule `.rw-saisie` y était remise à plat : chaque champ
portait donc cinq lignes de capitales sous lui. Corrigé par une règle placée **juste après** celle de
`.rw-saisie`, parce qu'à spécificité égale l'ordre tranche.

**CE QUI RESTE À V10** : la reconfiguration elle-même, qui **écrit** cette configuration sur la machine.
Son étage le plus fort n'est plus inatteignable.

## E-87 — La reconfiguration portée : le verdict vient de ce que le flux a MONTRÉ, pas de son dernier marqueur

**Module `supervision/`, sous-lot V10 : la reconfiguration d'un agent (flux `text/plain`, MODIFIE la
machine).** Suite : `tests/e2e/go-page-supervision-reconf.mjs` — **13 PASS sur le legacy, 27 sur le
portage** (base rouge relevée : **7 PASS / 7 FAIL**). Cible : **Test-Server-Debian (id 2, DEV)** ;
`srv-zabbix` jamais visée. Fixtures — une ligne `supervision_config` et un fichier — nettoyées à l'entrée
et dans un `finally`, état **relu pour être prouvé**.

**LA PROPRIÉTÉ CENTRALE : LE MARQUEUR TERMINAL MENT, ET LE PORTAGE NE LE RECOPIE PAS.** Mesuré sur les
deux cibles, même geste, même machine sans `systemctl` :

```
flux    : Exécution terminée (code 127).
          SUCCESS_MACHINE::2::Reconfiguration reussie pour Test-Server-Debian.

legacy  : « Reconfiguration reussie pour Test-Server-Debian. »        ← le marqueur, recopié
portage : « Configuration poussee sur Test-Server-Debian, mais une commande distante
            a ECHOUE (code 127). Le fichier est en place et le service ne tourne
            peut-etre pas : lisez le journal ci-dessous… »
```

L'information était dans le flux **deux lignes plus haut**. Le portage lit le flux **entier** et en tire
**quatre issues** : réussite, **partielle** (le cas que le legacy perd), échec, inachevé.

**ON PARSE LE NOMBRE, PAS LA PHRASE.** « Exécution terminée (code 127). » est une phrase française,
susceptible de changer ; `(code N)` est la partie protocole. Le verdict s'appuie sur `/\(code (\d+)\)/`,
sur les préfixes `ERROR:` / `WARN:` et sur les marqueurs `SUCCESS_MACHINE::` / `ERROR_MACHINE::` — jamais
sur un libellé traduisible.

**LE JOURNAL EST MONTRÉ, PAS RÉSUMÉ.** Donner le flux brut sous le verdict permet de **vérifier** ce
verdict au lieu de le croire. Le legacy a aussi son journal, mais il n'y cherche rien.

**QUATRE EFFETS, ÉNUMÉRÉS — et le découpage n'en annonçait que trois.** Sauvegarde datée, écriture clé par
clé, **écriture d'une clé PSK** si la configuration globale en porte une, puis redémarrage. Le quatrième
est **conditionnel, et sa condition est mesurée** : la fixture ne pose aucun PSK, donc la ligne est
**cachée**. Annoncer un effet qui n'aura pas lieu est aussi faux que d'en taire un.

**L'ÉCRITURE FUSIONNE, ELLE NE TRONQUE PAS — et la suite le mesure.** `_write_config_stream` purge chaque
clé au `sed` puis l'ajoute : les lignes que le portail ne gère pas **survivent**. La suite pose
`Timeout=42` dans le fichier avant le geste et vérifie qu'elle est **toujours là après**. C'est la
sémantique inverse de l'éditeur (V9), qui tronque avec `>`. Deux gestes voisins sur le même fichier, deux
comportements opposés : le dire évite de croire que l'un remplace l'autre.

**AUCUNE CONFIRMATION CÔTÉ LEGACY, ET C'EST MESURÉ.** `reconfigureSingle` part au premier clic — là où
`deploy` et `uninstall` ouvrent au moins un `confirm()`. La suite l'établit sans ambiguïté : aucune boîte
native ne s'est ouverte, **et le fichier a été écrit**. Côté portage, le bouton **ouvre** un panneau, et
le test assert qu'ouvrir n'émet aucune requête.

**PAR LIGNE, PAS SUR SÉLECTION.** Le legacy offre les deux : mesuré, **1 geste de masse et 3 cases à
cocher**. Le portage : **3 gestes par ligne, 0 case**. Une action de masse n'y est pas « déconseillée »,
elle est structurellement absente.

**UNE RÈGLE APPLIQUÉE PAR LE BACKEND SE REND VISIBLE.** `zabbix_reconfigure` rend **400 « Aucune
configuration globale »** tant que la table est vide — et elle l'est. Le bouton du portage est donc
**désactivé**, avec l'explication en infobulle, et la section l'annonce. Laisser cliquer pour se faire
refuser fait décider dans le vide.

**LA PASSERELLE BUFFERISE, ET C'EST ASSUMÉ — décision prise sur mesure.** `/supervision/` n'est pas dans
`EN_FLUX`. Mesure : une reconfiguration d'**une** machine dure **1,4 s**. Tenir la connexion ouverte pour
la rendre « vivante » n'apporterait rien à ce prix ; le geste est par ligne, pas sur le parc. Si V11 ou
V12 changent cet ordre de grandeur, la décision se remesure.

**UN MOTIF TROP LARGE, ENCORE.** Le contrôle de la traduction anglaise cherchait `/Reconfigure/` — qui est
un **préfixe de « Reconfigurer »** et passait donc sur la page française. Resserré sur des phrases
anglaises entières. Deuxième fois en deux sous-lots (`override_Hostname` contenait « name »).

**ET UN DÉTAIL D'ASSERTION QUI MENTAIT AU PASS** : « le journal est MONTRÉ — journal absent ou vide ». Le
détail est imprimé dans les deux cas : il doit dire ce qu'on a **trouvé**. Il imprime maintenant le nombre
de lignes et la ligne retenue.

**RESTE DÉCLARÉ ET NON CORRIGÉ** (hors autorisation) : `generic_reconfigure` annonce `SUCCESS_MACHINE::`
**sans rien avoir écrit** quand la configuration globale manque, et un échec de déchiffrement du PSK n'est
que journalisé — la clé n'est pas écrite, rien ne le dit, et le `.conf` continue de référencer
`TLSPSKFile` (E-85).

## E-88 — La désinstallation ne peut pas échouer, et l'inventaire oublie de toute façon

**Module `supervision/`, sous-lot V11 : la désinstallation d'un agent (flux `text/plain`, DÉTRUIT).**
Mesures sur **Test-Server-Debian (id 2, DEV)** ; `srv-zabbix` jamais visée. Fixture — une ligne
`supervision_agents` — retirée, état **relu pour être prouvé** (0 ligne, `/etc/zabbix/` vide).

**LE DÉFAUT CENTRAL : LE CODE DE SORTIE EST FABRIQUÉ.** La commande de désinstallation enchaîne
**quatre** étapes, et **chacune se termine par `|| true`** :

```
export DEBIAN_FRONTEND=noninteractive &&
systemctl stop zabbix-agent2 2>/dev/null || true &&
systemctl stop zabbix-agent  2>/dev/null || true &&
apt-get purge -y zabbix-agent zabbix-agent2 zabbix-agent2-plugin-* 2>/dev/null || true &&
apt-get autoremove -y 2>/dev/null || true
```

La chaîne **ne peut pas sortir autrement qu'en 0**. Un verrou apt, un dpkg cassé, un dépôt injoignable :
tout est avalé, et `2>/dev/null` jette même le message. Puis `SUCCESS_MACHINE::` est émis
inconditionnellement. **En V10 la vérité était dans le flux, deux lignes au-dessus du marqueur ; ici elle
n'est nulle part** — `|| true` l'efface avant qu'elle puisse être rapportée.

**MESURÉ, sur une machine où l'agent n'a JAMAIS été installé** (`command -v zabbix_agent2` → non) :

```
START_MACHINE::2::Desinstallation agent Zabbix sur Test-Server-Debian.
…
Exécution terminée (code 0).
SUCCESS_MACHINE::2::Agent Zabbix desinstalle de Test-Server-Debian.
```

Le portail annonce avoir désinstallé quelque chose qui n'était pas là.

**ET L'INVENTAIRE OUBLIE, QUOI QU'IL ARRIVE.** `_remove_agent(machine_id, platform)` s'exécute
**inconditionnellement**, hors de toute vérification. Mesuré avec une ligne d'inventaire en fixture :

```
inventaire avant : 1 ligne(s)   (« zabbix 7.0-fixture-v11 »)
inventaire apres : 0 ligne(s)
```

Rien n'a été retiré de la machine, et le portail a néanmoins effacé la trace de l'agent. **Si la purge
avait échoué, l'exploitant verrait le même succès vert et le même inventaire vide, pendant que l'agent
continuerait de tourner et de remonter des mesures.**

**`apt-get autoremove -y` : UN PÉRIMÈTRE QUI DÉPASSE L'AGENT.** La commande retire *tout* paquet que le
système considère comme devenu inutile — pas seulement les dépendances de Zabbix. Sur une machine où un
outil a été installé à la main et dont les dépendances ont été marquées « automatiques », elle emporte
autre chose. Les **quatre** plateformes portent la même ligne.

Mesuré **sans le payer**, par simulation sur la machine de test :

```
apt-get autoremove --dry-run  ->  0 upgraded, 0 newly installed, 0 to remove
```

**C'est le banc d'essai qui est exonéré, pas la commande.** Zéro paquet ici ne dit rien de ce qu'une
machine de production perdrait — et la suite de caractérisation peut donc s'exécuter sans risque, ce qui
est exactement ce qu'il fallait établir avant de la faire cliquer.

**QUATRE PLATEFORMES, LE MÊME DESSIN.** `generic_uninstall` a la même forme que la route Zabbix :
`_remove_agent` inconditionnel, `SUCCESS_MACHINE::` inconditionnel, et un `uninstall_cmd` en `|| true`
avec `autoremove`. Aucune des quatre ne peut rapporter un échec.

**DEUX EXONÉRATIONS.** Les quatre gardes sont en place (`@require_api_key`, `@require_role(2)`,
`@require_permission('can_manage_supervision')`, `@require_machine_access`). Et le paramètre est
`machine_id` au **singulier** : contrairement à la reconfiguration, la désinstallation est déjà par
machine côté backend — le legacy n'offre d'ailleurs qu'un bouton par ligne, avec un `confirm()` natif.

**CE QUE LE PORTAGE PEUT FAIRE SANS TOUCHER AU BACKEND.** Puisque la route ne peut pas rapporter un échec,
lui faire confiance serait recopier un succès invérifiable. Le portage **vérifie après coup** : il rejoue
la détection de version (V6, déjà portée) et dit ce qu'elle trouve — « désinstallé, et plus aucun agent
n'est détecté » ou « la commande a rendu un succès, mais un agent est TOUJOURS détecté ». Une réussite
mesurée vaut mieux qu'une réussite annoncée, et cela n'exige ni route neuve ni modification du backend.

## E-89 — La désinstallation portée : une réussite VÉRIFIÉE, pas annoncée

**Module `supervision/`, sous-lot V11 : la désinstallation (flux `text/plain`, DÉTRUIT).** Suite :
`tests/e2e/go-page-supervision-desinst.mjs` — **15 PASS sur le legacy, 29 sur le portage** (base rouge :
**8 PASS / 5 FAIL**). Le backend avait été corrigé au préalable (v1.37.44, E-88) : la commande ne purge que
ce que `dpkg-query` trouve installé, son code de sortie remonte, et l'inventaire n'est vidé que si ce code
vaut 0.

**LA CLÉ CASSÉE, MESURÉE LÀ OÙ ELLE FAIT LE PLUS DE MAL.** `confirm_uninstall` existe sous
`supervision.*` et **dans aucun des deux `js.php`** : `__()` la rend telle quelle. Mesuré à l'écran :

```
boite native ouverte par le legacy : confirm: confirm_uninstall
```

Le legacy demande donc de confirmer une **destruction** avec un identifiant pour tout message.
**Dix-huitième** clé de cette famille. Le portage la remplace par un panneau — il ne la déplace pas.

**LA PROPRIÉTÉ CENTRALE : LE PORTAGE VÉRIFIE APRÈS COUP.** Le backend ne peut plus mentir, mais il ne peut
pas tout garantir — et surtout « il n'y avait rien à purger » n'est pas « désinstallé ». Le portage rejoue
donc la détection de version (V6) une fois le geste fini, et **dit ce qu'elle trouve**, dans un
porte-messages **distinct** de celui du verdict : « la commande a rendu un succès » et « plus aucun agent
n'est détecté » ne sont pas la même affirmation.

**LA FIXTURE QUI REND CETTE PROPRIÉTÉ MESURABLE.** On ne peut pas installer un vrai agent sur le banc
d'essai. La suite pose donc un **faux binaire** `zabbix_agent2` — un script qui n'imprime qu'une version :

- `dpkg-query` ne le voit pas (ce n'est pas un paquet) → la commande rend `RIEN_A_PURGER` et un code 0 :
  elle « réussit » ;
- `command -v` le trouve → la détection de version le voit.

La commande dit donc oui et la vérification dit non. Mesuré :

```
verdict     : « Aucun agent n'etait installe sur Test-Server-Debian : il n'y avait rien a desinstaller. »
verification: « ATTENTION : un agent est TOUJOURS detecte sur ce serveur (version 7.0.99). La commande
                a beau avoir rendu un succes, l'agent est encore la. »
```

**CINQ ISSUES, tirées du contenu du flux** : purgé, **rien à purger**, échec, inachevé, refus. La
deuxième est celle que ni le legacy ni le marqueur ne distinguent.

**UN EFFET QUE JE N'AVAIS PAS PRÉVU, mesuré et conservé.** La désinstallation avait vidé l'inventaire — à
juste titre de son point de vue, puisqu'elle avait rendu 0. La vérification, elle, retrouve l'agent, et la
route de version **repose la ligne** (`_upsert_agent`). L'inventaire finit donc juste, non parce que la
désinstallation avait raison, mais parce que la vérification l'a corrigée. C'est un bénéfice de plus à
vérifier après coup, et il ne se voit **qu'en base** — une assertion le mesure désormais.

**NOMMER LA PRODUCTION, SUR LE GESTE QUI DÉTRUIT.** Vu à l'image : le panneau nommait la machine sans dire
qu'elle était en production, et `srv-zabbix` se lit exactement comme `Test-Server-Debian` dans une phrase.
Un exploitant a le droit de désinstaller un agent d'un serveur de production — ce n'est pas au portail de
le lui interdire — mais le lui **dire au moment où il décide**, oui. La propriété est mesurée **dans les
deux sens** : l'avertissement est caché sur DEV, et il nomme `srv-zabbix` quand le geste la viserait.
Ouvrir ce panneau-là n'émet aucune requête, ce que la suite vérifie aussi — la production n'est pas jointe
pour mesurer qu'on prévient à son sujet.

**LE PÉRIMÈTRE A ÉTÉ MESURÉ AVANT D'ÊTRE PAYÉ.** `apt-get autoremove --dry-run` rend « 0 to remove » sur
le banc d'essai, et la suite l'inscrit dans son journal à chaque exécution : un chemin destructeur se
simule avant de se déclencher.

**DEUX DÉFAUTS DE MA SUITE.** Elle assertait la chaîne brute du faux binaire
(`7.0.99-faux-v11`) alors que la route de version **extrait le numéro** par `(\d+\.\d+[\.\d]*)` et
n'affiche que `7.0.99` — la suite avait tort, pas le portage. Et un détail d'assertion disait « journal
absent ou vide » sur un PASS ; il imprime maintenant le nombre de lignes et la ligne retenue.

**UNE LACUNE DE COUVERTURE FERMÉE AU PASSAGE, sur une question de l'exploitant.** Les douze suites du
module se connectaient **toutes** en `rw-test-admin`, qui porte `can_manage_supervision`. Or la règle du
projet est qu'une permission vaut « cette permission **OU** superadmin (rôle 3) », et `rw-test-super` est
rôle 3 **sans** cette permission (mesuré en base). Le second chemin de la garde n'était donc jamais
exercé : un durcissement qui l'aurait cassé serait passé inaperçu. `supervision-onglets` mesure maintenant
les deux — rôle 1 → **403**, rôle 3 sans permission → **200** — des deux côtés, donc en parité
(14→16 sur le portage, 11→13 sur le legacy).

---

## E-90 — Le déploiement annonce une réussite sans jamais regarder un code de retour, et inscrit dans l'inventaire un agent qui n'existe pas

**Mesuré le 2026-08-23**, sous-lot V12, sur `Test-Server-Debian` (id 2, DEV). Flux complet d'un
`POST /supervision/zabbix/deploy`, relevé textuellement :

```
START_MACHINE::2::Deploiement agent zabbix-agent2 v7.0 sur Test-Server-Debian.
sh: 1: wget: not found
Exécution terminée (code 127).
E: Unable to locate package zabbix-agent2
Exécution terminée (code 100).
INFO: Fichier /etc/zabbix/zabbix_agent2.conf mis a jour avec succes.
sh: 1: systemctl: not found
Exécution terminée (code 127).
SUCCESS_MACHINE::2::Deploiement reussi pour Test-Server-Debian.
```

**Trois étapes en échec, et le marqueur conclut à la réussite.** La cause est la même qu'en E-85 mais
poussée d'un cran : `zabbix_deploy` et `generic_deploy` écrivent `yield from
execute_as_root_stream(client, cmd, root_pass)` **sans affecter la valeur rendue**. Depuis v1.37.44 cette
fonction *rend* son code de sortie ; aucune des deux routes ne le lit.

**ET L'INVENTAIRE HÉRITE DU MENSONGE.** `_upsert_agent(machine_id, 'zabbix', agent_version,
config_deployed=True)` est appelée inconditionnellement juste avant `SUCCESS_MACHINE::`. Relevé en base
immédiatement après le flux ci-dessus :

| `supervision_agents` | ce que la machine porte |
|---|---|
| `machine 2, zabbix, 7.0, config_deployed = 1` | `dpkg-query: no packages found` — aucun binaire d'agent |

Le portail affirmait donc un agent installé en version 7.0 là où la machine n'en portait aucun.

**LA LIGNE FAUSSE EST TRANSITOIRE, ET CE N'EST PAS LE MÉRITE DU DÉPLOIEMENT.** `zabbix_version` appelle
`_remove_agent` quand elle ne trouve rien, et les **deux** portails relancent une détection juste après :
le legacy par `autoDetect` sur les identifiants ayant émis `SUCCESS_MACHINE::`, le portage par la
vérification écrite pour E-91. Chacun efface donc son propre mensonge sans le savoir. Pour mesurer le
défaut il faut un déploiement que **aucune** détection ne suit — la suite l'obtient par une **requête
forgée** depuis la page, même motif qu'en E-86 : `statut 200 · succès annoncé = true · codes relevés
(127) (100) (127) · inventaire « zabbix 7.0 1 » · agent réellement installé = NON`.

**NON CORRIGÉ CÔTÉ BACKEND** : le backend reste intact faute d'autorisation. Le portage n'en a pas besoin
pour dire la vérité (E-91), mais un correctif reste souhaitable — c'est le geste le plus coûteux du module,
et son inventaire est lu par le tableau de parc.

**DEUX ASYMÉTRIES MESURÉES ENTRE LES DEUX ROUTES**, qui interdisent d'énumérer les mêmes effets partout :

| | `zabbix_deploy` | `generic_deploy` |
|---|---|---|
| sans configuration globale | **400** en 513 ms, rien n'est envoyé | **installe quand même**, sans écrire de configuration |
| avant d'installer | **purge** `zabbix-agent` et `zabbix-agent2`, renomme la config en `.old` | ne purge pas, **sauvegarde** la config, horodatée |
| dépôt externe | `repo.zabbix.com` (un `.deb` tiré par `wget`) | `packages.centreon.com`, `repos.influxdata.com` — **rien pour Prometheus** |
| `extra_config` | ajouté | ajouté, **jamais pour Telegraf** (`platform != 'telegraf'`) |

**DEUX PARAMÈTRES CALCULÉS PUIS JETÉS.** `_get_install_commands(platform, global_cfg, os_version)` n'utilise
ni `global_cfg` ni `os_version` : le dépôt Centreon est codé en dur sur `bookworm`. Même famille que
`agent_type` (E-77). Et l'appelant passe `linux_version` dans le paramètre nommé `os_version` — inoffensif
tant que le paramètre est ignoré, piège dès qu'il servira.

**LA PRODUCTION N'EST PAS DÉPLOYABLE PAR CETTE ROUTE**, et le message ne le dit pas : `srv-zabbix` porte
`linux_version = NULL`, donc `generic_deploy` rend `ERROR_MACHINE::1::OS non supporte: ` — **avec une
chaîne vide**. Constaté en base, sans joindre la machine.

**TROIS MESURES QUI DÉDOUANENT**, à dire aussi clairement que les accusations :

- **`machine_ids` au pluriel n'est PAS un trou de garde.** `require_machine_access` lit `machine_id`,
  `server_id`, `machine_ids` et `server_ids` depuis le patch A01, et refuse si **un seul** identifiant
  n'est pas autorisé ;
- **`agent_version` est une liste FERMÉE côté portage** (`['7.0', '7.2']`), donc l'interpolation de cette
  valeur dans l'URL passée à `wget` n'est pas atteignable depuis l'écran. La colonne reste un `varchar`
  libre côté base : le chemin direct, lui, resterait ouvert ;
- **aucune requête ne sort du banc d'essai.** Ni `wget` ni `curl` n'y existent, et le DNS n'y résout pas :
  la chaîne s'arrête **avant** l'URL. Sûreté mesurée, pas supposée.

**UNE GARDE SANS EFFET, QUI N'EST PAS UNE FAILLE.** Les deux routes portent `@require_role(2)` **et**
`@require_machine_access`, mais `check_machine_access` rend `True` dès que `role_id >= 2`. Le second
décorateur ne peut donc jamais refuser ce que le premier a laissé passer. Ce n'est pas un trou — la garde
de rôle est plus forte — c'est un décorateur décoratif, et le signaler évite qu'on le croie protecteur.

---

## E-91 — Le déploiement porté : les étapes sont NOMMÉES et rendues par plateforme, et la réussite est VÉRIFIÉE

Sous-lot V12, dernier du module. Base rouge mesurée avant de porter : **14 PASS / 16 FAIL** — les seize
propriétés que ce portage apporte. Après portage : **31 PASS / 0 FAIL** (legacy : **19 / 0**).

**LE VERDICT VIENT DU FLUX ENTIER**, comme en E-87, et ce que l'écran dit diverge donc franchement :

| | ce que l'écran affiche |
|---|---|
| legacy | « Deploiement reussi pour Test-Server-Debian. », en vert |
| portage | « Le déploiement sur Test-Server-Debian a **ÉCHOUÉ** (code 127, 100, 127). Le portail a malgré tout enregistré l'agent dans son inventaire. » |

`(code N)` est parsé comme **protocole**, jamais la phrase française. Trois issues seulement — *réussi*,
*échec*, *inachevé* — et **aucune tentative d'attribuer un code à une étape** : le flux n'émet pas de
marqueur par étape, donc conclure « installé mais non démarré » demanderait de compter les codes dans
l'ordre et de parier sur le nombre d'étapes réellement jouées, qui varie avec la PSK et l'`extra_config`.
C'est la **vérification** qui comble ce trou, en disant ce qui est là.

**LA VÉRIFICATION APRÈS COUP, PLUS PARLANTE QU'EN E-89.** En V11 elle faisait constater une absence ; ici
elle confronte une **présence que l'inventaire vient d'affirmer** :

> ATTENTION : AUCUN agent n'est détecté sur Test-Server-Debian. Le portail vient pourtant d'inscrire cet
> agent dans son inventaire — c'est l'inventaire qui a tort.

Quatre issues, et la version attendue est **retenue au moment de la décision** plutôt que relue après : une
bascule de plateforme entre-temps ferait comparer une version détectée à une version jamais demandée.

**LES ÉTAPES SONT ÉNUMÉRÉES, ET RENDUES PAR PLATEFORME.** Neuf pour Zabbix dans l'état mesuré (onze avec
PSK et `extra_config`), et la liste **est** le décompte : aucune phrase ne cite un nombre, parce qu'un
nombre écrit vieillit mal — E-87 annonçait trois effets et en avait quatre. Rendre les étapes de Zabbix
pendant que le sélecteur est sur Telegraf aurait reproduit **E-79 par un autre bout**, le libellé qui ne
suit pas la clé : la table est donc indexée par la même clé que `routesParPlateforme()`.

**UN DÉFAUT DE MON PROPRE PORTAGE, CORRIGÉ AU PASSAGE.** Le bouton « Reconfigurer » de V10 se désactivait
d'après la configuration de **Zabbix** quel que soit le sélecteur — la même famille E-79, déplacée du
chemin vers l'**état**. V12 l'aurait recopiée. L'état bloqué vient maintenant d'une table par plateforme,
mise à jour à chaque bascule, et **fail-closed** : une table illisible bloque le geste au lieu de l'ouvrir.

**LA PASSERELLE PASSE EN FLUX POUR CES QUATRE CHEMINS SEULEMENT.** Décision prise sur mesure et
**contraire** à celle de E-87 : la reconfiguration dure 1,4 s et reste bufferisée ; le déploiement a été
mesuré à **9 270 ms** sur le banc, mais ce chiffre est un **plancher** — le banc n'a ni DNS ni paquet à
télécharger, donc chaque étape réseau y échoue immédiatement. Un déploiement réel tire un `.deb` puis
installe un agent et ses greffons : 120 s ne sont pas un majorant crédible, et un dépassement rendrait une
erreur de passerelle **alors que l'installation continuerait sur la machine** — le pire des verdicts,
« échec » sur un geste qui a réussi. Les quatre chemins sont donc relayés morceau par morceau (900 s).
`estUnFlux` est évaluée **après** les trois refus : ce réglage ne change qu'un délai et un mode de relais,
aucune garde.

**LA 19e CLÉ CASSÉE, ET LA PLUS INSTRUCTIVE DE LA SÉRIE.** `confirm_deploy` n'est pas une traduction
manquante : elle **existe**, en FR et en EN, correctement rédigée — dans `lang/{fr,en}/supervision.php`,
donc **hors de l'espace `js.`** que `getJsTranslations('js.')` charge. Elle est écrite, correcte, et
inaccessible ; la boîte native affiche `confirm_deploy`. Le repli `|| 'Confirmer le deploiement ?'` avait
bien été anticipé, mais il reste inerte pour la raison mesurée en E-83 : `__()` rend la clé **telle
quelle**, donc une chaîne non vide. La suite mesure les **deux** faits séparément.

**AUCUNE CASE À COCHER, DONC AUCUNE ACTION DE MASSE.** Le legacy offre trois boutons par ligne, trois cases
et un « Déployer la sélection » ; le portage offre trois boutons par ligne, zéro case, zéro action de
masse. Et **ouvrir un panneau n'envoie rien** — propriété mesurée au **réseau**, en comptant les requêtes
vers `/deploy`, ce qui permet d'ouvrir le panneau sur la ligne de `srv-zabbix` pour lire l'avertissement
sans jamais joindre la production.

**TROIS DÉFAUTS DE MA SUITE, ET UN PASS QUI PASSAIT POUR UNE MAUVAISE RAISON.** Elle lisait le flux du
legacy dans `#deploy-logs` alors que `appendDeployLog` écrit dans `#deploy-logs-container` — le verdict
était donc toujours vide et l'assertion accusait le legacy de ne rien conclure. Elle rendait
`{porte: false}` sans `items`, et `items.length` levait deux assertions plus loin. Et elle lisait la liste
des étapes en testant `hidden` sur le `<ul>` au lieu du panneau qui le contient : l'assertion passait alors
que le bouton était désactivé et que **le panneau n'avait jamais paru**. Elle exige maintenant que le
panneau soit réellement visible.

**VU À L'IMAGE, CORRIGÉ.** L'énoncé du geste et l'avertissement de PRODUCTION portaient la même classe,
donc le même fond et la même bordure : sur le geste le plus coûteux du module, rien ne distinguait « voici
ce qui va se passer » de « ce serveur est en production ». L'énoncé est devenu un encart neutre ; seul
l'avertissement attire l'œil.

**UNE MÉMORISATION POSÉE AU PASSAGE.** `configurationParPlateforme()` était interrogée **six fois** par
requête. Reprocher au legacy de jouer la même requête deux fois (E-76) et le faire trois fois plus n'aurait
aucun sens : elle est mémorisée pour la durée de la requête, et l'écriture invalide la mémoire.

---

## E-92 — Le constat d'archivage acceptait un lien qui menait au 404 qu'il venait de créer

**Mesuré le 2026-08-23**, à l'archivage de `supervision/`. `tests/e2e/archive.mjs` vérifie qu'après un
`git mv`, l'entrée de menu du legacy mène au portage. Son filtre était :

```js
const mene = liens.filter(h => h && h.includes(routeportee));
```

La route portée est `/supervision`, l'ancien chemin legacy `/supervision/` : **le second contient le
premier**. Base rouge, anciens liens encore en place :

```
PASS  l'entree de menu du legacy mene au portage  — /supervision/
EXCEPTION TypeError: Invalid URL
```

L'assertion annonçait une réussite **en affichant le chemin archivé**. Ce qui a révélé le défaut n'est pas
l'assertion mais l'exception levée juste après par `new URL('/supervision/')` — un chemin relatif n'est pas
une URL. Autrement dit : **si l'ancien lien avait été absolu, le PASS serait passé inaperçu.**

C'est le **premier** des neuf modules archivés où la collision est possible. `/update/` contre
`/mises-a-jour`, `/tasks/` contre `/taches`, `/drift/` contre `/derive-config` : aucun recouvrement, donc
huit archivages ont validé un filtre qui ne pouvait pas les trahir.

**CORRIGÉ** : le lien doit être **absolu** et son `pathname` doit **être** la route, pas la contenir. Un
lien relatif est servi par le legacy, donc par construction il ne peut pas mener au portage — `new URL(h)`
sans base échoue sur un relatif, ce qui suffit à l'écarter. Et `repond()` rend `0` au lieu de lever, pour
qu'un href relatif produise un verdict et non une exception au milieu d'une suite. Les huit parties déjà
archivées restent vertes : mesuré sur `update-u1`, `tickets` et `drift`.

**LEÇON GÉNÉRALE** : une assertion « X mène à Y » écrite par inclusion de chaîne est satisfaite par tout
chemin dont Y est un préfixe — y compris celui qu'on vient de supprimer. Comparer des **chemins**, pas des
sous-chaînes ; c'est la même discipline que la comparaison par SEGMENT de la passerelle (E-02).

---

## E-93 — `supervision/` archivé : quatre points d'entrée, dont un que nul contrôle sur les liens ne voit

Le module est porté (V1 à V12) et déplacé dans `legacy/_deprecated/`. Le découpage annonçait « les deux
rendus du menu » ; la mesure en a trouvé **quatre** :

| fichier | nature |
|---|---|
| `legacy/menu.php:99` | barre latérale |
| `legacy/menu.php:240` | tiroir mobile |
| `legacy/index.php:374` | raccourci du tableau de bord |
| `legacy/head.php:211` | **carte de raccourcis CLAVIER** (`g` puis `v`) |

Le quatrième est un objet JavaScript, pas un `<a href>` : aucun contrôle portant sur les liens ne peut le
voir. Taper `g` puis `v` aurait navigué vers le 404 qu'on venait d'installer, sans qu'un seul `href` soit
en cause.

**LA PROPRIÉTÉ POSÉE EST NÉGATIVE ET COUVRE LES QUATRE**, lue sur le tableau de bord servi (qui inclut le
menu et la carte de raccourcis) : plus aucun `href="/supervision/"`, et plus aucun `: '/supervision/'`.
Base rouge, anciens liens rendus : **3 liens et 1 raccourci** — les quatre emplacements, comptés une
seconde fois et par un autre moyen. C'est ce qui rend le décompte crédible plutôt que déclaratif.

**DEUX PORTES DÉDOUANÉES**, que le précédent d'`update` avait pourtant signalées :

- `App\Support\Navigation` porte `'route' => 'supervision'` depuis V1 — le menu du **portage** n'a jamais
  pointé vers le legacy, contrairement à `updates` qui portait encore `'legacy' => '/update/'` après sept
  sous-lots ;
- `backend/routes/search.py` n'émet **jamais** `/supervision/` (mesuré : `/security/`,
  `/tickets/index.php`, `/update/index.php`). L'entrée ajoutée à `LiensLegacy::REMPLACEMENTS` est donc
  **préventive**, là où celle d'`update` réparait un 404 mesurable.

**CE QUI RESTE, ET QUI N'EST PAS DU RESSORT D'UN ARCHIVAGE.** La seule occurrence de `/supervision/`
subsistant dans le legacy est la liste blanche de `legacy/api_proxy.php:134` — une route de **backend**,
pas un lien. Le proxy du legacy continue donc de relayer les routes de supervision alors qu'aucune page ne
les appelle plus : surface morte, et d'autant plus notable que `/supervision/` est **absent de
`$ADMIN_ONLY_PREFIXES`** côté legacy. La retirer restreindrait ce que le legacy autorise — un changement
de droits, pas une conséquence du déplacement de trois fichiers. **Laissée en place, signalée.**

**RÉFÉRENCES LEGACY MESURÉES** : **6** pour douze suites (404 du répertoire, 404 des **trois** fichiers
réels, lien du menu, et le fait qu'il aboutisse), **8** pour `supervision-onglets`. Le constat est greffé
**en tête du `try`**, avant toute fixture : rien n'est posé, donc le `process.exit()` peut court-circuiter
le `finally` sans rien laisser sur la machine de test ni en base.

**VU A L'IMAGE, ET NON CORRIGE — DEUX CONSTATS QUI DEPASSENT CE SOUS-LOT.**

1. **Le legacy ne signale pas ses liens sortants.** `$sideLink` (`legacy/menu.php`) n'ajoute ni marqueur ni
   `target` : sur la capture, « Supervision » est assis entre « Audit SSH » et « Scan CVE », rendu trait
   pour trait comme une entree interne, alors qu'il mene a `192.168.0.245:8444` — un autre portail, un
   autre port, dans le meme onglet. **11 entrees** du menu legacy sont dans ce cas. Le portage, lui, marque
   l'inverse (`rw-menu__lien--externe`, `target="_blank"`, `rel="noopener"`, fleche `↗` avec `aria-label`),
   et un test y mesure meme la largeur RENDUE du marqueur. La regle existe donc dans le projet, ecrite pour
   un seul sens. **Defaut pre-existant** : huit entrees l'etaient deja, celle-ci fait la neuvieme.
2. **Le 404 d'un chemin archive est la page brute d'Apache** — « Not Found », aucun repere, aucun retour.
   C'est ce que voit quelqu'un qui avait un marque-page, et c'est vrai pour les **neuf** parties archivees.
   L'assertion mesure le STATUT, qui est la bonne propriete (le repertoire est bien parti) ; elle ne dit
   rien de ce qu'on voit.

Ni l'un ni l'autre n'est corrige : le legacy est en cours de depreciation, et soigner l'ergonomie de ce
qu'on demonte est un mauvais investissement. **Les deux sont signales, l'arbitrage appartient a
l'exploitant** — s'il veut que ce soit marque tant que les deux portails coexistent, c'est une ligne dans
`$sideLink` et un `ErrorDocument`.


---

## E-94 — Le second facteur était dérivable du premier, en production. Corrigé.

**Mesuré le 2026-08-20, reproduit et corrigé le 2026-08-23.** Ce n'est pas un écart de parité :
c'est une vulnérabilité du legacy, présente dans ce qui tourne en production, trouvée en
inventoriant `auth/` pour le porter.

`legacy/auth/enable_2fa.php` ne gardait que `isset($_SESSION['temp_user'])` — l'état posé par
`login.php` **après le mot de passe et avant le second facteur**. `login.php` renvoie certes vers
`verify_2fa.php` quand un secret existe, mais c'est une **redirection**, pas une garde ; rien
n'empêchait d'appeler la page directement, et `verify.php` l'autorise explicitement pendant que la
2FA est en attente.

Reproduction, avec le mot de passe seul et aucun code jamais fourni :

```
POST /auth/login.php        -> 302 vers verify_2fa.php     [2FA EN ATTENTE]
GET  /auth/enable_2fa.php   -> 200, 17 547 octets
                               contient le secret TOTP du compte EN CLAIR + son QR
```

`sha256(legacy/auth/enable_2fa.php)` était **égal** à `sha256(origin/main:www/auth/enable_2fa.php)`
(`be0bfda6…`), et `main` tourne en production : **quiconque détenait un mot de passe pouvait lire le
secret TOTP du compte et générer ses codes indéfiniment.**

**QUATRE DÉFAUTS, QUATRE CORRECTIFS**, tous sur `Migration-Laravel` (l'exploitant a demandé que tout
se fasse sur cette branche) :

| défaut | correctif |
|---|---|
| un compte **déjà enrôlé** recevait la page, donc son secret | renvoi vers `verify_2fa.php` — ça ne retire aucune capacité, il n'existe **aucun** écran de ré-enrôlement pour un compte authentifié |
| **un GET écrivait en base**, sans jeton CSRF, avant toute preuve | le secret vit en **session** jusqu'à la validation du premier code, et n'est écrit qu'alors |
| **aucune limitation de débit**, là où `verify_2fa.php` et `confirm_2fa.php` en ont deux | même schéma recopié : 5 tentatives par session sur 60 s **et** 10 par IP sur 10 min (`login_attempts`, étape `'2fa'`) |
| **anti-rejeu inerte** — motif E-01 : l'empreinte n'était posée que dans la branche de succès puis supprimée dans la même requête | posée à **chaque** tentative, avant la vérification |

**LE CAS NORMAL EST MESURÉ AUSSI, ET C'EST LA MOITIÉ QUI COMPTE.** Un correctif évident peut casser
le cas normal : refuser la page à un compte déjà enrôlé ne doit rien retirer à un compte qui n'a pas
encore de second facteur. `tests/e2e/go-auth-enrolement.mjs` (**18 PASS / 0 FAIL**) déroule
l'enrôlement complet — page servie à 200 avec son QR, **rien écrit** par l'affichage, secret
**stable** entre deux affichages (le régénérer rendrait l'enrôlement impossible), un code valide
achève l'opération, et le secret finit en base **chiffré**. La suite est **pilotée par des clics
Puppeteer**, convention du projet : un premier jet passait par `node:https` sans navigateur et
mesurait des statuts, pas l'écran. Appeler la fonction ne mesure pas que le bouton l'appelle —
et la règle inverse figurait dans la skill `rw-e2e` jusqu'au 2026-08-23, ce qui explique la
dérive.

**LA FIXTURE MUTE UN SECRET DE COMPTE**, ce qui n'était jamais arrivé : `rw-test-admin` (arbitrage de
l'exploitant), valeur sauvegardée, effacée, **restaurée dans un `finally`** et **relue pour être
prouvée** — treize suites dépendent de ce compte. Ni `rw-test-user` (D-5), ni `opsuser` (compte
réel), ni les cinq résidus `e2e_test_*`.

**UN DÉTAIL DE REPRODUCTION QUI A FAILLI DISCULPER À TORT** : l'attribut `value` du jeton CSRF est
sur la **ligne suivante** du HTML. Un `grep` par ligne ne le trouve pas, le POST rend alors **403**,
et un premier essai concluait que la vulnérabilité n'existait pas. Il faut supprimer les retours à la
ligne avant de chercher.

**CE QUI RESTE OUVERT SUR CE FICHIER**, et qui appartient au portage, pas au correctif : il n'existe
toujours **aucun écran de ré-enrôlement** pour un compte authentifié. `legacy/includes/onboarding.php`
propose `/auth/enable_2fa.php` comme action de l'étape « 2FA », mais un compte connecté n'a plus de
`temp_user` — le lien est mort, et l'étape est simultanément toujours cochée. Le portage devra offrir
ce chemin.

---

## E-95 — Le changement de mot de passe porté : la politique appliquée, et deux colonnes traitées différemment

Sous-lot **A2**, l'un des **deux blocages de la v2.0**. Mesure : **six comptes actifs sur dix** portent
`force_password_change = 1`, dont **`superadmin`**. Le portage **détectait** le drapeau
(`SecondFacteurController` pose `changement_mot_de_passe_requis`) et `/profil` l'annonçait par un
bandeau — mais **n'offrait aucun formulaire**, et renvoyait vers l'ancien portail. Après une bascule
directe, ces six comptes n'auraient jamais pu satisfaire l'exigence.

Base rouge : **7 PASS / 1 FAIL** — un seul échec, parce que la suite garde ses vingt autres assertions
derrière l'existence du formulaire. Après portage : **27 / 0** (legacy **26 / 0**).

**LA POLITIQUE EST CELLE DU LEGACY, À L'IDENTIQUE**, et c'est une obligation, pas un choix de style :
les deux portails partagent la base, donc une règle plus laxiste d'un côté serait un contournement de
l'autre. Quinze caractères, quatre classes, les cinq derniers hachés refusés **plus le courant**
(reprendre son propre mot de passe n'est pas un changement), HIBP en option. Comme le legacy, la
validation rend **une seule clé** pour les cinq règles de complexité : nommer la règle qui a échoué
renseigne autant l'attaquant que la personne.

**DEUX COLONNES, DEUX TRAITEMENTS OPPOSÉS — et les deux sont mesurés.**

| colonne | legacy | portage | pourquoi |
|---|---|---|---|
| `password_updated_at` | **pas écrite** — il compte sur `ON UPDATE CURRENT_TIMESTAMP` | **écrite explicitement** | la clause se déclenche à **toute** modification réelle de la ligne `users`. Un échec de connexion suivi d'un succès remet `failed_attempts` à 0, la ligne change, et le compteur de jours repart de zéro : la politique d'expiration serait vaincue par une faute de frappe. Elle est désactivée aujourd'hui, donc le défaut est **latent** — mais on ne s'appuie pas sur un effet de bord |
| `password_expires_at` | calculée et **écrite** | **pas écrite** | **personne ne la lit** : `verify.php:159` calcule l'expiration depuis `password_updated_at`. Mesure : **0 ligne renseignée** dans toute la table. La porter reviendrait à porter une colonne morte |

**LE JOURNAL S'ÉCRIT NU, ET C'EST CORRECT.** `user_logs` porte `prev_hash` et `self_hash`, et
l'administration offre une « vérification de la chaîne d'audit » — de quoi croire qu'une insertion doit
calculer la chaîne. Mesure : **3368 lignes, dont 757 sans empreinte**, aucun déclencheur sur la table,
et la chaîne est posée par un **scellement séparé** (`legacy/adm/api/audit_seal.php`). L'insertion nue de
`profile.php` est donc la norme, et le portage fait pareil. **Le legacy est dédouané** — en revanche 757
lignes non scellées laissent un trou dans la vérification, ce qui appartient à `adm/`.

**HIBP EST PORTÉ MAIS INERTE.** Opt-in via `HIBP_ENABLED`, en k-anonymity (seuls les cinq premiers
caractères de l'empreinte SHA-1 sortent, jamais le mot de passe), et **fail-open assumé** : bloquer un
changement de mot de passe parce qu'un service tiers est en panne serait pire que le risque couvert.
Mesure : la variable n'est définie dans **aucun** conteneur, donc **aucune requête ne sort**.

**LE REFUS DU MOT DE PASSE TROP COURT DIVERGE, ET LES DEUX SONT CORRECTS.** Le legacy refuse **côté
serveur, avec un message**. Le portage pose `minlength` sur ses champs : **le navigateur refuse d'émettre
la requête**, donc aucun message n'apparaît — et une assertion qui exigeait un message faisait échouer une
garde qui agit *plus tôt*. La suite mesure donc la **propriété** (« pas accepté, haché inchangé ») et
prouve la revalidation serveur **par une requête forgée** émise depuis la page : `minlength` est une
commodité du navigateur, qu'un attaquant ne respecte pas. Mesure : le serveur refuse aussi, haché
inchangé. Défense en profondeur, vérifiée des deux côtés.

**TROIS DÉFAUTS DE MA SUITE, ET LES TROIS ÉTAIENT DES PASS POUR UNE MAUVAISE RAISON :**

1. **la soumission était ancrée sur « le premier bouton `submit` de la page »**. `profile.php` porte
   **cinq** formulaires, et le premier appartient à celui du **courriel** : les six refus soumettaient le
   mauvais formulaire. La skill du projet l'interdit explicitement — on remonte du **champ** à son `form`
   par `closest('form')`. Vérifié au passage : l'adresse du compte n'a pas bougé ;
2. **le message se lisait par une classe approchante** (`[class*="text-red"]`), qui attrapait un compteur
   valant « 0 » sur le legacy — puis, sur le portage, le **bandeau d'exigence**, qui porte la même classe
   `.rw-erreur` et vient avant dans le DOM. Le portage porte donc un `data-rw` dédié ;
3. **`DELETE ... JOIN ... ORDER BY ... LIMIT` : MySQL refuse.** L'exception partait **dans le `finally`**
   et emportait le journal entier — la suite rendait « 0 PASS / 0 FAIL » sans dire si la restauration
   avait abouti. Le nettoyage borne désormais par identifiant (un **delta**) et **chaque étape est
   isolée**.

**UN TEXTE DEVENU FAUX, CORRIGÉ.** La tuile « non porté » annonçait « effectuez le changement depuis
l'ancien portail » alors que le changement venait d'être porté. Elle ne parle plus que des sessions
ouvertes, et dit explicitement que le mot de passe, lui, se change sur cette page.

**PREMIÈRE FIXTURE QUI CHANGE UN MOT DE PASSE DE COMPTE** : `rw-test-admin`, haché +
`force_password_change` + borne d'historique sauvegardés, restaurés dans un `finally`, **état relu pour
être prouvé** — treize suites dépendent de ce compte. Et **la réussite est vérifiée, pas annoncée** : la
suite se reconnecte avec le **nouveau** mot de passe avant de restaurer.

---

## E-96 — La re-authentification ponctuelle portée : un nom d'action par route, et un code qui ne sert qu'une fois

Sous-lot **A5**. Le legacy exige un second contrôle avant tout geste qui donne root
(`legacy/auth/step_up.php`), sur **quatre appelants et aucun autre** — `adm/api/delete_user.php`,
`adm/api/update_permissions.php`, `adm/api/anonymize_user.php` et `api_proxy.php:63`, tous avec le même
ordre de gardes : rôle → méthode → CSRF → step-up. Le portage, lui, **refusait en bloc** les routes
concernées (`PasserelleController`, 403 + `portage: non_porte`). Ce refus n'était pas un trou — accorder
root sans le second contrôle aurait été un recul — mais la capacité manquait : après une bascule directe,
personne n'aurait plus pu déployer ni annuler une politique sudo depuis le portail.

Caractérisation **38 PASS / 0 FAIL sur le legacy**, base rouge du portage **6 / 16**, portage
**24 / 0**.

**TOUT EST MESURÉ SUR LE CHEMIN DE REFUS.** Aucun geste root n'est émis par la suite : ni déploiement,
ni révocation, ni suppression de compte. Les chemins gardés rendent 403 **avant** de lire leur corps. La
seule cible re-jouée après un step-up accordé — et seulement côté legacy — est
`adm/api/update_permissions.php` **avec un corps vide** : il sort sur « Données manquantes » avant toute
écriture, ce qui rend le modal pilotable par de vrais clics sans rien détruire. Vérifié **en lisant le
fichier avant** de faire cliquer.

**LES QUATRE DÉFAUTS DU LEGACY, ET CE QUE LE PORTAGE FAIT À LA PLACE**

| défaut mesuré | legacy | portage |
|---|---|---|
| l'anti-rejeu vit dans `$_SESSION['_step_up_last_totp']` | le même code, rejoué depuis une session **neuve**, est **accepté** (mesuré : `success = true` deux fois) | **refusé** — la garde est le compteur de fenêtre **monotone par compte** de `Totp::verifie`, partagé avec la connexion |
| la clé d'anti-rejeu est propre au step-up | un code observé **à la connexion** reste utilisable pour obtenir un step-up | impossible : un code ne sert **qu'une fois, pour quoi que ce soit** |
| le quota est par session et n'est pas remis à zéro | après un succès, la 5ᵉ tentative suivante rend déjà **429** — cinq step-up légitimes en une minute échouent | quota **par compte**, **remis à zéro sur succès** : mesuré `200 200 200 200 200` après un succès |
| `api_proxy.php:63` fusionne trois routes root sous `policy_action` | un step-up consenti pour **annuler** une politique autorise un **déploiement sudo** pendant quinze minutes (mesuré : les trois refus annoncent le même nom) | **un nom par route** — `policy_sudo_deploy`, `policy_sftp_deploy`, `policy_rollback` — **dérivé du chemin**, pas pris dans une table : ajouter un motif suffit à doter la route de son nom, et l'oubli qui a produit ce défaut n'est plus possible |

**LA LISTE DES ACTIONS EST FERMÉE, ET VÉRIFIÉE PAR ALLER-RETOUR.** Le legacy accepte **n'importe quel**
nom d'action : il le nettoie au caractère puis pose `_step_up_<ce que le client a envoyé>`. Le portage
exige que le nom désigne un chemin réellement gardé — `policy_sudo_deploy` → `/policy/sudo/deploy` →
`policy_sudo_deploy`. Si un chemin gardé portait un jour un blanc soulignement, l'aller-retour échouerait
et le nom serait **refusé** : fail-closed, plutôt que d'ouvrir une marque sur un chemin voisin.

**UNE EXIGENCE DE MA PROPRE CARACTÉRISATION ÉTAIT DANGEREUSE, ET A ÉTÉ RETIRÉE.** Le premier jet de la
suite demandait qu'un second step-up pour une **autre** action reste possible dans la même fenêtre de
30 s, au motif que le refus du legacy gêne un geste légitime. C'était une exigence **d'affaiblissement** :
elle aurait autorisé le rejeu, pour obtenir un step-up, d'un code observé à la connexion — exactement
l'escalade que le step-up existe pour empêcher. Le refus est la bonne réponse. Ce qui cloche chez le
legacy n'est pas qu'il refuse, c'est qu'il refuse **depuis la session**, donc de façon contournable.
Contrepartie assumée et documentée : deux gestes sensibles dans la même fenêtre de 30 s demandent deux
codes.

**LE QUOTA EST PAR COMPTE, DONC IL TRAVERSE LES SESSIONS — c'est le but.** Conséquence visible dans le
journal : la série de statuts du portage n'est pas directement comparable à celle du legacy, dont le
compteur repartait de zéro à chaque session neuve. Brider le compte et non le navigateur est précisément
ce qu'on cherche.

**LE STATUT DISTINGUE LE SEUL DÉPASSEMENT DE QUOTA.** 429 pour le quota, 200 avec `success: false` pour
tout le reste — comme le legacy. Un code faux n'est pas une erreur de protocole, et varier les statuts
renseignerait sur la nature du refus.

**LA MARQUE VIT DANS LE CACHE, ET LE DÉFAUT EST DU BON CÔTÉ.** Le schéma appartient au backend Python et
ne reçoit pas de migration depuis le portage ; la marque est donc stockée comme la garde anti-rejeu de
`Totp`. Une purge du cache **referme** les autorisations en cours au lieu de les ouvrir.

**`step_up_ttl` EST ENFIN LU.** La clé existait dans `config/rootwarden.php` et **personne ne la lisait**
(vérifié par recherche). Elle borne désormais la durée de la marque. `step_up_tentatives` la rejoint,
avec sa valeur par défaut de 5 — celle du legacy.

**DEUX CHOSES NE SONT PAS PORTÉES, ET C'EST DIT PLUTÔT QUE TAIT.**

1. **Le panneau de décision en page.** Le legacy pose un modal (`js/utils.js:59-146`) **intégralement en
   français codé en dur, et qui tutoie** — donc hors parité FR/EN. Le portage ne le porte pas encore,
   pour une raison mesurée : **aucune page du portage n'appelle une route gardée par un step-up**. Les
   pages qui le feront — `ssh/` (K4) et `adm/` — ne sont pas portées. Un panneau posé dans le gabarit
   sans flux pour l'exercer ne pourrait être mesuré par aucun clic, et une pièce non mesurée dans le
   gabarit met en risque les quatorze pages déjà portées. Il sera porté **avec son premier
   consommateur** ;
2. *(levé — voir ci-dessous)* la branche « un step-up accordé laisse passer la requête » **est**
   mesurée sur le portage, par une cible de rejeu dont l'innocuité a été **vérifiée en lisant le
   backend**.

**UNE RÉVOCATION, QUE LE LEGACY N'A PAS.** `POST /profil/step-up/revoquer` efface les marques du
compte. Strictement dé-escaladant, donc sans garde de rôle : renoncer à une autorisation n'en demande
aucune. Chez le legacy la marque vit quinze minutes et **rien ne permet de l'abréger**, pas même la
fermeture du panneau. La révocation a une contrepartie technique : le pilote fichier du cache ne sait
pas effacer par motif, donc les actions marquées sont tenues dans un **index** par compte.

**LA BRANCHE « LA MARQUE LAISSE PASSER » EST MESURÉE SUR LES DEUX CIBLES — et c'est un accident qui l'a
rendue possible.** Elle était d'abord déclarée non mesurable : la vérifier semblait exiger de laisser la
passerelle transmettre `/policy/sudo/deploy`, c'est-à-dire exécuter un déploiement sudo réel. Puis une
exécution de la suite a trouvé sa première sonde **transmise** avec, en réponse,
`{"message":"machine_id requis."}` — une marque posée par l'exécution précédente avait survécu quinze
minutes. Lecture du backend faite ensuite, et pas avant de conclure :
`backend/routes/policies.py:220-225` résout les identifiants SSH **en premier**, et
`_resolve_ssh_creds` (`:44-47`) rend 400 dès que le corps ne porte pas de `machine_id` — **avant tout
`ssh_session`**. Un corps vide ne déploie donc rien, et la branche est mesurable sans risque.

**MA SUITE N'ÉTAIT PAS IDEMPOTENTE, ET C'ÉTAIT UN VRAI RISQUE.** Elle accordait un step-up pour une
route root, et l'exécution suivante postait sur cette même route quinze minutes plus tard. **Seul un
paramètre absent a empêché un déploiement sudo réel** — de la chance, pas une précaution, et
exactement ce que la règle du projet interdit : toute fixture se nettoie **à l'entrée et dans un
`finally`**. La suite rend désormais les privilèges aux deux bouts, et le journal imprime combien de
marques ont été effacées. La première exécution après le correctif a d'ailleurs montré « 0 marque
effacée » à l'entrée alors qu'une marque **orpheline** vivait encore : elle avait été posée avant que
l'index existe. Un `cache:clear` l'a levée — mais le fait que le nettoyage neuf n'ait rien vu de
l'ancien état est le genre de détail qui, non lu, aurait fait accuser le code.


---

## E-97 — L'enrôlement du second facteur porté : le dernier blocage de la v2.0 tombe

**C'était la dernière chose qui empêchait d'éteindre l'ancien portail.** L'enrôlement n'existait que
côté legacy : un compte neuf, ou un compte dont on aurait réinitialisé le second facteur, n'avait
**aucun chemin** vers un second facteur sur le portage. L'écran affichait une impasse explicite
renvoyant vers l'ancien portail — honnête, mais rédhibitoire pour une bascule directe.

Même suite sur les deux cibles : **18 PASS / 0 FAIL de chaque côté** (`go-auth-enrolement.mjs`, qui
n'était jusque-là jouée que sur le legacy et sortait par « sans objet » sur le portage).

**LE PORTAGE EST CELUI DU LEGACY CORRIGÉ, PAS DU LEGACY.** `enable_2fa.php` divulguait le secret d'un
compte **déjà enrôlé** à qui ne présentait que le mot de passe — corrigé en `v1.37.48`, voir **E-94**.
Les trois propriétés qui ferment ce trou sont reprises ici comme des **invariants**, et chacune est
mesurée :

| invariant | ce qu'il empêche | mesure |
|---|---|---|
| un compte qui a **déjà** un secret n'atteint jamais l'écran | la divulgation de E-94 | `/second-facteur/enrolement` renvoie vers la vérification, aucun QR, aucun secret à l'écran |
| le secret vit en **session** et ne touche la base qu'**après** la preuve | un `GET` qui écrit | après affichage, le secret en base est **toujours absent** |
| il ne **change pas** d'un affichage à l'autre | un QR scanné qui ne correspond plus au code attendu | rechargement : secret **identique** |

L'invariant 1 est vérifié **deux fois** : à l'affichage et de nouveau à l'activation. Entre les deux,
un autre chemin a pu enrôler ce compte — écraser son secret le rendrait inaccessible. Fail-closed.

**LE CODE D'ENRÔLEMENT PASSE PAR LE MÊME ANTI-REJEU QUE LA CONNEXION.** Le secret de session est
chiffré à la volée pour être présenté à `Totp::verifie`, donc au compteur de fenêtre monotone par
compte. Conséquence voulue : un code employé pour **enrôler** ne peut pas être rejoué pour **ouvrir
une session**.

**UN SEUL CHEMIN OUVRE UNE SESSION.** La vérification et l'enrôlement partagent désormais
`ouvreLaSession()` : deux copies de ce chemin auraient fini par diverger, et c'est le chemin où une
divergence **accorde un accès**. Le compte y est relu en base à cet instant — rôle et exigences
comprises — plutôt que repris d'un objet chargé plus tôt.

**LE QR DIVERGE PAR NATURE, ET LES DEUX SONT CORRECTS.** Le legacy rend un **PNG en base64** via `gd`.
Le conteneur du portage n'a **ni `gd` ni `imagick`** (mesuré) : il rend un **SVG en ligne**, produit
par `bacon/bacon-qr-code`, qui ne demande aucune extension et reste net à toute taille. La suite mesure
donc « un QR est présent », pas « une balise `<img>` est présente » — exiger la forme du legacy aurait
fait échouer un portage correct. `endroid/qr-code`, côté legacy, reste une **dépendance morte**.

**LE FOND BLANC DU QR N'EST PAS UNE COQUETTERIE.** Un lecteur de QR lit des modules sombres sur fond
**clair**. Un SVG posé sur le fond sombre du thème serait illisible **à la caméra**, et le DOM n'en
dirait rien : aucune assertion ne voit un contraste inversé. Le cadre impose donc `#fff` quel que soit
le thème, et la capture le **mesure** (`getComputedStyle`), elle ne le suppose pas.

**CE QUI N'EST PAS PORTÉ, ET POURQUOI.** Le **ré-enrôlement** — remettre un second facteur à un compte
qui en a déjà un — n'est pas ici. Il n'existe pas non plus dans le legacy sous forme d'écran : le seul
chemin vivant est `adm/includes/manage_roles.php:101-121`, qui porte une **garde hiérarchique**, et
`reset_totp.php` est du code mort **plus permissif** que ce chemin. Le ré-enrôlement appartient donc à
`adm/` et à sa garde, pas à l'écran de connexion. Le dire plutôt que de porter le fichier mort.

**UN ARTEFACT DE CAPTURE, MESURÉ AVANT D'ÊTRE « CORRIGÉ ».** Sur les images pleine page, le sélecteur
de langue paraît flotter au milieu de la carte. Vérification faite : `.rw-langues-flottant` est en
`position: fixed`, et un élément fixe se rend à sa position d'**écran** dans une capture pleine page.
Ce n'est pas un défaut de mise en page. Le script de capture le dit, pour que personne ne corrige ce
que l'image invente.

**DEUX DÉFAUTS VUS À L'IMAGE, PAS AUX ASSERTIONS.** Le bouton principal passait sur **deux lignes** et
devenait plus haut que son voisin — libellé raccourci à « Activer », comme l'écran voisin dit
« Valider ». Et avant cela, l'écran rendait **entièrement vide** : `$temporaire['name']` n'existe pas,
la clé de session s'appelle `nom`. Une clé de tableau supposée au lieu d'être lue, et la page tombait
en 500 — que seule la lecture du journal a révélée, l'assertion disant seulement « pas de QR ».


---

## E-98 — La page Docker portée : une panne réseau se voit enfin, et le geste dit ce qu'il coûte

Première des **19 entrées de menu restantes**, et la plus petite : 201 lignes, deux fichiers.
Même suite sur les deux cibles — **legacy 16 / 0**, **portage 16 / 0**, base rouge **1 / 9**.

**LE SCAN N'EST PAS UNE LECTURE, ET LA PAGE LE DIT MAINTENANT.** Relevé en lisant le backend avant
d'écrire un seul clic : `backend/docker_monitor.py:116` lance un **`git fetch`** dans le dépôt de
chaque projet compose de la machine visée — cela écrit dans `.git/` et fait **sortir la machine sur le
réseau** — et `backend/docker_registry.py` interroge le registre distant. Surtout,
**`/docker/scan_all` frappe TOUTES les machines**, `srv-zabbix` (production) comprise ; la machine est
bien dans le sélecteur, mesuré. Le legacy présente ces deux boutons comme des gestes anodins. Le
portage porte un encart de guidage qui nomme la production sur le geste qui coûte.

**AUCUNE MACHINE N'EST JOINTE PAR LA SUITE.** Les deux boutons sont **interceptés et avortés** : on
mesure que le clic émet la bonne requête, vers la bonne route, avec la bonne charge — et rien ne part.
C'est le motif « joint la production par construction → interception + avortement ».

**LE DÉFAUT QUE LE PORTAGE NE REPREND PAS.** `legacy/docker/js/main.js:14` fait `await fetch(...)`
**sans `try`** dans son `api()`. Quand le backend est injoignable, le rejet remonte hors du
gestionnaire de clic, la promesse n'est jamais rattrapée, et le message d'erreur pourtant prévu
(`docker.err_scan`) **n'apparaît jamais** : l'exploitant clique, et il ne se passe rien — ni résultat,
ni explication. `scanAll`, lui, enveloppe son `fetch` (`:106`) et affiche le message : l'asymétrie est
un oubli, pas une intention. Mesuré des deux côtés en avortant la requête, ce qui est exactement ce
qu'un backend éteint produirait. Le portage enveloppe chaque appel et ajoute une clé `err_reseau` que
le legacy n'a pas.

**LE LEGACY EST DÉDOUANÉ SUR UN POINT OÙ JE L'ACCUSAIS.** J'avais écrit l'écart « le refus rend
HTTP 200 avec une page habillée, donc un automate lit une réussite ». La mesure dit l'inverse : il rend
un vrai **403**. L'écart était une accusation sans fondement et il a été **retiré** — quand la mesure
dédouane, il faut le dire aussi clairement que quand elle accuse. Les deux cibles tiennent la
propriété, c'est donc une assertion partagée.

**UNE ASSERTION QUI LISAIT LE TEXTE AU LIEU DU CODE.** Le premier jet reniflait le corps de la page à
la recherche de « accès refusé ». Sur la base rouge, la page n'existait pas encore et rendait
« 404 Not Found » — que le renifleur comptait comme un **non-refus**. La propriété est le **statut**,
et il doit valoir 403 : un 404 dit « cette page n'existe pas », ce qui n'est pas « vous n'y avez pas
droit ».

**LA GARDE EST LE RÔLE, PAS UNE PERMISSION**, et c'est repris tel quel : `role:2` seul, comme
`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`. C'est la seule entrée de menu dans ce cas ; le relevé est
signalé dans `INVENTAIRE.md` et n'est pas corrigé au détour d'un portage.

**SEPT CLASSES CSS INVENTÉES, ET AUCUNE N'AURAIT LEVÉ D'ERREUR.** `rw-pastille--succes`,
`rw-tuile__libelle`, `rw-bouton--petit`, `rw-cache`, `rw-mono`… n'existent pas ; les vraies sont
`--ok`, `__texte`, `--minuscule`. Une classe absente ne produit **aucun message** : elle produit un
élément sans style, et le test DOM le voit bien présent. Relevé par comparaison avec la feuille avant
la première exécution. La grille des tuiles, elle, existait déjà en `rw-grille--compacte` — inutile
d'en inventer une.


---

## E-99 — `docker/` archivé, et le tiroir mobile du legacy s'avère incomplet

Dixième partie archivée. Le cycle du §4.4 déroulé : `git mv legacy/docker legacy/_deprecated/`,
bascule du point d'entrée, greffe de `constateArchivage` + `verifieMenuLegacy` en tête de la suite.
Référence legacy **16 → 5** : 1 (la partie rend 404) + 2 fichiers réels + 2 (le lien du menu mène au
portage, et il aboutit). Mesuré, pas calculé de tête.

**UN SEUL POINT D'ENTRÉE À BASCULER, ET C'EST UNE MAUVAISE NOUVELLE POUR LE LEGACY.** Le cycle prévient
qu'il faut basculer **tous** les points d'entrée — barre latérale, tiroir mobile, raccourcis du tableau
de bord, et la carte de raccourcis clavier de `head.php` qu'aucun contrôle sur les `href` ne voit. Ici
il n'y en avait qu'un. La raison, mesurée : **le tiroir mobile du legacy est incomplet** — 22 liens
contre 32 dans la barre latérale, et `docker` n'y figure pas. Une dizaine d'entrées sont donc
inaccessibles sur mobile depuis toujours.

C'est précisément la dérive que `App\Support\Navigation` rend impossible côté portage : la barre et le
tiroir incluent le **même** partiel, et un test vérifie qu'ils rendent les mêmes entrées. Le legacy,
lui, décrit son menu deux fois — et les deux descriptions ont divergé sans que rien ne le signale.
Défaut **non corrigé** : on ne soigne pas ce qu'on démonte, et les dix entrées concernées seront
portées.

**DEUX SURFACES DEVENUES MORTES, relevées et non touchées** : `legacy/api_proxy.php:151` garde
`/docker/` dans sa liste blanche — comme `/supervision/` avant elle, plus rien ne l'emprunte ; et
`legacy/documentation.php:1052` décrit « la page `/docker/` » dans une balise `<code>`, donc sans lien
cliquable, mais le chemin qu'elle nomme rend désormais 404. `documentation.php` est lui-même une entrée
de menu à porter.


---

## E-100 — ChatOps porté : le premier chemin PUBLIC du portage, et ce qu'il fallait ne pas faire

Deuxième des 19 entrées de menu restantes. Legacy **21 / 0**, portage **22 / 0**, base rouge
**4 / 13**. L'écart d'une assertion est celle que le legacy ne tient pas : « aucune boîte native ».

**LE MODULE A DEUX PIÈCES DE NATURE OPPOSÉE, et il fallait les traiter séparément.** La page de
configuration est ordinaire : elle lit et écrit des correspondances « identifiant chat → compte » par
trois routes du backend, derrière `role:2` **et** `perm:can_admin_portal`. Le `webhook.php`, lui, est un
passthrough **public, sans session et sans jeton CSRF**, que Slack appelle. Ce n'est pas une page, il
n'est pas dans le menu, et c'est **le premier chemin public du portage qui accepte un POST**.

**CE QUE LE RELAIS NE FAIT SURTOUT PAS : recopier les en-têtes en bloc.** Le legacy nomme quatre
en-têtes un par un (`X-Slack-Signature`, `X-Slack-Request-Timestamp`, `X-ChatOps-Token`,
`X-ChatOps-Platform`) et le portage fait pareil, avec la liste **fermée** en constante. Recopier
l'ensemble des en-têtes transmettrait un `Cookie` ou un `Authorization` du client vers le backend et
transformerait ce relais en **confusion d'identité** : le backend croirait parler à un appelant
authentifié. La liste fermée n'est pas une élégance, c'est la garde.

**ET LE REFUS EST MESURÉ, PAS SUPPOSÉ.** Une requête forgée depuis la page, sans signature et sans
jeton CSRF, rend **`403 {"text":"ChatOps desactive."}`** sur les deux cibles. Deux propriétés
distinctes, et les deux comptent :

| propriété | pourquoi |
|---|---|
| le webhook **n'exige pas** de jeton CSRF | Slack n'en présente aucun : un webhook qui l'exigerait ne pourrait pas fonctionner |
| une commande non signée **est refusée** | sinon la route serait une porte ouverte, publique, vers un exécuteur de commandes |

L'authentification réelle vit dans le backend, sur la signature Slack ou un jeton partagé, et il refuse
d'emblée si la fonctionnalité est désactivée — fail-closed vérifié en lisant
`backend/routes/chatops.py:34`, pas en observant une réponse.

**LA FONCTIONNALITÉ EST DORMANTE, ET C'EST CE QUI REND CE PORTAGE SANS RISQUE.** Mesure : aucune
variable `CHATOPS_*` dans `srv-docker.env` (seul l'exemple en porte, à `false`), et **zéro
correspondance** dans `chatops_users`. Aucune requête ne part vers Slack, aucun trafic entrant n'est
simulé.

**L'ADRESSE DU WEBHOOK CHANGE, ET LA PAGE LE DIT.** Elle ne finit plus par `webhook.php`. Le legacy
affiche l'adresse sans indiquer qu'elle bougera ; le portage ajoute une ligne en gras qui demande de la
reporter dans la messagerie **avant** d'activer ChatOps. Sans mapping ni secret aujourd'hui, l'impact
est nul — mais une bascule silencieuse aurait cassé la fonctionnalité le jour de son activation, sans
message et sans trace.

**LA BOÎTE NATIVE DISPARAÎT.** Le legacy supprime une correspondance derrière un `confirm()`. Cette
boîte recouvre précisément la ligne sur laquelle on décide, ne se style pas — action destructrice et
annulation au même poids — et **bloque Puppeteer**, donc aucun test ne peut mener l'action au bout. Le
portage ouvre un panneau de décision **en ligne**, sous la ligne concernée, avec son bouton de danger
et son annulation. La suite mesure les deux : elle accepte explicitement la boîte du legacy
(`page.on('dialog')`) et vérifie qu'**aucune** n'apparaît côté portage.

**LE CHOIX DE PLATEFORME EST UNE LISTE FERMÉE des deux côtés, et c'est mesuré comme tel** — pas
« un champ existe », mais « c'est un `select` ». Une plateforme est un identifiant que le backend range
puis relit : une saisie libre y ouvrirait une valeur que rien n'attend.

**LES DEUX CHEMINS DE LA GARDE SONT EXERCÉS**, ce qui n'était pas gagné : `rw-test-admin` a le **rôle 2
mais pas** `can_admin_portal` (mesuré en base), donc il mesure le chemin « permission » avec le rôle
satisfait ; `rw-test-user` mesure le chemin « rôle ». Les deux rendent **403** sur les deux cibles.

---

## E-101 — La pastille « ouverte maintenant » du legacy ment, et de deux heures

**Le défaut le plus grave rencontré depuis le début du chantier**, trouvé en LISANT le module avant
d'écrire un clic, puis démontré par un test piloté à la souris et au clavier.

`legacy/maintenance/js/main.js:26-35` calcule `isActiveNow` **dans le navigateur**, sur l'horloge du
navigateur. L'application, elle, se fait dans `backend/maintenance.py:_in_window`, sur l'horloge du
**conteneur**. Ce ne sont pas les mêmes :

| horloge | relevé du 2026-08-25 |
|---|---|
| hôte, navigateur, `rootwarden_php` | **CEST 19:09** |
| `rootwarden_python` — celui qui applique — et `rootwarden_laravel` | **UTC 17:09** |

**La démonstration tient en une ligne de journal.** La suite crée une fenêtre `18:48 → 19:28`, tous les
jours, à 19:09 heure locale. La plage encadre donc l'instant présent *du navigateur* et pas celui *du
serveur* :

```
INFO  horloge du navigateur : 19:09
INFO  horloge du conteneur qui applique : 17:09
INFO  verdict du backend pour cette fenetre : FERMEE
INFO  cellule d'etat de la ligne d'epreuve : « Ouverte »
```

Le legacy annonce **« Ouverte »**. Le backend refusera. Et comme l'enforcement vit dans **d'autres
modules** (`backend/routes/updates.py:19`, `backend/routes/monitoring.py:229`), le refus n'apparaît pas
sur cette page : l'exploitant lit « Ouverte », lance une mise à jour, et reçoit un **423** sans rapport
visible avec les fenêtres de maintenance.

En heure locale, pour une fenêtre `22:00 → 06:00` saisie normalement :

| heure locale | ce que la page annonce | ce que le backend fait |
|---|---|---|
| 22:00 → 00:00 | **ouverte** | **refuse** |
| 00:00 → 06:00 | ouverte | autorise |
| 06:00 → 08:00 | **fermée** | **autorise** |

Deux bandes de deux heures où la page et l'application se contredisent, **dans les deux sens**.

**Ce n'est pas E-73.** E-73 porte sur un *affichage* d'horodatage faux de deux heures. Ici la valeur
fausse est un **verdict** sur une règle de blocage, rendu par un code qui n'est pas celui qui décide.
E-73 est néanmoins élargi : le décalage ne fait pas que mal afficher, il fait **mal décider**.

**PORTAGE — le verdict remonte là où il est appliqué.** `list_windows`
(`backend/routes/maintenance.py`) rend désormais, par fenêtre, un `active_now` calculé par
`mw._in_window` — *la fonction même qui bloque* — ainsi que `server_time` et `server_offset`. Le
JavaScript du portage ne recalcule plus rien : il **affiche**. La règle n'est pas déplacée vers le
navigateur, elle y est annoncée telle qu'elle sera appliquée.

Le premier jet du portage recopiait pourtant le calcul en JavaScript, en promettant de « suivre le
Python pas à pas ». C'était la mauvaise réponse : **suivre le pas à pas ne protège de rien quand ce
n'est pas le pas qui diffère, mais l'heure.**

**ET LE VERDICT EST EXPLIQUÉ.** Un verdict juste mais incompréhensible ne vaut qu'à moitié : lire
« Fermée » sur une plage qui contient visiblement l'heure qu'il est passerait pour une panne. La page
affiche donc une ligne qui **nomme l'horloge du serveur** — et seulement lorsqu'elle diffère de celle du
navigateur, une mention permanente cessant d'être lue. Deux assertions la mesurent : elle est visible
exactement quand les horloges divergent, et elle cite bien l'heure du **serveur**, pas celle du
navigateur.

**NON CORRIGÉ, ET DÉLIBÉRÉMENT** : le fuseau du conteneur `rootwarden_python`. Le changer corrigerait
la racine et déplacerait **tous** ses horodatages, journaux d'audit compris. C'est une décision de
flotte, pas un détour de portage de page — elle attend l'exploitant. Le legacy garde également sa
pastille calculée côté navigateur : on ne soigne pas ce qu'on démonte.

---

## E-102 — Une fenêtre limitée à une machine n'est pas la flotte, et le portage a d'abord dit le contraire

Le legacy n'affiche **aucun état d'ensemble** : pour savoir si des actions mutantes sont restreintes, il
faut lire le tableau ligne par ligne et faire le calcul de tête — alors que c'est le seul renseignement
qui décide.

Le portage ajoute une pastille. **Son premier jet était faux**, et faux précisément dans le cas le plus
courant du banc d'essai : il comptait les fenêtres activées **sans regarder leur portée** et annonçait
« Flotte restreinte » dès la première.

La requête du backend dit exactement le contraire (`backend/maintenance.py:120-123`) :

```sql
WHERE enabled = 1 AND (scope = 'global' OR machine_id = %s)
```

Pour une machine donnée, les fenêtres applicables sont les **globales** activées **plus** celles
activées qui la **nomment**. Aucune applicable = aucune restriction. D'où **trois** états et non deux :

| situation | état annoncé |
|---|---|
| au moins une fenêtre **globale** activée | toute la flotte est restreinte |
| sinon, N machines nommées | **ces N machines seulement** |
| aucune | aucune restriction |

Annoncer « Flotte restreinte » quand une seule machine l'est ferait chercher une panne générale là où il
n'y en a pas — et c'est une erreur qu'on ne découvre qu'en la cherchant, puisque le refus se produit
ailleurs.

**UN SECOND DÉFAUT, TROUVÉ PAR LA MÊME ASSERTION.** Une fois la portée corrigée, la pastille restait
« Aucune restriction » après la création d'une fenêtre : elle est rendue par le **serveur** au
chargement, et la page crée, bascule et supprime ensuite sans jamais la rafraîchir. Un résumé
serveur que la page invalide par ses propres gestes vaut moins que pas de résumé. Le script la
recalcule désormais sur la liste que le backend vient de rendre — deux comptages sur `scope` et
`enabled`, soit la condition du `WHERE` ci-dessus, et **aucune** règle d'horaire dupliquée.

Sans cette assertion, les deux corrections n'auraient eu **aucun témoin**.

---

## E-103 — `maintenance/` : la boîte native disparaît, et la garde est exercée par ses deux chemins

Le legacy supprime une fenêtre derrière un `confirm()` (`js/main.js:104`). Même motif que partout
ailleurs dans ce chantier : la boîte recouvre la ligne sur laquelle on décide, ne se style pas — action
destructrice et annulation au même poids — et **bloque Puppeteer**. Le portage ouvre un panneau de
décision **en ligne**. La suite mesure les deux : elle accepte explicitement la boîte du legacy et
vérifie qu'**aucune** n'apparaît côté portage.

**Les deux chemins de la garde sont exercés** : `rw-test-admin` a le **rôle 2 mais pas**
`can_admin_portal`, donc il mesure le chemin « permission » avec le rôle satisfait ; `rw-test-user`
mesure le chemin « rôle ». **403** des deux côtés.

**UN GESTE DE TEST QUI AVAIT TORT.** Le premier jet remplissait les champs d'heure par
`click({ clickCount: 3 })` puis `type('1847')`, et lisait `22:47` : un `input[type=time]` est un
composite de segments, le clic avait posé le caret sur les **minutes**, les deux premiers chiffres se
sont perdus et les deux suivants ont écrasé les minutes seules. La suite accusait la page alors que le
défaut était dans le geste. Correction : revenir au premier segment par des flèches — un vrai geste de
clavier, et le seul qui replace le caret d'où qu'il vienne.

---

## E-104 — `adm/` D1 : les deux points d'API de la chaîne d'audit se **contredisent**, et le bouton qui devait boucher le trou ne peut rien sceller

Trouvé en lisant, **mesuré au clic** le 2026-08-25 par `tests/e2e/go-adm-audit.mjs`. La même base, au
même instant, obtient deux verdicts opposés :

| ce qu'on clique | ce qui répond |
|---|---|
| **Vérifier l'intégrité** (`adm/api/audit_verify.php`) | ✅ « Chaîne intacte — 3311 lignes scellées, 868 non scellées » |
| **Sceller les orphelines** (`adm/api/audit_seal.php`, en simulation) | ❌ « Désynchronisation détectée sur 1 ligne(s). Aucune réécriture effectuée. **Investigation requise** », `tampered_detected: [3]` |

**La cause tient en une ligne**, et c'est un désaccord sur ce qu'est la chaîne. Devant une ligne
**orpheline** (`self_hash IS NULL`) :

- `audit_verify.php:44-51` la **saute** sans avancer la tête de chaîne ;
- `audit_seal.php:79-84` **calcule** son hash et **avance** la tête (`$lastHash = $computed`).

Or la chaîne réellement inscrite en base saute les orphelines. Mesuré ligne à ligne :

| id | `prev_hash` | `self_hash` |
|---|---|---|
| 1 | `GENESIS` | `d36ccba5…` |
| 2 | **NULL** | **NULL** |
| 3 | `d36ccba5…` — *celui de la ligne 1* | `5a070372…` |
| 4 | **NULL** | **NULL** |
| 5 | `5a070372…` — *celui de la ligne 3* | `d9ce6fe8…` |

**C'est donc `audit_verify.php` qui a raison**, et deux mesures indépendantes le confirment sans
passer par lui :

1. un `LAG()` SQL sur les seules lignes scellées rend **3311 maillons, 0 rupture**, et le premier
   maillon est bien `GENESIS` ;
2. surtout, **le code qui ÉCRIT tranche** — et c'est lui l'autorité sur ce qu'est la chaîne.
   `adm/includes/audit_log.php:111-115`, seul chemin d'insertion scellée :

   ```sql
   SELECT self_hash FROM user_logs
    WHERE self_hash IS NOT NULL          -- il SAUTE les orphelines
    ORDER BY id DESC LIMIT 1 FOR UPDATE
   ```

   La chaîne inscrite saute donc les lignes non scellées **par construction**. `audit_verify.php`
   lit ce qui est écrit ; `audit_seal.php` lit autre chose.

**Ce que le défaut coûte, et c'est là qu'il devient grave.** `stopped_at_tamper` verrouille le bloc
d'`UPDATE` (`audit_seal.php:105` : `if (!$dryRun && !$stopAtTamper && …)`). Le parcours s'arrête sur
la ligne 3 à **chaque** appel, donc :

1. **le bouton « Sceller les orphelines » ne peut sceller AUCUNE ligne, jamais** — et il ne le dit
   pas : il rend « Scellé : 0 lignes sur 1 orphelines », ce qui se lit comme « il n'y avait presque
   rien à faire » alors qu'il y en a **868** ;
2. le trou grandit tout seul. Le plan annonçait **757** orphelines ; mesuré 866, puis 867, puis 868
   **en une heure** — l'insertion au journal est nue, chaque connexion en ajoute une, et le seul
   remède est inerte ;
3. chaque appel écrit une ligne `SECURITY … investigation requise` dans le journal d'erreurs PHP
   (`audit_seal.php:88-95`) pour une ligne qui n'a **pas** été altérée. **Une alarme de sécurité qui
   crie au loup use la seule alarme qu'on ait.**

**FERMÉ au portage** (`v1.37.59`) : `App\Services\JournalAudit::parcourt()` est la **seule** lecture
de la chaîne, et la vérification comme le scellement s'y adossent — ils ne *peuvent* plus diverger.
La règle retenue est celle du code qui écrit : une ligne non scellée ne fait pas avancer la tête.

Mesuré sur le portage le 2026-08-25, sur la même base et à la même seconde :

| | legacy | portage |
|---|---|---|
| « Vérifier » | chaîne saine | chaîne saine |
| « Sceller », en simulation | **ARRÊT sur incohérence** | **poursuite normale, 868 orphelines** |

Le scellement redevient donc possible. Il reste **irréversible**, et le portage le traite comme tel :
la décision se prend dans un panneau en page qui **nomme le nombre de lignes** et n'active sa
confirmation qu'à la saisie exacte de ce nombre — contrôle **répété côté serveur**, une garde du
navigateur déplaçant le refus sans le supprimer. Le garde-fou SQL `WHERE self_hash IS NULL` et le
refus de réécrire une ligne déjà scellée sont **repris tels quels** : ce sont les deux bonnes idées
du fichier d'origine.

---

## E-105 — `audit.entries_total` affiche son gabarit `:count`, en français **et** en anglais

Vu **à l'image**, pas par une assertion : la page annonce « **4 179 :count entrees au total** ».

La clé porte un gabarit de substitution que personne ne substitue :

| catalogue | valeur |
|---|---|
| `lang/fr/admin.php:259` | `':count entrees au total'` |
| `lang/en/admin.php:267` | `':count entries'` |

et `audit_log.php:142` écrit `number_format($total) . ' ' . t('audit.entries_total')` — le nombre est
déjà là, le gabarit reste. Les **deux** langues sont touchées, et la version anglaise est en plus
amputée (« entries », sans « au total »).

Aucune assertion DOM ne pouvait le voir : le nombre attendu **est** bien dans la page, la chaîne
`:count` n'est qu'un mot de plus à côté. **C'est la capture qui l'a montré.**

**FERMÉ au portage** (`v1.37.59`) : `__('audit.entries_total', ['nombre' => …])` substitue pour de
bon, et la page affiche « 4 179 entrées au total ». Le séparateur de milliers suit la langue, et il
est calculé dans le **contrôleur** — une vue n'a pas à porter cette règle.

Et la leçon de mesure, qui vaut au-delà de cette clé : **la parité FR/EN se relit sur le RENDU**, pas
sur la présence des clés. Les deux catalogues du legacy sont à parité stricte, et les deux affichent
un gabarit.

---

## E-106 — Le bouton « Sceller les orphelines » a l'air **désactivé** : `bg-yellow-600` a été purgée

**Quatrième occurrence** du même piège, et la plus ironique : le bouton qui ne peut rien faire (E-104)
a aussi l'air de ne rien pouvoir faire.

Mesuré dans le binaire CSS servi (`legacy/assets/css/tailwind.css`) :

| classe | présente ? |
|---|---|
| `.bg-purple-600` (bouton « Vérifier ») | **oui** |
| `.bg-green-600` (bouton « Exporter CSV ») | **oui** |
| `.bg-yellow-600` (bouton « Sceller ») | **non** |
| `.hover:bg-yellow-700` | **non** |

Le bouton rend donc **sans fond**, en gris, entre deux voisins colorés — la signature visuelle d'un
contrôle désactivé. Le HTML est juste ; c'est la feuille qui ne porte pas la classe. Aucune assertion
DOM ne le voit : l'élément est bien présent, bien cliquable, et sa classe est bien dans l'attribut.

**FERMÉ au portage** (`v1.37.59`) : le bouton prend `.rw-bouton--avertissement`, une classe de la
feuille écrite à la main — sans étape de construction, il n'y a rien qui purge. Vérifié à l'image :
le bouton rend en ambre, à côté du bleu de « Vérifier » et du gris d'« Exporter ».

La teinte n'est d'ailleurs pas prise au hasard : **le rouge est réservé à ce qui interrompt un
service**. Un scellement modifie sans interrompre.

Et la règle, une quatrième fois : **mesurer le style CALCULÉ, ou regarder l'image.**

---

## E-107 — Le journal d'audit n'est internationalisé qu'à moitié

Les libellés statiques passent par `t('audit.*')`. Tout ce que le JavaScript écrit est en **français
codé en dur**, dans un fichier par ailleurs bilingue :

| `adm/audit_log.php` | texte |
|---|---|
| `:189` | `'⏳ Verification de la chaine de hash en cours...'` |
| `:195` | `` `✅ Chaine intacte - ${d.sealed} lignes scellees, …` `` |
| `:201` | `` `❌ INCOHERENCE DETECTEE - type=… a la ligne …` `` |
| `:206`, `:229` | `'✗ Erreur : '` |
| `:213` | `confirm("Sceller les lignes orphelines dans la hash chain ?")` |
| `:225` | `` `🖋 Scelle : ${d.sealed} lignes sur … orphelines.` `` |

Un exploitant en anglais lit donc l'interface en anglais et **les verdicts en français** — y compris
celui qui annonce une incohérence de la chaîne d'audit.

S'y ajoute le `confirm()` natif de `:213`, qui recouvre la ligne sur laquelle on décide, ne se style
pas, et **bloque Puppeteer**. Même traitement que partout ailleurs : un panneau de décision en page.

**FERMÉ au portage** (`v1.37.59`) : **41 clés, FR et EN**, jeux comparés dans le même commit. Les dix
libellés que le script rend sont posés **en données** dans la page (`@json` sur une ligne) — une
chaîne écrite en dur dans du JavaScript échappe par nature à la parité.

Et le `confirm()` disparaît : la décision se prend dans un `rw-panneau-decision`, qui ne recouvre pas
la ligne sur laquelle on décide, se style, et ne bloque pas Puppeteer — c'est d'ailleurs ce qui rend
le chemin de refus **testable**, ce qu'une boîte native ne permet pas.

---

## E-108 — `adm/` D2 : « Marquer lu » ne marque rien, et l'écran affirme le contraire

Mesuré au clic le 2026-08-26 par `tests/e2e/go-adm-notifications.mjs`. Trois mesures qui convergent
sur la même seconde :

| ce qu'on mesure | ce qu'on relève |
|---|---|
| htmx est-il chargé sur la page ? | **oui** |
| requêtes POST émises par le clic | **aucune** |
| le bouton a-t-il disparu de l'écran ? | **OUI** |
| la ligne est-elle lue en base ? | **non** |

La cause est dans le balisage, `notifications.php:140-142` :

```html
<button hx-post="/adm/api/notifications.php" hx-vals='{"action":"read","id":…}' hx-swap="none"
        onclick="this.closest('div.flex').parentElement.classList.remove('bg-blue-50/50',…); this.remove();">
```

**Le `onclick` retire le bouton du DOM PENDANT l'événement de clic.** L'élément quitte le document
avant que htmx n'émette, donc rien ne part — mais le surlignage bleu est effacé et le bouton
disparaît. L'utilisateur voit exactement ce qu'il verrait si l'action avait abouti.

Ce n'est pas un affichage optimiste mal réconcilié : **il n'y a aucune requête à réconcilier**. La
notification reste non lue, la pastille du menu garde son compte, et un simple rechargement fait
revenir la ligne en bleu. Le seul chemin qui marque réellement une notification est le bouton
« Tout marquer comme lu », qui ne porte pas de `onclick` destructeur.

**FERMÉ au portage** (`v1.37.60`) : l'écran ne bouge **qu'après** la réponse du serveur, et le
compteur de la cloche vient de cette **même** réponse — deux appels peuvent se croiser, un seul ne le
peut pas. La ligne n'est d'ailleurs pas retirée : la faire disparaître empêcherait de vérifier ce
qu'on vient de faire. Un état affiché qui n'a pas été confirmé est un mensonge, et celui-ci était
indétectable — ni erreur, ni journal, ni trace réseau.

---

## E-109 — Un GET écrit, et sans le moindre jeton

`adm/api/notifications.php:26-27` n'appelle `checkCsrfToken()` que si la méthode est `POST` :

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkCsrfToken();
    …
}
```

Or l'action est lue dans `$_GET` **en premier** (`:23`, `$_GET['action'] ?? $_POST['action']`), et
`case 'read_all'` (`:107-110`) exécute son `UPDATE` sans rien exiger d'autre.

Mesuré depuis la page, avec la session réelle et **sans en-tête CSRF** :

```
GET /adm/api/notifications.php?action=read_all
→ 200  {"success":true,"updated":2}      non lues : 2 avant, 0 après
```

L'impact est modeste — on marque comme lues les notifications de la personne qui suit le lien — mais
la propriété violée ne l'est pas : **un GET ne doit rien écrire**, et c'est une règle que ce chantier
s'est déjà donnée. Un `<img src>` sur une page tierce suffit à le déclencher.

`read` et `delete` ne sont pas exploitables par la même voie, et il faut le dire : sur un GET, `$data`
n'existe pas et `$_POST['id']` non plus, donc `$id` vaut 0 et la route sort sur « id requis » avant
toute écriture. **C'est un accident de portée de variable qui les protège, pas une décision.**

**FERMÉ au portage** (`v1.37.60`) : chaque geste qui écrit est un `POST` sur sa propre route, et la
vérification de requête du cadre s'y applique. Le seul `GET` est le compteur, et il ne fait que lire.
Mesuré après portage : le même appel rend **405**.

---

## E-110 — Le correctif de diffusion ne couvre qu'une branche sur trois

`adm/api/notifications.php:120-124` porte un commentaire qui nomme le défaut avec précision :

> *Patch A01 : un simple utilisateur ne peut supprimer QUE ses propres notifications. Avant, le
> `OR user_id = 0` lui permettait de supprimer une notification broadcast (partagée par tous) →
> impact sur les autres.*

et `delete` scinde bien sur `$roleId >= 2`. **Ses deux jumeaux ne le font pas** :

| action | clause d'écriture | scindée sur le rôle ? |
|---|---|---|
| `delete` (`:125-130`) | `id = ? AND (user_id = ? OR user_id = 0)` **ou** `user_id = ?` | **oui** |
| `read` (`:93`) | `id = ? AND (user_id = ? OR user_id = 0)` | non |
| `read_all` (`:108`) | `(user_id = ? OR user_id = 0) AND read_at IS NULL` | non |

Et la lecture, elle, filtre : `$whereUser` ne rend les lignes `user_id = 0` qu'aux rôles ≥ 2
(`:33-36`). Un rôle 1 **écrit donc sur des lignes qu'il ne voit pas**.

Mesuré, les deux moitiés dans la même exécution :

```
rôle 1, page des notifications  → la diffusion d'épreuve n'apparaît PAS
rôle 1, POST action=read_all    → 200 {"success":true,"updated":1}
la diffusion est-elle passée lue ? → OUI
```

**Précondition, et elle compte** : la table ne portait **aucune** ligne `user_id = 0` au 2026-08-26.
Le trou est réel dans le code et à un `INSERT` d'être exploitable — ce n'est pas la même chose que de
dire qu'il l'est aujourd'hui. La suite pose sa propre diffusion pour l'exercer, et la retire.

**FERMÉ au portage** (`v1.37.60`) : `Notifications::portee()` est calculée **une fois** et les quatre
gestes s'y adossent — il ne peut plus y avoir de branche oubliée parce qu'il n'y a plus de branche.
Mesuré après portage : le `read_all` d'un rôle 1 ne touche pas la diffusion.

**Et le portage a failli reproduire le défaut sous une autre forme.** En lisant `user_id` là où la
session écrit `utilisateur_id`, la portée d'un rôle 1 devenait `user_id = 0` — **exactement les
lignes de diffusion**. Un identifiant illisible n'interdisait pas l'accès : il l'accordait. `portee()`
est désormais fail-closed sur `$userId <= 0`. Se méfier des valeurs sentinelles qui sont aussi des
valeurs réelles.

---

## E-111 — Quatre vocabulaires pour la colonne `type`, et les deux qui comptent ne se croisent pas

`notifications.type` est un `varchar(50)` sans contrainte. Quatre endroits en énumèrent les valeurs,
et ils ne s'accordent pas :

| source | valeurs |
|---|---|
| `update_notification_prefs.php:41-44` (`$allowedTypes`) | `cve_scan` `ssh_audit` `compliance_report` `security_alert` `backup_status` `update_status` |
| `notifications.php:46-53` (`$typeLabels`) | `cve_critical` `server_offline` `perm_granted` `perm_expired` `password_expiry` `info` |
| `menu.php` (icônes de la cloche) | mêmes six que la page |
| **les lignes réellement en base** | `cve_scan`, `security_alert` |

**L'intersection des deux premières est VIDE.** Mesurée, pas estimée. Toute notification que le
système de préférences peut produire retombe donc sur le repli `['Autre', 'bg-gray-100 …']`
(`notifications.php:113`) — et c'est bien ce que montre la capture : **trois lignes, trois pastilles
grises « Autre »**.

**CORRECTION du 2026-08-26, et elle change la décision de portage.** Ce document a d'abord écrit que
la page « ne peut colorier que des types que rien ne produit ». **C'est faux** : le backend produit
les douze, et le partage n'a rien d'arbitraire — il suit le CHEMIN D'ÉMISSION.

| chemin | honore les préférences ? | types émis |
|---|---|---|
| `notify()` / `notify_admins()` — `INSERT` direct (`backend/notify.py:26-66`) | **non** | `cve_critical` `server_offline` `perm_granted` `perm_expired` `password_expiry` |
| `notify_subscribed()` — filtre sur `notification_preferences` (`:109-142`) | **oui** | `cve_scan` `security_alert` `ssh_audit` |

Autrement dit : **la page nomme exactement les types qui arrivent SANS condition, et ne sait pas
nommer ceux pour lesquels on a réglé une préférence.** Et l'inverse est vrai aussi — cinq types ne
peuvent **pas** être coupés, puisqu'ils ne passent pas par les préférences ; la page de réglages
promet donc plus de contrôle qu'il n'en existe.

S'y ajoutent, sur la même page, deux défauts d'internationalisation :

- les six libellés de type sont en **français codé en dur** (`'CVE critique'`, `'Serveur offline'`…),
  comme le titre « Notifications », « Tout marquer comme lu » et « X non lue(s) sur Y total » ;
- **`<html lang="fr">` est écrit en dur** (`:57`), là où `adm/audit_log.php:122` écrit
  `<html lang="<?= getLang() ?>">`. La page est annoncée comme française à toute technologie
  d'assistance, quelle que soit la langue choisie.

**FERMÉ au portage** (`v1.37.60`), et mesuré sur la **même pastille** des deux côtés : le legacy rend
**« Autre »**, le portage rend **« Scan CVE »**.

**Une seule liste, et elle porte les DOUZE** — pas les six d'un côté. Un libellé par
type dans les deux langues, et un type inconnu s'affiche sous son **nom brut**, ce qui se
diagnostique, plutôt que sous « Autre », qui ne dit rien.

Ce qui ne se corrige PAS ici, et qu'il faut dire : les cinq types du chemin direct restent
inconfigurables tant que `notify()` ne consulte pas les préférences. Leur faire traverser
`notify_subscribed()` est une décision de comportement du backend — pas un détour de portage de
page. Le portage se borne à **ne plus les afficher comme « Autre »** et à ne pas laisser croire que
la page de réglages les gouverne.

---

## E-112 — `adm/` D3 : la politique de mot de passe est contournée par le seul chemin qui fixe le mot de passe **d'autrui**

Mesuré au clic le 2026-08-26 par `tests/e2e/go-adm-comptes.mjs`, sur un compte d'épreuve créé et
retiré par la suite — jamais sur un compte de test.

| exigence | libre-service (`profile.php:174-184`) | administrateur (`manage_roles.php:65-88`) |
|---|---|---|
| longueur minimale | **15** | **8** (`validateInputUsers`, `:48`) |
| minuscule, majuscule, chiffre, symbole | les quatre | **aucune** |
| non réutilisé (`password_history`) | oui | **non** |
| absent de HIBP | oui | **non** |
| écrit dans `password_history` | oui | **non** |

Tous les autres chemins du dépôt appellent `passwordPolicyValidateAll` — `profile.php`,
`adm/api/change_password.php`, `auth/reset_password.php`. **Le seul qui ne l'appelle pas est celui
par lequel un administrateur fixe le mot de passe de quelqu'un d'autre.**

Mesure : `password123` — onze caractères, sans majuscule ni symbole, connu de HIBP — est **refusé à
l'utilisateur pour lui-même** et **accepté à l'administrateur pour autrui**. Le haché en base change,
et `password_history` reste à **0 ligne avant, 0 après**.

Le trou d'historique a une conséquence propre : la vérification de non-réutilisation lit
`password_history`, donc un mot de passe posé par un administrateur peut être **reposé
immédiatement** par l'utilisateur, la politique n'en ayant aucune trace.

**LA MESURE DÉDOUANE SUR LE COÛT, et cela se dit aussi nettement qu'une accusation.**
`manage_roles.php:85` emploie `password_hash($p, PASSWORD_DEFAULT)` là où tout le reste emploie
`PASSWORD_BCRYPT` avec `['cost' => BCRYPT_COST]`. Mesuré sur ce PHP : les deux rendent **`$2y$12$`**.
Le haché **n'est pas plus faible aujourd'hui**. Ce qui reste vrai : `BCRYPT_COST` se lit dans une
variable d'environnement (`password_policy.php:28`, défaut 12). Si l'exploitant la relève, tous les
chemins suivent **sauf celui-là**. Le défaut est latent, et c'est l'exploitant qui l'armerait.

**FERMÉ au portage** (`v1.37.61`) : `Comptes::definitMotDePasse()` est le seul point d'écriture, et il
applique la politique **et** écrit l'historique quel que soit l'auteur. Le coût est lu au même endroit
que le legacy (`config('rootwarden.bcrypt_cost')` ← `BCRYPT_COST`), donc les deux portails restent
d'accord et un compte reste connectable des deux côtés.

---

## E-113 — Le mot de passe généré est rendu en clair, et `strip_tags` l'ampute au passage

`manage_roles.php:93` compose le message de succès en y plaçant le mot de passe généré :

```php
$success = … . t('roles.generated_password') . " : <strong>$new_password</strong>";
```

Mesuré : après une réinitialisation à champ vide, la page rend une chaîne de **10 caractères**
mêlant minuscules, majuscules et chiffres dans un `<strong>` — le secret, en clair. Il part dans
l'historique du navigateur et dans tout cache intermédiaire.

**Et il est corrompu en chemin.** `manage_roles.php:192` réinjecte ce même message dans un script :

```php
<script>… toast(<?= json_encode(strip_tags($success)) ?>, 'success', 8000);</script>
```

Or l'alphabet de `generateSecurePassword` (`crypto.php:253`) contient `<` et `>`. `strip_tags`
supprime alors tout ce qui ressemble à une balise **à l'intérieur du mot de passe**. Mesuré :

| mot de passe généré | ce que la bulle affiche |
|---|---|
| `ab<cd>ef12` | `abef12` |
| `x</script>y` | `xy` |
| `a<b` | `a` |

L'administrateur recopie donc une chaîne qui **n'est pas** le mot de passe enregistré, et le compte
devient inaccessible sans qu'aucun message ne le dise. La probabilité n'est pas négligeable : sur
un alphabet de 90 caractères et une longueur de 10, au moins un `<` apparaît environ une fois sur
neuf.

**FERMÉ au portage** (`v1.37.61`) : le mot de passe généré arrive dans la **réponse du geste** qui l'a
demandé, s'affiche une fois, et la suite mesure qu'il **ne survit pas au rechargement** de la page.
L'alphabet du générateur exclut les caractères de balisage, et le tirage garantit une occurrence de
chaque classe — un mot de passe généré ne peut pas être refusé par notre propre politique.

---

## E-114 — Une apostrophe de traduction désactive DEUX confirmations d'action destructrice — en français seulement

Le défaut le plus surprenant de D3, trouvé parce que la suite **assertait l'absence d'erreur
JavaScript** et en a relevé **deux**.

`manage_roles.php` place des chaînes traduites dans des littéraux JavaScript **entre apostrophes** :

```php
<button type="submit" name="reset_2fa" onclick="return confirm('<?= t('roles.confirm_reset_2fa', …) ?>')">
<button                                onclick="if(confirm('<?= t('roles.confirm_delete_user', …) ?>')) …">
```

Et deux des trois chaînes françaises portent une apostrophe :

| clé | français | anglais |
|---|---|---|
| `roles.confirm_reset_password` | `Reinitialiser le mot de passe de ":name" ?` | — |
| `roles.confirm_reset_2fa` | `… ? **L'**utilisateur devra reconfigurer …` | `… ? The user will need …` |
| `roles.confirm_delete_user` | `Supprimer **l'**utilisateur ":name" ? …` | `Delete user ":name"? …` |

L'apostrophe **ferme le littéral** : l'attribut `onclick` ne s'analyse pas.
`SyntaxError: Invalid or unexpected token`, **deux fois** — un par chaîne. `addslashes` est appliqué
au **nom**, jamais à la phrase traduite qui l'entoure.

**Ce que cela coûte — et une moitié de ce constat a été CORRIGÉE le 2026-08-26, après mesure.**

Le premier jet de cet écart annonçait deux actions destructrices partant sans confirmation. La mesure
des frontières de formulaire en dit autre chose, et il faut le dire aussi nettement que l'accusation :

| bouton | forme réelle | ce qui se passe en français |
|---|---|---|
| **Réinitialiser la 2FA** (`:260`) | `type="submit"`, **dans** le `<form>` ouvert en `:257` | l'`onclick` est mort, **le formulaire part sans confirmation** — le défaut est réel |
| **Supprimer l'utilisateur** (`:264`) | aucun `type`, et **hors de tout formulaire** — le `<form>` précédent se ferme en `:261` | l'`onclick` est mort, et il n'y a **rien pour prendre le relais** : le bouton est **totalement inerte** |

Le second n'est donc **pas** une action qui échappe à sa garde : c'est un bouton mort. On clique, rien
ne se passe, et aucun message ne le dit. C'est un défaut d'ergonomie, pas de sécurité.

**Et la suppression qui MARCHE est ailleurs, et elle est gardée.** `manage_users.php:286` appelle
`deleteUser()` de `js/admin.js:28`, qui pose son propre `confirm()` par `__('admin_confirm_delete_user')`
— une recherche dans un catalogue JavaScript, où l'apostrophe est une **donnée** et non du code.
Mesuré au clic : la boîte s'affiche bien, avec le nom du compte.

Reste donc **un** défaut de sécurité, et il est net : la réinitialisation du second facteur — qui
verrouille quelqu'un hors de son compte jusqu'à un nouvel enrôlement — part sans confirmation. **Et
seulement en français** : les chaînes anglaises n'ont pas d'apostrophe. La protection d'une action
irréversible dépend de la langue de l'interface.

Le troisième bouton, « Réinitialiser le mot de passe », n'a pas d'apostrophe dans sa chaîne : sa
confirmation fonctionne — et c'est celui que la suite a pu cliquer.

**La leçon de la correction** : deux `onclick` cassés de la même façon ne produisent pas le même
effet. Ce qui décide, c'est ce qui prend le relais quand le gestionnaire meurt — un `type="submit"`
dans un formulaire, ou rien du tout. **Lire la forme de l'élément, pas seulement son gestionnaire.**

**CORRECTION DU 2026-08-26 — LA CAUSE PRINCIPALE N'EST PAS L'APOSTROPHE, ET AUCUNE LANGUE N'EST
ÉPARGNÉE.** Le sous-lot D6a a trouvé le même montage dans `manage_servers.php` et l'a mesuré **au
navigateur** : l'attribut rendu vaut `return confirm('Supprimer le serveur ` — tronqué au 46e
caractère sur 99. Ce n'est pas l'apostrophe qui coupe, c'est le **guillemet double** de la
traduction, qui ferme l'attribut HTML avant que le littéral JavaScript n'entre en jeu.

Or les trois chaînes de `manage_roles.php` en portent deux chacune, **en français comme en anglais** :

| clé | guillemets | apostrophes | attribut coupé au |
|---|---|---|---|
| `roles.confirm_reset_password` | 2 | 0 | **58** / 71 |
| `roles.confirm_reset_2fa` | 2 | 1 | **49** / 117 |
| `roles.confirm_delete_user` | 2 | 1 | **49** / 93 |

Deux conclusions de cet écart sont donc à reprendre :

- **« seulement en français » est faux.** Les catalogues anglais portent le même guillemet ; la
  protection ne dépend pas de la langue, elle est absente dans les deux ;
- **« le troisième bouton fonctionne » est faux.** `confirm_reset_password` n'a pas d'apostrophe,
  mais ses guillemets coupent son attribut au 58e caractère. Sa confirmation ne s'exécute pas
  davantage que les deux autres — et il est `type="submit"` dans un formulaire, donc la
  réinitialisation de mot de passe part elle aussi sans boîte.

**MESURÉ AU NAVIGATEUR le 2026-08-26**, et le tableau est plus large que prévu.
`go-adm-permissions` demande désormais au moteur si chaque attribut **s'analyse** — `new Function(code)`
compile sans exécuter, donc aucune boîte ne s'ouvre et aucun formulaire ne part. Un décompte
d'apostrophes se laisserait tromper par un `\'` ; le compilateur non.

Sur `/adm/admin_page.php`, **33 boutons portent un `confirm()`, et les 33 échouent à l'analyse** :

| bouton | occurrences | forme | erreur du moteur |
|---|---|---|---|
| `change_password` | 10 | `submit`, **dans** un form | `Invalid or unexpected token` |
| `reset_2fa` | 10 | `submit`, **dans** un form | `Invalid or unexpected token` |
| suppression de compte | 10 | sans `type`, **hors** form | `missing ) after argument list` |
| `delete_server` | 3 | `submit`, **dans** un form | `Invalid or unexpected token` |

**23 des 33 sont des `submit` dans un formulaire** : pour ceux-là, le gestionnaire mort ne retient
rien et le geste part sans qu'aucune boîte n'ait paru. Les dix autres sont inertes.

Le code reçu par le navigateur est coupé exactement là où le guillemet ouvre :
`return confirm('Reinitialiser le mot de passe de `.

Cette mesure est celle que le premier jet de cet écart avait sautée — et c'est elle qui lui a coûté
ses deux conclusions.

**La leçon, corrigée** : chercher le délimiteur **le plus extérieur**. On a cherché ce qui cassait le
littéral JavaScript ; ce qui cassait était l'attribut HTML qui le contient, un niveau au-dessus, et
sur un caractère qu'aucune des deux langues n'évitait.

**FERMÉ au portage** (`v1.37.61`) : aucune boîte native, donc le problème disparaît **par
construction** — le texte traduit est posé par `textContent`, où une apostrophe est un caractère et
non un délimiteur. Le panneau de décision **nomme** le compte visé et dit ce que le geste engage, ce
qu'un `confirm()` ne peut faire ni l'un ni l'autre. La suite assertait « aucune erreur JavaScript » :
le legacy en porte deux, le portage aucune.

---

## E-115 — Trois chemins écrivent `users.ssh_key`, et ils s'accordent sur rien

| chemin | valide la clé | journalise | forme stockée |
|---|---|---|---|
| `manage_users.php:81` (formulaire de la page) | non — `validateInputSSH` le **dit** : « on ne fait pas de regex stricte ici » | à la création seulement | **échappée en HTML** (`htmlspecialchars`) |
| `api/update_user_status.php:50` | non | **oui** (`audit_log`) | brute |
| `api/update_user.php:83` | non | **non** — zéro appel à `audit_log` dans tout le fichier | brute |

Deux conséquences distinctes.

**Un trou dans la piste d'audit qui dépend du point d'entrée.** Remplacer la clé SSH de quelqu'un par
`update_user_status.php` laisse une ligne dans `user_logs` ; le faire par `update_user.php` n'en
laisse **aucune**. Le sous-lot D1 vient de rendre cette chaîne d'audit vérifiable : elle vérifiera
parfaitement un journal auquel il manque des entrées.

**Une clé stockée sous deux formes selon l'écrivain.** `validateInputSSH` applique
`htmlspecialchars` — un échappement d'AFFICHAGE, appliqué à l'ÉCRITURE. Une clé dont le commentaire
contient `&`, `<` ou `'` est donc stockée transformée par ce chemin et brute par les deux autres.
C'est cette colonne que le module `ssh/` déploie dans `authorized_keys` sur les machines.

**Précondition mesurée, et il faut la dire** : au 2026-08-26, **aucun compte ne porte de clé SSH** et
aucune valeur stockée ne contient d'entité HTML. Le défaut est réel dans le code et sans objet en
base — il est à une clé collée d'exister.

**FERMÉ au portage** (`v1.37.61`) : `Comptes::definitCleSsh()` est le seul écrivain. Il vérifie la
forme — algorithme dans une **liste fermée**, corps en base64, une seule ligne — ce qui écarte au
passage les préfixes d'options d'`authorized_keys` (`command=`, `from=`, `no-pty`), qui changent le
sens de la ligne déployée. La valeur est stockée **telle quelle** ; l'échappement appartient au rendu.
Et chaque écriture journalise, en reprenant la chaîne de hachage que D1 vérifie.

---

## E-116 — `adm/` D4 : supprimer un compte EFFACE son journal d'audit, et rompt la chaîne que D1 vient de rendre vérifiable

Mesuré dans `information_schema` le 2026-08-26 — une mesure de **structure**, qui n'écrit rien et ne
dépend d'aucune session :

| | |
|---|---|
| clés étrangères pointant vers `users` | **34** |
| dont `ON DELETE CASCADE` | **12** |
| règle de `user_logs.user_id` | **CASCADE** |

Supprimer un compte efface donc **tout son journal d'audit**. Et le sous-lot D1 vient d'établir que ce
journal est une **chaîne** : chaque ligne porte le `self_hash` de la précédente dans son `prev_hash`.
Retirer des lignes du **milieu** de cette chaîne la rompt — les lignes suivantes pointent vers une
empreinte qui n'existe plus, et « Vérifier l'intégrité » signalera une incohérence sans que rien ne
dise qu'une suppression l'a causée.

Ce n'est pas théorique : `delete_user.php:102` écrit sa ligne d'audit **avant** le `DELETE`. Cette
ligne appartient à l'auteur du geste, donc elle survit — et elle se retrouve **après** les lignes de
la cible qui, elles, disparaissent. Une suppression place donc mécaniquement un trou au milieu.

**Et la cascade manuelle du fichier est du code mort.** `delete_user.php:104-113` supprime `users`,
puis `user_machine_access`, puis `permissions` — mais les deux dernières sont **déjà** en CASCADE :
elles sont parties avec la première ligne. Le docblock du fichier s'inquiète pourtant de l'inverse :
*« la suppression du compte dans `users` peut échouer si des contraintes de clé étrangère sont actives
sur les tables enfants ; dans ce cas, supprimer d'abord `user_machine_access` et `permissions` »*.
L'auteur a vu un risque de `RESTRICT` là où le schéma porte `CASCADE`, et a écrit une note au lieu de
lire la contrainte.

**CE DÉFAUT N'A PAS ÉTÉ PROVOQUÉ, ET C'EST DÉLIBÉRÉ.** Rompre la chaîne d'audit est irréversible sur
un artefact que l'exploitant suit. La suite le contourne : elle n'agit que sur un compte **fraîchement
créé**, dont `user_logs` est vide — `audit_log()` écrit toujours avec l'identifiant de l'**auteur**,
jamais de la cible — et elle **vérifie cette précondition avant de cliquer**, fail-closed. Le défaut
est établi par le schéma et par la lecture ; sa démonstration demande un arbitrage.

**FERMÉ au portage** (`v1.37.62`) : la suppression d'un compte qui porte un journal est **refusée**
(409), et la page demande l'état **avant** d'ouvrir son panneau — elle dit combien de lignes seraient
emportées et propose l'anonymisation à la place. Un compte sans journal reste supprimable, derrière
une confirmation qui n'accepte que le **nom exact** et une **re-authentification**.

---

## E-117 — Le geste RGPD correct existe, il est commenté, il est gardé — et **aucun élément de l'interface ne l'appelle**

`adm/api/anonymize_user.php` (141 lignes) fait exactement ce que E-116 réclame :

- il **efface les données personnelles** par un `UPDATE` (nom, courriel, société, clé SSH) ;
- il supprime sessions, jetons, préférences, permissions et accès machines ;
- et il porte, ligne 117, ce commentaire : *« ← Les user_logs et login_history sont CONSERVES pour
  tracabilite legale »* ;
- il journalise l'opération sous le préfixe `[rgpd]`.

Il est gardé — rôle 3, méthode POST, jeton CSRF, step-up `anonymize_user` — et protège le dernier
super-administrateur actif.

**Il n'a aucun appelant.** Mesuré depuis la page elle-même : le mot `anonymize` n'apparaît nulle part
dans le HTML rendu de `admin_page.php`, alors que `deleteUser` s'y trouve. `documentation.php:890`
l'annonce pourtant comme le « soft-delete RGPD art. 17 ».

Et le verrou est double, comme pour les autres gestes gardés par un step-up : la marque
`_step_up_anonymize_user` ne s'obtient que par le modal, que seule une réponse `403 step_up_required`
à un `fetch` ouvre — et rien n'émet ce `fetch`.

**Le résumé de D4 tient dans une phrase** : le geste sûr, pensé et documenté, est inatteignable ; le
geste destructeur est à un clic, et il emporte la traçabilité que la plateforme existe pour garantir.

**FERMÉ au portage** (`v1.37.62`) : les deux gestes sont offerts côte à côte, et l'anonymisation est
proposée dès que le compte porte un journal. `Comptes::anonymise()` efface les données personnelles,
retire sessions, jetons, préférences, permissions et accès machines — et **ne touche ni `user_logs`
ni `login_history`**, ce qui est tout l'objet du geste.

---

## E-118 — `adm/` D5 : trois listes pour les mêmes droits, et deux permissions qu'on ne peut pas reprendre

Mesuré le 2026-08-26 en croisant le schéma, le formulaire de création et la liste blanche du point
d'API :

| | |
|---|---|
| colonnes `can_*` de `permissions` | **18** |
| posables **à la création** (`manage_users.php:116`) | **14** |
| basculables **ensuite** (`update_permissions.php:101`) | **16** |

Les écarts ne se compensent pas — ils se croisent :

| permission | créable | basculable | ce que cela donne |
|---|---|---|---|
| `can_manage_fail2ban` | **oui** | **non** | on l'accorde, et **on ne peut plus la retirer** par l'interface |
| `can_manage_bashrc`, `can_manage_graylog`, `can_manage_wazuh` | non | oui | absentes à la création, réglables après — sans conséquence |
| `can_manage_api_keys` | **non** | **non** | **inatteignable dans les deux sens** |

**Et les deux trous portent sur des droits qui gardent de vraies pages.**
`can_manage_fail2ban` garde `fail2ban/index.php:11`, son entrée de menu du legacy
(`menu.php:86,237`) **et** celle du portage (`Navigation.php:36`).
`can_manage_api_keys` garde `adm/api_keys.php:20` — page dont l'accès n'est donc possible que par le
rôle 3, qui contourne toute permission. Ce n'est pas une décision : c'est un oubli de liste, et
`documentation.php:272` présente pourtant `can_manage_fail2ban` comme une permission « si accordée ».

**Ce n'est pas théorique** : mesuré en base, **deux** comptes portent `can_manage_fail2ban` et **un**
porte `can_manage_api_keys`. Ils les ont reçues à la création ou par import CSV
(`import_csv.php:168`). Il y a donc bien, aujourd'hui, des droits accordés que l'interface ne sait
pas reprendre — les retirer demande un `UPDATE` à la main.

**FERMÉ au portage** (`v1.37.63`) : `Permissions::toutes()` lit la liste dans `information_schema`.
Une colonne ajoutée devient réglable, une colonne retirée disparaît partout à la fois — il ne peut
plus y avoir trois listes, parce qu'il n'y en a plus qu'une source. Les dix-huit permissions sont
nommées en FR et en EN, y compris les deux que le legacy laissait dehors.

---

## E-119 — La bascule de permission émet sa requête, reçoit un refus, et **ne montre rien**

L'inventaire l'avait établi par lecture ; le clic le confirme. Mesuré sur un compte d'épreuve :

```
clic sur la case  → POST /adm/api/update_permissions.php
réponse           → 403 {"success":false,"step_up_required":true,"action":"update_permissions", …}
can_scan_cve      → 0 avant, 0 après
à l'écran         → rien
```

Trois pièces, chacune correcte prise isolément, forment ensemble une impasse :

1. `update_permissions.php:60` exige un step-up — c'est **bien** ;
2. le modal qui permettrait de le fournir est une surcouche de **`window.fetch`**
   (`js/utils.js:38-49`) ;
3. la case est déclenchée par **htmx**, qui n'emploie que `XMLHttpRequest` — zéro occurrence de
   `fetch` dans `js/htmx.min.js`, vérifié.

La surcouche ne voit donc jamais la requête, le modal ne s'ouvre pas, et **aucun geste d'interface ne
permet d'obtenir la marque `_step_up_update_permissions`**. htmx, de son côté, traite `[45]..` en
`swap:false, error:true` par défaut, et le legacy n'a aucun écouteur `htmx:responseError` : rien n'est
remplacé, rien n'est annoncé.

**Résultat : pour un rôle 3, cocher ou décocher une permission ne fait rien du tout, en silence.** La
seule façon d'attribuer une permission aujourd'hui est de créer le compte avec, ou de passer par un
import CSV.

C'est la même famille que E-108 — un écran qui n'a pas de raison de bouger et un serveur qui n'a rien
entendu — mais prise par l'autre bout : ici la requête part **et** le refus est correct ; c'est le
chemin pour y répondre qui n'existe pas.

**FERMÉ au portage** (`v1.37.63`) : la garde est la **même**, et le panneau de re-authentification
**en page** écrit pour D4 la rend franchissable. Mesuré : refus annoncé, panneau ouvert, code saisi,
et `can_scan_cve` passe de `null` à **1**. La case, elle, ne bouge qu'après la réponse — une case
cochée qui ne l'est pas en base est un mensonge.

---

## E-120 — `adm/` D6a : un fragment MORT, toujours servi, et gardé sans la permission de sa page hôte

`legacy/adm/includes/manage_servers_table.php` (352 lignes) n'a **qu'une** référence dans tout le
dépôt : le `fetch()` de `manage_servers.php:709`. Et cette référence est **à l'intérieur d'un bloc
commenté** — `/*` en `:661`, `*/` en `:923`, soit **263 lignes sur 939**. Le fichier est donc mort
par navigation : aucun clic, aucune page ne l'appelle. Mesuré : `0` requête vers lui au chargement.

Il reste pourtant servi par Apache, et sa garde est conditionnelle :

```php
if (!function_exists('checkAuth')) {
    …
    checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
}
```

Le réflexe est bon — inclus depuis la page, la garde du parent suffit ; appelé en direct, il se garde
lui-même. Mais il appelle `checkAuth` et **PAS** `checkPermission('can_admin_portal')`, que sa page
hôte `admin_page.php` exige.

**Mesuré au navigateur, avec `rw-test-admin` (rôle 2, sans `can_admin_portal`)** :

| cible | statut |
|---|---|
| `/adm/admin_page.php` | **403** |
| `/adm/includes/manage_servers_table.php` | **200**, tableau complet rendu |

Un compte refusé sur la page obtient donc l'inventaire du parc en visant le fragment : noms,
adresses, ports, comptes SSH, environnement, criticité. C'est « la garde est sur la PAGE, pas sur la
REQUÊTE » — sixième occurrence — **sur du code mort qui répond encore**.

**CE QU'IL N'EXPOSE PAS, et il faut le dire aussi nettement que l'accusation.** Les colonnes « Mot de
Passe » et « Mot de Passe Root » sont des `<input type="password">` **vides**, portant « Laisser vide
pour ne pas modifier ». Mesure : **6 champs rendus, 0 rempli**. Aucun secret stocké n'est imprimé.
C'est une divulgation d'inventaire, pas de justificatifs.

**Le chemin d'ÉCRITURE est aussi ouvert.** `server_actions.php` — le point d'entrée des étiquettes,
notes, cycle de vie et test de connexion — porte `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` en `:29`
et **zéro** `checkPermission`. Il sera caractérisé en D6b ; il est nommé ici parce qu'il change la
gravité : ce n'est pas seulement une lecture qui fuit.

**FERMÉ au portage** (`v1.37.65`) : il n'y a **pas de fragment séparé**. `/serveurs` rend son tableau
elle-même, sous `role:2` + `perm:can_admin_portal` — la garde de la page hôte, appliquée une fois,
au seul endroit qui répond. Il n'y a plus deux portes à garder, donc plus de porte oubliée.

---

## E-121 — Un GUILLEMET de traduction tronque l'attribut, et le retrait d'une machine part sans confirmation

`manage_servers.php:495` rend le bouton de suppression ainsi :

```php
onclick="return confirm('<?= t('servers.confirm_delete',
         ['name' => htmlspecialchars(addslashes($server['name']))]) ?>')"
```

`addslashes` protège l'apostrophe **du nom**. Rien ne protège les **guillemets doubles** que porte la
traduction elle-même :

| langue | chaîne | guillemets |
|---|---|---|
| fr | `Supprimer le serveur ":name" ? Cette action est irreversible.` | **2** |
| en | `Delete server ":name"? This action cannot be undone.` | **2** |

Le premier guillemet **ferme l'attribut HTML**. Mesuré au navigateur — `getAttribute('onclick')` sur
la page réelle :

```
return confirm('Supprimer le serveur
```

Une chaîne non terminée : `SyntaxError: Invalid or unexpected token`, le gestionnaire ne s'attache
pas. Et le bouton est `type="submit"` **dans** le formulaire — donc, suivant la leçon d'E-114, il n'y
a rien pour prendre le relais du gestionnaire mort : **le formulaire part, et la machine est retirée
du parc sans qu'aucune boîte n'ait paru.** La suite le mesure : machine créée, puis retirée, `0`
ligne restante, et une erreur JavaScript relevée sur la page.

**CETTE MESURE CORRIGE LA PORTÉE D'E-114**, qui attribuait le défaut à l'**apostrophe** et concluait
« seulement en français ». Les deux catalogues portent le guillemet : **aucune langue n'est
épargnée**. L'apostrophe est une seconde cause, redondante, sur deux chaînes de `manage_roles.php` —
pas la cause principale. Voir la note de correction ajoutée à E-114, **confirmée au navigateur le
2026-08-26** : sur `/adm/admin_page.php`, 33 boutons portent un `confirm()` et les 33 échouent à
l'analyse, dont 23 `submit` dans un formulaire. Les trois `delete_server` de cet écart en font
partie — la page d'administration rend le balisage de ses trois onglets, y compris masqué.

**FERMÉ au portage** (`v1.37.65`) : aucune boîte native. Le premier clic ouvre un panneau qui **nomme
la machine** et dit ce que le retrait engage — et surtout ce qu'il n'engage pas : la machine
elle-même n'est pas touchée, rien n'y est modifié, aucun accès n'y est révoqué. Le texte est posé par
`textContent`, où guillemet et apostrophe sont des caractères et non des délimiteurs. La suite
vérifie en plus que **l'ouverture du panneau n'écrit rien** : `1` ligne encore présente après le
premier clic.

---

## E-122 — 68 lignes de recherche, filtres, tri et pagination : inatteignables, **et** écrasées

`manage_servers.php:218-285` construit une recherche sur trois colonnes, trois filtres, un tri validé
par liste blanche et une pagination. Ce code est mort **deux fois plutôt qu'une**, et les deux causes
sont indépendantes :

1. **aucun contrôle de l'interface n'émet ses paramètres.** Mesure du 2026-08-26 : pas un
   `?search=`, `?environment=`, `?network=`, `?criticality=`, `?sort=` ni `?page=` dans la partie
   vivante du fichier. Les quatre `name="environment"` et `name="criticality"` relevés appartiennent
   aux formulaires d'**ajout** et de **modification**, pas à un filtre ;
2. **et son résultat est écrasé.** `$all_servers` reçoit le jeu paginé en `:285`, puis un second
   `query()` **sans `WHERE` ni `LIMIT`** le remplace en `:296`. `$totalPages` est affecté une fois et
   n'est lu nulle part.

Ce qui filtre réellement est un `oninput` côté navigateur, sur les cartes déjà rendues — et il ne
regarde que le **nom**, là où la recherche morte visait nom, adresse **et** compte SSH.

**Ce n'est donc pas une fonction cassée : c'est du code mort qui ressemble à une fonction.** La
distinction décide de la conduite à tenir — il n'y a rien à réparer, il y a quelque chose à ne pas
porter.

**NON PORTÉ, délibérément** (`v1.37.65`). Porter du code mort, ce n'est plus migrer, c'est concevoir.
`/serveurs` garde le comportement **vivant** — rendre le parc entier, filtrer à l'affichage — avec une
seule différence, assumée : le filtre porte sur les **trois** champs que la recherche morte visait, et
qui sont tous les trois affichés dans l'en-tête de la carte. Filtrer sur ce qu'on ne voit pas ferait
disparaître des lignes sans raison lisible.

---

## E-123 — Le garde SSRF annonce le refus du multicast, et ne le vérifie pas

`manage_servers.php:55-72` porte un commentaire de dix lignes, ajouté par le correctif A10-01, qui
énumère ce que la validation d'adresse refuse :

> refuse loopback (127/8), link-local (169.254/16 = AWS/Azure metadata), 0.0.0.0/8, **multicast
> (224/4)** et IPv6 ::1/loopback

Les sept conditions de `$isLoopbackOrReserved` testent `127.`, `169.254.`, `0.`, `::1`, `fe80:`, `::`
et `0:0:0:0:0:0:0:0`. **Aucune ne teste le multicast.** `224.0.0.1` traverse la validation.

C'est le motif « l'en-tête qui ment » — cinquième occurrence relevée — et la raison pour laquelle il
dure : une relecture d'en-tête le **confirme**. Le commentaire dit vrai sur cinq points et faux sur
un ; rien ne distingue les six à l'œil.

**Portée réelle** : faible en pratique — une adresse multicast ne désigne pas une cible SSH, et une
tentative de connexion n'aboutit pas. Ce qui est relevé, c'est l'écart entre ce qui est **annoncé**
et ce qui est **appliqué**, sur une validation dont c'est tout le métier.

**FERMÉ au portage** (`v1.37.65`), puis **REFAIT** (`v1.37.68`) — et la deuxième version est la bonne.

Le premier jet appliquait bien les huit conditions, mais **sur des préfixes de chaîne**, comme le
legacy. Il en héritait donc l'angle mort, mesuré après relecture croisée : `::ffff:224.0.0.1` passait.
Voir E-129, qui est la suite de cet écart et vaut pour les deux portails.

`App\Services\Serveurs::valideIp()` réduit désormais l'adresse à sa forme **binaire** par
`inet_pton`, ramène les notations mappée (`::ffff:a.b.c.d`) et compatible (`::a.b.c.d`) à leur IPv4,
puis compare des **octets**. Une notation nouvelle ne peut plus contourner la règle, parce que la
règle ne regarde plus la notation. Dix-huit cas mesurés, zéro écart.

---

## E-124 — La légende des environnements annonce une valeur que le formulaire refuse, et tait celle qu'il offre

Vu **à l'image**, pas dans le code. La légende de l'onglet Serveurs affiche quatre pastilles :

```
● PROD   ● DEV   ● TEST   ● PREPROD
```

La liste fermée de `validateInput()` est `['PROD', 'DEV', 'TEST', 'OTHER']`, et les quatre `<option>`
du formulaire sont les mêmes. Donc :

- **PREPROD est annoncé et impossible** — aucun formulaire ne peut produire cette valeur, et la
  validation la refuserait ;
- **OTHER est offert et tu** — c'est la quatrième option réelle du menu déroulant, absente de la
  légende.

Une légende sert à lire un code couleur. Celle-ci décrit un parc qui ne peut pas exister.

**FERMÉ au portage** (`v1.37.65`) : il n'y a pas de légende séparée à tenir à jour, parce que
l'environnement est écrit **en toutes lettres** sur chaque machine (`PROD`, `DEV`, `TEST`, `Autre`).
La liste des valeurs vient de `Serveurs::ENVIRONNEMENTS`, la même constante que le formulaire et que
la validation : une valeur ajoutée apparaît partout, une valeur retirée disparaît partout. Une
légende recopiée à la main ne peut pas ne pas diverger — celle-ci a divergé.

---

## E-125 — `adm/` D6b : les quatre gestes vivants d'étiquettes et de notes sont INERTES

Quatre pièces, toutes correctes, et une liste incomplète. Le clic part, le serveur répond
`{"success":false,"message":"Token CSRF invalide"}`, **rien n'est jamais écrit** — et la mesure a été
faite au navigateur, en écoutant la réponse, parce que « aucune ligne en base » a trois causes
possibles qui ne se corrigent pas de la même façon.

| pièce | état |
|---|---|
| `admin_page.php:103` rend `<meta name="csrf-token">` | correct |
| `menu.php:267` charge `js/utils.js` | correct |
| `utils.js:19` enrobe `window.fetch` et pose `X-CSRF-TOKEN` | correct |
| `utils.js:22` — **mais seulement si l'URL contient `api_proxy.php`, `/adm/api/` ou `/auth/`** | la liste |

Les quatre `fetch` d'étiquettes et de notes visent `/adm/includes/server_actions.php`, qui n'appartient
à **aucune** des trois familles. Le jeton n'est donc jamais joint, et le point d'action — qui le
vérifie correctement — **refuse sa propre interface**.

Quatrième occurrence du motif « trois pièces correctes qui forment une impasse » (E-119, E-117, E-114).
Ici il y en a quatre, et ce qui manque tient dans une entrée de liste.

**ET LE CONTRASTE EST LE VRAI SUJET.** Ce même contrôle CSRF ne fait rien contre une requête forgée
depuis le portail : n'importe quel compte authentifié lit le jeton dans un champ caché de
`profile.php`. Mesuré. **Le garde tient dehors l'interface légitime et laisse entrer la requête
forgée** — ce qui est exactement l'inverse de son objet.

**FERMÉ au portage** (`v1.37.67`) : les quatre gestes sont des **formulaires**, pas des `fetch`.
`@csrf` pose le champ, le cadre le vérifie, et le geste fonctionne **sans une ligne de JavaScript**. Il
n'y a plus de liste d'URL à tenir à jour, donc plus d'entrée à y oublier. Le legacy rechargeait la page
après chaque succès (`location.reload()`) : le rendu est le même, pour une pièce mobile en moins.

---

## E-126 — `server_actions.php` ÉCRIT pour un compte refusé sur la page qui l'héberge

Même défaut qu'E-120, sur le chemin d'ÉCRITURE, et cette fois la conséquence n'est pas une lecture.

`server_actions.php:29` appelle `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` et **zéro
`checkPermission`**. Sa page hôte `admin_page.php` exige `can_admin_portal`.

**Mesuré au navigateur**, avec `rw-test-admin` (rôle 2, sans la permission) :

| étape | résultat |
|---|---|
| `/adm/admin_page.php` | **403** |
| jeton CSRF lu sur `/profile.php` | obtenu, 64 caractères |
| `POST` `add_tag` sur `server_actions.php` | **200** `{"success":true,"message":"Tag ajoute"}` |
| lignes réellement écrites dans `machine_tags` | **1** |

La propriété mesurée est **l'écriture**, pas le statut : un 200 portant `success:false` ne serait pas un
défaut. Une ligne écrite par un compte refusé sur la page en est un.

**FERMÉ au portage** (`v1.37.67`) : les quatre gestes sont des routes portant `role:2` +
`perm:can_admin_portal` — la garde de la page, appliquée à chaque geste. Il n'y a pas de point d'action
séparé à garder à part.

---

## E-127 — Le correctif SSRF A10-01 n'a été appliqué qu'à celui des deux chemins d'écriture qu'un clic emprunte

`manage_servers.php` et `server_actions.php` portent **chacun leur copie** de `validateInput()`. Celle
de la première porte le correctif A10-01, sur dix lignes de commentaire qui en nomment la cible :

> empêcher un admin compromis d'insérer 169.254.169.254 pour exfiltrer les credentials cloud

Celle de la seconde tient en une ligne :

```php
case 'ip':
    return filter_var($data, FILTER_VALIDATE_IP) ? $data : false;
```

**Aucun garde.** Mesuré au navigateur, par une requête forgée depuis la page — `add_server` de
`server_actions.php` n'a **aucun appelant vivant**, ses trois `fetch` sont dans le bloc commenté, donc
aucun clic ne peut l'atteindre :

```
200 {"success":true,"message":"Serveur ajouté avec succès.","server_id":"12"}
machine créée, ip = 169.254.169.254
```

La ligne est retirée dans la seconde qui suit, sans attendre le `finally` : une adresse de métadonnées
en base est précisément ce que le correctif cherche à empêcher.

**Sixième occurrence du motif « à moitié corrigé »**, et la plus conséquente : il ne s'agit pas d'un
oubli d'échappement dans une branche jumelle, mais d'un **correctif de sécurité** appliqué à un seul
des deux chemins — celui qu'on regarde, parce que c'est celui qu'un clic emprunte.

**Préconditions, et il faut les dire** : il faut un compte authentifié de rôle ≥ 2 et un jeton CSRF —
que `profile.php` donne à tout compte authentifié. Il ne faut **pas** `can_admin_portal` (E-126). Le
trou est donc atteignable par tout compte d'administration du portail, y compris ceux à qui la page
des serveurs est refusée.

**ET LA COPIE « DURCIE » NE TIENT PAS NON PLUS** — relecture croisée du 2026-08-26, puis mesure au
clic. Le correctif n'est pas seulement absent d'un fichier : il est **contournable en changeant de
notation**, sur les DEUX copies. Voir E-129.

**FERMÉ au portage** (`v1.37.67`, garde corrigée en `v1.37.68`) : il n'y a **qu'un seul chemin
d'écriture**, `App\Services\Serveurs::valideIp()`. Une copie ne peut pas diverger quand il n'y a pas
de copie — encore fallait-il que la copie unique soit juste, et elle ne l'était pas d'abord.

---

## E-128 — Une note se supprime par son seul identifiant, sans regarder la machine

`server_actions.php:180` : `DELETE FROM server_notes WHERE id = ?`. Ni la machine, ni l'auteur, ni
l'accès ne sont vérifiés. L'identifiant seul suffit à supprimer n'importe quelle note du parc, y
compris sur une machine qu'on ne verrait pas.

Portée réelle : faible — la page d'administration montre déjà tout le parc, et il faut un compte de
rôle ≥ 2. Ce qui est relevé, c'est que la vérification **manque** là où les trois gestes voisins
(`add_tag`, `remove_tag`, `add_note`) résolvent tous par `machine_id`.

**FERMÉ au portage** (`v1.37.67`) : `Serveurs::supprimeNote()` résout par le **couple** machine + note.
Viser la note d'une autre machine ne supprime rien, et la route le dit
(`serveurs.err_note_introuvable`).

---

## E-129 — Le garde SSRF compare des PRÉFIXES DE CHAÎNE : la même adresse passe sous une autre notation

Trouvé par une **relecture croisée** — pas par la suite qui venait pourtant d'écrire E-123 et E-127 —
puis mesuré au clic sur les deux portails.

Le correctif A10-01 teste des préfixes :

```php
strpos($data, '127.') === 0 || strpos($data, '169.254.') === 0 || strpos($data, '0.') === 0
```

`::ffff:169.254.169.254` désigne **exactement** le point de métadonnées que le commentaire du
correctif nomme, et ne commence par aucun de ces préfixes. Mesuré dans le conteneur PHP :

| adresse | IP valide | bloquée par A10-01 |
|---|---|---|
| `169.254.169.254` | oui | **oui** |
| `::ffff:169.254.169.254` | oui | **non** |
| `::ffff:a9fe:a9fe` | oui | **non** |
| `::ffff:127.0.0.1` | oui | **non** |

Puis mesuré **au clic**, par le formulaire d'ajout de `manage_servers.php` — donc par la copie
« durcie », celle qui porte le correctif : la machine est créée avec `::ffff:169.254.169.254`.

**Ce n'est donc pas E-127 sous un autre angle.** E-127 dit qu'une des deux copies n'a pas le garde ;
E-129 dit que **le garde lui-même ne tient pas**, y compris là où il est présent. Corriger E-127 seul —
en donnant à `server_actions.php` la copie durcie — n'aurait rien fermé.

**LA LEÇON ÉTAIT DÉJÀ ÉCRITE, ET LE PORTAGE L'A QUAND MÊME RATÉE.** « Valider la FORME avant le
contenu, et ne jamais recopier une règle de sécurité » — la leçon de `//exemple.com`. Le premier jet de
`Serveurs::valideIp()` (`v1.37.65`) a recopié fidèlement la règle du legacy, angle mort compris, et
l'a même étendue au multicast **en gardant la comparaison de chaîne**. Fidélité au mauvais niveau :
c'est l'INTENTION du correctif qu'il fallait porter, pas sa forme.

**FERMÉ au portage** (`v1.37.68`) : `inet_pton` d'abord, réduction des notations mappée et compatible
à leur IPv4, puis comparaison sur les **octets**.

| famille | refusé |
|---|---|
| IPv4 | `0/8`, `127/8`, `169.254/16`, `224/4` multicast, `240/4` réservé |
| IPv6 | `::`, `::1`, `fe80::/10`, `ff00::/8` |

**IL Y A TROIS COPIES, PAS DEUX** — la troisième trouvée en inventoriant D6c. `import_csv.php:66-70`
en porte une quatrième version du même garde, réduite à **cinq** conditions (ni `::`, ni
`0:0:0:0:0:0:0:0`), et toujours par préfixes. Mesurée au clic, par dépôt d'un fichier :
`::ffff:169.254.169.254` est importée et la machine créée.

| copie | conditions | tombe sur `::ffff:169.254.169.254` |
|---|---|---|
| `manage_servers.php:59-72` | 7 | **oui** |
| `import_csv.php:66-70` | 5 | **oui** |
| `server_actions.php:73` | 0 | **oui** (E-127) |

Trois copies d'une règle de sécurité, trois niveaux de complétude, et **aucune** qui tienne. C'est
l'argument le plus net pour la règle « une seule copie, et elle normalise avant de comparer ».

Dix-huit cas mesurés en PHP, zéro écart ; et la suite `go-adm-serveurs` pose désormais l'adresse
mappée **dans le formulaire** et vérifie qu'aucune machine n'est créée — un geste réel, sur les deux
cibles, qui constate le legacy et asserte le portage.

**NON FERMÉ côté legacy**, et c'est un choix à porter à l'exploitant : les deux copies de
`validateInput()` restent vulnérables. Le correctif est le même qu'ici — `inet_pton` et comparaison de
plages — mais il touche un fichier de production non porté.

---

## E-130 — `adm/` D6c : l'import CSV pose `users.sudo` sans la garde de rôle 3 que le geste dédié exige

`users.sudo` n'est pas une colonne comme une autre : c'est la **précondition du repli `NOPASSWD: ALL`**
du module `ssh/`, le point le plus dangereux du dépôt. Le geste dédié pour la poser,
`adm/api/toggle_sudo.php`, porte `checkAuth([ROLE_SUPERADMIN])` — **rôle 3 seul**.

`import_csv.php:162` lit `$data['sudo']` et l'écrit directement :

```php
$sudo = (int)($data['sudo'] ?? 0);
$stmt = $pdo->prepare("INSERT INTO users (name, email, password, ssh_key, role_id, active, sudo) …");
```

**Aucun contrôle de rôle.** La garde hiérarchique du fichier (`:155-158`) existe, elle est correcte, et
elle ne touche que `$roleId` :

```php
if ($myRole < 3 && $roleId >= $myRole) { $roleId = 1; }
```

**Mesuré au navigateur** — un fichier déposé dans le formulaire de l'onglet Utilisateurs, ligne
`epreuve_csv_d6c,,admin,1,1` :

```
compte importé (role|sudo|courriel) : 2|1|(nul)
```

Le drapeau est retiré dans la seconde qui suit, sans attendre le nettoyage final.

**CE QUI EST MESURÉ ET CE QUI EST LU, et il faut le dire séparément.** La CAPACITÉ — l'import écrit
bien `sudo = 1` — est mesurée ici, au clic, au rôle 3. La FRANCHISSABILITÉ au rôle 2 est établie par
**lecture** : le formulaire vit sur `admin_page.php`, gardée par `checkPermission('can_admin_portal')`
qui admet le rôle 2, et rien sur le chemin du `sudo` ne consulte le rôle. Aucun compte d'épreuve n'est
à la fois de rôle 2 et porteur de `can_admin_portal` : il n'y a pas de quoi la mesurer au navigateur.

C'est la même prudence que sur le repli `NOPASSWD: ALL` lui-même — « le trou est à un `UPDATE` d'être
exploitable, ce n'est pas la même chose que de dire qu'il l'est ». Ici l'import **est** cet `UPDATE`,
et il est offert un cran plus bas que le geste qui porte le même effet.

**COMPLÉTÉ LE 2026-08-26 PAR UNE RELECTURE CROISÉE, ET VÉRIFIÉ ICI.** L'écart est plus large que
« un rôle 2 atteint le formulaire », sur quatre points.

**a. La visibilité du formulaire n'est pas la garde — il n'y en a pas.** `admin_page.php:44` fait
`require_once __DIR__ . '/includes/import_csv.php'`, **inconditionnellement, avant toute logique
d'onglet**. Le fichier est donc chargé sur chaque requête qui passe les lignes 40-41
(`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis `checkPermission('can_admin_portal')`), et son
traitement s'exécute dès qu'un POST porte `import_type` — **que le formulaire ait été rendu ou non**.
Un POST forgé vers `admin_page.php` suffit ; l'onglet n'a jamais besoin d'être ouvert.

**b. `import_csv.php` n'a AUCUNE garde propre.** Zéro `checkAuth`, zéro `checkPermission` : sa seule
condition d'entrée est `REQUEST_METHOD === 'POST' && isset($_POST['import_type'])`. Il dépend
entièrement de qui l'inclut. Il n'y a qu'un incluant aujourd'hui ; le jour où une autre page l'inclut,
elle hérite de l'exposition sans que rien ne le signale. Même forme que `server_actions.php`.

**c. L'en-tête d'`admin_page.php` promet une garde qui n'existe pas.** Lignes 14-16 :

> Accès requis : rôle superadmin (`role_name = 'superadmin'`, `role_id = 3`). Un premier filtre rapide
> est assuré par `checkAuth([2, 3])` ; **une seconde vérification stricte via la BDD n'autorise que le
> superadmin.**

Cette seconde vérification **n'existe pas**. La ligne 41 est `checkPermission('can_admin_portal')`, qui
admet le rôle 2. C'est très probablement ainsi que le trou a survécu : quiconque a relu l'en-tête a cru
le fichier réservé au rôle 3. **Cinquième occurrence du motif « l'en-tête qui ment »** dans le dépôt,
après `compliance_report.php`, `ssh/index.php`, `iptables/index.php` et `fail2ban/index.php`.

**d. Personne n'occupe la position aujourd'hui, et elle est à UNE permission près.** Mesuré en base :

| | |
|---|---|
| comptes de rôle 2 | `rw-test-admin` (id 15) — `can_admin_portal = 0`, `sudo = 0` |
| comptes portant `sudo = 1` | `superadmin` (id 1, rôle 3) **seul** |

Accorder `can_admin_portal` à un compte de rôle 2 ouvre le chemin. Le geste n'est plus un `UPDATE` en
base mais **une attribution de permission** — c'est-à-dire un geste d'administration ordinaire.

### E-130 CHAÎNE avec l'arbitrage K4, et c'est ce qui compte

L'arbitrage K4 du plan justifie son niveau de risque ainsi :

> aucun compte actif de rôle 1 ne porte `users.sudo = 1`, donc le trou est réel et **à un `UPDATE`
> d'être exploitable**

**L'import CSV EST cet `UPDATE`**, et il est atteignable un cran plus bas que K4 ne le suppose.

Pire — et c'est la partie qu'il faut lire deux fois : la garde hiérarchique de l'import **produit
exactement la forme de compte que K4 attend**. Pour un importeur de rôle 2 :

```php
$roleId = 2;                                  // la ligne CSV dit `role=admin`
if ($myRole < 3 && $roleId >= $myRole) { $roleId = 1; }   // 2 >= 2  ->  rôle 1
$sudo = (int)($data['sudo'] ?? 0);            // reste à 1, jamais touché
```

Le compte créé est **rôle 1 avec `sudo = 1`** : la précondition du repli `NOPASSWD: ALL`, obtenue par
un compte de rôle 2, au moyen d'un fichier. La garde qui fait correctement son travail sur `role_id`
fabrique la cible que l'autre garde était censée protéger.

Les deux écarts se lisaient comme indépendants. **Ils sont chaînés** : la précondition que l'arbitrage
de K4 suppose manquante est fournie par un chemin que l'arbitrage de K4 n'examine pas. Que
`toggle_sudo.php` soit réservé au rôle 3 montre l'intention du produit — et l'import la contourne.

**NON FERMÉ** — D6c n'est pas encore porté. Le portage devra exiger le rôle 3 pour la colonne `sudo`,
ou la refuser à l'import ; la décision revient à l'exploitant, parce que retirer une colonne d'un
format de fichier documenté change un contrat. **Et elle ne concerne plus seulement D6c** : elle
conditionne aussi le niveau de l'arbitrage K4.

---

## E-131 — Un compte importé reçoit un mot de passe que personne ne connaît, et le seul chemin qui l'aurait envoyé est du code mort

`import_csv.php:149-150` :

```php
$password = bin2hex(random_bytes(8)); // 16 chars hex
$hash = password_hash($password, PASSWORD_DEFAULT);
```

`$password` n'est ensuite **ni affiché, ni stocké, ni envoyé**. La variable meurt à la fin de
l'itération.

`$sendWelcome` (`:21`) — qui aurait servi à l'envoyer — est **lu une fois et jamais utilisé**, et
**aucun formulaire n'émet `send_welcome`** : les deux formulaires d'import ne portent que
`import_type`, `csv_file` et `skip_duplicates` (`admin_page.php:229-266`). Mesuré.

Le compte est donc créé, actif, et **inutilisable**. Reste le chemin de réinitialisation — mais il
exige un `email`, et la colonne `email` du CSV est **facultative** : `$email ?: null`. Mesuré à
l'import : `courriel : (nul)`.

**Un compte importé sans courriel n'a donc aucun chemin d'accès, et aucun chemin de récupération.** Il
occupe un nom, compte dans les listes, et apparaît dans les sélecteurs d'identité — c'est exactement ce
qui est arrivé aux cinq comptes `e2e_test_*` relevés en §7 du plan.

**NON FERMÉ** — le portage devra soit rendre `email` obligatoire à l'import, soit rendre le mot de
passe généré **une fois** à l'écran comme le fait déjà la création de compte de D3, soit forcer
`force_password_change`. Décision à porter.

---

## E-132 — La politique de mot de passe des COMPTES s'applique aux mots de passe de MACHINES, sur un seul des deux chemins

`encryptPassword($password, $validate = true)` applique une politique — longueur, minuscule,
majuscule, chiffre, caractère spécial — et lève une exception si elle n'est pas respectée.

| chemin | appel | politique |
|---|---|---|
| formulaire (`manage_servers.php:115`) | `encryptPassword(trim($_POST['password']), false)` | **désactivée** |
| import CSV (`import_csv.php:89`) | `encryptPassword($data['password'] ?? '')` | **active** (défaut) |

Mesuré : une ligne CSV portant `motdepasse` comme mot de passe machine ne crée **aucune** machine ; la
même valeur passe par le formulaire.

Le choix du formulaire est le bon, et son motif est clair : **un mot de passe de machine est imposé par
la machine, pas choisi ici.** Le refuser rend le parc inadministrable — on ne peut pas déclarer une
machine dont le mot de passe existant ne plaît pas à la politique du portail. L'import applique donc
une règle qui n'a pas d'objet, et il le fait en silence : la ligne finit dans le compte d'erreurs sans
que le motif réel — « votre mot de passe machine n'est pas assez complexe » — soit jamais énoncé.

**NON FERMÉ** — le portage passera `false`, comme le formulaire, et l'écrira.

---

## E-133 — `adm/` D6d : `updated` recouvre deux situations opposées, et aucune interface ne peut s'en sortir

`POST /server_lifecycle` (`backend/routes/admin.py:110`) rend :

```python
cur.execute("UPDATE machines SET lifecycle_status = %s, retire_date = %s WHERE id = %s", …)
conn.commit()
return jsonify({'success': True, 'updated': cur.rowcount > 0})
```

**Aucun `SELECT` préalable.** Or `rowcount` vaut **0** dans deux cas opposés :

| situation | `rowcount` | ce que ça veut dire |
|---|---|---|
| on réécrit la valeur déjà en place | 0 | il n'y avait rien à faire — **succès** |
| la machine n'existe pas | 0 | la cible est fausse — **échec** |

`updated: false` ne dit donc pas laquelle. Une interface qui affiche « échec » ment dans le premier
cas ; une qui affiche « fait » ment dans le second. Il n'y a pas de troisième option : l'information
n'est pas dans la réponse.

**Mesuré au navigateur** — `200 {"success":true,"updated":false}` sur une réécriture sans effet.

**PAR UNE REQUÊTE FORGÉE, ET C'EST LE POINT INTÉRESSANT.** Aucun clic ne peut produire ce cas, parce
que **l'interface n'offre jamais le bouton de l'état courant** : machine `active` → bouton
« retirer » ; machine `retiring` → boutons « archiver » et « réactiver ». C'est une bonne propriété du
legacy, et elle est asserte par la suite. Le défaut est donc **latent** par l'interface et atteignable
par une requête forgée — ce qui abaisse sa gravité sans changer sa nature.

*(Le premier jet de cette étape cherchait le bouton de l'état courant, ne le trouvait pas, ne
déclenchait aucune requête — et son assertion passait sur une **chaîne vide**. Un test qui ne peut pas
échouer, révélé par le seul `(aucune)` du journal. La suite exige désormais d'avoir mesuré quelque
chose avant de conclure.)*

**FERMÉ au portage** (`v1.37.72`), et par la structure plutôt que par un message mieux tourné : le
cycle de vie s'écrit **en base**, sans passer par la route du backend. Celle-ci ne fait qu'un `UPDATE`
sur `machines` — aucun effet distant, aucune session SSH, aucun courriel — il n'y a donc rien à
hériter d'un aller-retour, sauf son défaut. Même décision que V4 pour `supervision_config`.

`Serveurs::definitCycle()` **résout la machine avant de la muter**, et rend donc trois issues au lieu
de deux :

| issue | message |
|---|---|
| `introuvable` | « Cette machine n'existe pas. » |
| `inchange` | « La machine était déjà dans cet état : rien n'a changé. » |
| `fait` | « La machine est mise en retrait. » |

Mesuré sur le portage, même requête forgée : « La machine était déjà dans cet état : rien n'a
changé. » L'ambiguïté ne se corrige pas au niveau du libellé — elle se corrige en **allant chercher
l'information qui manquait**, et un `SELECT` suffit.

**NON FERMÉ côté backend** : `/server_lifecycle` garde son `updated` ambigu, et `/exclude_user`
(`admin.py:115`) a la même forme. Le portage ne les appelle plus, mais le legacy si.

**Ce qui n'est PAS un défaut, et il faut le dire** : `/server_lifecycle` n'a pas
`@require_machine_access` là où `/server_status` le porte. Une première rédaction y a vu un IDOR —
**c'était faux**, `check_machine_access()` commençant par `if role_id >= 2: return True`. L'écart est
cosmétique. Voir la règle du §8 : vérifier qu'un garde est absent n'est pas vérifier que son absence
compte.

---

## E-134 — Le portage ignorait les permissions TEMPORAIRES, et D5 avait laissé toute une capacité derrière lui

Trouvé en inventoriant D7, sur une question qui n'avait rien à voir : `adm/api_keys.php` est gardé par
`checkPermission('can_manage_api_keys')`, et vérifier ce que fait `checkPermission` a montré qu'il
consulte **trois** sources, pas une.

`legacy/auth/functions.php:276-302` :

| source | ce qu'elle fait |
|---|---|
| rôle | `if ($roleId === 3) return true;` — repli superadministrateur |
| `permissions` | la table permanente, colonne `can_*` |
| **`temporary_permissions`** | `WHERE user_id = ? AND permission = ? AND expires_at > NOW()` |

**`App\Services\Droits::permissions()` ne lisait que la deuxième.** Un octroi temporaire ouvrait donc
la page sur l'ancien portail et rendait **403** sur le portage.

La divergence allait dans le sens **restrictif** — elle n'ouvrait rien, elle fermait. Ce n'est pas une
faille, c'est une rupture de parité ; et elle rendait **inopérante** une capacité que le backend
expose par trois routes et que le planificateur purge à deux endroits.

**Ce n'est pas une capacité morte.** Mesuré :

| pièce | état |
|---|---|
| `POST /admin/temp_permissions` (rôle **3**) | octroi, durée bornée à 1–720 h |
| `GET /admin/temp_permissions` (rôle 2) | liste |
| `DELETE /admin/temp_permissions/<id>` (rôle 2) | révocation |
| `manage_permissions.php:184-267` | **le formulaire complet** — compte, permission, durée — plus la liste et la révocation |
| `scheduler.py:400` et `:782` | purge des expirées, deux fois |
| `privacy.php:51` | purge RGPD à la suppression d'un compte |
| `mysql/migrations/014_temporary_permissions.sql` | sa migration dédiée |

**D5 a donc porté `manage_permissions.php` en laissant dehors la moitié de son interface**, et je ne
l'avais pas vu. C'est un sous-lot à part entière — **D5b** — parce qu'il faut porter trois gestes et
leur passage par la passerelle.

**FERMÉ pour la LECTURE** (`v1.37.73`) : `Droits::permissions()` fusionne désormais les octrois non
expirés. Mesuré sur **les deux cibles**, et c'est une assertion de parité stricte, pas un écart
assumé :

```
sans octroi                  403
octroi temporaire de 1 h     200
apres revocation             403   — sans reconnexion
```

La dernière ligne compte autant que les autres : les droits sont relus **à chaque requête**, donc une
révocation referme la page tout de suite.

**NON FERMÉ pour l'ÉCRITURE** : aucune interface du portage n'octroie ni ne révoque. C'est D5b.

### Et le legacy porte DEUX notions de permission, qui ne coïncident pas

Relevé par une relecture croisée le 2026-08-26, **vérifié ici**, et il complète l'écart plutôt qu'il
ne le corrige :

| chemin | ce qui décide | temporaires prises en compte |
|---|---|---|
| accès à une PAGE du legacy | `checkPermissionFromDB` | **oui** — rôle 3, `permissions`, `temporary_permissions` |
| ce que le legacy TRANSMET au backend | `api_proxy.php:89` → `$_SESSION['permissions']` → `getVerifiedPermissions` → `SELECT * FROM permissions` | **non** |

Un octroi temporaire ouvre donc la page du legacy **et ne franchit pas sa passerelle**. Les deux
notions vivent dans le même portail et ne se rejoignent nulle part.

**Le portage, lui, est cohérent** : `PasserelleController` transmet `Droits::permissions()`, qui
inclut désormais les octrois temporaires. Ce qui ouvre la page ouvre aussi l'appel.

C'est donc une **divergence de comportement assumée** : sur un octroi temporaire, un appel au backend
part depuis le portage et ne part pas depuis le legacy. Le portage a raison — refuser au niveau de la
passerelle ce qu'on vient d'accorder au niveau de la page n'est défendable nulle part — mais la
différence se déclare plutôt qu'elle ne se découvre.

**Conséquence pour l'arbitrage K4**, et elle est importante : le bouton de déploiement de clés vit
dans `ssh/index.php`, **non porté**. `POST /deploy` est donc appelé par le chemin où les permissions
temporaires manquent encore. Poser `@require_permission('can_deploy_keys')` sur cette route
refuserait un octroi temporaire venu du legacy. **Le verrou documenté sur `/deploy` n'est pas levé
par ce correctif** ; il le sera le jour où K4 sera porté. Faire lire la base à `api_proxy.php` est
possible — c'est un fichier du legacy, la convention l'autorise — mais cela touche de la production
et se mesure avant de se décider.

### Deux constats annexes, tous deux mesurés

**`machine_id` est déclaré, jamais renseigné, jamais filtré.** La table porte une colonne `machine_id`,
la route d'octroi l'accepte — et `checkPermissionFromDB` ne la filtre **pas** : un octroi qui se croit
limité à une machine vaut partout. Le formulaire du legacy n'offre d'ailleurs aucun sélecteur de
machine, donc elle est toujours nulle en pratique. Le portage reprend ce comportement **tel quel**,
fidèlement, et le signale ici plutôt que de corriger en silence une règle qu'aucune interface
n'exerce.

**`can_manage_api_keys` ne garde rien, et E-118 le disait déjà — c'est le CODE qui surinterprète.**
Première rédaction de cet écart : « E-118 le disait à tort ». **Faux, et vérifié avant publication.**
E-118 écrit noir sur blanc : « page dont l'accès n'est donc possible que par le rôle 3, qui contourne
toute permission ». C'est exact.

Ce qui surinterprète, c'est le docblock de `App\Services\Permissions` : « inatteignable dans les deux
sens, **alors qu'elle garde `adm/api_keys.php`** ». Elle ne le garde pas. Mesuré : elle est consultée à
**un seul endroit** du dépôt, `api_keys.php:20`, sur une page dont la ligne précédente est
`checkAuth([ROLE_SUPERADMIN])` — rôle 3 seul — et `checkPermissionFromDB` **rend `true` sans condition
pour le rôle 3**. Elle ne peut jamais décider de rien : elle n'est pas seulement inatteignable, elle
est **sans objet**. Le docblock est corrigé (`v1.37.73`).

*(Deux fois de suite j'ai failli publier une correction fausse d'un travail antérieur — ici en relayant
un résumé au lieu de relire la source. Relire E-118 a pris une commande.)*

---

## E-135 — `adm/` D7 : la portée d'une clé est validée par un moteur d'expressions et appliquée par un autre

`api_keys.php:47` valide chaque motif de portée **en PCRE** :

```php
if (@preg_match('#' . str_replace('#', '\\#', $p) . '#', '') === false) { $error = "Regex scope invalide : $p"; }
```

`backend/routes/helpers.py:88` l'applique **en Python** :

```python
if not any(re.search(p, route_path or '') for p in patterns):
```

Ce ne sont pas les mêmes grammaires. Mesuré le 2026-08-26, six motifs soumis aux deux moteurs :

| motif | PCRE | Python `re` |
|---|---|---|
| `(?<nom>/cve_.*)` | accepté | **refusé** — groupe nommé à la PCRE |
| `/a(?R)?b` | accepté | **refusé** — récursion, inexistante en Python |
| `/deploy*+` | accepté | accepté |
| `(?>/update)` | accepté | accepté |
| `/x{2,}?y` | accepté | accepté |
| `(?P<n>/ok)` | accepté | accepté |

Puis mesuré **au clic** : le formulaire accepte `(?<zone>/cve_.*)` et crée la clé. **La validation ne
prouve rien sur le moteur qui décide.**

**Ce que ça coûte, et il faut être exact.** L'exception de `re.search` est rattrapée par le
`except Exception` global de `_validate_api_key_from_db`, qui rend `(None, None)`. Or le correctif
**A07-02** fait que `db_ok is None` n'accorde le repli `Config.API_KEY` **que si `API_KEY_BOOTSTRAP`
est explicitement posée** — mesuré : elle est **absente** de l'environnement du backend. Le
comportement est donc **fail-closed**.

La conséquence n'est pas une faille, c'est **une clé rendue entièrement inutilisable** — et un
diagnostic trompeur : le journal annonce « API key DB lookup failed », donc une panne de base, pour un
motif que l'exploitant vient de saisir. **Mais si `API_KEY_BOOTSTRAP` était posée** — et son propre
commentaire la destine au démarrage — le même chemin deviendrait fail-open. Les deux se disent.

**FERMÉ au portage** (`v1.37.75`), **par l'absence** : `/cles-api` n'offre **aucun champ libre**. La
portée se coche dans une liste fermée dont les motifs sont écrits côté serveur — repris à l'identique
des présélections du legacy, qui sont toutes correctes. Ce portage ne peut pas compiler du Python : la
seule façon de garantir que ce qu'il valide sera compilable là-bas est de ne rien laisser saisir. Une
entrée libre validée se contourne par une requête forgée ; une entrée libre absente, non.

La suite **asserte cette absence** — un champ libre réapparu passerait inaperçu autrement.

---

## E-136 — La portée n'est pas ancrée : elle se lit plus étroite qu'elle n'est

`re.search` cherche **n'importe où** dans le chemin. Mesuré :

| motif | chemin | correspond |
|---|---|---|
| `/cve_scan` | `/cve_scan` | oui |
| `/cve_scan` | `/admin/cve_scan_all` | **oui** |
| `/deploy` | `/x/deploy_platform_key` | **oui** |
| `^/cve_` | `/admin/cve_scan_all` | non |

Un exploitant qui écrit `/deploy` croit borner la clé à cette route. Il lui accorde **tout chemin
contenant « deploy »** — dont `/deploy_platform_key`, `/deploy_service_account`. Et `/deploy` est
précisément la route qui écrit `authorized_keys` en root sans porter la moindre garde de rôle.

C'est la classe d'**E-02**, déjà tranchée pour la passerelle — « comparaison par SEGMENT, jamais par
préfixe » — sur une autre surface, et dans l'autre sens : ici c'est l'exploitant qui doit penser à
ancrer, et rien ne le lui dit. Le champ est présenté comme « une regex par ligne » ; les exemples du
`placeholder` sont bien ancrés (`^/cve_`), le texte d'aide ne l'est pas.

**FERMÉ au portage** (`v1.37.75`) : les motifs ne sont plus saisis mais **choisis**, et ceux de la
liste fermée sont tous ancrés par `^`. Il n'y a plus de chemin pour produire un motif non ancré.

Et la page **montre les motifs** sous chaque module : une portée qu'on coche sans voir ce qu'elle
couvre n'est pas une décision. Une portée vide — qui vaut **toutes les routes** côté backend — est
refusée à la création et signalée en toutes lettres dans la liste.

---

## E-137 — Créer une clé enregistre une SECONDE fois la clé d'environnement, et la révocation devient un tirage au sort

Deux mécanismes enregistrent le même secret, et ils ne se connaissent pas.

| mécanisme | nom posé | vérification avant insertion |
|---|---|---|
| `backend/bootstrap_api_key.py:40` | `proxy-internal-legacy-bootstrap-YYYYMMDD` | **`SELECT COUNT(*) WHERE key_hash = sha256(API_KEY) AND revoked_at IS NULL`** — idempotent |
| `adm/api_keys.php:86` | `proxy-internal-legacy` | **`INSERT IGNORE`**, qui ne se protège que par l'unicité du NOM |

Les noms diffèrent, et `key_hash` **n'est pas unique** (mesuré : `idx_key_hash` a `NON_UNIQUE = 1`).
L'`INSERT IGNORE` ne voit donc pas la ligne du bootstrap et insère un doublon.

**Mesuré au clic** : la table contenait 1 ligne avant la création d'une clé quelconque ; après,
**1 ligne `proxy-internal-legacy` de plus**, et `COUNT(DISTINCT key_hash)` sur les lignes
`proxy-internal-legacy%` vaut **1** — un seul secret, deux enregistrements actifs. *(La correspondance
entre le hachage stocké et `API_KEY` a été vérifiée par un booléen en SQL, sans qu'aucune valeur ne
sorte.)*

**Et voici ce que ça produit.** `_validate_api_key_from_db` fait :

```python
"SELECT id, name, scope_json, revoked_at FROM api_keys WHERE key_hash = %s LIMIT 1"
```

**`LIMIT 1` sans `ORDER BY`.** Avec deux lignes pour un même hachage, MySQL en rend une, sans garantie
de laquelle. Donc après avoir révoqué l'une des deux :

- si la requête rend la ligne révoquée → `return False` → **401**, alors qu'un enregistrement actif
  existe ;
- si elle rend l'autre → **la clé fonctionne**, alors que l'exploitant vient de la révoquer.

**La révocation devient non déterministe, dans les deux sens.** Un exploitant qui fait tourner
`API_KEY` puis révoque `proxy-internal-legacy` croit avoir fermé la porte ; l'ancienne clé peut
continuer d'ouvrir.

Le commentaire d'`api_keys.php:71-79` explique longuement pourquoi l'auto-enregistrement existe — et
il a raison sur le besoin. Ce qu'il ne fait pas, c'est vérifier que le secret n'est **pas déjà
enregistré sous un autre nom**, ce que le script Python fait, lui, correctement.

**FERMÉ au portage** (`v1.37.75`) : `ClesApi::assureCleEnvironnement()` interroge le **hachage**,
exactement comme `bootstrap_api_key.py` — le seul des deux mécanismes qui fût idempotent. Mesuré au
clic : créer une clé sur le portage produit **0** ligne supplémentaire, là où le legacy en produit 1.

Une ligne **révoquée** compte aussi : si l'exploitant a révoqué cette clé, la reposer irait contre sa
décision. C'est pourquoi la vérification ne filtre pas sur `revoked_at`.

**NON FERMÉ côté legacy**, et le nettoyage des doublons déjà présents reste une décision
d'exploitant : supprimer une ligne d'`api_keys` peut couper un consommateur.

---

## E-138 — `graylog/` G1 : « Tester » exécutait une commande à distance sur un seul clic, sans rien demander

Le module pose trois boutons par ligne dans l'onglet Machines, et chacun ouvre une **session SSH
réelle** qui exécute **en root** sur la machine de la ligne :

| bouton | ce qu'il fait | confirmation dans le legacy |
|---|---|---|
| Déployer | `apt-get install -y rsyslog` puis écriture dans `/etc/rsyslog.d/` | **oui** (`glDeploy`, js:90) |
| **Tester** | `logger -t <tag> <message>` | **AUCUNE** (`glTest`, js:100) |
| Retirer | `rm -f` des confs RootWarden puis `systemctl restart rsyslog` | **oui** (`glUninstall`, js:107) |

Et le tableau liste **toutes les machines non archivées** — la requête
(`backend/routes/graylog.py:245-263`) exclut seulement `lifecycle_status = 'archived'`. `srv-zabbix`
(id 1, production) y figure donc, avec ses trois boutons, et **rien dans le legacy ne distingue sa
ligne** de celle du banc d'essai.

L'asymétrie n'est pas une opinion : deux gestes sur trois demandent confirmation, le troisième non, et
c'est celui dont le nom — « Tester » — suggère le moins qu'il touche la machine.

**PORTAGE** : les **trois** gestes ouvrent une confirmation **en page**, et elle **nomme la machine et
son adresse**. Trois boutons par ligne et plusieurs lignes : un libellé générique ne dirait pas
laquelle. Le libellé dit aussi ce qui va se passer — « Une connexion SSH sera ouverte et la commande
exécutée en root ».

**Et la page le dit AVANT le clic**, pas seulement dans la confirmation : un encart de quatre lignes
décrit ce que chaque bouton fait vraiment, et signale que le tableau contient les machines de
production. Le legacy ne l'écrit nulle part.

### Ce que la suite ne clique pas, et pourquoi c'est écrit dans le fichier

`go-page-graylog-g1.mjs` ouvre l'onglet Machines et **lit** le tableau. Elle ne clique **aucun** bouton
de ligne. Cliquer « Tester » pour « voir ce qu'il fait » aurait joint une machine pour de vrai, et sur
la ligne de `srv-zabbix` cela aurait joint la production. Les gestes mutants sont le sous-lot **G2**,
qui viendra avec sa cible (`test-server`, machine 2) et son geste de retour (`uninstall`).

Le script de captures, lui, **ouvre** la confirmation de « Tester » — `ouvreConfirmation` ne fait que
rendre du DOM, aucune requête n'est émise — et il choisit la ligne du banc, jamais celle de la
production. Même quand un geste est inerte, viser la production pour une image serait prendre
l'habitude inverse de celle qu'on veut.

**Références** : legacy **25**, portage **26**. L'écart d'une assertion est « aucune boîte native » : le
legacy pose un `confirm()` pour supprimer un gabarit et un `alert()` pour rendre le résultat.

---

## E-139 — Un conteneur `flex` posé SUR un `<td>` fait ignorer son `colspan`

Défaut de **mon propre portage**, vu **à l'image** et invisible au DOM.

`.rw-panneau-decision` porte `display: flex` dans la feuille de style. Posé sur un `<td>`, il écrase
`display: table-cell` : **la cellule sort du modèle de tableau**, et son `colspan` n'a plus d'effet. Le
panneau de confirmation s'arrêtait à **745 px** sur un écran de 1920, le reste de la ligne restant
blanc.

Aucune assertion DOM ne pouvait l'attraper : l'attribut `colSpan` valait bien **6**. C'est la même
famille que la pastille à 1,06:1 — *le HTML était juste, le rendu ne l'était pas*.

**Correctif** : le conteneur flex va **dans** la cellule, jamais sur elle.

```
td (nu, colspan=6)
  └ div.rw-panneau-decision   (le flex vit ici)
```

Mesuré après correction, largeur rendue du panneau sur celle du tableau : **1590/1618**, **1070/1098**,
**907/923 px**. Une assertion a été ajoutée au script de captures — sans elle, la correction n'aurait
aucun témoin.

**⚠ `maintenance.js` a exactement le même défaut** (`td.className = 'rw-panneau-decision'`, sous-lot
porté en `v1.37.57`). Il n'avait pas été vu parce que la capture de ce module n'ouvrait pas le panneau.
À corriger dans son propre commit, avec sa suite rejouée — pas au détour de celui-ci.

### Et un second défaut de la même image

« Retirer » portait `rw-bouton--avertissement`, ce qui en faisait l'élément **le plus voyant du
tableau**, plus que « Déployer ». Attirer l'œil sur le geste destructeur est l'inverse de ce qu'on veut.
Les trois boutons de ligne sont désormais discrets ; le poids visuel appartient au panneau de
confirmation, où l'action porte `rw-bouton--danger` et l'annulation reste discrète.

---

## E-140 — Il n'existe aucune route `/graylog/history` : le legacy rend cet onglet côté serveur

Trois des quatre onglets du module viennent du backend. Le quatrième, l'historique, est rendu **en
PHP** depuis `user_logs` (`legacy/graylog/index.php:20-27`), avec un filtre sur le préfixe de chaîne
`[graylog]%`.

Le premier jet du portage appelait `/graylog/history` par la passerelle. **Cette route n'existe pas** —
vérifié avant d'exécuter quoi que ce soit, ce qui a évité un onglet qui aurait affiché « impossible de
lire » sans que rien n'explique pourquoi.

Le portage rend donc cet onglet côté serveur, avec la même requête et le même filtre. Le préfixe
`[graylog]` est un **marqueur de chaîne et non une colonne** : c'est ainsi que le legacy range ces
lignes, et changer ce rangement en portant une page aurait perdu l'historique déjà écrit.

**Le commentaire d'en-tête du contrôleur a dû être réécrit** : il annonçait « ce contrôleur ne lit rien
lui-même, et c'est délibéré », ce qui devenait faux dès l'ajout de cette lecture. Un commentaire qui
affirme plus que le code est le motif relevé cinq fois dans ce dépôt ; le laisser dans du code neuf
aurait été le sixième.

---

## E-141 — Trois suites rouges sans qu'un seul commit ait touché leur module

Constat du **2026-08-26**, à la fin d'un LOT de 117 exécutions et 1727 assertions.
`go-page-ssh-parc` (les deux cibles) et `go-page-ssh-preflight` (portage) échouent, et
`go-page-ssh-preflight` sur le legacy rend 8 au lieu de 10.

### Ce n'est pas une régression de code, et c'est daté

| LOT | `ssh-parc` laravel | `ssh-preflight` laravel | `ssh-parc` legacy |
|---|---|---|---|
| 2026-08-25 17:46 | 14/0 | 15/0 | 11/0 |
| 2026-08-25 20:53 | 14/0 | 15/0 | 11/0 |
| 2026-08-25 22:34 | 14/0 | 15/0 | 11/0 |
| **2026-08-26 13:18** | **11/1** | **12/1** | **8/1** |

Aucun commit de la journée ne touche `legacy/ssh/`, `cles-ssh.blade.php`, ni
`backend/routes/ssh*.py`. Vérifié : les seules modifications du legacy sont l'archivage de
`maintenance/` et `menu.php`. Le backend n'a pas bougé.

**Ce sont les DONNÉES du banc qui ont changé**, mesuré en base :

| table | état |
|---|---|
| `machine_tags` | **0 ligne** |
| `users.ssh_key` sur les 10 comptes actifs | **toutes vides** |

Et **aucune trace au journal d'audit** : ni « Cle SSH effacee », ni action sur une étiquette.
Les suppressions n'ont donc pas passé par l'interface — ce sont des écritures directes en base,
donc des fixtures de suites.

### Mais le défaut de fond est dans les SUITES, pas dans la donnée

`go-page-ssh-parc:224-236` lit le vocabulaire d'étiquettes en base au démarrage
(`TAGS_DU_PARC`), puis exige que le filtre de la page propose exactement ce vocabulaire :

```js
verifie('le filtre de tags propose exactement le vocabulaire du parc',
    Array.isArray(filtres.tags) && …)
```

Quand le parc n'a **aucune** étiquette, les deux portails **n'affichent pas le filtre du
tout** — ce qui est un comportement raisonnable. `filtres.tags` vaut alors `null`,
`Array.isArray(null)` est faux, et l'assertion échoue en accusant la page.

Trois assertions supplémentaires disparaissent au passage : elles vivent dans un
`if (TAGS_DU_PARC.length)`, donc elles ne s'exécutent plus. D'où 14 → 11.

Même mécanisme pour `ssh-preflight` : le rapport dit « aucun compte actif ne porte de clé SSH
— un déploiement ne déploierait rien », ce qui est **exact**, et la suite attendait de lui qu'il
nomme un autre prérequis manquant.

**La leçon n'est donc pas « quelqu'un a effacé des données » mais :**

> **Une suite qui dépend de données partagées PRÉEXISTANTES qu'elle ne crée pas finira par
> accuser la page pour un état du banc.** Elle ne peut pas distinguer « la page est fausse » de
> « le banc est vide », et son message désignera la page.

Deux façons de fermer cela, et la seconde est la bonne :

1. tolérer le cas vide — `filtres.tags === null` est acceptable quand `TAGS_DU_PARC` est vide.
   Ça rend la suite verte, mais elle ne mesure alors plus rien du filtre ;
2. **poser la fixture**. La suite crée son étiquette, mesure le filtre, la retire dans un
   `finally` — comme `graylog/` G1 le fait pour sa configuration de flotte et son gabarit. Elle
   devient indépendante de l'état du banc, et elle mesure le filtre **toujours**.

**Non corrigé dans ce commit** : `ssh/` n'est pas le module en cours, et modifier deux suites
d'un autre module au détour d'un portage `graylog/` mélangerait ce qui doit rester séparé. Le
constat est daté, le mécanisme établi, et la correction attend son propre sous-lot — avec la
question ouverte de savoir s'il faut aussi **restaurer** les étiquettes et les clés du banc, ou
si un banc sans elles est l'état normal qu'il fallait mesurer depuis le début.

### ⚠ CORRECTION de E-141 — les clés SSH n'ont JAMAIS existé, et l'écart n'accusait qu'à moitié juste

Écrit le 2026-08-26, quelques heures après E-141, sur une mesure que je n'avais pas faite : **la
lecture des journaux des LOT antérieurs**, qui existent tous dans `/tmp`.

E-141 affirmait que « les données du banc ont changé », en citant deux tables. **Une seule des deux
est vraie.**

| ce qu'E-141 disait | ce que les journaux montrent |
|---|---|
| `machine_tags` vidée | **VRAI** — le tag `banc-essai` est présent dans les **six** LOT du 2026-08-25 (09:13 → 21:22) et absent le 2026-08-26 à 11:42 |
| `users.ssh_key` vidée | **FAUX** — « 0 compte(s) actif(s) avec une cle SSH » dans **tous** les journaux du 25, à toute heure |

Le rapport de préflight disait déjà, le 25 : *« ATTENTION : aucun compte actif ne porte de cle SSH —
un deploiement ne deploierait rien »*. Il le disait alors que la suite était **verte**. Aucune clé n'a
donc disparu : il n'y en a jamais eu.

**Ce qui a réellement fait tomber `ssh-preflight` est double, et n'a rien à voir avec les clés** :

1. une assertion qui **présumait qu'un prérequis manque toujours**. Le portage répondait « Aucun
   prerequis manquant », ce qui était **exact**, et l'assertion l'a condamné pour avoir raison ;
2. l'état de scan de la machine 2, passé de `JAMAIS` au 25 à `2026-08-26 09:09:37`. Deux assertions
   vivent dans un `if (SCAN_M2 === 'JAMAIS')` et ont donc cessé de s'exécuter — d'où 15 → 13.

**Il ne reste qu'UN fait inexpliqué, et il est bien plus étroit qu'annoncé** : la disparition d'un
**seul tag**, `banc-essai`, entre le 25 à 21:22 et le 26 à 11:42, sans trace au journal d'audit. Les
clés sortent du dossier ; la question « faut-il restaurer les clés du banc ? » posée en E-141 **n'a pas
lieu d'être**.

### Ce que cette correction apprend, et c'est le vrai apport

**J'avais les journaux antérieurs sous la main et je ne les ai pas lus.** J'ai daté la régression sur
les *totaux* des LOT — `14/0` hier, `11/1` aujourd'hui — ce qui est une mesure juste, puis j'en ai
déduit un mécanisme au lieu d'aller le lire. Les journaux par suite portaient la réponse en clair,
ligne `INFO`, dans six exécutions successives.

> **Un total qui change dit QU'il s'est passé quelque chose, jamais QUOI. La ligne `INFO` du journal
> précédent le dit, elle.** Comparer les totaux date l'événement ; seule la lecture du détail
> l'identifie.

Et le motif de mon erreur est celui-là même que le chantier relève partout : j'ai vu deux tables vides
au *présent*, et j'ai conclu qu'elles avaient été *vidées*. Un état actuel ne dit rien de l'état
antérieur — c'est la même faute que « un état final correct ne prouve pas que le geste était correct »,
prise par l'autre bout.

### E-141 est CLOS — il n'y avait pas de mystère, il y avait une dépendance à une donnée que personne ne possédait

Dernière mesure, faite par la seconde session et **revérifiée ici** le 2026-08-26 :

| contrôle | résultat |
|---|---|
| `grep -rn "banc-essai"` sur `tests/`, `scripts/`, `mysql/`, `laravel/`, `legacy/`, `backend/` | **aucune occurrence** |
| apparition dans les journaux | absente le **2026-08-21 à 16:17**, présente à **16:22** |

L'étiquette `banc-essai` était donc une **fixture posée à la main**, en cours de session, qu'**aucune
suite ne créait ni ne maintenait**. Sa disparition n'a pas de trace au journal d'audit pour la même
raison que son apparition n'en a pas : elle n'est jamais passée par l'interface, dans un sens comme
dans l'autre.

**Il n'y a donc aucun événement à expliquer.** Ce qu'il y avait, c'est une suite qui mesurait une
propriété réelle — « le filtre propose exactement le vocabulaire du parc » — en s'appuyant sur une
donnée que **personne ne possédait**. Elle a tenu quatre jours, puis quelqu'un a nettoyé, et la suite a
accusé la page.

C'est exactement la leçon posée plus haut, et la voici confirmée par son propre cas :

> Une suite qui dépend de données partagées préexistantes qu'elle ne crée pas finira par accuser la
> page pour un état du banc.

La correction retenue — poser la fixture et la retirer dans un `finally` — ne rend pas seulement la
suite verte : elle rend la propriété mesurable **toujours**, y compris sur un banc fraîchement remis à
zéro. Les trois assertions qui vivaient dans un `if (TAGS_DU_PARC.length)` sont redevenues
inconditionnelles.

### Le corollaire de méthode, qui est le vrai gain de ces deux écarts

> Un total qui change dit **qu'**il s'est passé quelque chose, jamais **quoi**. Le journal du rejeu
> précédent, lui, le dit — il est en clair dans `/tmp`, à portée d'un `grep`, et **deux sessions ont
> passé deux jours sans y penser**.

Trois conclusions fausses ont été tirées avant qu'on les lise : que des clés SSH avaient disparu
(elles n'ont jamais existé), qu'une fixture de suite avait vidé une table (aucune suite ne la
touchait), et qu'un module avait régressé (deux assertions avaient simplement cessé de s'exécuter).
Les trois étaient réfutables par un `grep` dans les journaux conservés.

---

## E-142 — `adm/` D9a : l'aide du préréglage PAR DÉFAUT affirme l'inverse de ce que son propre module documente

**Mesuré** le 2026-08-26 par `tests/e2e/go-adm-politiques.mjs`, sur les deux cibles.

`legacy/adm/server_user_sudo.php` affiche, sous le préréglage `apt_only` :

> « L'utilisateur peut installer et mettre a jour des logiciels (commande « apt »).
> **Il ne peut pas toucher au reste du systeme.** »

`backend/sudo_manager.py:80-84`, dans la fonction qui produit cette règle même :

> « **AVERTISSEMENT : ce preset est EQUIVALENT ROOT.** `apt install/upgrade` execute des scripts de
> mainteneur (.deb postinst) en root -> un utilisateur avec ce preset peut obtenir un shell root via
> un paquet construit. Il n'existe pas de moyen sur de "limiter a apt" sans donner root. »

Et `apt_only` est le préréglage **retenu par défaut** (`server_user_sudo.php:32`).

### Pourquoi celui-ci coûte plus cher que les quatre précédents

C'est la cinquième occurrence du motif « l'en-tête qui ment », mais les quatre autres
(`compliance_report.php`, `ssh/index.php`, `iptables/index.php`, `fail2ban/index.php`) sont des
**commentaires** : ils trompent une relecture. Celle-ci est une **phrase d'interface**. Elle trompe
la personne qui décide, au moment où elle décide, sur l'étendue exacte des privilèges qu'elle
accorde — et elle le fait sur l'option qu'elle n'aura même pas eu à choisir.

### Ce que la mesure a montré en plus, et qui change la lecture

L'aide legacy de `all_nopasswd` dit **vrai** : « L'utilisateur devient administrateur TOTAL (root) et
peut TOUT faire, sans meme taper de mot de passe. » Ce n'est donc pas une négligence uniforme —
**c'est précisément l'équivalence root NON ÉVIDENTE que l'interface a prise à l'envers.** Le motif
« à moitié corrigé », une fois de plus : le cas visible est traité, le cas subtil ne l'est pas.

### Correction, et pourquoi elle ne pouvait pas être une phrase

Réécrire l'aide n'aurait pas suffi : une phrase juste dérive de `sudo_manager.py` exactement comme
l'autre l'a fait, et l'on aurait reconstruit le défaut avec de meilleurs mots. Recopier les gabarits
de règles en PHP aurait été pire — deux sources de vérité pour une règle de sécurité.

La garantie est **structurelle** et vit dans la suite : elle lit `sudo_manager.py` **dans le
conteneur** à chaque exécution, en **dérive** quels préréglages leur propre module signale comme
équivalents root, et refuse que l'écran les contredise. Rien n'est recopié.

> Le marqueur de dérivation est **étroit à dessein**. Une première rédaction cherchait « shell root »,
> qui apparaît dans la docstring de `read_logs` — « retrait de `less` (permettait `!sh` = shell
> root) », c'est-à-dire dans la phrase qui explique un **durcissement**. Elle aurait classé « donne
> root » le préréglage le plus borné des six.

**Divergence assumée qui en découle** : le portage retient `read_logs` par défaut, le legacy
`apt_only`. Un préréglage retenu par défaut est celui que la plupart des gens laisseront en place ;
il ne doit pas accorder root en silence. La propriété sous test n'est pas « le défaut vaut X » mais
**« le défaut ne figure pas parmi ceux que le module signale comme équivalents root »**.

---

## E-143 — `adm/` D9a : accorder root ne demandait rien ; le retirer demandait confirmation

**Mesuré au réseau**, pas au DOM.

`legacy/adm/js/server_user_policy.js` : `removePolicy()` ouvre par `if (!confirm(T.confirmRemove))
return;`, `rollbackTo()` de même — **`deployPolicy()` n'a aucune confirmation.**

| geste | ce qu'il fait | confirmation |
|---|---|---|
| `deploy` | **écrit** `/etc/sudoers.d/rootwarden-<user>` sur la machine | **aucune** |
| `remove` | supprime ce fichier | `confirm()` |
| `rollback` | réécrit une version antérieure | `confirm()` + `prompt()` |

L'asymétrie est à l'envers : **le geste qui DONNE était libre, celui qui REPREND était gardé.** La
confirmation protège le geste restauratif, pas celui qui accorde.

Mesure du premier clic sur « Déployer », legacy :

```
requetes d'ecriture au seul clic sur « deployer » : 1
requete AVORTEE : POST /api_proxy.php/policy/sudo/deploy
                  {"machine_id":2,"server_user_id":73,"preset":"apt_only","nopasswd":false,"runas":"root"}
```

Un seul clic envoyait donc le préréglage équivalent root — celui pré-sélectionné, dont l'aide
affirmait le contraire (E-142). **Les deux défauts se composent.**

### La propriété se mesure au RÉSEAU, et c'est ce qui a sauvé la mesure

Première rédaction : compter les `confirm()`. Elle aurait rendu **0 sur les deux cibles** — le legacy
n'en pose pas sur `deploy`, et le portage ne confirme pas par une boîte native mais par un
**panneau**. « Déployer est au moins aussi gardé que retirer » se serait donc vérifié des deux côtés,
sans rien mesurer.

> Ce qui compte n'est pas la **forme** de la confirmation mais son **effet** : après un clic sur
> « déployer », et avant tout consentement, rien ne doit être parti vers la machine.

Le portage : `0` au clic, `1` après consentement — et le panneau nomme la machine, le compte et la
portée réelle du préréglage avant que quoi que ce soit ne parte.

---

## E-144 — Le repli du backend est lui aussi le préréglage équivalent root

`backend/routes/policies.py`, dans `sudo_deploy()` :

```python
'preset': data.get('preset', 'apt_only'),
```

Une requête qui **omet** `preset` obtient donc `apt_only`, c'est-à-dire l'équivalence root. Le repli
dangereux n'est pas seulement à l'écran : il est aussi dans le backend, une couche plus bas, là où
aucune aide ne s'affiche.

Le portage envoie toujours `preset` — le JS le documente à l'endroit exact où il compose le corps —
mais **cela ne referme pas l'écart** : il reste ouvert pour tout autre appelant de la route, et il
n'est pas corrigeable depuis le portage. Il est porté ici pour arbitrage, avec E-142.

---

## Ce que la mesure de D9a DÉDOUANE

Deux constats, et ce module est le seul du chantier à porter les deux.

**Les gardes sont complètes aux TROIS niveaux.** La page porte `checkAuth([ROLE_SUPERADMIN])` —
mesuré : rôle 2 → **403** —, `api_proxy.php` inscrit `/policy/` dans ses préfixes d'administration,
et les onze routes de `backend/routes/policies.py` portent toutes `@require_role(3)`. Cinq modules
indépendants ont laissé passer la requête en gardant la page ; celui-ci non.

**Le geste distant est sûr.** `sudo_manager` valide par `visudo -cf` **avant** tout déplacement,
borne les chemins à `/etc/sudoers.d/rootwarden-*`, et lève plutôt que d'écrire si la validation
échoue. Ce n'est pas l'écriture qui était dangereuse ici : **c'était sa présentation.**

## Ce que D9a ne porte PAS, et le dit

`rollbackTo()` — l'annulation d'un déploiement — n'est pas portée : elle réécrit un fichier sudoers
sur la machine. L'historique du portage affiche donc, pour chaque déploiement restaurable, un lien
**marqué `↗`** vers l'ancien portail plutôt qu'un bouton inerte.

Le versant SFTP (`server_user_sftp.php`) est **D9b** : même JS, même module backend, mais ses
politiques n'ont pas de préréglages — et c'est dans sudo que vivait la question de l'équivalence root.

---

## E-145 — `graylog/` : l'état persisté affirmait l'inverse de la réponse, et le pire des deux sens

Relevé en lisant `backend/routes/graylog.py` avant d'écrire un clic du sous-lot G2, corrigé en
`v1.37.78` avec sept tests unitaires.

| geste échoué | ce que l'écran affirmait | la réalité |
|---|---|---|
| `deploy` | « Transfert actif » | rien ne part |
| `uninstall` | « Non déployé », et `success: true` | **le transfert continue** |

Le premier fait perdre des journaux. **Le second est une affirmation de confidentialité** : quelqu'un
qui retire le transfert pour une raison de conformité recevait une confirmation franche d'un geste qui
pouvait n'avoir rien fait. Et le marqueur étant **écrit en base**, il survit à la session — le message
d'échec disparaît au rechargement, la pastille reste.

C'est la mécanique de E-101 (la pastille de `maintenance/` calculée sur une mauvaise horloge) avec deux
aggravations : le marqueur est **persisté**, et il existe un sens où l'utilisateur croit avoir **arrêté**
quelque chose. On peut relire un formulaire ; on ne relit pas un flux qui continue.

### Le cas visible avait été traité, le subtil non

`deploy` calcule `syntax_ok` et `restart_ok`, les rend dans sa réponse, et compose son `success` avec.
Quelqu'un a donc pensé à l'échec — **mais seulement pour la réponse, pas pour l'état persisté**.
`uninstall`, lui, n'y pense pas du tout : il jette le code de retour de sa commande.

C'est le même motif que le préréglage `all_nopasswd` de `adm/` (E-142), dont l'aide dit **vrai** quand
celle du préréglage par défaut affirme l'inverse de son module. **Ce n'est pas une négligence uniforme,
c'est le cas non évident pris à l'envers** — et la présence d'un traitement correct juste à côté endort
la question.

### Ce que le correctif pose, et ce qu'il refuse de faire

`forward_deployed` signifie « la configuration RootWarden est **active** sur cette machine » — donc
`syntax_ok and restart_ok`. Les fichiers sont écrits **avant** ces deux contrôles, leur présence sur le
disque ne prouve rien. `last_deploy_at` n'est posé qu'en cas de succès : une tentative ratée n'est pas
un déploiement, et la dater ferait croire que la machine a été servie.

`uninstall` capture son code de retour et, en échec, **ne touche pas** à l'état — écrire `False`
affirmerait un retrait qui n'a pas eu lieu. Il rend 500 avec un message qui dit ce qui reste possible.

**Et la page le dit dans la langue de la personne** : le message du backend n'est pas traduit, donc le
portage ajoute `err_retrait_actif` (FR et EN) pour ce cas seul — le seul où l'utilisateur croit avoir
arrêté quelque chose.

### Les tests peuvent échouer, et c'est vérifié

En remettant l'ancien fichier une minute : **3 failed, 4 passed**. Avec le correctif : **7 passed**. Les
trois qui basculent sont exactement ceux du défaut.

Ils sont **unitaires et non E2E** parce que la branche d'échec n'est pas atteignable depuis l'interface
sans casser `rsyslog` sur une machine réelle. La session SSH est factice, `execute_as_root` est
**scripté** — on choisit quelle commande échoue —, et `_upsert_state` est **intercepté** plutôt que
dirigé vers la base : cela permet d'asserter non seulement ce qui a été écrit mais **qu'il ne l'a pas
été**. Un test qui lirait la base ne distinguerait pas « écrit `False` » de « pas écrit ».

Le blueprint `graylog` n'était **pas** enregistré dans l'application de test : aucune de ses routes
n'était joignable par un test HTTP. Ajouté.

**G2 mesurera les deux gestes au navigateur**, sur `test-server` (machine 2), avec `uninstall` comme
geste de retour. `srv-zabbix` : jamais.

---

## E-146 — `adm/` D9b : l'écran conseille explicitement de décocher trois cases, et les livre cochées

**Mesuré** le 2026-08-26 par `tests/e2e/go-adm-sftp.mjs`, sur les deux cibles.

E-142 était une aide qui **disait faux**. Celui-ci est plus net, parce que les aides du legacy disent
**vrai** — et recommandent, chacune, l'inverse de ce qui est livré :

| réglage | ce que l'aide dit | état livré |
|---|---|---|
| `allow_password_auth` | « Décoche : il DOIT utiliser une clé SSH (nettement plus sûr, **recommandé**). » | **coché** |
| `allow_tcp_forwarding` | « Si ce n'est pas nécessaire, **décoche : c'est plus sûr**. » | **coché** |
| `allow_agent_forwarding` | « Si ce n'est pas nécessaire, **décoche**. » | **coché** |

`server_user_sftp.php:97-99`, tous trois en `?? true`. Et `sftp_only` — la restriction qui donne son
nom à la page — est livré **décoché**.

### La mesure : apparier chaque case à SON aide, sans rien recopier

La propriété ne peut pas être « la case X doit être décochée » : ce serait recopier une liste, donc
reproduire le défaut dans l'outil qui le mesure. La suite remonte de **chaque case à son bloc**, y lit
le texte qui l'accompagne, et refuse qu'une aide disant que l'état sûr est l'état inactif accompagne
une case active. Rien n'est recopié — ni la liste des cases, ni le texte des aides.

Mesure legacy : **5 cases lues, 3 fautives.** Portage : **5 cases lues, 0 fautive.**

## E-147 — `sftp_manager.render_policy()` contredit sa propre docstring sur quatre clés, toutes vers le permissif

Dans la **même fonction**, à six lignes d'intervalle. La docstring donne l'exemple de référence, le
code prend les valeurs par défaut :

| clé | docstring | code |
|---|---|---|
| `sftp_only` | `True` | `False` |
| `allow_password_auth` | `False` | `True` |
| `allow_tcp_forwarding` | `False` | `True` |
| `allow_agent_forwarding` | `False` | `True` |
| `x11_forwarding` | `False` | `False` ✓ |

**Quatre écarts sur cinq, tous du côté permissif** — et le cinquième concorde, ce qui montre que la
comparaison ne signale pas tout indistinctement. La suite dérive cette table du fichier lui-même à
chaque exécution ; elle n'en recopie aucune valeur.

### Ce que cela produit, et pourquoi ce n'est pas qu'un réglage mou

Corps réellement intercepté au premier clic sur « Déployer », legacy :

```json
{"sftp_only":false,"chroot_dir":null,"working_dir":null,
 "allow_password_auth":true,"allow_tcp_forwarding":true,
 "allow_agent_forwarding":true,"x11_forwarding":false}
```

`render_policy` en tire un bloc **sans** `ForceCommand internal-sftp`, **sans** `ChrootDirectory`,
**sans** `PermitTTY no` — ceux-là ne sont ajoutés que si `sftp_only`. Ce n'est pas une restriction
SFTP : c'est un shell complet avec tunnels, sur une page intitulée « Accès SFTP ».

> Et un bloc `Match User` **fixe** ces directives pour ce compte, à la place de ce que la configuration
> générale de la machine aurait donné. Sur une machine durcie, déployer ce bloc **élargit** l'accès du
> compte au lieu de le restreindre — le contraire de ce que la page laisse attendre.

**Divergence assumée du portage** : l'état d'une politique neuve est **dérivé**, pas écrit à la main.
`AccesSftp::REGLAGES` classe chaque réglage `restreint` ou `ouvre`, et `initial()` active ce qui
restreint. Ajouter un réglage ne peut donc pas faire naître un défaut permissif par oubli. Le corps
émis par le portage est exactement l'exemple de la docstring :

```json
{"sftp_only":true,"allow_password_auth":false,
 "allow_tcp_forwarding":false,"allow_agent_forwarding":false,"x11_forwarding":false}
```

**E-143 vaut aussi pour SFTP** : le JS est partagé (`server_user_policy.js`, aiguillé par `TYPE`), donc
`deploy` partait au premier clic sans confirmation ici aussi — mesuré, 1 requête. Le portage confirme.

## Ce que la mesure de D9b DÉDOUANE

Mêmes deux constats qu'en D9a, et pour les mêmes raisons : **gardes complètes aux trois niveaux**
(rôle 2 → 403 mesuré) et **geste distant sûr** — `sftp_manager` écrit un temporaire, lance `sshd -t`
pour valider la configuration **complète**, et ne déplace qu'ensuite. Un bloc syntaxiquement invalide
ne peut donc pas fermer l'accès SSH à la machine. `chroot_dir` et `working_dir` passent par
`_validate_path` (absolu, sans traversée), **au backend** — une requête forgée ne le contourne pas.

## Ce que D9b ne porte PAS, et le dit

`rollbackTo()`, comme en D9a : lien marqué `↗` vers l'ancien portail dans l'historique, pas un bouton
inerte. **D9 est clos** — `server_user_policies.php` est une redirection 302 de 16 lignes vers la page
sudo, sans `checkAuth` mais sans rien à divulguer non plus (paramètres castés en entier, cible locale
fixe : pas de redirection ouverte). Elle disparaîtra avec l'archivage.

---

## E-148 — `bashrc/` : un des huit motifs de danger du gabarit est largement inerte

**Mesuré** le 2026-08-26, sous-lot B3.

`legacy/bashrc/js/bashrc.js`, `_TPL_DANGER_PATTERNS`, motif « redirect vers disque » :

```js
{ re: /\b>\s*\/dev\/[sh]d[a-z]/, name: 'redirect vers disque' }
```

**`\b` exige un caractère de MOT immédiatement avant le `>`.** Or un espace et `>` sont tous deux des
non-mots : il n'y a pas de frontière entre eux. La forme normale n'est donc pas reconnue.

| écrit dans le gabarit | reconnu ? |
|---|---|
| `cat x > /dev/sda` — la forme courante | **non** |
| `cat x >/dev/sda` | **non** |
| `echo y >> /dev/sdb` — l'ajout | **non** |
| `x> /dev/sda` — collé | oui |

Le motif ne reconnaît que la forme que personne n'écrit.

### Ce que cela coûte, et ce que cela ne coûte pas

**Ce n'est pas une faille**, pour la même raison qu'en §4.1 de `MODULE-BASHRC.md` : la reconnaissance
n'est pas un contrôle d'accès, et quiconque atteint cet écran détient déjà l'autorisation d'écrire le
fichier. Mais un garde-fou qui rate sept formes sur huit d'un même geste est **pire qu'absent** : il
donne l'impression d'avoir été vérifié.

### Correction du portage

`App\Services\Bashrc::MOTIFS_DANGEREUX` retire le `\b`. Les quatre formes ci-dessus sont reconnues,
et **aucun des huit motifs ne mord sur un gabarit sain** — vérifié motif par motif, chacun contre son
propre exemple et contre un `.bashrc` ordinaire.

> **Piège de vérification, payé au passage.** La première vérification employait
> `preg_match("/$motif/")` — avec des motifs contenant des `/`. Cinq des huit « ne compilaient pas ».
> C'était le délimiteur de l'outil qui cassait, pas les motifs. *Quand une vérification échoue en
> masse, suspecter la vérification.*

---

## E-149 — `services/` : les huit routes n'ont ni rôle ni permission ; seule la PAGE est gardée

**Relevé le 2026-08-27**, sixième occurrence du motif « la garde est sur la page, pas sur la
requête » — et la première non documentée.

| couche | ce qu'elle exige |
|---|---|
| **page** | `checkAuth([USER, ADMIN, SUPERADMIN])` **et** `checkPermission('can_manage_services')` |
| **proxy legacy** | session authentifiée, n'importe quel rôle. `/services/` **absent** de `$ADMIN_ONLY_PREFIXES` |
| **passerelle portage** | `/services/` dans `LISTE_BLANCHE`, **absent** d'`ADMIN_SEULEMENT` |
| **backend, 8 routes** | `@require_api_key`, `@require_machine_access`, `@threaded_route` — **ni rôle, ni permission** |

`check_machine_access()` ouvre par « rôle ≥ 2 : accès à tout ». Pour un rôle 2 ou 3, le seul garde
restant sur la requête est donc `@require_api_key` — **et c'est le proxy qui fournit cette clé**.

### Lu, puis mesuré — et la mesure change la portée

Le tableau ci-dessus est **lu**. Ce qui suit est **mesuré en base le 2026-08-27** :

```
comptes de rôle 2 au parc : 1   dont avec la permission : 1
rw-test-user   rôle 1  permission=0  et AUCUNE machine dans user_machine_access
rw-test-admin  rôle 2  permission=1
rw-test-super  rôle 3  permission=0  (le rôle 3 contourne légitimement)
```

> **Le trou est réel dans le code, et n'est exploitable par aucun compte existant aujourd'hui.**

Le seul compte de rôle 2 détient la permission ; le compte de rôle 1 qui ne l'a pas est arrêté par
`@require_machine_access`, qui pour lui n'est **pas** inerte. Même situation que le repli
`NOPASSWD: ALL` de `ssh/` : à un `UPDATE` d'être exploitable.

Trois gestes d'administration **ordinaires** le rendraient vivant : créer un admin au périmètre
restreint, retirer la permission au compte existant, ou donner un accès machine à un rôle 1.

### Pourquoi ce n'est pas corrigé ici

C'est un correctif de sécurité, et la convention du dépôt les veut sur une branche dédiée, jamais
fusionnés sans accord verbal. La seule correction qui ferme le trou pour **les deux** portails —
`@require_permission` sur les huit routes — **touche le backend de production**.

Porté au §7 du plan, avec E-142, E-144 et E-147 : **quatre correctifs backend attendent le même
arbitrage**, et trois d'entre eux sont la même famille — un garde absent ou un repli permissif.

---

## E-150 — `services/` : la liste des services protégés ne connaît que la forme `.service`

**Calculé le 2026-08-27** — le vrai calcul de `base`, exécuté contre la vraie liste du module.

`backend/routes/services.py`, aux **cinq** routes mutantes :

```python
base = service.replace('.service', '')
if base in PROTECTED_SERVICES:      # ['sshd','ssh','systemd-journald','systemd-logind','dbus','dbus-broker']
    return jsonify({'success': False, 'message': f'Service protege : {base}'}), 403
```

La liste ne contient que des noms **de service**. systemd, lui, pilote le même démon par plusieurs
types d'unités :

| unité demandée | `base` calculé | protégé ? |
|---|---|---|
| `ssh` · `sshd` · `ssh.service` · `sshd.service` | `ssh` / `sshd` | **oui** |
| **`ssh.socket`** | `ssh.socket` | **non** |
| **`sshd.socket`** | `sshd.socket` | **non** |
| **`ssh@.service`** | `ssh@` | **non** |
| **`systemd-journald.socket`** | `systemd-journald.socket` | **non** |

`_SAFE_SERVICE_RE` (`^[a-zA-Z0-9@._:-]+$`) laisse passer toutes ces formes.

### Ce que cela coûte

Sur un hôte à **activation par socket** — le défaut sur les Debian récentes —, `systemctl stop
ssh.socket` empêche toute nouvelle connexion SSH. **Y compris celle par laquelle RootWarden pilote la
machine.** Le module se couperait de sa propre cible, et la protection qui existe précisément pour
l'empêcher ne s'y opposerait pas.

### Ce qui est établi, et ce qui ne l'est pas

- **Établi par calcul** : les formes ci-dessus ne sont pas protégées. Ce n'est pas une lecture — le
  calcul a été exécuté contre le module réel.
- **Non établi** : que `ssh.socket` soit présent et actif sur les machines du parc. La vérification
  distante n'a pas abouti faute d'identifiant, et **on n'en fabrique pas**. La gravité réelle dépend
  donc d'un fait non mesuré.

C'est la même discipline qu'E-149 et que le repli `NOPASSWD: ALL` de `ssh/` : dire ce qui est prouvé,
et dire ce qui ne l'est pas.

### Ce que ce module fait BIEN, et qui rend ce défaut d'autant plus notable

**La protection est appliquée sur la REQUÊTE, aux cinq routes mutantes — pas seulement à l'écran.**
Le JS désactive aussi les boutons (`svc.protected ? 'disabled …'`). **Les deux couches gardent**, ce
qui est la première fois dans tout ce chantier. Le défaut n'est pas l'absence de garde : c'est que la
garde compare des noms là où systemd raisonne en unités.

### Correction

Normaliser vers l'unité, pas vers le nom : comparer sur le radical **avant le premier point**
(`ssh.socket` → `ssh`), ou étendre la liste aux types d'unités. La première ferme la famille entière ;
la seconde n'en ferme que ce qu'on a pensé à écrire.

**Touche le backend de production.** Porté au §7 avec E-142, E-144, E-147 et E-149 : **cinq
correctifs backend attendent le même arbitrage.**

---

## E-151 — `services/` : l'état au démarrage replie quatre valeurs de systemd sur deux

**Mesuré** le 2026-08-27 par `go-services-s3.mjs`, sur une énumération **servie** (voir plus bas).

systemd distingue quatre états de fichier d'unité — `enabled`, `disabled`, `static`, `masked`. Le
legacy n'en affiche que deux :

| unité | `unit_file_state` | legacy affiche | portage affiche |
|---|---|---|---|
| `nginx` | `enabled` | Active au boot | activé |
| `postfix` | `disabled` | Desactive | désactivé |
| `dbus` | **`static`** | **Desactive** | **statique** |
| `telnet` | **`masked`** | **Desactive** | **masqué** |

**Les trois derniers s'affichent pareil**, et ils ne veulent pas dire la même chose :

- **`static`** n'a pas d'interrupteur : systemd la lance quand une autre unité en a besoin. La dire
  « désactivée » suggère qu'on pourrait l'activer — on ne peut pas, et le legacy le sait puisqu'il
  n'offre pas le bouton.
- **`masked`** est activement bloquée : systemd *refusera* de la démarrer. La dire « désactivée »
  laisse croire qu'un « Démarrer » suffirait.

L'information existe, elle traverse le réseau, et l'affichage la perd. Même famille que le
`custom_detected` de `bashrc/` §4.5 : **une mesure vraie que l'interface abandonne.**

### Ce que la mesure a coûté à établir

Le banc n'ayant **pas de systemd**, aucune des deux cibles ne rend jamais de ligne : le défaut était
invisible et l'est resté pendant tout S2. Il n'a été vu qu'en **servant** une énumération synthétique
à la place de la vraie — le filet répond à `/services/list` au lieu de transmettre, et tout le chemin
de rendu s'exécute pour de vrai, sans qu'aucune machine ne soit jointe.

> Un portage mesuré uniquement sur un tableau vide est un portage largement non mesuré. **Deux
> défauts du portage y avaient vécu** — le champ lu sous le nom `enabled` au lieu de
> `unit_file_state`, et traité comme un booléen alors qu'il porte cinq valeurs.

---

## E-152 — `iptables/` et `fail2ban/` : sur 23 routes, DEUX portent une permission

**Relevé** par `MODULE-FILTRAGE.md` §1 ; **numéroté le 2026-08-27**, l'inventaire ne lui ayant jamais
donné d'entrée de parité. **Septième occurrence** du motif « la garde est sur la page, pas sur la
requête », et la plus large mesurée jusqu'ici.

| couche | ce qu'elle exige |
|---|---|
| **pages** | `checkAuth([USER, ADMIN, SUPERADMIN])` **et** `checkPermission('can_manage_iptables'/'can_manage_fail2ban')` |
| **proxy** | `/iptables`, `/iptables-` et `/fail2ban/` **absents** de `$ADMIN_ONLY_PREFIXES` |
| **backend, 23 routes** | **deux** portent un `@require_permission` — `/iptables-rollback` et `/fail2ban/geoip` |

> **La protection la plus forte est posée sur les deux actions les plus faibles.** `/fail2ban/geoip`
> est une lecture qui n'ouvre aucune session SSH, et c'est la **seule** route fail2ban gardée ;
> `/fail2ban/ban`, `/enable_jail` et `/whitelist` — qui écrivent **et redémarrent le service** — n'ont
> ni rôle ni permission. Symétriquement, `/iptables-rollback` exige la permission alors que
> `/iptables-apply`, qui fait la même chose avec des règles **arbitraires**, non.

Un compte authentifié sans `can_manage_iptables` peut donc `POST /iptables-apply` et réécrire
`/etc/iptables/rules.v4` sur une machine de son périmètre.

### Le rôle, lui, est un choix ASSUMÉ

`CHANGELOG.md:3078-3085` arbitre explicitement : « un rôle 1 inscrit dans `user_machine_access` est
opérateur de ses machines ». Ce n'est donc pas le rôle qui pose problème — **c'est la permission, qui
n'existe qu'à l'affichage.**

### Deux en-têtes qui mentent, et le journal qui le prouve

`iptables/index.php:14` annonce « superadmin (role_id = 3) **uniquement** — accès refusé à tous les
autres rôles » ; `:45` admet `ROLE_USER`. `fail2ban/index.php:5` annonce « admin (2), superadmin
(3) » ; `:10` admet `ROLE_USER`. **Troisième et quatrième occurrences du motif E-36.**

Aucun compte d'épreuve ne permet de le montrer par un clic — `rw-test-user` n'a pas la permission,
donc il est refusé, mais **par la permission**. `go-fail2ban-f1.mjs` le prouve **indirectement** : le
refus est journalisé « Permission refusee : can_manage_fail2ban », or un refus par *rôle* ne passe
jamais par `checkPermission`. Trouver cette ligne après le 403 établit que `checkAuth` a laissé passer
le rôle 1 — celui que l'en-tête dit exclu. La suite nomme cette mesure comme indirecte.

### Correction, et à qui elle appartient

`@require_permission` sur les 21 routes qui en manquent, et `/iptables`, `/iptables-`, `/fail2ban/`
dans les deux listes « admin ». **Touche le backend de production.** Porté au §7 avec E-142, E-144,
E-147, E-149 et E-150 : **six correctifs backend attendent le même arbitrage**, et cinq sont la même
famille — un garde absent, ou un repli qui retombe du côté permissif.

---

## E-153 — Un historique vide se CACHE, et l'échec lui ressemble

`loadHistory` (`legacy/fail2ban/js/main.js:287`) et `loadStats` (`:560`) sortent par `return` dès que
la réponse est vide :

```js
if (!d.success || !d.history || d.history.length === 0) return;
```

Les sections `#history-section` et `#stats-section` restent donc `hidden`, **et rien à l'écran ne
nomme l'absence**. « Aucun ban n'a jamais été enregistré sur cette machine » et « la lecture a
échoué » produisent **exactement le même écran** : rien.

Les deux fonctions se terminent d'ailleurs par un `catch (_) {}` — un échec est avalé sans un mot.

Mesuré le 2026-08-27 par `go-fail2ban-f2` : sur une table vide, `histoVisible = false`,
`friseVisible = false`, et aucun mot du texte de la page ne nomme l'absence.

**Le portage doit un état vide qui dit ce qui manque ET pourquoi** (`.rw-vide`), et distinguer
« rien à montrer » de « la lecture a échoué ».

---

## E-154 — Le tableau tronque à 50 lignes sans le dire

`GET /fail2ban/history` (`backend/routes/fail2ban.py:313`) porte `LIMIT 50`. `loadHistory` rend ce
qu'il reçoit, sans jamais demander le total ni signaler qu'il en manque.

Mesuré : **60 lignes en base, 50 rendues**, et le texte de la section ne contient aucun mot de
troncature. Rien à l'écran ne distingue « tout l'historique de cette machine » de « les 50 derniers
événements ». Sur une machine active, un historique de bans dépasse 50 en quelques heures.

C'est la forme la plus coûteuse du silence : la page **paraît** exhaustive.

**Le portage doit annoncer la troncature** — et donner le total, qui coûte un `COUNT(*)`.

---

## E-155 — La frise : la hauteur et l'échelle ne mesurent pas la même grandeur

`loadStats` (`main.js:575-577`) :

```js
const maxVal = Math.max(1, ...Object.values(days).map(d => d.ban + d.unban));
const h = Math.max(4, (counts.ban / maxVal) * 100);
```

**L'échelle compte les bans ET les débans ; la hauteur ne compte que les bans.** Une barre est donc
systématiquement plus basse que son échelle ne le laisse croire, et l'écart grandit avec la part de
débans.

Mesuré le 2026-08-27 sur une donnée d'épreuve de trois jours :

| jour | événements | hauteur attendue | hauteur rendue |
|---|---|---|---|
| J-3 | 6 (0 ban, 6 déban) | 15 % | **4 %** (le plancher), et **en vert** |
| J-2 | 40 (40 bans) | 100 % | 100 % |
| J-1 | 14 (5 bans, 9 débans) | 35 % | **12,5 %** |

Pire écart : **22,5 points**. Un classement des barres ne voit rien — les deux ordres coïncident ;
c'est la **proportion** qui diverge.

Le jour J-3 est le plus parlant : six débans, et la frise le rend au plancher, **en vert**, comme un
jour où il ne s'est rien passé. Une intervention de déban en masse y devient invisible.

**Second défaut de la même frise** : elle ne porte **aucun repère de date visible**. Les dates ne
vivent que dans l'attribut `title` — donc au survol : invisibles au doigt, invisibles à un lecteur
d'écran, invisibles sur une capture. Une frise de 30 jours sans axe ne se lit pas.

---

## E-156 — L'historique est en BASE, et une machine injoignable le masque

`loadStatus` (`main.js:66-67`) sort avant tout :

```js
const d = await apiPost('/fail2ban/status', serverPayload(srv));
if (!d.success) { appendLog(__('error_with_msg', {msg: d.message})); return; }
```

et n'appelle `loadHistory` / `loadStats` **qu'à la fin de son succès** (`:123-124`). Or ces deux
routes sont des `SELECT` sur `fail2ban_history` : **elles ne joignent aucune machine**.

Conséquence : une machine éteinte, injoignable, ou dont fail2ban est cassé **masque son propre
historique de bans** — précisément la situation où on vient le consulter.

Mesuré : avec un relevé de statut en échec, **zéro** lecture d'historique part, et la section reste
cachée alors que 60 lignes l'attendent en base.

**Le portage doit charger l'historique et la frise indépendamment du relevé.**

---

## E-157 — La colonne « Par » affiche un numéro — la moitié non corrigée d'un défaut connu

`_log_ban_action` (`backend/routes/fail2ban.py:106`) reçoit
`request.headers.get('X-User-ID', 'admin')` : `performed_by` contient donc **l'identifiant numérique**
de l'utilisateur, ou la chaîne littérale `'admin'` en repli. La colonne affiche `16`, `7`, `3`.

Mesuré : valeurs distinctes rendues à l'écran — **`16` et `admin`**.

Ce défaut a été **corrigé dans `iptables`**, avec un commentaire de huit lignes qui l'explique, et
laissé tel quel dans `fail2ban`. C'est la sixième occurrence du motif « à moitié corrigé » relevée
sur ce chantier : quelqu'un rencontre un défaut, le nomme, et n'en protège qu'une branche.

Le repli `'admin'` aggrave : il n'est pas un identifiant, et **rien ne le distingue d'un compte
réellement nommé `admin`**.

**Le portage doit résoudre l'identifiant en nom**, et dire explicitement quand il n'y parvient pas
plutôt que d'afficher un numéro brut.

---

## E-158 — La page `fail2ban/` ne suit pas la langue de l'interface, à deux endroits

La bascule fonctionne — mesuré : l'intitulé passe de « Historique des bans » à « Ban history ». Mais
deux valeurs restent écrites en dur :

- **`<html lang="fr">`** (`legacy/fail2ban/index.php:24`). La page en anglais se déclare française à
  toute technologie d'assistance. **Deuxième occurrence** du défaut déjà relevé en E-111 sur la page
  des notifications, là où `adm/audit_log.php:122` fait pourtant `<html lang="<?= getLang() ?>">` ;
- **`toLocaleString('fr-FR')`** (`main.js:298`). Mesuré : interface en anglais, date rendue
  `26/08/2026 03:59:44`. L'inventaire du module notait déjà que `fmtLocalDate` existe et n'est pas
  utilisé ici.

---

## E-159 — La frise ne s'affiche pas du tout : `h-32` est purgée, et 100 % de zéro fait zéro

E-155 décrit ce que la frise **dirait** si elle s'affichait. Elle ne s'affiche pas.

`legacy/fail2ban/index.php:210` : `<div id="stats-chart" class="flex items-end gap-1 h-32">`. La
hauteur du cadre vient de la classe Tailwind `h-32` — **absente du CSS compilé**. Le cadre a donc une
hauteur de **0 px**, et les barres, dont la hauteur est exprimée en **pourcentage**
(`bar.style.height = h + '%'`), se résolvent contre zéro.

Mesuré le 2026-08-27, sur le style **calculé** :

| | déclaré | rendu |
|---|---|---|
| cadre `#stats-chart` | `h-32` (8 rem) | **0 px** |
| barre J-3 | `4%` | **0 × 360 px** |
| barre J-2 | `100%` | **0 × 360 px** |
| barre J-1 | `12.5%` | **0 × 360 px** |

À l'écran, la carte « Statistiques » n'affiche que son titre. **Elle est vide, et elle a l'air
normale** : rien ne signale qu'un contenu manque.

**Quatrième occurrence** de la même famille dans ce projet — après la pastille KEV à 1,06:1, et deux
autres. Le motif est toujours le même : le HTML est juste, la classe est juste, **PurgeCSS ne garde
que ce qu'il a vu**, et aucune assertion sur le DOM ne peut le voir.

Et il a piégé la mesure autant que la page : la première rédaction de `go-fail2ban-f2` lisait
`b.style.height`, donc « 100% », et concluait que la barre était haute. **C'est la capture qui a
montré la carte vide.** Une suite mesure désormais `getBoundingClientRect().height`.

**Le portage n'exprime pas une hauteur en pourcentage d'un parent dont la hauteur vient d'une classe
utilitaire.**

---

## E-160 — La frise annonce 30 jours et n'en dessine que les jours actifs : l'axe horizontal ne mesure pas le temps

`GET /fail2ban/stats` groupe par jour (`GROUP BY DATE(created_at)`) : **les jours sans événement ne
sont pas rendus**. Le frontend dessine donc une barre par ligne reçue, réparties à largeur égale.

Conséquence : avec trois jours actifs sur trente, la frise affiche **trois barres occupant chacune un
tiers de la largeur**, sous un titre qui annonce « 30 jours ». Trois journées consécutives et trois
journées espacées de dix jours produisent **la même image**. L'axe vertical mesure une quantité,
l'axe horizontal ne mesure rien.

Présent **des deux côtés** — le portage a hérité de la forme du legacy. Relevé le 2026-08-27, à
l'image, pendant le portage de F2.

**Non corrigé, et c'est une décision assumée.** F2 s'était donné sept écarts (E-153 à E-159), tous
refermés et mesurés verts sur les deux cibles. Corriger celui-ci demande de construire la plage de
trente jours côté client et de rendre les jours vides — ce qui casse l'assertion « une barre par
jour » de `go-fail2ban-f2`, et la reformuler proprement (« une barre par jour ACTIF », lisible de la
même façon sur les deux cibles) demandait une mesure contournée. **Cinq faux PASS ont été écrits dans
cette suite en un tour**, tous nés d'une mesure contournée : élargir maintenant reviendrait à en
écrire un sixième.

À reprendre avec F3, où la frise sera de toute façon retouchée.

---

## E-161 — Un fichier ABSENT s'affiche comme le contenu du fichier

Les deux commandes distantes de F3 se terminent par un repli du shell :

```sh
cat /etc/fail2ban/jail.local 2>/dev/null || echo "[FICHIER ABSENT]"
tail -n <n> /var/log/fail2ban.log 2>/dev/null || echo "[LOG ABSENT]"
```

`loadConfig` (`main.js:274`) et `loadF2bLogs` (`:531`) posent ce retour dans le **même `<pre>` vert
sur noir** qu'une vraie configuration ou de vraies lignes de journal. À l'écran, sous un titre
`/etc/fail2ban/jail.local`, on lit :

```
[FICHIER ABSENT]
```

**Le marqueur du shell devient le contenu du fichier.** Rien ne distingue « voici la configuration »
de « il n'y en a pas », et un opérateur qui ne connaît pas ce marqueur peut le prendre pour une
directive. Mesuré le 2026-08-27 sur la machine d'essai, qui n'a pas fail2ban : les deux marqueurs
sont rendus tels quels.

**Le portage doit distinguer l'absence du contenu**, et le dire dans la langue de l'interface plutôt
qu'avec une chaîne fabriquée par un `echo` distant.

---

## E-162 — Deux notions de « la machine » dans la même page : douze gestes sur treize visent celle du DERNIER RELEVÉ

`loadConfig` (`main.js:266`) lit `getServer()` — la machine **du sélecteur**. Tous les autres gestes
du module lisent `_currentServer`, posé au dernier relevé **réussi** (`:60`) :

| lit `getServer()` | lisent `_currentServer` |
|---|---|
| voir `jail.local` | détail d'une jail · bannir · débannir · services détectés · activer une jail · désactiver une jail · liste blanche (lire, ajouter, retirer) · tout débannir · voir les journaux |
| **1 appel** | **12 appels** (`:139 :235 :252 :319 :396 :417 :433 :457 :467 :479 :525`) |

Relever sur A, changer le sélecteur pour B, et **tout agit sur A pendant que l'écran montre B**.

Mesuré le 2026-08-27, dans le sens **sûr** — relevé sur la machine d'essai, sélecteur basculé sur
`srv-zabbix` :

> le sélecteur affiche « srv-zabbix (192.168.0.244:22) » et la requête part vers la machine **2**

Le sens inverse — relever sur la production puis sélectionner la machine d'essai — enverrait
**bannir, désactiver une jail et vider la liste blanche vers la production** alors que l'écran
montrerait la machine d'essai. Il n'a pas été exercé, et ne doit pas l'être.

Les `confirm()` nomment `_currentServer.name`, donc **la confirmation dit vrai** : c'est le sélecteur
qui ment. Mais un opérateur lit le sélecteur, et une confirmation se lit vite.

**Le portage n'a qu'une seule notion de « la machine » : celle que le sélecteur affiche.**

---

## E-163 — `:count` n'est jamais substitué, dans les deux langues

`legacy/lang/fr/js.php:53` et `:61`, `legacy/lang/en/js.php:56` et `:72` :

```php
'js.f2b_jails_found'       => ':count jail(s) trouves',
'js.f2b_services_detected' => ':count service(s) detecte(s)',
```

et les appels, `main.js:117` et `:372` :

```js
__('f2b_jails_found',       {jails: d.jails.length, ips: ...})
__('f2b_services_detected', {installed, enabled})
```

**Le nom `:count` ne correspond à aucun paramètre passé.** La substitution n'a donc jamais lieu, et
l'écran affiche littéralement `:count jail(s) trouves`. Quatre valeurs sont calculées — le nombre de
jails, le total d'IP bannies, le nombre de services installés, le nombre activés — **pour être
jetées**.

Vu à l'image, puis mesuré : une assertion cherche désormais tout `:mot` isolé dans le texte rendu.
Présent en **FR et en EN** : une relecture de l'un des deux catalogues n'aurait rien montré, puisque
les deux portent la même faute.

---

## E-164 — Un `lines` non numérique rend un 500 HTML, pas un refus

`backend/routes/fail2ban.py:537` :

```python
data = request.get_json(silent=True) or {}
lines = int(data.get('lines', 50))     # <-- hors du `try`
ip, port, ... = _resolve_ssh_creds(data)
```

Le cast est **avant** le `try` de la route. Une valeur non numérique y lève une `ValueError` que rien
n'attrape : Flask rend une page **HTML** « 500 Internal Server Error » — pas même du JSON, donc le
frontend échoue aussi à la lire.

Mesuré le 2026-08-27 par une requête forgée depuis la page (`lines: "beaucoup"`) : **statut 500**,
corps `<!doctype html> … <title>500 Internal Server Error</title>`.

Deux remarques :

- **rien n'est joint** : le cast échoue avant `_resolve_ssh_creds`, donc avant toute session SSH.
  L'effet se limite au statut rendu ;
- **la borne existe déjà**, mais ailleurs : `get_fail2ban_logs` fait
  `max(10, min(500, int(lines)))` (`fail2ban_manager.py:253`). La route double donc une validation
  qu'elle fait moins bien que le manager — et c'est sa copie qui casse.

Une faute de la requête est rendue comme un défaut du serveur.

**CORRIGÉ dans le backend le 2026-08-27 (`v1.38.4`).** Le cast est passé dans un `try`, et une valeur
non numérique rend désormais **400** avec un message JSON. C'est §3.2 du plan qui l'autorise — « les
modifications backend et legacy sont autorisées, ne plus bloquer, ne plus demander » — et ce
correctif n'est **pas** de la même nature que les six qui attendent un arbitrage : ceux-là sont des
gardes d'accès manquantes, celui-ci une validation d'entrée. Mesuré après coup : **400**, sur les
deux portails, puisqu'ils partagent le backend.

---

## E-165 — Une réussite annoncée sans être vérifiée, et une table d'audit qui enregistre ce qui n'a pas eu lieu

`fail2ban_ban` (`backend/routes/fail2ban.py:211`), `fail2ban_unban` (`:240`) et
`fail2ban_unban_all` (`:456`) reçoivent le code de retour de la commande distante et **ne le testent
jamais** :

```python
out, stderr, rc = ban_ip(client, root_pass, jail, target_ip)
_log_ban_action(mid, jail, target_ip, 'ban', ...)          # inconditionnel
return jsonify({'success': True, 'message': f'{target_ip} banni dans {jail}', 'output': out})
```

Les deux routes voisines — `/install` et `/restart` — testent `rc`. **L'incohérence est interne au
fichier.**

Mesuré le 2026-08-27 sur la machine d'essai, qui n'a pas fail2ban :

| | |
|---|---|
| la page annonce | « 203.0.113.7 banni dans sshd » |
| sa propre liste d'adresses bannies, rechargée juste après | **ne contient pas** l'adresse |
| `fail2ban_history` | **1 ligne créée** — `ban │ 203.0.113.7 │ 16` |

Deux vérités sur le même écran, à une ligne d'intervalle — et une **table d'audit qui affirme qu'un
ban a eu lieu sur une machine où fail2ban n'est même pas installé**. C'est la forme la plus coûteuse
de ce défaut : un journal d'audit ne se relit pas, on lui fait confiance.

La preuve se lit **sur la page**, sans rien savoir du backend : `banIp` recharge le détail du jail
juste après, et cette liste est le second témoin.

**Le portage n'annonce une réussite qu'après l'avoir vérifiée**, et n'inscrit une ligne d'audit que
pour un geste qui a abouti — ou l'inscrit comme un échec, ce qui est encore un fait.

---

## E-166 — Les deux gestes les plus destructeurs sont les seuls à avoir perdu leur couleur d'alerte

Le panneau de détail d'une jail aligne **trois boutons destructeurs**, alimentés par le **même**
champ d'adresse :

| bouton | portée | classe | fond **rendu** |
|---|---|---|---|
| « Ban » | la machine choisie | `bg-red-600` | `rgb(220, 38, 38)` |
| « Ban global » | **TOUTES les machines, production comprise** | `bg-red-800` | **`rgba(0, 0, 0, 0)`** |
| « Débannir tout » | vide la jail entière | `bg-orange-600` | **`rgba(0, 0, 0, 0)`** |

**Le seul bouton qui garde sa couleur d'alerte est le moins dangereux des trois.** `bg-red-800` et
`bg-orange-600` sont absentes du CSS compilé — PurgeCSS ne garde que ce qu'il a vu — et les deux
gestes qui touchent la production ou détruisent en masse sont rendus **sans fond**.

**Cinquième occurrence** de la famille « classe purgée » sur ce chantier, et la première où elle
retire un signal de **danger**. Aucune assertion sur le DOM ne peut le voir : le HTML porte bien
`bg-red-800`.

S'y ajoute la géométrie, mesurée : « Ban » et « Ban global » sont à **8 px** l'un de l'autre, de même
forme et de même taille. Le geste qui atteint tout le parc est **entre** les deux qui ne l'atteignent
pas, et rien ne l'annonce que son libellé.

**Le portage sépare le geste de parc du geste local**, et ne fait pas dépendre un avertissement d'une
classe utilitaire.

---

*Note sur E-163* — troisième occurrence relevée le 2026-08-27 : le panneau de détail d'une jail
affiche « Jail **:name** ». `legacy/lang/fr/js.php:56` écrit `:name`, `main.js:142` passe `{jail}`.
Même faute que `:count`, sur un troisième message.

---

## E-167 — Une confirmation destructrice qui ne nomme ni l'adresse, ni la jail, ni la machine

`banIp` (`main.js:236`) passe les trois valeurs à la traduction :

```js
if (!confirm(__('f2b_confirm_ban', {ip, jail, server: _currentServer.name}))) return;
```

et les catalogues les ignorent **toutes les trois** :

```php
'js.f2b_confirm_ban'       => 'Bannir cette IP ?',            // fr
'js.f2b_confirm_unban'     => 'Debannir cette IP ?',
'js.f2b_confirm_unban_all' => 'Debannir TOUTES les IPs de ce jail ?',
```

Mesuré le 2026-08-27 : la boîte native affiche **« Bannir cette IP ? »**.

**Quatrième occurrence du motif d'E-163** — des paramètres passés, jamais utilisés — et la seule où
elle n'est pas cosmétique. On confirme un geste destructeur **sans savoir sur quelle adresse ni sur
quelle machine il porte**, alors qu'E-162 vient de montrer que la machine peut différer de celle
qu'affiche le sélecteur. Une boîte native ne peut d'ailleurs rien montrer de plus : elle tient en une
ligne et s'accepte au réflexe.

**FERMÉ au portage (`v1.38.6`)** — un panneau **en page**, qui nomme et qui explique ce que le geste
engage :

> « Bannir 203.0.113.7 sur Test-Server-Debian ? L'adresse 203.0.113.7 sera bannie dans la jail sshd,
> sur Test-Server-Debian **et sur elle seule**. Toute connexion venant de cette adresse sera refusée
> jusqu'à expiration du ban. »

---

*Note sur E-165* — **CORRIGÉ dans le backend le 2026-08-27 (`v1.38.6`).** Les trois routes testent
désormais le code de retour : un échec rend `success: false` avec la sortie de la commande et son
`exit_code`, et **n'écrit aucune ligne d'audit** — c'est correct, rien n'a eu lieu. §3.2 du plan
l'autorise. Re-mesuré après coup, sur le legacy comme sur le portage : le geste rend « n'a PAS été
banni », et `fail2ban_history` reste à **0 ligne**.

*Note sur E-166* — **FERMÉ au portage (`v1.38.6`)** : le geste de parc n'est pas rendu — il appartient
à F6 — et les deux gestes destructeurs de la page tirent leur couleur des **jetons du socle**, pas
d'une classe utilitaire. Mesuré : plus aucun bouton destructeur sans fond peint. **Reste ouvert côté
legacy**, où `bg-red-800` et `bg-orange-600` demeurent purgées.

---

## E-168 — La liste blanche affichée est SUPPOSÉE, pas lue

`manage_whitelist` (`fail2ban_manager.py:207-212`) lit la ligne `ignoreip` du `jail.local` distant.
Si elle est absente, il **suppose** :

```python
else:
    current_ips = ['127.0.0.1/8', '::1']
```

et rend cette liste comme si elle venait de la machine. Mesuré le 2026-08-27 sur le banc, dont le
`jail.local` **n'existe pas** : l'écran affiche `127.0.0.1/8` et `::1`, et **rien ne dit que ces deux
entrées sont une hypothèse**.

Un opérateur lit donc une liste blanche qui n'existe nulle part sur la machine — et il en tirera
qu'il n'a pas besoin d'y ajouter `127.0.0.1`.

**FERMÉ au portage (`v1.38.8`).** Le backend porte désormais un drapeau `lue` : c'était la seule
façon honnête de trancher, puisque **le deviner reviendrait à comparer la liste au défaut, donc à
supposer à son tour**. L'écran dit soit « Lue dans /etc/fail2ban/jail.local sur <machine> », soit
« Cette liste est SUPPOSÉE, pas lue » avec ce que cela implique.

---

## E-169 — Une des deux entrées par défaut porte un `×` qui ne peut JAMAIS aboutir

`_validate_ip` (`fail2ban_manager.py:26`) appelle `ipaddress.ip_address(ip)`. **Un CIDR y lève une
`ValueError`.** Or `127.0.0.1/8` *est* un CIDR — et c'est l'une des deux entrées qu'E-168 affiche par
défaut.

Son `×` envoie donc une requête que le backend refuse **toujours**. Mesuré : la requête part, la
liste reste inchangée, et le journal de la page affiche `Exception : Error: H…` — pas même un refus
lisible.

Trois choses en une :

- **un geste est offert alors qu'il ne peut pas aboutir** ;
- il est offert sur une entrée **supposée**, donc sur quelque chose qui n'existe pas ;
- et le refus arrive **après** la confirmation, en fin de course.

Le refus lui-même est correct — `127.0.0.1/8` n'est pas une adresse. C'est de l'**offrir** qui ne
l'est pas.

**FERMÉ au portage (`v1.38.8`).** Une entrée qui ne peut pas être retirée ne porte pas de bouton :
elle porte la **raison**. Deux cas, dits séparément — une entrée *supposée* n'est pas dans le fichier,
donc il n'y a rien à en retirer ; une entrée qui est un *réseau* ne sera jamais acceptée par
`_validate_ip`. La règle du portage est celle du backend, pas une approximation.

---

## E-170 — Le geste qui affaiblit la protection est le seul à ne pas confirmer, et aucun des deux ne dit que le service REDÉMARRE

`manage_whitelist` finit par `restart_fail2ban(client, root_password)`. Ajouter **ou** retirer une
exemption **redémarre fail2ban** — et un redémarrage **lâche tous les bans en cours**.

| geste | effet | confirmation |
|---|---|---|
| `addWhitelistIp` — **ajoute** une exemption | réécrit `jail.local`, redémarre | **aucune** |
| `removeWhitelistIp` — **retire** une exemption | réécrit `jail.local`, redémarre | `confirm()` |
| `submitEnableJail` — active une jail | réécrit `jail.local`, redémarre | **aucune** |

**Le seul geste qui confirme est celui qui RENFORCE la protection.** Les deux qui l'affaiblissent —
exempter une adresse, et réécrire une configuration — passent sans un mot.

Et **aucun des trois n'annonce le redémarrage**. Mesuré : la fenêtre de réglages d'une jail propose
trois nombres (`maxretry`, `bantime`, `findtime`) et ne dit ni qu'elle va écrire un fichier, ni que
le service va redémarrer.

**FERMÉ au portage (`v1.38.8`).** Les trois gestes confirment, et les trois annoncent le
redémarrage — l'avertissement de la fenêtre de réglages est **avant** les champs, pas après :
« ⚠ Activer une jail RÉÉCRIT /etc/fail2ban/jail.local et REDÉMARRE le service : tous les bans en
cours sur cette machine seront perdus. »

---

## E-171 — L'interpolation brute de `manage_whitelist` — RELEVÉ PAR LECTURE, NON MESURÉ

```python
f"grep -q '\\[DEFAULT\\]' /etc/fail2ban/jail.local && "
f"sed -i '/\\[DEFAULT\\]/a\\{new_line}' /etc/fail2ban/jail.local || "
f"printf '%s\\n' '{base64.b64encode(...)}' | base64 -d | ..."
```

`new_line` vaut `'ignoreip = ' + ' '.join(current_ips)`, et `current_ips` contient **les adresses
déjà présentes dans le fichier distant**, lues par un `grep` et découpées **sans aucune validation**.
Une apostrophe dans la ligne `ignoreip` de `jail.local` ferme le littéral shell.

**La branche de secours du même `||` passe, elle, par base64.** Une branche sur deux : quelqu'un a vu
le problème et n'en a protégé qu'une — sixième occurrence du motif « à moitié corrigé ».

**Ce défaut n'a PAS été mesuré, et c'est délibéré.** Le démontrer exigerait d'écrire une apostrophe
dans le `jail.local` d'une machine réelle, c'est-à-dire de **le commettre**. Même règle qu'en
`services/` S3, où `stop ssh.socket` n'a pas été forgé.

Portée réelle, dite honnêtement : l'exploitation suppose d'avoir **déjà** écrit dans `jail.local`,
donc **pas d'escalade depuis le portail**. C'est une élévation de « j'écris un fichier de
configuration » à « j'exécute du root au prochain passage de RootWarden ».

**Le portage ne peut pas refermer celui-ci** : la composition vit dans le backend. Porté au §7 avec
les autres correctifs backend.

---

## E-172 — La portée d'un geste de parc est décidée par un CACHE, et « jamais relevée » y compte comme « fail2ban absent »

`install_all` (`backend/routes/fail2ban.py:653`) choisit ses cibles ainsi :

```sql
FROM machines m
LEFT JOIN fail2ban_status f ON m.id = f.server_id
WHERE f.installed IS NULL OR f.installed = 0
```

Une machine **jamais relevée** n'a pas de ligne dans `fail2ban_status`. Le `LEFT JOIN` rend donc
`NULL` — et `NULL` passe le `WHERE`. **Ne l'avoir jamais regardée suffit à la faire installer.**

Mesuré le 2026-08-27, avec le SQL exact de la route :

> « installer sur tout le parc » toucherait : **`srv-zabbix` (PROD)** · `OpenCVE-Test-OnPrem` (DEV)

`srv-zabbix` est la machine de production que toutes les suites de ce chantier ont pour consigne de
ne jamais joindre. Elle est dans la portée **parce qu'elle n'a jamais été relevée**.

`ban_all_servers` (`:531`) fait l'inverse — `INNER JOIN … WHERE f.running = 1` — donc les machines
que le cache dit **actives**. Mesuré : `(aucune)`, le cache datant du **2026-08-12**, quinze jours
plus tôt. Une machine dont fail2ban est tombé depuis serait quand même visée ; une machine installée
depuis serait ignorée.

**Le parc atteint par un geste irréversible est décidé par un relevé qui peut avoir des semaines**, et
l'écran ne le dit pas.

---

## E-173 — Les confirmations des gestes de parc ne nomment ni l'adresse, ni le nombre, ni les machines

Mesuré, boîte native par boîte native :

| geste | corps réellement envoyé | ce que la confirmation dit |
|---|---|---|
| bannir sur tout le parc | `{"ip":"203.0.113.7","jail":"sshd"}` | « Bannir cette IP sur TOUS les serveurs ? » |
| installer sur tout le parc | `{}` | « Installer Fail2ban sur tous les serveurs sans Fail2ban ? » |

`banIpAllServers` (`main.js:495`) passe pourtant `{ip, jail}` à la traduction, et le catalogue les
ignore **tous les deux** — **cinquième occurrence** du motif d'E-163, et celle dont l'enjeu est le
plus grand : on accepte de bannir sur **tout le parc** sans savoir quelle adresse.

Pour l'installation de masse, le corps est **vide** : la portée est décidée entièrement côté serveur,
par la requête d'E-172. L'opérateur ne peut donc pas la connaître, même en principe — et la
confirmation ne lui en dit rien.

**Un geste irréversible sur tout un parc se confirme en sachant sur quoi il porte.**

---

*Note sur E-165* — **quatrième occurrence trouvée et corrigée le 2026-08-27 (`v1.38.9`).**
`ban_all_servers` ne **nommait même pas** `rc` : `success: True` par machine ne disait que « la
session SSH s'est ouverte et la commande est partie », et le résumé « banni sur 3/3 serveurs » se
calculait là-dessus. Les trois premières occurrences avaient été corrigées le même jour, celle-ci
oubliée — **c'est exactement le motif « à moitié corrigé » reproché six fois à ce module, et cette
fois le correctif partiel était le nôtre.** Le `success` global n'est désormais vrai que si TOUTES
les machines ont abouti : un « 0/3 » rendu avec `success: True` se lit comme une réussite.

*Note sur E-164* — **même chose sur `/fail2ban/stats`**, corrigé au même lot : `days = min(int(...))`
était hors de tout `try`. Chercher la branche jumelle est une règle de ce chantier, pas une
précaution.

---

## E-174 — `_validate_ip` valide et rend la chaîne REÇUE : exécution de commande arbitraire en root

**Le défaut le plus grave du chantier.** Trouvé par relecture le 2026-08-27, **hors du sous-lot en
cours**, et **occupé aujourd'hui par un compte actif**. Vérifié ligne par ligne et mesuré dans le
conteneur avant d'être écrit ici — trois lignes, chacune correcte en apparence.

### La chaîne

```python
# backend/fail2ban_manager.py:26-30
def _validate_ip(ip: str) -> str:
    """Valide une adresse IP (v4 ou v6)."""
    ip = ip.strip()
    ipaddress.ip_address(ip)   # appelée pour son EFFET DE BORD ; le résultat est jeté
    return ip                  # ... et c'est la chaîne REÇUE qui est rendue
```

```python
# backend/fail2ban_manager.py:163
return execute_as_root(client, f'fail2ban-client set {jail} banip {ip}', ...)
```

```python
# backend/ssh_utils.py:554
sudo_cmd = f"sudo -S -p '' sh -c {shlex.quote(command)}"
```

`shlex.quote` protège le shell **extérieur** — celui qui reçoit `sudo`. Il enveloppe la commande
**entière** en un seul argument, qui arrive intact au `sh -c` distant, **dont le travail est
précisément de l'interpréter**. Le `;` s'exécute donc, sous `sudo`, **en root**.

### Ce que `ipaddress.ip_address` accepte réellement — mesuré, pas supposé

Un identifiant de portée IPv6 (`%…`) peut contenir n'importe quoi. Relevé dans `rootwarden_python` :

| valeur soumise | verdict de `ip_address` | `str()` de l'objet rendu |
|---|---|---|
| `fe80::1%;id;` | **ACCEPTÉE** | `'fe80::1%;id;'` |
| `fe80::1%$(id)` | **ACCEPTÉE** | `'fe80::1%$(id)'` |
| <code>fe80::1%&#124;id</code> | **ACCEPTÉE** | <code>'fe80::1%&#124;id'</code> |

**Et c'est la mesure qui compte le plus** : `str()` **conserve l'identifiant de portée verbatim**. La
parade habituelle de ce chantier — « normalise d'abord, compare ensuite » — **n'aurait rien fermé
ici**, parce que la valeur ne sert pas à *comparer* mais à *composer*. Le correctif doit **refuser le
`%`**, pas normaliser.

### Établi sans joindre aucune machine

La commande réellement émise a été recomposée, `fail2ban-client` remplacé par un `echo` et `sudo`
retiré. `sh -c` scinde bien au `;` et exécute la seconde commande :

```
$ sh -c 'echo FAKE-CLIENT set sshd banip fe80::1%;echo MARQUEUR uid=$(id -u);'
FAKE-CLIENT set sshd banip fe80::1%
MARQUEUR uid=0
```

**C'est l'INTERPRÉTATION qui est mesurée, jamais le geste distant.** Aucune session SSH n'a été
ouverte, aucune machine du parc n'a été touchée — et la règle du chantier « un défaut irréversible
s'ÉTABLIT sans se provoquer » est respectée.

### Qui l'occupe, mesuré en base

| compte | rôle | ce qui l'ouvre | portée |
|---|---|---|---|
| `rw-test-admin` (15) | 2, actif, **second facteur fonctionnel** | `check_machine_access` rend `True` dès `role_id >= 2` | **les trois machines**, `srv-zabbix` comprise |
| `rw-test-super` (16) | 3, **sans** `can_manage_fail2ban` | la **page** le refuse, la **requête** l'accepte | idem |
| `opsuser` (2) | 1, actif, zéro permission | le chemin de requête l'accepte | **`srv-zabbix` seule** — sa seule ligne dans `user_machine_access` est la **production** |

Réserve dite aussi nettement que l'accusation : `opsuser` n'a pas de `totp_secret`, donc
`login.php:223-226` l'envoie vers `enable_2fa.php`, **un enrôlement libre**. Ce n'est pas une
barrière, c'est une étape — et elle laisse une trace.

**Et le pire vecteur n'est aucun de ceux-là** : `POST /fail2ban/ban_all_servers` porte
`@require_role(2)` et **aucun contrôle d'accès machine**. Un seul appel d'un rôle 2 exécute la
commande injectée sur **chaque machine à fail2ban actif** — parc entier, production comprise.

### Ce qui est DÉDOUANÉ, et il faut le dire aussi clairement

- les cinq comptes `e2e_test_*` n'ont **aucune** ligne dans `user_machine_access` : le décorateur les
  arrête. Ils n'occupent pas cette faille ;
- `rootwarden_python` publie `5000/tcp` **sans correspondance d'hôte** ; seuls 8443 et 8444 sont
  publiés. L'hypothèse « forger `X-User-Role: 3` en joignant le backend directement » est **écartée** ;
- `iptables/` n'interpole **aucune** valeur utilisateur brute — base64 et chemins littéraux.
  `MODULE-FILTRAGE.md` §3 a raison **sur ce point** ;
- `temporary_permissions` est **vide** : un correctif de garde posé maintenant ne casserait aucun
  chemin vivant.

### E-152 est amendé : son correctif NE FERME PAS celui-ci

E-152 disait « sur 23 routes, deux portent une permission ». C'est vrai et **insuffisant**.
`/fail2ban/ban` n'est pas « une écriture sans permission » : c'est un **shell root**. La garde absente
n'est donc pas le défaut principal, c'est son **amplificateur**. Poser `@require_permission` sur les
21 routes laisserait à tout porteur légitime de `can_manage_fail2ban` — `superadmin`,
`rw-test-admin` — l'exécution root intacte. **La permission est censée autoriser à bannir une
adresse ; elle confère root sur chaque machine à portée.** C'est une élévation par rapport à
l'**intention documentée du produit**, et pas seulement par rapport à une garde manquante.

### Correctif — les deux ENSEMBLE, pas l'un ou l'autre

1. `_validate_ip` : **refuser `'%' in ip`**, puis rendre `str(ipaddress.ip_address(ip))` ;
2. ceinture : `shlex.quote()` sur `jail` **et** `ip` **à l'intérieur** de la commande composée — ce que
   `MODULE-FILTRAGE.md` §5.6 réclamait déjà (« un f-string sur une valeur venue du client doit devenir
   impossible à écrire par accident »).

Ce que le correctif casserait : **rien de mesurable**. Aucun appelant légitime n'envoie
d'identifiant de portée — le portage valide en JavaScript avant d'émettre, le legacy aussi. C'est une
propriété qui se mesure, et elle est inscrite au banc.

### Pourquoi un module par ailleurs minutieusement audité l'a laissé passer

`MODULE-FILTRAGE.md` §3 classe `ban_ip` / `unban_ip` dans « liste blanche / parseur dédié — **SÛR :
oui** », **en citant nommément `ipaddress.ip_address()`**. L'inventaire a donc **dédouané le validateur
sans mesurer ce qu'il accepte**. C'est la mécanique de l'« en-tête qui mente », transposée dans un
document d'inventaire — et c'est la plus coûteuse des quatre formes rencontrées, parce qu'un
dédouanement écrit fait renoncer le lecteur suivant à mesurer. **Une ligne d'inventaire qui conclut
« sûr » doit porter la mesure qui l'établit, ou ne pas conclure.**

---

## E-175 — `/fail2ban/history` et `/iptables-history` lisent `server_id` là où le garde retient `machine_id`

**Écart mineur, dit comme tel.** Le décorateur d'accès résout `machine_id` en premier ; ces deux
routes lisent `server_id`. La divergence est réelle, donc le contrôle porte sur un identifiant que la
route n'emploie pas — la forme exacte d'« un garde sans objet ne garde rien ».

**Ce qu'il fuit aujourd'hui : rien.** Les **deux** tables sont vides — 0 ligne. Le défaut est réel et
sans porteur, et c'est précisément la distinction que ce chantier a payée : *vérifier qu'un garde est
ABSENT n'est pas vérifier que son absence COMPTE.* À corriger avec E-152, dont il partage le
périmètre ; à ne pas présenter comme une faille.

---

## E-176 — `queued: N` peut vouloir dire ZÉRO tâche lancée, et la page annonce déjà un suivi

`groups.py:311-315` rend `success` / `queued` juste après `t.start()` — accusé de réception, pas
verdict. Mais **le fil peut ne RIEN faire** : `_run_bulk` commence par
`if not _scan_lock.acquire(blocking=False): logger.info(...); return` (`:270-272`), donc **avant tout
`track()`**. Aucune tâche n'est créée. Or la page a déjà affiché « :n serveur(s) en file — **suivi dans
le centre de tâches** ». L'exploitant y va, il n'y a rien.

**Et le module voisin refuse franchement dans le même cas** : `security/` rend un **429**
(`cve.py:164-166`). Même situation, deux réponses opposées dans deux modules — c'est le genre
d'incohérence qu'aucune lecture d'un seul module ne peut voir. Aligner sur le `429` touche le backend
de production : porté au §7 du plan, même régime qu'E-144, E-147, E-149 et E-150.

## E-177 — Une tâche CVE échouée est marquée `success`

`track()` marque `success` à la sortie **normale** du bloc. Le bloc draine `_stream_cve_scan`, qui
**avale ses propres exceptions** (`cve.py:56-60`, `:108-111`) et les rend comme des **lignes
d'événement** que la boucle jette (`pass`). Machine injoignable, SSH refusé, aucun identifiant : le
générateur se termine normalement, **la tâche est verte**.

Même mécanique que le `forward_deployed = True` de `graylog/`, mais **persistée en base**.
**Défaut backend : il échouera des deux côtés** — ce n'est pas un écart de parité entre portails, et il
se corrige avec le portage.

## E-178 — Supprimer un groupe inexistant annonce « Groupe supprimé »

`delete_group` (`groups.py:218-225`) rend `deleted: cur.rowcount > 0` **sans résoudre l'objet** ;
`main.js:112` ne lit que `success`. Famille `/server_lifecycle` : `rowcount` ne distingue pas « rien à
changer » de « objet absent ». Le champ qui porterait l'information **existe et n'est lu par personne**.

## E-179 — Le panneau d'onboarding contredit le bouton qu'il décrit, dans les DEUX langues

`tip.groups_step3` : « Le bouton **Membres** permet d'**ajouter ou retirer** des serveurs du groupe » /
« lets you **add or remove** ». `showMembers()` (`main.js:77-91`) affiche une liste **en lecture seule**,
point. Et l'infobulle du **même bouton**, trois lignes plus loin, dit la vérité
(`js.groups.tip_members` = « Afficher les serveurs résolus »).

**Troisième variante du motif « l'en-tête qui mente »** : ni un commentaire de fichier (E-142), ni un
libellé au terme porteur non défini (le « fusionner » de `bashrc/`), mais un panneau d'**onboarding**
qui promet un geste **absent**. Le geste existe côté backend et n'a aucun appelant :
`PUT /groups/<id>` (`groups.py:170-210`) sait remplacer intégralement les membres statiques, et trois
traces montrent une fonctionnalité conçue et jamais branchée (`main.js:13` `editingId` jamais lu,
`save()` qui poste toujours sur `/groups`, et ce texte). **La brancher n'est plus migrer, c'est
concevoir** — porté au §7. Le portage corrige le TEXTE : *un texte faux se corrige, une capacité
absente s'arbitre.*

## E-180 — La purge du planificateur ne tourne pas, et trois nettoyages d'hygiène sont éteints par une variable de RÉTENTION DE JOURNAUX

`LOG_RETENTION_DAYS` est **commentée** dans `srv-docker.env`, donc vaut 0, donc `_purge_old_logs()`
sort immédiatement. **Rien n'a jamais été purgé** depuis la remise à zéro du 2026-05-26. Et la même
variable éteint **trois nettoyages qui ne sont pas des politiques de rétention** : sessions inactives,
permissions temporaires expirées, jetons de réinitialisation.

Mesuré : **2 132** sessions en base pour `rw-test-super`, 1 094 pour `rw-test-user`, 619 pour
`superadmin`. Et `verify.php:66` lit cette table à **chaque page protégée** — c'est la **liste de
révocation côté serveur**, et elle ne vieillit jamais.

**Activer la variable n'est pas la bonne réponse seule** : `user_logs` porte une chaîne scellée, et
purger par la tête **romprait la vérification d'intégrité**. Défaut commun aux deux portails, donc pas
un écart de parité au sens strict — inscrit ici parce que c'est le registre des mesures, et porté au §7
comme décision d'exploitation.

## E-181 — La portée d'un geste de parc ignore `lifecycle_status` : une machine retirée du parc reste une cible

Relevé le 2026-08-27 **en portant F6**, par lecture des deux requêtes. Les deux gestes de parc de
`fail2ban/` font `FROM machines m` **sans aucun filtre de cycle de vie**, alors que le sélecteur de la
page **écarte** les archivées (`Fail2ban::machines()`). Une machine retirée du parc reste donc une
cible des deux gestes **sans figurer nulle part à l'écran**.

C'est mot pour mot le défaut « **deux sources pour la même table** » qui a laissé une machine archivée
recevoir un `apt full-upgrade` dans `update/`. **Branche réelle et non exercée** : les trois machines
sont `active` aujourd'hui. Remesure :
`SELECT lifecycle_status, COUNT(*) FROM machines GROUP BY 1`.

Le portage la **MARQUE** (« retirée du parc », avec la raison) au lieu de la taire ; **il ne peut pas la
refermer**, le filtre vit dans le backend.

---

*Note sur E-164 — **REFERMÉ le 2026-08-27** (`v1.38.15`).* Le cast `int(server_id)` vivait **à
l'intérieur** du `try` qui rend « Erreur interne » : une faute de la **requête** obtenait un **500** sur
`/fail2ban/stats` et `/fail2ban/history`. La première moitié de l'écart — corps HTML illisible par
l'appelant — était déjà fermée ; celle-ci — « la faute est dans la requête, le statut dit qu'elle est
dans le serveur » — ne l'était pas. **Troisième occurrence du motif « à moitié corrigé » sur ce module,
et deuxième fois que le correctif partiel était le nôtre.**

Verrouillé par `backend/tests/test_fail2ban.py::TestIdentifiantDeServeurNonNumerique` (12 cas, 4
propriétés). **Mutation fidèle du correctif : 8 FAIL**, fichier restauré, empreinte SHA-256 identique.

Deux choses que la validation a établies **au-delà de la demande** :

- **l'ORDRE des contrôles.** Le test de présence reste **avant** le cast sur les deux routes, donc
  `server_id requis` et `server_id doit être un nombre` demeurent **deux messages distincts**. Un
  correctif qui aurait casté d'abord aurait fermé E-164 **en confondant les deux fautes** — c'est
  désormais une assertion permanente ;
- **les quatre propriétés ne protègent pas également, et c'est dit.** La quatrième — « la requête
  refusée ne touche pas la table d'historique » — reste **verte sur le code défectueux** : la
  `ValueError` était levée en évaluant les paramètres, donc **avant** le `execute()`. Elle est réelle,
  elle tenait déjà, et elle **ne distingue pas les deux états**. Une propriété vraie des deux côtés
  n'est pas une propriété qui verrouille.

Le mécanisme qui a rendu ce correctif vérifiable mérite d'être gardé : les deux propriétés attendues
avaient été écrites **avant** le correctif, en `xfail(strict=True)`. Elles ne rougissaient pas, et le
correctif les a fait passer en `XPASS(strict)`, donc **en FAILED** — le signal pour lequel elles
existaient. **Un correctif validé par un test qu'il ne pouvait pas influencer, écrit par une autre
session, et impossible à ajuster après coup.** Verrouiller le 500 aurait figé le défaut ; décrire
l'attendu en `xfail` l'a rendu impossible à oublier. `pytest` : **389 passed, 0 xfailed** après retrait
des marqueurs.

---

## E-182 — `_SERVICE_RE` accepte un nom d'unité commençant par un TIRET, et `-.mount` franchit aussi `_check_protected`

**Effet NON ÉTABLI. À ne pas mesurer par le geste.** Relevé le 2026-08-27 en recopiant
`_check_protected` à l'identique pour le mesurer — pas en lisant le code, en l'exécutant sur des valeurs.

`_SERVICE_RE = ^[a-zA-Z0-9@._:-]+$` place le tiret dans la classe **y compris en tête**. Deux valeurs
en sortent, que personne n'avait vues :

| valeur | classe | `_check_protected` |
|---|---|---|
| `-.mount` | franchit | **franchit** |
| `-.slice` | franchit | **franchit** |

**`-.mount` est le nom de l'unité du système de fichiers RACINE dans systemd.** Son nom commence
littéralement par un tiret, et tous ses caractères sont dans la classe. `PROTECTED_SERVICES` ne connaît
que six noms de services : ni l'un ni l'autre n'y figure. La valeur part **nue** dans
`f'systemctl {verbe} {service}'`, six fois (`services_manager.py:135,161,170,179,188,197`).

### Pourquoi ce n'est pas tranché, et pourquoi c'est la bonne décision

La question est : `systemctl` reçoit-il `-.mount` comme un **nom d'unité** ou comme une suite d'options
courtes invalides ? La convention documentée est `systemctl status -- -.mount`, **avec** séparateur, ce
qui *suggère* que sans lui l'unité n'est pas atteinte. Mais **le banc est un conteneur sans systemd**,
les seules machines qui pourraient trancher sont réelles, et **le geste à tester serait un
`systemctl stop` sur la racine**. Si l'hypothèse est fausse, il ne se passe rien ; si elle est juste, on
démonte le `/` d'une machine de production.

> **CONSIGNE PERMANENTE : personne ne teste ceci sur une machine réelle.** Ni sur le banc, ni a fortiori
> sur `srv-zabbix`. *Un défaut irréversible s'établit sans se provoquer.*

Si l'exploitant veut trancher : machine **jetable** dotée de systemd, et **`show` à la place de
`stop`** — `show` ne fait rien mais dit si l'unité est **résolue**. Même mesure, sans le geste.

### Le correctif rend la question sans objet, ce qui vaut mieux que d'y répondre

```python
_SERVICE_RE = re.compile(r'^[a-zA-Z0-9@._:][a-zA-Z0-9@._:-]*$')
```

Interdire le tiret **en tête** ferme du même coup **toute** l'injection d'argument. Aucune unité systemd
ordinaire ne commence par un tiret : ce que le correctif casserait est **rien**. Il se pose avec E-150 —
même fichier, même famille, et il serait absurde de toucher `services_manager.py` deux fois.

### Deux non-failles établies au même passage, dites aussi nettement que l'accusation

- **`_SAFE_VALUE_RE` (supervision) : NON exploitable.** C'était le bon candidat — le seul des 33
  validateurs ancrés `^…$` dont la valeur atterrit dans un fichier **multiligne**, et le contexte exact
  de V10a (une valeur qui devient une ligne de conf, donc un `UserParameter` Zabbix, donc une exécution
  de commande). **Deux propriétés indépendantes le referment** : `$` n'admet qu'**un** saut de ligne, en
  toute fin, rien après — une valeur acceptée finissant par `\n` produit une **ligne vide**, pas une
  directive ; et le rendu passe par **base64** (`supervision.py:363-366`), donc aucun caractère de la
  valeur n'atteint le shell. Le **commentaire**, lui, ment — il promet « refuse tout caractère de
  contrôle, saut de ligne compris » : **septième occurrence** du motif. Correctif cosmétique
  (`.fullmatch()` + corriger le commentaire), et **le second geste vaut plus que le premier** ;
- **`_SERVICE_RE` : pas d'injection d'argument utile**, et la raison n'est pas celle qu'on croit. Les six
  fonctions passent par `execute_as_root` — **qui atteint la route est déjà root sur la machine**. Une
  option `systemctl` acceptée ne franchit donc **aucune** frontière de privilège ; la seule chose qu'elle
  pourrait apporter est de contourner `_check_protected`, et elle ne le peut pas : un seul jeton, pas de
  `=`, pas d'espace, donc impossible de fournir à la fois une option **et** un nom d'unité. Agir sur
  `sshd` exige de le **nommer**, ce que le contrôle regarde.

**Conséquence pour l'arbitrage : E-150 est le seul contournement ÉTABLI de `_check_protected`, et il n'a
besoin d'aucune injection d'argument** — `ssh.socket`, `sshd.socket`, `ssh@.service` passent, mesuré en
recopiant le contrôle à l'identique. L'injection d'argument est une **imprécision à refermer au
passage**, pas un motif de correctif à elle seule.

### Et E-149 + E-150 sont CHAÎNÉS

Vérifié : les huit routes de `services.py` n'ont **ni rôle ni permission**. Un rôle 1 disposant d'une
machine peut donc arrêter des services sur elle, dont `ssh.socket`. **`opsuser` est ce compte, et sa
seule machine est `srv-zabbix`.** C'est la **troisième** fois que ce compte tombe dans un écart, après
E-174 et `cve_reprioritize` — à ce stade ce n'est plus une coïncidence, c'est une **propriété de sa
configuration** : rôle 1, une seule machine, et cette machine est la production.

*Amendement à E-182 et à E-149, mesuré le 2026-08-27 — deux bornes que la qualification n'avait pas.*

**(a) Le garde qui manque n'est pas le seul garde, et son absence RÉVÈLE l'autre.** Relevé route par
route : les huit routes de `services.py` portent `@require_api_key` + **`@require_machine_access`** +
`@threaded_route`. E-149 reste exact — ni rôle ni permission — mais **`@require_machine_access` MORD
ici**, et précisément **parce qu'**aucune de ces routes ne porte `@require_role(≥2)` :
`check_machine_access` ne sort donc pas par son court-circuit `if role_id >= 2: return True` et consulte
réellement `user_machine_access`.

> **C'est le seul module du chantier où l'ABSENCE d'un garde révèle l'action d'un autre** — l'inverse
> exact de la règle du §8, où la *présence* du décorateur masque son inertie sur 57 routes.

Cela ne dédouane pas E-149 : cela dit que l'exposition est **bornée aux détenteurs de la machine
visée**, et non ouverte à tout compte authentifié. La correction reste souhaitable ; sa portée est plus
petite qu'annoncé.

**(b) La population est d'exactement UN, et il a une marche à franchir.**

| compte rôle 1 | actif | second facteur | machines |
|---|---|---|---|
| **`opsuser`** (2) | oui | **NON** | **`srv-zabbix` — PRODUCTION** |
| `e2e_test_*` × 5 | oui | non | **aucune** |
| `rw-test-user` (14) | oui | oui | aucune |

Remesure :
`SELECT u.id,u.name,u.role_id,(u.totp_secret IS NOT NULL AND u.totp_secret<>'') FROM users u WHERE u.role_id=1;`
puis `SELECT user_id,machine_id FROM user_machine_access;`

`opsuser` est le **seul** rôle 1 à détenir une machine, et c'est la production — c'est ce qui rend la
chaîne sérieuse. **Mais il n'a pas de secret TOTP** : il devrait s'enrôler d'abord. **Ce n'est pas une
barrière, c'est une marche**, et elle laisse une trace. Dit dans les deux sens plutôt que présenté comme
un verrou.

**Et les cinq `e2e_test_*` n'ont AUCUN accès machine** : ils n'atteignent rien par ce chemin. Ce que le
§7 leur reproche — être offerts comme identité d'exécution ChatOps sans second facteur — reste vrai ;
**ce chemin-ci, non.** Leur gravité s'en trouve réduite, et une mesure qui dédouane se dit aussi
clairement qu'une qui accuse.

**Deux vérifications qui dédouanent au passage** : `.replace('.service','')` est **global**, donc
`ssh.service.service` est bien **bloqué** ; et `SSH.service` passe le contrôle, mais les noms d'unité
systemd sont **sensibles à la casse**.

---

## E-183 — `scan_server_users` : une LECTURE ratée EFFACE l'inventaire, et se journalise comme un succès

**La classe « une réussite annoncée n'est pas vérifiée » dans sa forme DESTRUCTRICE.** Pas « écrit un
état faux » — **« efface un état vrai ».** Trouvée le 2026-08-27 par balayage puis lecture, vérifiée
indépendamment avant d'être inscrite.

`backend/routes/ssh.py:1088`. Le mécanisme, ligne à ligne :

```python
stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
passwd_output = stdout.read().decode('utf-8', errors='replace')
#   le code de sortie n'est JAMAIS lu

scanned_users = []
for line in passwd_output.strip().split('\n'):
    if not line.strip(): continue          # une sortie VIDE -> liste VIDE
...
ghost_usernames = [u for u in existing.keys() if u not in scanned_usernames]   # :1280
if ghost_usernames:
    cur.execute(f"DELETE FROM server_user_inventory WHERE machine_id = %s AND username IN (...)")
```

**Si la lecture ne rend rien, `scanned_users` est vide, donc TOUTES les lignes d'inventaire de la
machine deviennent des « fantômes » — et elles sont supprimées.** Idem pour `server_user_ssh_keys`
trente lignes plus bas. **`recv_exit_status` n'apparaît pas UNE SEULE FOIS dans tout le fichier** —
mesuré, `grep -c` rend 0. Et il n'existe aucun garde `if not scanned_users` : les deux seules
occurrences de ce symbole sont des boucles `for u in scanned_users`.

### Quatre raisons qui la mettent au-dessus des quatre autres de la même famille

1. **elle DÉTRUIT.** E-90 écrivait un agent qui n'existe pas — faux, mais réparable par le geste
   suivant. Ici la donnée est **perdue** ;
2. **elle se journalise comme un succès** : `logger.info("%d fantome(s) purge(s)")`. Un opérateur qui
   relit le journal voit un **nettoyage**, pas un incident. Le commentaire au-dessus explique même
   pourquoi la purge est une bonne idée — « sans ça, un compte comme `cleopatre` reste visible à vie ».
   **Elle l'est, sur un scan qui a abouti.** C'est le motif « le cas visible traité, le cas subtil pris
   à l'envers » : la présence d'un raisonnement correct **à côté** endort la question ;
3. **le volume est réel** : `server_user_inventory` porte **72** lignes, `server_user_ssh_keys` **20** —
   mesuré. Remesure : `SELECT COUNT(*) FROM server_user_inventory;`
4. **c'est l'inventaire qui alimente K4.** Le §7 dit d'un déploiement de clés lancé en l'état qu'il
   « **RÉVOQUERAIT** les accès, il ne ferait pas rien ». **Un inventaire vidé à tort est exactement
   l'entrée qui rend ce raisonnement faux** — et l'arbitrage K4 reposerait alors sur une donnée à
   laquelle on ne peut pas se fier.

**Et le décorateur d'accès y est inerte** : la route porte `@require_role(2)` **et**
`@require_machine_access`, donc `check_machine_access` sort par son court-circuit `if role_id >= 2`.
Tout compte de rôle 2 l'atteint sur n'importe quelle machine — même si le déclencheur de la destruction
n'est pas l'appelant mais **un échec SSH passager**.

### Correctif — et il change le SENS d'un repli, ce qui est dit

Lire `recv_exit_status()`, et **refuser la purge quand le scan n'a rien rendu**. Aujourd'hui « je n'ai
rien vu » signifie « il n'y a plus rien » ; après, cela signifiera « **je ne sais pas** ».

**L'asymétrie décide, et elle est à sens unique** : le pire cas du correctif est qu'un compte mort reste
visible dans l'inventaire — un défaut d'**affichage**, celui-là même que le commentaire d'origine
voulait éviter. Le pire cas actuel est que **72 lignes disparaissent sur un incident réseau**. C'est un
arbitrage entre « un compte mort reste visible » et « l'inventaire est vidé », et il ne se tranche pas
dans le sens destructeur.

## E-184 — Une sonde qui échoue efface ce qu'elle n'a pas pu regarder

Un seul défaut sous **deux** formes, dans deux modules, et il se corrige d'une ligne chacune.

| route | ce qui se passe sur une lecture ratée |
|---|---|
| `monitoring.py:124 check_linux_version` | le code de sortie n'est pas lu ; `parse_os_release('')` rend **`'Inconnue'`** (mesuré) et l'`UPDATE` **écrase une valeur connue-bonne** |
| `supervision.py zabbix_version` / `generic_version` | miroir : quand la sonde ne rend rien, `version_str` est faux → **`_remove_agent`**. Une sonde qui échoue **efface l'agent de l'inventaire** |

**Gravité moindre qu'E-183, et pour une raison précise** : dans le premier cas la valeur écrite est
**honnête** (`Inconnue` est vrai : on ne sait pas) et sa conséquence est **fail-closed** —
`generic_deploy` refuse un OS non reconnu. Mais un incident SSH passager efface tout de même
l'inventaire d'OS.

Pour la seconde, **l'effet est documenté comme VOULU** au §7 du plan, pour vérifier une désinstallation
— **et il l'est.** Ce qui ne l'est pas : elle **ne distingue pas « l'agent est absent » de « je n'ai pas
pu regarder »**. C'est la même phrase que pour E-183, et c'est la formule de la classe entière :

> *Une sonde qui échoue n'efface pas ce qu'elle n'a pas pu regarder.*

*Note sur E-174 — **VERROUILLÉ le 2026-08-27*** par `backend/tests/test_fail2ban_manager.py`
(**75 assertions**, 1 `xfail`). Les **cinq** verrous du correctif ont été retirés **un par un** :
**14, 1, 3 et 1** rouges — **aucun n'est redondant**, et c'est un résultat, pas une relecture : il ne se
déduisait pas du code.

Deux mesures qui ne vont pas de soi et qui méritent d'être gardées comme méthode :

- **le verrou qui SÉPARE l'ancienne version de la nouvelle est la valeur RENDUE** (`FE80::0001` →
  `fe80::1`). Une assertion « la fonction ne lève pas » passerait **à l'identique** sur les deux
  versions : le défaut était que la valeur reçue était rendue telle quelle, pas que la validation
  échouait. *Mesurer ce que la fonction REND, pas qu'elle accepte* ;
- **la ceinture `shlex.quote` est mesurée SANS le validateur**, en simulant celui d'avant le correctif,
  puis en analysant la commande par `shlex.split` : la charge doit rester **un seul argument**. C'est la
  seule façon de savoir que la ceinture tiendra le jour où un caractère passerait la boucle — mesurer
  une défense en profondeur exige de **désarmer** celle du dessus ;
- **la garde fail-closed est mesurée CONTRE SON PROPRE COMMENTAIRE.** Le code affirme « si un jour un
  troisième chemin alimente `current_ips`, c'est ici que ça s'arrête ». Le troisième chemin a été
  fabriqué en neutralisant les deux filtres amont : elle lève, avant toute écriture composée. **Le
  commentaire dit vrai** — ce qui n'allait pas de soi sur un chantier qui compte cinq en-têtes annonçant
  un accès plus strict que leur code.

`pytest` : **464 passed, 1 xfailed** (348 en début de journée).

---

## E-185 — `manage_whitelist` : la lecture montre une entrée que l'écriture supprime en silence

Relevé le 2026-08-27 en verrouillant E-174, et **signalé spontanément par la session qui venait
d'écrire le correctif** plutôt que laissé à trouver.

`action == 'list'` sort **avant** le filtre de sécurité. La lecture rend donc la liste **brute** du
fichier distant, **entrée illisible comprise**. Un `add` ou un `remove` ultérieur recompose la liste
filtrée : l'entrée disparaît — **journalisée côté serveur, silencieuse pour l'appelant**.

Vu de l'exploitant : une entrée est affichée, un geste **sans rapport** est fait, l'entrée n'est plus là.
Le drapeau `lue` continue de dire `true`, et il ne mente pas sur l'origine de la liste — mais **il ne dit
rien du fait que la liste RÉÉCRITE n'est pas celle qui a été LUE.**

Même famille qu'E-168, et que le défaut de D1 où « Vérifier l'intégrité » et « Sceller les orphelines »
rendaient **deux verdicts opposés à la même seconde**.

### Ce qui est décidé — l'issue (b), et pourquoi pas (a)

Deux issues étaient sur la table : **(a)** filtrer aussi à la lecture, **(b)** rendre un champ
`ecartees` que l'écran nomme.

**(b) est retenue.** (a) masquerait une entrée qui **existe réellement dans le fichier** — c'est-à-dire
qu'elle réintroduirait exactement E-168, « la liste blanche affichée est SUPPOSÉE, pas lue », que F5
venait de refermer en obtenant du backend un drapeau `lue`. On ne referme pas un écart en rouvrant celui
d'avant. (b) garde la lecture **fidèle** et **nomme** ce qui ne survivra pas à une écriture.

**Le champ est ADDITIF**, donc sans effet sur le legacy, qui ne lit que les clés qu'il connaît — même
raisonnement que l'`active_now` de `maintenance/`.

**Et le libellé ne doit pas promettre des LIGNES** : la relecture découpe la ligne sur les **espaces**,
donc une charge qui en contient devient **plusieurs** entrées. Un champ `ecartees` compte des
**fragments**, pas des lignes. Le dire, ou l'écran mentira sur un nombre.

La propriété est posée en `xfail(strict=True)`, formulée pour **ne pas préjuger** de l'issue : *« ce que
la lecture montre, l'écriture le préserve, ou bien elle dit ce qu'elle a retiré »* — les deux issues la
satisfont. Elle rougira le jour du correctif, ce qui obligera à revenir l'écrire pour de bon : **le
mécanisme qui vient de fonctionner sur E-164.**

*Amendements du 2026-08-27 — deux écarts existent en DEUX exemplaires, et un seul patch en laisserait un armé.*

**E-144 existe DEUX fois.** La liste nommait `policies.py:236`. Il y a aussi **`sudo_manager.py:169`**,
dans `render_policy` **elle-même** : `preset = policy.get('preset', 'apt_only')`. Corriger la seule route
laisserait le repli **armé pour tout autre appelant** — le motif « chercher la branche jumelle », qui en
est à sa sixième occurrence sur ce chantier.

Et la **dérivation** exigée pour ne pas recopier une classification a confirmé le piège annoncé : le
marqueur « shell root » aurait classé `read_logs` — **le préréglage le plus borné des six** — comme
donnant root, parce que sa docstring emploie ces mots pour expliquer qu'on a **retiré** `less` (qui
permettait `!sh`). Le marqueur qui dérive juste est `ÉQUIVALENT ROOT` en majuscules dans un
avertissement, ou `Accès root complet`. **Deux** préréglages sortent : `all_nopasswd` (par construction)
et `apt_only` (par avertissement explicite de son propre code). Aucun autre.

**E-142 a une jumelle, et le défaut n'est plus que côté LEGACY — donc en production.** La liste nommait
`policies.preset_help_apt_only` (« Il ne peut pas toucher au reste du système »). Il y a aussi
**`policies.preset_hint_apt_only`** : « appliquer les mises à jour système **sans avoir root complet** »
— exactement aussi faux, même fichier, autres mots. **Quatre chaînes** à corriger (2 clés × FR/EN).
**Le portage est DÉJÀ correct** (`laravel/lang/{fr,en}/politiques.php`, `aide_apt_only` dit « CELA
ÉQUIVAUT À UN ACCÈS ROOT »). La phrase fausse ne se lit donc plus que sur l'ancien portail.

**Une erreur à ne PAS commettre sur E-149, et elle était tentante.** Ajouter `/services/` à
`ADMIN_SEULEMENT` en défense en profondeur, comme cela a été fait pour `/supervision/`, **casserait un
chemin légitime** : `ADMIN_SEULEMENT` exige le rôle ≥ 2, or **les deux pages admettent le rôle 1**
porteur de la permission (`legacy/services/index.php:11-12`, et `web.php` côté portage). La passerelle
n'a **aucun** mécanisme « permission » : le seul bon endroit est le décorateur backend. **Même
raisonnement pour `/fail2ban/`.**

**Ordre imposé entre E-174 et E-152** : E-174 d'abord, E-152 **ensuite**, comme défense en profondeur.
L'inverse donnerait le sentiment d'avoir traité le sujet — un porteur légitime de `can_manage_fail2ban`
conserverait l'exécution root.

*Amendement à E-183 — **il avait TROIS faces, et la troisième change l'arbitrage K4.*** Trouvée le
2026-08-27 **en écrivant le correctif**, pas en le concevant. Vérifiée indépendamment.

Les deux premières écritures effacent (`server_user_inventory`, `server_user_ssh_keys`). La troisième
n'efface rien :

```sql
UPDATE machines SET users_scanned_at = NOW()
```

**Ce n'est pas un horodatage d'affichage.** `backend/routes/ssh.py:381` :

```python
# Bloquer si le serveur n'a jamais ete scanne
if not m.get('users_scanned_at'):
    result['errors'].append("Scan utilisateurs requis avant le premier deploiement. …")
    result['scan_required'] = True
```

**C'est la précondition du préflight de déploiement**, et l'ancienne version la posait **après un scan
qui n'avait rien lu**. Donc un incident SSH passager ne se contentait pas de vider l'inventaire : il
**levait, dans le même geste, le garde de sûreté qui empêche de déployer sur un serveur non scanné**.

> Le §7 disait de K4 qu'un déploiement lancé en l'état « **RÉVOQUERAIT** les accès ». Ce raisonnement
> repose sur l'inventaire. Il fallait dire : **le même chemin détruisait la donnée ET ouvrait la porte
> qui la garde.** Un inventaire vidé n'est pas seulement une donnée à laquelle on ne peut pas se fier —
> c'est un préflight qui a cessé de bloquer.

Les trois écritures sont désormais gardées par un **prédicat unique**, le repli est **nommé** dans le
journal (« scan NON CONCLUANT, purge ABANDONNÉE, l'inventaire (N ligne(s)) est conservé tel quel ») et le
changement de sens est **écrit dans le code**. Et `recv_exit_status`, qui n'apparaissait **pas une seule
fois** dans `ssh.py`, y figure maintenant — **exactement là où un code de retour décide d'une
suppression**. Remesure : `grep -c recv_exit_status backend/routes/ssh.py`.

---

## E-187 — La purge des CLÉS est gardée par la mauvaise lecture, et la valeur qui la fermerait est déjà dans le code

Trouvé le 2026-08-27 par **relecture croisée du correctif d'E-183 déjà appliqué** — donc sur du code en
place, pas sur une proposition. C'est la moitié que ce correctif n'a pas fermée.

`scan_concluant = (passwd_rc == 0 and bool(scanned_users))` (`:1310`) mesure la lecture de
**`/etc/passwd`**. Or la purge des clés (`:1364`) et l'écriture de `keys_count` ne dépendent **pas** de
cette lecture : `seen_keys` vient des **deux dumps `authorized_keys`**, qui sont deux lectures
**différentes**.

| lecture | ligne | son code de sortie |
|---|---|---|
| `/etc/passwd` | `:1120` | **LU** — c'est ce que le correctif a ajouté |
| dump **root** des clés | `:1149` | **CAPTURÉ PUIS JAMAIS LU** (`_code`) |
| dump simple-utilisateur | `:1171` | **jamais obtenu** |

**`_code` est la seule occurrence de ce nom dans la fonction** — vérifié. **La valeur qui fermerait le
défaut est déjà dans le code, à portée d'un `if`.** C'est le motif « le cas visible traité, le cas subtil
pris à l'envers », et il est ici particulièrement net : la valeur était dans la main.

Le chemin : `/etc/passwd` se lit bien → `scan_concluant = True`. Le dump root échoue (sudo refusé, mot de
passe root absent, `NOPASSWD` non déployé) → attrapé, journalisé « dump root vide », **et on continue**.
Le dump simple-utilisateur ne rend que les clés du compte de connexion, ou rien. → `seen_keys` quasi vide
→ `stale` = **les clés de tous les autres comptes** → supprimées, garde inactif.

**Seconde face, qui ne demande même pas de suppression** : `keys_count` est **écrit** dans l'inventaire.
Un dump raté écrit donc `keys_count = 0` sur **tous** les comptes, sans rien effacer.
**L'inventaire affirme alors qu'aucun compte de la machine ne porte de clé** — et c'est exactement la
donnée sur laquelle K4 raisonne.

### Occupation mesurée, et c'est la production

| machine | mot de passe | mot de passe root | compte de service | lignes | clés |
|---|---|---|---|---|---|
| 1 `srv-zabbix` | **non** | **non** | oui | 28 | 6 |
| 2 `Test-Server-Debian` | oui | oui | non | 20 | 0 |
| 3 `OpenCVE-Test-OnPrem` | oui | oui | non | 24 | 14 |

**`srv-zabbix` ne stocke ni mot de passe ni mot de passe root.** Son dump root dépend **entièrement** du
`NOPASSWD` du compte de service — c'est-à-dire de la chose même que l'arbitrage K4 tient pour **non
validée**. Si ce `NOPASSWD` cesse de fonctionner, `execute_as_root` retombe sur `sudo -S` avec un mot de
passe **vide**, le dump échoue, et le scan suivant purge. **Ce n'est pas une hypothèse lointaine :
« redéployer la clé SSH pour valider `NOPASSWD` » est une action EN ATTENTE du chantier.**

### Et le journal contredit la réponse

`scan_server_users` rend **inconditionnellement** `{'success': True, 'users': inventory, …}`. Sur un scan
non concluant, le journal écrit un avertissement explicite et **l'appelant reçoit une réussite**, avec un
inventaire conservé donc **ancien**, et aucun champ qui dise que rien n'a été lu. L'écran affiche un
inventaire d'apparence fraîche.

**Le correctif d'E-183 a protégé la DONNÉE et laissé le VERDICT** — l'inverse exact d'E-90, où le verdict
avait été corrigé sans l'état persisté. La classe a deux moitiés et elles se ferment séparément.

### La mesure DÉDOUANE sur l'étendue, et c'est dit aussi nettement

**Il n'y a que DEUX purges par différence d'ensembles dans tout `ssh.py`**, toutes deux dans
`scan_server_users`. Les quatre suppressions du fichier :

| ligne | ce qu'elle supprime | forme | garde |
|---|---|---|---|
| `:1321` | inventaire, fantômes | différence d'ensembles | **OK** (E-183) |
| `:1364` | clés, obsolètes | différence d'ensembles | **mauvais drapeau** — cet écart |
| `:1704` | une clé **nommée** | ciblée | `if code != 0: return 500` — **le bon motif** |
| `:1940` | un compte **nommé** | ciblée | après suppression confirmée |

**Le bon motif existe déjà dans ce fichier** (`server_user_remove_key`, `:1689-1697` : il lit son code de
sortie, refuse de nettoyer la base si la commande distante a échoué, et rend 500). C'est ce qui rend
l'omission de `:1149` d'autant plus visible **une fois qu'on la cherche**.

**Une observation adjacente, bornée exprès** : sur 37 appels à `execute_as_root`, 25 jettent leur retour —
**et ce n'est pas la même classe.** 4 sont des restaurations de secours dans un chemin d'échec (délibéré,
correct) ; 19 composent la création du compte de service, dont le résultat est vérifié **globalement**
juste après par un `sudo whoami` ; 2 restent à examiner. **Aucun des 25 ne pilote une purge par
différence.** Les compter ensemble aurait produit un « 25 appels sans contrôle » du même genre que le
« 21 routes mutantes » qui comptait des routes où le décorateur n'aurait rien fait.

### Non mesuré, et nommé

- **ce que rend `dump_script` quand AUCUN `authorized_keys` n'existe.** La boucle sort en 0 même sans rien
  émettre, donc `rc == 0` avec un dump vide est un cas **légitime**. C'est la mesure qui distingue
  « échec de lecture » de « rien à lire », et **tout correctif proposé repose dessus.** À faire sur
  `Test-Server-Debian`, **jamais** sur la machine 1 ;
- **l'effet du verdict sur les deux écrans** : toute page qui teste `if (data.success)` verrait un scan
  non concluant comme un échec. C'est le comportement voulu, mais il change l'écran ;
- **les trois autres fichiers de `ssh/`** — `configure_servers.py`, `ssh_key_manager.py`, `ssh_utils.py`.
  La question portait sur `ssh.py`. **Ils ne sont pas dédouanés : ils ne sont pas mesurés.**

*Amendement à E-152 — mesuré route par route le 2026-08-27, et l'attribution est exactement à l'ENVERS
de la dangerosité.* Relevé de `backend/routes/fail2ban.py`, vérifié par deux comptages indépendants :

| | |
|---|---|
| routes | **19** |
| portant `@require_role(2)` | **3** — `ban_all_servers`, `install_all`, `geoip` |
| portant la **permission** | **1** — `geoip`, et lui seul |
| portant `@require_machine_access` | 15 |
| ne portant **ni** rôle **ni** permission | **16** |

> **La seule route que `can_manage_fail2ban` protège aujourd'hui est `/fail2ban/geoip` — un lookup
> d'adresse.** Les deux gestes qui touchent **tout le parc**, `srv-zabbix` comprise —
> `ban_all_servers` et `install_all`, ceux d'E-174 — ne portent que `require_role(2)`, **et pas même
> `require_machine_access`.**

E-152 ne se lit donc pas « deux routes sur 23 sont gardées ». Il se lit : **la garde est posée là où elle
coûte le moins.** Et le détail achève le motif : sur `geoip`, l'ordre est `require_role(2)` **puis**
`require_permission` — un rôle 1 y est donc refusé par le **rôle**, jamais par la permission. **La seule
route qui porte la permission est celle où le rôle 1 ne peut rien en mesurer.**

### Et la FIXTURE que ce correctif semblait exiger peut être évitée — par la POSITION du décorateur

Les deux gardes rendent des messages **distincts** (`helpers.py:288` et `:346`) :
`require_permission` → « Permission insuffisante » ; `require_machine_access` → « Accès refusé à cette
machine ». **Le motif d'un 403 est donc lisible**, et l'exécution des décorateurs va de haut en bas :

| ordre dans le patch | ce qu'un rôle 1 obtient | fixture nécessaire |
|---|---|---|
| `@require_permission` **AVANT** `@require_machine_access` | « **Permission insuffisante** » | **aucune** — `rw-test-user` suffit |
| `@require_permission` **APRÈS** | « Accès refusé à cette machine » | un **rôle 2 sans la permission** |

**L'ordre « permission d'abord » est aussi le plus juste indépendamment du test** : refuser pour absence
de droit fonctionnel **avant** de parler de machines ne divulgue pas quelles machines existent. C'est un
choix de correctif de sécurité, donc il appartient à la relecture, pas à la suite qui le mesure.

**Si l'ordre inverse est retenu, la fixture est un QUATRIÈME COMPTE et non une révocation temporaire**,
pour trois raisons mesurées : une révocation échoue **du mauvais côté** — l'état dégradé est une
**absence** de droit, sans symptôme, et si la suite meurt avant son `finally` **treize** suites tombent
pour une raison sans rapport avec ce qu'elles mesurent (le §8 a déjà payé cela deux fois avec la marque
de step-up qui survivait quinze minutes) ; le trou « rôle 2 sans permission » n'est **pas propre à ce
module** — `supervision/` et `services/` (E-149) posent la même question, donc un compte se documente une
fois là où une fixture serait recréée partout ; et il ne touche **à rien d'existant**, `rw-test-admin`
gardant ses neuf permissions.
**Deux réserves qui conditionnent sa création** : il exige un **secret TOTP** — et on n'en invente
jamais — et **un compte de plus est une identité de plus dans le parc**, visible aux écrans
d'administration et susceptible d'être proposée dans des listes. C'est exactement le reproche fait aux
cinq `e2e_test_*` offerts comme identité ChatOps. Il devra donc porter un second facteur **et** être
documenté au §6, pas seulement créé.

---

## E-188 — `active_sessions.last_activity` n'est JAMAIS mise à jour : la purge « inactive depuis 7 jours » signifie « CRÉÉE il y a 7 jours »

**Trouvé le 2026-08-27 en cherchant un défaut chez soi** — les deux index posés sur cette colonne
coûtent-ils une écriture d'index par requête, puisqu'elle porte `ON UPDATE CURRENT_TIMESTAMP` ? La mesure
a dédouané les index et trouvé ceci.

    total = 3930 · last_activity = created_at : 3930 · différentes : 0

**Zéro mise à jour sur 3 930 lignes.** La colonne porte bien `ON UPDATE CURRENT_TIMESTAMP`, mais **rien
ne l'écrit jamais** : la ligne est posée une fois à la connexion
(`REPLACE INTO active_sessions (session_id, user_id, ip_address, user_agent)`,
`auth/functions.php:81` et `login.php:212` — la colonne n'est pas dans la liste), et `verify.php:66` la
**lit** à chaque requête sans jamais la toucher. Vérifié indépendamment : aucun `UPDATE` ni `SET` sur
cette colonne dans `legacy/auth/`, `backend/` ni `backend/routes/`.

### Pourquoi cela CORRIGE un arbitrage déjà porté à l'exploitant

La purge dit `WHERE last_activity < NOW() - INTERVAL 7 DAY`. Cela se lit « inactive depuis 7 jours ».
**Cela signifie en réalité « CRÉÉE il y a plus de 7 jours ».** Une session utilisée tous les jours serait
révoquée au septième.

**Les deux défauts se masquent mutuellement** : la purge ne tourne pas (`LOG_RETENTION_DAYS = 0`, E-180),
donc personne n'a jamais été déconnecté à tort — **et c'est précisément pour cela que personne n'a jamais
vu le second.**

> **E-180 était donc incomplet, et l'incomplétude allait dans le sens dangereux.** Il disait « activer
> `LOG_RETENTION_DAYS` n'est pas la bonne réponse seule : `user_logs` porte une chaîne scellée ». Vrai —
> et il manquait que **les deux issues proposées déconnecteraient les exploitants tous les sept jours, en
> pleine session.** Ce qui était présenté comme de l'**hygiène** coupe des sessions **actives**.

**L'ordre correct est : réparer `last_activity` AVANT d'activer quoi que ce soit.** Trois formes, aucune
tranchée ici — la mettre à jour là où `verify.php` lit déjà la ligne (une écriture par requête, à peser) ;
renommer le prédicat pour qu'il dise ce qu'il fait (`created_at`) ; ou sortir ce nettoyage de la porte
`LOG_RETENTION_DAYS` avec un seuil qui lui soit propre.

**Relevé, non corrigé** : `profile.php:374` affiche à l'utilisateur une colonne « dernière activité » qui
est en fait l'heure de **connexion** — égales sur les 3 930 lignes. C'est du legacy, et on ne soigne pas
ce qu'on démonte ; mais **le portage héritera de la colonne s'il la reprend telle quelle.**

**Et le soupçon initial est levé par la mesure** : la colonne ne changeant jamais après l'insertion,
`idx_sessions_activity` et `idx_sessions_user_activity` ne sont touchés qu'à la connexion, une fois par
session. **Coût nul sur le chemin chaud** — dit parce que le soupçon portait sur le travail de celui qui
l'a vérifié.

---

*Décision sur E-152, prise le 2026-08-27 — l'ORDRE des deux décorateurs.*

> **`@require_permission` AVANT `@require_machine_access`**, sans exception.

**Et ce n'est pas un choix : c'est déjà la convention du dépôt**, mesurée par balayage AST des routes
portant les **deux** décorateurs :

| | |
|---|---|
| routes portant permission **et** accès machine | **34** |
| permission **avant** | **34** |
| accès machine avant | **0** |

Réparties sur `bashrc.py` (6), `graylog.py` (3), `supervision.py` (18), `wazuh.py` (7). **Aucun
contre-exemple dans tout le dépôt.** Adopter l'ordre inverse ferait de `fail2ban/` le seul module à
l'inverser — **et cette asymétrie-là a déjà coûté** : c'est exactement elle, entre `/server_status` et
`/server_lifecycle`, qui a fait écrire « IDOR » à tort dans `AUDIT-GARDES-BACKEND.md` §2, puis rétracter.
*Un ordre qui varie sans raison écrite se lit comme une intention.*

L'argument de non-divulgation — refuser pour absence de droit fonctionnel avant de parler de machines ne
révèle pas quelles machines existent — tient, et reste la **seconde** raison. Il ne départageait pas
seul.

### La sonde ne demande AUCUNE fixture, et elle porte un TÉMOIN

Non pas en lisant le **message** rendu, mais en **mesurant le statut** — la règle du chantier appliquée
telle quelle. Une requête **sans `machine_id` du tout** : `require_machine_access` ne trouve alors aucun
identifiant — son no-op connu — et laisse passer ; le corps refuse ensuite en 400.

| requête | avant le correctif | après |
|---|---|---|
| `POST /fail2ban/status`, corps `{}`, `rw-test-user` (rôle 1, **sans** perm) | 400 | **403** |
| idem, `rw-test-admin` (rôle 2, **avec** perm) | 400 | **400** ← le **témoin** |

La première mesure le correctif ; la seconde **isole sa cause**. **La faiblesse connue de
`require_machine_access` devient l'instrument qui mesure le garde posé au-dessus de lui.**

**Et c'est un argument DE PLUS pour l'ordre retenu** : avec l'ordre inverse, le rôle 1 obtiendrait 403 lui
aussi — par la permission placée après un no-op — donc **les deux ordres deviennent indistinguables au
statut** et il faut revenir au message. L'ordre retenu se mesure **au statut ET au message** ; l'ordre
inverse **seulement au message**. C'est donc le seul des deux qui se mesure **sans fabriquer une identité
de plus dans le parc**.

**Le quatrième compte n'est donc pas nécessaire**, et ses deux réserves — le secret TOTP qu'on n'invente
jamais, l'identité de plus dans le parc — n'ont pas à être levées. Les trois raisons contre la révocation
temporaire restent justes ; elles n'ont simplement plus d'objet.

*Correction de compte* : un document d'audit annonçait **18** routes ; il y en a **19**. Rien de ce qui en
découlait ne change — la route de l'injection, les comptes qui l'occupent, le correctif d'E-174 sont
inchangés. Mais **un compte faux dans un document d'audit se recopie**, et celui-là l'avait déjà été une
fois.

---

## E-189 — Le préflight de K4 teste le STATUT et pas le VERDICT : une fragilité placée au pire endroit

**Ce n'est PAS un défaut aujourd'hui, et c'est dit d'abord.** Relevé le 2026-08-27 par un balayage
systématique des appelants du portage, et vérifié à la main.

`laravel/public/js/cles-ssh.js:189` — **l'écran qui décide si un déploiement de clés peut partir** —
teste `rep.ok` et lit `d.results` **sans jamais regarder `d.success`**. Le commentaire l'assume même :
« LE STATUT D'ABORD, et le message du corps s'il en porte un. »

Et cela coïncide, aujourd'hui. `preflight_check` (`backend/routes/ssh.py:327`) n'a que **trois** retours,
vérifiés un par un :

| retour | statut | `success` |
|---|---|---|
| « Aucune machine spécifiée » | **400** | `False` |
| « Accès refusé à la machine N » | **403** | `False` |
| le chemin normal (`:494`) | **200** | **`True` — inconditionnellement** |

**Les deux contrôles rendent donc le même verdict, et c'est une coïncidence, pas une propriété.**

> Le jour où cette route gagne un `200 + success: false` — **ce qui vient précisément d'arriver à trois de
> ses voisines** (E-184, E-186, E-187) — l'écran présenterait des **résultats partiels comme une
> vérification réussie**, sur le module que ce plan appelle le plus dangereux du chantier, et juste avant
> le geste qui **révoque des accès sur la production**.

### Le résultat d'ensemble est un DÉDOUANEMENT, et sa raison est ce qui compte

Relevé : **50 appels dans 29 fichiers**. **Aucun appelant du portage ne présente aujourd'hui un refus
comme une réussite.** Mais la raison n'est pas que tout le monde lit `success` :

> **C'est que tout refus porte aujourd'hui un statut non-200.** Tester `.ok` et tester `success` rendent
> donc le même verdict, et les appelants qui ne testent que le statut sont **couplés à une coïncidence**
> — celle que trois correctifs viennent de rompre.

**Et c'est ce qui rend la règle exacte** : *quand une valeur cesse d'être constante, l'endroit à auditer
est celui qui ne la testait pas.* Les cinq sites concernés sont **invisibles au diff** de ces trois
correctifs, puisque rien n'y a changé. Les quatre autres visent des routes **Laravel**, dont tous les
refus portent déjà 400/404 : **la famille de la cible est ce qui tranche**, et les confondre aurait
produit un relevé de 28 « fautifs » dont 27 ne le sont pas.

### Et l'instrument s'est trompé trois fois avant d'être juste — la troisième est la leçon

| version du motif | résultat |
|---|---|
| `success` dans la fonction englobante | **28 « fautifs »** |
| + « rend un `.json()` » | 26 — le motif ratait `corpsJson = await r.json(); return {corps: corpsJson}` |
| + « lit du texte et jamais du JSON » | **dédouanait le préflight**, qui lit `.text()` dans sa branche d'ERREUR |
| + `getReader()` d'abord | **5**, tous qualifiés à la main |

**La troisième version a fabriqué un faux NÉGATIF.** Les deux premières accusaient des appelants
corrects ; celle-là **dédouanait le seul cas fragile du relevé**.

> Un motif trop large se trompe **dans les deux sens**, et la seconde erreur est la plus coûteuse :
> **un vert ne se relit pas.**

### La classe, que la matrice QA nomme désormais

Elle réunit ce site, les passes creuses de F6 et l'assertion aveugle de `go-adm-comptes-distants` :

> **Quand une route gagne un verdict, toute assertion qui passait par un PROXY de ce verdict devient
> aveugle — et elle passe au vert en ne mesurant plus rien.** Un statut HTTP, une liste relue en base, un
> compteur de départs de requêtes : trois proxys qu'un `200 + success:false` ne distingue plus.

### Un point POSITIF relevé au passage, et il mérite d'être écrit

`preflight_check` ne porte **aucun** décorateur d'accès machine : il appelle `check_machine_access(mid)`
**dans une boucle, sur chaque machine visée** (`:342-345`). C'est le bon motif — un décorateur ne sait
contrôler qu'**un** identifiant, et cette route en reçoit une liste. **Une garde absente qui n'est pas un
trou**, et c'est la première de cette forme sur le chantier.

---

## E-190 — « Un déploiement ne déploierait rien » : la moitié rassurante d'un constat dont l'autre moitié DÉTRUIT

**Cette phrase s'affiche MAINTENANT, sur l'écran qui décide de K4.** Trouvée le 2026-08-27 par relecture
croisée d'E-189, vérifiée sur les trois points.

`laravel/lang/fr/ssh.php:44` et `en/ssh.php:44` :

> « **ATTENTION : aucun compte actif ne porte de clé SSH — un déploiement ne déploierait rien** »
> « WARNING: no active account carries an SSH key — a deployment would deploy nothing »

**Mesure en base :** `SELECT COUNT(*) FROM users WHERE active = 1 AND ssh_key <> ''` rend **0**. La
condition d'affichage est donc remplie **aujourd'hui**.

### Elle est vraie du DÉPLOIEMENT et fausse du GESTE

`configure_users` fait **deux** choses, et la seconde ne dépend d'**aucune** clé :

1. la boucle de déploiement ne pose rien si personne n'a de clé — **la phrase est exacte pour elle** ;
2. `revoked = managed_users - authorized_names` (`configure_servers.py:755`) s'exécute **quoi qu'il
   arrive**, et fait `rm -f /home/<user>/.ssh/authorized_keys`.

> **« Ne déploierait rien » se lit « ne ferait rien ».** Un déploiement lancé aujourd'hui, avec zéro
> compte porteur de clé, ne déploierait effectivement rien — **et supprimerait quand même les
> `authorized_keys` de `claude-agent` et de `Timikana` sur `srv-zabbix`** (E-174 §K4, deux comptes
> mesurés, sans clé de plateforme, donc non rétablissables).

C'est la **seule** phrase de synthèse que l'écran met en avant, et elle est jointe par un tiret à
« Aucun prérequis manquant ». Un opérateur qui lit les deux ensemble conclut qu'il ne risque rien.

### Et la ligne juste AU-DESSUS porte le bon raisonnement

`ssh.php:41`, deux lignes plus haut dans le même fichier :

> « La vérification n'est pas concluante : le serveur n'a pas rendu de verdict. **Rien n'est affiché
> ci-dessous, parce qu'un résultat partiel se lirait comme une vérification réussie.** »

**L'auteur de cette ligne avait donc compris la classe exactement**, et la ligne suivante la commet.
C'est le motif « le cas visible traité, le cas subtil pris à l'envers » — **dans deux lignes adjacentes
du même fichier.** La présence d'un raisonnement correct *à côté* est ce qui endort la question.

### Correctif : quatre mots, et il ne peut rien casser

Dire que le déploiement ne **poserait** rien **et** qu'il **révoquerait quand même**. Parité FR/EN dans
le même commit. **Vérifié : `cles_aucune` n'apparaît dans AUCUN fichier de `tests/e2e/`** — aucune
assertion n'attend ce texte.

### Quatre autres constantes sur le même écran, de la même famille

- **la forme d'E-183, déplacée de la base vers l'écran de décision.** `users_revoked`,
  `users_to_create` et `user_impact` ne sont posés que dans un `try` **imbriqué** dans celui de la
  session SSH. Si l'audit d'inventaire lève, l'`except` **journalise sans rien ajouter à
  `result['errors']`** — et `ssh_ok` vaut déjà `True`. Côté écran, `listeNommee` sort **en silence** sur
  un champ absent. Résultat composite : badge **OK**, aucune erreur, **aucune liste « Accès qui seront
  RÉVOQUÉS »**, synthèse « Aucun prérequis manquant ». **Une machine dont l'inventaire n'a pas pu être
  lu est présentée comme vérifiée et sans révocation à prévoir** ;
- **deux implémentations de la même règle de révocation**, et elles ne filtrent pas pareil :
  `preflight` (`ssh.py:459-464`) filtre `u.active = 1` ; `configure_servers:735-737` **ne filtre pas** ;
  et `cleanup_users:658-661`, **dans le même fichier**, filtre. Aucun commentaire ne le dit.
  **Le sens dédouane pour l'instant** — `autorisés_preflight ⊆ autorisés_déploiement`, donc le préflight
  **sur-annonce** et ne sous-annonce jamais — **mais c'est accidentel** : un filtre ajouté au préflight
  que le déploiement n'a pas inverserait l'inclusion, et l'écran **sous-annoncerait ce qui va être
  détruit**. Mesuré : **0 compte inactif** dans le parc, donc aucun porteur. *Le correctif juste n'est
  pas d'aligner les deux copies mais de n'en garder qu'une* — la leçon de `maintenance/` ;
- `d.results` absent → `resultats = []` → `bloquantes = 0` → **« Aucun prérequis manquant » avec zéro
  machine affichée**. Lire `d.success` (E-189) ferme celle-ci en même temps ;
- une machine absente de `results` n'est comptée **ni** bloquante **ni** prête : `resultats.length`
  n'est jamais comparé à `cibles.length`. Faible portée, les cibles venant de cases réelles.

### Les cinq sont la même faute

> **Un ensemble ou un constat PARTIEL lu comme COMPLET.** Zéro clé lu comme zéro effet ; champ absent lu
> comme liste vide ; deux opérandes supposés égaux ; `success` supposé constant ; `results` supposé
> exhaustif.

Sur cet écran, la conséquence n'est pas un affichage faux — c'est **un arbitrage pris sur une
information qu'on croit avoir.**

### Le point positif d'E-189 est CONFIRMÉ, et il est plus fort qu'annoncé

`preflight_check` sans décorateur d'accès machine n'est pas un trou — il boucle
`check_machine_access(mid)` et refuse en 403 au premier. **Et il y a une raison de plus de ne pas le
« corriger » : cette route reçoit sa liste sous le nom `machines`** — un **troisième** nom, qu'aucune
version du décorateur ne lit (il connaît `machine_id`, `server_id`, `machine_ids`, `server_ids`).
**Ajouter le décorateur serait inerte ET donnerait l'apparence d'une protection que le corps assure
seul.** À écrire tel quel dans `AUDIT-GARDES-BACKEND.md`, sinon le prochain lecteur l'ajoutera en croyant
bien faire.

**Non mesuré, et dit** : le préflight n'a pas été exécuté (il ouvre des sessions SSH réelles) ;
`remove_from_sudoers` n'a pas été vérifié sur son code de retour ; et **`/deploy` lui-même
(`ssh.py:246`) n'a pas été relu — la question portait sur la chaîne de DÉCISION. Le geste n'est pas
dédouané, il n'est pas mesuré.**

*Amendement à E-190 — pourquoi le verdict affiché est la SEULE barrière.* Vérifié le 2026-08-27 :
`cles-ssh.js:87-89` active `deploy-btn` **et** `verifier-btn` sur la seule condition `n === 0`, où `n` est
le **compte de la sélection**.

```js
for (const id of ['deploy-btn', 'verifier-btn']) {
    const b = document.getElementById(id);
    if (b) b.disabled = n === 0;
}
```

**Le bouton de déploiement n'est donc PAS conditionné au verdict de la vérification.** Le panneau
s'ouvre quel que soit le résultat du constat — ce qui est **cohérent** avec la convention du portage
(« séparer vérifier et agir », et ne pas faire d'un constat une autorisation), mais qui a une
conséquence directe :

> **Le verdict affiché est la seule chose entre l'exploitant et sa décision.** Il n'y a aucun garde
> mécanique en aval qui rattraperait un verdict faux. C'est ce qui fait passer E-190 d'un défaut de
> libellé à un défaut de **décision**, et ce qui justifie de le corriger avant tout le reste.

**Portée d'aujourd'hui, et elle borne l'urgence** : K4 n'étant pas porté, **aucun déploiement ne part de
cette page**. L'écran est celui qu'on lit **avant** d'aller déclencher le geste ailleurs — donc le
mensonge porte sur l'information qui prépare la décision, pas sur le geste lui-même.

---

## E-191 — `POST /deploy` : la route la plus destructrice du chantier est la MOINS gardée, et elle annonce des révocations qu'elle ne vérifie pas

**Mesuré le 2026-08-27, décorateur par décorateur.** C'est le §7 « `can_deploy_keys` appliquée sur la
PAGE et nulle part sur la REQUÊTE » enfin **chiffré** — et c'est pire que « pas de permission » : il n'y
a **pas de rôle non plus**.

| route | ce qu'elle fait | gardes |
|---|---|---|
| **`POST /deploy`** (`ssh.py:246`) | écrit des clés root sur **toute une flotte** sélectionnée, **et révoque** | **`@require_api_key` SEUL** |
| `POST /deploy_platform_key` (`:517`) | écrit une clé sur **une** machine | `api_key` + **`role(2)`** + **`machine_access`** |
| `POST /reboot_server` (`monitoring.py:224`) | **redémarre** une machine | `api_key` + **`role(2)`** + **`machine_access`** |

> **La route qui écrit en root sur un parc entier est moins gardée que celle qui redémarre une seule
> machine.** Et sa voisine du même fichier, 270 lignes plus bas, porte le jeu complet avec un commentaire
> de patch explicite — « *Patch A01 : déploiement de clé plateforme réservé admin* ». **Quelqu'un a donc
> durci le déploiement d'une clé sur une machine et laissé ouvert celui du parc entier.**

Ce n'est pas une omission isolée : c'est une **asymétrie entre deux gestes du même module**, et le motif
« le cas visible traité, le cas subtil pris à l'envers » à son maximum — le geste durci est le moins
dangereux des deux.

### Et `/deploy` n'a NI fenêtre de maintenance NI approbation à quatre yeux

Mesuré : **zéro** occurrence de `is_allowed|maintenance|approvals|gate(` dans la route. Or d'autres
gestes du parc en ont. La route qui déploie et révoque sur une flotte n'a donc **aucun** des trois
contrôles que le dépôt sait poser.

### `/deploy` est une enveloppe mince, et son code de retour est JETÉ

    subprocess.Popen(["python3", "/app/configure_servers.py"] + machine_ids)
    process.wait()          # :279 — le code de retour n'est jamais lu

**Il n'ajoute rien au geste** : décrire `/deploy` en lisant `configure_servers.py` était donc **juste**.
**Dédouané, et cherché** : pas d'injection par l'`argv` — `argparse`, et les identifiants ne servent qu'à
`[m for m in all_machines if str(m['id']) in machines_to_configure]`, une comparaison de chaînes contre
des identifiants venus de la base. Une chaîne arbitraire ne sélectionne rien et sort en `exit(1)`.
Mais un déploiement **qui meurt** ne laisse **aucun** signal ailleurs que dans son fichier de log — **et
ce log est tronqué** (`open(..., "w")`) au déploiement suivant. Famille E-90, sur la route la plus
dangereuse du dépôt.

### ⚠ ET LA RÉVOCATION EST ANNONCÉE SANS ÊTRE VÉRIFIÉE — c'est l'INVERSE d'E-183

Dans la boucle de révocation, **ni** `rm -f {ak_path}` **ni** `remove_from_sudoers` ne lit son code de
retour — confirmé pour les deux. Et la boucle journalise, pour chaque compte,
« *Accès révoqué — retrait clé SSH et sudo* ».

> **Le déploiement peut donc annoncer une révocation qui n'a pas eu lieu.** E-183 **détruisait une donnée
> vraie** ; celui-ci laisse un **accès ouvert en affirmant qu'il est fermé**, sur le module qui écrit en
> root. **Pour un exploitant qui révoque un accès pour une raison de conformité, c'est la pire des
> deux** — la première se répare, la seconde se croit faite.

### Correctifs, par gravité — et le dernier n'est PAS un correctif

1. **la boucle de révocation lit ses codes de retour**, pour le `rm -f` de la clé **et** pour le
   sudoers. Un accès annoncé révoqué et non révoqué sort en **erreur**, pas en `logger.info` ;
2. **`/deploy` lit le code de retour de son sous-processus** ;
3. **la fenêtre de maintenance et l'approbation à quatre yeux sur `/deploy`** : c'est un **ajout de
   garde** sur la chaîne K4, pas un correctif de fiabilité. **Même régime que les six en arbitrage — rien
   ne sera écrit sans le mot de l'exploitant.** Et le rôle absent relève du même arbitrage, ouvert au §7
   depuis le début du chantier.

---

*Rétractation sur E-190 §« deux implémentations de la règle de révocation » — la prémisse était fausse,
et fusionner aurait été une ERREUR.*

J'avais demandé de n'en garder qu'une, en invoquant la leçon de `maintenance/`. **La mesure l'interdit.**
`deploy_user_config` est appelée pour **TOUS** les comptes, actifs et inactifs, et elle porte
(`configure_servers.py:499`, `:517-520`) :

```python
if user.get('active') and ssh_key:
    …écrit la clé…
else:
    execute_command_as_root(channel, f"rm -f {authorized_keys_path}")   # RETIRE la clé
```

**Les comptes inactifs perdent donc bien leur clé — par un autre chemin, en aval.** Et la branche
inactive appelle **aussi** `remove_from_sudoers`.

| compte | ce que le préflight annonce | ce que le déploiement fait |
|---|---|---|
| actif, autorisé | garde l'accès | clé écrite |
| **inactif**, autorisé | **révoqué** | **clé retirée** — par `deploy_user_config` |
| absent de `all_users`, managé | révoqué | clé retirée — par la boucle |

**Le préflight dit vrai dans les trois cas.** Il ne sur-annonce pas : il annonce une révocation qui a
réellement lieu, par un chemin différent.

**Ce qui est réellement en cause est un NOM.** Les deux ensembles s'appellent « autorisés » et désignent
deux notions distinctes — pour le préflight, « les comptes qui **garderont** l'accès » ; pour
`configure_users`, « les comptes que `configure_user` a **traités** », dont le seul rôle est de décider
qui **n'entre pas** dans la boucle de révocation. **N'en garder qu'une les confondrait, et le préflight
cesserait d'annoncer les révocations de comptes inactifs — une SOUS-annonce, exactement la direction
qu'on voulait éviter.**

Le fond de ma lecture tient — l'équivalence n'est écrite nulle part et elle est maintenue par une
compensation dans une **troisième** fonction — mais **le remède que je proposais ne s'applique pas.**
Le bon remède est celui que la même journée avait déjà écrit : *le correctif n'est pas toujours du code,
c'est parfois une phrase à l'endroit exact où la propriété tient.* Donc : **renommer** `authorized_names`
en ce qu'il est, **écrire la compensation** dans `deploy_user_config` à la ligne `else`, **aucune
fusion**, aucun changement de comportement.

*Et une correction à mon relevé : `clean_up_users` est du CODE MORT.* Aucun appelant — seulement sa
définition et une mention dans une **docstring de classe** (`:567`), qui annonce toujours qu'elle
nettoie, alors que `configure()` dit en clair « le nettoyage automatique des utilisateurs est
DÉSACTIVÉ ». Il n'y a donc pas **trois** traitements vivants d'une notion mais **deux**, plus une copie
morte. **Sixième « en-tête qui mente » du chantier**, et la première dans une docstring de classe.

---

## E-192 — La révocation d'accès se VÉRIFIE, et le correctif évident était impossible

Correctif de la seconde moitié d'E-191. **Refermé le 2026-08-27.**

**Le correctif attendu — « lire le code de retour » — n'existait pas à ce niveau.**
`execute_command_as_root` rend la **sortie**, jamais le code : mesuré, il le calcule sur son chemin
`service_account` (`ssh_utils.py:831`) et le **jette**, et il le jette aussi en dépaquetant
`execute_as_root`. **Un `rm -f` refusé est donc indiscernable d'un `rm -f` réussi pour TOUS ses
appelants** — et le rendre ne se décide pas dans ce commit, la fonction ayant d'autres appelants dans
`iptables_manager.py`.

> **Donc on ne vérifie pas la commande : on vérifie son EFFET.** `_absence_verifiee` sonde l'état de la
> machine **après** le geste — la clé SSH, le sudoers unifié, et l'ancien fichier à nom nu. Et le verdict
> d'échec dit la phrase qui compte : **« L'ACCÈS DOIT ÊTRE CONSIDÉRÉ COMME ENCORE OUVERT. »**

**Et le piège de `v1.37.11` devait être refermé ici aussi.** Le marqueur est assemblé par
**concaténation shell**, parce que sur les machines en mode `su`/`sudo` interactif le canal **échote** la
commande : un marqueur écrit en clair reviendrait dans la sortie **sans que rien n'ait été vérifié** —
faux positif **permanent**, sur une révocation d'accès. Mesuré, 9 assertions / 9 PASS :

| cas | verdict |
|---|---|
| écho PTY de la commande seule | **NON vérifié** — la ligne échotée ne contient pas `__RW_""ABSENT_OK__` |
| écho PTY **+** vraie sortie | **VÉRIFIÉ** — l'écho n'aveugle pas la sonde |
| marqueur en sous-chaîne | **NON vérifié** |
| exception, ou sortie `None` | **NON vérifié** — fail-closed |

**Un défaut trouvé au passage, et dédouané pour éviter une fausse alerte** : `uname` n'était pas validé
avant d'être interpolé dans un `rm -f` root. **Ce n'est PAS une élévation de privilège** — le nom vient
de `server_user_inventory`, donc du `/etc/passwd` de la machine, et seul le root de cette machine peut y
poser un tel nom, la commande s'exécutant sur cette même machine. Mais un nom porteur d'un espace ou
d'un `;` fait échouer le retrait **en silence** : c'est le défaut d'E-192 lui-même, donc corrigé au même
commit.

## E-193 — `/deploy` lit son code de sortie, et le verdict va là où on REGARDE

**La réponse HTTP ne peut pas le porter, et c'est normal** : `threading.Thread` dans le corps, donc
accusé de réception et non verdict (§8). Mais il n'était porté **nulle part**. Le seul endroit où
l'exploitant regarde est le flux SSE, qui ne lit que `deployment.log` — **le verdict y est donc écrit.**

Deux précautions, chacune pour un piège déjà payé : ouverture en `a` et **jamais** `w`, sinon on efface
le journal qu'on cherche à conclure ; et le terminateur `[Fin du flux de logs]` **n'est pas émis** —
c'est un **jeton de protocole** comparé littéralement, et l'écrire ferait croire au client que le flux
est fini.

Et sur un échec, le verdict dit aussi ce qui **reste vrai** : **« Les gestes déjà émis n'ont PAS été
annulés. »** *Un déploiement partiel n'est pas un déploiement annulé.*

## E-194 — Le préflight dit désormais qu'il n'a pas pu regarder

`audit_inventaire` est **toujours présent**, faux par défaut, et ne passe à vrai qu'**après** le calcul
de `users_revoked`. Il porte la différence entre « **établi et vide** » et « **pas établi** », que
l'absence d'un champ ne pouvait pas porter — c'est la forme générale du défaut, et pas seulement son
symptôme. L'`except` ajoute désormais à `errors`.

**La moitié backend ne suffit pas** : un écran qui affiche « aucun accès à révoquer » doit le
**conditionner à ce drapeau**, sinon le composite trompeur d'E-190 reste possible côté affichage.

## E-195 — Deux ensembles s'appelaient « autorisés » et ne désignaient pas la même chose

`authorized_names` → **`comptes_traites`**, et la compensation **écrite dans la branche `else` de
`deploy_user_config`** — avec les **trois** fonctions qui la maintiennent ensemble, et ce qui casserait
si l'on retirait ce `rm -f`. **Aucun changement de comportement, aucune fusion** : voir la rétractation
sous E-191, où fusionner aurait fait **sous-annoncer** le préflight.

C'est l'application du remède écrit le même jour — *le correctif n'est pas toujours du code, c'est
parfois une phrase à l'endroit exact où la propriété tient* — et le premier cas du chantier où un
renommage **est** le correctif.

---

*Sur les quatre : rien n'est mesuré en EXÉCUTION.* Les quatre sont vérifiés structurellement et par
sonde ; **aucun n'a été éprouvé contre une machine**, et éprouver E-192 signifierait **révoquer un accès
pour de vrai**. Ils sont par ailleurs **inertes jusqu'au prochain redémarrage** du conteneur — donc **une
révocation lancée maintenant s'annoncerait encore sans se vérifier.**

*Et une règle de coordination que ces quatre commits ont révélée* : **les numéros d'écart viennent du
Lead, comme les numéros de version.** Ils ont été pris ici dans l'ordre et sans collision — vérifié,
`E-192` à `E-195` claimés une fois chacun, `PARITE.md` s'arrêtant à `E-191` — mais c'est **la même classe
que la collision de `v1.38.19`** : un identifiant choisi par message est valide au moment où on l'écrit,
pas au moment où un autre l'emploie. **Nommer le défaut en clair suffit ; le numéro s'attribue ici.**

---

## E-197 — `_valid_username` accepte `.` et `..`, et la version STRICTE existe déjà deux fois dans le dépôt

Trouvé le 2026-08-27 **en vérifiant une supposition faite en écrivant E-192** : ce correctif rend
`_valid_username` **porteur** — c'est lui qui décide si un nom d'inventaire peut être interpolé dans un
`rm -f` root — et cela n'avait pas été mesuré.

`configure_servers.py:56` : `_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')`. **Il accepte `.` et
`..`, qui sont des composants de chemin et non des noms de compte.** Chemins normalisés, mesurés :

| nom | clé SSH | sudoers unifié | sudoers legacy |
|---|---|---|---|
| `alice` | `/home/alice/.ssh/authorized_keys` | `…/rootwarden-alice` | `…/alice` |
| **`..`** | **`/.ssh/authorized_keys`** | `…/rootwarden-..` | **`/etc`** |
| **`.`** | **`/home/.ssh/authorized_keys`** | `…/rootwarden-.` | **`/etc/sudoers.d`** |
| `-rf` | `/home/-rf/.ssh/…` | `…/rootwarden--rf` | `…/-rf` |

**`-rf` est DÉDOUANÉ** : les trois chemins sont préfixés, donc aucune injection d'option. Et les deux
chemins `rootwarden-..` / `rootwarden-.` **ne traversent pas** — `..` ne traverse que comme composant
entier, et là il est collé au préfixe.

### La portée destructrice est PLUS ÉTROITE que la table ne le suggère — mesuré

`rm -f` **échoue sur un répertoire**. Mesuré dans le conteneur, sur une cible jetable :

    rm: cannot remove '/tmp/rwtest/d': Is a directory
    code=1  ·  le repertoire EXISTE ENCORE

Donc `..` → `/etc` et `.` → `/etc/sudoers.d` **échouent sans effet**. **La seule cible réellement
supprimable est `/.ssh/authorized_keys`** (cas `..`), qui n'existe que là où le répertoire personnel de
root est `/` — pas le défaut sur Debian. **Le défaut est donc « un `rm -f` root sur un chemin qui n'est
pas celui visé », et non « un `rm -f` sur `/etc` »**, et il faut le dire ainsi : une formulation trop
large aurait fait chercher une catastrophe là où il y a un défaut de validation.

**Ce n'est PAS une élévation de privilège**, pour la même raison qu'au relevé précédent : seul le root de
la machine peut poser un tel nom dans son `/etc/passwd`, et la commande s'exécute **sur cette même
machine**. Rien n'est gagné.

**Atteignable, par une seule voie** : `scan_server_users` **ne valide pas** les noms qu'il insère dans
`server_user_inventory` — il valide `home` par une expression régulière et **pas** `username`. Un
`/etc/passwd` portant une ligne `..:` produit donc une ligne d'inventaire nommée `..`.

### ⚠ Et la version JUSTE existe déjà DEUX fois dans le même dépôt

    backend/configure_servers.py:56   ^[a-zA-Z0-9._-]{1,32}$        <- accepte `.` et `..`
    backend/sudo_manager.py:32        ^[a-z_][a-z0-9_-]{0,31}$      <- les REFUSE
    backend/sftp_manager.py:34        ^[a-z_][a-z0-9_-]{0,31}$      <- les REFUSE

Vérifié : la stricte refuse `.` et `..` et accepte `alice`. **Il y a donc TROIS implémentations de « un
nom d'utilisateur valide », et la plus permissive est celle qui garde le chemin d'un `rm -f` root.**

> **Ce n'est pas « ajouter une garde » : c'est aligner la plus dangereuse des trois sur les deux autres.**
> Même classe qu'E-152 — *la convention existait déjà, et personne ne l'avait mesurée* — et qu'E-195,
> *plusieurs implémentations d'une même notion*. Le correctif n'est donc pas d'écrire une quatrième
> expression mais de **reprendre celle qui existe**.

**Risque sur le cas normal : nul, et c'est mesurable** — aucun système Linux n'a de compte nommé `.` ou
`..`, `useradd` les refuse. Les quatre autres appelants n'en profitent que dans le bon sens.

### L'effet de bord est instructif : E-192 échoue FERMÉ, mais pour la mauvaise raison

Pour `..`, la sonde d'E-192 teste `test ! -e /etc`, qui existe toujours — elle rend donc
**« RÉVOCATION NON VÉRIFIÉE » en permanence**. Le correctif échoue donc **du bon côté**, ce qui est la
bonne direction, **mais il le fait pour une raison qui n'est pas la vraie cause et sans jamais la
nommer.** Un fail-closed qui masque son motif est un fail-closed qu'on finit par croire cassé.

**Un second endroit, DISTINCT, à ne pas traiter au même commit** : `scan_server_users` devrait **refuser
d'insérer** un nom invalide plutôt que de laisser l'inventaire porter des lignes qu'aucun geste ne pourra
honorer. C'est *valider aux deux bouts* — mais c'est un autre défaut, et il change ce que l'écran
d'inventaire affiche.

---

*Rétractation sur E-197 — mon instruction « reprends l'expression stricte » était FAUSSE, et elle aurait
rouvert le trou que E-192 à E-195 venaient de fermer.*

J'avais écrit : « n'écris pas une quatrième expression, reprends celle qui existe, aligne la plus
dangereuse sur les deux autres ». **Mesuré sur les 41 noms réels du parc, la stricte en refuse trois** —
et ma propre contre-mesure en trouve un quatrième :

| nom | laxe | **stricte** | correctif étroit |
|---|---|---|---|
| `Debian-exim` — compte système Debian, sur **toute** machine | accepté | **REFUSÉ** | accepté |
| `Debian-snmp` — idem | accepté | **REFUSÉ** | accepté |
| `Timikana` — **un compte réel** | accepté | **REFUSÉ** | accepté |
| `a.b` | accepté | **REFUSÉ** | accepté |
| `.` `..` `...` `....` | accepté | refusé | **REFUSÉ** |

La cause est la **majuscule**, que `^[a-z_][a-z0-9_-]{0,31}$` interdit en première position.

> **Et la conséquence est aggravée par E-192 lui-même** : un nom invalide y vaut désormais « RÉVOCATION
> REFUSÉE, aucun geste émis ». Aligner aurait donc rendu ces trois comptes **impossibles à révoquer, en
> silence** — c'est-à-dire **exactement le trou que la série E-192 → E-195 vient de fermer**, rouvert par
> mon instruction.

### La différence entre les trois implémentations est un DOMAINE, pas une sévérité

C'est ce que je n'avais pas vu, et c'est le fond :

- `sudo_manager` et `sftp_manager` valident des noms que RootWarden **gère** — la règle de `useradd` y
  est la bonne ;
- `configure_servers` valide des noms **découverts** dans le `/etc/passwd` d'une machine réelle, **où les
  majuscules existent**.

**Trois implémentations, mais DEUX notions.** Les fondre aurait été E-195 à nouveau — *plusieurs
implémentations d'une même notion* — appliqué à des notions qui n'en font pas une. **Ma règle était la
bonne, son objet ne l'était pas** : avant d'unifier deux copies, vérifier qu'elles valident la même
chose, et pas seulement qu'elles se ressemblent.

**Le correctif retenu est étroit et TOTAL pour la classe** : la classe de caractères reste, et est refusé
ce qui n'est fait **que de points** — `nom.strip('.') == ''`. Tester `.` et `..` à la main aurait laissé
passer `...` : mesuré, les quatre formes sont refusées, et `a b`, `a;id`, `a/b`, le vide et 33 caractères
restent refusés par la classe. **0 refus sur les 41 noms réels.** `pytest` : **509 passed**.

## E-198 — `Timikana` ne peut pas recevoir de politique sudo, à cause d'une majuscule

Relevé le 2026-08-27, **comportement pré-existant**, et c'est la **preuve vivante** que les deux domaines
d'E-197 se croisent déjà.

`policies.py` résout le nom depuis `server_user_inventory` — donc un nom **découvert**, où les majuscules
existent — puis le passe à l'expression **stricte** de `sudo_manager`, celle des noms **gérés**. Un compte
réel du parc est donc refusé par une règle écrite pour un autre domaine.

**Ce n'est pas un trou de sécurité : c'est une capacité inatteignable pour une classe de comptes**, et
elle est silencieuse. Elle confirme qu'il ne suffit pas de dire « deux notions » : **il faut dire laquelle
s'applique où**, sinon le croisement se produit sans que personne ne l'ait décidé — ce qui est déjà le
cas ici.

---

## E-199 — Un nom d'inventaire invalide est INSÉRÉ et MARQUÉ, et les trois conditions sont tenues

Second bout d'E-197 — *valider aux deux bouts*. `scan_server_users` insérait sans valider ; il marque
désormais. **Refermé le 2026-08-27**, décision de conception au §8 (« rendre visible un objet invalide
mais présent »).

| condition | ce qui est écrit, et ce qui a été mesuré pour l'établir |
|---|---|
| **drapeau renseigné, jamais omis** | chaque ligne porte `nom_valide` **et** `motif_invalide` — ce dernier vaut `None` quand le nom est bon, **il n'est pas absent**. `invalides_count` est dans la réponse **même à zéro**. C'est la forme d'`audit_inventaire` (E-194), réemployée le même jour |
| **le motif est un CODE, pas une phrase** | `vide` · `trop_long` · `composant_de_chemin` · `caracteres_interdits`. Propriété mesurée : **aucun motif ne contient d'espace**, et deux causes distinctes rendent deux codes distincts. Un nom valide rend `None` **et pas `''`** — une chaîne vide se confondrait avec « motif inconnu » |
| **hors des comptages qui appellent une décision** | `pending_count` exclut les lignes illisibles, et `invalides_count` est rendu **séparément** plutôt qu'un seul nombre corrigé : « 3 à examiner » et « 3 dont 1 illisible » n'appellent pas le même geste |

### ⚠ Et la condition 3 a été REFUSÉE à un second endroit — avec raison

Le préflight compte **aussi** les `pending_review`, en SQL (`ssh.py:479-487`), et ce compte **BLOQUE** le
déploiement en ajoutant à `result['errors']`. **Il n'a pas été filtré, délibérément.**

> **En exclure les lignes invalides DÉBLOQUERAIT un déploiement — donc desserrerait un garde.** La
> condition 3 vise les nombres qui **promettent un travail** ; celui-là en **interdit** un. Appliquer la
> règle mécaniquement aux deux aurait transformé une condition d'**information** en **relâchement de
> sûreté**, sur la chaîne de K4.

Vérifié : la ligne filtrée est bien celle du **listing** (`:1592`, `status == 'pending_review' and
nom_valide`) et la ligne **:481** est intacte. **Conséquence assumée** : une ligne illisible en
`pending_review` **bloque** le déploiement jusqu'à ce que quelqu'un la traite — **et l'écran dira
désormais pourquoi**, ce qui était précisément le manque.

### Une seule source pour la validité, et l'équivalence PROUVÉE

`_valid_username` **ne porte plus sa propre règle** : elle dérive de `_motif_nom_invalide`. « Valide ? »
et « pourquoi pas ? » ont donc la même source **par construction** — sans quoi une **quatrième**
implémentation de la validité de nom serait née le jour même où E-197 expliquait pourquoi il n'en fallait
pas. La route **importe** cette source au lieu de la recopier ; aucun cycle d'import.

**L'ordre des tests porte le sens** : un nom vide passerait `strip('.') == ''` et serait annoncé
« composant de chemin », ce qui serait **faux**. Le motif le plus **précis** gagne, et c'est écrit dans la
docstring.

**Équivalence du refactor prouvée sur 24 valeurs — 0 écart.** *Un refactor qui changerait le verdict
serait pire que le défaut qu'il corrige*, et cela ne se savait pas sans le mesurer. `pytest` :
**509 passed, 1 xfailed** ; sonde des trois conditions : 12 assertions, 12 PASS.

---

## E-200 — Le drapeau d'E-199 n'existe que sur le chemin d'ÉCRITURE : un compte illisible est invisible tant que personne ne rescanne

Relevé le 2026-08-27 **en portant la moitié écran d'E-199**, et vérifié : `server_user_inventory` porte
**15 colonnes** — `username`, `uid`, `home_dir`, `shell`, `status`, `managed_by`, `notes`, `keys_count`,
`has_platform_key`, `first_seen_at`, `last_seen_at`, `reviewed_at`, `reviewed_by`, `machine_id`, `id` —
et **aucune n'est `nom_valide`**. Le drapeau est **calculé** par la route de scan (`ssh.py:1577`,
`row['nom_valide'] = motif is None`).

Or la page rend son inventaire **depuis la base, au chargement**. Elle ne voit donc le drapeau **qu'au
retour d'un scan**.

> **Un compte nommé `..` reste invisible sur cette page tant que personne n'a relancé un scan — c'est-à-dire
> précisément dans l'état où on en aurait le plus besoin.**

**Et le portage a REFUSÉ de recopier la règle en PHP**, alors que c'était plus court et que la règle est
simple (vide · > 32 · `strip('.') == ''` · classe de caractères). La raison est celle du chantier : *la
question « quels gestes sont offerts » est tranchée par le backend, et une règle recopiée finit par
diverger de celle qui décide.* Ce dépôt en compte trois occurrences, dont deux corrigées le même jour
(E-195, E-197). **Un écran qui offrirait un geste que le backend refuse — ou l'inverse — serait pire que
l'écran actuel.**

### Deux issues, et la seconde est préférée

| issue | coût | forme |
|---|---|---|
| **persister** le verdict | une colonne, donc une **migration** | l'état est figé au dernier scan, et se périme comme lui |
| **exposer sur un chemin de LECTURE** | une route qui rend l'inventaire avec ses drapeaux, **sans joindre la machine** | **remonter la règle de là où elle s'applique**, au lieu de la recalculer |

La seconde est préférée, et **elle a exactement la forme de `GET /fail2ban/portee`** — la route obtenue
pour la même raison, et dont le bien-fondé s'est vérifié tout seul le même jour quand la portée est passée
de 2 à 3 machines sans qu'aucune inférence côté navigateur n'ait à suivre.

### Un détail de conception à ne pas deviner

Le nombre fait autorité par `invalides_count`, les noms par la liste. **Si les deux se contredisent, c'est
le TOTAL DU SERVEUR qui gagne** : il compte tout, la liste ne porte que ce qui a voyagé. Sans cette règle,
une liste tronquée aurait fait afficher un nombre **plus petit que la réalité** — la direction dangereuse.

---

## E-201 — La porte à QUATRE YEUX est activée, nomme les deux gestes les plus larges, et ne leur est jamais demandée

**Forme neuve, et pire que les précédentes : ce n'est ni un décorateur inerte ni un commentaire trompeur,
c'est la CONFIGURATION D'EXPLOITATION qui affirme une protection que le code ne consulte pas.**

Mesuré le 2026-08-27, et vérifié indépendamment :

```
srv-docker.env:68   APPROVAL_ENABLED=true
srv-docker.env:69   APPROVAL_ACTIONS=reboot_server,delete_remote_user,
                                     regenerate_platform_key,revoke_service_account
```

**Quatre actions configurées. Deux appels de `gate()` dans tout le backend :**

| appel réel | action |
|---|---|
| `monitoring.py:270` | `reboot_server` |
| `ssh.py:2166` | `delete_remote_user` |

> **`regenerate_platform_key` et `revoke_service_account` ne demandent JAMAIS l'approbation** — et ce
> sont **les deux plus larges** : la rotation de la clé de toute la flotte, et le `userdel -r -f` du
> compte de service.

**Pourquoi c'est la forme la plus coûteuse de la famille** : un exploitant qui relit son
`srv-docker.env` y lit `regenerate_platform_key` et en conclut, **raisonnablement**, que le geste est
gardé. Aucune lecture de code ne le détrompe, parce que l'absence d'appel ne se voit pas — *il n'y a rien
à lire là où la garde manque.*

**Deux aggravations mesurées** : là où la porte **est** appelée, elle est **fail-open** (`try/except` +
`logger.debug("… skipped")` — et `debug` n'est pas journalisé en exploitation) ; et `approvals.gate` est
**fail-open sur erreur de base** (`approvals.py:116`). **Ce qui borne** : `regenerate_platform_key` exige
le rôle 3.

**Trois issues, et « ne rien faire » est la seule qui laisse croire à un garde inexistant** : brancher
`gate()` sur les deux routes ; ou **retirer les deux noms de la configuration** ; ou l'assumer par écrit.

## E-202 — ⚠ DEUX CHEMINS VERROUILLENT ROOTWARDEN HORS DE LA PRODUCTION, EN UN APPEL, SANS RETOUR

**Le plus grave du chantier.** Aucun des deux n'est un défaut d'**accès** : les deux sont des gestes
**légitimes** dont la cible peut être l'accès de RootWarden lui-même. Trouvés par pré-relecture avant
portage, vérifiés en base.

### L'état mesuré du parc — c'est lui qui rend les deux mortels

| id | nom | `user` | mot de passe | mdp root | clé plateforme | compte de service |
|---|---|---|---|---|---|---|
| **1** | **`srv-zabbix`** | `user` | **non** | **non** | **oui** | **oui** |
| 2 | `Test-Server-Debian` | `testuser` | oui | oui | non | non |
| 3 | `OpenCVE-Test-OnPrem` | `utilisateur` | oui | oui | non | non |

**`srv-zabbix` — la production — n'a plus AUCUN mot de passe connu de RootWarden.** Sa seule voie est la
clé. Les machines 2 et 3 en ont un ; elle, non. **Ce n'est pas une hypothèse sur un parc futur, c'est
l'état d'aujourd'hui.**

### Chemin 1 — `regenerate_platform_key` (rôle 3)

`ssh_key_manager.py:117-126` fait `PRIVATE_KEY_PATH.unlink()` — **une suppression, pas un renommage** —
puis régénère. Et **les trois tentatives d'authentification de `connect_ssh` emploient la même clé
privée**. Après le geste : ancienne clé publique sur chaque machine, nouvelle clé privée qui ne
correspond à rien, ancienne **détruite**. Il ne reste que le mot de passe — que `srv-zabbix` n'a pas.

**Et l'`UPDATE machines SET platform_key_deployed = FALSE` est sans `WHERE`.** Il est *honnête*, mais ces
colonnes étaient **le seul enregistrement de quelles machines avaient la clé** :

> **Après le geste, on ne peut plus lister ce qu'on vient de rendre injoignable.**

La seule trace survivante est `server_user_ssh_keys WHERE is_platform_key = 1` — **et c'est précisément
la table qu'E-192/E-197 ont montré purgeable à tort.** *La seule trace dépend d'un défaut.*

### Chemin 2 — `delete_remote_user` visant `rootwarden` (RÔLE 2)

Trois mesures qui se composent :

```
ssh.py:2142   protected = {'root','nobody','daemon','bin','sys','www-data'}   <- pas `rootwarden`
ssh.py:2159   if username == m['user']                                        <- vaut 'user' pour la machine 1
ssh_utils.py:241   username='rootwarden'                                      <- EN DUR, compte de service
```

**Le compte de connexion réel de `srv-zabbix` est `rootwarden`. La liste protégée ne le connaît pas, et la
comparaison porte sur `machines.user` = `'user'`.** Et il **existe** en inventaire (machines 1 et 3,
uid 999 et 988).

> `POST /delete_remote_user {machine_id: 1, username: "rootwarden"}` supprime par `userdel` le compte par
> lequel RootWarden s'authentifie sur la production. **Même verrouillage, au RÔLE 2 — donc plus bas que
> le chemin 1.**

La porte à quatre yeux **est** appelée ici (`:2166`), donc elle **ralentit** — elle exige un second
administrateur, **pas qu'il comprenne ce que `rootwarden` est**. Même forme qu'E-150 : **la protection
énumère des NOMS au lieu de résoudre une FONCTION.**

**Une réserve à lever avant de conclure** : `rootwarden` porte le statut `excluded` en inventaire. Reste
à mesurer si l'écran l'offre malgré ce statut — deux sessions l'affirment indépendamment, mais **la
mesure n'a pas été faite au clic.**

### Ce que la page INVITE à faire, et qui fabrique cet état

`remove_ssh_password` n'efface pas le mot de passe **sur la machine** : il efface la copie de RootWarden.
Et **toute la page de la clé pousse à cet effacement** — barre de progression, `platform.migration_done`
atteint quand tous les mots de passe sont partis, bouton de masse, pastille verte réservée aux machines
sans mot de passe.

> **La fin de la migration telle que la page la dessine EST l'état où la régénération est sans retour.**

**Et le retour offert est à moitié** : `reenter_ssh_password` écrit `password` — **jamais
`root_password`**. Mesuré : dans tout le backend, **une seule** écriture de `root_password`, celle qui
l'efface. Le seul remplisseur est une **autre page**. Le bouton « Ressaisir » *paraît* annuler
« Supprimer » ; **il en annule la moitié.**

### La contrainte de test la plus inhabituelle du chantier

> **La réussite de ce geste ne doit JAMAIS être mesurée. Il n'existe aucune cible sûre** — il n'est pas
> paramétré par une machine, il porte sur la flotte. Le mesurer une fois verrouille la production.

Le portage doit donc être conçu pour que **la seule chose mesurable soit le refus**, et **cela doit être
écrit dans le fichier de suite** — sinon quelqu'un comblera un jour le trou apparent.

### Et un kill-switch qui n'a aucune interface

`/revoke_service_account` — documenté « kill-switch », rôle 3, `userdel -r -f` — **n'a aucun appelant**.
C'est **le seul moyen de défaire un `NOPASSWD: ALL`**, et il n'est offert nulle part. Triplement fermé :
pas d'interface, pas de porte à quatre yeux (E-201), et **`deploy_platform_key` l'accorde par un bouton
qui n'en parle pas** — il enchaîne `useradd`, dépôt de clé et
`echo 'rootwarden ALL=(ALL:ALL) NOPASSWD: ALL'` « dans la foulée ».

> **Accorder root tient en un clic ; le reprendre n'a pas de clic.**

---

## E-203 — Le portage n'a AUCUNE révocation de session côté serveur

Relevé le 2026-08-27 en réparant `last_activity` (E-188). **Ce n'est pas un défaut de colonne, c'est un
écart de parité fonctionnelle.**

Le portage **ne tient pas `active_sessions`** : aucune écriture ni lecture dans son authentification,
seulement des suppressions. Les **3 930** lignes de la table viennent donc **toutes** du legacy.

> **Conséquence : un bouton « Révoquer » de `profile.php` n'a aucun effet sur une session Laravel.** Le
> legacy porte une liste de révocation côté serveur — `verify.php` la consulte à chaque page protégée — et
> le portage n'en a pas.

**Aujourd'hui c'est masqué** parce que les deux portails coexistent et que l'authentification passe encore
largement par le legacy. **Le jour où le legacy s'éteint — l'objectif 2.0 — la capacité disparaît
silencieusement** : l'écran continuera d'offrir la révocation, et elle ne révoquera rien.

C'est la même forme qu'E-188 prise un cran plus haut : là, une colonne n'était jamais écrite ; ici, c'est
**le mécanisme entier** qui n'a pas de pendant. Et comme pour E-188, **les deux défauts se masquaient
mutuellement** — la purge ne tournant pas, personne n'a jamais constaté qu'une session Laravel survit à sa
révocation.

**À trancher avec l'objectif 2.0**, et pas après : soit le portage tient la table (le cadre a son propre
mécanisme de session, il faut donc décider lequel fait foi), soit l'écran cesse d'offrir un geste sans
effet.

---

*Note sur E-90 — **REFERMÉ, et c'est le LOT complet qui l'a établi** (2026-08-27).*

`go-page-supervision-deploiement` rend **FAIL**, et **c'est une bonne nouvelle** : son assertion de
caractérisation **exige que le défaut soit PRÉSENT** —
`forgee.conclut === true && apresForge.length === 1 && agentInstalle() === 'NON'`.

La mesure donne `conclut = false`, un inventaire **vide**, et un flux qui remonte enfin ses vrais codes
(`code 127`, `code 100`, `code 2`).

> **Ce n'est pas la page qui a régressé, c'est la caractérisation qui est périmée.** E-90 — « le
> déploiement backend n'inspecte aucun code de retour et inscrit un agent inexistant » — est **fermé**
> depuis `v1.38.11`, et sa portée réelle était de **quatre** routes et non deux.

**C'est le troisième `go-bashrc-b4` du chantier** : un **FAIL permanent qui ne dit rien de mauvais**, et
qui rougirait à **chaque** LOT tant qu'il n'est pas tranché. Les deux précédents ont coûté, chacun, une
demi-journée de diagnostic à quelqu'un qui lisait un rouge inexplicable.

**Décision : l'assertion est RETOURNÉE** — « le déploiement ne conclut plus au succès quand la machine
refuse ». Retourner une assertion de caractérisation équivaut à **déclarer un écart fermé**, ce qui
appartient à ce fichier : c'est donc écrit ici, et la suite suit. La référence sera remesurée après le
retournement.

---

## E-205 — `Fail2ban::machines()` rend TOUTES les machines, quel que soit le rôle — un module déjà livré, et personne ne l'atteint aujourd'hui

**Trouvé par la session 5 en portant `iptables/` I1, dans un module qui n'est pas le sien.** C'est la
manière dont cet écart a été trouvé qui décide de sa gravité, et non son effet actuel.

**Le legacy filtre, le portage ne filtre pas :**

    legacy/fail2ban/index.php:14-20   filtre par `user_machine_access` des que le role < 2
    legacy/iptables/index.php:52-58   fait exactement la meme chose
    App\Services\Fail2ban::machines()  rend TOUTES les machines non archivees, quel que soit le role

Les deux pages legacy portent la **même** règle, à deux endroits. Le portage de `fail2ban/` a repris la
page et pas la règle.

### Pourquoi il n'a aucun effet mesurable aujourd'hui, et pourquoi ça ne le referme pas

**Aucun compte de rôle 1 ne détient `can_manage_fail2ban`** : personne n'atteint donc la page avec un
rôle assez bas pour que le filtre compte. L'écart est **réel et sans porteur**.

Il s'ouvrirait à la **première attribution de cette permission** — un geste d'administration ordinaire,
fait depuis `/comptes`, par quelqu'un qui n'a aucune raison de savoir qu'il arme un écart. *Une propriété
qui tient parce que personne n'exerce le chemin n'est pas une propriété : c'est un accident de
configuration.* C'est le même mécanisme que `@require_machine_access` inerte sur 57 routes — la garde est
*présente* et ne garde *rien* — et que les gabarits `iptables` codant `--dport 22` en dur, invisibles
uniquement parce que les trois machines écoutent sur 22.

### Ce qui a été fait, et ce qui ne l'a pas été

**La session 5 ne l'a pas corrigé, et elle a eu raison** : `App\Services\Fail2ban` appartient à la
session 3. Elle a en revanche **écrit la règle dans son propre service** `App\Services\Iptables`, pour
que le portage de `iptables/` ne recopie pas le mauvais des deux précédents disponibles.

*Fermer un défaut sans chercher ses autres implémentations, c'est le fermer à moitié* — et ici la
symétrie était inverse : le défaut était déjà fermé dans le legacy aux **deux** endroits, et c'est le
portage qui a perdu la règle sur l'un des deux. **Le troisième porteur possible est `groups/`**, dont le
portage reste à faire : à vérifier au moment de G2.

### La correction

`App\Services\Fail2ban::machines()` filtre par `user_machine_access` dès que le rôle est inférieur à 2,
comme `App\Services\Iptables` le fait déjà. **Le correctif appartient à la session 3**, et il n'est pas
urgent au sens de l'exposition — il l'est au sens où il sera oublié dès que l'attention passera à un
autre module.

---

## E-206 — `/search/` est archivée depuis le 2026-08-18 et son entrée de redirection n'a jamais été posée

**Trouvé par la propriété `LiensLegacy` à sa PREMIÈRE mesure** — celle qui venait d'être écrite pour
prévenir exactement ce défaut. Elle a trouvé le cas qu'elle devait empêcher, déjà présent.

    parties archivees (`legacy/_deprecated/*`) ..... 13
    entrees de `LiensLegacy::REMPLACEMENTS` ....... 16
    parties archivees SANS entree ................. 2

- `/services/` — archivée le 2026-08-27, table complétée dans le même lot. **Attendu** ;
- **`/search/` — archivée le 2026-08-18, absente depuis neuf jours.** Vérifié :
  `legacy/_deprecated/search/` porte bien `index.php` et `js/main.js`.

### L'effet est nul, et c'est le point

Comme pour `/docker/`, l'entrée serait **préventive** : le relevé exhaustif des liens que le backend pose
en dur ne contient ni `/search/` ni `/services/` — seulement `/security/` ×4, `/ssh-audit/` ×2,
`/update/index.php`, `/tickets/index.php`, `/profile.php`, `/approvals/`, `/adm/audit_log.php`,
`/adm/admin_page.php` et `/`. **Aucun utilisateur ne rencontre ce lien mort aujourd'hui.**

**Ce qui en fait un écart n'est donc pas son effet mais son mode de découverte.** `/docker/` — le même
oubli, au même endroit, à la `v1.37.54` — avait été rattrapé par une **relecture**. `/search/` ne l'a pas
été, et personne ne l'a vu pendant neuf jours et deux archivages. *Un défaut rattrapé par une relecture
est un défaut dont la prochaine occurrence dépend de qui relit.*

Il restait **cinq** parties à archiver quand la propriété a été écrite : elle arrive juste à temps pour
les cinq suivantes, plutôt qu'une de trop tard.

### La correction

Deux entrées à poser dans `LiensLegacy::REMPLACEMENTS`, toutes deux préventives, **par la session 3** qui
possède le fichier : `'/services/' => 'services'` et `'/search/' => 'recherche'`. Puis la propriété
mesure `0` partie archivée sans entrée — et **c'est cette mesure-là qui vaut**, pas la relecture qui a
servi à trouver le cas.

---

## E-207 — La pastille « keypair » est verte sur une machine qui a encore ses DEUX mots de passe : un drapeau et les colonnes qu'il résume sont deux sources

**Trouvé par la session 3 en portant `platform_key` P1, et l'inventaire du module ne l'avait pas vu.**

### Les deux lecteurs du drapeau, et l'écrivain qui les périme

    legacy/adm/platform_keys.php:24    $nbPasswordRemoved = count(array_filter($servers,
                                         fn($s) => !$s['ssh_password_required']));
    legacy/adm/platform_keys.php:160   pastille verte « keypair » : $deployed && !$pwRequired

    legacy/adm/includes/manage_servers.php:136,182
                                       remplissent `root_password` SANS jamais toucher
                                       `ssh_password_required`

**Mesuré : `srv-zabbix` porte `ssh_password_required = 0` avec `password` ET `root_password` présents.**
La page Serveurs est le seul chemin qui réécrit le mot de passe root, et elle ne touche pas le drapeau.
L'ancien portail compte donc cette machine comme migrée et **lui donne la pastille verte**.

### L'indicateur est faux dans le sens rassurant

C'est ce qui le classe. Un compteur qui sous-estime une migration fait poser une question ; un compteur
qui la surestime fait **cesser** de la poser. Ici l'écran annonce « mot de passe supprimé » sur une
machine dont les deux mots de passe sont en base — et c'est le tableau qu'un exploitant regarde pour
décider si la bascule vers l'authentification par clé est terminée.

### La bonne nouvelle, qui est calculée et non supposée

**Aucune machine n'est aujourd'hui dans la position sans retour** — celle où le mot de passe a été retiré
et où la clé est le seul accès. C'est l'inverse de ce que l'inventaire relevait le matin même, et ça
**abaisse la gravité de P4**. Le drapeau menait la lecture dans les deux sens : il faisait croire à une
migration acquise *et* à un risque qui n'existait pas.

### La correction

`App\Services\ClePlateforme::compteurs()` compte les **colonnes** et non le drapeau, et **dit** quand le
drapeau les contredit — au lieu de choisir silencieusement l'une des deux sources. Porté par la session 3.

*Un drapeau et les colonnes qu'il prétend résumer sont deux sources, et il suffit d'un chemin d'écriture
qui en oublie une pour qu'elles divergent sans bruit.* Même faute de forme que la seconde copie du numéro
de version, refusée par la même session le même après-midi — **elle a refusé une duplication dans le
compose et en a trouvé une en base dans la même heure.**

---

## E-208 — TROIS pages legacy sur CINQ ne bornent pas le parc au périmètre du compte, et celle qui expose le plus n'est pas celle qu'on surveillait

**Relevé par la session 3 en corrigeant E-205, sur les cinq pages qui listent des machines** — et non sur
les trois annoncées par le Lead, *parce que les gardes ne sont pas au même niveau et que l'intuition ne
les devine pas* :

    legacy/fail2ban/index.php:14-20    filtre par `user_machine_access` si role < 2
    legacy/iptables/index.php:52-58    filtre
    legacy/bashrc/index.php:25-35      ne filtre PAS
    legacy/groups/index.php:22         ne filtre PAS
    legacy/adm/platform_keys.php:18    ne filtre PAS

**Deux conséquences immédiates pour le chantier :**

1. **`groups/` n'est PAS le troisième porteur d'E-205.** Le Lead l'avait annoncé comme un porteur possible
   à vérifier au moment de G2 ; mesuré, sa page ne filtre pas, donc **la reprendre fidèlement sera juste**.
   Bon à savoir avant d'y arriver plutôt qu'après ;
2. **`adm/platform_keys.php` expose le plus, et personne ne la regardait** : *tout le parc, avec l'état de
   la clé et du compte de service par machine*, à un rôle 1 porteur de la permission. Le portage P1 ne
   filtre pas non plus, **par fidélité** — et c'est le bon choix par défaut.

### Ce que ça dit, et pourquoi ce n'est pas une correction

**Le legacy est incohérent avec lui-même** : deux pages sur cinq bornent le parc, trois non. Il n'existe
donc **aucune règle du produit** à reprendre — seulement cinq décisions historiques dont deux ont divergé.
*Un portage fidèle ne peut pas trancher une incohérence de l'original : il la reproduit et la nomme.*

**Resserrer les trois pages serait un changement de droits**, pas un correctif de parité — un rôle 1 qui
voit aujourd'hui tout le parc cesserait de le voir. **C'est un arbitrage de l'exploitant** (§7), pas une
décision de portage, et il porte sur le produit et non sur la migration.

**Et une septième branche non exerçable est livrée avec le correctif d'E-205** : le filtre ne s'exerce
qu'avec un rôle 1 portant `can_manage_fail2ban`, et il n'en existe aucun. La correction est juste et
**aucun test ne peut la démontrer** en l'état — c'est écrit ici pour que personne ne la « simplifie » plus
tard en constatant qu'aucune suite ne la couvre.

---

## E-209 — ⚠ EN PRODUCTION : le guide de la clé de plateforme enseigne qu'un geste durcit la machine, alors qu'il retire le seul filet de RootWarden — et il dit « plus sécurisé »

**Trouvé par la session 3 en portant `platform_key`, en refusant de porter fidèlement. C'est le défaut le
plus grave de la journée, et il est servi en production sur `main` (v1.37.15).**

### Ce que le guide affirme, mot pour mot, dans les deux langues

    legacy/lang/fr/tips.php:125
    'tip.platform_step4' => '<strong>Supprimer le password</strong> desactive l'authentification
                             par mot de passe sur le serveur (plus securise).'
    legacy/lang/en/tips.php:113
    'tip.platform_step4' => '<strong>Remove password</strong> disables password authentication
                             on the server (more secure).'

Affiché par `legacy/adm/platform_keys.php:50`, dans un panneau « Comment ça marche ? » en quatre étapes.

### Ce que le geste fait

    backend/routes/ssh.py — remove_ssh_password
    UPDATE machines SET password = '', root_password = '', ssh_password_required = FALSE WHERE id = %s

**C'est tout.** Aucune `SSHClient`, aucun `connect`, aucun `exec_command`, aucune écriture dans
`sshd_config`, aucun `PasswordAuthentication`. **Le geste ne joint pas la machine.**

### Pourquoi c'est plus qu'une inexactitude

Le compte Unix **garde son mot de passe**, et quiconque le connaît entre encore. Ce que le geste efface,
c'est **la copie que RootWarden détenait** — c'est-à-dire son propre recours.

> **« Plus sécurisé » est le mot qui coûte.** Le geste ne durcit pas la machine : il retire le filet. Un
> exploitant qui suit ce guide **croit se protéger et se prive d'un recours** — sur la page même où toute
> la mise en page le pousse vers cet état, et où la rotation de clé devient sans retour.

**C'est la troisième forme du motif que ce chantier suit**, et la plus coûteuse :

| forme | exemple | ce qu'elle trompe |
|---|---|---|
| un en-tête qui mente sur un accès | « superadmin uniquement » avec `ROLE_USER` (E-36, 4 occurrences) | qui relit le code |
| un libellé qui promette un contrôle | le bouton « Révoquer » sans révocation (E-203) | qui clique |
| **un guide qui enseigne une procédure en se trompant sur son EFFET** | **celui-ci** | **qui ne sait pas** |

*Un guide est ce qu'on lit quand on ne sait pas.* Les deux premières formes trompent quelqu'un qui a déjà
une hypothèse ; celle-ci **fabrique** l'hypothèse.

### Et l'étape 2 est incomplète dans le sens qui compte aussi

    'tip.platform_step2' => 'Deployer keypair installe la cle publique sur les serveurs selectionnes.'

Vrai, et **incomplet** : le même geste crée le compte `rootwarden` avec **`NOPASSWD: ALL`**
(`ssh.py:704-775`). Un guide qui décrit « installe une clé publique » et taît la création d'un compte à
sudo sans mot de passe ne décrit pas le geste que l'exploitant autorise.

### La correction, et la forme qu'elle prend

Le portage écrit la séquence **corrigée**, en liste numérotée — *« déployer la clé » avant « effacer le mot
de passe » n'est pas une préférence de présentation mais la différence entre une migration et un
verrouillage* — et **la correction est DITE sous le guide, pas faite en silence** : un exploitant qui a lu
l'ancien texte doit savoir lequel des deux croire.

**Le legacy n'est pas corrigé par ce lot** — il est servi en production et toute écriture dans
`legacy/lang/` est hors du régime du chantier. **Cela appartient à l'exploitant** (§7) : c'est le seul
écart de la journée dont la version fausse est **lue par des utilisateurs en ce moment**.

---

## E-210 — Le panneau « Comment ça marche ? » n'a JAMAIS été porté : 26 pages, 148 clés traduites, aucun rendu — et un homonyme a fait croire le contraire

**Mesuré par la session 2, et le fait n'est pas « le portage a fait moins bien sur deux modules » : c'est
qu'une capacité du produit n'a jamais été portée du tout, et qu'elle disparaît à chaque `git mv`.**

### Le compte

    legacy/lang/{fr,en}/tips.php ....... 148 cles, FR = EN, jeux IDENTIQUES (parite parfaite)
      dont motif `tip.<module>_(title|stepN)` .... 125 cles, 27 groupes
      hors motif .................................. 23 cles
    pages posant `includes/howto_tip.php` ........ 26   (15 vivantes, 11 deja archivees)

    cles des parties DEJA ARCHIVEES ...... 52  (x2 langues = **104 chaines orphelines MAINTENANT**)
    cles des parties ENCORE VIVANTES ..... 73  (x2 langues = 146, orphelines aux 5 archivages restants)

**104 chaînes traduites sont orphelines aujourd'hui, et l'ont été archivage après archivage — douze fois
— sans que personne ne le remarque.**

### Ce n'est pas « porté sous un autre nom », et la preuve tient sur deux fondements indépendants

1. **aucune clé d'étape dans aucun catalogue du portage** — parcours récursif de `laravel/lang/*/`, toute
   clé nommée `etape`/`step` : **zéro** ;
2. **et surtout : il n'y a AUCUN RENDU.** `legacy/includes/howto_tip.php` est un composant `<details>`
   pliable avec mémorisation en `localStorage`. Le portage n'a pas d'équivalent — `rw-aide` est une classe
   de **texte d'aide en ligne**, `rw-etapes` un **indicateur de progression d'authentification**. **Sans
   renderer, aucune clé ne pourrait s'afficher même si elle existait.**

Le second fondement est le plus solide : *il ne dépend d'aucun nom de clé.*

### ⚠ Pourquoi personne ne l'a vu : un homonyme, et c'est la vraie cause

    legacy   tip.graylog_step1     ->  panneau <details> « Comment ca marche ? »
    portage  docker.tip_scan_one   ->  attribut title="" d'un bouton

**Le portage emploie `tip_*` massivement — pour des INFOBULLES.** Un `grep tip` dans `laravel/lang/` rend
des dizaines de correspondances. **Quiconque a vérifié « les tips sont-ils portés ? » par un motif a
conclu que oui.** Même mot, deux objets sans rapport.

*Un motif qui suppose une forme ne mesure que cette forme* — mais appliqué ici à un **contrôle de
complétude de portage** et non à une garde, et c'est ce qui le rend coûteux : **le contrôle a l'air d'avoir
été fait.** La parade est la même qu'ailleurs : **mesurer le RENDU, pas le nom.** La question juste n'est
pas « les clés existent-elles » mais **« une page portée affiche-t-elle un panneau pas-à-pas ? »** — non,
sur les 25 entrées portées.

### Et une nuance de la session 3 qui déplace le diagnostic sans l'annuler

Sur `graylog`, le portage a bien **cinq** clés de guide — mais elles ne répondent pas à la même question :

- **le legacy explique COMMENT FAIRE** — une séquence : configurer l'URL et le jeton, éditer les
  collecteurs, sélectionner et installer, lire l'onglet Sidecars ;
- **le portage explique CE QUE LE BOUTON FAIT VRAIMENT** — « Déployer ouvre une connexion SSH et installe
  rsyslog », « Retirer supprime les fichiers posés et redémarre ».

**Les deux sont légitimes et complémentaires.** Le portage a donc opéré une **substitution** non nommée —
un guide de *procédure* remplacé par un guide de *conséquence* — et il l'a fait parce que les libellés
mentaient (E-209 en est la preuve). **Ce qui est perdu n'est pas « du conseil », c'est l'ORDRE.** Et là où
le portage n'a rien mis, il est perdu sec : `platform_key` n'avait aucun guide une heure après son portage,
dans le module même où la séquence décide entre une migration et un verrouillage.

### Ce que ça décide pour FEAT-001, et la fenêtre qui se ferme

**FEAT-001 ne remplace pas un acquis : il comble un trou ouvert depuis le premier archivage.** Le legacy
répondait à la question de l'exploitant — *« un nouvel utilisateur ne le sait pas »* — sur **26 pages**, en
deux langues.

- **125 clés × 2 langues sont déjà écrites et traduites.** Reprendre coûte un composant Blade et un
  mappage ; concevoir de zéro coûte la rédaction et la traduction de **250 chaînes** ;
- **mais elles ne se reprennent pas telles quelles** : E-209 montre que deux des quatre étapes de
  `platform_key` disaient faux. *Un acquis traduit n'est pas un acquis vérifié* ;
- **la fenêtre se ferme module par module.** Après un `git mv`, les clés restent dans `tips.php` mais plus
  rien ne dit **à quelle page** elles appartenaient. **Pour les 11 parties déjà archivées, cette
  information n'est récupérable que dans `legacy/_deprecated/*/index.php`** — donc tant que `_deprecated/`
  existe, et pas après la disparition finale du legacy.

### Ce qui n'est pas mesuré, et qui borne l'écart

La session 2 le déclare : elle affirme qu'il n'y a **pas de panneau** et **pas de clé d'étape** ; elle
n'affirme **pas** que l'information est absente des écrans portés — une page a pu reformuler une étape dans
un texte d'aide en ligne. Les 23 clés hors motif ne sont pas ventilées par module, et le **rendu effectif**
des 15 pages vivantes n'est pas vérifié (le composant est un `<details>` : une page peut l'inclure et le
rendre replié).

---

## E-211 — `GET /ssh-audit/policies` sans `machine_id` rend les politiques GLOBALES, sans rôle ni permission — quatrième occurrence de « un garde sans objet ne garde rien »

**Trouvée par la session 4 dans le relevé des 229 routes. La portée annoncée était plus large que la
portée réelle, et la mesure la corrige — mais l'écart subsiste et il appartient à un motif connu.**

### Le code

    backend/routes/ssh_audit.py:478
    @require_api_key
    @require_machine_access          <- sans objet si `machine_id` est absent
    @threaded_route
    def ssh_audit_policies_get():
        machine_id = request.args.get('machine_id')      # OPTIONNEL
        if machine_id:
            ... WHERE machine_id = %s OR machine_id IS NULL
        else:
            ... WHERE machine_id IS NULL                 # les politiques GLOBALES

**Aucun `@require_role`, aucun `@require_permission`.**

### ⚠ Ce que la session 4 a annoncé, et ce que la mesure dit

Le compte rendu disait : *« un appelant de rôle 1 qui omet le paramètre lit les politiques d'audit SSH
**au-delà de son périmètre** »*. **Faux sur ce point** : quand `machine_id` est absent, la requête ne rend
**que** `WHERE machine_id IS NULL` — les politiques **globales du portail**, pas celles des machines
d'autrui. Il n'y a pas de lecture transverse du parc.

**L'écart réel, plus étroit et toujours réel** : les politiques **globales** — `directive`, `policy`,
`reason`, `updated_by`, `updated_at` — sont lisibles par **tout porteur de la clé d'API**, quel que soit son
rôle, **sans détenir `can_audit_ssh`**. La page legacy, elle, exige `can_audit_ssh` (`ssh-audit/index.php:13`)
et **son seul appelant passe toujours `machine_id`** (`js/main.js:321`) : **le chemin sans paramètre n'est
exercé par aucune interface.**

*Une correction qui rétrécit un écart le rend plus utile, pas moins* — annoncé large, il aurait fait chercher
une fuite de parc qui n'existe pas.

### Pourquoi il compte quand même : le motif, et c'est la QUATRIÈME fois

**`@require_machine_access` ne trouve aucun identifiant dans la requête, donc il ne refuse rien.** C'est
exactement *« un garde sans objet ne garde rien »* — le décorateur est **présent**, et il ne garde **rien**
sur ce chemin. Occurrences connues :

1. le décorateur inerte dès `role_id >= 2` — **59 routes** sur 116 ;
2. le décorateur sans identifiant dans le corps — relevé cette semaine ;
3. `POST /deploy` portant `@require_api_key` **seule** (E-191) ;
4. **celle-ci** — le paramètre est **FACULTATIF**, et le repli rend des données globales au lieu de refuser.

> **⚠ CORRECTION DU MÉCANISME, 2026-08-27 — la première explication de cet écart était FAUSSE, et le Lead
> l'avait inscrite.** Il était écrit que le décorateur « ne trouve aucun identifiant dans les **paramètres
> d'URL** ». Non :
>
>     helpers.py
>     single = (data.get('machine_id') or request.args.get('machine_id')
>               or data.get('server_id') or request.args.get('server_id'))
>
> **Il lit la query-string explicitement.** Avec `?machine_id=5` il trouve l'identifiant et vérifie l'accès.
> **Ce qui le neutralise n'est pas la PROVENANCE du paramètre, c'est son caractère FACULTATIF** : absent, la
> liste reste vide, et une liste vide ne refuse rien.
>
> **L'écart et le correctif sont inchangés — mais l'explication comptait** : *« le décorateur ne lit pas la
> query-string » aurait envoyé corriger le décorateur, qui n'a rien à corriger, au lieu de la route.*
>
> **Deuxième rectification de la même trouvaille en un jour** : la première rétrécissait sa **portée**, celle-ci
> corrige sa **cause**. *Une trouvaille juste peut être expliquée faux — et l'explication est ce qu'on
> réutilise.* Corollaire pour ce document : **une trouvaille vérifiée n'a pas son explication vérifiée**, et
> ce sont deux relectures distinctes.

**Et le quatrième est le pire de la famille, parce que le repli est SILENCIEUX et UTILE** : au lieu de rendre
une erreur, la route rend un jeu de données parfaitement cohérent. *Un repli permissif ressemble à de la
robustesse* — le chemin non gardé est celui qui a l'air de bien se comporter.

### La correction

`machine_id` **obligatoire**, ou bien `@require_permission('can_audit_ssh')` sur la route pour aligner
l'accès sur celui de la page. La seconde est la plus fidèle : la page legacy garde par la permission, pas par
le paramètre. **Route backend, donc session 4** — et *qui écrit le code ne valide pas seul son correctif* :
la session 6 écrit le test.

### Le contexte qui en fait un écart de parité et pas seulement un défaut

**C'est la même famille qu'E-208** : le legacy est incohérent avec lui-même sur le bornage au périmètre du
compte, donc **il n'existe aucune règle du produit à reprendre**. Et la conséquence pour `api_docs` est celle
que la session 4 nomme : **une page de documentation lisserait cette incohérence sans le vouloir**, en
présentant comme une règle ce qui n'est qu'une collection de décisions dont certaines ont divergé.

---

## E-212 — ⚠ EN PRODUCTION : tout ce que le portail dit de Graylog décrit un produit qu'il n'installe pas — et le backend le sait

**Trouvé par la session 2 en mesurant si la SÉQUENCE était dite. La question s'est retournée : il n'y avait
rien de vrai à porter.** E-209 montrait deux étapes sur quatre qui mentaient ; **ici c'est le panneau entier,
son titre, et deux autres textes.**

### Le module fait du transfert `rsyslog`. Les textes annoncent Graylog **Sidecar**.

| ce que le legacy affiche | ce que le module fait |
|---|---|
| « Comment déployer le Graylog **Sidecar** ? » | il installe `rsyslog` |
| « URL du serveur + **token API** … *token chiffré en base* » | **`graylog_config` n'a AUCUNE colonne de jeton** |
| « éditez les **collectors** (filebeat / nxlog / winlogbeat) » | des gabarits **rsyslog** |
| « ajout du repo, install du paquet, **enrôlement auprès du manager** » | `apt-get install -y rsyslog`, **aucun enrôlement** |
| « l'onglet **Sidecars** affiche le statut par machine » | **il n'y a pas d'onglet Sidecars** |

**Mesures, vérifiées indépendamment du compte rendu :**

    colonnes de `graylog_config` : id · server_host · server_port · tls_ca_path
                                   ratelimit_burst · ratelimit_interval · updated_by · updated_at
                                   -> AUCUN jeton, aucune cle d'API

    occurrences de sidecar|filebeat|nxlog|winlogbeat :
      legacy/graylog/index.php ......... 0
      legacy/graylog/js/graylog.js ..... 0
      laravel/.../graylog.blade.php .... 0
      backend/routes/graylog.py ........ 1   <- et c'est un COMMENTAIRE : « Approche rsyslog (pas de sidecar) »

### ⚠ Le backend le SAIT, l'écrit, et personne n'a corrigé l'écran

`backend/routes/graylog.py:8` porte, en clair : **« Approche rsyslog (pas de sidecar) »**. La seule
occurrence du mot dans tout le code d'exécution est **la note qui dit que ce n'est pas ça.**

*Ce n'est donc pas un défaut de connaissance, c'est un défaut de propagation* — quelqu'un a su, l'a écrit à
l'endroit que lisent les développeurs, et les trois textes que lisent les **utilisateurs** sont restés faux.

### Trois sites, et le troisième est le plus grave

    1. legacy/lang/{fr,en}/tips.php        le panneau « Comment ca marche ? », titre + 4 etapes
    2. legacy/lang/fr/dashboard.php:49     « Deploie le sidecar, centralise et edite les collectors »
    3. legacy/lang/fr/admin.php:89         perms.desc_graylog :
                                           « Deployer le Graylog Sidecar et gerer les collectors »

**Le n°3 est la description de la PERMISSION**, affichée dans la page d'administration des comptes. **Un
administrateur qui accorde `can_manage_graylog` lit une description fausse de ce qu'il accorde.**

C'est un cran au-dessus de la hiérarchie d'E-209, et il faut l'ajouter :

| forme | trompe | conséquence |
|---|---|---|
| un en-tête qui mente sur un accès (E-36) | qui relit le code | une relecture rassurée |
| un libellé qui promette un contrôle (E-203) | qui clique | un geste cru fait |
| un guide qui se trompe sur son effet (E-209) | qui ne sait pas | **fabrique** l'hypothèse |
| **une description de permission fausse** | **qui ACCORDE un droit** | **une décision d'habilitation prise sur une fiction** |

*Les trois premières trompent quelqu'un sur ce qu'il fait ; la quatrième trompe quelqu'un sur ce qu'il
autorise autrui à faire.*

### Ce que ça requalifie, et qui n'est pas un détail

**La « substitution non nommée » d'E-210 n'était pas un choix de style : la source était inutilisable.** Le
portage n'a pas remplacé un guide de *procédure* par un guide de *conséquence* par préférence — **il n'y
avait pas de procédure vraie à porter.** Donc :

> **Sur `graylog`, ce qui est perdu n'est PAS l'ORDRE : il n'a jamais été dit correctement.** La formulation
> « la séquence est-elle dite quelque part ? » vaut pour les autres modules ; **pas pour celui-là**, où la
> bonne question était « ce qui est dit est-il vrai ? ».

### La correction

**Le portage** : rien à reprendre du panneau. Il lui manque une phrase de premier pas, à écrire depuis le
comportement réel — pas depuis le legacy.

**Le legacy est servi en PRODUCTION**, et les trois sites y sont faux dans les **deux** langues. `legacy/lang/`
est hors du régime du chantier : **arbitrage de l'exploitant** (§7), au même titre qu'E-209. Le n°3 est celui
qui devrait partir en premier — il est lu au moment où un droit est accordé.

---

## E-213 — ⚠⚠ UN STATUT NOMMÉ `excluded` N'EXCLUT PAS : deux magasins ont divergé, et la décision de suppression ne lit que l'un des deux

**Trouvé par la session 4 en lisant le corps de `/exclude_user` sur ma demande. C'est le défaut le plus
conséquent du chantier à ce jour : il DÉTRUIT des données, en silence, et le mot que l'interface emploie pour
la protection est exactement celui qui ne protège pas.**

### Les deux magasins

    user_exclusions                 <- ecrit par `/exclude_user` SEULE  (admin.py:129, INSERT IGNORE)
                                    -> LU par la DECISION DE SUPPRESSION (configure_servers.py:793)

    server_user_inventory.status    <- ecrit par `classify`, `classify_bulk`, `scan_server_users`
                                    -> lu UNIQUEMENT pour `status = 'managed'` (configure_servers.py:887),
                                       et seulement pour retirer des cles

**La migration 030 les a copiés une fois. Rien ne les synchronise depuis.**

### La décision de suppression, mot pour mot

    configure_servers.py:818-832
    for username in valid_existing_users:
        if username.lower() in _PROTECTED_USERS or username in allowed_usernames:  continue
        if username in excluded_usernames:                                          continue   # <- user_exclusions
        execute_command_as_root(channel, f"userdel -r {username}", ...)                         # <- TOUT LE RESTE

**`status = 'excluded'` n'est jamais consulté par cette décision.** Et la suppression est **`userdel -r`** :
le compte **et son répertoire personnel**.

> **Classer un compte `excluded` dans `comptes-distants` ne le protège PAS du `userdel -r`.** Il sera
> supprimé, avec son `$HOME`, au déploiement suivant.

### Ce qui en fait le pire de sa famille

Ce n'est pas une capacité manquante. **C'est un bouton remplacé par un sosie** — un statut nommé
littéralement `excluded`, dans la page vers laquelle on proposait de renvoyer l'utilisateur, qui n'a pas cet
effet.

> *Perdre un bouton se voit. Le remplacer par un bouton qui a l'air de faire la même chose ne se voit pas.*

Et `ComptesDistants.php:29` écrit que `classify` n'a « aucun effet distant ». **C'est exact, et ce n'est pas
le point** : l'effet ne vient pas du classement, il vient de **ce que le déploiement lit** — et il lit
l'autre table. *Une affirmation vraie sur son propre périmètre peut être trompeuse sur le périmètre qui
compte.*

C'est aussi la quatrième occurrence du motif « **deux sources pour la même notion** » en une journée : le
drapeau `ssh_password_required` contre les colonnes (E-207), les deux copies refusées du numéro de version,
les deux conventions de `verifie()` (INF-002), et celle-ci — **la seule des quatre qui détruise.**

### Conséquences immédiates sur le chantier

1. **Le lien ne remplace pas la table de `platform_key`, et pour une raison plus forte que la mienne.** Ma
   condition était « rien ne doit être perdu » — insuffisante : ce qu'on aurait obtenu est **un renvoi vers
   une page dont le statut de protection ne protège pas** ;
2. **K4 reste bloqué, et ce blocage est désormais PROTECTEUR.** Un déploiement lancé aujourd'hui exécuterait
   `userdel -r` sur tout compte non autorisé et non présent dans `user_exclusions` — y compris ceux qu'un
   exploitant croit protégés. Le blocage sur l'arbitrage `NOPASSWD: ALL` couvre incidemment celui-ci ;
3. **le portage de C4 devra lire les DEUX magasins** ou aucun geste de classement ne devra prétendre protéger.

### Les trois issues, et aucune n'est un arbitrage de portage

- **unifier les deux magasins** — change ce qui est **détruit sur des machines réelles**, et des lignes
  `excluded` existent déjà depuis la migration 030 ;
- **porter le geste `/exclude_user` tel quel** dans `comptes-distants`, à côté du classement — deux notions
  visibles au lieu d'une trompeuse ;
- **ne rien retirer**, et **dire** dans l'interface que le classement ne protège pas.

**C'est un arbitrage de l'exploitant** (§7) : la première touche à ce qui est supprimé en production.

---

## E-214 — `sshd_allow_user` atteste « AllowUsers patché » même si `sshd` n'a jamais rechargé : `|| true` rend le code de sortie toujours nul

**Mesuré par la session 4, démontrable sans rien exécuter — c'est de la sémantique de shell.**

    systemctl reload … || … || true      -> code de sortie TOUJOURS 0

**La branche de rollback est du code mort**, et la fonction annonce la réussite dans tous les cas.

**Ce qui est faux est l'ATTESTATION, pas l'état** : aucun accès n'est coupé — l'ancienne configuration
tourne encore, `sshd` n'ayant simplement pas rechargé. C'était la crainte portée au plan pour C3 ; elle est
**levée sur ce point précis**, et remplacée par une plus discrète : *le portail affirme un durcissement qui
n'a pas eu lieu, donc personne ne le refera.*

Même famille qu'E-192 et que les quatre routes de `supervision/` corrigées en `v1.38.11` : *un `|| true`
transforme une vérification en décoration.*

**Non mesuré** : le helper ne patche que la **première** ligne `AllowUsers`, et un fichier `.conf` inclus
devrait primer. Signalé par la session 4, **pas compté** comme un défaut — aucune machine pour le vérifier.

---

## E-215 — `remove_user_keys` : E-192 est revenu, sur une RÉVOCATION D'ACCÈS — et son mode sélectif filtre par sous-chaîne

**Deux défauts sur le même geste, et le premier est une récidive nommée.**

**1. La fausse attestation.** Le résultat d'`execute_as_root` est **jeté**, `success: True` rendu sans rien
vérifier. Le commentaire d'E-192 dit déjà pourquoi c'est la pire forme de ce motif : *« une FAUSSE
ATTESTATION — personne ne rouvre un dossier de conformité clos. »* **Ici l'objet est une révocation
d'accès** : le portail atteste qu'une clé a été retirée, et elle peut être restée.

**2. La sélection par sous-chaîne.** Le mode `rootwarden_only` fait `sed '/rootwarden/d'` — **là où sa
voisine du MÊME fichier recalcule les empreintes avec `ssh-keygen -lf`.** Une clé **étrangère** dont le
commentaire contient ce mot **saute en silence**.

*On compare des segments, pas des sous-chaînes* — troisième occurrence de la règle en une journée, après le
`hooks.slack.com/services/` de l'archivage et le `//exemple.com` des liens. **Et ici la sous-chaîne décide
d'une suppression**, pas d'un affichage.

### Ce qui est DÉDOUANÉ, et le dire compte autant

**Sur les trois corps lus — `sshd_allow_user`, `remove_user_keys`, `server_user_remove_key` — la question
d'E-174 rend NON pour les trois** : `shlex.quote` partout, et `_validate_username` dérivée (E-204) en amont.
*Un relevé qui ne dédouane pas se lit comme un réquisitoire, et on cesse de le croire.*

**Non corrigés** : ce sont des gestes distants dont le correctif change ce qui s'écrit sur des machines
réelles. À qualifier par la session 5 avant écriture.

---

## E-216 — Un changement d'identifiant sur une machine de production ne laisse AUCUNE trace

**Trouvé par la session 3 en remesurant `srv-zabbix` pour P4, et c'est la trouvaille collatérale qui compte
plus que la mesure demandée.**

    seul chemin qui ecrit `password` / `root_password` d'une machine :
      legacy/adm/includes/manage_servers.php:136,182      -> ne journalise RIEN

    `user_logs` : aucune entree de modification d'identifiants MACHINE.
    Les « Mise a jour du mot de passe » qu'elle porte concernent des COMPTES UTILISATEURS.

**Donc l'identifiant d'accès root d'une machine de production peut changer sans qu'aucun journal ne le
dise** — ni qui, ni quand, ni depuis où.

### Ce qui l'a révélé, et pourquoi c'est instructif

`MODULE-PLATFORM-KEY.md` §4.4 affirmait « ni mot de passe ni mot de passe root » sur `srv-zabbix` et
concluait : *« son unique voie d'accès est la clé de plateforme. »* La session 3 a relancé la requête verbatim
et **déchiffré — en ne faisant rendre que les LONGUEURS, jamais les valeurs** :

    id 1  srv-zabbix  PROD   len(chiffre)=79 / 79    dechiffre : 13 / 13 caracteres
                             ssh_password_required = 0

**Ce ne sont pas des chiffrés de chaîne vide : deux mots de passe réels.** La mesure d'origine n'était pas
fausse — **l'état a changé depuis**, et le seul moyen de le savoir a été de remesurer. *Une conclusion écrite
sur un état mutable se périme sans prévenir, et rien dans le document ne le signale.*

**L'exploitant avait bien ressaisi ces mots de passe et l'avait dit** — donc l'écart n'est pas « un
changement inexpliqué ». **L'écart est qu'aucune trace ne permettrait de le savoir si personne ne l'avait
dit.**

### Ce que ça corrige dans le vocabulaire du chantier

**La phrase « RootWarden ne peut plus administrer `srv-zabbix` » sort du vocabulaire.** Il existe aujourd'hui
un repli par mot de passe. **L'interdiction de P4 tient sur ses AUTRES fondements** — `UPDATE` sans `WHERE` à
l'échelle du parc, volume non sauvegardé, destruction sans copie — et c'est précisément pourquoi il fallait
retirer celui-ci : *un interdit qui repose sur quatre fondements dont un est faux se fait démolir sur le
faux.*

### Et un état que la page ne peut pas produire

`srv-zabbix` porte **les deux mots de passe présents ET `ssh_password_required = 0`** — combinaison
qu'**aucun geste de la page de clé de plateforme ne peut produire** (E-207 : la page Serveurs réécrit les
colonnes sans toucher le drapeau). Le legacy lui peint donc la pastille verte « keypair », c'est-à-dire
« migration terminée, plus de mot de passe ». Le portage P1 **rend la divergence** au lieu de choisir une
source.

### La correction

Journaliser dans `user_logs` toute écriture de `password` / `root_password` d'une machine : qui, quand,
quelle machine, **et jamais la valeur ni sa longueur**. Chemin unique connu — `manage_servers.php:136,182` —
donc un seul point à instrumenter. **Le legacy est en production** : arbitrage de l'exploitant, au même titre
qu'E-209 et E-212.

---

## E-217 — Les deux implémentations ne s'accordent pas sur ce qu'est « pas de mot de passe » : `encryptPassword('')` rend une colonne NON vide

**Trouvé par la session 3 dans son PROPRE correctif P1, quelques heures après l'avoir écrit.**

    Python  encrypt_password('')        -> ''             colonne vraiment vide
    PHP     encryptPassword('', false)  -> 'sodium:…'      colonne NON vide

P1 corrigeait E-207 — « lire le drapeau au lieu du fait » — en testant les colonnes :
`(password IS NOT NULL AND password <> '')`. **Or ce test rend VRAI pour un mot de passe réellement vide**,
dès que la ligne a été écrite par le formulaire d'ajout du legacy avec le champ laissé blanc.

> **Le correctif échange une réponse fausse contre une autre sur ce cas.** *Corriger « le drapeau au lieu du
> fait » ne suffit pas si les deux implémentations ne s'accordent pas sur ce qu'est le fait.*

### Atteignable, et par le motif qu'on connaît

`manage_servers.php:352` pose `required` — **mais c'est du HTML.** Le contrôle serveur `$invalidFields`
(`:122-130`) n'inclut **ni `password` ni `root_password`** : une requête forgée passe. **Troisième occurrence
de « la garde est sur la PAGE, pas sur la REQUÊTE ».**

**Absent du parc aujourd'hui** — les trois lignes déchiffrent en 13 / 20 / 8 caractères — donc l'écart est
**réel et sans porteur**, comme E-205. Il s'ouvre à la première machine ajoutée par ce formulaire avec le
champ vide.

### Ce que la session 3 a refusé de faire, et elle a eu raison

**Elle n'a pas réimplémenté le déchiffrement en PHP** pour trancher. Le seul test fidèle est « déchiffrer et
regarder si c'est vide », et il vit dans le backend : *ne jamais recopier une règle de crypto* est une règle
du dépôt, et elle passe devant l'exactitude d'un compteur. Elle n'a **rien affirmé à l'écran que le code ne
tienne**.

### La correction, tranchée

**Le backend expose un booléen calculé** — « ce mot de passe déchiffre-t-il en vide ? » — et le portage le
consomme. Même précédent qu'**E-168**, où le portage aurait dû *supposer* faute d'un drapeau `lue`, et
qu'**INF-003**. Session 4 l'écrit, session 3 le consomme.

---

## E-218 — ⚠⚠ Le coupe-circuit d'un `NOPASSWD: ALL` ne fonctionne peut-être pas dans l'état exact vers lequel la page pousse — et le DÉPLOIEMENT porte le même défaut

**Trouvé par la session 3 en écrivant l'interface de `revoke_service_account` que le Lead venait d'autoriser
— donc en lisant une route qu'elle allait rendre cliquable. Le Lead a vérifié la chaîne entière et a trouvé
un SECOND porteur.**

### La chaîne, ligne par ligne

    1. ssh.py:970   revoke_service_account
                    with ssh_session(ip, port, user, ssh_pass, logger=logger)
                    -> PAS de `service_account=` : le defaut est False

    2. ssh_utils.py:246/278/312   `_rootwarden_auth_method` vaut donc
                                  'keypair' ou 'password', JAMAIS 'service_account'

    3. ssh_utils.py:537   execute_as_root court-circuite vers `sudo sh -c` SANS mot de passe
                          UNIQUEMENT si _rootwarden_auth_method == 'service_account'
                          -> sinon : `sudo -S -p ''` + root_password ecrit sur stdin

    4. remove_ssh_password   sur une machine migree, root_password = '' (chaine vide)

**Donc `sudo -S` reçoit un mot de passe vide.** Il ne réussit que si le compte **nominal** dispose d'un sudo
sans mot de passe — **ce que rien ne garantit.**

### Ce qui rend l'écart grave, et c'est sa position

`revoke_service_account` est **le seul moyen de reprendre un `NOPASSWD: ALL`** accordé en un clic. S'il
échoue sur les machines migrées, **l'octroi y est de fait définitif.**

> **Le coupe-circuit est sûr tant qu'on n'en a pas besoin, et douteux dans l'état exact vers lequel toute la
> page pousse.** C'est la forme que la session 3 venait d'inscrire ailleurs, appliquée à elle-même : *la
> révocation ne tient pas par une règle, elle tient par les droits sudo du compte nominal — que rien ne
> garantit.*

### ⚠ Le second porteur : `deploy_service_account`

    ssh.py:1061   deploy_service_account
                  with ssh_session(...)    <- PAS de `service_account=` non plus
                  puis trois `execute_as_root`

**Comparaison avec les quatre routes qui le passent correctement** — `:595`, `:1460`, `:2234`, `:2375`
portent toutes `service_account=m.get('service_account_deployed', False)`. **Seules `:970` et `:1061` l'omettent.**

Pour un **premier** déploiement l'omission est défendable : le compte de service n'existe pas encore, on ne
peut pas s'y connecter. **Mais pour un RE-déploiement sur une machine migrée, la même impasse s'ouvre** — et
c'est le geste que la page propose en masse.

*Fermer un défaut sans chercher ses autres implémentations, c'est le fermer à moitié* : la session 3 avait
nommé une route, il y en a deux.

### Ce qui n'est PAS mesuré, et ce qui borne l'écart

**Rien n'a été exercé.** L'écart est **dérivé du code** — quatre maillons lus, aucun geste émis. Et le
maillon final est un état de machine : **le compte nominal PEUT disposer d'un sudo sans mot de passe** (le
dépôt connaît un `/etc/sudoers.d/rootwarden-<user>`), auquel cas les deux routes fonctionnent.

**C'est précisément ce qui en fait un écart et non une panne** : la réussite dépend d'un état de parc que
personne ne vérifie, sur le geste dont dépend la réversibilité d'un privilège root. *Une propriété qui tient
par l'état du parc n'est pas une propriété* — quatrième occurrence du motif en une journée, après E-205 sans
porteur, les gabarits `--dport 22`, et l'avertissement que la session 3 a inscrit pour `srv-zabbix`.

### La correction

Passer `service_account=m.get('service_account_deployed', False)` sur `:970` **et** sur `:1061`, comme les
quatre autres. **Route backend, session 4** — et *qui écrit le code ne valide pas seul son correctif*.

**En attendant, la borne est DITE dans le panneau de décision**, pas dans un journal : c'est là que la
décision se prend. Le Lead confirme ce choix — *un avertissement qui arrive après le clic n'a pas averti.*

---

## E-219 — ⚠⚠ Le « kill-switch » documenté pour une COMPROMISSION DE CLÉ laisse la même clé autorisée sur root : il retire une porte sur trois

**Trouvé par la session 5 en relisant l'interface de révocation que la session 3 venait d'écrire — donc dans
une pré-relecture, avant qu'une ligne d'interface soit commitée. Vérifié par le Lead dans le code, sans
toucher aucune machine.**

### Les trois copies de la MÊME clé publique

    deploy_platform_key
      ssh.py:745    >> ~/.ssh/authorized_keys                  du compte NOMINAL
      ssh.py:755    >> /root/.ssh/authorized_keys              de ROOT
      ssh.py:808    >  /home/<sa>/.ssh/authorized_keys         du compte de service
      (ssh.py:1081  la meme, par deploy_service_account)

**`revoke_service_account` supprime le compte de service. Les deux autres copies restent.**

### Ce que la docstring annonce, mot pour mot

    ssh.py:896-910
    @require_role(3)  # superadmin only - kill-switch
    """
    Patch A04-INSEC-N5 (OWASP A04 Insecure Design) - kill-switch.
    ...
    Cas d'usage : compromission suspectee de la cle Ed25519 plateforme,
    rotation forcee, audit sortant.
    """

> **Si la clé de plateforme est compromise, ce « kill-switch » laisse deux portes sur trois ouvertes — dont
> celle de root.** Le geste ne traite **aucun** des trois cas d'usage qu'il nomme : ni la compromission (la
> clé reste autorisée), ni la rotation forcée (elle ne tourne pas), ni l'audit sortant (les accès subsistent).

**⚠ CORRIGÉ PAR E-226 :** il était écrit ici que *« le seul remède à une clé compromise est la ROTATION »*.
**Faux — mesuré.** La rotation ne révoque pas la clé : deux des trois écritures d'`authorized_keys` sont des
**AJOUTS** (`ssh.py:745`, `:755`) et `regenerate_platform_key` n'en touche aucun. **Il n'existe AUCUN geste
unique qui réponde à une clé compromise** — retirer l'ancienne clé exige `server_user_remove_key`, compte par
compte et machine par machine, et ce geste porte E-215.

### Cinquième forme du motif, et la plus grave de la série

| forme | trompe | exemple |
|---|---|---|
| un en-tête qui mente sur un accès | qui relit le code | E-36, 4 occurrences |
| un libellé qui promette un contrôle | qui clique | E-203 |
| un guide qui se trompe sur son effet | qui ne sait pas | E-209 |
| une description de permission fausse | qui **accorde** un droit | E-212 |
| **un CONTRÔLE DE SÉCURITÉ qui ne remplit pas le cas d'usage qu'il documente** | **qui répond à un incident** | **celle-ci** |

*Les quatre premières trompent en régime normal. La cinquième trompe pendant un incident* — au moment où
personne ne relit le code, où l'on clique ce que la documentation désigne, et où l'erreur ne se rattrape pas.
**Un coupe-circuit qui ne coupe pas est pire qu'un coupe-circuit absent** : son absence fait chercher une
autre parade.

### La correction, en deux temps

**Immédiat, et fait** : le libellé du portage dit ce que le geste **fait** — « Supprimer le compte
d'administration » — et le panneau dit ce qu'il **laisse en place**. **⚠ Et la suite de cette phrase était FAUSSE** (E-226) : il y était écrit que le remède à une clé
compromise est la rotation. *Un geste correctement nommé cesse d'être un piège même s'il reste partiel.*

**À arbitrer** : la docstring backend et l'étiquette `kill-switch` sont **fausses** et vivent dans le code.
Deux issues — corriger le texte pour qu'il décrive le geste réel, ou étendre le geste pour qu'il retire les
trois copies. **La seconde change ce qui est détruit sur des machines réelles** et rendrait RootWarden
incapable de joindre la machine autrement que par mot de passe : c'est un arbitrage de l'exploitant (§7).

### Ce que la même relecture a établi, et qui RESSERRE E-218

**Reformulation causale de la session 5, retenue** : `remove_ssh_password` **refuse** tant que le compte de
service n'est pas déployé. **Donc le seul état où `root_password` est vide est exactement celui où ce compte
existe.** Ce n'est pas une conjonction de deux états indépendants — **c'est une implication.**

Conséquence sur E-218 : la réserve est **levée pour la révocation** — la route se connecte par le compte
d'administration et s'élève sans mot de passe. **Un résiduel subsiste et il est nommé** : `connect_ssh`
retombe sur le compte nominal si cette connexion échoue (`ssh_utils.py:250-264`) — le cas `AllowUsers` que ce
dépôt connaît — et **ce repli rencontre `root_password = ''`**.

**La réserve TIENT en revanche pour la REPRISE du compte** : après une révocation le drapeau vaut 0, donc la
route ne peut pas se connecter par un compte qui n'existe plus. **Et c'est le bouton de révocation lui-même
qui rend cet état atteignable** — `ssh.py:986` est la seule écriture qui remette ce drapeau à 0. *Deuxième
occurrence du jour de « un correctif qui rend un chemin possible doit regarder ce qu'il rend irréversible sur
ce même chemin » — cette fois c'est une INTERFACE neuve qui ouvre le chemin.*

### Un état sans marqueur lisible par la machine

Le correctif d'E-218 a introduit un troisième verdict — `exit 2`, « compte supprimé mais sudoers subsistant, à
rejouer ». **Il n'arrive à l'écran que dans le TEXTE du message**, sans champ dédié. Le portage l'affiche donc
comme un échec dont le message dit « à rejouer ».

**La session 3 refuse de comparer des chaînes, et elle a raison** : *un état que seule une phrase distingue
n'est pas un état, c'est une coïncidence de rédaction* — et une traduction, une reformulation ou un
changement de casse le supprime sans bruit. **Correction : un champ `partiel` dans la réponse.** Route
backend, session 4.

---

## E-220 — ⚠⚠ Un PRIVILÈGE ORPHELIN sans nom : `NOPASSWD: ALL` pour un compte qui n'existe plus, et il n'a pas de nom dans le code

**Trouvé par la session 5 en relisant le correctif d'E-218 — donc dans la relecture d'un correctif qui venait
lui-même de fermer un piège. Le Lead a vérifié et trouvé un amplificateur que la session 5 n'avait pas.**

### L'état

Le correctif d'E-218 a introduit `exit 2` : **compte supprimé, fichier sudoers subsistant**. Sur `code == 2`,
`service_account_deployed` reste à **1** pour garder le rejeu ouvert — **bon choix**, et c'est ce choix qui
crée l'état.

    /etc/sudoers.d/rootwarden   contient  'rootwarden ALL=(ALL:ALL) NOPASSWD: ALL'
                                et AUCUN compte de ce nom n'existe

**Inerte aujourd'hui** : pas d'utilisateur, pas d'élévation. **Il redevient vivant à l'instant où quoi que ce
soit recrée un compte de ce nom** — gestion de configuration, `useradd` manuel, un paquet. **Root est alors
accordé en silence, sans que personne n'ait écrit de règle sudo.**

**Sur le chemin de RootWarden c'est sans conséquence** : `deploy_service_account` écrit le fichier avec `>`
(`ssh.py:813`, `:1127`), donc il l'écrase. **Sur tout autre chemin, non.**

### ⚠⚠ CORRECTION DU LEAD, 2026-08-27 — « L'AMPLIFICATEUR » QUE J'AI ÉCRIT ÉTAIT FAUX

**J'avais écrit** : *« le seul mécanisme du produit qui purge des fichiers sudoers a une exception explicite
pour celui-là, et elle rend l'orphelin durable — une exception de sûreté fondée sur "ce compte existe" survit
à la disparition du compte parce qu'elle ne la teste pas. »* **C'est faux, et je l'ai relayé à l'exploitant.**

**Mesure.** `_purge_legacy_sudoers(channel, username)` (`configure_servers.py:328`) n'est appelée que depuis
`add_to_sudoers` (`:430`) et `remove_from_sudoers` (`:459`), **toujours avec le nom d'un utilisateur GÉRÉ du
portail.** Son exception `if username == _RESERVED_SA_USER: return` (`:331`) est un **garde-fou de collision
de noms** : si un utilisateur du portail s'appelait `rootwarden`, ne pas écraser le fichier du compte de
service. **Elle ne regarde jamais `/etc/sudoers.d/rootwarden` en dehors de ce cas.**

> **L'exception n'est donc PAS ce qui maintient l'orphelin en vie.** La cause est plus simple et plus large :
> **aucune routine du produit ne balaie `/etc/sudoers.d/` à la recherche de fichiers sans compte
> correspondant.** Le fichier survit parce que personne ne le cherche, pas parce qu'une règle le protège.

**La conclusion tient — l'état est permanent — mais mon mécanisme était faux.** Troisième fois de la journée
qu'une trouvaille juste reçoit une explication fausse (après la portée puis la cause d'E-211), **et cette
fois-ci c'est moi qui l'ai écrite, quelques heures après avoir posé la règle** : *une trouvaille vérifiée n'a
pas son explication vérifiée, et ce sont deux relectures distinctes.* **Écrire une règle donne le sentiment de
l'avoir appliquée.**

### Ce qui maintient réellement l'état, et une demi-mesure que la mesure fait apparaître

**Ce qui le maintient** : la révocation est le **seul** geste du produit qui tente de retirer ce fichier, et
sur une machine migrée son rejeu ne peut pas élever (`root_password` vide). `deploy_service_account` l'écrase
(`>`) — mais **en recréant le compte**, donc il résout l'orphelin en supprimant sa condition, pas en le
nettoyant.

**Donc l'état persiste exactement sur les machines révoquées et jamais redéployées.**

**Et une demi-mesure existe, contrairement à ce que le relevé concluait** : un geste qui tourne déjà en root
sur une machine **sans** compte de service — `deploy_platform_key`, ou la passe de configuration de K4 — peut
retirer un `/etc/sudoers.d/rootwarden` **dont le compte n'existe pas**, en testant les deux. Auto-réparation,
**sans changement de schéma et sans état à persister.**

**Ce n'est pas une décision de portage** : c'est une écriture supplémentaire sur des machines réelles, donc un
arbitrage de l'exploitant (§7). **Et l'argument qui la rend praticable est mesuré** : `deploy_platform_key`
appelle `execute_as_root` et écrit dans `/root/.ssh/` — **donc si elle s'exécute, l'élévation a déjà réussi.**
Le nettoyage **hérite** d'une élévation prouvée au lieu de payer la précondition qui bloque le rejeu.

#### ⚠ DEUX GARDES OBLIGATOIRES, et sans elles le défaut irait dans le sens DESTRUCTEUR

Relevé par la session 4, et c'est la réserve qui compte : la condition « aucun compte de ce nom n'existe »
**n'est pas fail-closed naturellement.**

`id rootwarden` peut échouer pour une raison qui **n'est pas** l'absence du compte — NSS indisponible, LDAP
injoignable, délai dépassé. **Une condition écrite « si `id` échoue » retirerait alors un `NOPASSWD: ALL`
légitime et casserait le compte de service d'une machine saine** — dans un geste de parc lancé en masse.

    1. exiger l'absence POSITIVEMENT : `getent passwd rootwarden` distingue « absent » (code 2)
       d'une « erreur de service » (autres codes). Ne retirer que sur l'absence NOMMEE,
       jamais sur « la commande n'a pas reussi ».
    2. croiser avec la BASE : ne retirer que si `service_account_deployed = 0`.
       Apres E-220 le drapeau vaut 0 exactement dans l'etat orphelin — les deux
       signaux doivent CONCORDER, sinon on ne touche a rien.

*Un marqueur n'est pas un verdict, et un échec de commande n'est pas une réponse* — la règle a servi deux fois
dans la journée, et ici elle décide entre un nettoyage et une casse.

#### ⚠ ET L'OPTION 1 N'EST PAS UN SUR-ENSEMBLE DE L'OPTION 2

**Correction de la présentation du Lead, par la session 4.** L'auto-réparation ne répare que les machines
**redéployées**. **Une machine révoquée puis laissée telle quelle garde son privilège dormant
indéfiniment** — et c'est précisément la population qui crée l'orphelin.

> **Les deux options sont COMPLÉMENTAIRES, pas classées** : l'auto-réparation **réduit la population**, la
> colonne **rend le reste visible**. Le Lead les avait présentées comme un premier choix et un repli ; c'est
> faux. *Une mesure qui réduit un ensemble ne remplace pas celle qui décrit ce qui reste.*

### Le vrai défaut est que l'état n'a PAS DE NOM

`exit 2` n'arrive à l'écran que dans le **texte** de `r['message']`. **La route connaît l'état ; l'écran ne le
voit pas.** La session 3 a refusé de comparer des chaînes pour le distinguer — *un état que seule une phrase
distingue est une coïncidence de rédaction*, qu'une traduction ou une reformulation supprime sans bruit.

**Et l'absence de nom se propage à une AUTRE route, ce qui est le point qui décide :**

    ssh.py:1275   remove_ssh_password :  if not m.get('service_account_deployed'):  -> refus

Sur `code == 2` le drapeau vaut **1**. Donc `remove_ssh_password` **accepterait**, et viderait les deux mots
de passe d'une machine **dont le compte de service n'existe plus**.

**Ce n'est pas un verrouillage** — la clé de plateforme reste sur le compte nominal et sur `root` (E-219),
donc `connect_ssh` retombe sur sa première tentative. **Mais la précondition ne mesure plus ce qu'elle croit
mesurer.**

> **Un état qui n'a pas de nom ne peut être pris en compte par aucune autre route.** Formulation de la
> session 5, et c'est la généralisation qui compte : le drapeau `service_account_deployed` est **binaire** pour
> une réalité devenue **ternaire** — déployé / absent / **sudoers orphelin**. Toute route qui lit ce drapeau
> hérite de l'imprécision.

### La correction

**Un champ nommé dans la réponse : `sudoers_orphelin: true`**, et non un `incomplet` abstrait —
recommandation de la session 5, retenue pour sa raison : *un nom porte la raison, un booléen porte une
couleur.* Puis les routes qui lisent `service_account_deployed` comme une précondition doivent savoir
distinguer les trois états.

**Route backend, session 4.** Et *qui écrit le code ne valide pas seul son correctif* : c'est le deuxième
correctif consécutif sur cette route, et le premier avait armé un piège que sa propre relecture n'avait pas vu.

---

## E-221 — ⚠⚠ « Avoir accès à une machine » et « avoir le droit de la mettre à jour » sont deux questions, et une seule est posée

**Mesuré par la session 4 sur les 28 routes sans autorisation au-delà de la clé d'API. Le verdict est net :
c'est un risque, pas un inventaire.**

### Le classement

    28  routes sans role ni permission
        19  joignent une machine
             4  INSTALLENT des paquets en root, tout de suite
                apt_update · update_server · apply_security_updates · custom_update
             3  POSENT UNE TACHE PLANIFIEE qui mettra a jour plus tard, EN ROOT
                schedule_update · schedule_advanced_update · schedule_advanced_security_update
             3  modifient l'etat sans installer
                dpkg_repair (killall -9 + dpkg --configure -a) · dry_run_update · pending_packages
             9  lecture distante seule
         9  ne joignent pas de machine
             7  lectures en base · 1 ecriture (`cve_reprioritize`) · `update_zabbix` (307, dedouanee)

### Ce qui manque n'est pas le périmètre, c'est la CAPACITÉ

**Ces routes portent `@require_machine_access` et il MORD** — elles sont dans les 54. Le périmètre machine
**est** vérifié. Ce qu'aucune ne demande, c'est un **rôle** ou une **permission**.

> **Un compte de rôle 1 ayant une seule machine dans son périmètre peut y lancer `apt-get full-upgrade -y` et
> y installer une tâche planifiée qui tourne en root.**

Vérifié : `apt_update` exécute bien `full-upgrade`. *« Avoir accès à une machine » et « avoir le droit de la
mettre à jour » sont deux questions, et une seule est posée.*

### La catégorie la plus lourde ne se voit PAS dans un décompte « écrit / lit »

Les trois routes de planification n'écrivent **qu'un fichier**. Mais c'est un `/etc/cron.d/*` qui
**s'exécutera en root indéfiniment**. Un balayage qui compte les écritures les rangerait avec
`cve_reprioritize`, un simple `UPDATE` en base.

> *Un geste ponctuel se rejoue ; un geste planifié se répète sans que personne ne le redemande.* **Le nombre
> d'écritures ne classe pas un risque : la durée de vie de l'effet le classe.**

### Le remède est connu et il a un précédent dans ce dépôt

Une **permission de mise à jour**, comme `can_manage_fail2ban` l'a fait pour les quinze routes de `fail2ban`
via **E-152**. **`updates/` est le seul module du parc où douze routes n'en portent aucune.**

### ⚠ Décision : NE PAS l'écrire maintenant

Douze routes de plus dans une file de **quinze correctifs déjà inertes**. **Le Lead confirme le choix de la
session 4 d'attendre le redémarrage**, et la raison n'est pas la prudence :

- **écrire le correctif maintenant ne protège rien** — `backend/**.py` est lu au démarrage du processus,
  l'écriture est inerte, seul le redémarrage mord ;
- **et ça aggrave le seul risque réel du lot** : un lot de 27 correctifs non mesurés qui prennent effet
  ensemble. *Un correctif inerte n'est pas un correctif en attente, c'est un correctif dont le comportement
  n'a jamais été observé.*

**Ce qui doit monter à l'exploitant n'est donc pas le correctif : c'est la PRIORITÉ du redémarrage.** Cet
écart est le premier du lot qui décrive une **élévation de privilège atteignable par un compte existant** — et
non un texte faux, un compteur trompeur ou un état dérivé du code.

---

## E-222 — La sauvegarde d'une copie de règles pare-feu DÉTRUIT l'ancienne avant d'écrire la nouvelle, sans transaction — et un échec ne laisse rien

**Trouvé par la session 5 en portant `iptables/` I2, sur le schéma. Le Lead a vérifié et trouvé un mécanisme
différent, plus probable et plus dommageable que celui relevé.**

### Ce que la session 5 a relevé, et qui est exact

    mysql/init.sql:138-145
    CREATE TABLE iptables_rules (
      id INT AUTO_INCREMENT PRIMARY KEY,
      server_id INT NOT NULL,            -- AUCUNE contrainte UNIQUE
      rules_v4 TEXT, rules_v6 TEXT,
      FOREIGN KEY (server_id) REFERENCES machines(id) ON DELETE CASCADE )

    legacy/iptables/index.php:110
    SELECT rules_v4, rules_v6 FROM iptables_rules WHERE server_id = ?   -- puis fetch()
                                                   -- ni ORDER BY, ni LIMIT

**Si deux lignes existaient pour la même machine, celle qui est lue ne serait pas déterminée.** Même défaut
que le `LIMIT 1` sans `ORDER BY` relevé sur la révocation des clés d'API, où il rendait la révocation non
déterministe.

### ⚠ Mais le chemin d'écriture n'est pas un `INSERT` : c'est un `DELETE` PUIS un `INSERT`, sans transaction

    legacy/iptables/index.php:142-151
    // Suppression de l'ancienne entree avant remplacement (pas d'UPSERT)
    DELETE FROM iptables_rules WHERE server_id = ?      -- execute
    INSERT INTO iptables_rules (server_id, rules_v4, rules_v6) VALUES (?, ?, ?)

**Aucun `beginTransaction`, aucun `commit`, aucun `rollBack` dans le fichier — vérifié.** Deux conséquences,
et la seconde est celle qui compte :

1. **la duplication est peu probable sur le chemin normal** — le `DELETE` précède chaque écriture. Elle
   demande un entrelacement concurrent (`DELETE A`, `DELETE B`, `INSERT A`, `INSERT B`). Le défaut relevé par
   la session 5 est donc **réel mais difficile à atteindre** ;
2. **et le défaut PROBABLE est l'inverse : si l'`INSERT` échoue après un `DELETE` réussi, la copie est
   PERDUE.** Il n'en reste aucune. La page annonce alors « Erreur lors de la sauvegarde des règles » — message
   **exact sur l'échec de l'écriture, et muet sur la destruction de l'existant.**

> **Un « enregistrer » qui détruit avant d'écrire, sans transaction, n'est pas une sauvegarde risquée : c'est
> une suppression suivie d'une tentative.** Et l'utilisateur qui lit « erreur lors de la sauvegarde » conclut
> que rien n'a changé — *le message décrit le geste qui a échoué, jamais celui qui a réussi.*

L'absence d'`UNIQUE` est donc la cause de la **forme** choisie — pas d'`UPSERT` possible sans elle, comme le
commentaire du code le dit lui-même — et cette forme est la vraie faiblesse. **La contrainte manquante et le
`DELETE` préalable sont un seul défaut, pris par deux bouts.**

### Sans porteur aujourd'hui, et la table est vide

**Aucune ligne** dans `iptables_rules`. L'écart est **réel et sans porteur**, comme E-205 et E-217 — et il
s'ouvre à la première copie enregistrée. *Une propriété qui tient par l'état du parc n'est pas une propriété.*

### Ce que le portage fait, et ce qu'il reste à faire

**Fait par I2** : la lecture prend la ligne **la plus récente** et **annonce s'il y en a plusieurs** — au lieu
de lire une ligne indéterminée en silence.

**À faire** : une contrainte `UNIQUE (server_id)` et un véritable `UPSERT`, ou à défaut une transaction autour
du `DELETE`/`INSERT`. **Migration sur une table de production** — donc arbitrage de l'exploitant, et la table
étant vide, c'est le moment le moins coûteux de l'histoire du produit pour poser la contrainte.

### Deux gestes de portage qui méritent d'être la règle

**1. Un refus repris d'ailleurs plutôt qu'inventé.** Une copie dont l'IPv4 est vide est refusée **parce
qu'`iptables-rollback` refuse déjà d'appliquer une version vide.** On remonte la règle existante au lieu d'en
écrire une seconde.

*C'est l'exact complément de la réserve que trois sessions ont opposée au Lead* — « avant d'unifier deux
choses qui se ressemblent, nomme le domaine de chacune ». **Ici le domaine est le même**, donc réutiliser est
juste, et écrire une seconde règle aurait créé deux vérités sur la même question. **La règle n'est ni
« unifier » ni « distinguer » : c'est nommer le domaine, puis suivre ce qu'il dit.**

**2. La borne des colonnes contrôlée AVANT l'écriture, en OCTETS.** `TEXT` tient 65 535 **octets**, et
**MySQL tronque en silence** en mode permissif. Sans ce contrôle, *l'écran annoncerait « enregistré » sur une
copie amputée, et la troncature ne se verrait qu'au moment de l'appliquer* — c'est-à-dire au pire moment,
sur une règle de pare-feu.

**Et un texte qui devenait faux** : l'encart d'I1 annonçait que la copie en base n'était pas portée. I2 la
porte — corrigé dans les deux langues. *Un texte peut devenir faux sans qu'aucun test ne le voie*, et c'est
la sixième occurrence de la famille aujourd'hui.

---

## E-223 — Le portage lit `FEATURE_WAZUH`, qui n'existe NULLE PART : désactiver Wazuh le cache dans le legacy et laisse le menu du portage pointer vers un 404

**Trouvé par deux sessions indépendamment, à la même heure, sur la même question. Vérifié par le Lead.**

    laravel/config/rootwarden.php:100   'wazuh' => env('FEATURE_WAZUH', true)
    srv-docker.env.example:504          WAZUH_ENABLED=true
    backend/config.py:143               WAZUH_ENABLED = os.getenv('WAZUH_ENABLED', 'true')...

**`FEATURE_WAZUH` n'apparaît qu'à cette seule ligne dans tout le dépôt** — ni dans `srv-docker.env.example`,
ni dans `laravel/.env.example`, ni dans `docker-compose.yml`. Le conteneur du portage reçoit bien
`srv-docker.env` (`env_file`), **mais la variable y porte l'autre nom.**

> **Le défaut par défaut `true` s'applique donc TOUJOURS, quoi que fasse l'exploitant.**

### La chaîne complète quand `WAZUH_ENABLED=false`

| étage | lit | quand | résultat |
|---|---|---|---|
| page legacy | `WAZUH_ENABLED` | **par requête** | menu caché **et** `wazuh/index.php:19` rend 404 |
| proxy `api_proxy.php` | **aucun** | — | relaie ; `/wazuh/` est en liste blanche |
| backend | `Config.WAZUH_ENABLED` | **une fois au démarrage** | **le blueprint n'est pas enregistré** → 404 natif |
| **portage `Navigation`** | **`FEATURE_WAZUH`** | par requête | **`true` → l'entrée RESTE affichée** ⚠ |

**Et l'entrée y est déclarée `'legacy' => '/wazuh/'`** : cliquer mène à la page legacy, **qui rend 404**.
*Un module désactivé se présente comme un module cassé.*

### Ce que ce n'est PAS, et il faut le dire

**Ce n'est pas « une garde présente qui ne garde rien ».** Le drapeau backend conditionne l'**enregistrement
du blueprint** : il n'existe aucune route à atteindre. *C'est plus fort qu'un contrôle par requête, pas plus
faible* — le seul coût est opérationnel, basculer le drapeau demande une recréation du processus.

**C'est la forme « une règle qui vit en deux langages »**, ici en **trois**, avec **deux noms de variable pour
un seul drapeau.** Non exploitable : un défaut de cohérence et de disponibilité.

**Et c'est le seul cas connu où le portage CONTREDIT une décision d'exploitation** : celui qui désactive Wazuh
croit l'avoir désactivé partout. **Le chantier fabrique lui-même un 404 dans un menu** — même famille que
l'oubli de `/docker/` dans `LiensLegacy`.

### Un second désaccord, mesuré interpréteur contre interpréteur

    valeur      PHP legacy    Python
    'true'      ON            ON
    'false'     OFF           OFF
    ''          ON (defaut)   OFF     <-- DESACCORD
    '1','yes'   OFF           OFF

`feature_enabled()` traite `''` comme « absente » et rend **ON** ; Python fait `''.lower() == 'true'` → **OFF**.
Donc `WAZUH_ENABLED=` — présente et vide, faute d'exploitation banale — rend **la page servie et toutes ses
routes 404.** *Une colonne vide et une valeur absente ne sont pas la même chose, et les deux moitiés du
produit ne s'accordent pas* — troisième occurrence de ce motif après `encrypt_password('')` (E-217).

**Ce qui borne** : `wazuh` est le **seul** appelant de `feature_enabled()` dans tout le legacy. Le helper est
générique, son rayon est d'un module.

### La correction : un drapeau de MOINS, pas une règle en double

`env('WAZUH_ENABLED', true)`, et **`FEATURE_WAZUH` disparaît.** *Le domaine est le même, donc le nom doit
l'être* — l'inverse exact de la réserve « avant d'unifier, nomme le domaine de chacune ». **Session 3**,
`laravel/config/` étant son périmètre.

### ⚠ Et une cinquième place à basculer, qui n'est dans aucune catégorie du cycle

`Navigation.php:102` porte une clé **`'feature' => 'wazuh'`** que le premier relevé avait manquée — *le motif
ne cherchait pas cette forme.* **C'est le cinquième emplacement de ce module**, après la barre latérale, le
tiroir, le raccourci clavier (absent) et la tuile du tableau de bord. Le cycle d'archivage n'en connaît que
quatre : **à ajouter.**

### Deux réserves déclarées, à ne pas croire sur parole

1. **rien n'a été vérifié au navigateur** — c'est une lecture de code. La propriété à mesurer est *l'entrée de
   menu est-elle rendue avec `WAZUH_ENABLED=false` ?*, et elle demande le jeton de banc ;
2. **`env()` hors `config:cache` est lu par requête**, donc le portage n'a pas le régime « une fois au
   démarrage » ici. **Mais l'entrypoint ne fait que `view:cache` : si quelqu'un ajoute `config:cache`, ce
   drapeau se figerait**, et le nom corrigé n'y changerait rien.

---

## E-224 — ⚠ `POST /wazuh/install_all` est CASSÉ, personne ne l'a su, et corrigé il commencerait par la PRODUCTION

**Trouvé par la session 2 en inventoriant `wazuh/`. Vérifié.**

    backend/routes/wazuh.py:465-467
    LEFT JOIN wazuh_agents a ON a.machine_id = m.id
      ...
      AND a.id IS NULL

    mysql/migrations/034_wazuh.sql:43
    machine_id INT NOT NULL PRIMARY KEY      -- il n'y a AUCUNE colonne `id`

**`ERROR 1054 — Unknown column 'a.id' in 'where clause'`**, reproduit à l'identique. **Aucun `try` n'entoure la
requête → 500.** Et `wazuh_agents` porte **0 ligne** : *le module n'a jamais servi, donc personne ne l'a vu.*

À noter : `wazuh.py:298` porte le **même** `LEFT JOIN` sans la faute — la bonne écriture est à quelques lignes.

### ⚠ Ce n'est pas une protection, c'est un accident

**La requête corrigée, le geste part — et il trie `CRITIQUE` en premier, donc il commencerait par
`srv-zabbix`.** Même famille que `/ssh-audit/scan-all` et `groups/run` : *une route sans paramètre de portée ne
se borne pas par une fixture.* **Mais celle-là MUTE** : elle installe un paquet.

> **Un défaut qui protège par accident cesse de protéger au moment exact où on le corrige** — et l'ordre de
> tri fait de la production la **première** cible, pas une parmi trois.

**Conséquence immédiate** : ne corriger cette requête **qu'avec** une borne de portée, jamais seule. Et
**aucune suite ne doit approcher cette route**, au même titre que `go-ssh-audit-scanall.mjs`.

---

## E-225 — `install` ajoute un dépôt tiers et sa clé GPG ; `uninstall` ne les retire pas

**Trouvé par la session 2. Vérifié.**

    backend/routes/wazuh.py:348-350  (et :507-509 pour install_all)
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg ... --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo 'deb [signed-by=...] https://packages.wazuh.com/4.x/apt/ stable main'
        > /etc/apt/sources.list.d/wazuh.list

**Donc chaque machine gérée émet vers Internet et fait confiance à ce dépôt de façon permanente.**

`uninstall` fait `purge || true && rm -rf /var/ossec` — **et ne retire ni le dépôt ni la clé** (mesuré par la
session 2 : zéro occurrence de `sources.list` ou `keyrings` dans la route).

> **Désinstaller laisse la machine configurée pour faire confiance à un dépôt tiers**, avec sa clé de
> signature installée dans `/usr/share/keyrings/`. *Un geste réversible qui ne rend pas tout ce qu'il a pris
> n'est pas réversible : il est partiel, et le reste est invisible.*

Même forme qu'E-220 — le privilège orphelin — appliquée à une **relation de confiance** au lieu d'un droit
sudo : l'état résiduel est inerte tant que rien ne l'emploie, et il n'a **aucun porteur en base.**

**Arbitrage de l'exploitant** : retirer le dépôt à la désinstallation change ce qui s'écrit sur des machines
réelles, et un exploitant peut légitimement vouloir garder le dépôt pour réinstaller. **Ce qui n'est pas
discutable, c'est que le geste ne le DIT pas.**

### Le dédouanement, et il est remarquable

**Les 15 routes de `wazuh.py` portent TOUTES `@require_api_key` + `@require_role(2)` +
`@require_permission('can_manage_wazuh')`** — 15 sur 15, **le module le plus uniformément gardé du chantier**,
devant `groups/` (6/6). **Et la page s'accorde avec ses routes** : `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`,
rôle 2 des deux côtés — **premier module où la page n'est pas plus permissive que ses requêtes.**

*Un relevé qui ne dédouane pas se lit comme un réquisitoire, et on cesse de le croire.*

---

## E-226 — ⚠⚠⚠ LA ROTATION DE CLÉ NE RÉVOQUE PAS LA CLÉ COMPROMISE. IL N'EXISTE AUCUN GESTE QUI Y RÉPONDE.

**Trouvé par la session 5 en relisant P4 avant son commit. Vérifié par le Lead ligne par ligne. Cet écart
CONTREDIT une conclusion que le Lead avait écrite dans ce fichier et transmise à l'exploitant.**

### La mesure

    ssh.py:745   printf … | base64 -d >> ~/.ssh/authorized_keys        compte NOMINAL   APPEND
                 sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys
    ssh.py:755   printf … | base64 -d >> /root/.ssh/authorized_keys    ROOT             APPEND
                 sort -u /root/.ssh/authorized_keys -o …
    ssh.py:808   printf … | base64 -d >  /home/<sa>/.ssh/authorized_keys   compte de service   ECRASE

    regenerate_platform_key : occurrences de `authorized_keys` / `sed -i` / `remove` -> **0**

**Deux des trois écritures sont des AJOUTS. La rotation ne touche aucun `authorized_keys`.**

> **Après une rotation puis un redéploiement, `root` et le compte nominal portent les DEUX clés publiques.
> Qui détient la clé compromise garde un accès root sur chaque machine, après la rotation.**

La rotation empêche RootWarden d'**utiliser** l'ancienne clé. **Elle ne la RÉVOQUE pas.**

### Et le `sort -u` aggrave, au lieu de protéger

Il **déduplique** — donc le fichier reste propre et paraît intentionnel. **Deux clés RootWarden distinctes s'y
installent sans que rien n'ait l'air anormal.** *Un nettoyage cosmétique appliqué à un résidu le rend
indiscernable d'un état voulu.*

### ⚠ CE QUE LE LEAD AVAIT ÉCRIT, ET QUI EST FAUX

Le Lead a inscrit dans ce fichier, et transmis à l'exploitant :

> ~~*« La rotation est le seul remède réel à une clé compromise. P4 n'est pas seulement le geste le plus large
> du module : c'est le SEUL qui réponde au cas d'usage que le portail attribue à un autre bouton. »*~~

**FAUX.** La rotation n'est pas un remède partiel : **elle ne répond pas au cas.** Le raisonnement était juste
dans sa forme — la révocation ne traite pas la compromission (E-219), donc un autre geste doit le faire — **et
le Lead a conclu sans mesurer que la rotation le traitait.** *Une déduction par élimination suppose que la
liste est complète et qu'un des membres répond ; ici aucun ne répond.*

**C'est la quatrième fois de la journée qu'une trouvaille juste reçoit une explication fausse, et la seconde
fois que c'est le Lead** — après le faux « amplificateur » d'E-220. Les deux fois, l'erreur est allée dans le
sens **rassurant** : *il existe un remède*, puis *il existe un nettoyage*.

### Il n'existe AUCUN geste unique qui réponde à une clé compromise

Retirer la clé exige de réécrire les `authorized_keys` **compte par compte et machine par machine** —
`server_user_remove_key` (`ssh.py:2200`).

> **⚠ CORRECTION DU LEAD, 2026-08-28 — J'AVAIS ATTRIBUÉ E-215 À LA MAUVAISE FONCTION.**
> Il était écrit ici que `server_user_remove_key` « atteste sans vérifier et filtre par sous-chaîne ».
> **Faux, et relevé par la session 3 avec la mesure :**
>
>     `sed -i '/rootwarden/d' … ; echo OK`  ->  ssh.py:2403, dans **remove_user_keys** (def :2352)
>     def server_user_remove_key                                                        (def :2200)
>
> **`server_user_remove_key` est la route SOIGNEUSE du fichier** : elle refuse `is_platform_key` sans `force`
> (« utilise --force si tu veux vraiment te locker hors du serveur »), **sauvegarde** (`${tmp}.bak`),
> **recalcule les empreintes ligne par ligne** avec `ssh-keygen -lf`, distingue `exit 1` d'`exit 2`, et **lit
> son code de retour**. C'est précisément l'implémentation que la session 5 demande de **remonter** pour
> corriger `remove_user_keys`.
>
> **Deux sessions ont fait la même confusion avant de mesurer, le Lead compris.** *Deux fonctions du même
> fichier, même geste, des noms qui ne diffèrent que par un préfixe — et l'une garde ce que l'autre ignore.*
> **Le nom ne dit pas laquelle.**

**Donc la chaîne complète de réponse à une compromission est, aujourd'hui :**

| geste | ce qu'il fait | ce qu'il laisse |
|---|---|---|
| `revoke_service_account` — documenté « kill-switch, compromission » | supprime le compte de service | **la clé sur root et sur le nominal** (E-219) |
| `regenerate_platform_key` — P4, « le geste le plus large » | génère une paire neuve | **l'ancienne clé autorisée partout** (celui-ci) |
| `server_user_remove_key` — aucune interface de parc | retire une clé, un compte, une machine — **soigneusement** : sauvegarde, empreintes recalculées, refus par défaut sur la clé de plateforme | **rien** — c'est `remove_user_keys` qui porte E-215, pas elle |

*Trois gestes, aucun qui ferme la porte, et celui qui en approche le plus n'a pas d'interface.*

### Conséquence immédiate : P4 NE COMMITE PAS EN L'ÉTAT

Le panneau de P4 annonce que la rotation répond à une clé compromise. **C'est un texte faux sur l'écran qu'on
lit pendant un incident** — la cinquième forme du motif, la plus grave, et **le portage était en train de la
reproduire en croyant corriger E-219.**

**Ce que le panneau doit dire** : la rotation **remplace la clé que RootWarden emploie** ; elle **ne retire pas
l'ancienne des machines** ; et **répondre à une compromission demande, en plus, de retirer l'ancienne clé
compte par compte.** *Moins plutôt que faux, et surtout : ne pas fabriquer la fausse certitude qu'on vient de
se protéger.*

### Second point bloquant sur P4, du même relecteur

**La rotation est le seul des six gestes du module à n'exiger RIEN.** La révocation demande un motif, la
ressaisie un mot de passe — **la rotation, un clic.** Le bouton de confirmation n'est désactivé que *pendant*
la requête : **il ne naît pas désactivé**, et aucun champ de recopie n'existe. **Le legacy en demandait deux.**

*Le portage a pris la première moitié de la leçon du chantier — un panneau plutôt que deux `confirm()` — et
laissé la seconde.* Correction : **le bouton naît DÉSACTIVÉ et ne s'active qu'à l'égalité exacte d'une
recopie.** Le panneau affiche déjà le total du parc ; le faire recopier n'invente rien.

### ⚠ Et une consigne du Lead était trop étroite

Le Lead a interdit `tests/e2e/go-ssh-audit-scanall.mjs`. **Le danger n'est pas la suite :**

    legacy/ssh-audit/index.php:82   <button type="button" onclick="scanAll()">

**Le geste est à UN CLIC sur la page.** Nommer le fichier et laisser le bouton, c'est laisser toute mesure
conduite sur cette page — pour n'importe quel motif — à un clic malheureux de scanner tout le parc, production
comprise. **La formulation qui protège** : *sur cette page, ne cliquer que des éléments visés par identifiant
relu — jamais « le premier bouton », jamais un balayage.*

**Dédouanement** : l'en-tête de ce fichier est **honnête**, conforme au code — après quatre en-têtes menteurs
dans les modules voisins.

---

## E-227 — ⚠⚠⚠ OUVRIR LA PAGE DE DIAGNOSTIC DÉPLOIE UN `NOPASSWD: ALL` SUR LA PRODUCTION

**Trouvé en retirant l'entrée d'E-224 : la ligne voisine était vivante, et la mesure a montré bien pire.**
`legacy/adm/health_check.php` est **servi en production**.

### La cible n'est pas « une machine quelconque » : c'est toujours la pire

    health_check.php:49-50
    $stmt = $pdo->query("SELECT id FROM machines LIMIT 1");   -- SANS `ORDER BY`
    $machineId = $stmt->fetchColumn() ?: 0;

**Mesuré : rend `id = 1` — `srv-zabbix`, criticité `CRITIQUE`, LA PRODUCTION.** La machine que tout le
chantier a l'interdiction de joindre.

### `testRoute()` fait un VRAI `curl`, et la page boucle dessus au chargement

**Le fichier porte déjà un correctif** (`:52-57`) qui pointe les routes mutantes sur `$mutId = 0` — « ne
doivent JAMAIS s'exécuter sur un vrai serveur au simple chargement de la page ». **Sept y avaient échappé :**

| entrée | ce qu'elle fait sur `srv-zabbix`, au chargement |
|---|---|
| `/deploy_service_account` | **crée le compte `rootwarden` avec `NOPASSWD: ALL`** |
| `/deploy_platform_key` | déploie la clé publique sur le compte nominal **et sur `root`** |
| `/sshd_allow_user` | **réécrit `sshd_config`** et recharge `sshd` |
| `/server_user_remove_key` | tente une suppression de clé |
| `/scan_server_users` | **écrit et DÉCIDE** — `INSERT` avec auto-classement (E-213) |
| `/last_reboot`, `/dry_run_update` | lectures distantes |

> **Ouvrir une page d'administration accordait un accès root permanent et sans mot de passe sur la
> production.** Aucun clic, aucune confirmation, aucune trace de décision.

### Ce qui le rend pire qu'un défaut : le correctif existait et était incomplet

*Un correctif appliqué à certains porteurs et pas à tous laisse le défaut intact là où il coûte le plus, ET
fait croire qu'il est fermé.* Le commentaire de `:52-57` énumère consciencieusement les routes protégées —
`services start/stop`, `ssh-audit fix/save/toggle/reload`, `dpkg_repair`, `update`… — **et sa liste ne contient
aucune des quatre plus destructrices.** Quiconque relisait ce fichier lisait une intention de protection et
concluait qu'elle était tenue.

**C'est aussi la sixième occurrence de « fermer un défaut sans chercher ses autres implémentations, c'est le
fermer à moitié »** — et la première où la moitié oubliée est la plus grave.

### Et deux entrées de diagnostic MUTAIENT le parc entier

- **`/fail2ban/install_all` — VIVANTE.** `SELECT … FROM machines m … WHERE f.installed IS NULL OR f.installed
  = 0`, **aucun `machine_ids`, aucune portée**, puis `for m in machines: ssh_session(…)` et **installe le
  paquet**. Corps vide au `curl` → **ouvrir la page installait fail2ban sur tout le parc, production
  comprise** ;
- **`/wazuh/install_all` — inerte PAR ACCIDENT**, sa requête étant cassée (E-224). Son libellé disait
  « dry, vide la liste » : **le mot décrivait un accident, pas une conception**, et *une conclusion écrite fait
  renoncer à mesurer.* **Le jour où E-224 est corrigé, elle devient la jumelle vivante de la précédente** — et
  son `ORDER BY … CASE WHEN criticality = 'CRITIQUE'` place `srv-zabbix` **en premier**.

### Corrigé, et dans l'ordre qui compte

**Les deux entrées `install_all` sont retirées** — *une entrée de DIAGNOSTIC n'a pas à MUTER le parc* — et les
**sept** routes ci-dessus visent désormais `$mutId = 0`, comme leurs voisines. **Retiré AVANT le correctif SQL
d'E-224**, et c'est l'ordre qui compte : *le SQL seul serait plus dangereux que le défaut qu'il corrige.*

**Ce qui n'est PAS corrigé, et reste à l'exploitant** : la requête `LIMIT 1` sans `ORDER BY` désigne toujours
la production pour les **lectures** distantes — dix-sept entrées ouvrent une session SSH vers `srv-zabbix` au
chargement. C'est une lecture, mais *la règle du chantier ne distingue pas lecture et écriture sur la
production*, et **une page de diagnostic n'a pas à choisir la machine la plus critique par accident de tri.**

---

## E-228 — E-227 avait laissé une HUITIÈME route mutante, et deux entrées de diagnostic visent des routes qui n'existent pas

**Trouvé par la session 4 en instruisant la question de la cible. Elle a retourné contre E-227 le commentaire
que le Lead avait écrit dans ce fichier même.**

### La huitième

    health_check.php:114   ['Pending Packages', 'POST', '/pending_packages', ['machine_id' => $machineId], …]
    updates.py             pending_packages -> `apt-get update -qq` en ROOT

**`apt-get update` réécrit les listes de paquets.** La route visait `$machineId` — donc **`srv-zabbix`, la
production — à chaque chargement de la page.**

> **E-227 a corrigé « les sept routes mutantes ». Il en restait une huitième, classée parmi les lectures.**

**Et c'est le commentaire posé par E-227 qui dit pourquoi ça compte** : *« un correctif appliqué à certains
porteurs et pas à tous laisse le défaut intact là où il coûte le plus, ET fait croire qu'il est fermé. »*
**Ça valait aussi pour E-227.** Corrigé : `$mutId`.

**Pourquoi elle avait échappé** : *son NOM dit « pending », sa commande dit `update`.* Septième occurrence du
motif « le libellé n'est pas le geste » — et la première où c'est un **nom de route** qui trompe, non un
commentaire ni un en-tête.

### Le balayage exhaustif des quinze restantes, et le faux positif de la sonde du Lead

Cette fois les quinze ont été vérifiées **par leur COMMANDE, pas par leur nom** : `server_status`,
`linux_version`, `preflight_check`, `test_platform_key`, `apt_check_lock`, `supervision/zabbix/config/read`,
`supervision/zabbix/backups`, `wazuh/detect`, `ssh-audit/backups`, `services/list`, `services/status`,
`services/logs` → **lectures confirmées.**

**⚠ Et la sonde du Lead a produit un faux positif, dans le sens qui ALARME** : elle a signalé
`supervision/zabbix/version` comme mutante (`apt-get install`, `systemctl restart`). **Faux** — `version_cmd`
(`supervision.py:138-144`) fait `command -v zabbix_agent2 && zabbix_agent2 -V | head -1`, une lecture pure. Les
motifs venaient d'`install_cmd` et `uninstall_cmd`, **dans le même bloc `AGENT_REGISTRY`** que la plage de la
sonde englobait.

*Levé en lisant le corps.* **Septième occurrence de « une sonde écrite pour accuser se trompe du côté qui
alarme »** — et la troisième fois que c'est celle du Lead.

### ⚠ Deux entrées de diagnostic mesurent RIEN et paraissent VERTES

    health_check.php appelle  /ssh_audit/scan    et  /ssh_audit/config     (tiret bas)
    le backend enregistre     /ssh-audit/scan    et  /ssh-audit/config     (TRAIT D'UNION)

**Les deux chemins appelés n'existent pas** — vérifié, aucun `@bp.route` ne les porte.

**Et le Lead a d'abord écrit que « le 404 s'affiche en vert ». Faux, mesuré** — il faut distinguer deux
choses dans ce fichier :

    health_check.php:45   return [$code >= 200 && $code < 500, …]   <- le VERDICT : un 404 compte comme REUSSI
    health_check.php:351  $r['code'] >= 200 && < 400 ? green : yellow  <- la COULEUR : un 404 s'affiche JAUNE

**Donc la ligne est jaune, et l'entrée compte quand même comme passante.** *La couleur et le verdict ne
viennent pas de la même condition* — un lecteur voit un avertissement, l'agrégat voit une réussite.

> **Deux entrées de la page de diagnostic n'ont jamais rien diagnostiqué. Le jaune le suggérait ; le verdict
> le niait.** Même famille que le « LOT conforme » sur zéro exécution : *un verdict de réussite sur une mesure
> qui n'a pas eu lieu est un silence, pas un verdict* — et **un jaune noyé parmi les jaunes légitimes** (tous
> les `$mutId = 0` rendent 404 par conception) **ne se distingue pas.** C'est ce qui l'a rendu invisible :
> *le signal existait, il était indiscernable du bruit voulu.*

**À corriger avec la cible** (ci-dessous) : ce sont les deux seules entrées du fichier dont le chemin est
faux, et elles sont vertes depuis leur écriture.

### La proposition de cible, et pourquoi ce n'est pas « id 2 »

**La question du Lead mélangeait deux outils.** `health_check.php` diagnostique **le portail** — il affiche un
code HTTP et une durée, et *une réponse « machine introuvable » y est VERTE*, c'est déjà le principe de
`$mutId = 0`. **Il ne rend aucun verdict sur l'état d'un serveur ; diagnostiquer le parc est un autre outil.**

    HEALTH_CHECK_MACHINE_ID=      (vide -> 0)

1. **vide vaut 0** — le repli déjà éprouvé dans ce fichier : aucune machine jointe, page fonctionnelle, **et
   aucune valeur par défaut ne désigne une victime** ;
2. **viser la production redevient une DÉCISION** — écrire `1` et l'assumer. *Un diagnostic peut viser la
   production ; ça doit être une décision, pas un accident de `LIMIT 1`* ;
3. c'est le motif du produit — 80 variables dans `srv-docker.env.example`, récupérées automatiquement.

**Trois options écartées avec leur raison** : `WHERE environment <> 'PROD'` — la colonne existe et est juste
aujourd'hui, mais **une machine ajoutée sans étiquette deviendrait la cible en silence** ; *une étiquette
d'inventaire n'est pas un garde-fou*, même raison qu'E-224. `2` en dur — marche ici et nulle part ailleurs.
`ORDER BY id DESC` — **déplace l'accident sans le supprimer.**

**La valeur par défaut est le seul vrai arbitrage : elle est à l'exploitant** (§7).

---

## E-229 — Elles sont VINGT-ET-UNE, et la vingt-et-unième vient d'être créée par un correctif du chantier

**Le classificateur de la session 6 rejoué sur l'arbre actuel donne 21, non 20.** L'écart est
**`/sshd_allow_user`**, qui rendait `'success': True` **en dur** et rend `'success': atteste` **depuis le
correctif d'E-214 du même soir.**

> **Le chantier a ajouté une route à cette famille — et la session 6 l'avait annoncé quelques heures plus
> tôt** : *« quand tu fais rendre 200 + success:false à une route qui rendait toujours true, tu changes un
> contrat. »*

**Deux mesures justes qui divergent parce qu'elles datent de deux moments.** *Une liste de routes n'est pas une
donnée : c'est une photographie, et le chantier la périme lui-même.* C'est la troisième liste figée à rancir en
deux jours — et la seule dont la péremption ait été **prédite avant de se produire.**

### Vingt sur vingt-et-une sont ATTEIGNABLES

`rc == 0` (**8**) · `all_ok` (**4**) · `ok == len(results)` (**2**) · `deleted > 0` (**2**) · le reste.

### Et la vingt-et-unième est inatteignable PAR UN DÉFAUT

**`/wazuh/install_all` ne rend jamais son `jsonify`** : `AND a.id IS NULL`, aucun `try`, donc **500 avant le
verdict** (E-224).

> **Elle redeviendra atteignable au moment exact où E-224 sera corrigé.**

**Argument de plus pour la borne `machine_ids`** : le correctif d'E-224 n'ouvre pas seulement une route de parc
vers la production — **il ouvre aussi un verdict que personne n'a jamais vu se produire.** *Troisième
occurrence de « un défaut qui protège par accident cesse de protéger quand on le corrige », et la première où
elle se cumule avec une autre.*

### Une note donnée comme une note

`/fail2ban/install` fait `success = rc == 0 or 'is already the newest version' in out`, et **sa commande ne
pose pas `LC_ALL`** alors que ses homologues d'`updates.py` posent `LC_ALL=C.UTF-8`. **Ce n'est pas un défaut
aujourd'hui** : `apt-get install -y` rend `rc = 0` quand le paquet est déjà là, donc le premier terme couvre le
cas et la sous-chaîne est **redondante**. *Ce qui mérite signalement est l'incohérence avec les commandes
voisines* — et une sous-chaîne redondante devient décisive le jour où le premier terme change.

---

## E-230 — ⚠⚠ Les pages acceptent une permission TEMPORAIRE, le backend ne la voit pas — et `/deploy` avait REFUSÉ `@require_permission` pour cette raison exacte

**Trouvé par le DSI en instruisant E-221. C'est ce que le redémarrage casse vraiment — et ce n'est pas ce que
le Lead avait annoncé.**

    legacy/auth/verify.php:333          SELECT 1 FROM temporary_permissions …   -> la page ACCEPTE
    laravel/app/Services/Permissions.php:155,174                                -> le portage ACCEPTE
    backend/scheduler.py:400,787,792    la PURGE et la notifie                  -> jamais pour AUTORISER

**Le backend ne consulte `temporary_permissions` sur aucun chemin d'autorisation.** Il lit
`X-User-Permissions`, que la passerelle remplit depuis la session — **les permanentes seules.**

> **Après le redémarrage, un porteur de permission temporaire ouvre la page et prend 403 sur les 18 routes :
> page affichée, tous les boutons en échec, et rien à l'écran qui l'explique.**

### ⚠ Et l'auteur de `/deploy` avait refusé ce durcissement POUR CETTE RAISON, en l'écrivant

    ssh.py:422-431
    ══ POURQUOI `role(2)` ET PAS `@require_permission('can_deploy_keys')` ═══
    La permission serait le miroir exact de la page — et elle CASSERAIT un chemin legitime.
    La page accepte les permissions TEMPORAIRES (`checkPermissionFromDB` interroge
    `temporary_permissions`), tandis que le backend lit `X-User-Permissions`, que la
    passerelle remplit depuis la session, c'est-a-dire les PERMANENTES seules. Un compte
    dont la permission est temporaire passerait la page et serait refuse ici.
    `role(2)` ferme l'ecart mesure sans rencontrer ce probleme.

> **Les 33 routes d'E-149 et E-152 reproduisent exactement ce que l'auteur de `/deploy` a refusé de créer, et
> il avait écrit pourquoi.**

*Une réserve écrite dans le code n'est lue que par qui ouvre ce fichier* — et les correctifs d'E-149/E-152 ont
été posés dans d'autres fichiers, par d'autres sessions, sans jamais croiser ce commentaire. **C'est le
symétrique du motif que ce chantier suit depuis deux jours** : là, un texte affirmait plus que le code ; ici,
**un texte savait plus que le chantier**, et personne ne l'a lu.

**Porteur aujourd'hui : AUCUN** — `temporary_permissions` est **vide**. L'écart est donc **réel et sans
porteur**, comme E-205 et E-217, et il s'ouvre à la **première permission temporaire accordée** — un geste
d'administration ordinaire.

### La correction n'est pas de retirer les gardes

Les 33 routes ferment un écart page/route mesuré (E-149, E-152). **Le défaut est que la passerelle ne
transmette pas les permissions temporaires**, pas que les routes les exigent. Deux issues :

1. **la passerelle inclut les temporaires dans `X-User-Permissions`** — aligne les trois couches, et rend
   `@require_permission` équivalent à ce que la page décide déjà ;
2. **les routes gardent `role(2)`** comme `/deploy` — ferme l'écart sans rencontrer le problème, au prix d'une
   granularité perdue.

**La première est la bonne**, et sa raison est celle du §8 : *un drapeau de moins vaut mieux qu'une règle en
double* — ici, **une source de moins vaut mieux que trois lectures qui divergent.** Arbitrage de l'exploitant :
la passerelle est le chemin d'authentification.

---

## E-231 — ⚠ La spécification d'API porte les DEUX orthographes du même module, dont sept fausses — et elle se taît sur 64 routes

**Mesuré par la session 3 avant de porter `api_docs`. Vérifié par le Lead.** Le module fait **40 lignes de
coquille Swagger** plus **un YAML statique de 91 Ko daté du 2026-08-20** — et **rien ne le tient en phase.**

    chemins declares dans la spec : 146        routes reelles du backend : 203
    apres NORMALISATION des parametres de chemin :
      documentes ET reels     : 139
      documentes INEXISTANTS  :   7
      reels NON documentes    :  64

### Les sept fantômes ont tous le même motif, et la spec porte les DEUX orthographes

    la spec declare  /ssh_audit/config  /ssh_audit/fix  /ssh_audit/fleet  /ssh_audit/history
                     /ssh_audit/policies  /ssh_audit/scan  /ssh_audit/scan_all      (souligne)
    la spec declare AUSSI  /ssh-audit/backups  /ssh-audit/fleet  /ssh-audit/reload
                           /ssh-audit/restore  /ssh-audit/save-config  …            (tiret)
    le backend ne sert QUE le tiret — 14 routes, dont `/ssh-audit/results` que la spec ignore

**`/ssh_audit/fleet` et `/ssh-audit/fleet` sont tous deux déclarés : la même route, deux orthographes, une
fausse.** Et **`/ssh_audit/history` n'existe sous aucun séparateur.**

> **Qui lit cette documentation ne peut pas savoir quelle moitié est réelle.** Dix routes du module y sont
> justes, sept rendent 404, et rien ne les distingue.

### ⚠ La première mesure annonçait 22 fantômes — trois fois trop

**Elle comparait `{id}` d'OpenAPI à `<int:id>` de Flask : deux notations pour la même chose.** La normalisation
a divisé les fantômes par **trois** et les non-documentés de 79 à 64.

*Huitième occurrence de « une sonde écrite pour accuser se trompe du côté qui alarme »* — et la session l'a
levée elle-même avant de transmettre. **C'est la seule de la journée où le faux positif n'a pas quitté son
auteur.**

### La question n'est pas COMMENT porter, c'est QUOI porter

**Servir ce YAML dans le nouveau portail y installe un document qui se trompe sur les chemins d'un module
entier et se taît sur 64 routes — et c'est un document qui AFFIRME DES AUTORISATIONS.** Cinquième forme du
motif de ce chantier, la plus grave : *celle qui trompe pendant un incident.*

**✅ DÉCISION DU LEAD : DÉRIVER, et non porter le YAML.** Trois raisons, dans l'ordre de poids :

1. **ce n'est pas une incohérence de l'original, c'est un CACHE PÉRIMÉ.** La règle du chantier — *un portage
   fidèle ne peut pas trancher une incohérence de l'original : il la reproduit et la nomme* — **ne s'applique
   pas** : reproduire un artefact figé que rien ne régénère n'est pas de la fidélité à un comportement, **c'est
   recopier un cache** ;
2. **l'exploitant a demandé la dépréciation COMPLÈTE du legacy.** Un YAML daté du 2026-08-20 porté dans la 2.0
   serait *un artefact legacy survivant à l'intérieur du nouveau portail* — exactement ce qu'on retire ;
3. **+33 routes ont gagné une garde en deux jours.** Aucun document figé ne peut suivre ce rythme ; **seul un
   document dérivé peut.**

### La forme retenue : TROIS énoncés distincts plutôt qu'un seul faux

| ce que la page dit | d'où ça vient | régime |
|---|---|---|
| ce que **la passerelle** autorise | `RoutesBackend::LISTE_BLANCHE` et `ADMIN_SEULEMENT` — **dérivé** | toujours juste |
| ce que le **relevé** dit des décorateurs | `RELEVE-GARDES-BACKEND.md` | **daté**, et son régime nommé : *arbre de travail, pas service* |
| **là où les deux divergent** | la comparaison | le plus utile des trois |

**⚠ Trois bornes, et la première n'était pas dans la proposition :**

1. **chaque énoncé NOMME SA COUCHE.** Dériver depuis `RoutesBackend` dit ce que **la passerelle laisse
   passer**, pas ce que **le backend accepte** — et E-230 vient de montrer **trois couches qui divergent** sur
   la même question. *Une page qui mélange les trois refait le défaut qu'elle documente* ;
2. **les 64 routes non documentées sont COMPTÉES ET NOMMÉES comme telles.** Sinon la page dérivée **hérite du
   silence du YAML** : *un document qui omet ce qu'il ne sait pas est plus trompeur qu'un document daté* ;
3. **la page ne se présente pas comme une référence d'API.** Elle dérive des **autorisations**, pas des
   contrats. *Un titre qui promet plus que le contenu est la même faute, un étage plus haut.*

### Un écart mineur du même fichier, à ne pas recopier

    legacy/api/docs.php:4   « Accessible uniquement aux admins et superadmins »
    legacy/api/docs.php:9   checkAuth([ROLE_SUPERADMIN])

**Le commentaire promet un accès PLUS LARGE que le code** — direction inverse d'E-36 et de `platform_keys`.
Aucune conséquence de sûreté ; **à ne pas transporter dans le portage.**

### Et une fausse alerte levée par son auteur, qui mérite d'être dite

`documentation.php:1743` embarque une console appelant un point d'accès **arbitraire**
(`fetch('/api_proxy.php' + endpoint)`) sur une page ouverte aux **trois** rôles. **Soupçon légitime, et faux** :
elle est dans un `if ($isAdmin)` avec `$isAdmin = $role >= 2` (`:16`). **Le rôle 1 ne la voit pas.**

*La règle qui a arrêté l'accusation est celle de la journée : lire la fonction qui décide avant de conclure.*
**Et le dire compte** — c'est la troisième fausse alerte de la journée levée par son auteur avant transmission.

---

## E-232 — Archiver `legacy/api/` retire la SEULE référence d'API du produit, et la page dérivée ne la remplace pas

**Conséquence directe de la décision E-231, et il faut la dire avant l'archivage, pas après.**

`api_docs` est **basculé** — `Navigation.php:133`, `'route' => 'autorisations-passerelle'`. Le menu passe donc
à **26 portées / 6 restantes.** Et la page dérivée tient les trois bornes du Lead, **y compris celle qui la
disqualifie comme référence** :

    laravel/lang/fr/autorisations.php   'pas_reference_titre' · 'pas_reference_texte'
                                       -> annonce AVANT son contenu qu'elle n'est pas une reference d'API

> **C'est exactement ce qui a été demandé, et c'est exactement pourquoi elle ne remplace pas ce qu'on
> archive.** Elle décrit **des autorisations**, pas des **contrats** : ni schémas de requête, ni codes de
> réponse, ni exemples.

### Ce que `legacy/api/` contient, et ce qui disparaît

    docs.php  ·  openapi.php  ·  openapi.yaml (92 Ko)  ·  swagger/

**En l'archivant, le produit n'a plus de référence d'API du tout.** *Re-siter une capacité et la retirer se
ressemblent dans un journal de commits ; elles ne se ressemblent pas pour l'utilisateur* — et ici c'est bien un
**retrait**, assumé.

### L'argument qui le rend défendable, et sa limite

**Le YAML était faux à 32 %** : 7 chemins fantômes, **64 routes sur 203 non documentées**, et **les deux
orthographes du même module**. *Une référence fausse à ce point n'est pas une référence : c'est un piège daté.*
**Mais « le remplacement était faux » ne rend pas « aucun remplacement » suffisant.**

### ⚠ ARBITRAGE — délégable, et il appartient au DSI

**Trois issues, aucune ne détruit :**

1. **accepter le retrait** — le produit n'expose plus de référence d'API. Cohérent avec la dépréciation
   complète du legacy, **et à écrire dans `DEPRECIATION.md` comme une capacité RETIRÉE**, jamais comme une
   capacité portée ;
2. **régénérer une spécification DEPUIS les routes** — le même geste que la page dérivée, appliqué au catalogue
   au lieu des autorisations. *Ce qui a rendu le YAML faux est qu'il était figé ; un catalogue dérivé ne peut
   pas l'être.* Coût réel, et **c'est la seule issue qui rende au produit ce qu'il perd** ;
3. **garder `legacy/api/` hors archivage** jusqu'à la régénération — *le legacy survit sur ce seul point*, ce
   qui contredit l'instruction de l'exploitant.

**Recommandation du Lead : la 2.** Le mécanisme est déjà écrit et éprouvé deux fois aujourd'hui — les douze
tuiles dérivées du menu, et cette page dérivée de la liste blanche. *Dériver un catalogue de routes est le même
geste, sur une autre source.*

### ⚠ Et l'archivage ne peut pas partir avant cette décision

`legacy/api/` porte **quatre** fichiers et un dossier `swagger/`. Le cycle du §4.4 s'applique — **neuf étapes**,
dont la **huitième** (liens entrants, quatre natures) et la **neuvième** (clés de conseil, comptées zéro
compris). **Mais l'étape zéro est celle-ci** : *savoir si l'on archive une capacité portée ou une capacité
retirée change ce qu'on écrit dans `DEPRECIATION.md`* — et ce registre est le seul endroit où la différence
restera lisible dans six mois.

---

## E-233 — Le proxy legacy autorise par ESPACE DE NOMS : la majorité des routes qu'il laisse passer n'y est jamais nommée

**Relevé par le DSI (9e décision, `e438000`). Mesuré indépendamment par le Lead à 14:18 CEST — et les deux
chiffres diffèrent, ce qui est en soi le résultat.**

### Ma mesure, avec sa méthode

    prefixes du proxy         : 63   (50 nommes, 13 ESPACES DE NOMS finissant par `/`)
    routes backend            : 203
    atteignables par le proxy : 171
      dont NOMMEES explicitement            :  48
      dont par ESPACE DE NOMS, jamais nommees : **123**
    non atteignables          :  32

**Commande** : normalisation des paramètres de chemin (`<int:id>` → `{x}`), correspondance **exacte** pour les
préfixes nommés, `startswith` pour les espaces de noms. *Sans la normalisation, un `<int:id>` ne correspond à
aucun préfixe littéral et le compte s'effondre — c'est le piège que la spec d'API a déjà payé (E-231).*

### ✅ RÉCONCILIÉ (2026-08-28, 15:0x CEST) — TROIS LECTURES, ET LA MIENNE ÉTAIT FAUSSE SUR SES PROPRES TERMES

    la regle du PHP, telle qu'ecrite (api_proxy.php:154-156)
        if ($path === $prefix || strpos($path, $prefix) === 0)

    A  ce que le PHP FAIT           (startswith sur les 63)                    **199**
    B  ce que la liste SEMBLE dire  (exact sur 48 nommes, startswith sur 15 NS) **191**
    C  la lecture du Lead                                                       171   <- FAUSSE
    ---------------------------------------------------------------------------------
    surface d'ACCIDENT (A - B)                                                    **8**

**Mon `171` n'était pas « une autre question » : c'était B, mal exécutée.** J'ai détecté les espaces de noms
par **`endswith('/')` seul — 13 au lieu de 15** — et manqué **`/cve_`** et **`/iptables-`**, qui en sont, avec
un `_` et un `-` pour séparateur. **Les 20 routes d'écart sont exactement celles-là.**

> **Même classe de faute que les deux orthographes de la spec d'API et que « on compare des segments, pas des
> sous-chaînes » : une hypothèse sur la FORME du séparateur.** *Une sonde qui suppose un séparateur ne mesure
> que ce séparateur* — et j'ai signé cette règle trois fois aujourd'hui avant de la commettre.

**Le `151` du DSI est reproduit** et il répond bien à *« combien le proxy laisse-t-il passer sans les
nommer »* — `199 − 48`.

### ⚠⚠ ET LA MESURE QUI MANQUAIT RENVERSE LA LECTURE

**Les huit routes de la surface d'accident, nommées :**

    /approvals/stats · /approvals/{x}/approve · /approvals/{x}/reject
    /chatops/users/{x}/{x} · /command_log/contexts
    /groups/{x} · /groups/{x}/members · /groups/{x}/run

> **Ce sont TOUTES des sous-chemins légitimes de la ressource nommée.** `/approvals` couvrant
> `/approvals/stats` est le comportement qu'on attend d'un préfixe de ressource. **Il n'existe aujourd'hui
> AUCUNE collision accidentelle de type `/search` → `/searchall`.**

**Donc le 151 est dominé par les 15 espaces de noms, qui sont DÉLIBÉRÉS.** Le DSI l'écrit contre lui-même :
*« j'ai publié l'agrégat sans séparer les deux populations, et l'agrégat vaut vingt fois la population qui
inquiète. C'est la sonde écrite pour accuser — celle que je reproche depuis ce matin — appliquée à ma propre
décision. »*

**Sa phrase « une route nouvelle devient atteignable sans que personne ne l'ait décidé » reste vraie comme
MÉCANISME et fausse comme AMPLEUR : zéro occurrence.**

*Un agrégat qui mélange une population délibérée et une population accidentelle mesure la première et alarme
sur la seconde.* **La mesure qui décide n'était ni 151 ni 171 : c'était 8, puis leur lecture.**

### Et ce qui reste NON expliqué est dit comme tel

Le DSI ne sait pas d'où venait mon 171 — *« je le dis plutôt que de fabriquer une explication : j'ai failli
publier que ta sonde n'appliquait pas `startswith` aux préfixes nommés, et la mesure a montré que
`/admin/backups` passe par `/admin/`, un espace de noms. Mon hypothèse était fausse. »*

**Elle l'était, et la vraie cause est celle mesurée ci-dessus.** *Deux chiffres réconciliés sur le point qui
décide valent mieux qu'une explication inventée pour le reste* — et refuser d'inventer a laissé la place à la
mesure qui a trouvé.

### ~~Le DSI compte 151, le Lead 123~~ — conservé pour la trace

**L'écart de 28 est probablement dans la définition de « nommée »** : ma correspondance exacte sur chemin
normalisé classe comme *nommée* une route qu'une correspondance par préfixe classerait comme *couverte par un
espace de noms*.

> **Les deux chiffres répondent à deux questions distinctes** — *« combien de routes le proxy laisse-t-il passer
> sans les nommer ? »* et *« combien de routes ne figurent-elles nulle part dans sa liste ? »* **Aucune des deux
> n'est fausse ; une seule répond à la question qu'on se pose.**

*Le Lead ne reprend donc pas le 151, et n'impose pas son 123* — **à réconcilier par celui qui a écrit la
décision, avec sa méthode explicite.** C'est la règle du jour appliquée à un chiffre : *un fait sans sa commande
est une opinion sur une méthode.*

### ✅ Et la décision de NE PAS resserrer est la bonne

**Le Lead la confirme, pour une raison que la mesure rend nette** : `api_proxy.php` est **le proxy du legacy**.
Il **meurt d'un bloc, avec le legacy** — c'est ce qui est écrit pour les onze parties déjà archivées, dont les
entrées de liste blanche sont devenues **surface morte** et ont été **laissées en place** : *on ne soigne pas ce
qu'on démonte.*

**Resserrer les 13 espaces de noms en 123 lignes nommées** coûterait un travail réel **sur un fichier dont la
disparition est programmée**, et **chaque ligne ajoutée serait une occasion de casser un chemin vivant** —
*treize `startswith` qui marchent contre 123 égalités dont une seule mal écrite coupe une page.*

**La borne qui compte est ailleurs, et elle existe** : la passerelle du **portage** (`RoutesBackend`) est
énumérée, et c'est elle qui survivra. *Durcir le chemin qu'on garde vaut mieux que durcir celui qu'on retire.*

### Ce qui reste vrai et doit être dit

**171 routes sur 203 sont atteignables par le proxy legacy aujourd'hui**, et **123 le sont sans figurer
nommément dans sa liste.** *Une liste blanche qui autorise par préfixe n'est pas une liste blanche : c'est une
liste de familles*, et personne ne peut dire de mémoire ce qu'elle contient. **C'est mesurable, ce n'est pas
resserré, et la raison est écrite** — la triade que ce chantier demande à chaque écart sans porteur.

## E-234 — `documentation.php` porte une CONSOLE D'API : la page dont le nom promet qu'elle ne fait rien est un client HTTP generique vers la passerelle

**Mesure du 2026-08-28, 15:50 CEST.** Releve par la session 2, verifie par le Lead
(`sed -n '11p;16p;1719,1724p;1741,1745p' legacy/documentation.php`).

`legacy/documentation.php` (1756 lignes, **aucun JS separe** : tout est en ligne) n'est pas une
page statique. Son unique appel sortant reel est **arbitraire** :

    :1624   <input type="text" id="api-endpoint" value="/cve_test_connection">   CHAMP LIBRE
    :1629   <select id="api-method">                                            GET / POST
    :1636   <textarea id="api-payload">                                         corps JSON libre
    :1743   fetch('/api_proxy.php' + endpoint, options)

**Controle d'acces EFFECTIF :**

    :11   checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])   -- et AUCUN checkPermission
    :16   $isAdmin = $role >= 2
    :1721 <?php if ($isAdmin): ?>                               -- la console

> **Tout compte de role >= 2 obtient un client HTTP generique vers la passerelle, sans
> qu'aucune permission ne soit exigee.**

### Ce que ce n'est PAS, et il faut le dire aussi nettement

**Ce n'est pas une escalade de privilege.** Le proxy applique sa liste blanche et
`$ADMIN_ONLY_PREFIXES` — que le role 2 franchit de toute facon — et le backend applique ses
decorateurs. **Un role 2 n'atteint par la console rien qu'il n'atteindrait par les pages.**

### Ce que c'est : le contournement de l'INTERFACE, pas des gardes

### ⚠ MA PREMIERE LISTE ETAIT FAUSSE SUR DEUX ENTREES ET MANQUAIT LES TROIS QUI COMPTENT

**Rectification du 2026-08-28 16:00 CEST**, apres mesure route par route (role, permission,
`gate()`, liste blanche du proxy) — la premiere version de cet ecart, ecrite dix minutes plus
tot, annoncait `/regenerate_platform_key` et un `install_all` « de parc par construction ».
**La session 5 m'a contredit, et elle avait mesure.**

    /regenerate_platform_key   role=3  gate=OUI   ->  HORS D'ATTEINTE d'un role 2
    /wazuh/install_all         machine_ids OBLIGATOIRE, corps vide -> 400
    /cve_scan_all              ABSENT de $ALLOWED_PROXY_PREFIXES  ->  le proxy BLOQUE

**Les trois faux dedouanent, et je les avais ecrits comme aggravants.** Pire : `install_all`
est borne **par un correctif que j'ai numerote moi-meme, E-224** — j'ai repete « de parc »
apres deux sessions sans relire la borne que j'avais inscrite. *Trois lecteurs d'accord ne
valent pas une mesure ; c'est la quatrieme session, seule contre trois, qui avait raison.*

### CE QUE LA CONSOLE ATTEINT REELLEMENT — mesure, role 2

`$ADMIN_ONLY_PREFIXES` (25 entrees) ne borne que les roles < 2 : **pour le public de la
console, seule la liste blanche compte**, puis les decorateurs du backend.

| route | role | permission backend | atteignable par la console |
|---|---|---|---|
| **`POST /ssh-audit/scan-all`** | 2 | **AUCUNE** | **OUI** — SSH sur toute la flotte |
| **`POST /docker/scan_all`** | 2 | **AUCUNE** | **OUI** |
| `POST /wazuh/install_all` | 2 | `can_manage_wazuh` | oui, avec la permission — et `machine_ids` obligatoire |
| `POST /groups/<id>/run` | 2 | `can_admin_portal` | oui — **3 effets sortants PAR MACHINE** |
| `POST /fail2ban/install_all` | 2 | `can_manage_fail2ban` | oui |
| `POST /supervision/scan-all` | 2 | `can_manage_supervision` | oui |
| `POST /drift/scan_all` | 2 | `can_view_compliance` | oui |
| `POST /cve_scan_all` | 2 | — | **non** : hors liste blanche |
| `POST /regenerate_platform_key` | **3** | — + **`gate()`** | **non** |

> **Le fait le plus net n'etait pas dans ma premiere liste : `POST /ssh-audit/scan-all` ouvre
> une session SSH sur toute la flotte, en role 2, SANS AUCUNE PERMISSION, dans la liste
> blanche, hors `ADMIN_ONLY`, sans porte d'approbation** — et depuis la console, **sans panneau,
> sans nom de machine, sans compte annonce.** C'est la route dont la consigne permanente du
> chantier dit « ne jamais lancer `go-ssh-audit-scanall.mjs` ». `/docker/scan_all` est dans le
> meme cas.

Et **`/cve_scan_all` est bloque par la liste blanche** : la console **n'envoie donc pas** de
courriel. C'est un dedouanement, et il compte autant que le reste — l'effet sortant de S7b
n'est pas joignable par la.

**Aucun panneau de decision, aucun nom de machine, aucun compte annonce** — alors que chacune
de ces pages en porte un, et que ce chantier a passe des semaines a les poser.

> **C'est l'inverse du motif habituel du depot.** D'ordinaire la garde est sur la PAGE et pas
> sur la REQUETE — six occurrences numerotees. **Ici les gardes de requete tiennent toutes, et
> c'est tout ce que l'interface AJOUTE qui manque.** Un panneau de confirmation n'est pas une
> garde ; il n'en est pas moins la seule chose qui empeche un geste de masse d'etre involontaire.

### Consequence directe sur la depreciation du legacy

Tant que `documentation.php` est servi, cette console est joignable par **tout** compte de
role >= 2 **sans permission**. *L'argument le plus fort pour finir la depreciation ne se
trouvait pas dans le plan : il est sur la page dont le nom promet qu'elle ne fait rien.*

### Arbitrage EXPLOITANT — la console se porte-t-elle ?

Ce n'est pas un detail de fidelite : **c'est la seule capacite vivante de la page.** Trois
issues, aucune neutre : la porter telle quelle (fidelite stricte, on reconduit le
contournement) · la porter derriere `role:3` + une permission dediee + un panneau (divergence
declaree, comme `/supervision/`) · ne pas la porter (perte de capacite assumee, a inscrire).

## E-235 — `/wazuh/` passe la passerelle pour un role 1 : un rempart manquant sur deux, et le precedent `/supervision/` a deja tranche dans l'autre sens

**Mesure du 2026-08-28, 15:52 CEST.** Releve par la session 6, **verifie par le Lead avec un
analyseur independant** — un automate qui distingue chaine, commentaire de ligne et commentaire
de bloc, parce qu'un `grep` sur ce fichier rend l'INVERSE de la verite (les apostrophes des
commentaires francais, `n'a`, `l'un`, ouvrent de fausses chaines et la premiere extraction de
la session 6 declarait `/wazuh/` **et** `/groups` hors liste blanche).

    LISTE_BLANCHE      66 entrees   wazuh=['/wazuh/']   groups=['/groups']
    ADMIN_SEULEMENT    27 entrees   wazuh=-             groups=['/groups']

**`/wazuh/` est dans la liste blanche et ABSENT de `ADMIN_SEULEMENT`.** Un role 1 porteur de
`can_manage_wazuh` atteint donc `/api/gateway/wazuh/install_all` : **la passerelle transmet.**

**Le backend refuse** — les 15 routes portent `@require_api_key` + `@require_role(2)` +
`@require_permission('can_manage_wazuh')`, le module le plus uniformement garde du chantier.
**C'est donc un rempart manquant sur deux, pas un trou.** Il faut le dire dans les deux sens :
rien n'est joignable aujourd'hui, et il ne reste qu'une barriere.

**Le precedent existe et il a tranche dans l'autre sens** : `/supervision/` a ete AJOUTE a
`ADMIN_SEULEMENT` alors que le legacy ne l'y avait pas, divergence declaree, *parce qu'on ne
depend jamais d'un seul rempart*. **`/wazuh/` merite le meme traitement, et pour une raison
plus forte : `install_all` installe un paquet sur un parc entier.**

`laravel/app/Support/RoutesBackend.php` est le fichier de la session 3. Divergence a declarer,
non a decider seul.

### Et la faute d'instrument vaut d'etre inscrite pour elle-meme

La session 6 a signale que sa premiere mesure rendait l'inverse, et **c'est ce signalement qui
a permis de la verifier.** *Un releve qui s'annonce comme redresse se controle ; un releve
silencieux se croit.* Sans son controle de vraisemblance sur quatre entrees connues, le
chantier aurait recu un ecart imaginaire sur `/groups` et manque le vrai sur `/wazuh/`.

## E-235b — l'ecart etait sur TROIS espaces, pas un : `/ssh-audit/`, `/docker/`, `/fail2ban/` — et `/wazuh/` est deja ferme

**Mesure du 2026-08-28, 16:10 CEST.** La session 6 a demande d'elargir E-235, avec le bon
motif : *un defaut a moitie corrige revient par la branche jumelle.* **Elle avait raison
d'elargir, et l'ensemble n'est pas celui qu'elle nommait.**

    espace          LISTE_BLANCHE   ADMIN_SEULEMENT
    /wazuh/         OUI             OUI            <- FERME entre-temps (eb0b6f7, 15:58)
    /ssh-audit/     OUI             non            <- rempart manquant
    /docker/        OUI             non            <- rempart manquant
    /fail2ban/      OUI             non            <- rempart manquant
    /supervision/   OUI             OUI
    /groups         OUI             OUI
    /drift/         OUI             OUI

**Deux corrections a la demande :** `/wazuh/` etait deja corrige par la session 3 douze minutes
avant qu'elle ecrive — l'ecart s'est ferme pendant qu'on en parlait ; et **`/fail2ban/`, qu'elle
n'a pas nomme, est le troisieme.** *Une demande d'elargissement se remesure comme une
accusation : elle peut viser trop peu.*

### Et le contraste des gardes est une CONCEPTION, pas un oubli

Verifie decorateur par decorateur, parce qu'une premiere sonde annoncait « aucun role » sur
trois routes et que c'etait sa fenetre de lecture, pas le code :

    /ssh-audit/scan       une machine   @require_machine_access   (mord pour un role 1)
    /ssh-audit/scan-all   tout le parc  @require_role(2)          AUCUNE permission
    /docker/scan          une machine   @require_machine_access
    /docker/scan_all      tout le parc  @require_role(2)          AUCUNE permission
    /fail2ban/install_all tout le parc  @require_role(2) + can_manage_fail2ban

> **Les routes a UNE machine se gardent par machine ; celles de PARC se gardent par role.**
> C'est coherent — le role 2 *est* la portee du parc dans ce depot — et les sessions 4 et 5 le
> concluent independamment. **Ce n'est pas un defaut.**

**Mais c'est ce qui rend le rempart manquant consequent.** Un role 1 passe la passerelle vers
`/ssh-audit/scan-all` ; arrive au backend, il n'y a **pas** de `@require_machine_access` pour le
rattraper sur la variante de parc — seulement `@require_role(2)`. **Une seule barriere, et sur
`/ssh-audit/scan-all` comme `/docker/scan_all` il n'y a meme aucune permission derriere.**

`/ssh-audit/scan-all` est le pire cas des trois : SSH sur toute la flotte, **role 2 sans aucune
permission**, et c'est la route dont la consigne permanente du chantier dit « ne jamais lancer
`go-ssh-audit-scanall.mjs` ».

### Le geste, en une fois et non en trois

Ajouter les **trois** espaces a `ADMIN_SEULEMENT`, divergence declaree, precedent `/supervision/`
— *on ne depend jamais d'un seul rempart.* Fichier de la session 3.

## E-236 — `/ssh-audit/scan-all` : un role 2 a qui le portail REFUSE d'afficher le module peut appeler la route la plus dangereuse du chantier

**Releve par la session 4, verifie par le Lead le 2026-08-28 a 16:15 CEST.**

    legacy/ssh-audit/index.php:12   checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])
                              :13   checkPermission('can_audit_ssh')
    Navigation.php:101              'garde' => 'can_audit_ssh'
    /ssh-audit/scan-all             @require_api_key + @require_role(2)   -- AUCUNE permission
    api_proxy.php                   /ssh-audit/ en liste blanche, ABSENT d'ADMIN_ONLY

`can_audit_ssh` **existe** — c'est la permission qu'E-211 vient d'ajouter a `/ssh-audit/policies`.
Il n'y avait donc rien a creer.

### ⚠ CE N'EST PAS « LA ROUTE EST PLUS FAIBLE QUE LA PAGE » — LES DEUX GARDES NE S'ORDONNENT PAS

La page est plus **souple** sur le role (elle admet un role 1) et plus **stricte** sur la
permission. La route est plus **stricte** sur le role et n'a **aucune** permission. Deux
consequences symetriques :

1. un role 1 portant `can_audit_ssh` **passe la page et est refuse par la route** — famille d'E-230 ;
2. **un role 2 SANS `can_audit_ssh` ne peut pas ouvrir la page, et peut appeler la route.**

> **La route que la consigne permanente du chantier designe comme « a ne jamais lancer »
> (`go-ssh-audit-scanall.mjs`) est atteignable par un compte a qui le portail refuse d'afficher
> le module.** SSH sur toute la flotte, sans permission, sans porte d'approbation.

### La forme est NEUVE, et c'est ce qui l'a rendue invisible

Ce chantier a numerote six occurrences de *la garde est sur la PAGE, pas sur la REQUETE*.
**Les six comparaient un seul axe.** Ici la route a l'air **plus stricte** — elle exige un role
superieur — et c'est precisement ce qui l'a dedouanee dans tous les releves precedents.

> **Une garde plus stricte sur un axe peut etre plus permissive sur un autre, et un
> rapprochement qui ne compare qu'un axe conclut a l'envers.**

*Il faut croiser role ET permission, pas les additionner en un « niveau ».*

### Verdict : OUBLI pour `ssh-audit`, CONCEPTION pour `docker`

La session 4 separe les deux cas, et la separation tient a une mesure :

- **`/docker/scan_all`** — role 2 sans permission, **et aucune colonne `can_manage_docker`
  n'existe** : il n'y a rien a exiger. Le voisin immediat le prouve — `/graylog`, deux lignes
  plus haut dans `web.php`, porte `['role:2', 'perm:can_manage_graylog']`. **L'auteur a decide
  par module**, il a mis une permission la ou elle existe. **Rien a corriger** ;
- **`/ssh-audit/scan-all`** — `can_audit_ssh` existe et est exigee ailleurs dans le meme module.
  C'est un oubli.

*Deux routes au meme releve brut — role 2, aucune permission — et deux verdicts opposes, que
seule l'existence de la colonne separe. Un tableau de conformite qui ne regarde que les
decorateurs les aurait comptees pareilles.*

### ARBITRAGE, pas un correctif

Aligner la route sur la page demanderait d'**abaisser** son role a 1 tout en **ajoutant** la
permission : elargir un axe pour en resserrer un autre, **sur la route la plus dangereuse du
module**. La session 4 refuse de le proposer comme diff, et elle a raison.

### LA PORTEE EST MESUREE : UN COMPTE, REEL, ACTIF — releve du 2026-08-28 16:50 CEST

Le gel leve, la session 4 a mesure en base ce qui restait inconnu :

    role 3   3 comptes                        ouvrent la page ET appellent la route  (legitime)
    role 2   1 fixture AVEC la permission     ouvre et appelle
    role 2   1 compte REEL sans              **n'ouvre PAS la page, APPELLE la route**  <- l'ecart
    role 1   6 reels + 1 fixture, aucun avec  n'ouvrent pas, n'appellent pas (role 2 exige)

**Verifie : `checkPermissionFromDB` court-circuite au role 3** (`if ($roleId === 3) return true;`),
exactement comme `require_permission` cote backend — les roles 3 ne sont donc pas dans le perimetre.

**Ce n'est ni theorique ni massif : un compte, reel, actif.** C'est le chiffre sur lequel
l'exploitant arbitre.

**Et une borne qui change la gravite, donnee par la session 4** : ce compte est **deja role 2**,
donc `check_machine_access` lui rend `True` sur tout le parc. **Ce qu'il gagne n'est pas un acces a
des machines — c'est une CAPACITE** : lancer l'audit SSH de toute la flotte, la route dont la
consigne permanente dit « ne jamais la lancer ». *Un ecart de capacite, pas de confidentialite.*

## E-237 — `/wazuh/uninstall` : le verdict est corrige, l'ETAT PERSISTE ne l'est pas — et le correctif evident est faux dans l'autre sens

**Releve par la session 5, verifie par le Lead le 2026-08-28 a 16:20 CEST.** La session 4
rapportait « deja corrige, rien a relever » ; la session 5 rapportait un defaut subsistant.
**Les deux ont raison, sur des moities differentes** — et il faut dire laquelle repond a quoi
plutot que de relayer une seule.

**Ce qui EST corrige** (session 4, verifie) : `success` ne vaut plus `code == 0` mais
`paquet_retire`, mesure **par l'effet** en lecture seule (`dpkg-query -W`, puis `rpm -q`), et la
reponse **nomme les vestiges**. Sur RHEL/SUSE la route dit desormais que le paquet est reste.

**Ce qui ne l'est PAS** (session 5, verifie) — l'ordre des lignes :

    :57   _, err_out, code = execute_as_root(client, cmd, …)
    :58   _, _, code_v     = execute_as_root(client, verif_cmd, …)
    :59   _upsert_agent(row['id'], status='never_connected', …)   <- INCONDITIONNEL
          …
          paquet_retire = (code_v == 0)                           <- le verdict vient APRES

**L'inventaire est ecrit avant que le verdict existe, et sans le consulter.** Sur RHEL ou SUSE la
route repond correctement `success: false` **et a deja inscrit « jamais connecte »**. Etat reel :
**paquet installe, `/var/ossec` supprime, inventaire disant qu'il n'y a rien** — faux **dans la
direction qui masque le probleme**, personne n'ira chercher le paquet reste en place.

**C'est E-90 / E-183 a l'identique : le verdict corrige, l'etat persiste laisse.**

### ⚠ ET LE CORRECTIF EVIDENT EST FAUX DANS L'AUTRE SENS

N'ecrire qu'en cas de reussite laisserait l'ancien etat — `active`, avec identifiant et version —
sur une machine dont `/var/ossec` vient d'etre supprime : **un agent mort annonce comme
fonctionnel**, pire pour un exploitant.

### ⚠ RECTIFICATION DU 2026-08-28 16:55 — MA LISTE DE STATUTS ETAIT COURTE D'UN, ET C'EST CELUI QUI RESOUT

J'avais ecrit : *« le vocabulaire n'a pas de mot pour l'etat atteint — `pending`, `active`,
`disconnected`, `never_connected`, aucun ne dit partiellement desinstalle. »* **L'enumeration en
porte CINQ**, releve par la session 4 :

    034_wazuh.sql:48   status ENUM('active','disconnected','never_connected','pending','unknown')

**`unknown` existe, et de bout en bout** : le backend l'ecrit (`wazuh.py:742`), l'interface le rend
en badge gris (`wazuh.js:102`) avec un **repli** pour tout statut non mappe (`:105`), et le libelle
existe.

**Et c'est la valeur juste** : il ne dit pas « partiellement desinstalle », il dit *« je ne sais pas
ce qu'il y a sur cette machine »* — **ce qui est exactement la verite de l'etat atteint.** Mes deux
options **affirmaient** l'une et l'autre quelque chose de faux ; celle-ci **n'affirme rien**.
Ecrire `unknown` apres l'echec de la verification n'echange donc pas un mensonge contre un autre :
c'est la seule des trois ecritures honnete, et **elle ne demande aucune migration.**

> **Le vocabulaire d'un champ, c'est le SCHEMA — pas ce que le code ecrit.** Ma liste de quatre
> venait d'un motif sur les litteraux `status='…'` ; `unknown` est ecrit par une **expression
> conditionnelle** (`'active' if … else ('disconnected' if … else 'unknown')`), qu'aucun motif sur
> une affectation litterale ne peut voir. *C'est la meme famille que `'route' =>` rendant 0 sur un
> fichier qui aligne ses fleches : un motif suppose une forme d'ecriture.*

**Reserve a porter avec le geste** : **il n'existe aucun `laravel/lang/{fr,en}/wazuh.php`** —
verifie, wazuh n'est pas encore porte. Si `unknown` est retenu, le libelle devra exister **au
moment du portage**, sinon l'ecran affichera `wazuh.status_unknown` en clair.

**Ce qui RESTE un arbitrage** : le `purge` `apt`-only, au DOSSIER-04. *Le verdict et le vocabulaire
sont resolus ; le geste distant multi-famille ne l'est pas.*

**Meme forme que `sudoers_orphelin`** : un champ enumere face a une realite qui a gagne un etat
qu'il ne peut pas exprimer. Meme remede : **nommer l'etat AVANT de choisir une valeur.** Tant
qu'il n'a pas de nom, aucune autre route ne peut en tenir compte.

**~~Ne pas deplacer `_upsert_agent` sous une condition tant que l'etat n'a pas de nom.~~** —
*consigne RETIREE : l'etat a un nom, voir la rectification ci-dessus.* Le geste est desormais
disponible et sans migration.

*Et le `purge` reste `apt`-only : le rendre multi-famille est un changement de comportement sur un
geste destructeur distant — c'est au DOSSIER-04 en attente de signature, ou le DSI a scinde E-225.*

## E-235c — l'ensemble derive est 38 espaces, pas 7 : et la parade n'est pas une liste plus longue

**Mesure du 2026-08-28, 16:30 CEST.** Quatre estimations successives du meme ensemble :

    session 6, 1re fois   2 espaces  (/ssh-audit/, /docker/)
    Lead                  3 espaces  (+ /fail2ban/, et /wazuh/ deja ferme)
    session 6, 2e fois    7 espaces
    ensemble DERIVE      38 espaces

**Chaque correction etait une liste plus longue, et chacune etait encore une liste.** La session 6
a nomme la parade avant que je la mesure, et sa formule est la bonne :

> **La parade n'est pas une liste plus longue : c'est de DERIVER l'ensemble. Une liste d'exemples
> se corrige indefiniment ; une enumeration ne se corrige qu'une fois.**

C'est la meme regle que *« compter une structure, c'est la faire lire par son propre
analyseur »* — appliquee non plus a un langage mais a un **ensemble d'objets**.

*Pourquoi les listes montaient : les trois premieres ne voyaient que les prefixes en forme
d'espace de noms — ceux qui finissent par `/`. La liste blanche en compte 66, dont 15 seulement
finissent ainsi ; les autres sont des prefixes en mot nu (`/cve_`, `/iptables-`, `/deploy`,
`/update`). **C'est le meme angle mort que mon 171 sur le proxy legacy, ou `endswith('/')`
trouvait 13 des 15 espaces.***

### Ce que la derivation trouve et qu'aucune liste n'avait

    LISTE_BLANCHE = 66   ADMIN_SEULEMENT = 28   ->  38 espaces sans le rempart

Parmi eux, ceux qui portent des routes gardees par **un role SEUL** — ni permission, ni
`@require_machine_access` :

    /cve_          7 chemins distincts, 11 enregistrements   <- LA PLUS FORTE CONCENTRATION
    /ssh-audit/    7 chemins distincts,  8 enregistrements
    /docker/       1     /cron_preview 1     /logs 1     /update 1     /update-logs 1

**`/cve_` n'etait dans aucune de nos quatre listes**, et c'est la plus fournie :
`cve_scan_all`, `cve_whitelist` (GET/POST), `cve_remediation` (GET/POST), `cve_schedules`
(GET/POST/PUT/DELETE). *Le module dont l'effet sortant est un arbitrage exploitant depuis des
semaines — S7b — est celui dont le plus de routes ne portent qu'un role.*

### Deux precisions qui empechent de conclure trop vite

**`/cve_scan_all` est dedouanee sur UNE passerelle et pas sur l'autre.** J'ai mesure plus haut
qu'elle est **hors** de la liste blanche du proxy **legacy** (`api_proxy.php`) : la console
d'E-234 ne l'atteint pas. Elle est **dans** celle du portage (`RoutesBackend.php`). **Les deux
mesures sont justes et repondent a deux questions differentes** — et il y a deux passerelles.

**11 n'est pas un nombre de routes** : c'est un nombre d'enregistrements `@bp.route`, plusieurs
methodes sur un meme chemin. **7 chemins distincts.** Idem pour `/ssh-audit/` : 8 enregistrements,
**7 chemins**. *La session 6 avait ecrit 8 et 1 ; les deux etaient des enregistrements. Un compte
qui melange chemins et methodes gonfle du cote qui alarme.*

### Le rang, mesure et non suppose

La session 6 a raison de refuser le rang unique que je proposais, **et sa raison est mesurable** :

- **consequents** — `/ssh-audit/` et `/cve_` : des routes de parc que **rien** ne garde qu'un
  role, donc un role 1 qui passe la passerelle n'a **plus qu'une** barriere ;
- **defense en profondeur** — les 36 autres, dont `/fail2ban/` : **toutes ses routes portent une
  permission**, mesure a 16:25. *Elle en portait une de moins ce matin* — la session 6 signale
  que sa propre lecture du matin aurait classe `/fail2ban/` au rang consequent. **C'est pourquoi
  un releve se publie avec son heure.**

Les traiter au meme rang ferait passer `/ssh-audit/` et ses sept chemins pour l'equivalent de
`/bashrc/`, qui n'en porte aucun.

## E-238 — LE BACKEND EN SERVICE EST CELUI D'HIER : aucun chiffre sur `wazuh`, `ssh` ou `ssh_audit` ne veut dire ce qu'il parait dire

**Releve par la session 2, verifie par le Lead le 2026-08-28 a 17:05 CEST.**

    docker inspect rootwarden_python --format '{{.State.StartedAt}}'
      ->  2026-08-27T12:28:43Z   =  HIER 14:28 CEST
    find backend -name '*.py' -newermt '2026-08-27 14:28' | wc -l                    ->  27
    idem, -not -path 'backend/tests/*'                                               ->  20
    idem, backend/routes/ seul                                                       ->  10
    backend/tests/ seul                                                              ->   7
    wazuh.py 10:11 · ssh.py 10:03 · helpers.py 09:58 · ssh_audit.py 08:14   (tous le 2026-08-28)

Les `.py` sont lus **au demarrage du process**. **Le process a demarre avant que 27 fichiers soient
modifies.**

### Trois comportements pour une meme route, selon ce qu'on lit

    en SERVICE   `AND a.id IS NULL` sur une table sans colonne `id`   ->  500
    dans l'ARBRE  machine_ids obligatoire, corps vide                  ->  400
    ce que le Lead a DIT   « geste de parc »                           ->  faux depuis E-224

Idem `/wazuh/uninstall` : le service rend encore `success = (code == 0)`, pas `paquet_retire`.

> **Une suite ecrite contre l'arbre et jouee contre le service mesure l'ecart entre les deux, et
> l'attribue a la page.** Le test echoue pour une raison qui n'a rien a voir avec ce qu'il croit
> mesurer — meme forme que `go-page-ssh-flux`, ou E-196 rotationnait un fichier qu'une suite
> supposait, sans que rien ne les relie.

### Ce que ce releve change au dossier de REDEMARRAGE

Le Lead le presentait comme **« 27 modules ecrits et inertes »** — un **cout**. *Ce n'en est plus un :*
**tant que le redemarrage n'a pas eu lieu, aucune mesure sur ces routes n'est interpretable.** Le
redemarrage cesse d'etre une mise en service et devient un **prealable de justesse**.

### Et le « 27 » contre le « 20 » du DSI est le CINQUIEME faux desaccord du jour

**27 = 20 hors tests + 7 tests**, dont **10 modules de routes**. Les deux chiffres sont justes ; le
DSI comptait hors tests, moi tout. **Le nombre qui decide est 20** — les fichiers de tests ne sont
pas charges par le process — et plus precisement **10 modules de routes**.

*Cinquieme fois du jour que deux mesures justes ont ete prises pour un desaccord*, apres `iptables`
369/870, les cles Graylog 5 et 5, `/wazuh/uninstall`, et pytest 462/509/549/566. **La cause est
chaque fois la meme : un chiffre voyage sans son ETIQUETTE.** Et le DSI a fait la seule chose qui
ferme ce genre d'ecart en un tour — *donner son chiffre avec sa methode plutot que reprendre le
mien.*

*Le chiffre « 20 modules » que le Lead relayait depuis ce matin etait donc juste par accident : il
designait autre chose, et coincidait.*

## E-235c bis — mon 38 etait 39, et la soustraction annoncait une amelioration qui n'a pas eu lieu

**Session 3, verifie par le Lead a 17:00 CEST.** J'ai derive l'ENSEMBLE puis compte par
**soustraction** — `66 − 28`. La soustraction suppose une **bijection** entre les deux listes ; elle
n'existe pas : plusieurs entrees de `ADMIN_SEULEMENT` sont plus specifiques que l'entree de liste
blanche qui les couvre.

    soustraction naive, ADMIN_SEULEMENT=28  ->  38     (ce que j'ai inscrit)
    soustraction naive, ADMIN_SEULEMENT=30  ->  36     (apres le correctif de la session 3)
    DERIVE, reserveeAdmin() par entree     ->  39     AVANT ET APRES

> **La soustraction a BAISSE de 2 pendant que la realite ne bougeait pas** : la session 3 a ajoute
> deux **routes exactes**, pas deux entrees de liste blanche. **Elle annoncait une amelioration qui
> n'a pas eu lieu.**

*J'avais derive l'appartenance a l'ensemble, puis reintroduit le raccourci dans l'arithmetique.*
**Deriver un ensemble et compter ses elements sont deux gestes, et le second peut defaire le
premier.** Cinquieme nombre du jour venu d'un raccourci plutot que d'une derivation.

### Et deux routes que mon releve n'avait pas nommees

    /cve_trends           @require_api_key SEUL   -- rend des donnees de FLOTTE
    /cve_test_connection  @require_api_key SEUL

*Mon motif cherchait dans `cve.py` ; `/cve_trends` vit dans `monitoring.py`.* **Un motif qui suppose
le fichier ne trouve pas ce qui est ailleurs** — quatrieme fois du jour, apres `'route' =>`,
`guide.php` et les litteraux `status='…'`. **Signalees, non fermees.**

## E-239 — j'ai transpose la CONCLUSION d'un precedent sans verifier sa CONDITION, et le geste aurait casse le role 1

**Session 3 a refuse le perimetre que le Lead lui donnait, et elle avait raison. Verifie.**

J'avais demande de fermer `/ssh-audit/` **et** `/cve_` en entier dans `ADMIN_SEULEMENT`, au motif du
precedent `/supervision/`. Mesure de la session 3 :

    security/index.php:37    checkAuth([ROLE_USER, …]) + can_scan_cve      <- role 1 admis
    ssh-audit/index.php:12   checkAuth([ROLE_USER, …]) + can_audit_ssh     <- role 1 admis
    portage                  /scan-cve en role:1 + perm:can_scan_cve

Un role 1 porteur de la permission atteint `/cve_scan`, `/cve_results`, `/cve_history`,
`/cve_compare`, `/cve_reprioritize` — **toutes gardees par `@require_machine_access`, la garde qui
MORD au role 1** et le borne a **ses** machines.

> **Fermer le prefixe entier remplacerait une borne PRECISE — vos machines — par une borne AVEUGLE
> — personne sous le role 2 — et casserait la page pour les comptes auxquels elle est destinee.**

**Le precedent `/supervision/` ne se transpose pas, et c'est sa CONDITION qui le dit** : la page y
exigeait le role 2 des deux cotes, donc **personne ne perdait rien**. Ici le role 1 est admis des
deux cotes.

> **La condition d'un precedent decide, pas sa conclusion.** *Un remede qui resserre un axe peut
> desserrer la protection reelle* — meme forme qu'E-236, ou une garde plus stricte sur un axe etait
> plus permissive sur un autre.

**Ferme au bon perimetre** : les **deux routes de parc seulement**, deja en `require_role(2)`, sans
borne par machine — un role 1 n'y a jamais eu acces. **Les huit routes par machine intactes**,
verifie apres pose.

## E-240 — un jeu de regles VALIDE declare invalide : le marqueur de code de sortie est cherche dans des FRAGMENTS de 4096 octets, pas dans la sortie recomposee

**Releve et reproduit sans SSH par la session 5** (`AUDIT-PRERELECTURE-IPTABLES.md` §1), inscrit par
le Lead le 2026-08-28 a 17:15 CEST.

La detection cherche `EXIT_CODE=0` dans chaque **fragment** de lecture de 4096 octets. **Des que le
marqueur chevauche une frontiere de fragment, il n'est trouve dans aucun des deux** — et un jeu de
regles parfaitement valide est declare invalide.

> **Et l'echo PTY est ce qui rend cette frontiere ATTEIGNABLE** : le canal legacy echote la commande,
> donc la sortie porte des centaines d'octets qui ne viennent pas du programme. Sans lui, la
> frontiere tomberait rarement au mauvais endroit ; avec lui, la position du marqueur depend de la
> longueur de la commande envoyee.

**C'est la troisieme consequence de l'echo PTY inscrite dans ce chantier**, apres le faux « visudo
refuse » permanent et le `isdigit()` global. *Un canal qui echote transforme toute mesure positionnelle
en pari.* Le remede general reste le meme : **recomposer d'abord, parser ensuite, et par ligne.**

**Le correctif est d'une ligne et il touche le backend.** Donc, sous E-238 : **a preparer, pas a
appliquer** — le process en service date d'hier, un correctif pose aujourd'hui serait inerte, et un
ecran qui annoncerait la protection mentirait sur l'etat reel.

### La regle de conduite qui en decoule pour I4

**I4 ne doit ni corriger ni annoncer une correction.** Il doit rendre le defaut LISIBLE : quand la
validation echoue, distinguer *« les regles sont invalides »* de *« je n'ai pas pu lire le verdict »* —
les deux memes issues que I3 vient de separer sur l'historique. *Le portage ne repare pas le backend ;
il cesse de presenter une incertitude comme un verdict.*


## E-241 — REGRESSION REELLE : apres un enregistrement refuse, les onglets de `graylog` cessent de repondre — et j'avais inscrit « la page est mesuree saine »

**Caracterise par la session 7 le 2026-08-28 vers 17:20 CEST. Le Lead avait inscrit l'inverse deux
heures plus tot, et c'est la faute a lire d'abord.**

### ⚠ MA PROPRE NOTE DISAIT « MESUREE SAINE »

`v1.38.87` et le §2 du plan portaient : *« la page est mesuree saine — le clic ouvre le panneau,
champ a 45 px, contrat DOM intact, zero erreur JS ; le defaut est dans l'enchainement de la suite »*.

**Deux fautes, et la seconde est la mienne seule :**

1. la sonde citee mesurait le clic **au chargement de la page**, pas **apres** la sequence qui casse.
   *Une sonde qui ne rejoue pas la sequence ne mesure pas le defaut de la sequence* ;
2. **j'ai recopie une conclusion rassurante d'un compte rendu qui s'annonçait lui-meme comme NON
   ISOLE.** La session 7 avait ecrit « non isole et non pretendu tel » — **je l'ai inscrit comme un
   dedouanement.** *Une prudence dans un compte rendu ne survit pas a la recopie : elle devient un
   verdict.*

Troisieme fois du jour qu'une conclusion rassurante de ma main s'est reveleee fausse — apres
« aucun lien entrant » et « la page est saine » ici. **Et c'est la premiere ou j'ai transforme la
reserve d'un pair en certitude.**

### La sequence, mesuree, et 8 secondes de re-clics n'y changent rien

    1. au chargement          panneau cache,   onglet actif = config
    2. clic « templates »     panneau VISIBLE, actif = templates       <- les onglets MARCHENT
    3. clic « config », champ hote VIDE, clic « enregistrer »
    4. re-clic « templates »  RIEN NE CHANGE — hidden reste true, actif reste config
    erreurs JS : AUCUNE       legacy : 27/0

**Consequence pour un exploitant** : apres avoir enregistre une configuration Graylog, **il ne peut
plus changer d'onglet sans recharger la page, et rien ne le lui dit.**

### Ce que la session 7 a ECARTE, et qui vaut autant que ce qu'elle a trouve

htmx / re-rendu de fragment (aucun `hx-*`, aucun `innerHTML` sur les onglets) · `annonce()` (elle ne
fait que `textContent` et `className`) · **l'appel reseau — avec un hote vide, `enregistreConfig`
fait `return` AVANT tout envoi.** *Donc le defaut survient sans qu'aucune requete ne parte : ce n'est
pas la reponse du serveur qui casse les onglets.*

### CE QUE LE LEAD AJOUTE : LA PISTE CITABLE, ET ELLE EXPLIQUE L'ERREUR D'ORIGINE

Verifie dans l'arbre :

    laravel/resources/views/graylog.blade.php:99   <p class="rw-annonce" data-rw="graylog-config-etat">   VIDE au chargement
    laravel/public/css/rw.css:1076                 .rw-annonce:empty { display: none; }

**Au premier echec, cet element passe de `display: none` a un bloc : il GAGNE une hauteur.** C'est un
**decalage de mise en page**, declenche exactement a l'etape 3 — et c'est la signature de l'erreur
d'origine, *« Node is either not clickable or not an Element »*, qui survient quand la mise en page
bouge entre le calcul des coordonnees et l'arrivee du clic.

**Ce que le Lead a verifie et ECARTE en plus** : aucun `<form>` dans la vue et **tous les boutons en
`type="button"`** — donc aucune navigation ; `ouvreOnglet` et `enregistreConfig` sont corrects a la
lecture ; les quatre panneaux portent bien un `data-rw` concordant.

**Non localise, et le Lead ne le pretend pas** : la piste explique le *« not clickable »* d'origine,
pas le *« le clic n'a plus d'effet »* d'apres correction. `graylog.js` et `graylog.blade.php`
appartiennent a la session 3.

### Et arbre et service concordent ici — verifie

    graylog.js  mtime 2026-08-26 16:37     StartedAt  2026-08-27 14:28

**Ce defaut n'est PAS un artefact d'E-238** : le code servi est bien celui de l'arbre.

### La regle que la session 7 en tire, et qui corrige la mienne

> **Une suite qui echoue merite qu'on se demande d'abord si c'est ELLE qui a tort — mais la reponse
> peut etre non, et il faut alors le dire aussi fort.**

Ce chantier a passe la journee a se corriger dans le sens *« ce n'est pas un defaut »*. **Celui-ci va
dans l'autre sens, et il etait deja inscrit comme dedouane.** Et c'est la correction de la suite —
attendre la **propriete** plutot qu'une **duree** — qui a transforme un echec opaque en defaut
localise : *un `dors(900)` fixe ne cache pas seulement une lenteur, il cache la NATURE du defaut.*

### Reference : ROUGE, et c'est JUSTE

`REF_LARAVEL[go-page-graylog-g1]` **n'est pas inscrite** tant que le defaut vit. *Une reference posee
sur un rouge legitime transforme le defaut en etat normal.* **`REF_LEGACY = 27`** (de 25 : les deux
assertions d'ouverture d'onglet y passent).
