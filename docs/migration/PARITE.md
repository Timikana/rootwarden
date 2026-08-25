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
