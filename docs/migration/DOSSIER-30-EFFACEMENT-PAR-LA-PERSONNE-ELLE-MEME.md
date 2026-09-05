# DOSSIER 30 — L'effacement demandé par la personne elle-même

**2026-09-05, 11:40 CEST.** *Sur le relevé de 0b (`06642b2`), vérifié clause par clause.*

> **Ce dossier est le seul point où l'extinction du legacy retirerait une obligation
> réglementaire. Les dix-huit autres gestes des trois fichiers mesurés sont portés.**

---

## 1. LE FAIT, MESURÉ

    legacy   privacy.php:35    `if (isset($_POST['delete_data']))`
             privacy.php:217   le bouton qui le poste
             -> la personne supprime SON PROPRE compte, depuis SA page

    portage  auto-suppression : **0 occurrence**  (temoin : 'profil' dans 26 fichiers)
             la seule suppression est ADMINISTRATIVE :
             web.php:745-746   DELETE /comptes/{id}   `role:3` + `can_admin_portal`

**Ce n'est pas couvert par la suppression administrative, parce que l'ACTEUR change.**
*C'est l'article 17 exercé par le sujet lui-même, et non par un administrateur en son nom.*
**C'est le second point RGPD après l'article 20, qui lui a été porté.**

---

## 2. ⚠ LA BRÈCHE EST PLUS ÉTROITE QU'ELLE N'EN A L'AIR — et c'est important

**Le portage a la SUBSTANCE de l'article 17. Il lui manque l'ACTEUR.**

    Comptes::supprimableSansPerte()    `journauxDe($id) === 0`
    et son docblock, :505-507 :
      « audit_log ecrivant toujours avec l'identifiant de l'AUTEUR et jamais de la
        cible. Sinon, L'ANONYMISATION EST LE GESTE JUSTE : elle efface les donnees
        personnelles et PRESERVE le journal. »

**Deux gestes complémentaires, tous deux portés** : *supprimer quand il n'y a rien à
perdre ; anonymiser sinon.* **Et `anonymize_user` est porté table pour table — 7 gestes
sur 7, y compris sur ce qu'il n'efface PAS.**

> **C'est une conception, pas un héritage : le fichier écrit sa raison.** *Cela tranche le
> « non tranché » du relevé — la garde plus restrictive du portage est VOULUE.*

**Et elle répond à une tension réelle que ce chantier a mesurée ce matin même** :
`user_logs` est une chaîne de hachage où retirer une ligne casse la vérification de toutes
les suivantes. **« Effacez-moi » contre « la chaîne d'audit ne doit pas rompre » est un
vrai conflit — et l'anonymisation est la réponse que le droit admet.**

### Une correction de magnitude, dans le sens qui alarmait

    comptes actifs sur ce banc          12
    comptes portant des entrees          4     ->  8 seraient supprimables

**Le relevé disait « avoir des entrées de journal vise presque tous les comptes ».** *Sur
ce banc, c'est un tiers.* **« Presque tous » est une inférence sur une instance vivante,
pas une mesure.**

---

## 3. CE QUE J'ARBITRE, ET CE QUE JE NE PEUX PAS

### ⛔ Arbitré : `legacy/privacy.php` NE S'ARCHIVE PAS

**Quatrième interdit d'archivage.** *Il est le seul accès à un geste réglementaire non
porté.* **Levée : quand l'effacement en libre-service existe côté portage.**

### ⚖ Ce qui revient à l'exploitant, et c'est une vraie question, pas une formalité

**Le portage possède déjà les deux gestes. Ce qui manque tient en une route sur `/profil`
qui les appelle avec le demandeur pour cible.** *Techniquement petit.*

**Mais RootWarden n'est pas un service grand public : c'est un portail
d'administration.** *Et là, l'auto-suppression n'est pas évidemment souhaitable :*

    - elle peut retirer le DERNIER superadministrateur — le legacy s'en garde
      explicitement, et cette garde-la devrait etre reprise ;
    - sur un portail dont les comptes sont des ACCES et non des inscriptions, un
      depart se traite d'ordinaire par le retrait de l'acces, pas par l'effacement ;
    - et le compte est l'objet meme que le journal d'audit designe.

**Trois formes, et je recommande la deuxième :**

    (a) porter l'auto-suppression telle quelle
    (b) porter une DEMANDE d'effacement : la personne la declenche, elle est tracee,
        et le geste execute est l'ANONYMISATION — celle qui est deja portee et qui
        preserve la chaine                                    <- RECOMMANDE
    (c) ne pas porter, et assumer que l'article 17 s'exerce par l'administrateur

> **(b) donne à la personne l'initiative, qui est ce que le droit exige, sans donner à un
> compte d'administration le pouvoir de se retirer du journal.** *(c) est défendable
> juridiquement mais fait dépendre un droit d'un tiers, ce que l'article 20 n'a pas
> accepté ici — et le portage a tranché ce précédent dans l'autre sens.*

**Ce que je ne veux pas, c'est (c) SANS le savoir** — c'est-à-dire par archivage
silencieux de `privacy.php`.

---

# ⚠ ÉLARGISSEMENT (11:45) — ce n'est pas un geste, c'est une CLASSE

**Sur le lot 1/3 de 0b (`21c8d1d`), vérifié.** *Le dossier ouvert pour l'effacement en
couvre quatre, et le titre du document est désormais trop étroit.*

## Les quatre gestes non portés ont tous la même forme

    changer son adresse de courriel        profile.php:112
    poser sa propre cle SSH                profile.php:127
    fermer toutes ses AUTRES sessions      profile.php:93
    supprimer son propre compte            privacy.php:35

> **Le compte agissant sur SON PROPRE compte.**

## ⛔ POURQUOI CETTE CLASSE EST INVISIBLE À TOUS NOS INSTRUMENTS

**Le côté ADMINISTRATIF de chacun de ces gestes est porté, et porté avec soin** — clé SSH,
suppression, anonymisation, déverrouillage, réinitialisation du second facteur.

    une passe par TABLE   voit `users.ssh_key` ecrite et `users` supprimee -> COUVERT
    une passe par ROUTE   voit des routes existantes                       -> COUVERT
    une passe par NOM     trouve les libelles des deux cotes               -> COUVERT

**C'est l'ACTEUR qui distingue, et l'acteur n'apparaît QUE dans la garde de la route.**

> **Aucune des cinq formes de sonde employées sur ce chantier ne lit une garde.** *C'est le
> premier défaut de la journée qu'aucun de nos instruments ne pouvait attraper — et il a
> fallu quatre occurrences avant que la forme se voie.*

## Le détail de chacun, mesuré

    changer son adresse   ⛔ MANQUE DES DEUX COTES. Les deux seules ecritures de la
                          colonne sont l'anonymisation (met a null) et la CREATION par
                          import CSV. AUCUNE route ne change l'adresse d'un compte
                          existant — ni pour lui-meme, NI POUR UN ADMINISTRATEUR.
                          (ma sonde : 0 fichier, sur un corpus de 102)

    sa cle SSH            l'unique ecriture est `definitCleSsh`, atteignable par la
                          seule route `web.php:731`, gardee `role:3` +
                          `can_admin_portal`. Un role 1 ne peut pas poser sa cle.

    fermer ses sessions   DEGRADE, pas absent : `/profil/sessions/fermer` existe, mais
                          `revoquerSession` ne revoque qu'UNE session par empreinte.
                          « Je suis compromis, ferme tout le reste MAINTENANT » devient
                          N clics sur un N inconnu.

    supprimer son compte  voir le corps de ce dossier.

## Ce que ça change à la question posée à l'exploitant

**La question n'est plus « faut-il porter l'auto-suppression ». Elle est :**

> **Le portage a-t-il une notion de LIBRE-SERVICE, et laquelle ?**

**Il en a une** — `/profil` existe, avec `donnees-personnelles`, `sessions/fermer`,
`mot-de-passe`, `step-up`, `step-up/revoquer`. **Elle est incomplète, et son incomplétude
n'a jamais été décidée : elle est le résidu de quatre portages faits chacun du côté
administrateur.**

**Deux des quatre touchent le RGPD exercé par le sujet lui-même** : *rectifier son adresse
(art. 16) et supprimer son compte (art. 17).* **Je le signale et ne le qualifie pas — la
conformité est un jugement juridique, et l'export art. 20 portait déjà cette réserve.**

**Ma recommandation (b) tient et s'étend** : *porter le libre-service comme un ensemble
cohérent plutôt que geste par geste* — sans quoi le prochain portage refera le même choix
par défaut, du côté administrateur, sans que personne ne l'ait tranché.

---

## ✅ ET UNE ALERTE VOISINE QUI TOMBE : la liste blanche CVE

**`/cve_whitelist` a été signalé comme « capacité qui mourrait sans décision ».** *La
décision existe — `MODULE-SECURITY.md`, E-59, « capacité inerte, la table n'a aucun
lecteur ».* **Et le fait est plus fort que la décision :**

    `whitelistCve` dans legacy/security/   1 occurrence : sa PROPRE DEFINITION
                                            0 appelant
    temoin : `runScan` dans le meme module  4 occurrences

> **La capacité est déjà injoignable DANS LE LEGACY.** *L'archiver ne perd rien qu'un
> utilisateur puisse atteindre aujourd'hui — et la table, elle, n'est pas touchée par un
> `git mv`.*

**Aucun interdit d'archivage n'est requis de ce fait.**
