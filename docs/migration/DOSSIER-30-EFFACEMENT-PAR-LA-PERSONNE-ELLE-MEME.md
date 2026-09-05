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
