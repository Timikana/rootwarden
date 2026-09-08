# QA — le catalogue `sftp` : 65 clés, 63 atteintes, 2 orphelines

**Le verdict**, puis **l'instrument** qui le reproduit et vaut pour les autres catalogues.

    catalogue sftp             65 cles (fr = en, parite exacte)
    TEMOIN  fichiers lus       342   (non nul)
    fichiers citant « sftp. »    7
    litterales                  36
    liste curatee               13
    construites (domaines)      27
    ATTEINTES                   63 / 65
    TEMOIN  « titre » atteint   oui   ·   cle forgee atteinte : non

    ✅ aucune cle atteinte n'est absente du catalogue

## L'écart de 65 à 40 se résout en TROIS chemins, pas un

Le relevé initial comptait « 40 occurrences » et laissait craindre 25 clés mortes. **Il y en
a deux.** Les autres sont atteintes autrement :

| chemin | nombre | comment |
|---|---|---|
| **littérale** | 36 | `__('sftp.titre')` |
| **curatée** | 13 | `foreach ([...] as $cle) $libelles[$cle] = __('sftp.' . $cle)` — elles voyagent dans un bloc JSON vers le script |
| **construite** | 27 | trois familles à préfixe, domaines énumérés à leur source |
| **orpheline** | 2 | aucun des trois |

⚠ **Une clé curatée n'est pas orpheline.** La confondre ferait retirer un libellé en service —
c'est le cas de 13 des 15 clés que mon premier relevé donnait pour mortes.

### Les trois domaines, énumérés À LEUR SOURCE

    sftp.f_ · sftp.h_   $champs, tableau LITTERAL de la vue (`acces-sftp.blade.php:12`)
                        sftp_only · password · tcp · agent · x11
    sftp.etat_          `policy_deployments.status`, ENUM MySQL — l'autorite est le SCHEMA
                        applied · rolled_back · failed · superseded

**Aucune des 14 clés construites ne manque.** *C'était la vérification qui comptait* : `__()`
rend **le nom de la clé** quand elle est absente — un identifiant nu affiché à l'utilisateur,
et un titre **non vide**, donc satisfaisant toute assertion de forme.

## Les deux orphelines, et elles ne sont pas de la même espèce

**`sftp.rollback_lien`** — *« Annuler ce déploiement dans l'ancien portail »*. C'est le résidu
d'un état **révolu** : le contrôleur porte maintenant `rollback_confirme`, avec le commentaire
*« L'annulation d'un déploiement, rouverte le 2026-09-07 »*. **La capacité a été portée, le
libellé qui renvoyait au legacy est resté.** À retirer.

**`sftp.restreint`** — *« Restreint l'accès »*. `AccesSftp::REGLAGES` donne à chaque réglage
son effet : `sftp_only => 'restreint'`, les quatre autres `=> 'ouvre'`. Or la vue ne rend le
badge **que si l'effet ouvre** (`:113`, `@if ($effets[$colonne] === 'ouvre')`).

**Ce n'est donc pas une clé morte : c'est la moitié non rendue d'une paire, et le choix se
défend** — on avertit de ce qui **ouvre** un accès, pas de ce qui le restreint. *Le libellé
survit à une décision de ne pas l'afficher.* À retirer **ou** à documenter sur place ; ce
n'est pas la même chose que la première.

---

## L'instrument — `scripts/cles-atteintes.py`

**Il REFUSE de conclure quand il rencontre un domaine qu'il ne connaît pas** (code de sortie
3), et nomme les sites à énumérer. *Une sonde qui devine un domaine rend un verdict faux dans
les deux sens : elle signale une « clé citée mais absente » qui n'existe pas, et elle déclare
atteintes des clés qui ne le sont pour aucune valeur réelle.*

### Trois pièges d'instrument fermés dans l'outil

**1. Population par CONTENU, jamais par nom de fichier.** Le consommateur de `sftp` s'appelle
`acces-sftp.blade.php` : un glob `sftp*.blade.php` rend « module mort » sur un module vivant.

**2. Commentaires dépouillés à chaque fois**, sans se demander si ce fichier-là en contient —
cinq syntaxes. *Un commentaire qui cite une clé en prose la fait compter comme atteinte.*

**3. Ancre à gauche.** `t\('…'\)` sans ancre matche la fin de `document.createElemen` +
`t('article')`.

### Et des témoins qui doivent rendre non-zéro

« 0 clé orpheline » et « ma sonde n'a rien lu » sont **la même sortie**. L'outil rend donc, à
chaque exécution : le nombre de fichiers lus, le nombre de fichiers citants, et deux témoins
nommés — une clé connue qui doit être atteinte, une clé forgée qui ne doit pas l'être.

    ./scripts/cles-atteintes.py sftp
      -> REFUS, 4 sites construits nommes

    ./scripts/cles-atteintes.py sftp --domaine='sftp.f_=…' --domaine='sftp.etat_=…' …
      -> 63/65, 2 orphelines, code 0

Code de sortie : **0** rien d'absent · **2** une clé atteinte manque au catalogue · **3**
domaine non énuméré, verdict refusé.


---

# ADDENDUM — arbitrage rendu, et le risque du badge REMESURÉ

**Décision (`0f4bd0a2`)** : `rollback_lien` se retire · `restreint` se garde, documenté sur
place. *Coût asymétrique : une entrée dormante coûte une ligne ; la retirer obligerait celui
qui rendra un jour un badge neutre à réinventer le libellé, avec un risque de divergence
FR/EN à la clé.*

## ⚠ LE RISQUE SIGNALÉ, ET CE QUE LA MESURE EN FAIT

L'inquiétude transmise était celle-ci — et elle est de la bonne famille :

> *Le badge dit « ceci ouvre » par sa PRÉSENCE. Son absence dit « restreint ». Donc un badge
> perdu — CSS purgé, contraste insuffisant, jeton inerte — fait lire SÉCURISÉ un réglage qui
> OUVRE l'accès. Quatre sur cinq ouvrent : la perte est silencieuse ET favorable.*

**Mesuré : le badge n'est pas le seul porteur du sens.** Le libellé du champ l'énonce déjà,
dans les deux langues :

    f_sftp_only   « Transfert de fichiers uniquement (pas de terminal) »   n'ouvre pas
    f_password    « Autoriser la connexion par mot de passe »              Allow…
    f_tcp         « Autoriser les tunnels reseau »                         Allow…
    f_agent       « Autoriser le rebond de cle »                           Allow…
    f_x11         « Autoriser l'affichage graphique distant »              Allow…

    concordance libelle / effet : 5 / 5, en FR comme en EN

**Un badge perdu DÉGRADE l'avertissement ; il n'INVERSE pas le sens.** L'opérateur lit encore
« Autoriser les tunnels réseau » sur la case elle-même. *C'est une différence de degré qui
change la priorité : ce n'est pas la pastille KEV à 1,06:1, où le HTML juste ne disait rien
de plus.*

## ⛔ MAIS LA MESURE, ELLE, EST IMPOSSIBLE — et ça reste ouvert

    <span class="rw-badge rw-badge--attention" data-rw="sftp-effet-{{ $cle }}">

**L'ancre `data-rw` n'existe QUE dans la branche qui ouvre.** Conséquence :

    reglage RESTREINT     aucune ancre  ->  l'assertion ne trouve rien
    badge PERDU           aucune ancre  ->  l'assertion ne trouve rien

**Aucune épreuve DOM ne peut distinguer les deux.** Un test qui vérifie l'absence du badge sur
`sftp_only` passerait tout aussi bien si le badge avait disparu partout.

*C'est le défaut réel, et il est de testabilité plutôt que d'affichage.* Le fermer demanderait
**une ancre dans les deux branches** — un `data-rw="sftp-effet-x"` portant `ouvre` ou
`restreint` en valeur, plutôt qu'un élément présent ou absent. **Une propriété portée par une
VALEUR se mesure ; une propriété portée par une PRÉSENCE ne se distingue pas d'une panne.**

Non fait ici : c'est un changement de vue, et la décision de rendre ou non le second badge
vient d'être prise dans l'autre sens.

## Ce qui n'a pas pu être mesuré, et pourquoi

**Le contraste calculé du badge.** C'est la mesure utile — *aucune assertion sur la présence
du `<span>` ne peut voir un badge invisible* — et elle demande un navigateur.

    swap        3604 / 3702 Mio   =  97,4 %
    disponible  1,4 Gio
    Chrome      « Timed out waiting for the WS endpoint », deux fois chez une autre session

**Une suite lancée dans cet état échouerait pour cette raison, pas pour la sienne.** Reporté,
et dit plutôt que tenté.
