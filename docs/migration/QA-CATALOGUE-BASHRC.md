# QA — catalogue `bashrc` : 92 clés, les 7 gestes nommés sont TOUS atteignables

**Apparié contre ce que le JS APPELLE**, jamais contre la table des routes. *Une route qui
existe ne dit pas que le geste est porté.*

    catalogue bashrc            92 cles (fr = en, parite exacte)
    TEMOIN  fichiers lus       342   ·  fichiers citant « bashrc. » : 4
    ATTEINTES                   90 / 92
    TEMOIN  « titre » atteint   oui  ·  cle forgee : non

## ⚠ L'INSTRUMENT PRESCRIT NOMME LA FAMILLE, PAS LES GESTES

    NODE_PATH=… node laravel/tests/Outils/analyse-appelants.mjs laravel/public/js
      -> 42 fichiers, 75 appels
      -> pour bashrc : UN SEUL site   « bashrc.js:124  lit()  ->  PASSERELLE + chemin »

**Un seul site pour tout le module** : `lit()` est l'aide, les gestes sont ses **appelants**.
C'est exactement l'écueil annoncé. Remonté à l'AST, avec la fonction englobante :

    ligne  chemin appele                                          geste
      238  /bashrc/users?machine_id=…                             lire les comptes
      280  /bashrc/prerequisites                                  INSTALLER figlet (root, SSH)
      373  /bashrc/deploy                                         DEPLOYER le .bashrc
      411  /bashrc/backups?machine_id=…&user=…                    lister les sauvegardes
      437  /bashrc/restore                                        RESTAURER une version
      502  /bashrc/preview                                        apercu (diff)
      618  /bashrc/template                                       lire le gabarit
      656  /bashrc/template                                       enregistrer le gabarit

    TEMOIN  9 sites lit()/fetch trouves · 3 constantes repliees

## Le croisement, famille par famille — AUCUN geste manquant

| famille | clés | geste | site qui le prouve |
|---|---|---|---|
| `comptes_*` | 6 | lire les comptes | `bashrc.js:238` |
| `figlet_*` | 6 | installer figlet | `bashrc.js:280` |
| `deploy_*` | 7 | déployer | `bashrc.js:373` |
| `restore_*` | 8 | restaurer + lister | `bashrc.js:437` · `:411` |
| `apercu_*` | 7 | aperçu | `bashrc.js:502` |
| `gabarit_*` | 14 | lire et écrire le gabarit | `bashrc.js:618` · `:656` |

**Les 7 chemins sont appelés. Chaque clé qui nomme un geste a son geste.** Les 44 clés
restantes sont des colonnes, des états et des avertissements — elles ne nomment aucun geste.

---

## ⛔ MAIS UNE CLÉ ANNONCE TROIS ABSENCES QUI SONT TOUTES COMBLÉES

`bashrc.non_porte_texte`, rendue en page (`bashrc.blade.php:252`) :

    « Le deploiement, la restauration et la liste des sauvegardes sont portes ici.
      L'installation du paquet figlet ne l'est pas : elle ecrit sur la machine en
      root pour un utilitaire d'affichage. Elle se fait par SSH, une fois par
      machine.d'une version anterieure et la liste des sauvegardes se font pour
      l'instant depuis l'ancien portail. »

**Trois affirmations, trois démentis mesurés :**

    « l'installation de figlet n'est pas portee »   ->  bashrc.js:280, POST /bashrc/prerequisites
                                                        bouton `bashrc-figlet-installer` (:133)
                                                        cycle complet : confirme · en_cours · fait · echec
    « la restauration … depuis l'ancien portail »   ->  bashrc.js:437, POST /bashrc/restore
    « la liste des sauvegardes … ancien portail »   ->  bashrc.js:411, GET /bashrc/backups

### Et la clé se contredit DANS SA PROPRE VALEUR

Sa première phrase dit *« la restauration et la liste des sauvegardes **sont portées ici** »* ;
sa dernière dit que les deux *« se font pour l'instant **depuis l'ancien portail** »*.

⚠ **Elle est aussi MALFORMÉE, dans les deux langues** :

    FR  « …une fois par machine.d'une version anterieure et la liste… »
    EN  « …once per machine.version and listing the backups are… »

**Un fragment d'une rédaction antérieure recollé sans espace ni majuscule.** Le début de la
phrase a été remplacé, la queue est restée. *C'est du texte affiché à l'utilisateur, et il se
lit comme une panne.*

### `non_porte_lien` est ORPHELINE — donc la page annonce sans offrir

`bashrc.non_porte_lien` = *« Ouvrir bashrc dans l'ancien portail »* n'est **rendue nulle
part**. La page affiche donc le titre et le texte qui renvoient au legacy, **sans le lien**.

> **Un libellé qui annonce une absence comblée envoie l'opérateur ailleurs pour un geste qui
> est sous ses yeux** — et ici il l'envoie sans même lui donner la porte.

C'est la même espèce que `sftp.rollback_lien`, et le dépôt porte déjà la décision : un
commentaire de `fail2ban.blade.php:549-550` dit que `non_porte_titre` et `non_porte_texte`
*« sont retirées des DEUX catalogues dans le même commit »* — la règle existe, elle n'a pas
été appliquée à `bashrc`.

**Non corrigé ici** : retirer trois clés et l'encart qui les rend est un geste sur une vue et
deux catalogues. *Je qualifie et je transmets.*

## La seconde orpheline

`bashrc.sensible_titre` = *« Machine de production ou critique »*. `sensible` et
`sensible_aide` sont rendues (`:90`, `:269`), **le titre non**. Moitié non rendue d'une paire,
même forme que `sftp.restreint` — à retirer ou à documenter, pas la même décision que
ci-dessus.

## Ce que ce rapport n'établit pas

- **Que les 7 gestes FONCTIONNENT.** Il établit qu'ils sont **appelés**, avec leur ligne. *Un
  appel n'est pas une réussite* — et rien n'a été exercé ici.
- **Le contraste ni le rendu.** Aucun navigateur : le swap est à **3702/3702 Mio (100 %)**,
  1,1 Gio de RAM disponible. *Une suite lancée dans cet état échouerait pour la machine.*
