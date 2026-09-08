# PRÉ-RELECTURE SÉCURITÉ — I5 (`240fc7f6`)

    Session   5 — securite, LECTURE SEULE. Je n'ai ecrit aucune ligne d'I5.
    Mesure    2026-09-08
    Portee    les trois questions posees, plus l'arbitrage du retour arriere.

---

## 1. « Le backend inspecte-t-il quoi que ce soit ? » — NON, et c'est ABSOLU

```
--dport   dans TOUT backend/*.py et backend/routes/*.py   ->  0 fichier
iptables_manager.py : aucun `dport`, `ACCEPT`, `INPUT`, `ssh_port`
apply_iptables_rules()  ->  ecrit le texte (base64) puis `iptables-restore <`
```

**Aucune route, aucun module du backend ne lit le CONTENU d'un jeu de règles.**
*Le texte reçu est écrit tel quel dans `/etc/iptables/rules.v4` et rechargé.*

> ⛔ **Conséquence, et c'est la phrase qui doit accompagner Q2 partout où elle
> voyage : Q2 est la SEULE chose entre un opérateur et son propre verrouillage,
> et elle s'exécute dans le NAVIGATEUR.** *Un `curl` vers la passerelle ne la
> rencontre pas ; `RoutesBackend:114` porte `'/iptables-'` et `:446` compare par
> PRÉFIXE, donc les routes destructrices passent déjà la passerelle
> aujourd'hui.*

**Porter I5 ne crée pas l'atteignabilité : il crée l'ÉCRAN — et l'écran est le
seul endroit où la propriété est vérifiée.**

---

## 2. « `can_manage_iptables` gouverne-t-il ce qui rend le geste dangereux ? » — OUI

**La question est la bonne, et la réponse est rassurante pour une raison précise
qu'il faut nommer.**

`routes/helpers.py::resolve_ssh_creds` — *les identifiants de connexion sont lus
EN BASE à partir de `machine_id`, et la fonction REFUSE de travailler sans lui* :

```
machine_id = data.get('machine_id')
if not machine_id:  ->  'machine_id requis.'
SELECT … WHERE id = %s      <- l'ip, le port, les mots de passe viennent de LA
```

> **`server_ip`, `ssh_user`, `ssh_password` présents dans le corps de la requête
> sont IGNORÉS.** *Donc l'objet que `@require_machine_access` contrôle et l'objet
> que le geste ATTEINT sont le même.* **Ce n'est pas une garde sans objet.**

*Et son docblock refuse lui-même le titre de garde — « une PRÉCONDITION, pas une
garde » — ce qui est exactement la distinction juste.*

### 2.1 ⚠ Mais deux décorateurs sur trois n'ajoutent rien au-dessus du rôle 1

```
check_machine_access(…)   ->  if role_id >= 2: return True     INCONDITIONNEL
require_permission(…)     ->  if role_id >= 3: return func()   BYPASS
```

**Le crible EFFECTIF du geste destructeur est donc :**

    role >= 3                        AUCUNE garde — ni permission, ni machine
    role 2 + can_manage_iptables     TOUTES les machines du parc, production comprise
    role 1 + can_manage_iptables     ses machines seulement

> **`@require_machine_access` ne mord qu'au rôle 1.** *Le citer comme borne d'un
> geste destructeur donne une impression de profondeur que le code n'a pas — trois
> décorateurs, un seul crible réel.*

**Ce n'est pas un défaut d'I5 : c'est le socle. Mais I5 est le premier écran qui
OFFRE ce geste, et la phrase « c'est gardé par trois décorateurs » ne doit pas
voyager avec lui.**

---

## 3. « Q4 ne dit rien d'un appelant qui n'est pas la page » — exact, et ça découle du §1

**Q4 mesure l'absence de requête AU RÉSEAU, depuis le navigateur.** *Elle est
juste et elle ne peut rien dire d'un client qui n'ouvre pas la page.* **Le §1
ferme la question : il n'y a rien en aval qui inspecte.**

---

## 4. L'ARBITRAGE DU RETOUR ARRIÈRE — aucune raison de sécurité de ne pas porter

**Je ne vois aucun argument contre, et j'en vois un POUR que l'arbitrage ne
nomme pas :**

> **Le retour arrière est le geste où Q2 fonctionne LE MIEUX.** *Les règles à
> appliquer sont connues À L'AVANCE — elles sont en base, dans
> `iptables_history.rules_v4`.* **Q2 peut donc s'exécuter AVANT qu'aucune session
> SSH ne soit ouverte, sur le contenu exact qui partira.**

*Sur `apply`, l'opérateur compose ; sur le retour arrière, l'objet existe déjà et
se laisse inspecter. C'est le cas le plus favorable des cinq.*

### 4.1 ⚠ MAIS L'ARGUMENT DE L'ARBITRAGE RÉVÈLE UN TROU QU'IL NE NOMME PAS

**Mesuré** — l'historique ne rend PAS les règles, dans les deux portails :

```
backend  /iptables-history        id · created_at · changed_by · change_reason
portage  PareFeuController:279-282 'id' · 'date' · 'auteur' · 'motif'
```

**L'opérateur choisit une DATE. Q2 refusera peut-être. Il verra « je ne peux pas
prouver que cette version laisse le port ouvert » — sur une ligne qui n'affiche
qu'une date et un motif.**

> ⛔ **Un refus qu'on ne peut pas instruire est un refus qu'on contourne.**
> *C'est la même conclusion qu'au §9 de la revue Q2, et elle mord ici plus fort :
> là-bas l'opérateur avait ses règles sous les yeux ; ici il ne les a pas.*

**Deux remèdes, et le second est meilleur :**

1. rendre `rules_v4` avec chaque version — *la colonne existe, elle est déjà lue
   par le rollback* ;
2. **exécuter Q2 sur CHAQUE version au moment où la liste se construit, et
   pastiller chaque ligne.** *L'opérateur choisit alors parmi des versions dont
   il sait laquelle le couperait — au lieu de découvrir au clic.*

**Le second transforme un refus en un CHOIX, et il ne coûte rien de plus : la
propriété est déjà écrite, et les données sont déjà en base.**

---

## 5. Ce que je n'ai pas mesuré

    NON MESURE   si un compte reel occupe l'un de ces chemins aujourd'hui —
                 les quatre voies d'acces a la base me sont fermees
    NON EXERCE   aucune requete, aucune machine jointe, aucune regle appliquee
    NON LU       je n'ai pas relu le detail des quatre fichiers JS d'I5 ;
                 cette note repond aux TROIS QUESTIONS posees, elle n'est pas
                 la relecture ligne a ligne du lot
