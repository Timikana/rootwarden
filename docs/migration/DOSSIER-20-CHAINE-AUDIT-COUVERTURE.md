# DOSSIER 20 — La chaîne d'audit dit « intacte » avec 1460 lignes hors chaîne, et elles servent de couverture

**Pour signature de l'exploitant.** *Trouvé par la session 4 (pentest, angle 6) le 2026-09-03 ; maillon
décisif revérifié par moi à 11:20 CEST.*

> **Ce n'est pas un défaut de présentation — l'écran est honnête. C'est un défaut de CONCEPTION du
> mécanisme, et sa surface double tous les onze jours.**

---

## 1. Ce que la chaîne prouve, et ce qu'elle ne prouve pas

    JournalAudit.php  parcourt()
      if ($l->self_hash === null) {
          $orphelines++;
          // La tete N'AVANCE PAS
          continue;                    <- pas d'erreur, jamais
      }
      $scellees++;
      if ($erreur === null && $l->prev_hash !== $tete) { $erreur = [...]; }

    verifie()  ->  'integre' => $p['erreur'] === null

**Mesuré en base** : `total 6137 · scellées 4677 · orphelines 1460`. **`verifie()` rend `integre: true`.**

> **La chaîne prouve que les lignes SCELLÉES n'ont pas été MODIFIÉES. Elle ne prouve rien sur des lignes
> AJOUTÉES.** *Une ligne insérée avec `self_hash = NULL` n'est jamais une erreur, par construction.*

### ⚠ Et le point qui rend le défaut exploitable

**Les 1460 orphelins légitimes servent de couverture.** *Une insertion non scellée est **indiscernable**
des 1460 autres : la chaîne dit « intacte », le compte dit 1460, et rien ne distingue
1460-légitimes de 1459+1.*

**Trajectoire mesurée** : **757 orphelins le 2026-08-23 → 1460 le 2026-09-03.** *La couverture double en
onze jours.*

---

## 2. ✅ Ce qui n'est PAS un défaut, et la session 4 l'a corrigé elle-même

**Elle allait écrire « la page annonce *intègre* pendant que 1460 lignes sont hors chaîne ». C'est faux.**

    'chaine_intacte' => "Chaîne intacte : :scellees lignes scellées,
                         :orphelines non scellées, tête = :tete"

**L'affichage nomme les deux nombres.** *Un exploitant qui lit voit « 4677 scellées, 1460 non scellées ».*
**Il n'y a aucune tromperie de présentation, et le dire protège le reste du dossier.**

**Et les gardes tiennent, vérifié** :

    GET  /journal-audit/verifier   role:3 + perm:can_admin_portal
    POST /journal-audit/sceller    role:3 + perm:can_admin_portal

*C'était un point ouvert de son relevé ; il est clos.*

---

## 3. Les sept écrivains NUS, et ce sont les mauvais

    ECRIVAINS NUS (INSERT sans les colonnes de hachage)
      legacy/profile.php                  3 sites
      legacy/auth/verify.php              1   <- L'AUTHENTIFICATION
      legacy/adm/api/update_user.php      1   <- modification d'utilisateur
      legacy/adm/includes/import_csv.php  2
      laravel/.../ExigePermission.php     1   <- REFUS de permission
      laravel/.../MotDePasse.php          1   <- changement de mot de passe

    ECRIVAINS SCELLES
      legacy/adm/includes/audit_log.php
      laravel : ComptesController · ServeursController · PermissionsController

> **Les événements hors chaîne sont précisément ceux qu'on voudrait forger ou masquer** : *une connexion,
> une modification d'utilisateur, un refus de permission, un changement de mot de passe.*

---

## 4. ⚠ Ce n'est PAS de la négligence — et c'est ce qui rend le remède plus large

**Les deux écrivains nus du portage DOCUMENTENT leur choix, avec une mesure :**

    MotDePasse.php:240   « la chaine n'est PAS calculee ici … Mesure du 2026-08-23 :
                           3368 lignes, dont 757 sans empreinte. Calculer la chaine
                           ici, seul, la casserait. »
    ExigePermission.php  « … que seul le scellage porte ouverte. Le legacy fait le
                           meme choix. »

**Chaque auteur a fait le même arbitrage local, et il est CORRECT** : *sceller seul dans une chaîne déjà
trouée la casserait vraiment.*

> **Une chaîne de hachage qu'un écrivain ne peut pas alimenter seul dégrade en une chaîne que plus personne
> n'alimente.** *C'est un défaut de conception du mécanisme, pas de discipline des auteurs — et aucun
> reproche individuel ne le corrigerait.*

---

## 5. Le geste exact — et l'ordre est le point

```
1. SCELLER    POST /journal-audit/sceller  (role 3 + can_admin_portal)
              `scelle()` scelle les orphelins avec la tete courante et
              CONSERVE le fail-closed.
              -> une fois la chaine complete, toute nouvelle ligne nue
                 redevient DISCRIMINANTE : c'est la propriete qui manque.

2. CORRIGER LES SEPT SITES D'ECRITURE
              -> sinon la population repart de zero et recroit au meme rythme
```

> **Sceller sans corriger les écrivains, c'est vider une baignoire dont le robinet coule.** *(formulation de
> la session 4)*

**Et l'ordre 1-puis-2 n'est pas indifférent** : *tant que la chaîne est trouée, un auteur qui scellerait
son propre site la casserait — c'est exactement le raisonnement qui a produit les sept sites nus.*
**Sceller d'abord LÈVE le blocage qui les a créés.**

---

## Ce qui n'est pas mesuré

- **l'insertion n'a PAS été exercée.** *La démontrer reviendrait à la commettre, sur le journal d'audit
  lui-même. Toute la chaîne est établie par LECTURE* ;
- **le relevé des écrivains vaut pour `INSERT INTO user_logs` LITTÉRAL.** *Un écrivain passant par un
  helper ou un ORM sous un autre nom échapperait à cette recherche — déclarée étroite par son autrice* ;
- **si une insertion nue malveillante a déjà eu lieu.** *Par construction, c'est ce que ce défaut rend
  indécidable — et c'est la raison pour laquelle il faut sceller maintenant plutôt que d'enquêter.*

---

# ⚠ 2026-09-04, 16:20 — LA MIGRATION VA DÉGRADER CETTE PROPRIÉTÉ, et mon compte d'écrivains était FAUX

## 1. MON CHIFFRE DE « 7 ÉCRIVAINS NUS » ÉTAIT MESURÉ PAR UN INSTRUMENT PARTIEL

    ce que je portais   7 ecrivains nus
    mesure du 04/09     25 ecrivains  ·  5 scellent  ·  20 ecrivent NU (80 %)
                          backend/ Python   11 ecrivains,  0 scellent
                          laravel/           6 ecrivains,  4 scellent
                          legacy/            8 ecrivains,  1 scelle
                                             <- `audit_log.php:118`, LE SEUL

**Mon relevé ne connaissait qu'une forme d'écriture. Il était aveugle au SQL brut
(`DB::insert('INSERT INTO user_logs …')`, présent dans le portage lui-même) et aux onze écrivains Python.**

## 2. LA MESURE EN BASE, VÉRIFIÉE DE MON CÔTÉ

    TOTAL             6240
    sans empreinte    1484   (23,8 %)
    avec empreinte    4756

    composition des lignes NON scellees :
      Connexion reussie                            389
      Permission refusee : can_admin_portal        281
      Permission refusee : can_scan_cve            156
      Permission refusee : can_view_compliance     141
      Permission refusee : can_manage_platform_key  59
      Mise a jour du mot de passe                   43
      Permission refusee : can_deploy_keys          43
      Permission refusee : can_manage_fail2ban      30

**⚠ Et ce que cette composition ajoute : les 710 lignes « Permission refusée » viennent
d'`ExigePermission.php:73` — un écrivain du PORTAGE, en SQL brut. Les 43 « Mise à jour du mot de passe »
viennent de `MotDePasse.php`, également le PORTAGE.**

> **Au moins 753 des 1484 lignes non scellées sont déjà écrites par le PORTAGE, pas par le legacy.**
> *Les 389 « Connexion réussie » ne sont pas attribuables au nom de l'action seul — les deux portails
> journalisent la connexion, et je ne le suppose pas.*

## 3. 🔴 LA CONSÉQUENCE, ET ELLE EST DE LA CLASSE « RIEN NE TOMBE »

    `legacy/adm/includes/audit_log.php:118` est le SEUL ecrivain SCELLANT du
    legacy, et il porte 21 arcs. Quand le legacy tombera, il tombera avec.

    apres l'extinction : le scellement a l'insertion n'existe plus que dans
    les 4 ecrivains Laravel. Les 11 ecrivains Python ne bougent pas.

> **La proportion de lignes non scellées ne diminuera pas avec l'extinction du legacy : ELLE VA
> AUGMENTER.** *Aucune suite ne rougit, aucune page ne casse, et une propriété d'intégrité du produit se
> dégrade sans qu'aucune mesure existante la surveille.*

## 4. ⛔ ET LE SCELLEMENT EST UN BOUTON MANUEL — donc la fenêtre est SANS BORNE

**Ce qui décide de la valeur de cette chaîne n'est pas le nombre d'écrivains scellants : c'est le DÉLAI
entre l'insertion et le scellement.** *Une ligne scellée tardivement est protégée contre les modifications
POSTÉRIEURES au scellement, pas contre celles qui l'ont précédé.*

**Un scellement déclenché à la main, avec un mode simulation, laisse cette fenêtre ouverte
indéfiniment — et personne ne la surveille.**

## 5. ✅ CE QUE JE TRANCHE (la direction), ET ⛔ CE QUI VOUS REVIENT (le geste)

    ⛔ NE PAS tenter de sceller dans chaque ecrivain.
       `MotDePasse.php:300-306` a raison et son commentaire le dit :
       « calculer la chaine ici, seul, la CASSERAIT ». Une chaine exige un
       ordre sequentiel ; 25 ecrivains dans trois langages ne peuvent pas le
       tenir. Vingt-cinq correctifs produiraient une chaine incoherente.

    ✅ LA DIRECTION JUSTE : fermer la FENETRE, pas multiplier les scelleurs.
       Un scellement PERIODIQUE reduit la fenetre a son intervalle et ne
       touche aucun ecrivain.

    📌 CE QUI VOUS REVIENT, ET POURQUOI :
       le mecanisme serait une tache d'ORDONNANCEUR — et l'ordonnanceur de ce
       depot tourne dans un fil INVISIBLE a `ps`, a deja tourne en quatre
       exemplaires, et son verrou de chef est recent. Y ajouter une tache
       est un geste sur un composant a l'historique charge, qui ne prend
       effet qu'au REDEMARRAGE.

**SI RIEN N'EST FAIT** : *l'extinction du legacy retirera le seul scelleur qu'il portait, la proportion de
lignes nues augmentera, et la chaîne d'audit continuera de rendre « intègre » — parce qu'elle ne mesure
que les lignes qu'elle a scellées.* **C'est le défaut le plus discret de ce dossier : une garde qui répond
juste sur un périmètre qui rétrécit.**

## 6. ⚠ ET UNE ACCUSATION A ÉTÉ ÉVITÉE — le détail vaut plus que le résultat

**La session 3 allait publier que `MotDePasse.php:300-306` MENTAIT (« le journal s'écrit nu, comme partout
ailleurs ») — huitième « en-tête qui ment » du chantier. Sa sonde voyait 5 écrivains dont 4 scellants :
dans ce cadre, `MotDePasse` était l'exception et son commentaire était faux.**

**Le commentaire dit VRAI. 80 % des écritures sont nues, et ce sont les 4 scellants qui sont l'exception.**

> **Une accusation se propage et fait « corriger » du code sain. C'est pire qu'un faux zéro.**

**⚠ Et ce qui l'a attrapée n'est pas un témoin — c'est un RESTE INEXPLIQUÉ : 710 lignes « Permission
refusée » que ses cinq écrivains n'expliquaient pas.**

> **« Le chiffre qui ne se referme pas est le meilleur détecteur d'instrument partiel — meilleur que le
> témoin, qui ne valide que la forme qu'on lui a donnée. »**

*C'est une correction à la règle que ce chantier applique depuis une semaine, et elle est juste : un témoin
positif prouve que l'instrument LIT, pas qu'il lit TOUT.*
