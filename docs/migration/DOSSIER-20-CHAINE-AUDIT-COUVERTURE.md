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
