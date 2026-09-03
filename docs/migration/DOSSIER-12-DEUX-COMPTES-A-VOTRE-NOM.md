# DOSSIER 12 — Deux comptes à votre nom, dont un qui a tout accès sans aucune permission

**Pour décision de l'exploitant.** Mesuré par la session 4, complété et contre-contrôlé par moi le
**2026-09-02 vers 21:20 CEST**. *Ce dossier a changé d'objet en cours de mesure : la question de départ
était un durcissement de routes, et le fait qu'elle a fait apparaître est ailleurs.*

---

## 1. Le fait principal, et personne ne l'avait nommé

    id 78   role 3   AUCUNE ligne dans `permissions`   ->  ACCES COMPLET
    backend/routes/helpers.py:338   if role_id >= 3:  ->  court-circuite require_permission

> **Personne n'a décidé des permissions de ce compte. Le rôle a décidé à sa place.**
>
> *« Aucune ligne de permissions » se lit comme « ce compte n'est pas configuré » et se comporte comme
> « ce compte est pleinement autorisé ».*

**C'est le motif de tout ce chantier, appliqué au niveau du COMPTE** — *une même absence pour deux
états* :

| l'absence | état 1 | état 2 |
|---|---|---|
| `''` en base | vide | illisible |
| `None` pour un secret | absent | illisible |
| `never_connected` | rien ici | je ne sais pas |
| **aucune ligne de permissions** | **non configuré** | **tout permis** |

**Formulation de la session 4, que je reprends telle quelle.**

---

## 2. Les deux comptes, mesurés

    id 77   « Broussier Gaudéric »   role 2   cree 2026-08-27 16:50:37   aucune permission
    id 78   « Gaudéric Broussier »   role 3   cree 2026-08-27 16:50:45   aucune permission
                                                        ^^^^^^^^ HUIT SECONDES d'ecart, noms inverses

**Aucun des deux n'est référencé où que ce soit.** *Session 4 : zéro sur douze tables. Contre-contrôlé
par moi sur quatre, avec témoin :*

    table                  compte 77   compte 78   TEMOIN (id 1)
    user_logs                      0           0             869
    login_history                  0           0             863
    user_machine_access            0           0               1
    permissions                    0           0               1

**L'instrument mord** — le témoin rend des centaines de lignes. **Les zéros sont réels : ce sont deux
coquilles.** *Aucune session, aucune trace, aucune machine attribuée, aucun jeton.*

---

## 3. Les trois questions, et aucune n'est mesurable

    1. ces deux comptes sont-ils VOULUS, ou l'un est-il un doublon de creation ?
    2. si `77` doit servir, avec quelles permissions — il n'en a AUCUNE aujourd'hui ?
    3. et `78`, role 3 sans permissions : cet acces complet est-il DECIDE ou HERITE ?

> **Elles portent sur l'intention de qui a créé les comptes le 27 août à 16:50.** *C'est ce que vous
> détenez et que personne ici ne peut mesurer.*

---

## 4. Le durcissement qui a ouvert ce dossier

**Huit routes de `ssh_audit.py` ne gardent que le RÔLE, jamais la permission** — dont `POST /schedules`,
qui crée une **cron** de scan SSH, et `POST /policies`, *qui paraît traité et ne l'est pas* (voir §6).

    la population exposee est le role EXACTEMENT 2 sans `can_audit_ssh`
    -> un seul compte : id 77
    -> qui n'a jamais ouvert de session

**Le durcissement est donc gratuit aujourd'hui, et il ne le restera pas** : *le jour où `77` entre en
service sans permissions, il perd l'accès à des écrans qu'un rôle 2 est censé avoir.*

### ⚠ La session 4 a RETIRÉ sa recommandation, et sa raison mérite d'être lue

Elle recommandait *« accorder `can_audit_ssh` à 77 avant de durcir »*. **Elle l'a retirée :**

> *Ma recommandation supposait que le compte était en service. Il ne l'est pas. J'ai bien vérifié **à
> qui** le compte appartient — **et pas s'il servait.** Vérifier l'identité d'un compte ne dit pas s'il
> est en service : deux questions, deux mesures, et je n'en avais fait qu'une.*

---

## 5. Le geste exact, selon votre réponse

```
# ── CAS A : les deux comptes sont voulus
#   1. definir les permissions de 77 (INSERT — aucune ligne n'existe)
#   2. decider si l'acces complet de 78 est voulu, ou lui poser une ligne explicite
#   3. puis les huit @require_permission('can_audit_ssh')

# ── CAS B : l'un des deux est un doublon de creation
#   1. desactiver le doublon
#   2. les huit @require_permission, sans rien accorder
```

**Le diff des huit routes est mécanique** — une ligne par route. *La session 4 ne l'a délibérément **pas**
préparé : la file compte six correctifs inertes, et en ajouter un avant l'arbitrage l'allongerait sans
protéger personne.*

---

## 6. ⚠ Et une doctrine de sécurité dont la rédaction dit plus qu'elle ne fait

**`POST /ssh-audit/policies` est documenté en quatre endroits sous SEC-013**, traité par la « fermeture
par l'ABSENCE » : *la page n'émet que des `GET` et ne compose jamais ce `POST`.*

    RoutesBackend.php:115   '/ssh-audit/' est en LISTE BLANCHE de la passerelle
    -> POST /api/gateway/ssh-audit/policies passe, et le backend l'accepte sur le role seul

> **L'absence empêche la PAGE de composer l'appel. Elle n'empêche pas une requête forgée d'atteindre la
> route.** *SEC-013 protège contre l'exposition accidentelle, pas contre la requête forgée — et sa
> rédaction ne distingue pas les deux.*

**Trouvé par la session 3, qui a refusé d'amender SEC-013 elle-même** — *une règle de sécurité déjà
arbitrée ne se recopie ni ne s'amende seul.* **Ce dossier porte la question ; il ne la tranche pas.**

**Et le portail ne peut pas fermer cette route** : `correspond(string $chemin, …)` **ne reçoit jamais la
méthode**. *`/policies` GET et POST sont la même URL, et le GET doit rester ouvert — il est borné par
permission et par machine, et un rôle 1 le lit légitimement.* **Seul le backend peut distinguer.**

---

## 7. Ce qui se passe si on ne fait rien

    ssh_audit_schedules ..... 0 ligne
    compte 77 ............... 0 connexion, 0 trace sur douze tables
    compte 78 ............... idem, et acces complet par le role

**Rien ne se dégrade.** *Aucune cron n'existe, et les deux comptes dorment.*

> **Le risque n'est pas un incident : c'est qu'une décision se prenne par défaut.** *Le jour où `77`
> entre en service, ses droits seront ceux que personne n'a choisis. Le jour où quelqu'un d'autre reçoit
> un rôle 2, le trou des huit routes devient réel sans qu'aucune décision ne l'ait ouvert.*

**Et le `DOSSIER-02` propose deux comptes de rôle ≥ 2 de plus.** *Les deux dossiers se répondent :
celui-ci devrait être tranché avant celui-là.*

---

## Ce qui n'est pas mesuré

- **l'intention derrière les deux comptes.** *Le fait qui décide, et il n'est pas dans la base* ;
- **le chemin n'a pas été EXERCÉ.** *L'argument est de lecture — liste blanche du préfixe,
  `ADMIN_SEULEMENT` sans l'entrée, backend en `require_role(2)`.* **La session 3 a proposé de le mesurer
  en se connectant à un compte de rôle 1 ; je l'ai refusé** : ce compte est dans les interdits, et une
  connexion touche `login_attempts` et la fenêtre TOTP partagée ;
- **les routes des autres modules qui gardent le rôle seul.** *Le test n'a été appliqué qu'à `ssh_audit`.*
