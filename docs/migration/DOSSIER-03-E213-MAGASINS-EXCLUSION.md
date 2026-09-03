# DOSSIER 03 — E-213, les deux magasins d'exclusion

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**.

> ⚠ **Ce dossier CONTREDIT `PARITE.md` sur son point le plus lourd, et la mesure va dans le sens
> rassurant — donc dans celui que personne ne vérifie.** `PARITE.md` appartient au Lead ; l'entrée
> E-213 et le §4.3 bis du plan sont à corriger.

---

## 1. Recommandation

**Ne pas unifier les deux magasins. Faire LIRE les deux par `delete_remote_user`**, le seul chemin de
suppression vivant, avec un `force` explicite — **et retirer `clean_up_users` du dépôt.**

> ⚠ **Révision du 2026-08-28, sur mesure de la session 2.** Ma première recommandation était *« porter
> le geste `/exclude_user` à côté du classement »* — l'issue n°2 des trois qu'E-213 proposait. **Elle
> est retirée : `user_exclusions` n'a AUCUN lecteur vivant**, donc la porter aurait ajouté un second
> mot décoratif à côté du premier. Détail au §3.2.

**Aucune des trois issues d'E-213 n'était donc la bonne** — et ce n'est pas un reproche à qui les a
écrites : les trois supposaient qu'un des deux magasins était lu. *Quand deux options se partagent une
prémisse fausse, en choisir une est encore la suivre.*

**Ce que je ne recommande PAS : unifier.** C'était l'issue qui rendait ce dossier non délégable, parce
qu'elle *« change ce qui est détruit sur des machines réelles »*. **Mesuré, elle ne changerait rien de
ce qu'on croyait** — et elle ferait porter à `user_exclusions` une charge que rien ne lit.

---

## 2. Conséquence, mesurée — et la prémisse d'E-213 est fausse

### Ce qui reste vrai, et c'est le défaut

    user_exclusions                   0 ligne          <- ecrit par /exclude_user SEULE
    server_user_inventory.status='excluded'   69 lignes  <- ecrit par classify, classify_bulk, scan

**Le magasin que la décision de suppression lit est VIDE ; celui que l'interface remplit porte 69
lignes.** Le mot `excluded`, affiché sur 69 comptes, n'a d'effet sur **aucun** chemin de suppression
vivant. *Perdre un bouton se voit ; le remplacer par un bouton qui a l'air de faire la même chose ne se
voit pas.* **Ce constat-là tient entièrement.**

### ⚠ Ce qui est FAUX : « un déploiement exécuterait `userdel -r` »

    grep -rn "clean_up_users" (hors _deprecated)
      backend/configure_servers.py:703   <- une mention dans une DOCSTRING
      backend/configure_servers.py:780   <- sa propre definition
      -> AUCUN APPELANT

    configure_servers.py:770-774, dans `configure()` :
      # Le nettoyage automatique des utilisateurs est DESACTIVE.
      # La suppression de comptes se fait uniquement depuis
      # Administration > Utilisateurs distants (action explicite).
      # Le deploiement ne fait que deployer/retirer les cles SSH.
      self.configure_users(root_channel)

> **`clean_up_users` est du code MORT. Un déploiement K4 n'exécute aucun `userdel`.** La séquence de
> déploiement appelle `configure_users` et elle seule.

**Et ce n'est pas le commentaire qui l'établit** — un commentaire qui affirme moins de danger que le
code est exactement la forme qu'on ne vérifie pas. C'est le **comptage des appelants**, sur tout le
dépôt, qui le dit ; le commentaire ne fait que concorder. **La docstring de `:703`, elle, annonce
toujours `clean_up_users` dans la séquence : c'est le seul texte du fichier qui soit faux.**

### Ce qui en découle, et il faut le dire aussi nettement qu'une accusation

**« K4 reste bloqué, et ce blocage est désormais PROTECTEUR » est sans objet.** Le blocage de K4 tient
sur ses **autres** fondements, qui sont mesurés et intacts :

| fondement de K4 | état |
|---|---|
| l'arbitrage `NOPASSWD: ALL` | **intact** |
| la révocation de clés sur la production | **intacte et VIVANTE** — `configure_users` est appelée, et `configure_servers.py:908-909` fait `revoked = managed_users - comptes_traites` puis `rm -f …/authorized_keys` sur `Timikana` et `claude-agent`, deux comptes que RootWarden ne peut pas rétablir |
| ~~`userdel -r` sur les comptes `excluded`~~ | **retiré — code mort** |

> *Un interdit qui repose sur quatre fondements dont un est faux se fait démolir sur le faux.* Retirer
> celui-ci **renforce** l'interdit au lieu de l'affaiblir — c'est exactement ce qui a été fait pour
> E-216 sur « RootWarden ne peut plus administrer `srv-zabbix` ».

### Ce que le geste vivant fait, lui

`delete_remote_user` (`ssh.py:2648`) — `@require_role(2)`, un compte à la fois, depuis
*Administration → Utilisateurs distants*. **Lu ligne à ligne : il ne consulte NI `user_exclusions` NI
`server_user_inventory.status`.** Ses gardes sont `_validate_username`, six noms système, `machines.user`,
le compte de service, et `gate()`.

> **Donc le défaut d'E-213 survit à la correction de sa prémisse, sous une forme plus étroite et
> toujours réelle : `excluded` ne protège d'aucun chemin, y compris du seul qui soit vivant.**

### Combien de comptes sont réellement en jeu : **un**, et il n'est pas `excluded`

Ma première mesure a rendu **52 comptes menacés**. **Elle était fausse d'un facteur 26**, et la faute
est celle que le §8 décrit : j'avais pris l'**inventaire** pour l'entrée du script. Le script bâtit sa
liste **depuis la machine** —

    configure_servers.py:813   awk -F: '$3 >= 1001 {print $1}' /etc/passwd

— donc les UID < 1001 n'apparaissent jamais. **Les 69 lignes `excluded` sont à 67 des comptes système**,
et les deux restants sont `nobody` (UID 65534) sur deux machines, **déjà dans les six noms protégés**.

**Inventaire complet des comptes à UID ≥ 1001 du parc, les cinq :**

| machine | compte | uid | statut | ce qu'un déploiement ferait |
|---|---|---|---|---|
| `srv-zabbix` (PROD) | `Timikana` | 1001 | `managed` | **clé retirée** — `rm -f authorized_keys`, non rétablissable |
| `srv-zabbix` (PROD) | `claude-agent` | 1002 | `managed` | **clé retirée**, idem |
| `srv-zabbix` (PROD) | `nobody` | 65534 | `excluded` | rien — nom protégé |
| `Test-Server-Debian` | `nobody` | 65534 | `excluded` | rien — nom protégé |
| **`OpenCVE-Test-OnPrem`** | **`Timikana`** | **1001** | **`pending_review`** | **rien aujourd'hui** — et *tout* si `clean_up_users` redevenait appelable |

> **Le seul compte que l'unification aurait protégé n'est pas `excluded` : il est `pending_review`.**
> Unifier les deux magasins ne l'aurait donc pas couvert. *La correction proposée ne rencontrait pas le
> cas qui existe.*

---

## 3. Le geste exact

**Rien à exécuter sur une machine. Trois écritures dans le dépôt, aucune destructrice.**

**1. Retirer le code mort — session 4, `backend/configure_servers.py` :**

```
supprimer  la methode `clean_up_users` (:780-857)
corriger   la docstring :703, qui l'annonce encore dans la sequence
```

> **Ou l'inverse — la rendre appelable — mais alors ce dossier redevient non délégable** et il faut
> d'abord unifier les magasins. *Un `userdel -r` à un appel de distance, décrit par une docstring comme
> faisant partie de la séquence, est la configuration exacte où quelqu'un « restaure » un oubli.*
> **Ma recommandation est de le retirer.**

**2. ⚠ CORRIGÉ le 2026-08-28 — NE PAS porter `/exclude_user`. Le rendre EFFECTIF sur le chemin vivant.**

> **Ma recommandation initiale était « porter `/exclude_user` à côté du classement — deux notions
> visibles au lieu d'une trompeuse ». Elle est retirée, sur mesure de la session 2, vérifiée :**
>
>     ecrivains de user_exclusions   admin.py:129  (/exclude_user, INSERT IGNORE)
>     LECTEURS                       configure_servers.py:805  -- et SEULEMENT lui
>                                    or :805 est DANS clean_up_users (:780-857), qui n a aucun appelant
>
> **`user_exclusions` n'a aucun lecteur vivant.** Le bouton « Exclure » de `platform_keys.php:458` est
> visible, documenté (`documentation.php:390` le décrit nommément), il écrit — **et rien ne lit.**
> *Porter ce geste aurait ajouté un SECOND mot décoratif à côté du premier* : deux boutons qui ne
> protègent de rien, dont un que j'aurais recommandé d'ajouter.

**La décision qui remplace, et elle est du même ordre qu'E-224** : *rendre `excluded` vrai sur le seul
chemin qui détruise.*

```
backend/routes/ssh.py, `delete_remote_user` — session 4

  avant toute session SSH, apres les cinq gardes existantes :
    le compte est-il present dans `user_exclusions` (machine_id, username)
    OU porte-t-il `server_user_inventory.status = 'excluded'` ?
      -> REFUS, sauf `force: true` explicite
      -> et le refus DIT lequel des deux magasins l a marque, et quand
```

**Trois raisons, dans cet ordre :**

1. **c'est le seul geste vivant**, donc le seul endroit où le mot peut devenir vrai. Le rendre effectif
   là coûte une lecture ; l'annoncer ailleurs ne coûte rien et ne protège rien ;
2. **il lit les DEUX magasins, et ce n'est pas une unification.** Chacun garde son écrivain ; c'est le
   *lecteur* qui consulte les deux. Ne lire que `user_exclusions` protégerait **0 compte** (table vide) ;
   ne lire que `status` ignorerait le bouton. *Avant d'unifier deux copies, vérifier qu'elles valident la
   même chose* — ici elles disent la même chose (« ne touche pas à ce compte »), donc les lire ensemble
   est juste, et les fusionner serait détruire l'une des deux ;
3. **une garde qui n'ajoute qu'un REFUS ne peut pas détruire davantage.** C'est le précédent d'E-224,
   délégué pour cette raison exacte : une borne fail-closed sur un geste destructeur est une décision de
   conception, pas un arbitrage sur des données.

**Et la réserve qui vient avec, parce qu'elle a déjà mordu ici** : *un garde-fou qui se déclenche à tort
ne protège plus, il empêche* — `stopped_at_tamper` a rendu le seul remède au trou d'audit définitivement
inerte. **D'où le `force` explicite**, qui est déjà le motif de la maison : `server_user_remove_key`
refuse la clé de plateforme sans `force` et dit pourquoi. **Et le refus doit NOMMER sa cause** — sinon
l'exploitant ne peut pas distinguer « refusé parce qu'exclu » de « refusé parce que je n'ai pas le
droit ». *Deux causes, un même vide.*

**3. Dire ce qui est vrai — session 3, i18n FR/EN dans le même commit :**
le classement `excluded` **n'a aucun effet distant** ; il documente une intention. `ComptesDistants.php:29`
le dit déjà pour le classement, et *c'est exact sur son périmètre et trompeur sur celui qui compte* :
la phrase doit nommer **ce qui protège**, pas seulement ce que le classement ne fait pas.

**Contrôle, en lecture :**

    SELECT COUNT(*) FROM user_exclusions
    SELECT status, COUNT(*) FROM server_user_inventory WHERE uid >= 1001 GROUP BY status
    grep -rn "clean_up_users" --include=*.py . | grep -v _deprecated

---

## 4. Ce qui se passe si on ne fait rien

**Rien ne se détruit, et c'est le changement le plus important de ce dossier.** Mais trois choses
restent, et la troisième est celle qui coûte.

1. **69 comptes portent un statut qui ne protège de rien**, dont aucun n'est aujourd'hui menacé. Le mot
   reste faux et il ne coûte rien tant que personne ne s'y fie ;
2. **`user_exclusions` reste vide**, donc le jour où un chemin de suppression le lira, il ne protégera
   personne — et l'interface qui le remplit n'est pas portée ;
3. **⚠ `clean_up_users` reste à UNE LIGNE d'être vivant, et sa docstring l'annonce déjà.** C'est le
   vrai risque de l'inaction : quelqu'un lit `:703` — *« Nettoyer les utilisateurs non autorisés
   (clean_up_users) »* — constate que l'appel manque, et le « rétablit ». **Ce jour-là, `userdel -r`
   part sur tout compte à UID ≥ 1001 non autorisé et non exclu, et `user_exclusions` étant vide, la
   seule protection restante est la liste des six noms système.**

> **Le danger n'est plus dans le code : il est dans le texte qui le décrit.** *Une garde conditionnelle
> sur du code mort répond quand même* — ici c'est l'inverse et c'est pire : **une docstring décrit un
> geste que le code ne fait pas, et elle invite à l'ajouter.**

**Et ce qui se périme si on attend** : cette mesure. `clean_up_users` n'a aucun appelant **au
2026-08-28**. Un appel ajouté ailleurs ne rougirait dans aucune suite — *aucune suite n'assère qu'une
méthode reste sans appelant.*

---

## Ce qui n'est pas mesuré

- **que les comptes de l'inventaire existent réellement sur les machines.** C'est l'inventaire qui est
  lu, pas `/etc/passwd` — et E-187 établit que cet inventaire peut être faux. `last_seen_at` vaut
  `2026-08-18` pour `srv-zabbix` : la donnée est **cohérente, elle n'est pas confirmée** ;
- **le comportement de `configure_users` en exécution.** Établi par lecture ; aucun déploiement n'a été
  lancé ;
- **si `/exclude_user` est atteignable depuis une page vivante** — la route existe, son interface n'a
  pas été cherchée.
