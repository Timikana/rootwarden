# Décisions du DSI délégué — session 8

**Ouvert le 2026-08-28.** Charte au **§7.0 de `PLAN-DE-MIGRATION.md`**. Ce document porte les
**sept arbitrages délégués**, tranchés, **plus un huitième né d'une mesure**. Les huit qui ne peuvent
pas l'être vivent dans les `DOSSIER-*.md`, une page chacun.

> **La ligne de la charte :** *ce qui se défait d'un clic est délégué ; ce qui détruit, retire un accès
> ou publie ne l'est pas.* Aucune décision de ce document n'écrit sur une machine, ne redémarre un
> service, n'applique une migration, ne pousse ni ne fusionne.

**Les mesures de ce document sont DATÉES INDIVIDUELLEMENT, en UTC.** L'en-tête annonçait d'abord
« toutes entre 06:40 et 06:55 » — **c'était vrai à l'ouverture et faux deux heures plus tard**, quatre
révisions ayant suivi. *Un fait sans heure est une opinion sur le passé*, et à sept sessions qui
commitent en continu, un relevé est une **photographie** et non un état. Les conteneurs sont en **UTC**,
l'hôte et le navigateur en **CEST** : E-73 a déjà fait mal décider sur ces deux heures.

**Six de mes propres écrits ont été retournés par la mesure en une journée** — cinq par des pairs, un
par moi. Chacun est marqué à l'endroit où il était faux, jamais effacé : *un document qui efface ses
erreurs ne permet pas de savoir laquelle des deux versions on a lue.*

**Le sixième n'est pas de la même nature que les cinq autres, et c'est le seul qui compte vraiment** :
les cinq étaient des lectures fausses — une prémisse, un chiffre, une recommandation. **Le sixième est
une vérification affirmée et non faite.** *Une erreur de lecture se corrige en relisant ; une
vérification omise ne se corrige qu'en refaisant le geste, et rien ne signale son absence.*

---

## Table des dix

| # | arbitrage | décision | ce qu'elle coûte |
|---|---|---|---|
| 1 | portée du tableau de bord | **bornée au périmètre** | `opsuser` voit 1 machine au lieu de 3 |
| 2 | E-221 — accorder les 4 permissions | **n'en accorder AUCUNE** — la prémisse est fausse | rien ; et une fixture est sauvée |
| 3 | E-209 · E-212 · E-219 — textes faux | **corriger, et E-219 avec son remplacement** | trois chaînes × deux langues, plus une docstring |
| 4 | E-225 — dépôt tiers laissé par la désinstallation | **le DIRE** (issue 1), ne pas le retirer | une phrase dans la réponse |
| 5 | E-208 — les 3 pages qui ne bornent pas | **borner dans le PORTAGE, ne pas toucher le legacy** | rien : zéro porteur mesuré |
| 6 | E-224 — borne d'`install_all` | **`machine_ids` obligatoire**, 400 si absent ou vide | le bouton « installer sur tous » envoie sa liste |
| 7 | E-222 — `UNIQUE (server_id)` | **écrire la migration**, ne pas l'appliquer | `DOSSIER-06` pour la signature |
| **8** | **neuve** — écrire d'autres correctifs backend avant le redémarrage | **GEL** jusqu'au redémarrage | vingt items justes attendent ; le lot cesse de grossir |
| **9** | E-233 — le proxy legacy autorise par préfixe | **ne rien resserrer** ; le portage l'a déjà fait, mesuré | rien : surface d'accident **nulle**, et le défaut meurt avec le legacy |
| **10** | E-237 — l'état persisté d'`uninstall` Wazuh | **lire `code_v`, écrire `unknown`** — ⚠ ma 1re version demandait une migration, retirée | rien : la valeur est déjà au schéma et déjà rendue |
| — | E-234 — porter la console d'API du legacy | **NON** — elle ne se porte pas | la page ferme par l'**archivage**, pas par un correctif |
| **11** | E-242 — le troisième état de `supervision_agents` | **écrire la colonne**, la joindre à 063, **une seule signature** | rien : la table est **vide**, et la fenêtre se ferme au premier agent |

---

## 1 — La portée du tableau de bord : **bornée au périmètre**

### La décision

Le tableau de bord porté affiche l'état du parc **borné au périmètre du compte**. Un rôle 1 voit ses
machines ; un rôle ≥ 2 voit tout, `check_machine_access` rendant `True` sans condition dès ce rôle.

**L'exploitant a tranché la direction le 2026-08-28** — *« il faut déprécier complètement le legacy,
il ne doit plus exister, donc il faut tout migrer : dashboard, fonction, api, documentation »*. Cela
ferme l'issue n°3 (deux vues) : elle reporte la décision de droits au lieu de la prendre, et il a
demandé de **finir**. Il restait à choisir entre borner et reproduire.

### Pourquoi borner, et pas reproduire

- **le legacy n'a pas de règle à reprendre.** E-208 le mesure : **2 pages sur 5 bornent, 3 non**. *Un
  portage fidèle ne peut pas trancher une incohérence de l'original* — mais ici il n'y a pas d'original
  cohérent à suivre, donc « fidèle » ne désigne rien ;
- **les deux pages qui bornent sont celles de sécurité** (`fail2ban`, `iptables`). La section
  `securite` est neuve et le plan la nomme « l'identité du produit » : borner suit le produit qu'on
  construit, pas celui qu'on démonte ;
- **reproduire la fuite contredirait deux pages livrées** et il faudrait ensuite la retirer, c'est-à-dire
  reprendre aux comptes une visibilité qu'on vient de leur donner. *Un droit accordé se reprend plus
  mal qu'il ne s'accorde.*

### Ce que ça coûte, mesuré et non estimé

    id  compte                machines au perimetre
     2  opsuser                 1  (srv-zabbix)
     3,4,5,10,12  e2e_test_*    0
    14  rw-test-user            0

**Un seul compte réel est concerné : `opsuser`.** Il verrait **1** machine au lieu de 3 — et les deux
qu'il perd de vue sont deux machines auxquelles il n'a **aucun accès**. Les six autres rôles 1 sont
cinq résidus d'épreuve et la fixture `rw-test-user`, dont le périmètre vide **est** la fixture.

> **Le coût annoncé — « retire une visibilité aux rôles 1 » — est réel et il vaut deux lignes de
> tableau pour un compte.** C'était l'argument le plus lourd contre cette issue ; mesuré, il ne pèse
> presque rien.

**Remesure :** `SELECT u.id,u.name,COUNT(a.machine_id) FROM users u LEFT JOIN user_machine_access a ON
a.user_id=u.id WHERE u.active=1 AND u.role_id=1 GROUP BY u.id`

### La borne qui accompagne la décision

**Le compteur global n'est pas interdit — il est interdit *sans son détail*.** Ce que l'issue n°3
proposait de bien est repris ici sans son coût : un compte qui ne voit qu'une machine sur trois doit
**savoir** que le parc en compte trois, sinon le tableau de bord ment par omission au lieu de fuir. La
forme retenue : *« 1 de vos machines · 3 au parc »*. Un nombre qui décrit un ensemble qu'on ne peut pas
détailler n'est pas une fuite ; un nombre présenté comme le total de ce qu'on voit, si.

> **⚠ DEUX RAFFINEMENTS QUE MA BORNE NE DISAIT PAS, imposés par la mesure de la session 3 au portage
> (2026-08-28, `572316c`). Ils sont adoptés :**
>
> 1. **la réserve ne s'affiche QUE si la borne mord.** Un rôle ≥ 2 voit le parc entier : lui montrer
>    « vous ne voyez que vos machines » serait une **réserve sans objet**, et *une réserve sans objet
>    devient un décor qu'on ne lit plus* — donc elle affaiblit celles qui en ont un. Le second nombre
>    disparaît avec elle : « 3 · 3 » n'apprend rien ;
> 2. **une base injoignable n'est pas un parc vide.** Ma forme suppose **deux nombres lisibles**. Sur un
>    échec de lecture, rendre `0 · 0` se lirait comme un **fait** : l'écran doit **dire** qu'il n'a pas
>    su lire. C'est exactement le défaut d'E-217 pris par l'autre bout — *« je ne sais pas » déguisé en
>    « c'est vrai »*.
>
> **La seconde est celle que j'aurais dû écrire moi-même** : j'ai passé la matinée à mesurer que
> `[].every()` est vrai sur l'ensemble vide et qu'une énumération vide satisfait toute propriété
> universelle, **et j'ai proposé une forme d'affichage qui prend un zéro pour une mesure.**
>
> **Et le bornage lui-même est REPRIS, pas réécrit** — le prédicat vient de `pourMisesAJour`,
> `Iptables::machines` et `Fail2ban::machines`. *Trois implémentations d'une même règle finiraient par
> diverger* : c'est la règle du chantier appliquée au moment où elle coûte le moins.

**Et les douze tuiles de raccourci ne dépendent pas de cet arbitrage** — elles reprennent les gardes du
menu. Elles se posent sans attendre quoi que ce soit de ce document.

---

## 2 — E-221 : **n'accorder aucune des quatre permissions**, et la raison est que la prémisse est fausse

> ⚠ **Précision de référence, avant tout le reste.** Le message qui m'ouvre ce poste nomme cet
> arbitrage « E-221 », et le §7.0 aussi. **E-221 dans `PARITE.md` est autre chose** : les 28 routes
> d'`updates/` sans rôle ni permission, dont la décision écrite est *« NE PAS l'écrire maintenant »*.
> La tâche déléguée est **`AVANT-LE-REDEMARRAGE.md` §1 et §3.1**. Les deux sont liés par le
> redémarrage et par rien d'autre. *Une décision écrite sous une mauvaise référence s'applique un jour
> au mauvais objet* — et celle-ci dit « n'accordez rien » pendant que l'autre dit « n'écrivez rien ».

### Ce qui a été demandé, et ce que j'ai mesuré avant de le faire

La demande : *« Après le redémarrage, aucun compte non-administrateur ne pourra plus toucher au
pare-feu (…) il frappera des pages qui marchaient le matin. Décide qui doit les recevoir, et
fais-le. »*

**Les quatre chiffres de la session 4 sont exacts, recomptés colonne par colonne :**

    permission              detenue par   sur 9 comptes de role < 3
    can_manage_iptables         0
    can_manage_fail2ban         1          <- rw-test-admin (id 15), le seul porteur des trois
    can_manage_services         1
    can_audit_ssh               1

**Et la phrase qu'ils soutiennent est fausse.** *Les pages ne marchaient pas ce matin non plus.*

    legacy/fail2ban/index.php:11    checkPermission('can_manage_fail2ban')
    legacy/iptables/index.php:46    checkPermission('can_manage_iptables')
    legacy/ssh-audit/index.php:13   checkPermission('can_audit_ssh')
    laravel/routes/web.php:725      middleware(['role:1','perm:can_manage_iptables'])
    laravel/routes/web.php:755      middleware(['role:1','perm:can_manage_fail2ban'])
    laravel/routes/web.php:777      middleware(['role:1','perm:can_manage_services'])

    legacy/auth/verify.php:322      if ($roleId === 3) return true;    <- contournement au ROLE 3 SEUL

> **Sur les deux portails, la page exige déjà exactement la permission que la route s'apprête à
> demander.** Un compte de rôle < 3 qui ne la détient pas ne peut ouvrir **aucune** de ces pages
> aujourd'hui. Le durcissement ne retire donc **aucun chemin d'interface** : il ferme l'écart entre la
> page et la route, c'est-à-dire exactement le trou qu'E-149 et E-152 ont relevé.

### Les 9 comptes, un par un — et pourquoi aucun ne doit rien recevoir

| id | compte | rôle | ce que c'est | décision |
|---|---|---|---|---|
| 15 | `rw-test-admin` | 2 | compte d'épreuve, **13 suites en dépendent** | **rien**, et voir l'encadré |
| 77 | `Broussier Gaudéric` | 2 | compte réel, **aucune ligne dans `permissions`** | **rien** — il ne perd rien, il n'a rien |
| 2 | `opsuser` | 1 | compte réel, aucune permission, seule machine `srv-zabbix`, **sans second facteur** | **rien** |
| 3, 4, 5, 10, 12 | `e2e_test_*` | 1 | résidus d'épreuve, sans second facteur | **rien** |
| 14 | `rw-test-user` | 1 | **D-5, ne pas toucher** — zéro permission **est** la fixture | **rien** |

> ⚠ **ET SURTOUT : NE PAS ACCORDER `can_manage_iptables` À `rw-test-admin`.** C'est le geste que la
> formulation de la demande rend le plus naturel, et c'est celui qui coûterait le plus.
>
> Le plan établit que le seul chemin qui **discrimine** la garde `permission OU rôle ≥ 3` est **un
> rôle 2 SANS la permission → 403**, et que ce chemin n'existe pour aucune des permissions de
> `fail2ban` — `rw-test-admin` la détient, donc les cinq suites `f2`→`f6` resteraient vertes *si le
> correctif n'était jamais appliqué comme si on l'appliquait de travers*.
>
> **Pour `iptables`, cette fixture existe : `rw-test-admin` est rôle 2 et ne détient pas
> `can_manage_iptables`.** C'est la seule du parc, et `iptables` est le module que la session 5 porte
> en ce moment. La lui accorder détruirait, la veille de I1→I5, le seul moyen de mesurer que la garde
> mord.

### ⚠ Ce que le redémarrage casse RÉELLEMENT, et qu'aucune permission accordée ne répare

**Trouvé en vérifiant le dernier maillon** — `checkPermission` lit une **troisième** source.

    legacy/auth/verify.php:329-337   SELECT 1 FROM temporary_permissions WHERE user_id=? AND permission=? AND expires_at > NOW()
    laravel/app/Services/Droits.php:64        idem
    laravel/app/Services/Permissions.php:155  idem

    backend/routes/helpers.py        SELECT * FROM permissions WHERE user_id = %s     <- UNE SEULE TABLE

> **Les deux pages acceptent une permission TEMPORAIRE ; le backend ne la voit pas.** Après le
> redémarrage, un compte porteur d'un `can_manage_fail2ban` temporaire **ouvre la page** et prend
> **403 sur les dix-huit routes**. Une page qui s'affiche, des boutons qui échouent tous, et rien à
> l'écran qui l'explique.

**Et le backend le sait déjà, et l'a refusé une fois** — `backend/routes/ssh.py:422-431`, sur le choix
de garder `role(2)` plutôt qu'une permission sur `POST /deploy` :

> *« La permission serait le miroir exact de la page — et elle CASSERAIT un chemin légitime. La page
> accepte les permissions TEMPORAIRES (…) tandis que le backend lit (…) les PERMANENTES seules. Un
> compte dont la permission est temporaire passerait la page et serait refusé ici. »*

**Les 33 routes d'E-149 et E-152 reproduisent exactement le problème que l'auteur de `/deploy` a refusé
de créer.** Ce n'est pas un défaut de leur correctif : c'est une divergence de sources qu'aucun des deux
côtés ne peut fermer seul, et que personne n'avait rattachée au redémarrage.

**Porteur aujourd'hui : aucun.** `temporary_permissions` est **vide**. C'est donc un écart réel et sans
porteur — *une propriété qui tient par l'état du parc n'est pas une propriété* — et il s'ouvre au
premier octroi temporaire, qui est un geste d'administration ordinaire, offert par l'interface.
**Remesure : `SELECT COUNT(*) FROM temporary_permissions WHERE expires_at > NOW()`.**

C'est porté au **`DOSSIER-01`**, parce que le remède touche le backend et prend effet au redémarrage.

### Les chiffres du dossier de la session 4, recomptés — et ils sont plus gros

`AVANT-LE-REDEMARRAGE.md` annonce « 26 routes gagnent une permission, une en gagne une autre », et sa
propre table en additionne 29 (5 + 15 + 8 + 1). **Mesuré en comptant des BLOCS DE DÉCORATEURS et non des
occurrences** — un `require_permission` peut vivre ailleurs que sur une route :

    module        en service   arbre    nouvelles
    iptables           1          7        +6
    fail2ban           1         19       +18
    services           0          8        +8
    ssh_audit          0          1        +1
                                          ---
                                          +33

**Régime de cette mesure, et il faut le dire** : « en service » est reconstruit depuis
`47e5f11`, dernier commit de `backend/routes/` antérieur au `StartedAt`. **Or un redémarrage publie
l'ARBRE, pas l'historique** — donc c'est un *proxy*, pas une lecture du serveur. Ce qui est **mesuré
sans proxy**, en revanche, c'est l'inertie elle-même : `StartedAt = 2026-08-27T12:28:43Z`, et les quatre
fichiers portent un `mtime` postérieur (18:10 la veille, 06:14 ce matin). **Aucun redémarrage n'a eu
lieu depuis la rédaction du dossier** — vérifié, parce que `docker ps` affichait « Up 18 hours » là où
le dossier datait le démarrage de la veille à midi, et que l'écart méritait une remesure plutôt qu'une
inférence.

**Le chiffre ne change aucune décision** — ni qui reçoit quoi, ni s'il faut redémarrer. Il change la
**taille** de ce qu'on met en service d'un coup, et c'est ce que le `DOSSIER-01` doit porter.

### Et la seconde population que le dossier ne nomme pas : la clé d'API seule

`get_current_user()` rend **`(0, 0)` avec des permissions vides** quand `X-User-ID` est absent
(`helpers.py:199-201`). Un appelant authentifié par **clé d'API seule** tomberait donc en 403 sur les 33
routes — et **aucune permission accordée dans l'interface ne le réparerait**, puisqu'une permission
s'attache à un `user_id`.

**Mesuré : cette population est vide.** Une seule clé active,
`proxy-internal-legacy-bootstrap-20260526`, `last_used_ip = 172.18.0.4` = le conteneur `rootwarden_php`,
qui transmet toujours `X-User-ID` (`api_proxy.php:87`) — comme la passerelle du portage
(`PasserelleController.php:108`). **Le fail-closed est ici la bonne conception** ; il n'y a rien à
corriger, seulement à savoir avant d'émettre une clé à un consommateur extérieur.
**Remesure : `SELECT name,last_used_ip FROM api_keys WHERE revoked_at IS NULL`.**

### ✅ CONFIRMÉ PAR UNE MESURE VENUE POUR ME CONTREDIRE — 2026-08-28, 08:17 UTC

**La session 4 a classé les quatre permissions par USAGE RÉEL plutôt que par écart de détention** — bonne
méthode, et elle a rendu une conclusion alarmante :

    iptables    0/9 detenteurs    0 action
    ssh-audit   1/9               0
    fail2ban    1/9              22        <- « un compte qui s en servait la veille »
    services    1/9               8

> *« Le redémarrage retire une capacité à un compte qui s'en servait la veille. »* Et la recommandation
> qui suivait : **deux permissions à accorder avant le redémarrage suffiraient à supprimer tout
> l'impact observable.**

**Mesuré moi-même. Les 30 lignes sont 30 REFUS.**

    SELECT LEFT(action,110), COUNT(*) FROM user_logs WHERE user_id = 14
      AND (action LIKE '%fail2ban%' OR action LIKE '%service%') GROUP BY 1

    Permission refusee : can_manage_fail2ban    22
    Permission refusee : can_manage_services     8

**Aucune action réussie. Ce sont les lignes que `checkPermission` écrit quand elle REFUSE.** Et le
compte est **`rw-test-user` (id 14)** — rôle 1, zéro permission, **D-5 : ne pas toucher** —, la fixture
dont le rôle *est* d'être refusée. Les 30 lignes, du 2026-08-26 22:30 au 2026-08-27 16:23, sont des
exécutions de suites.

> **La phrase s'inverse mot pour mot** : ce compte a été refusé trente fois **par la garde qui existe
> déjà**. Les 30 lignes ne contredisent pas ma décision — **elles la prouvent.**

**Et la recommandation aurait fait accorder `can_manage_fail2ban` et `can_manage_services` à la fixture
D-5**, dont plusieurs suites mesurent le « rôle 1 → 403 ». **Deuxième fois de la journée qu'une
recommandation bien intentionnée aurait détruit une fixture de garde**, après `can_manage_iptables` sur
`rw-test-admin`. *Les deux fois, la formulation partait d'un chiffre réel et sautait la question « à qui
appartient ce compte ».*

**Le mécanisme est celui du §8, et c'est le plus coûteux** : *un observable ne dit jamais par quel chemin
il a été produit.* Un `COUNT(*)` de lignes `user_logs` contenant « fail2ban » ne distingue pas un geste
d'un refus — et il s'est trompé **du côté qui alarme, donc du côté qui fait agir.**

**La méthode reste la bonne** : appliquée à la bonne donnée, le classement par usage rend **zéro usage
sur les quatre permissions**, ce qui est plus fort que ce qu'elle annonçait.

### La décision, en une ligne

> **Aucune permission n'est accordée. Le durcissement ne retire aucun accès d'interface : les pages
> portent déjà la garde que les routes s'apprêtent à porter.** La tâche de configuration « à faire
> avant, pas après » n'a pas d'objet — *et les deux gestes qu'elle appelait le plus naturellement,
> `can_manage_iptables` à `rw-test-admin` puis `can_manage_fail2ban`/`can_manage_services` à
> `rw-test-user`, auraient détruit les DEUX fixtures de garde du parc.*

**Ce que je n'ai pas mesuré, et qui reste :** que les 33 routes se comportent comme prévu une fois en
service. Personne ne l'a mesuré — c'est l'objet du `DOSSIER-01`, et c'est le vrai risque du lot.

---

## 3 — E-209, E-212, E-219 : corriger les textes faux, et E-219 **avec son remplacement**

*Corriger un texte faux ne détruit rien ; le laisser, si.* Les trois sont servis en production. Aucun
n'est un geste : ce sont des chaînes et une docstring.

### E-209 — le guide de la clé de plateforme

    legacy/lang/{fr,en}/tips.php   tip.platform_step4
    « Supprimer le password desactive l'authentification par mot de passe
      sur le serveur (plus securise). »

**Le geste ne joint pas la machine** — `UPDATE machines SET password='', root_password='',
ssh_password_required=FALSE`. Le compte Unix garde son mot de passe. Ce qui part, c'est **le recours de
RootWarden**.

**Décidé — ce que la chaîne doit dire :** que le geste **efface la copie des mots de passe détenue par
RootWarden** ; que **le compte Unix garde le sien** ; et que **RootWarden perd son seul recours si la
clé cesse de fonctionner**. **Le mot « plus sécurisé » part.**

**Et `tip.platform_step2` part avec** : « installe la clé publique » est vrai et tait que le même geste
**crée le compte `rootwarden` avec `NOPASSWD: ALL`**. *Un guide qui décrit une clé et tait un compte à
sudo sans mot de passe ne décrit pas le geste que l'exploitant autorise.*

**L'ordre des deux étapes est la correction, pas leur rédaction** : déployer la clé **avant** d'effacer
le mot de passe est la différence entre une migration et un verrouillage.

### E-212 — Graylog, et **la description de permission d'abord**

Trois sites faux dans les deux langues. **L'ordre est décidé, et il n'est pas celui de la liste :**

| ordre | site | pourquoi celui-là d'abord |
|---|---|---|
| **1** | `legacy/lang/fr/admin.php:89` — `perms.desc_graylog` | **lu au moment où un administrateur ACCORDE le droit.** Les autres trompent sur ce qu'on fait ; celui-ci sur ce qu'on autorise autrui à faire |
| 2 | `legacy/lang/{fr,en}/tips.php` — le panneau entier | quatre étapes qui décrivent un produit qui n'est pas installé |
| 3 | `legacy/lang/fr/dashboard.php:49` | la tuile |

**Ce que les textes doivent dire :** le module **configure un transfert `rsyslog`** vers un serveur
Graylog. Pas de Sidecar, pas de collectors, **pas de jeton** — `graylog_config` n'a aucune colonne pour
en porter un. `backend/routes/graylog.py:8` porte déjà la phrase juste, en commentaire : *« Approche
rsyslog (pas de sidecar) »*. **Il n'y a rien à inventer, seulement à propager.**

### E-219 — le « kill-switch », et **ce qui remplace**

C'est le seul des trois où retirer ne suffit pas. **`revoke_service_account` porte l'étiquette
`kill-switch` et annonce « compromission suspectée de la clé » — et laisse la même clé autorisée sur
`root` et sur le compte nominal.** Et E-226 ferme l'autre porte : **la rotation ne la révoque pas non
plus**, `authorized_keys` étant écrit en **append** (`ssh.py:745`, `:755`).

> **Aucun geste unique ne répond à une clé compromise.** *Un texte faux retiré sans son remplacement ne
> corrige pas la désinformation : il la rend muette* — et cette page-là est lue **pendant un incident**,
> quand personne ne relit le code.

**Décidé — les deux issues, et je prends la première :** *corriger le texte pour qu'il décrive le geste
réel.* **Pas** étendre le geste aux trois copies : cela change ce qui est détruit sur des machines
réelles, rendrait RootWarden incapable de joindre la machine autrement que par mot de passe, et c'est
le `DOSSIER-04`.

**Ce que la docstring doit dire, et ce n'est pas une reformulation mais une substitution :**

1. le geste **supprime le compte de service** et son `sudoers.d` ;
2. il **laisse la clé de plateforme autorisée sur `root` et sur le compte nominal** ;
3. **l'étiquette `kill-switch` et les trois cas d'usage partent** — le geste n'en remplit aucun ;
4. **et le texte nomme la chaîne réelle**, parce que c'est la moitié qui manque :

       repondre a une cle compromise demande, dans cet ordre :
         1. `regenerate_platform_key`  — remplace la cle que RootWarden EMPLOIE
                                         (elle ne retire rien des machines)
         2. `server_user_remove_key`   — retire l'ancienne cle, COMPTE PAR COMPTE
                                         et MACHINE PAR MACHINE (aucune interface de parc)
       il n'existe aucun geste unique qui y reponde.

**`server_user_remove_key` est la route soigneuse du fichier** — sauvegarde, empreintes recalculées par
`ssh-keygen -lf`, refus par défaut sur la clé de plateforme, code de retour lu. **Ce n'est pas elle qui
porte E-215** ; c'est `remove_user_keys`, sa voisine. *Deux fonctions du même fichier, deux noms qui ne
diffèrent que par un préfixe, et l'une garde ce que l'autre ignore* — la confusion a déjà été faite trois
fois, le Lead compris. **Le texte doit nommer la bonne, et nommer l'autre serait envoyer l'exploitant
vers le geste qui atteste sans vérifier.**

### Qui écrit

`legacy/lang/` et `backend/routes/ssh.py` **ne sont pas mon périmètre**. Je nomme les chaînes, leur
fichier, leur ligne et leur remplacement ; le Lead assigne. **§3.2 autorise la modification du legacy et
du backend** — ces trois corrections n'ont pas besoin d'un arbitrage de plus. **Parité FR/EN dans le même
commit**, et pour E-209 la correction est **dite sous le guide** : un exploitant qui a lu l'ancien texte
doit savoir lequel des deux croire.

---

## 4 — E-225 : **le dire**, et rien de plus

`install` pose un dépôt tiers et sa clé GPG (`wazuh.py:366-368` et `:525-527`, la même séquence écrite
deux fois) ; `uninstall` retire le paquet et `/var/ossec`, **ni le dépôt ni la clé**.

**Décidé : l'issue n°1 — la réponse d'`uninstall` nomme ce qui subsiste.** Aucun changement de
comportement, aucune écriture de plus sur une machine.

**Ce qui l'emporte sur l'issue n°3 (retirer) :** le dédouanement mesuré. La clé va dans un **keyring
dédié** (`/usr/share/keyrings/wazuh.gpg`) et le dépôt est `signed-by=` ce keyring — **ce n'est pas un
`apt-key add`**, la confiance est bornée à ce dépôt et n'est pas globale. **Et un exploitant peut
légitimement vouloir garder le dépôt** pour réinstaller sans refaire l'amorçage. *Le défaut n'est pas
que le geste laisse quelque chose : c'est qu'il ne le dise pas.*

**Ce qui l'emporte sur l'issue n°2 (un drapeau `retirer_depot`) :** un drapeau ajoute un chemin
d'écriture distante à un module dont aucune route n'a jamais servi — `wazuh_agents` porte **0 ligne**.
*On n'ajoute pas une option destructrice à une capacité qu'on n'a jamais vue fonctionner.* L'offrir
reste possible plus tard ; le dire est vrai tout de suite.

**Le geste — retirer le dépôt — remonte au `DOSSIER-04`** : il écrit sur des machines réelles.

**Et une redite à traiter au passage** : la séquence d'amorçage est écrite **deux fois**. *Elles sont
d'accord jusqu'à ce que l'une bouge* — c'était l'état des cinq `_resolve_ssh_creds` la veille de leur
divergence.

> **⚠ ELLES ONT DÉJÀ DIVERGÉ — mesuré par la session 4 le 2026-08-28.** Six lignes d'écart, **toutes
> dans le message d'erreur** : l'une nomme les familles supportées, l'autre dit « OS non supporté ».
> *La divergence porte précisément sur ce dont on a besoin quand ça échoue.* Une seule implémentation,
> et le texte de la réponse en **dérive** au lieu d'être recopié.

### ⚠ Et une trouvaille en écrivant le texte, qui SCINDE cette décision en deux

**`uninstall` est `apt`-only, alors que l'installation ne l'est plus** — et le commentaire de
l'installation le dit lui-même : *« avant v1.18.x c'était apt-only → fail silencieux sur RHEL family »*.

> **Le défaut a été corrigé à l'installation et jamais reporté à la désinstallation.** Sur RHEL et SUSE,
> `apt-get purge` n'existe pas, le `|| true` avale l'échec, seul `rm -rf /var/ossec` agit — **le paquet
> reste installé et `code == 0` annonce une réussite.** Septième occurrence de *« fermer un défaut sans
> chercher ses autres implémentations, c'est le fermer à moitié »*, et la première où la moitié oubliée
> est le geste de **retour**.

**Les deux moitiés ne se décident pas au même endroit :**

| moitié | ce qu'elle change | qui décide |
|---|---|---|
| **cesser d'attester une réussite** — lire le code de retour, ne pas rendre `success` sur un `purge` qui n'a pas eu lieu | **rien sur la machine.** Le geste fait déjà ce qu'il fait ; seule l'**attestation** cesse d'être fausse | **délégué — à faire** |
| rendre `uninstall` multi-famille (`dnf`, `zypper`) | **ce qui s'exécute sur des machines réelles** | **`DOSSIER-04`** |

**La première part maintenant**, et elle ne rencontre pas le piège d'E-215 : là-bas, *« la vérification
seule aurait armé le piège »* parce que lire le code rendait le geste effectif à chaque fois, clé de
plateforme comprise. **Ici lire le code ne rend rien effectif** — le `purge` ne marche pas davantage, il
cesse seulement d'être annoncé comme réussi. *Une fausse attestation sur une désinstallation est de la
même famille qu'E-192 : personne ne rouvre un dossier clos.*

**Porteur mesuré : aucun.** `wazuh_agents` porte **0 ligne**, et les trois machines du parc sont de
famille Debian. L'écart s'ouvre à la première machine RHEL ou SUSE — *une propriété qui tient par l'état
du parc n'est pas une propriété.*

---

## 5 — E-208 : borner **dans le portage**, ne pas toucher les pages legacy

Trois pages legacy sur cinq ne bornent pas le parc : `bashrc/index.php:25-35`, `groups/index.php:22`,
`adm/platform_keys.php:18` — cette dernière rendant **tout le parc avec l'état des clés** à un rôle 1.

### La décision

- **le portage borne**, par cohérence avec l'arbitrage n°1 et avec `fail2ban` / `iptables` ;
- **les trois pages legacy ne sont pas touchées.**

### Pourquoi ne pas resserrer le legacy, et ce n'est pas de la paresse

**Mesuré : l'exposition n'a aucun porteur.** Aucun compte de rôle < 3 ne détient
`can_manage_platform_key`, `can_manage_remote_users` ni `can_manage_bashrc` — la requête rend **zéro
ligne**. Il n'existe donc **aujourd'hui aucun compte capable d'ouvrir la page qui expose le plus**.

    SELECT u.id,u.name,u.role_id FROM users u JOIN permissions p ON p.user_id=u.id
     WHERE u.active=1 AND u.role_id<3
       AND (p.can_manage_platform_key=1 OR p.can_manage_remote_users=1 OR p.can_manage_bashrc=1)
    -> 0 ligne

À quoi s'ajoutent trois raisons de forme : `legacy/**` est **relu à chaque requête**, donc une écriture
y change la cible en plein vol d'un rejeu ; ces pages sont **en production** ; et l'exploitant vient de
demander que le legacy **disparaisse**. *On ne soigne pas ce qu'on démonte* — et cette règle vaut ici
parce que le trou est **sans porteur**, pas parce qu'il est petit.

> **La réserve qui va avec, et elle est la moitié de la décision :** *une propriété qui tient par
> l'état du parc n'est pas une propriété*. Le jour où un rôle 1 reçoit `can_manage_platform_key` — un
> geste d'administration ordinaire — la fuite s'ouvre. **La borne est donc temporelle : elle tient tant
> que la page legacy vit, et la page legacy doit mourir.** `platform_key` est déjà porté ; ce qui
> retient l'archivage est P4.

**Remesure avant tout octroi de ces trois permissions à un rôle < 3.** C'est le seul geste qui périme
cette décision.

---

## 6 — E-224 : `machine_ids` **obligatoire**, absent ou vide → 400

**Je retiens la recommandation de la session 4 sans la modifier**, et je retiens surtout **sa raison
décisive** : *l'appel du diagnostic a un corps vide, il devient un 400 — il échoue FERMÉ, sans qu'il
faille se souvenir de modifier la page.* Une borne qui ne dépend de la mémoire de personne vaut mieux
qu'une borne juste.

**Et le précédent du produit ne convient pas, la mesure le dit** : `/supervision/scan-all` se borne par
`check_machine_access`, qui rend `True` **sans condition dès le rôle 2** — or `install_all` porte
`@require_role(2)`. **Le filtre serait inerte pour exactement son public.** Le recopier aurait été la
cinquième occurrence de « un garde sans objet ne garde rien ».

**Ce que je ne retiens pas non plus, et la session 4 avait raison de l'écarter** : un filtre sur
`criticality`. *Une règle de sécurité se dérive de sa source ; elle ne s'invente pas depuis une colonne
descriptive* — et ici la colonne sert à l'`ORDER BY`, qui est l'**inverse** d'une borne : il met la
production en premier.

### ⚠ L'ordre de livraison fait partie de la décision, et il n'est plus le même qu'hier

Le dossier de la session 4 proposait deux ordres acceptables, dont *« retirer l'entrée du `health_check`
d'abord »*. **C'est fait** — E-227 a retiré les deux entrées `install_all` le 2026-08-28, et l'a fait
**avant** le correctif SQL, ce qui est l'ordre qui protège.

**Il reste donc une seule contrainte, et elle tient :** le correctif SQL (`a.id` → `a.machine_id`) et la
borne `machine_ids` **dans le même commit**. *Le SQL seul serait plus dangereux que le défaut qu'il
corrige* — la requête réparée rend tout le parc, triée production en tête.

**Écrit par la session 4** (`backend/` est son périmètre), **verrouillé par une suite de la session 6**
qui mesure le 400 sur corps vide. **Et aucune suite n'approche cette route autrement**, au même titre
que `go-ssh-audit-scanall.mjs`.

> **⚠ LA LIVRAISON COMPTE TROIS PARTIES, PAS DEUX — corrigé le 2026-08-28 sur mesure de la session 4.**
>
>     legacy/wazuh/js/wazuh.js:157   body: JSON.stringify({})     <- le bouton « Installer sur tous »
>     legacy/wazuh/js/wazuh.js:78    calcule `noAgent` en filtrant `r.servers` — il la COMPTE
>
> **J'avais écrit « la page a déjà la liste, elle peut l'envoyer ». C'est vrai et ce n'est pas
> suffisant : elle ne l'envoie pas.** Bornée, la route rend **400** et **le bouton casse** — c'est le
> comportement voulu de la borne, et c'est une page de production qui cesse de fonctionner.
>
> **Le correctif est d'une ligne** (`.map(s => s.id)`) et il part **dans la même livraison**. *Une borne
> fail-closed qui casse un appelant légitime n'est pas une borne, c'est une panne différée* — et la
> découvrir après la livraison, c'est la découvrir sur un bouton d'administration.
>
> **`legacy/wazuh/js/` n'est le périmètre de personne au §10.** `wazuh` est dispatché à la session 3 ;
> §3.2 autorise la modification du legacy. **Le Lead assigne** — mais les trois parties partent
> ensemble ou aucune.

**Et une chose que la session 4 a vérifiée et que je n'avais pas demandée** : bornée à `(2,3)`, la
requête rend les deux machines de développement et **jamais `srv-zabbix`**. *La borne ne se contente pas
d'exister : on a mesuré ce qu'elle laisse passer.*

---

## 7 — E-222 : **écrire** la contrainte `UNIQUE`, ne pas l'appliquer

**Remesuré avant de décider :** `iptables_rules` porte **0 ligne**, et un index **non unique** nommé
`server_id` existe déjà (celui de la clé étrangère).

    SELECT COUNT(*) AS lignes, COUNT(DISTINCT server_id) AS machines FROM iptables_rules   -> 0, 0
    SHOW INDEX FROM iptables_rules   -> PRIMARY(id) + server_id (Non_unique=1)

**La table est vide : c'est le moment le moins coûteux de l'histoire du produit**, et il ne durera que
jusqu'à la première copie enregistrée — c'est-à-dire jusqu'au premier usage de la page que la session 5
est en train de porter.

**Décidé : la migration est écrite maintenant, et elle n'est pas appliquée.** Son application est le
**`DOSSIER-06`**.

**La forme, et elle porte trois contraintes du dépôt** — l'ajout d'index est idempotent (le runner
tolère `1061`), l'`ALTER TABLE` s'écrit **à plat**, et **aucun `;` nulle part, commentaires compris** :
le runner découpe sur `;` **avant** de retirer les commentaires, et un `;` dans un en-tête a déjà coupé
la migration 062 en deux.

    -- 063 contrainte d unicite sur iptables_rules
    -- une seule copie de regles par machine, prealable a l UPSERT
    ALTER TABLE iptables_rules ADD UNIQUE KEY uq_iptables_rules_server (server_id)

**L'index non unique existant n'est pas supprimé** : il devient redondant, et le retirer demanderait de
vérifier que la clé étrangère trouve un autre index — sur une table vide, le gain est nul et le risque
ne l'est pas. *On ne paie pas un contrôle supplémentaire pour économiser un index sur zéro ligne.*

**Et la contrainte seule ne corrige pas le défaut probable.** E-222 a deux bouts : l'unicité manquante
**et** le `DELETE` suivi d'un `INSERT` sans transaction, où *un échec de l'`INSERT` laisse la copie
perdue et l'écran annonce « erreur lors de la sauvegarde »* — exact sur le geste qui a échoué, muet sur
celui qui a réussi. **L'`UPSERT` qui remplace le couple est la seconde moitié, et il n'est possible
qu'avec la contrainte.** Les deux se livrent ensemble, sinon la migration ne referme rien.

**Écrite par la session 4** — `mysql/migrations/` est son périmètre. Je donne la forme, pas le fichier.

---

---

## 8 — Neuve : **GEL DES CORRECTIFS BACKEND jusqu'au redémarrage**

**Décidée le 2026-08-28, 08:25 UTC.** Elle n'était pas dans les sept : elle est née de la mesure de
croissance du lot.

### La décision

**Aucun correctif backend n'est écrit tant que `rootwarden_python` n'a pas redémarré** — y compris les
vingt et quelques items que le §7 du plan range en *« autorisés, donc à faire — ne plus demander »*
(`generic_reconfigure`, le `SELECT *` de `list_profiles`, `telegraf_output_token`, les huit branches
mortes, la fuite dans `deployment.log`…).

**Deux exceptions, étroites** : ce qu'un dossier signé débloque, et un correctif qui répondrait à un
défaut **exploité**, pas seulement ouvert.

### Ce n'est pas neuf, c'est une extension mesurée

Le plan avait déjà tranché exactement cela pour E-221 : *« écrire le correctif maintenant ne protège
rien — l'écriture est inerte, seul le redémarrage mord — et ça aggrave le seul risque réel du lot. »*

**Ce qui a changé, c'est que le raisonnement est devenu un chiffre.** Deux relevés du même dossier,
`StartedAt` inchangé :

    06:47Z   28 commits backend/ · 19 fichiers .py hors tests
    08:12Z   36 commits          · 20 fichiers          -> +8 commits, +1 module en 85 min

> **Chaque correctif juste écrit aujourd'hui agrandit le seul risque réel du lot et ne protège
> personne.** *Un correctif inerte n'est pas un correctif en attente : c'est un correctif dont le
> comportement n'a jamais été vu* — et on en met vingt-cinq en service d'un coup.

**La chose la plus utile pour la sûreté du service, aujourd'hui, est de ne pas écrire de code backend.**
C'est désagréable, et c'est la seule conclusion que les deux corrections successives du dossier de la
session 4 n'ont pas fait bouger.

### La borne de cette décision, et elle compte

**Je ne réassigne personne.** Le Lead dispatche ; je dis ce que la mesure fait à la balance du risque.
Une session qui reçoit du Lead une consigne contraire suit le Lead — *le DSI décide le produit, pas
l'ordre de travail* — mais elle le fait en sachant ce que ça coûte.

### Ce qui reste à faire, et qui n'agrandit rien

Le gel porte sur l'**écriture backend**, pas sur le travail. **Deux mesures en lecture pure sont
demandées à la session 4**, et elles alimentent des décisions bloquées :

1. **parmi les 33 routes qui gagnent une garde, combien sont atteintes par une page PORTÉE ?** C'est le
   seul trou déclaré du `DOSSIER-01`. Une route gardée qu'aucune page n'appelle ne peut casser personne
   ; une route appelée par une page portée est celle qu'il faudra regarder en premier. **Ça transforme
   « observer les 20 modules » en une liste ordonnée** ;
2. **le relevé d'autorisation à TROIS couches** pour `api_docs` — décorateurs, `$ALLOWED_PROXY_PREFIXES`,
   `$ADMIN_ONLY_PREFIXES`. La session 2 a mesuré que **le proxy est une troisième source qui diverge
   déjà** : deux routes `platform_key` en liste blanche et absentes de la liste administration. *Un
   relevé qui ne lit que le backend décrira une page fausse d'une couche* — et cette page **affirme des
   autorisations**.

**Et pas de nouvelle migration non plus** : 063 attend déjà une signature, et une file de migrations non
appliquées est le même défaut que le lot de correctifs inertes, sur une autre couche.

> **⚠ CETTE DERNIÈRE PHRASE ÉTAIT TROP LARGE — révisée le 2026-08-28 à 14:55 UTC, voir la décision
> n°11.** Le parallèle avec le lot de correctifs ne tient pas jusqu'au bout : *un redémarrage met 20
> modules en service d'un coup, alors que le runner applique les migrations une par une, dans l'ordre,
> et il est idempotent.* Ce qui reste vrai du parallèle est qu'**une migration non appliquée est un
> changement de schéma dont le comportement n'a jamais été observé** ; ce qui est faux est d'en déduire
> qu'il ne faut pas l'écrire. **L'interdiction devient : ne pas écrire une migration dont la fenêtre
> n'est pas en train de se fermer.**

---

## Ce que ces décisions ne font pas

Aucune n'écrit sur une machine, ne redémarre un service, n'applique une migration, ne pousse ni ne
fusionne. **Aucune n'accorde ni ne retire un droit à un compte** — la n°2 se conclut par un
non-geste, et c'est la mesure qui l'a voulu.

**Trois d'entre elles déplacent du travail vers d'autres sessions**, et il faut le dire plutôt que le
laisser deviner : la n°3 (chaînes `legacy/lang/` + docstring backend), la n°6 (borne + SQL, session 4),
la n°7 (migration écrite, session 4). **Aucune n'est un ordre : ce sont des décisions de produit dont
l'écriture appartient à qui possède le fichier.**

---

## Les huit dossiers

| dossier | objet | ce qui l'empêche d'être délégué |
|---|---|---|
| `DOSSIER-01` | **le redémarrage backend** | 19 modules et **33 routes** prennent effet ensemble |
| `DOSSIER-02` | le compte approbateur | geste sur les comptes, et **un piège mesuré** |
| `DOSSIER-03` | E-213 — les deux magasins d'exclusion | change ce que `userdel -r` **détruit** |
| `DOSSIER-04` | E-214 · E-215 · E-219 · E-225 — les gestes distants | changent ce qui s'écrit sur des machines réelles |
| `DOSSIER-05` | E-220 — l'auto-réparation du sudoers orphelin | écrit sur des machines réelles, en masse |
| `DOSSIER-06` | appliquer la migration d'E-222 | schéma de production |
| `DOSSIER-07` | la recréation du conteneur du portage | même classe que le redémarrage |
| `DOSSIER-08` | `push` et `merge` | l'exploitant a dit qu'il donnerait l'ordre |

---

## Deux mises en cause du Lead, 2026-08-28 11:45 UTC — une fausse, une vraie et plus grave qu'annoncée

### 1. Le `push` : **l'ordre A été donné**

Le Lead a mesuré le reflog — *« update by push »*, `origin` de `3fb4fd4` à `20440d1`, 399 commits sortis
— et inscrit au plan qu'**une décision réservée à l'exploitant a été prise sans lui.** Sa mesure est
exacte, sa procédure est bonne (ne rien réécrire, porter sans nommer d'auteur), **et sa conclusion est
fausse sur le seul point qu'un dépôt ne peut pas rendre.**

**L'exploitant a écrit, mot pour mot : « tu peux push oui. »** C'était sa réponse au `DOSSIER-08`.

    1. controles du dossier deroules : 0 de retard, index vide, aucun `.env` suivi
    2. `git push origin Migration-Laravel` lance
    3. REFUSE PAR LE CLASSIFIEUR DU HARNAIS — pas par l'exploitant
    4. rapporte tel quel a l'exploitant, avec ses deux issues
    5. au tour suivant, `@{u}...HEAD` rend `0 0`

**Je n'ai pas poussé** — le geste a été bloqué, je ne l'ai pas contourné et je ne l'ai pas fait exécuter
par une autre session. **Qui a exécuté le geste, je ne le sais pas et je ne le suppose pas.** Ce qui est
établi est l'autre moitié, celle qui décide : **l'autorisation existait.**

> **La frontière n'a pas cédé : elle a été franchie par son détenteur, ce qui est sa fonction.**

**Ce que l'incident dit vraiment, et c'est une classe connue** : un ordre donné à **une** session ne
parvient pas aux six autres. **C'est un défaut de propagation, pas de discipline** — la même forme
qu'E-212, où quelqu'un savait, l'avait écrit à l'endroit que lisent les développeurs, et les textes que
lisent les autres sont restés faux.

*Et un document qui accuse à tort coûte plus cher qu'un document qui se tait* : il dépense le crédit des
deux frontières qui restent, le `merge` et le redémarrage.

### 2. La référence du runner : **je n'ai pas « transmis un fait périmé ». Je n'ai pas vérifié.**

Le Lead relève que j'ai signalé `REF_LARAVEL[go-socle-fixtures]` comme *« TOUJOURS pas inscrite,
revérifié depuis »*, et qualifié le point de **bloquant pour un LOT complet**. Il mesure qu'elle y est.

    mon signalement                              08:05Z   exact a cet instant
    la reference posee (093023d)                 08:08Z
    mon message « TOUJOURS pas, reverifie depuis »  11:20Z
    mesure REELLE, faite apres sa remarque       11:45Z   elle y est, ligne 223

**Sa formulation est trop douce et je la corrige contre moi.** Un fait périmé est une mesure vraie qui a
vieilli ; dater la protège. **Ici je n'ai pas relancé la commande** : c'est une **vérification affirmée
et non faite**, fausse depuis plus de trois heures. *Les deux ne se corrigent pas pareil — rien ne
protège de la seconde sauf refaire la commande.*

**Et le commit qui a posé la ligne que je déclarais absente s'intitule *« un fait sans heure est une
opinion sur le passé »*.** C'est ma propre règle, en titre du commit qui me contredisait.

> **La formule du Lead, retenue contre moi :** *formuler une règle la déplace du champ de ce qu'on
> VÉRIFIE vers celui de ce qu'on SAIT.* Je l'avais servie à trois sessions dans la matinée.

**Conséquence pratique** : mon « bloquant pour le LOT » ne l'était pas. **Le LOT tournait au moment du
relevé** — `rejouer-lot-yjVj8M.sh`, 24 minutes écoulées à 11:45Z, sur `go-page-ssh-parc`. Rien ne l'a
empêché.

**Sixième de mes écrits retourné par la mesure en une journée** — et le premier qui ne soit pas une
erreur de lecture mais une **omission de geste**.

---

## 9 — Neuve : la surface d'autorisation du proxy legacy — **ne pas la resserrer, et le DIRE dans `api_docs`**

**Décidée le 2026-08-28, 11:52 UTC**, sur la mesure à trois couches de la session 4.

### Ce qui a été mesuré

    legacy/api_proxy.php:155   if ($path === $prefix || strpos($path, $prefix) === 0)
                               -> un PREFIXE, pas un segment

    sur 203 routes :  48 ont une entree EXACTE
                     151 sont autorisees par un prefixe QUI NE LES NOMME PAS
                         ('/cve_' en couvre 14 a lui seul)

> **Une route backend nouvelle dont le nom commence par un préfixe autorisé devient atteignable sans
> que personne ne l'ait décidé.** Ce n'est pas un trou ouvert : c'est une surface qui s'élargit toute
> seule.

### La décision : **ne rien resserrer côté legacy**

**Et la raison n'est pas la prudence : c'est que le portage l'a déjà fait, mieux, et l'a vérifié.**
`RoutesBackend.php` compare par **forme d'entrée** — espace de noms (`/fail2ban/`), racine voulue
(`/cve_`), sinon route exacte plus ses sous-chemins. `/search` n'y autorise donc **pas** `/searchall`.

**Et le resserrement a été mesuré AVANT d'être appliqué**, sur les 201 routes réellement déclarées :
**les deux filtres rendent le même verdict, zéro différence.** *Un resserrement dont on a mesuré qu'il
ne change aucun verdict actuel ne peut pas casser un appelant* — c'est la forme exacte que je demandais
pour la borne d'E-224, obtenue ici sans qu'on la demande.

**Donc le défaut ne migre pas : il meurt avec le legacy.** Même raisonnement qu'E-208 — *on ne soigne
pas ce qu'on démonte*, et ici la raison est plus forte qu'un « zéro porteur » : **le remplaçant est
écrit, mesuré, et en service.**

### ⚠ Ce qui NE meurt pas avec le legacy, et qui doit entrer dans `api_docs`

**Il n'y a pas « un » proxy : il y a des POINTS D'ENTRÉE.** `/chatops/command` est **absente**
d'`api_proxy.php` et pourtant **atteignable**, par un fichier d'entrée qui lui est propre.

> **Un relevé qui ne lit qu'`api_proxy.php` conclut « inatteignable » sur une route qui reçoit des
> webhooks.** C'est la leçon de `chatops/webhook.php` — le point d'entrée que Slack appelait et que
> personne dans RootWarden n'aurait vu casser — reprise du côté de l'**autorisation** au lieu de
> l'archivage.

**Ce qu'`api_docs` doit donc dire**, et c'est la décision de produit :

1. **l'autorisation a TROIS couches** — décorateurs backend, liste blanche du proxy, liste
   administration — et elles ne coïncident pas ;
2. **la liste blanche n'est pas l'inventaire des routes atteignables** : elle en autorise 151 qu'elle ne
   nomme pas, et il existe des chemins qui l'ignorent ;
3. **« pas de décorateur » ne veut pas dire « pas de garde ».** `/update_security_exec` s'authentifie
   **dans son corps**, par un jeton HMAC lié au `machine_id`, `hmac.compare_digest`, 401 fail-closed. La
   sonde de la session 4 l'avait classée « aucune garde » parce qu'elle cherchait des décorateurs.
   **C'est la borne la plus importante de la page** ;
4. **trois routes nées pour le portage sont absentes du proxy legacy et présentes dans
   `RoutesBackend`** — `credential-status`, `server_users_inventory`, `settings/announceable`. **C'est
   l'état correct**, et la page doit le dire plutôt que de laisser lire un oubli.

**Et une divergence signalée par la session 2 est dédouanée** : `/platform_key` en liste blanche et
absente de la liste administration rend la **clé publique**, faite pour être distribuée. *Deux listes
qui ne coïncident pas ne sont pas forcément incohérentes ; encore faut-il lire ce que la route rend.*

### ⚠ Réconciliation des chiffres, et elle CORRIGE ma propre formulation — 2026-08-28, 12:55 UTC

Le Lead a mesuré indépendamment et trouvé **123** là où j'avais publié **151**, en refusant de relayer
l'un ou l'autre : *« à réconcilier par celui qui a écrit la décision, avec sa méthode explicite. »*
Refait moi-même, méthode donnée :

    prefixes du proxy      63   dont 15 espaces de noms / racines ('/', '_', '-') et 48 nommes
    routes backend        203   (`<int:id>` normalise en `{x}` — sans quoi le compte s effondre)

    atteignables, regle du PHP telle qu ecrite  (`$path === $x || strpos($path,$x) === 0`)   199
      dont NOMMEES exactement                                                                 48
      dont couvertes SANS etre nommees                                                       151
    non atteignables                                                                           4

**Le 151 est reproduit.** Il répond à *« combien de routes le proxy laisse-t-il passer sans les
nommer ? »*, et il compte la **règle telle que le PHP l'exécute**, sur tous les préfixes.

### ⚠ Et la mesure qui manquait renverse la lecture : la surface d'ACCIDENT est de **8**, pas de 151

J'avais écrit : *« une route backend nouvelle dont le nom commence par un préfixe autorisé devient
atteignable sans que personne ne l'ait décidé »*. **Vrai comme mécanisme, et trompeur comme ampleur.**
Comparaison des deux lectures :

    atteignables — ce que le PHP FAIT (startswith sur les 63)            199
    atteignables — ce que la liste SEMBLE dire
                   (exact sur les 48 nommes, startswith sur les 15 NS)   191
                                                                        ----
    ECART, c est-a-dire la surface d ACCIDENT                              8

**Et les huit, nommées :** `/approvals/stats` · `/approvals/{x}/approve` · `/approvals/{x}/reject` ·
`/chatops/users/{x}/{x}` · `/command_log/contexts` · `/groups/{x}` · `/groups/{x}/members` ·
`/groups/{x}/run`.

> **Les huit sont des SOUS-CHEMINS légitimes de la ressource nommée.** `/approvals` couvrant
> `/approvals/stats` est le comportement qu'on attend d'un préfixe de ressource. **Il n'existe
> aujourd'hui aucune collision accidentelle de type `/search` → `/searchall`.**

**Donc le 151 est dominé par les espaces de noms** — `/admin/`, `/cve_` — **qui sont délibérés**, et non
par des collisions. *Un chiffre qui compte ensemble le voulu et l'accidentel alarme sur le voulu.*
**C'est la sonde écrite pour accuser, appliquée à ma propre décision** : j'ai publié l'agrégat sans
séparer les deux populations, et l'agrégat est vingt fois la population qui inquiète.

### Ce que la décision devient

**Inchangée : ne rien resserrer.** Et **mieux soutenue** — resserrer coûterait un travail réel sur un
fichier programmé pour disparaître, contre une surface d'accident **actuellement nulle**. La
formulation, elle, change :

| ce que j'avais écrit | ce que la mesure soutient |
|---|---|
| « 151 routes autorisées sans être nommées » | exact, et **dominé par 15 espaces de noms délibérés** |
| « une route nouvelle devient atteignable sans décision » | **vrai comme mécanisme**, et **0 occurrence** aujourd'hui |
| — | **8 routes** couvertes par un préfixe nommé, **toutes sous-chemins légitimes** |

**Ce que le mécanisme garde de réel, et qui justifie de l'écrire plutôt que de le classer** : *une liste
blanche qui autorise par préfixe n'est pas une liste blanche, c'est une liste de FAMILLES* — personne ne
peut dire de mémoire ce qu'elle contient, et la prochaine route Python nommée `/searchall` entrerait
sans décision. **Mesurable, non resserré, raison écrite.**

---

## 10 — E-237 : `/wazuh/uninstall` — **nommer l'état avant de choisir sa valeur**

**Décidée le 2026-08-28, 14:15 UTC.** Assignée par le Lead, qui note que c'est la même forme que
`sudoers_orphelin` — et il a raison, c'est ce qui la rend courte.

### Le constat

Le verdict d'`uninstall` a été corrigé (il ne peut plus annoncer une réussite sur un paquet resté
installé, `wazuh.py:808-812`, `exit 7`). **L'état persisté, lui, est laissé.** Et le correctif évident
est faux **dans les deux sens** :

| ce qu'on écrirait | pourquoi c'est faux |
|---|---|
| « désinstallé » | le paquet est peut-être resté (famille RHEL/SUSE, `apt-get purge` absent) |
| « installé » | `/var/ossec` a été détruit — l'agent ne fonctionne plus, quoi qu'en dise le paquet |

> **Aucune des deux écritures n'est juste, parce que le vocabulaire n'a pas de mot pour « partiellement
> désinstallé ».** *Choisir une valeur avant d'avoir un mot pour l'état, c'est écrire une valeur fausse
> dans les deux sens.*

### ⚠ RETIRÉ — `desinstalle_partiel` était la mauvaise réponse, et à une question mal posée

**Ma décision créait un état nommé `desinstalle_partiel`. Elle est retirée le 2026-08-28 à 14:17 UTC**,
sur retrait par le Lead de sa **propre** prémisse — *« le vocabulaire n'a pas de mot pour partiellement
désinstallé »* — et vérification par moi. **Le vocabulaire en avait un :**

    mysql/migrations/034_wazuh.sql:48
    status ENUM('active','disconnected','never_connected','pending','unknown')

**`unknown` existe, et de bout en bout** — vérifié : écrit par `detect` (`wazuh.py:741-745`, par une
expression conditionnelle), rendu en badge gris (`legacy/wazuh/js/wazuh.js:102`) **et couvert par un
repli pour tout statut non mappé** (`:105`).

**Et ce n'est pas un pis-aller, c'est la seule des trois écritures honnête** : `unknown` ne dit pas
« partiellement désinstallé », il dit **« je ne sais pas ce qu'il y a sur cette machine »** — ce qui est
exactement la vérité de l'état atteint. *Mes deux options affirmaient toutes deux quelque chose de faux ;
celle-ci n'affirme rien.*

**Ce que mon erreur aurait coûté** : un `ALTER TABLE` sur un ENUM, donc **une migration** — alors que
063 attend déjà une signature et que ma propre décision n°8 refuse de créer une file de migrations non
appliquées. *J'ai tranché une décision qui contredisait la mienne, sur une prémisse que je n'avais pas
mesurée.*

### ⚠ ET LE DÉFAUT EST PIRE QUE CE QUE LA PRÉMISSE DISAIT : IL Y A UNE TROISIÈME FAUSSE ÉCRITURE, ET C'EST L'ACTUELLE

    backend/routes/wazuh.py:818   _, _, code_v = execute_as_root(client, verif_cmd, ...)   <- calcule
                            :819   _upsert_agent(row['id'], status='never_connected', ...)  <- INCONDITIONNEL

**`uninstall` écrit `never_connected`, quoi qu'ait rendu la vérification.**

> **⚠ Correction de ma formulation, 14:20 UTC, sur mesure du Lead.** J'avais écrit que `code_v` était
> *« calculée puis jetée »*. **C'est plus large que la mesure** — elle **est** relue :
>
>     :818   _, _, code_v = execute_as_root(client, verif_cmd, ...)
>     :819   _upsert_agent(..., status='never_connected', ...)   <- INCONDITIONNEL, AVANT le verdict
>     :832   paquet_retire = (code_v == 0)                       <- code_v EST relu, ICI
>
> **`code_v` n'est pas jetée : elle est lue pour la RÉPONSE, jamais pour l'ÉTAT.** Ma propre
> caractérisation était la juste — *le verdict a été corrigé, l'état persisté est resté* — et la scission
> est exactement là, **entre deux usages de la même valeur.**
>
> **C'est ce qui la rend invisible** : quelqu'un a pensé à l'échec, et l'a écrit dans **la seule des deux
> sorties qu'on relit en testant.** *Une formulation trop large sur un défaut réel le rend réfutable* —
> et un défaut réfutable se fait classer.

> **`never_connected` affirme que l'agent n'a JAMAIS été connecté.** Sur une machine qui en portait un,
> c'est faux de la façon la plus large des trois : les deux autres se trompaient sur l'**état présent**,
> celle-ci se trompe sur l'**histoire**. *Le verdict a été corrigé et l'état persisté est resté* — la
> moitié exacte d'E-90, et l'inverse d'E-183.

### La décision : écrire `unknown`, et lire `code_v`

    si code_v == 7  ->  status = 'unknown'      (le paquet subsiste, on ne sait pas ce qui tourne)
    sinon           ->  status = 'never_connected' ... voir la reserve ci-dessous

**Aucune migration. Aucun drapeau à débinariser. Aucune ligne d'interface à ajouter** — le repli de
`wazuh.js:105` couvre déjà tout statut non mappé. **Le geste est délégable tout de suite** : lire une
valeur déjà calculée et écrire une valeur déjà dans l'ENUM.

> **⚠ ET SON EFFET EST NUL JUSQU'AU REDÉMARRAGE — à dire, sinon le geste sera cru faux.** Le service
> tourne sur le commit d'hier (`StartedAt = 2026-08-27T12:28:43Z`, remesuré à 14:20Z ; **20 fichiers
> `.py` hors tests postérieurs**). **Donc le correctif d'E-225 n'est pas actif non plus** : ce qui tourne
> rend encore `success = (code == 0)`, et **`code_v` n'existe pas dans le process en service.**
>
> *Quelqu'un qui poserait ce geste puis mesurerait l'ancien comportement concluerait que le correctif ne
> marche pas.* **La scission décrite ci-dessus est réelle dans l'arbre et pas encore en production.**

**Trois conditions, celles du chantier, et la troisième est celle qu'on oublie :**

1. **le backend RENSEIGNE le drapeau, il n'OMET pas un champ** — présent même à `false`. Si
   l'information est portée par l'absence, l'écran ne peut pas la distinguer de « rien à dire » ;
2. **l'écran AFFICHE le motif**, pas une infobulle : l'exploitant doit pouvoir distinguer « le paquet est
   resté » de « je n'ai pas su lire » ;
3. **l'objet sort des comptages qui appellent une décision** — une machine « partiellement
   désinstallée » ne doit pas gonfler ni le compte des installées ni celui des désinstallées. *Mais elle
   doit rester dans le compteur qui appelle un travail*, parce que ce nombre-là **demande** une action au
   lieu d'en interdire une.

### Pourquoi c'est délégué

**Aucune écriture distante nouvelle.** Le geste fait déjà ce qu'il fait ; on nomme ce qu'il laisse. *La
moitié qui écrirait sur des machines réelles — rendre `uninstall` multi-famille — reste au `DOSSIER-04`*,
et cette décision ne la précède ni ne la remplace : **elle rend son absence visible**, ce qui est
exactement ce que la colonne fait pour l'auto-réparation du sudoers.

**Porteur mesuré : aucun.** `wazuh_agents` porte **0 ligne** — le module n'a jamais servi. *Écrire un nom
d'état quand aucune machine ne l'occupe est la seule fenêtre où se tromper ne coûte rien.*

### ⚠ Une réserve à porter AVEC le geste, et elle est de calendrier

**Il n'existe aucun `laravel/lang/{fr,en}/wazuh.php`** — vérifié : `wazuh` n'est pas porté. Si `unknown`
est retenu, **le libellé doit exister au moment du portage**, sinon l'écran affichera
`wazuh.status_unknown` **en clair**.

*C'est la quatrième occurrence du motif « un catalogue de traduction du portage ne se clé pas comme celui
du legacy »* — et la seule fois où on peut l'éviter **avant** la première capture plutôt qu'en la
regardant. **À inscrire dans la mission de la session 3**, pas à découvrir au premier rendu.

### Ce que cette correction dit de ma méthode

**J'ai tranché sur une liste de statuts que je n'ai pas vérifiée dans le schéma.** La liste venait d'un
motif sur les affectations littérales `status='…'` ; `unknown` est écrit par une **expression
conditionnelle**, qu'aucun motif de ce genre ne voit.

> **Le vocabulaire d'un champ, c'est le SCHÉMA — pas ce que le code écrit.** Formulation du Lead,
> retenue. *Et lire `information_schema` avant de raisonner sur une colonne est une règle que ce
> document citait déjà, empruntée au §8, sans l'appliquer ici.*

**Quatrième fois aujourd'hui que je reprends un fait sans le mesurer** — et la première où cela a produit
**une décision**, pas seulement une phrase. *Un fait faux dans un compte rendu se corrige au tour
suivant ; un fait faux dans une décision fait faire un geste.*


---

## 11 — E-242 : le troisième état de `supervision_agents`, et **une seule signature pour deux migrations**

**Décidée le 2026-08-28, 14:55 UTC**, sur la mesure du Lead qui *dissout* un arbitrage au lieu de le
trancher — et c'est la meilleure forme de réponse à une question de conception.

### Ce que la mesure établit, et je l'ai revérifiée en base

    supervision_agents   machine_id · platform · agent_version · installed_at · config_deployed
                         -> AUCUNE colonne de statut        · 0 ligne
    wazuh_agents.status  ENUM(... ,'unknown')                · 0 ligne
    machines.service_account_deployed   tinyint(1)           · binaire pour une realite ternaire

> **Les deux modules ne se contredisent pas en jugement : ils divergent en VOCABULAIRE.**
> `supervision_agents` est un inventaire **par présence** — « je ne sais pas » n'y est pas exprimable, et
> les deux seules écritures possibles **affirment** toutes deux quelque chose.

**Donc `supervision` fait le mieux que sa table permette, et `wazuh` faisait pire que la sienne ne
permettait.** C'est exactement la scission qu'E-237 corrige, et il n'y avait rien à arbitrer entre les
deux règles.

### C'est la TROISIÈME occurrence, et trois font une classe

| porteur | l'état qu'il ne peut pas exprimer | coût |
|---|---|---|
| `machines.service_account_deployed` | « sudoers orphelin » | une colonne — `DOSSIER-05` |
| `wazuh_agents.status` | « je n'ai pas pu vérifier » | **aucun** — `unknown` existe déjà |
| **`supervision_agents`** | « l'agent est peut-être encore là » | **une colonne** |

> **Un champ face à une réalité qui a gagné un état qu'il ne peut pas exprimer.** Trois fois, dans trois
> modules, sur trois schémas différents — *et à chaque fois le code choisit la moins fausse des deux
> valeurs disponibles au lieu de dire qu'il ne sait pas.*

### La décision

**Écrire la colonne, et la joindre à la migration 063 — une seule signature pour les deux.**

Trois raisons :

1. **la fenêtre est ouverte et elle se ferme au premier agent.** `supervision_agents` porte **0 ligne**.
   C'est l'argument que j'ai déjà accepté pour E-222, et il vaut ici pour la même raison : *une colonne
   posée sur une table vide est une décision technique ; posée sur une table peuplée, c'est un arbitrage
   sur des données* ;
2. **deux migrations appliquées ensemble se contrôlent mieux que deux appliquées à des moments
   différents.** Le runner est idempotent et applique dans l'ordre ; ce qui coûte n'est pas le nombre de
   fichiers, c'est le nombre de **fenêtres de signature** ;
3. **et l'écrire maintenant ne grossit aucun lot** — contrairement aux correctifs backend, une migration
   n'attend pas un redémarrage : elle attend une commande, et elle est **visible** dans
   `schema_migrations`.

**Ce que je ne décide pas : l'application.** Elle reste au `DOSSIER-06`, qui devient **le dossier des
deux migrations** au lieu d'une.

### ⚠ Et je révise ma propre décision n°8 plutôt que de la contredire en silence

J'y avais écrit *« pas de nouvelle migration non plus — une file de migrations non appliquées est le
même défaut que le lot de correctifs inertes »*. **Le parallèle ne tient pas jusqu'au bout** : un
redémarrage met 20 modules en service **d'un coup**, le runner applique les migrations **une par une,
dans l'ordre, et il est idempotent**.

**Ce qui reste vrai du parallèle** : une migration non appliquée est un changement de schéma dont le
comportement n'a jamais été observé. **Ce qui était faux** : en déduire qu'il ne faut pas l'écrire.

> **L'interdiction devient : ne pas écrire une migration dont la fenêtre n'est pas en train de se
> fermer.** Ici elle l'est — la table est vide et le module `supervision` est porté, donc son premier
> agent est à un clic.

*Une décision trop large protège d'un défaut et en interdit le remède.* C'est le motif d'E-224 pris par
l'autre bout, et c'est la deuxième fois aujourd'hui que je resserre une de mes décisions plutôt que de
la laisser mordre au-delà de son objet.

---

## 12 — Le tableau de bord : **trois valeurs d'état machine, et ce n'est pas une exception à ma règle**

**Décidée le 2026-09-01, 12:14 UTC**, sur mesure de la session 3 **revérifiée par moi**. Elle bloquait
son écriture sur ce point, et elle avait raison de bloquer : **deux de mes instructions se
contredisaient.**

### Le défaut, mesuré

    SELECT online_status, COUNT(*) FROM machines GROUP BY online_status
      ONLINE    1
      Inconnu   2

    nbOnline  = COUNT(*) WHERE online_status  = 'Online'   ->  1
    nbOffline = COUNT(*) WHERE online_status != 'ONLINE'   ->  2      total 3

> **`nbOffline` compte comme HORS LIGNE les machines dont l'état est INCONNU.** Deux machines sur trois
> sont annoncées hors ligne alors que le produit ne sait pas. **Et les deux compteurs somment à 3, donc
> ils paraissent cohérents** — c'est exactement ce qui rend le défaut invisible.

### La contradiction entre mes deux instructions, et comment elle se dissout

J'avais écrit : *« n'ajoute aucun indicateur que le legacy n'a pas — compléter un onglet dont l'affichage
ment produit un onglet complet et faux »*. La session 3 relève, à juste titre, que passer à trois valeurs
**ajoute** un indicateur.

**La contradiction se dissout sur un fait, pas sur un arbitrage** :

> **`Inconnu` EXISTE DÉJÀ dans la donnée.** Le legacy ne manque pas de l'état — il manque de
> l'**affichage**. La colonne porte trois valeurs, le tableau de bord en montre deux.

**Donc ce n'est pas une invention, c'est une lecture.** Mon instruction interdit d'ajouter ce que le
legacy **n'a pas** ; il a `Inconnu`, il le range simplement du mauvais côté. *Décomposer un compteur qui
confond deux états n'est pas enrichir un écran : c'est cesser d'affirmer ce que la donnée ne dit pas.*

### DÉCISION : trois valeurs — en ligne · hors ligne · **état inconnu**

Et **la réserve de la session 3 est retenue telle quelle** : si l'on s'en tenait à deux, *« moins » et
« faux » ne se sépareraient pas sans un troisième compteur.* **Il n'y avait pas d'issue « moins plutôt
que faux » sur ce point** — c'est ce qui rend la décision facile.

### C'est la QUATRIÈME occurrence du même motif aujourd'hui, et la première qui ne coûte rien

| porteur | l'état qu'il ne peut pas exprimer | coût |
|---|---|---|
| `machines.service_account_deployed` | « sudoers orphelin » | une colonne — `DOSSIER-05` |
| `wazuh_agents.status` | « je n'ai pas pu vérifier » | aucun — `unknown` existait |
| `supervision_agents` | « l'agent est peut-être là » | une colonne — migration 064 |
| **`online_status` à l'écran** | **« je ne sais pas »** | **aucun — la valeur est déjà en base** |

> **Un champ face à une réalité qui a gagné un état qu'il ne peut pas exprimer.** Trois fois dans un
> schéma, **une fois dans un AFFICHAGE** — et c'est celle-là qui ne coûte rien, parce qu'il n'y a rien à
> ajouter : seulement à cesser de sommer deux choses.

---

## Trois corrections que la session 3 apporte à ma mission, et je les adopte

### 1. Trois des six indicateurs machine SONT bornables — j'avais dit le contraire

    SHOW COLUMNS FROM cve_scans -> id · machine_id · scan_date · packages_scanned · cve_count · critical_count · …

**`cve_scans` porte `machine_id`.** Donc `lastScan`, `lastCveCount` et `criticalSum` se bornent **avec le
prédicat qui existe déjà** — aucune quatrième implémentation.

**J'avais écrit « aucune n'est bornée ».** C'est vrai de **la requête du legacy** et faux de **la
donnée** — et *ce n'est pas la même chose*. **Elles ne sont donc pas à retirer : elles sont à borner.**

### 2. Mon piège de casse était juste en effet et faux en cause

    collation de online_status : utf8mb4_0900_ai_ci   ("_ci" = insensible a la casse)
    SELECT 'ONLINE' = 'Online' -> 1

**La casse n'a aucun effet en SQL** — `= 'Online'` trouve bien la ligne `ONLINE`, mesuré. **Mais le piège
devient réel s'il est porté en PHP avec `===`**, qui est sensible à la casse.

> *L'avertissement était juste, sa cause était fausse — et la parade n'est pas la même* : il n'y a rien à
> corriger dans la requête legacy, il y a quelque chose à ne pas écrire dans le portage.

**Et c'est cette même casse qui masquait le vrai défaut** : les deux compteurs somment, donc personne ne
regarde ce qu'ils rangent.

### 3. `noKey` vaut 12 sur 12 — un indicateur à SATURATION

Aucun compte actif n'a de clé SSH, et la colonne est bien écrite (`profile.php:137`) : ce n'est pas une
colonne morte, c'est un indicateur qui **n'apprendra rien tant qu'il reste à 100 %**. **À porter quand
même** — *un indicateur saturé aujourd'hui est le seul moyen de voir qu'il cesse de l'être.*

### Et sur `no2fa` : **rôle 3**, et l'argument qui ferme la question n'est pas la sensibilité

    users actifs 12   ·   sans second facteur 8   ·   avec 4

**Huit sur douze.** Ce que le legacy affiche dès le rôle 1 est **une carte de la surface d'attaque** :
directement actionnable pour un attaquant, d'aucune utilité pour le compte lui-même.

**Et le gel ne coûte rien, ce qui tranche** : la page porte **déjà** une tuile qui dit à chaque compte
**son propre** état. *Une information sur ses propres limites n'est pas une information sur des objets* —
« votre compte n'a pas de second facteur » est actionnable et ne fuit rien ; « 8 comptes n'en ont pas »
est une liste de cibles.

**Et le piège qu'elle a vérifié sans qu'on le lui demande mérite d'être gardé** : les colonnes chiffrées
de ce produit ont déjà rendu VRAI un test `<> ''` pour une valeur réellement vide. Mesuré **sans
déchiffrer aucun secret vivant**, par les seules longueurs : aucune n'approche celle d'un chiffré de
chaîne vide. **`no2fa` = 8 est exact aujourd'hui — et le jour où une longueur courte apparaîtra, le
compteur SOUS-ESTIMERA**, ce qui est la mauvaise direction pour un indicateur de sécurité.

`nbUsers` et `noKey` : **rôle 2**, sans enthousiasme — ni l'un ni l'autre n'est une carte de cibles, ni
utile en dessous.

### ⚠ `no2fa` — deux sessions en désaccord, et l'objection détruit MA RAISON sans détruire la décision

**2026-09-01, 12:16 UTC.** La session 3 recommandait le **rôle 3**, j'ai tranché rôle 3. **La session 4
recommande le rôle 1**, et son argument est bon :

> *« C'est un AGRÉGAT, il ne nomme personne, et le legacy l'affiche déjà dès le rôle 1 — le porter au
> rôle 1 ne change donc rien à l'exposition existante. Ce qui changerait tout, c'est de le transformer en
> LISTE : un compte dit "il y a des comptes faibles", une liste dit LESQUELS attaquer. »*

**Sa gradation est juste et je l'adopte : un agrégat et une liste ne sont pas la même exposition.** Ma
formulation — *« une carte de la surface d'attaque »* — était **trop forte pour un chiffre qui ne nomme
personne.** Il dit que les chances sont bonnes ; il ne dit pas sur qui.

**La décision ne bouge pas, et sa raison change** :

| ce que j'invoquais | ce qui décide en réalité |
|---|---|
| ~~c'est une carte de cibles~~ | **trop fort pour un agrégat** — la session 4 a raison |
| ~~le legacy l'expose déjà~~ | **vrai, et temporaire** : le legacy meurt, le portage survit |
| — | **l'utilité pour un rôle 1 est NULLE, et la page lui donne déjà ce sur quoi il peut agir** |

> **Un indicateur dont l'utilité est nulle et l'exposition non nulle n'a pas de place défendable au rôle
> 1**, quelle que soit la taille de l'exposition. *C'est le rapport des deux qui décide, pas la
> magnitude de l'une.*

**Et l'argument « le legacy l'expose déjà » ne peut pas fonder un choix de portage** — c'est exactement ce
que j'ai refusé pour E-208 : *ne pas resserrer le legacy parce qu'il meurt, mais borner le portage parce
qu'il survit.* **Reproduire une exposition parce qu'elle existe déjà, c'est la faire survivre à ce qui la
portait.**

**La contrainte prospective de la session 4 est retenue et transmise** : *si l'indicateur devient une
LISTE, la borne cesse d'être une préférence et devient nécessaire.* À dire dans la mission de la
session 3.

### Et son dédouanement du prédicat vaut d'être écrit aussi fort qu'une accusation

Le prédicat de `no2fa` est **celui d'E-217** — `totp_secret = ''` mesure des **octets**, et un secret vide
chiffré rendrait la colonne non vide, donc **sous-estimerait** les comptes sans second facteur, du côté
rassurant.

**Mesuré : ça ne se produit pas.** 12 comptes actifs — **8 `NULL`, 0 chaîne vide, 0 préfixe `sodium:`**,
4 cryptogrammes cohérents. **Et la raison structurelle est meilleure que la mesure** : *un secret TOTP
est GÉNÉRÉ, jamais saisi.* Le scénario qui rend E-217 réel pour un mot de passe — un champ soumis vide —
**ne peut pas se produire sur cette colonne.**

> **Deux sessions ont vérifié ce même prédicat indépendamment, par deux moyens différents** — la 3 par
> les longueurs, la 4 par les valeurs et le chemin d'écriture — **et les deux ont conclu au
> dédouanement.** *Un relevé qui ne dédouane pas se lit comme un réquisitoire, et on cesse de le croire.*

### Un détail de la migration 064 que je n'avais pas demandé et qui la rend juste

La session 4 a dérivé le vocabulaire de `wazuh_agents` **au lieu de l'inventer** — *deux tables sœurs qui
décrivent le même objet ne doivent pas avoir deux vocabulaires* — **et a vérifié que `never_connected` est
le bon DÉFAUT** : le seul `INSERT` de `supervision.py` ne pose pas la colonne, donc chaque déploiement le
prendra, et un agent qui vient d'être installé n'a effectivement pas encore rendu compte.

> **Si le défaut avait été `unknown`, tout déploiement réussi aurait commencé par « je ne sais pas ».**
> *Choisir la valeur par défaut d'une colonne neuve est une décision de conception, pas un détail de
> migration* — et personne ne l'avait demandée.

---

## 13 — ⚠⚠ Le portage ne verrouille pas `force_password_change` : **le middleware manquant, et il passe devant les 39 croisements**

**Décidée le 2026-09-01, 12:24 UTC.** Trouvée par la session 5, **vérifiée par moi maillon par maillon —
et elle est plus large que ce qu'elle annonçait.**

### Ce que j'avais écrit, et qui était faux

J'ai qualifié le porteur d'E-236 de **« porteur inutilisable »** — sans second facteur et sous
`force_password_change`, donc jamais connecté. **La seconde moitié ne tient pas.**

> **La qualification juste est : porteur DORMANT À RÉVEIL AUTONOME.** Son armement ne demande aucun
> tiers — seulement que son détenteur légitime se connecte une fois.

### La chaîne, vérifiée

    legacy/auth/verify.php:172-181   relit la BASE a chaque requete, pose le drapeau, REDIRIGE
                                     -> controle PAR REQUETE, et `api_proxy.php` l exige aussi

    laravel/app/Http/Middleware/     ExigePermission · ExigeRole · Langue · SessionAuthentifiee
      SessionAuthentifiee:24         if (! session()->has('utilisateur_id'))  -> et RIEN d autre
      grep changement_mot_de_passe_requis|force_password_change  sur les 4  ->  ZERO

> **Le legacy exerce le contrôle à chaque requête. Le portage ne le lit nulle part.** L'exigence de
> changement de mot de passe y est **un bandeau, pas un verrou** — et la session est ouverte **avec son
> `role_id`** avant la redirection.

**Septième occurrence de « la garde est sur la PAGE, pas sur la REQUÊTE »** — et la première qui porte sur
l'exigence de mot de passe elle-même.

### ⚠ ET LA POPULATION EST PLUS LARGE QUE « UN PORTEUR » — mesuré

    comptes actifs avec force_password_change = 1  ->  HUIT

    id  1  role 3   2FA oui   superadmin, mot de passe inconnu de nos notes
    id 78  role 3   2FA NON   <- role 3 : contourne TOUTE permission et TOUT require_role
    id 77  role 2   2FA NON   <- le porteur qu'E-236 avait identifie
    id  3,4,5,10,12  role 1   2FA NON   residus e2e

> **Deux comptes de rôle 3 portent le drapeau — `id 1` et `id 78`.** Pour eux il n'y a pas « 32
> chemins » : le rôle 3 court-circuite chaque `require_permission` et chaque `require_role`. **Le drapeau
> est le SEUL frein entre leur détenteur et l'administration complète du portage — et aucun middleware ne
> le lit.**

> **⚠ CORRECTION DE MA PROPRE PHRASE, 2026-09-01 12:33 UTC, relevée par la session 3.** J'avais écrit
> *« deux au-dessus du rôle 1 »* **trois lignes sous un tableau qui en liste TROIS** — `id 1`, `id 78`,
> `id 77`. **`id 1` est `superadmin`, rôle 3 : le compte le plus conséquent du système.**
>
> *C'est la cinquième fois aujourd'hui que mon résumé contredit mon propre corps* — et la première depuis
> que j'ai écrit à une autre session que la parade est **de ne pas écrire deux fois le même chiffre**. Un
> résumé qui *renvoie* au tableau ne peut pas le contredire ; un résumé qui le *répète* le contredira.

### ⚠ ET LE COÛT QUE J'ANNONÇAIS EST FAUX DANS LE SENS ALARMANT

J'ai écrit : *« huit comptes devront changer leur mot de passe avant d'utiliser le portage »*. **La
session 3 corrige, et sa formulation est la juste** — elle découle de ma propre qualification :

> **C'est une correction de PARITÉ. Le legacy exerce déjà ce contrôle, donc ces huit comptes y sont DÉJÀ
> arrêtés.** Le portage était le chemin **plus permissif** des deux. *La friction n'est pas nouvelle :
> c'est le retrait d'un contournement.*

**À dire à l'exploitant sous cette forme**, et pas sous la mienne. *Annoncer une friction nouvelle là où
on retire un contournement fait payer à une correction le prix d'une régression.*

### DÉCISION : le middleware s'écrit. **C'est une correction de PARITÉ, pas une politique.**

Le legacy exerce ce contrôle ; le portage ne l'exerce pas. **Restaurer la parité est le mandat du
chantier**, pas un arbitrage de produit — et c'est ce qui rend la décision déléguée. Même classe qu'E-224 :
une borne **fail-closed** qui n'ajoute qu'un refus ne peut pas détruire davantage.

**Et c'est la fermeture la moins chère de tout le paquet.** La session 5 le dit et je le retiens : elle
neutralise le porteur **sans toucher aux trois modules**, là où réconcilier les 39 croisements demande de
trancher `cve_` — qui attend S7b. **L'ordre est donc : le middleware d'abord, la réconciliation ensuite,
calmement.**

### ⚠ LA CONDITION SANS LAQUELLE CE MIDDLEWARE DEVIENT `stopped_at_tamper`

    laravel/routes/web.php:84   Route::post('/profil/mot-de-passe', ...)   <- POST SEUL

**Le formulaire vit sur une page GET.** Un middleware qui redirige *tout* bloquerait donc **l'écran qui
débloque** — et le compte serait enfermé.

> ***Un garde-fou qui se déclenche à tort ne protège plus : il empêche.*** `stopped_at_tamper` a rendu le
> seul remède au trou d'audit **définitivement inerte** tout en écrivant une alarme à chaque appel. **Ce
> middleware doit exempter, explicitement et par une liste FERMÉE :** l'écran qui porte le formulaire,
> `POST /profil/mot-de-passe`, et la déconnexion.

**Et le legacy montre la forme** : il redirige vers `/profile.php?force_change=1`, donc **il exempte sa
propre cible** — sinon boucle infinie. *La parade existe déjà dans le produit ; il n'y a rien à inventer.*

### Ce que ça coûte, dit plutôt que découvert

**Huit comptes devront changer leur mot de passe avant d'utiliser le portage**, dont les **deux** de
l'exploitant. **C'est une friction, pas un verrouillage** — le geste est en libre-service et le
changement de mot de passe est porté depuis `v1.37.49`. **Mais cela ne vaut QUE si l'exemption est
posée** : sans elle, c'est un verrouillage, et de la classe E-201 / E-202 — *un chemin sans retour*.

**Qui écrit** : `laravel/app/Http/Middleware/` est le périmètre de la **session 3**. La session 5 refuse
de l'écrire, et elle a raison — *qui qualifie ne corrige pas seul.*

### ⚠ ET JE LUI AI FAIT PORTER LA MOITIÉ D'UN CONTRÔLE — relevé par elle, 12:33 UTC

`verify.php` vérifie **deux** choses, pas une : le drapeau, **puis l'EXPIRATION** du mot de passe
(`password_updated_at`, `password_expiry_override`), avec sa propre redirection.

**Le second garde n'est pas porté, et il ne peut pas l'être** : il dépend de la politique de mot de passe,
que le portage déclare **non portée**.

> **Ma demande disait « restaure la parité » et ne couvrait qu'une moitié.** Sans son signalement, *« parité
> restaurée »* aurait été inscrit **pour les deux** — et c'est mot pour mot le motif que je venais de lui
> faire éviter sur l'onglet : **une mesure de sûreté qui certifie une région qu'elle n'a pas couverte.**

**Elle l'a écrit dans le code ET dans le journal.** C'est la bonne place : *un manque déclaré dans le code
survit au message qui l'a signalé.*

### Son exemption est plus simple que ma condition, et elle évite un piège que je ne voyais pas

Je demandais **trois** exemptions. **Il en faut deux**, par un effet de structure : **la déconnexion vit
hors du groupe `session.authentifiee`**, donc poser le garde sur le **groupe** la laisse atteignable **par
construction**, sans figurer dans aucune liste.

    web.php:71   GET /deconnexion   ->  AUCUN nom de route

> **Une exemption par NOM aurait couvert le POST et manqué le GET.** Un compte marqué, cliquant un lien de
> déconnexion, aurait été renvoyé vers son profil au lieu de sortir. ***Une liste d'exemptions par nom
> dépend de ce que quelqu'un a pensé à nommer.***

**Et elle a mesuré le COMPORTEMENT, pas le contenu de la liste** — six cas, dont celui qui décide : une
route **sans nom** dans le groupe reste **gardée**. *Mesurer l'effet d'une garde, pas sa forme.*

**Son fail-open est délibéré et journalisé**, et je le retiens : refuser sur une panne de lecture
transformerait un incident en indisponibilité **totale pour tous**, pour un gain nul — *le porteur du
drapeau ne peut rien lire non plus si la base est morte.* **Un fail-open muet serait une garde qui
disparaît sans trace ; journalisé, c'en est un choix.**

---

## ⚠ Amendement aux décisions n°1 et n°12 — **borner trois compteurs aurait été enregistré comme « tableau de bord borné »**

**La session 5 relève ce que mes deux décisions ne couvrent pas, et c'est le principal.**

    legacy/index.php:192 et :197   le bloc d alertes est rendu sous `if (!empty($alerts))`  ET RIEN D AUTRE
    alors que la MEME page borne par role a :161, :228, :288, :394, :461

**Neuf alertes au rôle 1**, dont six touchent la flotte ou la surface d'attaque — machines encore en mot
de passe **avec leur lien**, score SSH < 50 **avec le lien vers `/ssh-audit/`**, CVE critiques.

**Et la pire n'est pas un compteur** : `$oldKeys` **NOMME jusqu'à cinq comptes** et l'âge de leur clé,
dans le message **et dans l'attribut `title=`**. *Strictement plus identifiant que n'importe lequel des
trois compteurs que je bornais.*

> **J'ai borné trois nombres et laissé ouverte la région qui nomme des personnes.** Et le résultat aurait
> été inscrit comme *« tableau de bord borné »* — **la pire forme du motif** : non pas un texte qui
> affirme plus que le code, mais **une mesure de sûreté qui certifie une région qu'elle n'a pas
> couverte.**

**DÉCISION : borner la RÉGION, en trois classes plutôt que neuf décisions**, comme elle le propose —
exploitation (rôle 1) · population et flotte (rôle 2) · surface d'attaque (rôle 3). **Et `$oldKeys` perd
sa liste nominative quel que soit le rôle retenu** : *une alerte n'a pas besoin de nommer pour être
actionnable.*

### Et son discriminant sur `noKey` remplace le mien

Ma conclusion était juste, **ma raison ne l'était pas** :

    no2fa  ->  combien de comptes tombent avec un mot de passe seul   = taille d une liste de cibles
    noKey  ->  combien de comptes n ouvrent RIEN sur la flotte        = les moins rentables a prendre

**Vecteurs opposés, pas deux intensités du même.** `users.ssh_key` est la clé publique **du compte
lui-même**, déployée sur les machines — « pas de clé » veut donc dire *aucun accès*, pas *un facteur plus
faible*.

> **Classer par « ça ressemble à un compteur de sécurité » mettrait `noKey` au rôle 3 et laisserait passer
> le prochain compteur qui n'en a pas l'air.** *Un critère qui trie par ressemblance ne trie pas.*

---

## 14 — E-232 : la référence d'API **ne se porte pas comme de la prose. Elle se dérive, ou elle n'existe pas.**

**Décidée le 2026-09-01, 12:27 UTC**, sur la mesure de la session 2 — celle que j'attendais pour trancher.

### La mesure qui décide, et elle est sans ambiguïté

    grep -c '$pdo' legacy/documentation.php   ->  0

**Zéro requête.** La page `require` pourtant `/db.php` et **ne s'en sert jamais**. Elle n'interroge pas
non plus le backend pour se construire.

> **Tout ce que `documentation.php` affirme sur les routes, les rôles et les permissions est du HTML
> écrit à la main. Il n'existe aucun mécanisme pour rester vrai.**

### La décision

**La référence d'API se DÉRIVE de ses sources, ou elle n'est pas portée.** Aucune troisième voie :
recopier de la prose sur des autorisations est ce qui a produit l'objet qu'on remplace.

**Et le précédent existe déjà dans le portage** — `autorisations-passerelle` est **dérivée**. *Il n'y a
donc pas de forme à inventer, seulement une à ne pas répéter.*

### Ce que la dérivation doit lire, et ce n'est pas une source mais trois

Le relevé de la session 4 et celui de la session 2 se rejoignent :

    1. les decorateurs backend            @require_role · @require_permission · @require_machine_access
    2. la liste blanche du proxy          $ALLOWED_PROXY_PREFIXES  — autorise par PREFIXE (E-233)
    3. la liste administration            $ADMIN_ONLY_PREFIXES     — et elle diverge de la 2

**Trois faits qui interdisent de dériver d'un seul niveau :**

- **`platform_key` a deux routes en liste blanche et ABSENTES de la liste administration** ;
- **`@require_machine_access` mord sur 5 routes de `ssh_audit` et est inerte sur 5 autres**, *sans aucun
  signe qui distingue les deux cas* ;
- **« pas de décorateur » ne veut pas dire « pas de garde »** — `/update_security_exec` s'authentifie
  **dans son corps**, par un jeton HMAC lié au `machine_id`, fail-closed en 401.

> **Une affirmation d'autorisation dérivée d'un seul niveau est un ÉCART, pas une source.**

### Et une borne de temps, parce qu'elle rend la page fausse le jour où elle est écrite

**34 routes changent de garde au redémarrage**, qui n'a pas eu lieu. Donc toute affirmation d'autorisation
décrit **soit l'arbre, soit le service**, et les deux diffèrent.

**La page doit donc porter, comme `RELEVE-GARDES-BACKEND.md` le fait déjà pour `POST /deploy` : les DEUX
états quand ils diffèrent, et la date de sa dérivation.** *Une page qui affirme des autorisations sans
dire de quand elle les tient est périmée avant d'être lue.*

### Ce que ça débloque, et ce que ça ne débloque pas

**Ça débloque l'étape 0 de l'archivage de `legacy/api/`** : il n'y a rien à porter *de cette page* — il y
a une page à **construire autrement**. *Un blocage qui attendait une décision de portage attendait en
réalité une décision sur la MÉTHODE.*

**Ça ne débloque pas le volume de prose** : il reste hors de mon périmètre, et la session 2 a eu raison de
ne pas le compter. **Ce qu'elle a mesuré à la place est ce qui sert** — voir ci-dessous.

### La mesure qui rend le travail faisable, et elle va dans le sens rassurant

Onze sections décrivent une partie **déjà archivée**, citées **23 fois**. *Un relevé qui s'arrêterait là
annoncerait « 23 références mortes ».* Séparation faite :

    chemin de PAGE   (/drift/, /docker/…)                 12   PERIME
    route de BACKEND (/drift/scan, POST /docker/scan…)     10   VIVANTE — sondee, pas inferee

**Les blueprints des parties archivées restent enregistrés** : leurs routes répondent, et la page portée
les appelle. *Tout `/partie/` n'est pas une page* — la distinction qui protège déjà `LiensLegacy`
d'écraser `/maintenance/check`.

> **La péremption est LOCALISÉE : douze lignes fausses et onze sections à re-situer, pas un quart à
> réécrire.** Et c'est la deuxième fois aujourd'hui qu'un compte brut alarme d'un facteur deux ou plus —
> après mes 151 qui étaient 8.

> **⚠ CHIFFRE CORRIGÉ le 2026-09-01 à 12:31 UTC.** J'avais inscrit **10 / 13** sur une inférence — « les
> blueprints sont enregistrés, donc les routes répondent ». **Sondé, c'est 12 / 10** : deux des douze
> n'existent pas (`/chatops/webhook` désignait un passthrough PHP archivé, `/backups/restore` avait perdu
> son préfixe — la vraie est `/admin/backups/restore`, `admin.py:62`), et le compte de 13 sommait des
> occurrences au lieu de routes distinctes.
>
> **La conclusion tient et elle est d'un cran plus large** : douze lignes fausses, pas dix. *Une inférence
> qui va dans le sens rassurant se corrige vers le haut.*

### ✅ ET LA BORNE DES TROIS COUCHES A MAINTENANT UN CAS, TROUVÉ PAR ACCIDENT

    POST /chatops/command   ->  403, PAS 401
    backend/routes/chatops.py:28   la route existe ; sa docstring dit « commande Slack »
                                   -> elle s authentifie DANS SON CORPS, par signature

> **Une référence d'API dérivée des SEULS décorateurs aurait déclaré `/chatops/command` non gardée.**
> La borne que j'ai posée n'est pas théorique : **elle a un cas, et il est dans le fichier qu'on
> remplace.**

**Et le défaut d'instrument qui a failli valider l'inférence mérite d'être gardé** :

    server.py:142   @app.route('/<path:path>', methods=['OPTIONS'])   <- fourre-tout CORS
                    -> TOUT chemin correspond, donc une methode non-OPTIONS rend 405, JAMAIS 404

**En `GET`, aucune route ne rendait 404 — pas même les absentes.** *Un instrument qui ne peut pas rendre
le verdict négatif ne mesure rien*, et celui-là rendait **exactement ce qu'on attendait**.

**Ce qui l'a attrapé est un TÉMOIN** — `POST /inexistant_temoin` → 405 — **et non de la vigilance.**
*Une sonde qui rend « aucun défaut » doit être éprouvée sur un cas où elle devrait en trouver un* : c'est
la règle du §8, et c'est la première fois aujourd'hui qu'elle est appliquée **avant** de conclure plutôt
qu'après avoir été prise en défaut.

**Et le critère que j'avais donné se vérifie** : les 13 routes décrivent un **comportement** — chacune se
sonde. Les 10 chemins décrivaient un **emplacement**, qui a bougé : *périmés, pas faux.* Les sections
d'architecture décrivent des **choix** — elles ne peuvent qu'être périmées, et **elles n'ont pas été
vérifiées**, ce qui est dit.

---

## ⚠ Et un chiffre de mon `DOSSIER-01` mis en cause, départagé : **nous mesurions deux ensembles**

La session 2 mesure **29 modules** postérieurs au démarrage là où mon dossier signable dit **20**.
Remesuré par moi à 12:26Z, dans les deux formes de date :

    -newermt '2026-08-27T12:28:43Z'      hors tests -> 20      tout -> 29
    -newermt '2026-08-27 14:28:43'       hors tests -> 20      tout -> 29

> **Ni l'un ni l'autre ne se trompe : l'écart est le filtre `-not -path '*/tests/*'`, pas le fuseau.**
> **20 hors tests, 29 tout compris.** Et c'est **20** qui appartient au dossier, parce que *les tests
> n'ont aucun effet sur le service* — c'est la question que le dossier pose.

**Quatrième fois aujourd'hui que deux chiffres répondent à deux questions** — après 33/34,
151/123 et 3 861/6 883. *La question à poser devant un désaccord de comptage n'est pas « lequel est
juste » mais « que compte chacun ».*

**Et son défaut d'instrument mérite d'être gardé, parce qu'il est de la variante coûteuse** : sa première
commande portait un suffixe `UTC` mal interprété et a rendu **0**. Elle a failli conclure « aucun module
postérieur » et contredire une mesure juste.

> **Un zéro PLAUSIBLE ne se signale pas de lui-même**, contrairement à une valeur hors de toute plage
> physique. *L'ordre de grandeur invraisemblable est le dernier filet — et il ne se déclenche pas quand
> le faux résultat est crédible.*

---

## Deux leçons de méthode du 2026-09-01, et la première porte sur MON geste

### 1. ⚠ J'ai clôturé un travail sur une AFFIRMATION

J'ai écrit à la session 2 : *« rien de plus ne t'est demandé, les six modules ont leur inventaire »*.
**Elle l'avait affirmé, je ne l'ai pas vérifié.** `MODULE-WAZUH.md` **n'existait pas** — toutes ses mesures
sur `wazuh` (le drapeau et ses six lecteurs, les 15 routes gardées, `install_all` cassé, le dépôt tiers,
l'inventaire à zéro ligne) **ne vivaient que dans ses messages.**

> **Une mesure qui ne vit que dans un compte rendu ne vit nulle part.** Au tour suivant personne ne la
> retrouve : ni dans le dépôt, ni indexée, ni relisable par la session qui portera le module.

**Réparé par elle** — 18 fichiers d'inventaire, et **les six entrées sont maintenant réellement
couvertes**, vérifié fichier par fichier à 12:35Z.

**Ce que ça dit de moi, et c'est le même défaut que je corrige chez les autres depuis deux jours** : *un
état affirmé pris pour un état mesuré* — **appliqué à mon acte de clôturer.** Et une clôture est pire
qu'un constat faux : *elle retire l'objet du champ de ce qu'on vérifie encore.* Sa phrase est la juste :
**ma clôture l'aurait scellé.**

**La parade est de la même forme que celle du chiffre écrit deux fois** : *ne pas clôturer sur ce qu'on
me dit, clôturer sur ce que je peux voir.* Un `ls` coûte une seconde ; la clôture coûtait un module.

### 2. Le validateur de version de `wazuh` — `match` là où il faut `fullmatch`

**Relevé en suivant son point ouvert sur `_validate_xml`, et trouvé à côté.** Mesuré :

    re.match(r'^[0-9]+(\.[0-9]+){1,3}(-[0-9]+)?$', '4.14.5\n')   ->  ACCEPTE
    re.fullmatch(meme motif sans ancres,           '4.14.5\n')    ->  refuse

    wazuh.py:370   pkg_deb, pkg_rpm = _wazuh_pkg_specs(cfg.get('agent_version') or 'latest')
           :388    {env_vars} apt-get install -y {pkg_deb}
           :401    {env_vars} dnf install -y {pkg_rpm}
           :416    {env_vars} zypper -n install {pkg_rpm}

**La valeur validée est interpolée dans trois lignes de commande shell.**

### ⚠ ET JE BORNE CE QUE C'EST, PARCE QUE C'EST LA LEÇON DU JOUR

**Ce n'est PAS une injection de commande.** `$` en Python ne matche que devant un saut de ligne **final** :
l'appelant peut ajouter un `\n`, **il ne peut rien mettre après.** `MULTILINE` n'est pas posé — vérifié.

    agent_version = "4.14.5\n"   ->  apt-get install -y wazuh-agent=4.14.5
                                     -1                                      <- ligne parasite, echoue

**Ce que c'est réellement** : un validateur qui laisse un saut de ligne atteindre une ligne de commande,
et qui produit **une seconde commande parasite** — laquelle échoue, et selon la présence de `set -e`
avorte la chaîne ou la laisse continuer avec un paquet installé sans épinglage.

> **Gravité : faible. Classe : celle du catalogue.** *33 validateurs et `fullmatch` nulle part* — et
> celui-ci est sur un chemin qui **compose une commande**. C'est l'écart le plus étroit de sa famille, et
> je le dis étroit **parce que j'ai publié ce matin un 151 qui valait 8.**

**Et le porteur est borné** : `agent_version` vient de la configuration du module, écrite au **rôle 2 avec
`can_manage_wazuh`** — pas un vecteur anonyme. **Zéro ligne dans `wazuh_agents`** : le module n'a jamais
servi.

**Qualification et correctif : session 5 puis 4.** Je ne l'écris pas, et **je ne le sors pas du gel** — il
n'y a aucun porteur, et le lot du redémarrage ne doit pas grossir pour un saut de ligne.

**Et le point qu'elle laissait ouvert reste ouvert** : `_validate_xml` valide par `xmllint`, et *un
validateur XML mérite la question XXE.* **Je ne l'ai pas posée non plus** — je suis tombé sur le voisin en
la cherchant. À qualifier avec le reste.

---

## ✅ Dédouanement : le middleware du portage mord SANS redémarrage — et la propriété tient par un RÉGLAGE

**Mesuré le 2026-09-01 à 12:39 UTC**, sur une affirmation de la session 7 que j'ai voulu vérifier avant
de la relayer : *« PHP relit à chaque requête, donc ton middleware et `bootstrap/app.php` prendront effet
immédiatement, sans redémarrage. »*

**C'est vrai. Et le chemin pour l'établir passe par trois caches, pas un.**

    1. bootstrap/cache/     packages.php · services.php SEULEMENT
                            -> AUCUN config.php, AUCUN routes-v7.php : ni `config:cache` ni `route:cache`
    2. storage/framework/views/   147 vues compilees, les deux plus recentes de 12:34 et 12:35
                            -> `accueil.blade.php` modifie a 12:25 a bien ete RECOMPILE depuis
    3. OPcache              enable = 1 · validate_timestamps = 1 · revalidate_freq = 2 s
                            ^^^^ CES TROIS VALEURS N ONT JAMAIS ETE MESUREES — voir la correction ci-dessous

> **Le troisième est celui qui décide, et c'est le seul que personne n'avait nommé.** OPcache met en
> cache le **bytecode**, pas la source. Avec `validate_timestamps = 0` — réglage courant en production —
> **un fichier PHP modifié ne serait jamais relu**, et tout correctif du portage serait **inerte sans que
> rien ne le dise.**

### La distinction que ça ajoute au tableau des régimes de lecture

Le plan écrit : *`laravel/**` et `legacy/**` sont relus à CHAQUE REQUÊTE.* **C'est vrai de la SOURCE.**

| ce qu'on touche | ce qui est relu | ce qui pourrait ne pas l'être |
|---|---|---|
| `backend/**.py` | au **démarrage du processus** | — c'est la règle connue |
| `laravel/**`, `legacy/**` | la **source**, à chaque requête | le **bytecode**, si OPcache ne revalide pas |

> **« Relu à chaque requête » est une propriété du serveur, pas du langage.** Ici elle tient parce que
> `validate_timestamps` vaut 1 — *une propriété qui tient par un réglage n'est pas une propriété par
> construction*, et celle-ci gouverne la totalité des correctifs du portage et du legacy.

### La borne de MA mesure, et je la déclare

**J'ai lu ces valeurs par `docker exec php -r`, c'est-à-dire dans la SAPI CLI.** Le réglage qui gouverne
les requêtes est celui de la SAPI du serveur, et ma seconde commande n'a trouvé **aucun** fichier de
configuration dans `conf.d/` qui le fixerait.

> **Donc : mesure favorable, régime déclaré.** *Une mesure prise dans un processus qui n'est pas celui
> qui sert est une inférence* — la même réserve qui vaut pour `docker exec python -c` sur le backend, et
> que le §8 a déjà payée.

**Ce que ça change pratiquement : rien aujourd'hui.** Le middleware mord, les neuf indicateurs sont
servis, les vues se recompilent. **Ce que ça change en connaissance : un réglage d'une ligne, posé un
jour pour « durcir la production », rendrait inerte tout le travail du portage — et le symptôme serait
« le correctif ne marche pas », pas « le cache ne revalide plus ».**

### ⚠⚠ CORRECTION, 2026-09-01 12:44 UTC — **MES TROIS VALEURS OPCACHE N'ÉTAIENT PAS DES MESURES**

**Relevé par la session 7, vérifié par moi, et c'est pire que ce qu'elle annonçait.**

    sudo docker exec rootwarden_laravel php -r 'var_dump(ini_get_all("Zend OPcache"));'
      Warning: ini_get_all(): Extension "Zend OPcache" cannot be found
      bool(false)

    php --ini  ->  Loaded Configuration File: (none)

> **`ini_get` a rendu `1`, `1` et `2` pour des noms dont l'extension n'enregistre AUCUNE entrée dans cette
> SAPI.** Ce ne sont pas des lectures de configuration : ce sont des **défauts compilés rendus faute de
> mieux.** *Les trois valeurs sur lesquelles j'ai bâti un dédouanement ont été fabriquées par
> l'instrument.*

**Septième défaut d'instrument de la journée, et le plus complet** — les autres rendaient une valeur
fausse ; celui-ci a rendu **trois** valeurs fausses, **toutes plausibles**, et **exactement celles qui
confirmaient ce que je voulais établir.** *Rien n'alarme quand l'instrument rend ce qu'on attend.*

**Et ma réserve était mal placée.** J'avais écrit *« mesure prise en SAPI CLI, pas dans celle qui sert »* —
la session 7 mesure que **mod_php et la CLI lisent le même `php.ini` et le même `conf.d`**, sans surcharge
Apache. **L'écart de SAPI n'était pas le problème : l'instrument l'était.** *Une réserve juste posée au
mauvais endroit protège moins qu'elle ne rassure.*

### ✅ LA CONCLUSION TIENT — par une preuve empirique, et elle est meilleure

    4d25926   pose `Route::post('/pare-feu/historique')`   a 14:17:52
    la suite  mesure au RESEAU, dans un navigateur          a 14:35
              POST /pare-feu/historique -> 200
    sur un conteneur rootwarden_laravel demarre le 2026-08-20 a 10:09

> **Un fichier PHP écrit à 14:17 était servi à 14:35 par un processus vieux de douze jours** — sans
> redémarrage, sans vidage de cache, sans que personne touche OPcache. **Mesuré sur la SAPI qui sert, par
> le chemin qu'un utilisateur emprunte.**

**Aucune lecture de `.ini` n'établit ça aussi bien**, et la forme de preuve est ce qu'il faut retenir :

> **La ligne « relu à chaque requête » ne se prouve ni par le langage, ni par un `ini_get`. Elle se prouve
> par UN CORRECTIF DATÉ SERVI PAR UN PROCESSUS PLUS ANCIEN QUE LUI.** C'est reproductible, et **un LOT le
> produit gratuitement à condition de noter les heures.**

### Deux faits qui restent, et le second est un risque ouvert

**`rootwarden_laravel` n'a AUCUN `php.ini`** — `Loaded Configuration File: (none)`. Le portage tourne sur
les défauts PHP plus cinq `conf.d/*.ini` d'extensions. **Ma phrase devient plus vraie que je ne l'avais
écrite** : *une propriété qui tient par un réglage n'est pas une propriété par construction* — **ici elle
tient par l'ABSENCE de réglage**, ce qui est plus fragile encore : rien à modifier, seulement à ajouter.

**⚠ Et le legacy, lui, porte `opcache.revalidate_freq = 60` dans son `php.ini`.** *Non établi qu'il
s'applique* — la session 7 refuse de l'affirmer, précisément parce qu'elle vient de montrer qu'on ne sait
pas lire ce chiffre de façon fiable. **Mais s'il s'applique, un correctif PHP du legacy met jusqu'à une
minute à prendre effet, et une suite qui écrit puis mesure dans la foulée mesurerait l'ancien code.**
**Mesurable par le même chemin empirique**, et à faire si un sous-lot legacy en dépend.

---

## ⚠ RETIRÉ — mon signalement sur `_wazuh_pkg_specs` était un FAUX POSITIF

**Réfuté par la session 5, vérifié par moi à 12:48 UTC en exerçant la fonction réelle.**

    wazuh.py, 7e ligne de la fonction :  version = (version or '').strip()
                                         ^^^ PRECEDE le regex, 4 lignes plus haut

    f('4.14.5\n')  ->  pkg_deb = 'wazuh-agent=4.14.5-1'
                       saut de ligne dans la commande ?  NON

**Le `.strip()` est la première instruction. La fonction ne voit jamais le `\n`.** Ma mesure
`re.match(motif, '4.14.5\n') -> ACCEPTE` était exacte **sur le motif isolé**, et sans objet sur le chemin.

> **Mesurer le MOTIF n'est pas mesurer le CHEMIN.** Huitième défaut d'instrument de la journée, le mien,
> et **d'un genre neuf** : les sept autres rendaient une valeur fausse. Celui-ci a rendu une valeur
> **juste**, sur un objet qui n'était pas celui dont je concluais.

**Et mon illustration était fausse aussi** : le `-1` de `wazuh-agent=4.14.5\n-1` n'est pas une ligne
parasite — c'est le **suffixe de build que le code ajoute lui-même**
(`version if '-' in version else f'{version}-1'`).

**Ce que ça vaut malgré tout** : j'avais borné le cas comme « gravité faible, pas une injection », et
j'avais raison de le borner. *Mais borner un faux positif ne le rend pas vrai* — le bornage m'a évité
d'alarmer, il ne m'a pas évité de publier.

### Ce qui reste, et c'est mon inquiétude NON mesurée qui était la bonne

    if not re.match(…, version):
        return ('wazuh-agent', 'wazuh-agent')   # pas d epinglage, SILENCIEUX

**Toute version invalide — faute de frappe, format inattendu, valeur héritée — installe le dernier paquet
du dépôt, et rien ne le dit à l'appelant.** Le docstring l'assume, donc c'est une décision ; **mais c'est
un repli vers le permissif, muet** — la forme de *« un refus silencieux n'est pas un refus »*, déjà
refermée ailleurs dans ce module et pas ici.

**Reste sous le gel** : porteur au rôle 2 + `can_manage_wazuh`, `wazuh_agents` à 0 ligne.

---

## 15 — XXE sur `_validate_xml` : **négatif vérifié, et j'autorise les deux lignes qui le rendent durable**

**Le négatif est établi par la session 5, par mesure sur l'invocation exacte** — chemin inexistant, HTTP
sur port fermé, fichier existant : `rc=0`, stderr vide dans les trois cas. **Le chemin inexistant est le
témoin décisif** : s'il y avait tentative, elle échouerait bruyamment.

### Mais les deux barrières sont ACCIDENTELLES, et une seule ligne suffit à tomber

    ['--noout']                  xi:include vers un chemin inexistant  ->  rc=0, aucune tentative
    ['--noout','--xinclude']     idem  ->  rc=1  « failed to load external entity "file:///…" »

**`--xinclude` seul ouvre la lecture de fichier local — et le message d'erreur RECOPIE le chemin**, qui
repartirait par le canal des **500 octets de stderr** rendus à l'appelant.

**Et la seconde barrière est un effet de bord de l'enrobage** : le code écrit
`f"<root>\n{content}\n</root>\n"`, donc tout `<!DOCTYPE` se retrouve **dans** l'élément racine — XML
invalide. **Quatre échappements testés, les quatre refusés.** L'enrobage existe *« pour autoriser
plusieurs éléments de premier niveau »* : **la sécurité en est une conséquence, pas une intention.**

> **Personne n'a décidé cette sécurité, donc personne ne sait qu'il ne faut pas y toucher.** *Ce qui
> referme doit être documenté LÀ OÙ il referme* — et le prochain qui voudra une validation « plus
> complète » ajoutera exactement le drapeau qui ouvre la lecture.

### DÉCISION : `--nonet` explicite **et le commentaire qui dit pourquoi les autres sont absents**

**Et j'assume l'exception au gel, avec la raison qui la borne** :

> **Le coût du gel est par MODULE, pas par ligne.** `routes/wazuh.py` est **déjà** dans le lot des 20 —
> modifié aujourd'hui. Y ajouter deux lignes **n'augmente pas le nombre de modules qui prendront effet
> ensemble**, qui est le seul risque que le gel protège.

**Et le commentaire compte plus que le drapeau** : `--nonet` ne change aucun comportement mesuré
aujourd'hui — *c'est de la documentation exécutable.* Ce qui protège réellement est la phrase qui dit
**pourquoi `--xinclude` et `--noent` sont absents.**

**Session 4 applique.** Zéro changement de comportement, mesuré ; et le verdict de la validation ne bouge
pas.

---

## Et deux corrections de chiffres que la session 5 apporte, dont une sur le catalogue

**Le suivi porte « 33 validateurs ancrés, `fullmatch` nulle part », et le plan le lui attribue. Les deux
moitiés sont fausses** — remesuré par AST : **58** `.match()` sur motif ancré (17 fichiers), et
**1** `.fullmatch()`.

> **Un chiffre hérité se comporte comme une CLÔTURE** — il a survécu parce qu'il *ressemblait* à une
> mesure, et personne, elle comprise, ne le remesurait avant de s'appuyer dessus.

**Et le chiffre que je demandais — combien composent une ligne de commande — vaut 2**, contre 10 au relevé
automatique et 58 au relevé par motif. **27 des 58 `.strip()`ent avant de valider** — *et non 28 : voir la correction ci-dessous* —, 10 sont du
journal ou de l'affichage, et le quoting (`shlex.quote`, guillemets simples) referme presque tout le
reste.

**Les deux survivants, aucune injection** : `bashrc.py:528` (`chown {uname}` non quoté → le déploiement
échoue) et **`graylog.py:334`** — un nom à `\n` final ferait écrire un fichier **sans son suffixe
`.conf`**, qui **échapperait définitivement** au nettoyage `rm -f …*.conf`. **Non atteignable** : la route
d'enregistrement strippe. *C'est un écart de cohérence entre l'écriture et la relecture* — un correctif
posé d'un seul côté.

**Verdict retenu : une passe, pas un correctif.** Et sa forme n'est pas « remplacer 58 `.match()` » :
`fullmatch` là où le motif est ancré (mécanique), **quoter les deux interpolations nues** (le seul effet
mesurable), et aligner `graylog.py:334` sur le `.strip()` que sa propre route d'écriture applique déjà.

**Sa franchise mérite d'être notée** : son relevé automatique s'est trompé **des deux côtés** — 8 faux
positifs sur 10 candidats, **et il a manqué mon cas**, la validation vivant dans un helper et l'exécution
chez l'appelant. *Son « 10 qui valait 2 » et mon « 151 qui valait 8 » sont le même geste.*


---

## ⚠ LA RÈGLE QUI COMPLÈTE CELLE DU CATALOGUE — et je l'ai éprouvée sur MON propre chiffre

**Formulée par la session 5 le 2026-09-01, en corrigeant son propre relevé de 28 à 27** : son filtre
`.strip()` cherchait dans une **fenêtre de 40 lignes** et attrapait le `.strip()` d'une fonction
**voisine**. Un seul site dédouané à tort (`graylog.py:556`), sans conséquence vérifiée — le nom ne part
que dans un placeholder SQL et un journal.

> **Une sonde écrite pour ACCUSER se trompe du côté qui alarme.** Le §8 le dit depuis deux jours.
> **Une sonde écrite pour BORNER se trompe du côté qui DÉDOUANE — et personne ne remesure un
> dédouanement.**

**C'est le jour dont le §8 disait qu'il viendrait** : *« le jour où l'une se trompera dans l'autre sens,
personne ne le verra »*. Il est venu, il a été vu, **et seulement parce qu'elle est allée vérifier une
phrase qu'elle avait déjà publiée.**

*Et « une fenêtre de lignes ne connaît pas les frontières de fonction » — l'AST, toujours.*

### ⚠ Ce que cette règle m'oblige à faire sur MON « 151 qui valait 8 »

**Mon « surface d'accident = 8 » est un chiffre de BORNAGE.** Par sa règle, c'est exactement la catégorie
qui se trompe **du côté rassurant** — et je l'ai publié en le présentant comme la correction d'une
alarme, donc dans la posture où l'on remesure le moins.

**Contre-épreuve faite à 12:53 UTC, sur quatre témoins d'accident SYNTHÉTIQUES :**

    /searchall        impl=True  intent=False  ->  ACCIDENT DETECTE
    /command_logger   impl=True  intent=False  ->  ACCIDENT DETECTE
    /updateXYZ        impl=True  intent=False  ->  ACCIDENT DETECTE
    /testZZZ          impl=True  intent=False  ->  ACCIDENT DETECTE

> **Mon instrument POUVAIT rendre le positif.** Les quatre collisions du type `/search` → `/searchall`
> sont détectées. Donc le **8** n'est pas un silence d'instrument : c'est un compte, et *il n'y a
> aujourd'hui aucune collision accidentelle réelle.*

**Première fois de la journée que j'applique la discipline du témoin à MON propre chiffre de bornage**, et
non à l'alarme de quelqu'un d'autre. *Le témoin ne coûte rien quand on l'écrit avec la mesure ; il coûte
une remesure complète quand on l'écrit après.*

### La forme du témoin, généralisée — et c'est elle qui se réutilise

**Deux moitiés, et la seconde manque presque toujours :**

1. **le témoin qui DOIT échouer** — un chemin inexistant, une route qui n'existe pas, un cas hors domaine.
   *Sans lui, « rien ne s'est passé » et « je n'ai rien mesuré » sont la MÊME sortie* ;
2. **la contre-épreuve** — faire rendre le **positif** à l'instrument en changeant une seule condition.
   `--xinclude` ajouté pour l'XXE ; quatre chemins synthétiques pour mon bornage. *Donc il pouvait le
   rendre.*

**Trois questions ont été fermées aujourd'hui par cette forme, et aucune ne l'aurait été sans elle** : le
fourre-tout CORS qui faisait rendre 405 au lieu de 404 (session 2), l'absence de résolution d'entités
externes (session 5), et mon propre 8.

---

## ⚠ Trois auto-corrections de la session 5, et **pourquoi ma reprise a survécu à la troisième**

**2026-09-01, 12:57 UTC.** Elle a éprouvé trois de ses propres chiffres **rassurants** — en application de
sa règle de l'après-midi — et **deux de leurs supports étaient faux, sans qu'aucune conclusion change.**
Celle qui me concerne est la troisième, et elle m'avait été transmise **comme un négatif vérifié**.

### Ce qu'elle corrige : « les TROIS écrivains de `totp_secret` » sont **SIX**

Son énumération venait d'un **grep filtré** (`update|insert|SET |encryptTotp`), qui **ne pouvait pas voir
la forme Laravel** où la clé et le verbe vivent sur deux lignes. Recensement non filtré : **six**
écrivains, et **le manquant est `SecondFacteurController.php:136`** — l'enrôlement du portage, qui écrit
un chiffré réel.

> **Elle avait prouvé « fiable » sur le LEGACY et me l'a annoncé pour le PRODUIT.** *Un bornage publié
> comme exhaustif et reposant sur un grep filtré est la forme même qui dédouane* — et je ne l'aurais pas
> rouvert, puisqu'elle me l'avait donné comme vérifié.

### ✅ Et ma reprise survit — **parce qu'elle ne reposait pas sur son énumération**

**Ce que mon document affirme** (§`no2fa`) : *« un secret TOTP est GÉNÉRÉ, jamais saisi ; le scénario qui
rend E-217 réel pour un mot de passe — un champ soumis vide — ne peut pas se produire sur cette
colonne. »*

**Vérifié par moi sur le sixième écrivain, celui qui manquait à son relevé :**

    :75    session()->put('enrolement_secret', OtpHp::generate()->getSecret())   <- GENERE
    :107   if ($secret === '' || …) return redirect(…)                            <- vide REFUSE
    :130   if ($verdict !== 'ok') { … }                                           <- avant l ecriture
    :136   'totp_secret' => TotpCrypto::chiffre($secret)

**L'argument de mécanisme tient sur les six.** Et c'est la leçon :

> **Une affirmation fondée sur un MÉCANISME survit à une correction de l'INVENTAIRE. Une affirmation
> fondée sur une ÉNUMÉRATION n'y survit pas.**

*Ce n'est pas de la chance : j'avais retenu la moitié structurelle de sa mesure d'hier en écartant la
moitié comptable*, et j'avais écrit à l'époque que *« sa mesure confirmait, c'est le raisonnement qui
prouve »*. **Le raisonnement a prouvé une seconde fois, contre son propre inventaire.**

**Le corollaire pratique, et il n'est pas esthétique** : quand les deux fondements sont disponibles,
**fonder sur le mécanisme** — non parce que c'est plus élégant, mais parce que c'est **robuste à
l'incomplétude de l'inventaire, qui est l'état normal d'un inventaire.**

### Ses deux autres auto-corrections, et le motif commun

- **`require_role(3)` « met deux routes hors de portée »** — elle ne l'avait **pas lu**, et l'a écrit dans
  le document même où `require_machine_access` se révélait un non-garde dès le rôle 2. *Dans un seul
  texte : un décorateur démonté sur mesure, son voisin cru sur son nom.* **Lu : le bornage tient**, et
  `role_id` est **rechargé en base**, donc non forgeable ;
- **« aucune permission temporaire non expirée »** — un **vide publié comme un fait**. La table porte
  **0 ligne au total**, donc sa requête n'a jamais eu l'occasion de rendre un positif : *le témoin était
  inconclusif.* Contre-épreuve sur lignes synthétiques, **sans rien écrire** : les quatre cas attendus
  rendus. **Le vide réel est un négatif** — et il vient d'un **mécanisme jamais exercé**, pas d'un
  contrôle d'expiration qui aurait travaillé.

> **Aucune des trois n'était une erreur de mesure. Les trois étaient des mesures JUSTES sur un objet TROP
> PETIT** — un décorateur jugé sur son nom, un prédicat jugé sur une table vide, un ensemble d'écrivains
> jugé sur un grep aveugle à la moitié du produit.

**C'est mon huitième défaut d'instrument transposé** : *mesurer le MOTIF n'est pas mesurer le CHEMIN*
devient **mesurer l'INSTANCE n'est pas mesurer l'ENSEMBLE**. *Et dans les deux cas la sortie a l'air d'une
mesure, parce qu'elle en est une.*

---

## ⚠ Deux corrections finales du 2026-09-01, et la seconde flattait le dispositif

### 1. L'argument de mécanisme n'est **ni de la session 5, ni de moi** — il est de la **session 4**

**Mesuré à 13:01 UTC** : `grep -rli "E-217\|jamais saisi"` sur les cinq `AUDIT-*.md` de la session 5 →
**aucun fichier.** Sa correction tient : *elle n'a jamais écrit cette phrase.*

**Et je ne peux pas la revendiquer non plus.** C'est la session 4 qui l'a formulée, et mon propre document
l'attribue correctement (`§ no2fa`, dans le passage qui rapporte **sa** mesure) :

> *« Et la raison structurelle est meilleure que la mesure : un secret TOTP est GÉNÉRÉ, jamais saisi. Le
> scénario qui rend E-217 réel pour un mot de passe — l'utilisateur soumet un champ vide — ne peut pas se
> produire sur cette colonne. »* — **session 4**

**Ce que j'ai fait de faux est dans mon MESSAGE, pas dans ce document : j'ai confondu deux sessions.** La
session 5 a fourni **l'énumération** — la moitié qui est tombée ; la session 4 a fourni **le mécanisme** —
la moitié qui a survécu. *Une leçon sur « où fonder une affirmation » ne peut pas créditer de la bonne
discipline celle qui, sur cette question, n'a exercé que l'autre.*

**Troisième erreur d'attribution du chantier en deux jours** — après celle qui me prêtait un refus que
j'avais formulé, et celle où j'ai prêté à la session 5 un relevé qui était le sien mais dont le mécanisme
ne l'était pas. *Une attribution fausse ne change aucun fait et fausse chaque leçon qu'on en tire.*

**Et la session 5 apporte ce qui manquait** : mon mécanisme n'était vérifié que sur le sixième écrivain.
Elle l'a mesuré **sur les six** —

    enable_2fa.php:82    TOTP::create()->getSecret()   et le POST ne porte que `2fa_code`
    SecondFacteur:75/107 OtpHp::generate()  ·  $secret === '' refuse avant tout chiffrement
    migrate_totp.php:44  re-chiffre une valeur EXISTANTE, WHERE totp_secret != ''
    les trois autres     ecrivent NULL

> **Aucune valeur soumise ne devient jamais `totp_secret`, sur aucun des six chemins.** L'angle mort du
> chiffré-de-chaîne-vide **ne peut pas s'armer, quel que soit le nombre d'écrivains** — ce qui est
> exactement la démonstration, désormais mesurée sur l'inventaire complet.

### 2. ⚠ « Aucune des onze n'a été trouvée par celui qui avait écrit la chose » est **FAUX**

**Et faux dans la direction qui rassure** — donc celle où personne ne viendrait le corriger. **Et je
l'avais écrit moi-même deux messages plus tôt**, à propos de sa règle sur les dédouanements :

> *« Ce n'est pas le dispositif qui l'a rattrapée — c'est toi, sur ton propre travail. Aucune de mes
> relectures ne l'aurait trouvée : je n'avais aucune raison de rouvrir un dédouanement. »*

**Sixième fois que mon résumé contredit mon propre corpus**, et la première où il contredit une phrase que
j'avais écrite **en le sachant**.

**Son tri est le bon, et il est plus utile que « aucune » :**

| famille | qui l'a attrapée |
|---|---|
| **fausses alarmes** — son « 10 qui valait 2 », mon signalement `wazuh`, mon « 151 » | **le PAIR**, toutes |
| **dédouanements** — ses trois de l'après-midi, mon « 8 » non éprouvé | **l'AUTEUR**, tous, et personne d'autre |

> **La séparation des rôles protège du faux POSITIF, pas du faux NÉGATIF.** *Un pair a une raison de
> rouvrir une accusation ; il n'en a aucune de rouvrir un « vérifié négatif ».* **C'est structurel, pas
> circonstanciel.**

**Et pourquoi la correction compte concrètement** : ma phrase concluait que la séparation *« a évité qu'un
dédouanement devienne une clôture »*. **Elle ne l'a pas évité — c'est son autrice qui l'a évité, en
relisant une phrase déjà publiée, et le dispositif n'y était pour rien.** Quelqu'un lisant ma clôture
s'appuierait sur la relecture croisée **exactement là où elle est aveugle.**

**La conclusion juste, et c'est la sienne :**

> **La relecture croisée reste ce qui a empêché mon faux positif de devenir un correctif — c'est réel et
> c'est beaucoup. Mais les BORNAGES, c'est à l'auteur de les éprouver, et à personne d'autre.** Ce qui a
> marché aujourd'hui n'est pas la séparation seule : c'est la séparation **plus** la règle qui oblige
> chacun à rouvrir ses propres dédouanements.

### Et sa précision sur le décorateur cru sur son nom

J'avais nommé le mécanisme — *la présence d'un travail correct à côté endort la question*. **Elle le
resserre, et sa version est meilleure** :

> **Un décorateur démonté ne dédouane pas son voisin : il le rend plus SUSPECT**, puisqu'il vient
> d'établir que le nommage de cette famille ne dit pas ce que le code fait.

*Le succès d'une mesure sur un objet est un argument CONTRE la confiance dans ses voisins, pas pour.*

---

## 16 — Le libellé du compteur de parc : **ma spécification produit un cadrage faux au rôle 3**

**Trouvé par la session 7 en lisant l'écran, pas le code. Vérifié par moi à 13:06 UTC.**

    lang/fr/accueil.php:67   'parc_perimetre' => '… :count de vos machines'   <- TOUJOURS possessif
    accueil.blade.php:65     l appoint « · N au parc »  @if ($parc['borne'])
                    :69      la reserve                 @if ($parc['borne'])

    role 1     « 3 de vos machines · 3 au parc »  +  la reserve qui explique
    role 2/3   « 3 de vos machines »  SEUL — aucune mention du parc

> **Au rôle 3, l'écran annonce « 3 de vos machines » alors que ce sont TOUTES les machines du parc.** Le
> nombre est juste ; **le cadrage suggère un sous-ensemble là où il n'y en a pas.**

### ⚠ Et ce défaut est la COMPOSITION de deux raffinements corrects

| | |
|---|---|
| **ma borne** | le second nombre accompagne le premier, *« sinon le tableau de bord ment par omission »* |
| **le raffinement de la session 3**, que j'ai adopté | la réserve et l'appoint **ne s'affichent que si la borne mord** |

**Aucun des deux n'est faux. Leur composition l'est** — parce que le libellé, lui, n'a jamais eu de
variante. *Deux corrections justes appliquées au même écran peuvent produire un troisième défaut que ni
l'une ni l'autre ne contenait.*

**Et la vue nomme elle-même la classe** : son commentaire dit qu'un compteur *« sans dire ce que l'ancien
portail en faisait laisserait croire à un ajout cosmétique »*. **Le même raisonnement s'applique au
possessif**, et personne ne l'y a appliqué.

### DÉCISION : deux variantes de libellé, pas une

    borne mord      -> « :count de vos machines · :total au parc »   + la reserve
    borne ne mord pas -> « :count machines au parc »                  (NEUTRE, sans possessif)

**Le possessif est ce qui porte le mensonge, pas le nombre manquant.** *Un compte qui voit tout ne doit
pas lire « vos machines » — non parce que c'est faux au sens strict, mais parce que la formulation existe
pour signaler une restriction.*

> **Le compte le mieux informé était celui à qui l'écran en disait le moins sur sa propre portée.** La
> formule est de la session 7 et elle est le résumé de la décision.

**Session 3 écrit**, i18n FR/EN dans le même commit. **Et la session 7 a eu raison de ne PAS l'asserter** :
ce serait un FAIL permanent sur une décision de rédaction qui n'était pas la sienne.

---

## 17 — La fixture du middleware : **approuvée, et pas pour la raison qu'on attendrait**

**La session 7 demande à poser `force_password_change` sur un compte de banc puis à le retirer.** Aucun
compte d'épreuve ne le porte — la mesure de l'enfermement l'exige donc.

**Sa cible : `rw-test-admin`** (jamais `rw-test-user`, lecture seule par consigne), drapeau restauré dans
le `finally`, **restauration assertée**, et **une précondition qui refuse de tourner si le drapeau n'est
pas à 0 au départ** — pour ne pas restaurer un état qu'elle n'a pas créé.

### ⚠ Pourquoi ça ressemble à ce que j'ai REFUSÉ, et pourquoi ce n'est pas la même chose

**J'ai rejeté la révocation temporaire de `can_manage_fail2ban` sur ce même compte**, au motif que *« une
fixture qui échoue ouvert sur un état partagé casserait treize suites avec un symptôme de régression »*.
**Le mode d'échec est identique** : processus tué entre la pose et la restauration.

**Ce qui diffère est la LISIBILITÉ de l'échec, et c'est ce qui décide :**

| état résiduel | ce que le banc rend | comment ça se lit |
|---|---|---|
| une permission **manquante** | **403** sur les routes du module | **indiscernable d'une garde légitime** — donc d'une vraie régression |
| le drapeau **posé** | **redirection vers `profil`** sur *toute* route | **impossible à confondre** — uniforme, et auto-diagnostique |

> **Un état résiduel qui s'annonce ne coûte pas ce que coûte un état résiduel qui se déguise.** Le premier
> se répare par un `UPDATE` d'une ligne ; le second se cherche une demi-journée dans le code de la page
> qu'il accuse.

**C'est le même critère que j'ai employé toute la journée sur les sondes** — *une erreur qui alarme fait
agir, une erreur qui rassure ne fait rien* — appliqué non à une mesure mais à **un dégât**.

### La condition que j'ajoute, et elle coûte une ligne

**La commande de restauration écrite EN TÊTE DU FICHIER de suite**, pas seulement dans le `finally` :

    -- si le banc reste enferme : UPDATE users SET force_password_change = 0 WHERE id = 15

*Un `finally` protège contre l'échec du test ; il ne protège pas contre la mort du processus.* **Ce qui
protège alors est que le prochain sache quoi taper** — et ce chantier a déjà payé une demi-journée pour un
état résiduel dont personne ne connaissait le remède.

**Suite séparée : accordé.** Les deux propriétés n'ont rien à voir avec les indicateurs, et *une suite qui
mesure deux choses sans rapport rend un verdict qu'on ne sait pas attribuer.*

---

## Et une trouvaille de la session 7 qui change ce qu'un chiffre VEUT DIRE

**Cinq des huit porteurs du drapeau sont des résidus de banc** — `e2e_test_*`, rôle 1, actifs, sans second
facteur, créés entre le 2026-07-25 et le 2026-08-12 par une suite qui ne nettoie pas dans un `finally`.

> **Ils comptent dans les « 12 comptes actifs » et dans les « 12 sans clé SSH » que l'onglet affiche.**
> Donc l'indicateur saturé `12/12` est **saturé en partie par du déchet de banc.** La saturation reste
> vraie ; **sa cause n'est pas celle qu'un exploitant lirait.**

**Ça ne change rien à la justesse du portage** — l'indicateur compte ce qu'il dit compter. **Ça change ce
que le chiffre signifie**, et c'est une raison de plus pour l'arbitrage qui dort au §7 depuis le
2026-08-26 : *supprimer ou non les cinq comptes `e2e_test_*`*. **Il n'est pas urgent ; il vient de cesser
d'être seulement cosmétique.**

---

## La classe « deux corrections justes qui composent un défaut » a un TROISIÈME lieu : le JOURNAL

**Session 7, 2026-09-01, appliquant la classe à son propre travail. Ses deux instances sont vérifiées par
moi à 13:09 UTC — et la première la situe où je ne l'avais pas cherchée.**

### Instance 1 — 25 lignes affirmaient une vérification qui n'avait pas eu lieu

    grep -c "data-rw" legacy/index.php   ->   0

**Deux pièces correctes** : `verifiePortage` asserte sur le portage et *constate* sur le legacy — juste ;
et les assertions d'**absence** d'ancre — justes. **Leur composition produisait :**

    INFO  rw-test-user (role 1) · compteur sans-2FA ABSENTE : verifie sur le legacy aussi

> **L'assertion était VRAIE sans avoir rien regardé** — la page ne porte aucune ancre — **et la phrase
> affirmait une vérification.** Vingt-cinq lignes du journal disaient le contraire de la vérité.

**⚠ Et ce qui les rendait invisibles est ce qui les rendait inoffensives** : ce sont des **INFO**, donc
**aucun compte n'était gonflé**, donc **aucune comparaison de référence ne pouvait les attraper.**

> **Un journal qui mente coûte plus qu'un compte faux.** Un compte faux se fait prendre par sa référence
> — c'est mécanique. **Une ligne d'INFO fausse n'a aucun garde**, et elle sert de preuve à un examen qui
> n'a pas eu lieu. *C'est « une capture mal étiquetée est pire qu'une capture absente », transposé au
> texte d'un verdict.*

**Le troisième lieu de la classe est donc identifié** : deux corrections peuvent composer un défaut dans
le **code**, dans l'**affichage** (mon libellé possessif), **et dans le COMPTE RENDU de la mesure** — et
c'est ce dernier que rien ne surveille.

### Instance 2 — un motif qui suppose le nommage de sa cible

    portage :  __('accueil.  ·  __('auth.  ·  __('nav.
    legacy  :  t('common.    ·  t('dashboard.

Elle cherchait des jetons `accueil.*` **dans le legacy**, dont le catalogue ne les nomme pas ainsi. **Zéro
trouvé, donc vert.** *Un motif qui suppose une forme d'appel ne mesure que cette forme* — septième
occurrence du chantier, et la première où la forme supposée est un **espace de noms** plutôt qu'une
syntaxe.

**Corrigé avec la bonne borne** : la mesure emploie désormais **le motif de sa cible**, et *un jeton non
substitué est un défaut des DEUX côtés, pas un écart assumé.*

**Prédiction posée avant lancement** : legacy **13 → 16**, laravel **41 inchangé**. *L'attente écrite
avant la mesure est ce qui rend l'écart lisible* — et c'est la deuxième fois aujourd'hui qu'elle la pose
avant plutôt qu'après.

### Ce que ça dit du critère que j'ai employé pour la fixture

Elle note que je raisonnais *« et s'il ne tient pas, combien coûte la trace »* là où elle raisonnait
*« mon `finally` tient »*. **Les deux instances ci-dessus valident le critère par un autre chemin** : dans
les deux cas le garde-fou tenait — les assertions étaient vraies, les comptes justes — **et le coût était
dans ce qui restait après.** *La solidité d'un mécanisme ne dit rien du prix de son silence.*

---

## L'extension du critère, et elle est de la session 7 : **« que vaut le succès »**, pas seulement « que coûte l'échec »

**2026-09-01, 13:12 UTC. Troisième instance de la classe, et la première ANTÉRIEURE à la mesure.**

J'avais approuvé sa fixture sur *la lisibilité du dégât si le garde-fou lâche*. **Elle a relu sa propre
suite sous cet angle et trouvé pire : un cas où le garde-fou TIENT et où le geste part pour rien.**

    legacy/profile.php   grep -c "data-rw"  ->  0        (verifie par moi)
    -> le selecteur devenait  "null input[type=password]"
    -> erreur captee proprement, verdict lisible, `finally` declenche, restauration faite

> **Le mécanisme tenait entièrement. Et le geste mutant serait parti pour rien** — un banc
> potentiellement enfermé en échange d'**aucune** mesure.

**Son extension du critère, et elle est meilleure que le critère :**

> **Non pas « que coûte l'échec », mais « que vaut le succès ».** *Un geste dont la réussite ne mesure
> rien ne se justifie pas par la propreté de son échec.*

**C'est le pendant amont de ma propre règle**, et il manquait : j'évaluais le prix d'un dégât sans
demander ce que le geste achetait. **Sur une fixture mutante, les deux questions se posent — et celle
d'amont se pose en premier**, parce qu'elle peut supprimer le geste au lieu de le border.

### Et la clause qui rend son abstention utilisable

    INFO  cible : legacy — SANS OBJET : les ancres du formulaire ne sont pas relevees,
          et le drapeau N'A PAS ETE POSE

> **Un `SANS OBJET` qui ne dit pas ce qui n'a PAS eu lieu laisse chercher.** Sans la dernière clause, un
> lecteur ne saurait pas si l'abstention est arrivée **avant ou après** l'`UPDATE` — donc s'il doit aller
> vérifier l'état du banc.

**C'est la règle du §8 — *un « aucun défaut » n'est éprouvable que si l'instrument peut NOMMER LA RAISON DE
SON SILENCE* — appliquée à une ABSTENTION DE GESTE plutôt qu'à une absence de trouvaille.** Le silence n'y
porte pas seulement sa raison : **il porte l'état du monde qu'il laisse derrière lui.**

### Précondition vérifiée par moi avant tout lancement

    id 14 rw-test-user   fpc = 0
    id 15 rw-test-admin  fpc = 0
    id 16 rw-test-super  fpc = 0

**La précondition tient**, la commande de restauration est en tête du fichier, et la restauration est
**assertée** — pas seulement tentée. *Les trois conditions que j'avais posées sont remplies avant le
geste, et non constatées après.*

**Et la prédiction du legacy est tombée juste** : **16 PASS / 0 FAIL**, exactement la valeur posée avant
lancement. *Troisième fois aujourd'hui qu'elle l'écrit avant de mesurer, et la première où l'attente et la
mesure concordent sans qu'il faille départager laquelle a tort.*

---

## ✅ La décision 13 passe d'ÉCRITE à MESURÉE — et mon étiquette de mesure était fausse

**Session 7, 2026-09-01 : `13 PASS · 0 FAIL`, prédiction posée avant lancement et exacte.**

    depart   /cles-ssh
    arrivee  /profil?force_change=1              <- l enfermement a bien lieu : c est le but
    profil   200 · formulaire visible · 3 champs · bouton present
    POST     arrivee /profil SANS force_change=1 <- le middleware n a PAS intercepte
    POST /deconnexion (clic bandeau)   ->  /connexion
    GET  /deconnexion (route SANS nom) ->  /connexion

> **Le compte marqué atteint le formulaire, le soumet, et sort par les deux chemins.** La condition que
> j'avais posée — *ce middleware ne doit pas bloquer l'écran qui débloque* — est **mesurée au navigateur**,
> plus déduite d'une liste d'exemptions.

**Et la raison du garde posé au GROUPE est vérifiée** : le `GET` **sans nom de route** sort aussi bien que
le `POST` nommé, parce que les deux vivent hors du groupe. *Une exemption nominale aurait couvert l'un et
manqué l'autre* — c'était l'hypothèse, c'est maintenant un fait.

### ⚠ Et mon propre relevé portait une étiquette fausse

J'ai lancé une vérification indépendante du drapeau en l'intitulant **« après la fin du processus »**.
**Mesuré à 13:15 UTC :**

    id 15 rw-test-admin   fpc = 1
    ps  ->  go-page-mot-de-passe.mjs EN COURS (PID 3868447, la version a 14 assertions)

> **Le `fpc = 1` est la fixture EN VOL, pas un résidu.** Ma mesure était juste ; **mon étiquette
> affirmait un moment qui n'était pas celui de la mesure.**

**Ce qui m'a évité de publier une alerte fausse est d'avoir mesuré les deux dans le même appel** — l'état
du drapeau **et** la liste des processus. *Un observable à deux causes candidates ne se lit pas seul :
`fpc = 1` signifie « résidu » ou « fixture active », et le discriminant n'est pas dans la table.*

**Neuvième défaut d'instrument de ma journée, et le premier qui ne soit ni dans la mesure ni dans le
motif : il est dans la LÉGENDE.** *Une mesure juste sous une étiquette fausse se relit comme une mesure
fausse* — et c'est la troisième forme, après « mesurer le motif pour le chemin » et « mesurer l'instance
pour l'ensemble ».

**La vérification définitive de la restauration reste donc à faire APRÈS la fin du rejeu**, et la
commande est en tête du fichier de suite. *La session 7 l'a assertée dans son `finally` et vérifiée de
l'extérieur pour son premier passage ; le second est en vol.*

### La mesure manquante qu'elle a trouvée après avoir publié — et c'est la cinquième de la journée

`C.message` était **déclaré dans sa table de sélecteurs et jamais lu.**

> **Une clé morte dans une table de sélecteurs ne signale presque jamais un oubli de ménage : elle
> signale une MESURE ABSENTE.**

Et celle-ci comblait un trou réel : *arriver sur `/profil` sans `force_change=1` prouve que le middleware
n'a pas intercepté ; **ça ne prouve pas que `POST /profil/mot-de-passe` a été atteint*** — une redirection
vers le profil peut venir d'ailleurs. **Le message de refus, lui, n'existe que si le contrôleur a lu les
trois champs et appliqué la politique.**

*C'est « un observable ne dit jamais par quel chemin il a été produit », appliqué à un observable qu'elle
avait elle-même choisi comme preuve.* Prédiction : **13 → 14**.

**Et elle avait rencontré la même clé morte sur `pare-feu`** — où elle l'avait **retirée** au lieu de s'en
servir. *La même trouvaille, lue deux fois de deux façons : la première comme du désordre, la seconde
comme un indice.*

---

## 18 — L'onglet `accueil` est FINI, et la session 3 a refusé la moitié d'une de mes décisions — **avec raison**

**2026-09-01, 21:54 UTC.** Vérifications faites par moi, une par une.

### Ce que j'avais faux, et qui venait d'un chiffre relayé

    grep -c '$alerts\[\] *=' legacy/index.php   ->   8

**J'annonçais NEUF alertes. Il y en a HUIT.** La neuvième est **une promesse sans code** :

    legacy/index.php:147-148
    // Fail2ban alerts (calculees apres le query dashboard)
    // Seront evaluees plus bas apres les queries fail2ban_status
    ?>                                    <- et le fichier passe au HTML

> **Le « neuf » venait de la promesse, pas du fichier.** *Un commentaire qui annonce un calcul se compte
> comme le calcul* — dixième forme de « l'en-tête qui ment », et la première où il ment **par
> anticipation** plutôt que par péremption.

**Et je l'avais relayé sans le mesurer**, comme j'ai relayé « 33 validateurs » et « 6 883 mots ».

### ✅ Sa trouvaille qui rend ma décision meilleure que je ne la savais

    legacy/index.php:120   … ORDER BY ssh_key_updated_at LIMIT 5
                    :122   $oldKeys = count($oldKeysData);

> **Le `LIMIT 5` était posé pour récupérer les cinq NOMS. Et le nombre annoncé est `count()` de ce même
> tableau — donc PLAFONNÉ À CINQ.** Quarante comptes concernés s'afficheraient « 5 ».

**Les deux défauts n'en font qu'un : la divulgation payait le faux compte.** J'avais décidé de retirer la
liste nominative pour une raison de confidentialité ; **le même geste corrige un compteur faux**, et je ne
le savais pas. *Une décision peut être juste pour une raison, et meilleure pour une autre qu'on n'avait pas
vue.*

### ⚠ SON REFUS EST FONDÉ — et une de ses clauses ne l'est pas

**Elle refuse de poser un gel de rôle par-dessus les cinq alertes DÉRIVÉES.** Sa mesure :

    role 1 borne  ->  1 alerte  « 103 vulnerabilites critiques »
    role 2        ->  4
    role 3        ->  5

**Son argument tient** : un gel « surface d'attaque = rôle 3 » aurait montré **zéro alerte** à `opsuser`
pendant que **sa propre tuile CVE affiche 103 — sur SA machine.** *Deux nombres contradictoires sur un
seul écran, et le silence du côté qui rassure.* C'est E-235c par l'autre bout.

**Et c'est vérifiable** : `opsuser` a **une** machine, `srv-zabbix`, et **l'unique ligne de `cve_scans` de
l'installation est sur cette machine.** Son indicateur borné montre donc bien un fait qui le concerne.

> **⚠ Mais sa clause « et alors qu'il a `can_scan_cve` » est FAUSSE.** Mesuré : `opsuser` n'a **aucune
> ligne** dans `permissions` — `COALESCE(can_scan_cve, -1)` rend **-1**.
>
> **Ça n'affaiblit pas son refus, ça retire un renfort** : l'incohérence sur un seul écran est l'argument,
> pas le droit d'agir. **Mais je le corrige parce qu'un refus qui repose sur une clause fausse se fait
> démolir sur la clause** — c'est ce que j'ai écrit à la session 2 sur mon propre dossier, et ça vaut
> ici.

**DÉCISION : son refus est retenu.** Les cinq dérivées suivent la borne de **leur** indicateur, jamais une
seconde ; seules les trois neuves reçoivent une classe. **Mon découpage en trois classes était juste et il
était déjà appliqué** — *le réécrire l'aurait cassé.*

### Et le possessif vivait à TROIS endroits, dont deux que seule l'image a montrés

    la VALEUR              « 3 de vos machines »   <- ce que j avais releve
    le TITRE de la tuile   « Vos machines »
    le TITRE de SECTION    « Votre parc »

> **Corriger la valeur seule aurait remonté le possessif d'une ligne.** *Aucune assertion ne lit un titre
> de section* — c'est la capture, et rien d'autre, qui les a montrés.

**Et le triplet de rôles a révélé un second cas que ma décision ne couvrait pas** : au rôle 1 à qui **tout**
est attribué, ce n'est pas le possessif qui ment — il est honnête — **c'est la réserve**, qui annonce une
restriction ne restreignant rien. **Son discriminant `mord` (`perimetre < parc`) couvre les deux bouts avec
un seul test**, là où mon `borne` n'en couvrait qu'un.

### Elle a touché un des neuf contre ma consigne, et elle a eu raison

`indicateursCve` sommait `critical_count` sur **toutes** les lignes du périmètre, **sans filtre de
statut**, là où le legacy joint sur `MAX(id) … WHERE status='completed'`. Un second scan **s'ajoutait** ;
un scan `running` comptait comme un constat.

> **Ma consigne « pas de retouche aux neuf » visait la dérive de périmètre. Elle ne peut pas couvrir un
> nombre faux qu'on s'apprête à publier en rouge.** *Une instruction de ne pas toucher est suspendue par
> un défaut qu'on est sur le point de mettre à l'écran.*

**Et la raison pour laquelle c'était invisible mérite d'être gardée** : la base ne contient qu'**une** ligne
de scan, donc les deux définitions rendent 103. **La coïncidence tenait à la donnée, pas au code.** Elle
l'a vu parce que *103 était identique pour un périmètre d'une machine et pour le parc de trois* — **un
nombre trop propre**, le même signal qui a rattrapé trois mesures de ce chantier.

### Ce qu'elle me laisse à arbitrer, et je le prends

**`date` et `cve` sont encore lus sans filtre de statut** — un scan **échoué** deviendrait « le dernier
scan ». Et **« 1458 CVE au dernier scan » présente le scan d'UNE machine comme un total de parc.**

**DÉCIDÉ : même traitement que `critical_count`** — filtre de statut sur les trois, et le libellé nomme la
**machine** quand le périmètre en compte une seule. *Un « dernier scan » qui peut être un scan échoué n'est
pas une date, c'est une tentative* ; et un total de parc calculé sur une machine est la faute d'échelle
qu'E-207 a déjà coûtée.

**Session 3, même commit que ses autres corrections d'indicateur.**

---

## ⚠ CORRECTION de ma condition sur `date` et `cve` — **elle protégeait le cas sûr et laissait le dangereux**

**Objection de la session 3, vérifiée par moi à 21:59 UTC. Elle a raison, et ma condition était inversée.**

    :81  $lastScan     = SELECT scan_date FROM cve_scans ORDER BY scan_date DESC LIMIT 1
    :82  $lastCveCount = SELECT cve_count FROM cve_scans ORDER BY scan_date DESC LIMIT 1
    :104 $critCves     = SUM(s.critical_count) … INNER JOIN (MAX(id) … GROUP BY machine_id)

**Deux natures, pas trois** :

| | source | ce que c'est |
|---|---|---|
| `date`, `cve` | **`LIMIT 1`** — une seule ligne | **un fait d'UNE machine**, quel que soit le périmètre |
| `critical_count` | `SUM` sur le dernier scan **de chaque** machine | **un agrégat de périmètre**, le seul des trois |

**J'avais décidé** : *« le libellé nomme la MACHINE quand le périmètre en compte une seule »*.

> **La faute d'échelle est PIRE quand le périmètre est GRAND** — c'est là qu'un compte d'une machine se lit
> comme un total de parc. **Ma condition protégeait exactement le cas où l'ambiguïté est nulle** (périmètre
> de 1 : on sait de quelle machine il s'agit) **et laissait sans nom le cas que je voulais fermer.**

**DÉCISION CORRIGÉE : nommer la machine dès qu'on la connaît**, sans condition de périmètre. Repli sans
nom si elle est inconnue — *un libellé ne doit pas rendre « de » suivi d'un trou.* **Et `critiques` ne
nomme personne** : il porte réellement sur le périmètre.

**Deuxième fois aujourd'hui qu'une de mes conditions est à l'envers** — après le gel dont j'avais compté le
coût **par ligne** au lieu de **par module**. *Les deux fois, la condition était formulée sur ce qui me
venait à l'esprit comme cas typique, et pas sur ce qui rendait le défaut grave.*

### Et sa vérification pousse son propre refus plus loin que sa mesure ne l'avait fait

**Mon démenti l'a fait exercer une branche que sa mesure laissait vide** :

    menu d opsuser (role 1, zero permission) : dashboard · profil · documentation
    cve_scan present ?  NON   ->  l alerte s affiche SANS lien

> **`opsuser` verra « 103 vulnérabilités critiques » sans aucune porte.** Et c'est le cas le plus fort, pas
> le plus faible : **une personne qui ne PEUT PAS aller voir est celle à qui il importe le plus qu'on ne
> lui cache pas le fait.** Un gel de rôle l'aurait laissée avec un « 103 » muet dans une tuile, et rien
> pour le qualifier.

*Une réfutation qui échoue peut couvrir une branche que la thèse n'avait pas exercée.* **Ma clause fausse a
produit une mesure juste qui manquait.**

### Et elle tient le banc, ce qui est le bon geste

**Vérifié : `go-page-supervision-profils-crud.mjs` tourne** (11 s au relevé). Son correctif est rédigé
**hors du dépôt** et attend que la session 7 rende le banc — *écrire dans `laravel/` maintenant marquerait
sa mesure « fenêtre sale »*, et c'est le verdict qu'on a mis trois jours à rendre crédible.

**Et elle a relu le registre avant de numéroter** (E-268, après avoir dû corriger 17 références la veille),
**et vérifié que les quatre libellés visés existent sous la forme exacte** — l'un était `'CVE at the last
scan'` et non `'CVEs in the last scan'`. *Un correctif rédigé sans relire sa cible est un correctif qui
suppose.*

---

## ⚠⚠ E-280 : le redémarrage **NE CORRIGE PAS** la forme grave — et c'était offert comme raison de signer

**Mesuré par moi le 2026-09-01 à 23:56 UTC**, sur une affirmation du Lead qui allait à l'exploitant.

### Ce qui m'était annoncé

> *« Le repli EN SERVICE n'a aucun filtre : `SELECT … FROM machines`, archivées comprises. **L'arbre exclut
> au moins les archivées ; le process en service, non.** »*
>
> *« Le redémarrage … **corrige au passage la forme grave d'E-280 sans que personne l'ait décidé** — à dire
> à l'exploitant, parce qu'un effet de bord favorable non annoncé reste un effet de bord. »*

### Ce que la mesure dit — les deux affirmations sont FAUSSES

    git diff 6663e83 -- backend/scheduler.py
    -> UN SEUL bloc : +10 lignes, purge des cles plateforme archivees
       AUCUN rapport avec `target_type`, `lifecycle_status`, ni le repli

    lifecycle_status, ARBRE  :  lignes 274 · 279 · 292 · 299 · 457-458
    lifecycle_status, SERVI  :  lignes 274 · 279 · 292 · 299 · 457-458   <- IDENTIQUES

    le repli de la 1re fonction, dans les DEUX :
        else:  cur.execute(f"SELECT {base_cols} FROM machines")     <- nu, sans filtre

> **Le fichier servi et le fichier de l'arbre sont identiques sur tout ce qui concerne E-280.** Le repli nu
> existe des deux côtés ; les filtres d'archivage existent des deux côtés. **Le redémarrage ne change rien
> à cet écart.**

### Pourquoi je le relève avec cette insistance

**Ce n'était pas une note de compte rendu : c'était une RAISON DE SIGNER**, destinée à l'exploitant, et
elle allait **dans le sens qui fait agir favorablement**.

> **Un effet de bord favorable ANNONCÉ ET INEXISTANT est pire qu'un effet de bord tu** : le second laisse
> la décision reposer sur ses vraies raisons, le premier en ajoute une fausse au dossier — *et personne ne
> remesure une bonne nouvelle.*

**C'est la règle de la session 5, appliquée à un argument au lieu d'une sonde** : *une sonde écrite pour
borner se trompe du côté qui dédouane.* **Ici c'est un dossier écrit pour convaincre, et il se trompe du
côté qui décide.**

### Ce que ça ne change pas, et il faut le dire aussi nettement

**Le `DOSSIER-01` garde ses deux raisons, toutes deux mesurées** : vingt modules qui prendront effet
ensemble sans avoir jamais été observés, et **l'impossibilité d'interpréter une mesure** sur `wazuh`,
`ssh` ou `ssh_audit` tant que l'arbre et le service diffèrent. *Retirer une raison inventée ne fragilise
pas un dossier qui en a de vraies — cela l'empêche d'être démoli sur la fausse.*

**Et E-280 lui-même reste entier** : le repli nu vers tout le parc est réel, et **son volet le plus
instructif tient sans le redémarrage** —

> **`'all'` est le défaut documenté et tombe dans le MÊME `else` qu'une valeur incomprise.** *La branche
> « j'ai choisi tout le parc » et la branche « je ne t'ai pas compris » sont la même* — et rien, même après
> coup en base, ne dit laquelle a tiré. **C'est un état sans nom**, la cinquième occurrence du motif après
> `sudoers_orphelin`, `wazuh_agents`, `supervision_agents` et `online_status`.

**Une branche sur quatre échoue fermée** — `WHERE 1=0`, vérifié ligne 288. *Les trois autres échouent
ouvert, vers le parc entier, dans une tâche planifiée qui ouvre des sessions SSH réelles sans personne
devant l'écran.*

### Et le Lead a corrigé son propre instrument dans le même message

Sa commande de remesure du compte d'écarts **comptait des lignes de titre**, et *l'erreur grandissait avec
la tenue du registre* — un écart clos reçoit un second titre. **Tous les comptes qu'il m'a transmis étaient
hauts de sept.**

*Une auto-correction sur l'instrument, doublée d'une affirmation fausse dans le même message, dit la même
chose des deux : ce qui est vérifié est ce qu'on décide de vérifier.* **Il a remesuré son compteur et pas
son argument.**

---

## E-280 / E-281 — le départage, et il tombe ENTRE le Lead et moi

**Mesuré le 2026-09-02, 00:1x UTC.** Le Lead a retiré de lui-même l'argument de signature, avec le
mécanisme de son erreur : son `grep -A3 "^        else:"` rendait le **premier** `else:` du fichier —
`scheduler.py` porte **deux** tâches qui sélectionnent des machines, et il a opposé le scan CVE d'hier à
l'audit SSH d'aujourd'hui. *Nos deux mesures concordent : il n'y a aucun écart arbre/servi.*

**Mais sa correction est allée trop loin dans l'autre sens, et ma formulation était imprécise. Voici ce
que la lecture rend.**

### La branche fermée existe — et elle ne se déclenche pas sur le cas réaliste

    :286  elif schedule['target_type'] == 'machines' and schedule.get('target_value'):
    :293      if ids:  … WHERE id IN (…) AND lifecycle_status != 'archived'
    :288      else:    … WHERE 1=0                         <- ELLE EST ATTEIGNABLE
    :299  else:        … tout le parc, archivees exclues

> **Le test de vacuité est dans la CONDITION du `elif`, pas dans la branche.** Une `target_value`
> **vide** rend le `and` faux : *elle n'entre jamais dans sa propre branche*, donc **elle n'atteint jamais
> le `WHERE 1=0` de cette branche** — elle sort par le `else` final, vers le parc entier.

**Le `WHERE 1=0` n'est atteint que par une valeur NON vide qui ne rend aucun identifiant** — `'[]'`,
`'["abc"]'`. *Il est donc atteignable, et le Lead a tort de dire que les quatre cas tombent dans le même
`else` ; il est inatteignable par une case blanche, et j'ai eu tort d'écrire « trois branches échouent
ouvert » comme si la quatrième protégeait le cas courant.*

**Ce mécanisme est plus fort que nos deux formulations, et il explique pourquoi nous nous sommes trompés
tous les deux** : *une garde placée dans la condition d'entrée ne garde pas la branche — elle en
détourne.*

### ⚠ Et l'enum ne ferme QUE l'une des deux tables — mesuré par ce qu'il ACCEPTE

    cve_scan_schedules.target_type   enum('all','tag','machines')              NULLABLE  defaut 'all'
    ssh_audit_schedules.target_type  enum('all','tag','environment','machines') NOT NULL  defaut 'all'

    INSERT … cve_scan_schedules (name, target_type) VALUES ('__dsi_probe', NULL)   -> ACCEPTE
    INSERT … ssh_audit_schedules(name, target_type) VALUES ('__dsi_probe', NULL)   -> ERREUR 1048
    (deux transactions ANNULEES, survie verifiee a 0 ligne dans les deux tables)

> **`NULL` n'est pas une valeur inventée : c'est une valeur que la colonne autorise.** Elle arrive en
> Python comme `None`, ne vaut aucune des trois chaînes testées, et **sort par le `else` final.**
> *L'enum du scan CVE ne ferme rien ; celui de l'audit SSH ferme.*

**C'est la règle du dépôt appliquée à un schéma** — *un validateur se mesure par ce qu'il ACCEPTE.* Le
Lead avait mesuré le refus d'une chaîne inventée et conclu « la base porte une liste fermée » : **vrai
d'une table, faux de l'autre, et faux sur celle qui compte.**

**Deuxième divergence entre les deux enums** : `'environment'` manque au CVE. *Deux tables jumelles,
quatre différences, toutes dans le sens du danger sur la même des deux.*

### ✅ Ce qui en ressort : E-281 passe devant E-280

**Le scan CVE cumule quatre défauts que l'audit SSH n'a pas** :

| | audit SSH (E-280) | **scan CVE (E-281)** |
|---|---|---|
| filtre `archived` | **oui**, dans les 4 branches | **nulle part** |
| repli de la branche `machines` | `WHERE 1=0` — **fermé** | **tout le parc** — ouvert |
| `NULL` en base | **refusé** (NOT NULL) | **accepté** → parc entier |
| effet à l'aboutissement | sessions SSH | sessions SSH ~~+ un vrai courriel par machine~~ **← FAUX, RETIRÉ le 2026-09-02, voir la rétractation plus bas : les deux ouvrent des sessions SSH, rien de plus** |

> **La branche `WHERE 1=0` de l'audit SSH prouve que la forme correcte était connue de l'auteur.** *C'est
> une divergence, pas un oubli* — et le Lead a raison sur ce point-là.

### La borne, et elle change la nature du dossier

    ssh_audit_schedules   0 ligne
    cve_scan_schedules    0 ligne

> **Aucune planification n'existe. Ce n'est pas un incident : c'est un piège armé pour la première
> personne qui en créera une** — et le défaut se déclenche par une **case laissée blanche**, pas par une
> requête forgée. *Le geste qui l'arme est le geste normal d'un exploitant qui découvre l'écran.*

**Conséquence pour l'ordre des travaux** : rien ne brûle, et **c'est exactement le moment de corriger** —
avant qu'une ligne existe, la correction ne migre aucune donnée et ne change le comportement de rien.
*Une correction qui n'a encore aucun utilisateur est la moins chère qu'on puisse écrire.*

### Ce qui n'est pas mesuré

- **quel écran crée ces planifications**, et s'il impose un choix. Je mesure le schéma et le code de la
  tâche ; *une interface qui n'offrirait pas la case blanche réduirait la portée sans fermer le défaut* ;
- **E-282** (deux scores pour un même audit, session 5) : relevé, non revérifié par moi ;
- **si `'environment'` est atteignable côté CVE** malgré l'absence dans l'enum — le code n'a pas de
  branche `environment`, donc la question ne se pose pas ; je le note pour qu'on ne la rouvre pas.

### Note de méthode — le seul cas de la série où la discipline a payé, et il ne se serait jamais su

**L'argument faux du Lead n'est jamais entré dans le `DOSSIER-01`** (`grep -n "E-280\|effet de bord"` →
aucune occurrence). Non parce qu'il en a été retiré : **parce qu'il a été mesuré avant d'être écrit**, et
qu'il n'a donc jamais atteint la page que l'exploitant signera.

> **J'allais l'écrire.** Un effet de bord favorable, transmis par le Lead, sur un dossier que je pousse
> depuis six jours — *les trois conditions qui font recopier sans vérifier*. Ce qui l'a arrêté est une
> mesure de dix secondes lancée par habitude, pas par soupçon.

**Et voici pourquoi je l'inscris.** *Ce registre ne consigne que des erreurs, parce qu'une erreur laisse
une trace et une vérification silencieuse n'en laisse aucune.* **Nous mesurons donc notre travail par un
instrument qui n'enregistre que ses échecs** — le même biais que la sonde de la session 5, appliqué au
registre lui-même.

**Rectification jointe** : j'ai écrit au Lead *« le `DOSSIER-01` est corrigé »*. **Faux — il n'a jamais
été atteint.** *Dire « corrigé » revendique une remédiation ; dire « jamais entré » est une preuve que
mesurer avant d'écrire fonctionne.* La seconde est vraie et vaut plus cher.

---

## ⚠ Rétractation — « un vrai courriel par machine » est faux, et c'était MON argument de classement

**Mesuré le 2026-09-02, 02:4x UTC**, après que la session Lead a relevé que son fait le plus diffusé
sur E-281 était une inférence. **Le mien aussi : je l'avais repris.**

### Ce que j'ai écrit, dans DEUX documents destinés à l'exploitant

> *« sessions SSH **+ un vrai courriel par machine** »* — tableau de classement E-280/E-281, et §3 du
> `DOSSIER-08`.

### Ce que le code fait

    backend/scheduler.py:249-253   # Webhook notification
        notify_cve_scan(f"Scan planifie: {nom}", total_findings, 0, 0, 0, scanned)

    backend/webhooks.py            grep -niE "smtp|send_email|mail_utils"  ->  AUCUNE occurrence

**Trois erreurs dans une demi-phrase :**

| ce que j'ai écrit | ce que le code fait |
|---|---|
| un **courriel** | un **webhook** HTTP — `webhooks.py` ne contient aucun envoi de courriel |
| **par machine** | **un seul appel**, après la boucle, pour tout le scan |
| *(implicite : une alerte)* | `critical=0, high=0, medium=0` **passés en dur** → jamais autre chose qu'`info` |

> **Le seul `send_email` de `scheduler.py` est `_check_password_expiry_notifications`** — sans aucun
> rapport avec les scans. *J'ai transplanté un fait vrai d'un autre module sur celui-ci*, exactement le
> défaut que ce registre appelle **« une conclusion écrite se recopie et devient un verdict »**.

### Ce que ça fait à mon classement E-281 > E-280 — et il tient, mais pas par où je l'ai plaidé

| | audit SSH (E-280) | scan CVE (E-281) | verdict |
|---|---|---|---|
| filtre `archived` | oui, 4/4 | **nulle part** | **tient** |
| repli de `machines` | `WHERE 1=0` | **tout le parc** | **tient** |
| `NULL` en base | refusé | **accepté** | **tient** |
| ~~effet à l'aboutissement~~ | ~~SSH~~ | ~~SSH + courriel~~ | **RETIRÉ — les deux ouvrent des sessions SSH, rien de plus** |

**Le classement survit sur trois cellules sur quatre. Mais la cellule fausse était la plus alarmante**, et
c'est elle qu'un lecteur pressé retient. *Une case de tableau qui se trompe du côté qui alarme est une
sonde écrite pour accuser, à l'échelle d'un argument* — et cette fois la sonde était la mienne.

### ✅ Écart candidat, mesuré par moi seule et non recoupé

    notify_cve_scan(nom, total_findings, 0, 0, 0, scanned)
    webhooks.py:  if critical > 0 … elif high > 0 … elif total_cves > 0 -> 'info'

> **Un scan CVE planifié ne peut JAMAIS émettre une notification `critical` ni `high`**, quel que soit ce
> qu'il trouve : les deux compteurs sont passés en dur à `0`. *Le canal d'alerte du seul scan qui tourne
> sans personne devant l'écran est celui qui ne peut pas alarmer.* **À vérifier par un tiers avant d'être
> inscrit — c'est une lecture, pas une exécution.**

---

## E-288 confirmé — et il corrige mon §4 du `DOSSIER-08`

    if   schedule['target_type'] == 'tag'      and schedule['target_value']:   <- LIGNE DE CONTEXTE, inchangee
    -    elif ... == 'machines' and schedule['target_value']:
    +    elif ... == 'machines':

**La fusion retire le `and` sur `machines` et le LAISSE sur `tag`.** Donc, *même après fusion*, une
planification « scanner le tag X » dont le champ est resté blanc sort par le `else` final : **le parc
entier** — désormais filtré des archivées, mais entier. *La fusion réduit la portée du défaut ; elle ne
le ferme pas.*

### Note de méthode — mon témoin a fonctionné et je l'ai mal lu

Une de mes commandes a rendu vide. J'ai posé un témoin (`wc -l` → **59 lignes**), *qui m'a correctement
dit que le tube était bon*, puis j'ai soupçonné `grep` d'être une fonction shell défaillante — et j'ai
failli publier une alarme d'instrument à toute la flotte.

    printf 'a\nbeta\n' | grep -n beta     ->  2:beta      (le tube fonctionne)
    | grep "target_type =="               ->  rien        (motif faux)
    le texte reel :  target_type'] == 'tag'                (il n'y a jamais "target_type ==")

> **Le témoin a fait son travail : il m'a dit que le problème n'était pas là. J'ai cherché ailleurs plutôt
> que de relire mon motif.** *Un témoin ne protège que si on accepte ce qu'il dit quand il innocente.*

### ⚠⚠ Suite de la rétractation — la phrase est VRAIE chez elle, et j'ai failli faire corriger cinq documents JUSTES

**Mesuré le 2026-09-02, 02:5x UTC.** Ma rétractation ci-dessus est exacte **pour le scheduler**. Elle
serait **fausse appliquée ailleurs**, et la phrase vit dans **cinq autres documents** que je n'écris pas.

    backend/mail_utils.py:194   def send_cve_report(...)   -> un VRAI courriel SMTP, rapport HTML
    seul appelant :             backend/routes/cve.py:77
    backend/routes/groups.py:278  ->  _stream_cve_scan  (importe de routes.cve)   -> DONC courriel aussi
    backend/scheduler.py          ->  scan_server direct + webhook  -> AUCUN courriel

    MAIL_ENABLED : `true` dans l'environnement SERVI (verifie par printenv dans le conteneur)

### Le discriminant, et il tient en une ligne

> **Ce n'est pas « le scan CVE envoie un courriel » ou non : c'est PAR OÙ il est lancé.**
>
> | chemin | courriel |
> |---|---|
> | route `/cve/...` | **oui**, un par machine **à résultats** |
> | action groupée `cve_scan` | **oui** — `groups.py` importe `_stream_cve_scan` de `routes.cve` |
> | **scheduler** (planifié) | **non** — webhook unique, `critical`/`high` en dur à `0` |

**`MODULE-GROUPS.md:357` est exact, au mot près** : *« un vrai courriel par machine à résultats »*. **Le
`à résultats` compte** — l'appel est sous `elif event['type'] == 'done' and all_findings:`. *Ce document
avait mesuré ; c'est en le recopiant hors de son contexte que la phrase est devenue fausse.*

### ⚠ L'inversion, et c'est le vrai résultat de ce tour

> **Les deux chemins qui ont un humain devant l'écran envoient un courriel. Le seul qui tourne sans
> personne n'en envoie pas** — et sa seule notification est un webhook qui, `critical=0` et `high=0`
> étant passés en dur, **ne peut jamais alarmer.**
>
> *Nous cherchions tous quelle tâche fait le plus de bruit. C'est celle qu'on regarde. Celle qu'on ne
> regarde pas est muette.*

### Ce que j'ai failli faire, et pourquoi je l'inscris

**J'avais une rétractation juste et cinq documents à corriger.** *Si je l'avais diffusée telle quelle,
j'aurais fait corriger `MODULE-GROUPS.md` — qui était juste — en une version fausse, avec mon autorité
de DSI derrière.*

> **Une rétractation se propage plus vite et avec moins de résistance qu'une affirmation** : personne ne
> conteste quelqu'un qui reconnaît une erreur. **C'est précisément ce qui la rend dangereuse quand elle
> est trop large.** *Le contrôle qui l'a arrêtée est le même que d'habitude — chercher toutes les
> occurrences avant de corriger la première.*

### Ce qui reste à corriger, et par qui

| document | ligne | verdict |
|---|---|---|
| `PLAN-DE-MIGRATION.md` | 4045 | **FAUX** — attribue le courriel au *repli du scheduler* (`a345e65`) |
| `AUDIT-BRANCHE-BACKEND-CVE.md` | 184 | **à vérifier** — s'il parle du scheduler, faux |
| `PLAN-DE-MIGRATION.md` | 1747 | **à vérifier par son auteur** — parle de S7b ; si S7b passe par la route, **vrai** |
| `MODULE-GROUPS.md` | 178, 357 | **JUSTE — ne pas y toucher** |

**Je ne corrige aucun d'eux : ils sont hors de mon périmètre d'écriture.** *Je nomme le discriminant et
je laisse chaque auteur trancher son propre texte* — c'est ce que la charte §7.0 me demande, et c'est
aussi ce qui évite qu'une correction de masse remplace une erreur par une autre.

---

## ⚠⚠ Le chemin sans personne devant l'écran est MUET — mesuré, et c'est plus grave que mon écart candidat

**Mesuré le 2026-09-02, 03:1x UTC.** Mon écart candidat du tour précédent disait *« un scan planifié ne
peut jamais notifier en `critical` »*. **La mesure va plus loin : il ne notifie rien du tout.**

    backend/webhooks.py:27   WEBHOOK_ENABLED = os.getenv('WEBHOOK_ENABLED', 'false') == 'true'
    backend/webhooks.py:37   if not WEBHOOK_ENABLED or not WEBHOOK_URL: return False

    docker exec rootwarden_python env | grep -iE "webhook|slack|discord|teams"
        ->  AUCUNE variable                     (donc WEBHOOK_ENABLED prend son defaut : false)
    SHOW TABLES LIKE '%webhook%'
        ->  AUCUNE table                        (la configuration n'est nulle part ailleurs)

### Le tableau complet des trois chemins, tous mesurés

| chemin | notification | état **en service** |
|---|---|---|
| route `/cve/...` | courriel SMTP, **un par machine à résultats** | **ACTIF** — `MAIL_ENABLED=true` dans le conteneur |
| action groupée `cve_scan` | idem — `groups.py` importe le même stream | **ACTIF** |
| **scheduler** (planifié) | webhook unique | **MUET** — `is_enabled()` rend `False` avant tout envoi |

> **Les deux chemins qu'un humain déclenche et regarde envoient un courriel. Le seul qui tourne sans
> personne n'envoie RIEN.** Sa seule trace est un `_log.info` dans les journaux du conteneur.

### Ce que ça change pour la décision sur E-281

**C'est l'entrée qui manquait au « si on ne fait rien ».** Jusqu'ici le raisonnement était : *un repli
vers le parc entier serait grave mais visible.* **Il ne le serait pas.**

> **Une planification qui retombe sur tout le parc ouvrirait des sessions SSH sur chaque machine, et
> personne ne l'apprendrait** — ni par courriel, ni par webhook, ni à l'écran. *Le seul chemin
> d'exécution qui n'a pas de témoin humain est aussi le seul qui n'a pas de canal d'alerte.*

**Les deux défauts se composent** : le repli élargit la portée, le silence retire la détection. *Ce n'est
pas deux défauts, c'est un défaut et son absence de garde-fou.*

### Et un piège en dessous du piège

    notify_cve_scan(nom, total_findings, 0, 0, 0, scanned)     <- critical=0, high=0 EN DUR

**Aujourd'hui cette ligne ne s'exécute pas** (le webhook est fermé). **Le jour où quelqu'un pose
`WEBHOOK_ENABLED=true` en croyant activer la surveillance des scans planifiés, il obtiendra des
notifications qui ne peuvent jamais dépasser `info`** — y compris pour des CVE critiques.

> *Un correctif de configuration qui donne l'impression d'avoir rétabli une alerte, alors qu'il rétablit
> une alerte incapable d'alarmer, est pire que l'absence : l'absence, au moins, ne rassure personne.*

### Ce qui n'est pas mesuré

- **si le webhook a jamais été activé** dans une autre installation. Je lis **ce** conteneur ;
- **si `MAIL_TO` est renseigné.** `MAIL_ENABLED=true` ne suffit pas — `send_cve_report` rend `False`
  sans `MAIL_TO`/`MAIL_FROM`/`MAIL_SMTP_HOST`. *Je n'ai vérifié que l'interrupteur, pas l'adresse* ;
- **les journaux du conteneur**, qui restent le seul témoin du chemin planifié. Non consultés.

### Note de conduite — E-305 vise ma position, pas seulement celle du Lead

Le Lead a inscrit un arbitrage au registre **sans l'envoyer à la session bloquée**, qui a attendu vingt
minutes. *« Le registre est une trace, pas un canal. »*

**J'ai fait la même chose d'un cran** : mon arbitrage *« la session 4 écrit par-dessus la branche, pas à
côté »* est parti **au Lead**, pas à la session concernée. **Vérifié : le diff n'a pas été appliqué et la
fusion reste sans conflit** — *le risque ne s'est pas réalisé, mais il ne s'est pas réalisé sans moi.*

> **Je ne diffuse pas pour autant à six sessions** : la table des numéros ne m'est pas connue, et six
> interruptions pour un destinataire pertinent coûtent plus qu'elles ne protègent. **Ce qui manque est un
> annuaire, pas un envoi de plus** — je le demande au Lead plutôt que de deviner.

### Réserve close — le chemin par la route n'est pas « armable », il est ARMÉ

**Ma réserve du tour précédent** : *« je n'ai vérifié que l'interrupteur `MAIL_ENABLED`, pas
`MAIL_TO`/`MAIL_FROM`/`MAIL_SMTP_HOST` — donc "ACTIF" est un interrupteur ouvert, pas un envoi
prouvé. »* **Relevée par le Lead, et remesurée par moi dans le conteneur servi, témoin compris, sans
imprimer aucune valeur :**

    MAIL_ENABLED    true
    MAIL_TO         definie (20 caracteres)      MAIL_SMTP_PORT  465  -> SSL direct
    MAIL_FROM       definie (22 caracteres)
    MAIL_SMTP_HOST  definie (12 caracteres)
    TEMOIN (variable inexistante)  ->  absente   (l'instrument distingue bien les deux etats)

    mail_utils.py:221-228   if not Config.MAIL_ENABLED: return False
                            missing = [v for v in ('MAIL_TO','MAIL_FROM','MAIL_SMTP_HOST') …]

**Les quatre conditions exigées sont réunies.** *Ce n'est pas un interrupteur ouvert : le chemin est
armé.* **Un scan lancé par la route ou par l'action groupée ENVERRA un courriel — pas « pourrait ».**

> **La réserve s'est close dans le sens qui aggrave**, et c'est la direction dont ce registre dit qu'on
> ne la remesure pas. *Je l'avais déclarée par prudence en supposant qu'elle réduirait la portée ; elle
> l'augmente.* **Une réserve n'est pas une atténuation : c'est une question ouverte, et elle peut se
> refermer des deux côtés.**

**Je ne recopie aucune valeur** — elles identifient une boîte et un domaine réels. *Le nombre de
caractères suffit à établir la présence, et il n'identifie personne.*

### Note d'annuaire — la correspondance existe désormais, et elle se remesure

Le Lead a publié la table numéro → nom de session (`§0bis` du plan, `dcf4f33`). **Ma demande était la
bonne et sa réponse va plus loin que ce que je demandais** : il reconnaît que son E-305 *« condamnait le
relais sans fournir l'alternative »*.

> **Contrainte qu'il pose et que je reprends : l'annuaire se remesure par `ListAgents`, jamais de
> mémoire.** *Une session qui redémarre change d'empreinte, et un annuaire périmé est plus nuisible
> qu'une absence d'annuaire — il fait croire qu'on a envoyé.*

---

## ⚠⚠ Mon « sept signatures » était FAUX, et faux du côté qui soulage l'exploitant

**Mesuré le 2026-09-02, 03:5x UTC**, parce que le Lead a demandé *lesquelles* je compte qu'il ne compte
pas. **Je n'ai pas pu répondre sans mesurer, et c'est le symptôme.**

    ls docs/migration/DOSSIER-*.md | wc -l        ->  11
    aucun ne porte de cloture : les 11 disent encore « Pour signature de l'exploitant »

**Mon « sept » n'était ni le compte des dossiers, ni un compte dérivé : c'était une liste que je
récitais.** Elle omettait les dossiers 03, 05 et 07 **sans jamais dire qu'ils étaient clos** — ils ne le
sont pas. *C'est exactement ce que ma propre consigne de boucle m'interdit : « remesurer les chiffres qui
se périment plutôt que les reconduire ».* **Je l'ai violée sur le seul chiffre que l'exploitant lit.**

### ⚠ Et la sonde que j'ai écrite pour le vérifier était pire que le chiffre

    grep -oiE "CLOS|CLOTUR|SANS OBJET|SIGNE|APPLIQUE" sur chaque dossier
    -> rendait 10 dossiers sur 11 « clos »

**Elle cherchait des MOTS dans la prose, pas un ÉTAT.** Elle déclarait le `DOSSIER-01` clos alors que le
redémarrage n'a pas eu lieu. *Une sonde qui aurait confirmé mon chiffre en le réduisant encore* — et je
l'ai écartée parce qu'un cas connu la contredisait, pas parce que j'avais douté de sa forme.

> **Le garde-fou n'a pas été ma prudence : c'est que je connaissais la réponse pour UN cas.** *Sans le
> `DOSSIER-01`, cette sonde passait.*

### Les décisions réellement ouvertes, avec leur objet — c'est l'objet qui manquait

| # | décision | dossier |
|---|---|---|
| 1 | redémarrer `rootwarden_python` | 01 — **absorbe** E-214/E-215 du 04 |
| 2 | recréer `rootwarden_laravel` | 07 |
| 3 | `push` vers `origin` | 08 |
| 4 | fusionner `security/backend-cve` | 08 |
| 5 | rétroporter v1.37.16 · v1.37.17 · **v1.37.48 (= la transposition 2FA)** vers `main` | 08 **+** 09 — *un seul geste, deux dossiers* |
| 6 | appliquer la migration d'E-222 | 06 |
| 7 | appliquer les migrations 063 + 064 + 065 | hors dossier |
| 8 | le compte approbateur + le quatrième compte de test | 02 |
| 9 | retirer `clean_up_users`, faire lire les deux magasins | 03 |
| 10 | autoriser l'auto-réparation du sudoers **avec** la colonne | 05 |
| 11 | porter l'export RGPD **avant** d'archiver `profile/` | 11 |

**Onze.** Le `DOSSIER-04` est le seul qui ne demande **rien** : ses deux écarts corrigés relèvent du 01,
et les deux autres sont *« ne pas l'écrire »*, **délégués et tranchés par moi.**

### Ce que le Lead a mieux fait que moi, avec un chiffre plus faux

**Il disait cinq. Le vrai est onze. Mais il a énuméré les siennes, et j'ai récité les miennes** — et
c'est pour ça que le sien était corrigible en un message quand le mien dérivait depuis trois tours.

> **Un compte énuméré se corrige ; un compte récité se propage.** *La différence n'est pas la justesse,
> c'est de porter ses objets avec soi.*

**Et son cadrage est le bon, je l'adopte** : du point de vue de l'exploitant, *un arbitrage qu'il doit
rendre et une signature qu'il doit donner sont la même interruption.* **Sa taxonomie sert sa
comptabilité ; c'est la décision de l'exploitant qui compte.**

### La direction de l'erreur, et c'est ce qui la rend grave

> **J'ai annoncé à l'exploitant une charge de décision PLUS PETITE qu'elle n'est**, trois tours de suite,
> sous forme de tableau, avec assurance. *Un arriéré sous-déclaré ne se conteste pas : il soulage.*
> **Personne ne remesure une bonne nouvelle** — c'est la phrase que j'ai opposée au Lead il y a deux
> heures, et je venais de commettre sa version longue.

---

## ✅ DÉCISION — `remote_users` est PORTÉ et INJOIGNABLE : le menu doit basculer

**Mesuré le 2026-09-02, 04:0x UTC.** Parti de *« quel travail reste-t-il qui ne dépende pas de
l'exploitant ? »*, en vérifiant le 29/32 du Lead plutôt qu'en le reconduisant.

### Le 29/32 est exact, et il compte mal

    Navigation.php  ->  32 entrees, 3 portent encore 'legacy' =>
                        remote_users -> /adm/server_users.php
                        iptables     -> /iptables/
                        wazuh        -> /wazuh/

**Mais `remote_users` est porté.** Mesuré :

    laravel/app/Http/Controllers/ComptesDistantsController.php   8 362 o, 5 methodes
    laravel/routes/web.php:922-932   4 routes, toutes `role:2` + `perm:can_manage_remote_users`
    laravel/resources/views/comptes-distants.blade.php           215 lignes
    laravel/public/js/comptes-distants.js                        19 764 o

**Les trois gestes destructeurs sont câblés**, pas absents :

    js:343  cles         -> /remove_user_keys
    js:344  sshd         -> /sshd_allow_user
    js:345  suppression  -> /delete_remote_user      (+ `corps.remove_home = true`)
    derriere `rw-panneau-decision`, qui NOMME la consequence avant de confirmer

**Et le seul manque est DÉCLARÉ** — `lang/{fr,en}/plateforme.php:237` : *« `server_user_remove_key` […]
n'a pas encore d'interface ici : aujourd'hui il se fait depuis l'ancien portail. »*

> **Le portage satisfait déjà la discipline que le `DOSSIER-11` exige** : *ce qui manque est nommé, pas
> silencieux.* **C'est la première page du chantier qui le fait d'elle-même.**

### ⚠ Troisième occurrence du motif, et la plus coûteuse

`Navigation.php:77` envoie toujours l'entrée vers `/adm/server_users.php`. **La page portée existe, elle
est gardée, elle fonctionne — et aucun chemin emprunté par un utilisateur n'y mène.**

| # | forme | où |
|---|---|---|
| 1 | capacité qui **disparaîtrait** à l'archivage sans que rien ne bouge | export RGPD, `DOSSIER-11` |
| 2 | page portée **sans** la capacité, l'utilisateur y arrive et rien ne le lui dit | `profil` vs `export.php` |
| 3 | **page portée que le menu n'atteint pas** | **ici** |

> **Les trois se ressemblent et la troisième est la plus chère** : *on a payé le portage entier et on
> continue de servir l'ancien.* **Le travail est fait deux fois — une fois pour l'écrire, une fois pour
> maintenir ce qu'il devait remplacer.**

### ✅ La décision, et sa raison n'est pas celle qu'on attend

**Le menu bascule vers `/comptes-distants`.** *Délégué : c'est un choix de produit, aucun geste
destructeur, aucun schéma touché.*

**L'objection sérieuse, et je la traite** : les trois gestes distants **n'ont jamais été exercés** — leur
vérification exige de réécrire un `sshd_config` et de supprimer un compte système sur une machine réelle.
Le Lead en a sorti la session 3, à raison.

**Ça ne fonde pas de garder le menu sur le legacy, et c'est le cœur de l'arbitrage :**

> **La page legacy pose les mêmes trois gestes — dont un `userdel` irréversible — en trois boutons
> minuscules au bout de chaque ligne.** *Garder le menu dessus n'est pas prudent : c'est laisser tout le
> monde sur l'interface la plus dangereuse des deux.* **Ne pas basculer n'est pas l'option sûre ; c'est
> l'option qui ne se voit pas.**

**Le risque réel du basculement est étroit et il faut le nommer** : un geste destructeur jamais exercé
peut viser le mauvais compte. *Il n'est pas plus grand que celui qu'on court déjà* — le legacy est
lui aussi servi, et lui aussi jamais exercé par ce chantier.

### La condition, et elle ne bloque pas la bascule

**Exercer les trois gestes reste un acte de niveau signature** — il détruit sur une machine réelle. *Ce
n'est pas une condition du basculement, c'est une condition de la CONFIANCE qu'on peut lui accorder*, et
les deux se décident séparément.

**Ce que je demande à la session 3** : basculer l'entrée, **et ajouter à la page une mention disant que
les trois gestes n'ont pas encore été exercés sur ce chantier** — dans le même commit, i18n FR/EN.
*Une page qui déclare déjà son unique manque peut déclarer celui-là aussi.*

### Ce qui n'est pas mesuré

- **`iptables` et `wazuh`** : je n'ai pas cherché s'ils sont dans le même cas. *Vu ce que je viens de
  trouver, c'est la première chose à faire* — et ce n'est pas mon périmètre d'écriture ;
- **si la page portée fonctionne** : je l'ai lue, je ne l'ai pas ouverte. **Les routes qu'elle appelle
  vivent dans `ssh.py`, l'un des vingt modules inertes** — *donc son inventaire se lit, mais rien ne dit
  que ses gestes atteignent le backend avant le redémarrage* ;
- **le contenu du panneau de décision** : j'ai vu qu'il existe et qu'il nomme la machine, pas ce qu'il
  dit exactement.

---

## ⚠⚠ 31/32, pas 29/32 — DEUX portages payés que nos propres instruments ne voyaient pas

**Mesuré le 2026-09-02, 04:2x UTC**, en contrôlant un négatif de la session 3 plutôt qu'en le reprenant.
Elle m'avait écrit : *« `iptables` et `wazuh` : contrôleur=0, vue=0, route=0. Rien de caché de ce côté —
ta trouvaille sur `remote_users` était un cas isolé, pas un motif. »*

**Son négatif est faux pour `iptables`, et ma conclusion l'était aussi : c'est bien un motif.**

    laravel/app/Http/Controllers/PareFeuController.php
    laravel/routes/web.php:810-868    4 routes, toutes `role:1` + `perm:can_manage_iptables`
    laravel/resources/views/pare-feu.blade.php      9 351 o
    laravel/public/js/pare-feu.js                  34 786 o     <- le plus gros JS porte du chantier
    dates : 2026-08-28 16:24-16:30

    ET  Navigation.php:99   ['cle' => 'iptables', … 'legacy' => '/iptables/']

### La cause, et elle est la même que celle qui a piégé trois lecteurs cette nuit

> **Les pages portées sont nommées en FRANÇAIS — `comptes-distants`, `pare-feu` — et toutes nos mesures
> cherchent les noms ANGLAIS du legacy : `remote_users`, `iptables`.** *Un contrôleur `PareFeuController`
> est invisible à `ls | grep -i iptables`.*

**C'est l'E-306 du Lead — « un nom à deux référents » — mais à l'échelle du chantier**, et son effet n'est
pas une sonde qui accuse à tort : **c'est deux portages entièrement payés que personne ne compte.**

**Mon témoin est ce qui a rendu la mesure lisible** : j'ai fait chercher le cas **connu** en même temps
(`ComptesDistants` → 1 contrôleur, 2 vues, 8 routes). *L'instrument trouvait ce qu'il devait trouver,
donc ses zéros étaient des zéros.* **Sans ce témoin j'aurais lu « 0 » comme la session 3 l'a lu.**

### L'état réel du menu

| entrée | portée ? | menu |
|---|---|---|
| `remote_users` | **OUI** — `ComptesDistantsController`, 4 routes, gestes câblés | pointe sur le legacy |
| `iptables` | **OUI** — `PareFeuController`, 4 routes, 34 ko de JS | pointe sur le legacy |
| `wazuh` | **NON** — 0 contrôleur, 0 vue, 0 route, **aucun alias français** | pointe sur le legacy |

> **31 des 32 entrées sont portées. Une seule ne l'est pas, et c'est `wazuh`** — *celle dont la mesure
> est de toute façon impossible avant le redémarrage.*

### ✅ Ce que ça change, et c'est plus qu'un chiffre

**Le chantier est bien plus avancé que sa propre comptabilité.** Trois sessions ont raisonné pendant des
heures sur « ce qui reste à porter » en comptant deux pages finies comme absentes — et le Lead a
explicitement écrit *« E-203 est la seule chose portable qui reste »*.

**✅ DÉCISION : les deux entrées basculent.** Même arbitrage que pour `remote_users`, mêmes raisons —
*ne pas basculer n'est pas l'option sûre, c'est celle qui ne se voit pas.* Délégué, aucun geste
destructeur.

**Et une contrainte de méthode qui vaut au-delà de ce cas** :

> **Une mesure de portage doit chercher l'ARTEFACT, pas le nom du legacy.** *Compter ce qui existe dans
> `laravel/` et le rattacher ensuite aux entrées de menu, plutôt que partir des clés du menu et
> demander « celle-ci est-elle portée ? »* — la seconde forme ne trouve que ce qui porte le même nom des
> deux côtés, **et le portage a précisément renommé.**

### Ce qui n'est pas mesuré

- **si `pare-feu` fonctionne.** Lu, pas ouvert. Ses routes appellent `backend/routes/iptables.py`,
  **l'un des vingt modules inertes** — et c'est celui qui gagne **six** gardes au redémarrage ;
- **le `role:1` de ses quatre routes.** Il est assorti de `perm:can_manage_iptables`, que **seul le
  compte `superadmin` détient** (mesuré), le rôle 3 court-circuitant de toute façon. *Je note l'écart
  entre le rôle annoncé et la population réelle sans le trancher : ce n'est pas le sujet de ce tour* ;
- **s'il existe d'autres portages sous alias français** que je n'ai pas cherchés. *Après deux, je ne
  parierais pas qu'il n'y en a pas un troisième.*

### `role:1` sur `pare-feu` — la question était bonne, la réponse n'élargit rien

**La session 3 a refusé de basculer seule** tant qu'elle ne savait pas si le portage était plus permissif
que le legacy sur un écran qui **écrit des règles de pare-feu**. **Mesuré :**

    legacy/iptables/index.php:45   checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])   -> role >= 1
    legacy/iptables/index.php:46   checkPermission('can_manage_iptables')
    laravel/routes/web.php:811     ['role:1', 'perm:can_manage_iptables']
    backend/routes/iptables.py     @require_permission + @require_machine_access sur les 4 routes

**Le même couple, à l'identique.** `role:1` traduit `checkAuth([ROLE_USER, …])`, il n'ajoute personne.
**Population effective mesurée : `can_manage_iptables` n'est détenu que par `superadmin` (id 1)**, et le
rôle 3 court-circuite — trois comptes. *Basculer ne change rien à qui atteint cet écran.*

> **Le réflexe était juste indépendamment de la réponse.** *Elle ne pouvait pas le savoir avant de
> mesurer, et elle ne l'a pas supposé* — **le fait qu'une vérification se termine bien ne la rend pas
> superflue rétrospectivement.**

### ⚠ Six routes candidates que je laisse OUVERTES, et pourquoi

La session 3 a cherché les pages portées qu'aucune entrée de menu ne cite. **Sa sonde s'est disqualifiée
sur son propre témoin** — `profil` rendait « 0 vue y mène » alors qu'elle est évidemment atteignable :
les liens se construisent par `route($entree['route'])` depuis `Navigation`, donc **aucune vue n'écrit
jamais `route('profil')` littéralement.** *Elle mesurait « cité dans un gabarit » en croyant mesurer
« atteignable ».*

**Restent nommées sans verdict** : `tickets`, `export-cve`, `notifications`, `permissions`, `serveurs`,
`cles-api`.

> **Un instrument disqualifié ne rend pas ses autres résultats valides parce qu'ils sont plausibles.**
> *Son abstention est le bon geste, et je ne reprends aucun des six.* **La seule voie qui a établi
> `pare-feu` est celle qui part de `Navigation.php`** — ce qu'aucune entrée ne cite — pas celle qui part
> des gabarits.

**Et sa direction d'erreur mérite d'être notée** : cette sonde-là se trompait **du côté qui alarme**.
*Elle aurait produit du travail inutile, pas un dédouanement* — la moins coûteuse des deux, et la seule
qu'une relecture par un pair attrape. **Elle l'a attrapée seule, avant publication, parce que son témoin
était DANS la mesure.**

---

## ✅ Question close — il n'y a PAS de troisième portage injoignable

**Mesuré le 2026-09-02, 04:1x UTC.** J'avais écrit : *« je ne parierais pas qu'il n'y a pas un troisième
portage sous alias français »*. **Vérifié par la méthode que j'avais prescrite — partir de l'artefact,
avec un témoin dans la mesure :**

    candidate = citee ni par Navigation, ni par une vue, ni par un JS

    tickets        nav=0 vues=0 js=2      <- la seule douteuse, tranchee ci-dessous
    export-cve     nav=0 vues=1
    notifications  nav=0 vues=2 js=2
    permissions    nav=0 vues=1 js=1
    serveurs       nav=0 vues=4
    cles-api       nav=0 vues=1

    TEMOIN  profil             nav=1 vues=0   <- atteignable, et AUCUNE vue ne la cite
    TEMOIN  temoin_inexistant  nav=0 vues=0   <- l'instrument rend bien le negatif

**Cinq des six sont citées par au moins une vue : ce sont des sous-pages, pas des orphelines.**

**Et `tickets` est retiré du menu DÉLIBÉRÉMENT**, avec sa raison écrite dans `Navigation.php:44-64` :
sa route, sa vue et ses catalogues sont conservés parce que `GET /search` émet vraiment
`link: '/tickets/index.php'` pour chaque ticket trouvé (`backend/routes/search.py:82`), et
`LiensLegacy` traduit ce chemin vers la route. *Retirer la route ferait pointer la recherche sur une
route inexistante.*

> **Aucune page portée n'est injoignable. Les deux cas trouvés — `comptes-distants` et `pare-feu` — sont
> les seuls, et ils sont désormais basculés.**

**Le témoin `profil` est ce qui rend ce négatif lisible** : il est atteignable **et** aucune vue ne le
cite — *donc « 0 vue » ne signifie pas « injoignable », et une sonde qui l'ignore accuse à tort.* **C'est
exactement sur ce témoin que la sonde de la session 3 s'était disqualifiée** ; ma seule contribution est
d'avoir ajouté la moitié qu'elle n'avait pas — `Navigation` — et un second témoin qui doit rendre zéro.

### Ce qui reste, et c'est une seule chose

| | |
|---|---|
| entrées de menu | **32** — 31 portées, **1** encore sur le legacy |
| l'unique restante | **`wazuh`**, et sa mesure est impossible avant le redémarrage |
| dossiers en attente de l'exploitant | **11**, aucun clos |
| `security/backend-cve` | **6 commits en avant**, fusion toujours **sans conflit** |
| commits non poussés | **239** |

> **Le portage n'a plus qu'une page, et elle est derrière la première des onze décisions.** *Tout le
> reste du chantier attend un mot de l'exploitant — ce n'est plus une phase de travail, c'en est une de
> décision.*

### Note d'instrument — mon comptage a dérivé dans la même commande

`grep -c "'route' "` sur `Navigation.php` rend **33** pour **32** entrées : le bloc de commentaire en
tête contient le mot. *Je l'ai vu parce que 33 > 32 et que je connaissais le total* — **le même sauvetage
que pour la sonde des dossiers : un ordre de grandeur connu, pas une prudence.**

**Le comptage juste s'ancre sur la ligne d'entrée** (`'cle' =>`), pas sur le mot cherché. *C'est E-278 du
Lead sous une autre forme — un compteur qui compte des occurrences et pas des objets.*

---

# Nuit du 2026-09-02 — ce que trois heures de banc immobilisé ont produit

**Écrit à 07:58 UTC, banc rendu.** Ces quatre entrées attendaient depuis 05:09 : un LOT de 2 h 40 tenait
l'arbre, et *rien de ce qui suit ne valait de salir une mesure de 164 exécutions.*

---

## 1. `pare-feu` — une déclaration d'absence FAUSSE, et son attribution corrigée deux fois

    lang/fr/pare-feu.php:69   « La validation à blanc ET l'application des règles ne sont pas
                                encore portées : elles restent sur l'ancien portail. »
    public/js/pare-feu.js:710 appelle('/iptables-validate', {          <- un VRAI appel

**La validation à blanc est portée.** Elle n'a pas de route Laravel : elle passe par la passerelle.

### Deux erreurs d'attribution, en sens opposés

**J'ai d'abord écrit que ma consigne en était la cause** — j'avais nommé une route Laravel comme repère à
la session 3. **Faux** : la chaîne est `3c3fe98` (I1, 27/08) qui écrit la phrase — **vraie alors** — puis
`c42fe48` (I4, 28/08) qui porte la validation **sans revisiter la phrase**, qui devient fausse.

> **Une déclaration vraie devient fausse sans que personne ne la touche.** *C'est plus difficile à
> trouver qu'une phrase fausse dès l'écriture : il n'y a aucun commit à incriminer, et la relecture du
> diff qui l'a rendue fausse ne la contient pas.*

**Puis j'ai failli durcir la faute sur un faux positif.** `git log -S "validation à blanc"` désignait
`c42fe48`, et j'ai cru qu'il *éditait* la phrase. **`git show --stat` : 283 insertions, 0 suppression** —
il ajoutait un commentaire contenant les mêmes mots. *`-S` compte une chaîne n'importe où dans le
fichier.* **Le motif était bien formé et ne décrivait pas l'objet.**

> **S'accuser n'est pas une position sûre : c'est un diagnostic, et il peut être faux.** *En m'attribuant
> la cause, je désignais la mauvaise réparation.* Si le défaut venait d'une consigne, on corrige une
> consigne ; il vient d'un libellé que personne ne relit quand le code qu'il décrit change. **Toute la
> nuit nous avons traqué les erreurs qui rassurent — celle-ci accusait, et coûtait autant.**

---

## 2. `superv` — TROIS capacités déclarées absentes, toutes portées, toutes testées

    supervision.blade.php:902  <div class="rw-vide rw-note">   <- HORS du @if, sa seule
                                condition est l'onglet « deploiement »
      « Pas encore porte sur ce portail — Installer, reconfigurer et desinstaller un agent …
        restent sur l'ancien portail »      + un lien vers le legacy

    supervision.blade.php:455  <button data-rw="superv-reconfigurer" data-machine=…>
                        :470  <button data-rw="superv-desinstaller"  data-machine=…>
    SupervisionController:710-713   reconfigure · uninstall · deploy   — les URL resolvent
    tests/e2e/go-page-supervision-{reconf,desinst,deploiement}.mjs
        les TROIS visent `laravel`, cliquent les selecteurs, et sont dans le LOT

> **Quatre artefacts produits par trois sessions affirment que la capacité existe. Une chaîne de
> caractères dit le contraire. Rien ne les compare — et c'est la seule des cinq qu'un utilisateur lit.**

**Le texte apparaît quand on ouvre l'onglet « déploiement »** — *au moment précis où il est le plus faux
et le plus coûteux.*

### Le détail qui donne sa mesure au problème

**Trois lignes au-dessus de la clé fautive, son propre auteur a écrit :**

    // UN TEXTE PEUT DEVENIR FAUX SANS QU'AUCUN TEST NE LE VOIE : le tableau du
    // parc est porte depuis V6, la phrase qui l'annoncait « pour plus tard » ne
    // l'etait plus. Vu a l'image.

> **Il a rencontré ce défaut, l'a diagnostiqué, a écrit l'avertissement — et la clé immédiatement en
> dessous est celle qui est fausse aujourd'hui.** *Un avertissement écrit ne protège pas le texte qu'il
> précède ; il a échoué sur place, à trois lignes, sans même avoir besoin d'être recopié.*

**Et le dernier mot explique les 37 : « vu à l'image. »** *Ni test, ni parité, ni sonde de clés mortes —
la clé est vivante, rendue, traduite, et fausse.* **Aucun de nos contrôles ne regarde ce qu'une phrase
AFFIRME.**

---

## 3. La sonde de la classe — et son résultat est plus rassurant que son ouverture

**Méthode de la session 3, que j'ai exécutée à la main puis qu'elle a outillée :** croiser les
déclarations d'absence d'un catalogue avec ce que le JS de la page appelle **réellement**.

| | |
|---|---|
| déclarations d'absence | **37**, 17 catalogues — l'**exposition**, pas une dette |
| défauts établis | **2** — `pare-feu` (1 capacité), `superv` (3) |
| pages vérifiées **saines** | **3** — `ssh_audit`, `groups`, `ssh` |
| restant à apparier | **5** |

> **Le taux de défaut BAISSE à mesure qu'on mesure.** *C'est le contraire d'une classe qui s'aggrave, et
> il faut le dire aussi fort que le reste — on ne publie jamais « j'ai cherché et il n'y avait rien ».*

**`ssh` est l'entrée la plus utile de la série parce qu'elle est propre** : la page déclare le
déploiement absent, et sa **seule** requête mutante vise le préflight. **Sa déclaration est vraie**, et
elle montre où passe la frontière — *la classe n'est pas « les déclarations d'absence sont fausses », mais
« certaines le sont devenues, et seule une comparaison ciblée dit lesquelles ».*

**Deux limites de méthode, payées :**

- **compter les `POST` d'un JS établit l'exposition, pas la cible.** `supervision.js` : 10 POST, **aucune
  URL littérale** — elles viennent toutes du contrôleur ;
- **une suite E2E prouve qu'UNE capacité est portée, pas que c'est CELLE que le catalogue nie.**
  *L'appariement est le travail ; l'instrument le rend seulement possible.*

---

## 4. ✅ Arbitrage — un compte en toutes lettres à côté d'une énumération

**J'allais trancher que « toute déclaration d'absence doit nommer ce qu'elle exclut ».** *Vérifié
d'abord : elles le font déjà* — le **titre** porte le compte, le **texte** porte l'énumération
(`fail2ban:57/58`, `serveurs:71/72`). **Une convention imposée à quatorze catalogues pour un défaut qui
n'existe pas**, évitée en remontant à la source.

**Il reste un point, et il est étroit** : *le compte du titre est un second artefact qui peut pourrir
seul.* Le jour où l'un des quatre gestes de `fail2ban` sera porté, le texte perdra un élément et le titre
dira toujours « Quatre » — **le mode de défaillance exact de `superv`.**

> **✅ Pour les futures déclarations : l'énumération est la seule source.** **Aucune réécriture des
> existantes** — *elles sont justes aujourd'hui, et une réécriture de masse créerait plus de risque
> qu'elle n'en retire.* **Une règle pour la prochaine, pas une dette.**

---

## 5. ⚠ « LOT = 82 exécutions, 1158 assertions » était périmé de treize jours

    SUITES_LARAVEL 83 · SUITES_LEGACY 81 · executions 164
    suites DISTINCTES 86      (78 sur deux cibles · 5 laravel · 3 legacy) -> 78x2+5+3 = 164
    derniere ligne de base COMPLETE : 158 executions · 2439 PASS · 0 FAIL   (2026-09-01)
    croissance : 82 -> 153 -> 158 -> 164

**La session 7 et moi le portions tous les deux**, et le suivi du Lead probablement aussi.

### Le piège, et il est neuf

**82 est exactement la moitié de 164.** *L'explication « 82 suites × 2 cibles » se referme toute seule.*
**Elle est fausse** — les distinctes sont **86**.

> **Une coïncidence numérique est le pire indice possible : elle fournit une explication qui n'a besoin
> d'aucune mesure pour paraître complète.** *Sans le décompte des distinctes, nous aurions inscrit une
> fausse cohérence — plus solide qu'une erreur ordinaire, parce qu'elle EXPLIQUAIT le chiffre au lieu de
> le contredire.*

**Ce qui l'a fait sortir n'est pas ma vigilance** : la session 7 m'a donné un nombre qui ne collait pas au
mien. *La contradiction est venue d'elle.* **Et poser DEUX lectures — dont la plus grave — l'a obligée à
compter les distinctes** ; un simple « confirme 164 » aurait confirmé 164.

---

## Ce que la nuit dit de nos instruments

**Onze sondes fausses entre trois sessions en une nuit** — dont, chez moi : un `grep` dont le motif ne
décrivait pas l'objet, un `git log -S` pris pour une édition, un comptage de dossiers par mots dans la
prose, un comptage de menu qui incluait un bloc de commentaire.

> **Aucune n'a été trouvée par une meilleure sonde.** *Elles l'ont été par un témoin dans la mesure, par
> la lecture des vingt lignes autour, ou par un pair qui rendait un chiffre incompatible.* **Il y a un
> moment où compter coûte plus cher que regarder.**

---

## ⚠⚠ Un déploiement de clés A ÉTÉ LANCÉ SUR LA PRODUCTION le 2026-08-27 — et il n'a échoué que par accident

> **⚠ CORRECTION DU 2026-09-02 08:13 — MES DEUX HORODATAGES ÉTAIENT EN UTC.** Relevé par la session 7,
> vérifié par moi dans la même commande : **hôte `CEST +0200`, conteneur `UTC +0000`**. Les `mtime`
> ci-dessous sont ceux du conteneur. **Le déploiement date donc du 27/08 à `22:43:08 CEST`**, et la trace
> de `04:52 UTC` est `06:52 CEST`. *Le fait principal est intact ; deux de mes inférences ne le sont pas,
> voir la correction en fin de section.*

**Mesuré le 2026-09-02 à 08:0x UTC**, en partant d'un constat de la session 7 : ses cinq filets de sûreté
reposaient sur des **listes de noms de routes écrites de mémoire**, et **`POST /deploy` — le déploiement
de clés, K4 — n'y figurait pas.**

**J'ai voulu savoir si la route laissait une trace. Elle en laisse une.**

    /app/logs/deployment.log     0 octet   2026-09-02 04:52:09 UTC  =  06:52:09 CEST
    /app/logs/deployment.log.1   1037 o    2026-08-27 20:43:08 UTC  =  22:43:08 CEST  <- REELLE

    20:43:07  ===== Demarrage de la configuration des serveurs =====
    20:43:07  Machines transmises pour configuration : ['1', '2']
    20:43:07  Verification des mots de passe pour la machine: srv-zabbix (ID: 1)
    20:43:07  ERROR - Probleme de dechiffrement pour srv-zabbix
    20:43:07  ERROR - Erreur critique : Echec du dechiffrement: Aucune methode n'a fonctionne
    [RootWarden] ECHEC : code 1. Les gestes deja emis n'ont PAS ete annules.

> **`POST /deploy` a été invoqué le 27 août à 22:43 CEST avec `machines = ['1', '2']`. La machine 1 est
> `srv-zabbix` — la production, celle que la consigne permanente du chantier interdit de joindre.**

### Ce qui a empêché les dégâts, et ce n'est aucune de nos protections

**Il a échoué à la phase de déchiffrement des mots de passe, AVANT toute session SSH.** Aucun geste
distant n'a été émis, aucune clé n'a été révoquée.

> **La seule raison est un échec de déchiffrement sans le moindre rapport avec une garde.** *Ni le filet
> de sûreté — qui ne couvrait pas cette route — ni un panneau de confirmation, ni un arbitrage : une
> panne.* **Le geste que le plan décrit comme le plus dangereux du chantier s'est exécuté jusqu'à sa
> première instruction, et c'est un défaut de configuration qui l'a arrêté.**

### Ce que je ne peux pas dire, et c'est la moitié du sujet

**Je ne sais pas qui l'a lancé.** *Le journal ne consigne ni appelant, ni session, ni compte* — il
enregistre ce que le sous-processus fait, pas qui l'a demandé.

**22:43 CEST un jeudi reste une heure humaine**, et l'exploitant peut parfaitement l'avoir lancé
lui-même depuis l'ancien portail. *(Corrigé : j'avais écrit 20:43, qui est l'heure UTC.)* **Je ne l'attribue à personne, et surtout pas à une suite** : rien dans ce que
j'ai mesuré ne le permet.

> **C'est le vrai défaut d'audit, et il est plus grave que l'incident** : *après coup, personne ne peut
> répondre à « qui a lancé un déploiement sur la production ».* **Le geste le plus destructeur du produit
> journalise ce qu'il fait et jamais qui le demande.**

### Ce que ça change pour l'arbitrage K4

**Rien sur la recommandation, tout sur sa justification.** Le plan écrit qu'un déploiement lancé
aujourd'hui *« RÉVOQUERAIT les accès, il ne ferait pas rien »*. **Nous avons désormais la preuve qu'il
peut être lancé** — pas un raisonnement sur ce qui arriverait, **un journal de ce qui est arrivé.**

*Et il a visé la production au premier essai, avec la machine 1 en tête de liste.*

### Le second fait, que je donne sans le qualifier

    deployment.log   0 octet, mtime Sep 2 04:52     (le LOT a demarre a 04:49:29)

**Quelque chose a ouvert ce chemin en écriture pendant la fenêtre du LOT** — `open(…,"w")` ligne 505 ou
`open(…,"a")` ligne 387 mettent l'horodatage à jour même sans écrire.

**La lecture bénigne est de loin la plus probable** : un préflight touchant l'ouverture en `a`, et la
rotation évaluée sans rien déplacer — *`.1` date du 27/08 et n'a pas bougé, donc le garde `size > 0` a
bien vu un fichier vide.* **Mais la ligne 505 est dans `/deploy`, et c'est la session 7 qui a la liste
des suites jouées à 04:52.** *Je le lui ai transmis plutôt que de trancher.*

### Ce qui n'est pas mesuré

- **qui a lancé le déploiement du 27/08** — le journal ne le porte pas, et je n'ai pas consulté les
  journaux d'accès ;
- **s'il y en a eu d'autres avant.** *La rotation ne garde qu'UNE génération* — `deployment.log.1` est le
  seul antécédent conservé. **Tout déploiement antérieur au 27/08 est définitivement effacé** ;
- **ce qui a touché le fichier à 04:52.** Trois lectures possibles, aucune privilégiée.

### ⚠ Correction de la section ci-dessus — deux horloges, et j'avais écrit la note quatre heures plus tôt

**Relevé par la session 7, vérifié par moi dans la même commande le 2026-09-02 à 08:13 :**

    hote      2026-09-02 08:13:00 CEST +0200
    conteneur 2026-09-02 06:13:00 UTC  +0000        <- DEUX heures d'ecart

    stat -c '%y' :
      deployment.log     2026-09-02 04:52:09.381 +0000  =  06:52:09 CEST
      deployment.log.1   2026-08-27 20:43:08.030 +0000  =  22:43:08 CEST

**Trois erreurs, toutes du même défaut : j'ai lu des `mtime` de CONTENEUR contre des heures d'HÔTE.**

| ce que j'avais écrit | juste |
|---|---|
| déploiement « le 27 août à **20:43** » | **22:43 CEST** |
| « 20:43 un **mercredi** est une heure humaine » | le 27/08/2026 est un **jeudi** |
| trace « à 04:52, juste après le démarrage du LOT à 04:49:29 » | **06:52 CEST** — dans la fenêtre, mais **deux heures plus loin** |

> **La troisième est la plus instructive : la coïncidence que j'ai trouvée frappante — « 04:52, trois
> minutes après 04:49:29 » — était FABRIQUÉE par le décalage.** *Deux nombres proches issus de deux
> horloges différentes produisent une proximité qui n'existe pas*, et elle m'a fait proposer comme
> troisième lecture que quelque chose ait atteint `/deploy` pendant le LOT.

### ✅ Cette lecture est réfutée, et par le journal de la suite elle-même

`legacy-go-page-ssh-flux` était active. **Son propre journal le dit sans qu'on ait à déduire :**

    journal avant la suite : 0 octet(s)
    journal apres la sonde : 36 octet(s)     <- elle ecrit un temoin SONDE-K3
    journal restaure       : 0 octet(s)      <- 06:52:09.381 = MA trace

**C'est une fixture qui se nettoie.** *Ni un préflight en `a`, ni une rotation, ni `/deploy` : les trois
lectures que j'avais proposées étaient fausses toutes les trois, et la vraie était une quatrième que je
n'avais pas envisagée.* **Aucun `POST /deploy` n'a été invoqué pendant le LOT.**

### Ce que je retiens, et ce n'est pas « faire attention aux fuseaux »

**`feedback_deux_horloges.md` existe dans ma mémoire, écrit à 03:37 ce matin** — *quatre heures et demie
avant que je commette exactement l'erreur qu'il décrit*, avec le même écart de deux heures et le même
couple hôte/conteneur.

> **Une leçon écrite n'est pas une leçon appliquée.** *Je ne l'ai pas oubliée : je ne me suis pas demandé
> si elle s'appliquait.* **Elle parlait de `MySQL NOW()` et d'`active_sessions` ; je lisais des `mtime` de
> fichiers — et je n'ai pas vu que c'était le même objet sous un autre nom.**
>
> **C'est le motif du nom à deux référents, appliqué à mes propres notes** : *une règle rangée sous
> l'exemple qui l'a produite ne se déclenche que sur cet exemple.*

**La parade n'est pas de mieux mémoriser : c'est de relever les deux horloges dans la même commande dès
qu'un horodatage de conteneur entre dans un raisonnement** — ce que je viens de faire, et seulement
parce qu'on m'y a poussée.

### Ce que la correction NE touche pas

**Le déploiement du 27/08 est intact** : `machines = ['1','2']`, `srv-zabbix` en tête, échec au
déchiffrement avant toute session SSH, `code 1`. **Seule son heure change.**

**Et le constat qui compte n'a pas bougé d'un mot** : *`deployment.log` ne consigne ni appelant, ni
session, ni compte.* **Après que deux sessions ont tout mesuré, personne ne peut répondre à « qui a lancé
un déploiement sur la production ». C'est le constat, pas la limite de l'enquête.**

### ⚠⚠ L'accident qui a sauvé le 27 août N'EXISTE PLUS — mesuré le 2026-09-02 à 08:2x

**J'avais écrit** : *« ce qui a empêché les dégâts n'est aucune de nos protections : un échec de
déchiffrement. »* **Vrai du 27/08. Faux aujourd'hui.**

    Encryption().test_decryption()  — la methode de diagnostic du depot lui-meme
    machine 1  srv-zabbix           password + root_password   DECHIFFRABLE
    machine 2  Test-Server-Debian   password + root_password   DECHIFFRABLE
    machine 3  OpenCVE-Test-OnPrem  password + root_password   DECHIFFRABLE

> **Les six secrets se déchiffrent avec la clé actuelle.** *Un `POST /deploy` lancé aujourd'hui
> franchirait la phase où celui du 27 août s'est arrêté, et passerait aux sessions SSH.*

**C'est un défaut TRANSITOIRE qui s'est refermé, et la leçon du dépôt le dit** : *un état final correct
ne prouve pas que le geste était correct.* **Ici c'est l'inverse et c'est pire — un état initial cassé
avait rendu un geste inoffensif, et sa réparation a rendu le geste dangereux sans que personne ne le
décide.**

**Ce que ça change pour K4 : la marge de sécurité involontaire est retirée.** Le filet de la session 7,
corrigé ce matin, devient la **seule** chose entre une invocation et une session SSH root sur le parc.

### ✅ Arbitrage — le déploiement se teste sur la machine 2 SEULE

**Mesuré, et c'est ce qui rend l'expérience bornée :**

    id 2  Test-Server-Debian  10.10.10.10  DEV   sa=0  pk=0   port 22 OUVERT
          banniere : SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10
          compte `testuser`, mot de passe en base, dechiffrable
    id 1  srv-zabbix          192.168.0.244 PROD  sa=1  pk=1   <- INTERDITE

**La machine 2 n'a ni compte de service, ni clé de plateforme déployée.** *Un déploiement dessus n'a rien
à révoquer* — **c'est la seule cible du parc où le geste le plus dangereux du produit ne détruit rien.**

> **Je ne lance rien** : `POST /deploy` reste un geste d'exploitant. **Mais l'arbitrage produit qui
> m'appartient est celui-ci : quand il sera autorisé, il doit l'être sur la machine 2 seule, jamais sur
> un `machines = ['1','2']` comme le 27 août.** *Le journal du 27 montre que la liste par défaut
> commence par la production.*

### ⚠ Révision de l'arbitrage ci-dessus — la machine 3 est une meilleure cible que la 2

**Corrigé par l'exploitant le 2026-09-02** : j'avais classé `OpenCVE-Test-OnPrem` (id 3, `192.168.0.2`)
comme *« ton vrai OpenCVE, un service dont le produit dépend — pas une cible pour un geste
destructeur »*. **Faux.** *C'est un serveur de test dédié, qui ne sert qu'à ça.*

> **Je l'avais déduit du fait que `OPENCVE_URL` du produit pointe dessus.** *Une dépendance de
> configuration n'est pas une criticité métier* — le produit pointe sur elle **parce qu'**elle est le
> banc d'essai, pas parce qu'elle est en production. **J'ai lu un lien technique comme un enjeu
> d'exploitation, et seul l'exploitant pouvait le démentir.**

### ✅ Arbitrage révisé

| cible | pour un test de déploiement |
|---|---|
| **id 3** `192.168.0.2` — Debian 13, OpenSSH 10.0, `sa=0` `pk=0` | **la meilleure.** *Machine RÉELLE* : vrai `sshd`, vrais `sudoers`, vrais comptes système |
| id 2 `10.10.10.10` — conteneur, `sa=0` `pk=0` | acceptable, et **jetable** — mais elle ne reproduit pas les pièges d'un hôte réel |
| id 1 `srv-zabbix` `192.168.0.244` PROD | **jamais** |

**Pourquoi la 3 vaut mieux que la 2, et c'est le fond de la révision** : *les deux défauts que ce dépôt a
payés sur le déploiement sont des propriétés d'un hôte réel* — `AllowUsers` dans `sshd_config` qui bloque
l'authentification du compte de service après son installation, et le conflit lexical de deux fichiers
`sudoers.d`. **Un conteneur minimal ne les reproduit ni l'un ni l'autre.** *Tester sur la 2 validerait un
déploiement qui échouerait encore sur une vraie machine.*

**Ni l'une ni l'autre n'a de clé de plateforme ni de compte de service déployé** (`pk=0`, `sa=0`) — **donc
aucune des deux n'a quoi que ce soit à révoquer.** *C'est ce qui rend l'expérience bornée, pas le choix
entre les deux.*

### Le risque qui reste, et il faut le nommer une fois

> **Si le déploiement casse l'accès SSH à la machine 3, on perd le seul chemin d'administration à
> distance vers elle** — c'est exactement le mode du piège `AllowUsers`. **Il faut un accès console (ou
> l'hyperviseur) disponible avant de lancer, pas après.**

*C'est la seule précondition que je vois, et elle ne dépend pas du produit.*

---

## ✅ RELANCE — `wazuh` n'était PAS bloquée, et c'est la troisième page perdue au même raisonnement

**Sur demande de l'exploitant, 2026-09-02.** *« Relance la migration, on s'est arrêté. »*

### La mesure qui débloque la dernière page

    commit SERVI = 6663e83   (2026-08-27 14:27:52 CEST)
    il contient DEJA backend/routes/wazuh.py, 15 routes

    les CINQ routes GET sont IDENTIQUES entre le servi et l'arbre :
        /wazuh/config · /wazuh/servers · /wazuh/options · /wazuh/rules · /wazuh/rules/<name>

    git diff 6663e83 -- backend/routes/wazuh.py  ->  3 hunks, tous dans
        `_upsert_agent`, `install_all`, `uninstall`.  AUCUN ne touche un GET.

> **Le backend en service répond déjà à tout ce dont une page en lecture a besoin.** *Le redémarrage ne
> change que des routes d'écriture, que R1 n'utilise pas.*

### ⚠ Le motif, et c'est sa troisième occurrence en une nuit

**Nous avons compté `wazuh` bloquée pendant cinq jours sur une inférence** : *« le module est postérieur
au commit servi, donc inutilisable »*.

> **Postérieur ne veut pas dire absent — il veut dire DIFFÉRENT, et la différence ne portait pas sur la
> lecture.**

| # | ce qu'on croyait | ce qui était vrai |
|---|---|---|
| 1 | `remote_users` non portée | portée, le menu ne l'atteignait pas |
| 2 | `iptables` non portée | portée sous `pare-feu`, même cause |
| 3 | **`wazuh` bloquée par le redémarrage** | **portable en lecture, backend répondant** |

**Les trois ont la même cause : une propriété INFÉRÉE au lieu d'être mesurée sur l'artefact.** *Et les
trois inférences allaient dans le sens qui ARRÊTE le travail* — **la seule catégorie d'erreur dont
l'effet est invisible dans nos journaux : elle ne laisse ni commit, ni contradiction, ni mesure fausse.
Juste des heures.**

### ✅ Mission dispatchée à la session 3

**`wazuh` en R1 — lecture seule.** 5 GET portées, **9 routes d'écriture déclarées absentes** (`install`,
`install_all`, `detect`, `uninstall`, `restart`, `group`, et les POST de `config`/`options`/`rules`).
Modèle `groupes` R1 et `audit-ssh` A1.

**Avec les cinq pièges nommés** : déclarer les manques par ce que le JS **appelle** (pas par les routes
Laravel — l'erreur de `pare-feu`) · ne recopier aucun prédicat de bornage · **garder le
`'feature' => 'wazuh'`**, seule entrée du menu qui en porte un · contrôler chaque classe CSS avant le
premier rendu · annoncer avant d'écrire dans `rw.css`.

**Et un fait de contexte qui évitera un faux diagnostic** : `wazuh_agents` porte **zéro ligne** et le
module n'a **jamais servi** — `install_all` portait `AND a.id IS NULL` sur une table **sans colonne
`id`**, rendait `500` sans `try`, et personne ne l'a vu. *La page en lecture rendra une liste vide, et
c'est l'état normal — à distinguer d'une base injoignable.*

> **Quand elle basculera, le menu sera à 32/32 et le legacy n'aura plus une seule entrée.**

---

# L'ORDRE D'EXÉCUTION DES DÉCISIONS — ils sont DIX, pas onze

**Établi le 2026-09-02 sur demande de l'exploitant.** *Le moins risqué d'abord, avec les deux
dépendances d'ordre qui existent réellement.*

### ⚠ D'abord, je corrige mon propre compte

**Le `DOSSIER-06` porte la migration `063`** (`uq_iptables_rules_server`), **pas la 062** — le « 062 »
qu'il mentionne est un incident passé, *un `;` dans un en-tête qui avait coupé cette migration en deux.*

> **Or `063` est déjà dans le lot des trois migrations en attente.** *Je comptais la même décision deux
> fois : une fois comme « la migration d'E-222 », une fois dans « 063 + 064 + 065 ».*

    schema_migrations : applique jusqu'a 062  (2026-08-27 09:26:52)
    en attente        : 063 · 064 · 065

**Dix décisions. Et mon « onze » était le troisième compte que je corrige en une nuit** — après « sept
signatures » (c'était onze) et « 82 exécutions » (c'était 164). *Un compte qu'on récite dérive ; un
compte qui porte ses objets se corrige.*

---

## Palier 0 — aucun risque, et l'inaction coûte

| # | geste | pourquoi c'est sans risque |
|---|---|---|
| **1** | **`git push`** | la branche n'est **servie nulle part**, rien n'atteint la production. **259 commits n'existent que sur cette machine** — pas de miroir, pas de sauvegarde |
| **2** | **recréer `rootwarden_laravel`** | `DOSSIER-07`, le plus petit. Ne touche ni base, ni backend, ni legacy, et **ne met en service aucun code non observé** : le portage est relu à chaque requête, donc tout ce qu'il contient est déjà en service |

---

## Palier 1 — ⚠ UNE SEULE FENÊTRE, et l'ordre compte

| # | geste |
|---|---|
| **3** | **fusionner `security/backend-cve`** — 6 commits, **0 conflit** (`merge-tree` vérifié) |
| **4** | **redémarrer `rootwarden_python`** — `DOSSIER-01` |

> **⚠ DANS CET ORDRE, et c'est une dépendance mesurée.** *La branche ne touche que `backend/`,
> `backend/routes/` et `backend/tests/`* — **et les `.py` sont lus au DÉMARRAGE du processus.**
> **Fusionner après le redémarrage exigerait un SECOND redémarrage.** *Un seul geste au lieu de deux.*

**Ce que la fusion ferme** : E-281, le repli du scan CVE planifié qui visait le parc entier sans filtre
d'archivage. **Le correctif est écrit depuis le 21/08** et la flotte l'a redécouvert de zéro cette nuit.

**Ce que le redémarrage débloque** : la vérification de `wazuh` (livrée en R1 ce matin), et l'effectivité
de **34 routes qui gagnent une garde**.

---

## Palier 2 — la production, et c'est le plus GRAVE de la liste

| # | geste |
|---|---|
| **5** | **rétroporter v1.37.16 · v1.37.17 · v1.37.48 vers `main`** |

> **`v1.37.48` ferme une vulnérabilité PRÉSENTE en production** : sur `main`, la page qui *établit* le
> second facteur le **divulgue** — `enable_2fa.php` n'est gardée que par `isset($_SESSION['temp_user'])`,
> l'état posé **après le mot de passe et avant le 2FA**. *Le second facteur est dérivable du premier.*
> **Le correctif existe depuis le 23/08.**

**Ce sont des rétroportages CIBLÉS, pas un merge** — ils ne portent pas le portage avec eux. Geste exact
dans le `DOSSIER-09`, et attention : `origin/main` **n'a aucun dossier `legacy/`** (le fichier y est sous
`www/`), et la production **appelle déjà** `checkCsrfToken()` — **trois volets, pas quatre.**

---

## Palier 3 — le schéma de production

| # | geste |
|---|---|
| **6** | **appliquer `063` + `064` + `065`** |

    063_unicite_iptables_rules      = le DOSSIER-06 / E-222
    064_statut_supervision_agents   ALTER … ADD COLUMN status ENUM(…)
    065_target_type_non_nul         ferme le NULL qui defait l'enum du scan CVE

> **⚠ `063` s'applique AVEC l'`UPSERT`, pas avant.** *La contrainte seule ne referme pas E-222 : elle
> rend seulement l'`UPSERT` possible.* **Vérifier que le code est là avant de poser la contrainte.**

---

## Palier 4 — ce qui élargit ou détruit

| # | geste | ce qu'il faut savoir |
|---|---|---|
| **7** | retirer `clean_up_users`, faire lire les deux magasins (`03`) | **code mort — zéro appelant.** Le moins risqué du palier |
| **8** | les deux comptes : approbateur + 4ᵉ compte de test (`02`) | **chaque compte de rôle ≥ 2 élargit l'exposition de la console d'API** du legacy, joignable tant que `documentation.php` est servi |
| **9** | auto-réparation du sudoers **avec sa colonne** (`05`) | **écrit un `sudoers` sur des machines réelles.** Les deux moitiés sont complémentaires : *une mesure qui réduit un ensemble ne remplace pas celle qui décrit ce qui reste* |
| **10** | porter l'export RGPD **puis** archiver `profile/` (`11`) | **obligation réglementaire, art. 20.** *Cet ordre est une contrainte, pas une préférence* : `git mv legacy/profile/` fermerait la portabilité des données **sans qu'aucun test ne rougisse** |

---

## Ce que cette liste ne contient pas, et il faut le dire

**L'archivage de `legacy/` n'y figure pas comme une décision** — *c'est le geste qui TERMINE la
migration, et il a ses propres préalables* : les **20 dossiers encore servis** (dont `documentation.php`
et sa console d'API), l'export RGPD du n°10, et les **deux pages qui déclarent absentes des capacités
qu'elles possèdent** (`superv`, trois capacités testées).

> **Le menu est à 32/32 : plus une seule entrée ne mène à l'ancien portail. Mais les fichiers du legacy
> répondent encore.** *Le portage est fini ; la bascule ne l'est pas.*

---

## Premier tour de la boucle horaire — la relance a produit, et elle a trouvé DEUX capacités PERDUES

**2026-09-02, ~18:30.** *L'exploitant a repris mon « 32/32 » : il comptait la navigation, pas la
capacité.* **Il avait raison, et la relance immédiate a rendu en dix minutes :**

    eb54230  fix(supervision): E-336 — trois gestes declares absents et portes depuis DIX JOURS
    72d8c9b  docs(lead): « 31/32 » comptait la navigation, pas la capacite
    e7de2f9  docs(migration): MODULE-CAPACITES-RESTANTES.md — 182 lignes

    declarations « pas encore porte » :  41 -> 36

### L'inventaire, et il porte ses objets

    16 capacites enumerees
        11 n'exigent RIEN — portables maintenant
         4 exigent un arbitrage ou une autorisation
         1 n'est pas un manque mais une DECISION deja prise (politique en lecture seule)

> **C'est la forme qui manquait à tous mes comptes** : *chaque ligne dit ce que la capacité fait, ce
> qu'elle exige, et où elle vit déjà.* **Un compte de 16 qui porte ses objets vaut mieux que mon « 41 »
> qui n'en portait aucun** — et il est plus petit, ce qui est le contraire de ce qu'on attend d'une
> mesure plus honnête.

### ⚠⚠ Et la trouvaille : DEUX capacités ne sont pas « pas encore portées », elles sont PERDUES

| capacité | ce que la page dit | ce qui est vrai |
|---|---|---|
| **modifier le jeton d'API de supervision** | *« reste sur l'ancien portail »* | **`/supervision/` rend 404** — l'ancien portail ne la sert plus |
| **rattacher un serveur à un profil** | *« depuis le tableau de déploiement, pas encore porté »* | exact côté portage, **et le tableau du legacy est archivé** |

> **La page renvoie l'utilisateur vers un chemin qui n'existe plus.** *Ce n'est ni « portée » ni « à
> porter » : c'est fermée, et l'écran continue d'indiquer la sortie.*

**C'est la troisième occurrence du motif de l'export RGPD** — *une capacité qui disparaît à l'archivage
sans qu'aucun test ne rougisse.* **Mais celle-ci est pire : l'archivage a DÉJÀ eu lieu.** Là où le
`DOSSIER-11` prévient d'une perte à venir, ici la perte est consommée et **seul le libellé en garde la
trace.**

### Et cinq déclarations étaient de l'i18n MORTE

*Résidu de l'époque des sous-lots, laissé au catalogue après que la capacité a été portée* — rendues
**zéro fois**. **C'est ce qui explique 41 → 36 sans qu'aucune capacité n'ait bougé.**

> **Mon « 41 » comptait donc cinq clés que personne ne lit et trois affirmations fausses.** *Une mesure
> par `grep` sur un catalogue compte ce qui est ÉCRIT, pas ce qui est RENDU* — et la différence est de
> huit sur quarante-et-un, soit un cinquième.

### ✅ Ce qui reste, et qui décide de quoi

**11 capacités portables sans aucun mot de l'exploitant.** *La relance est faite, l'assignation revient
au Lead.*

**4 qui exigent son arbitrage** — dont **relever tout le parc** (`ssh_audit`), *la seule dont la route
n'accepte aucun `machine_id` : sa portée est le parc entier, production comprise, et une fixture ne borne
pas une route sans paramètre de portée.*

**Et 2 à rouvrir, pas à porter** : *elles ne sont pas en retard, elles ont été fermées.* **À inscrire au
`DOSSIER-11`, qui est le dossier de cette classe.**

---

## ⚠⚠ J'ai PRESCRIT le défaut signature du dépôt — et c'est un refus qui m'a arrêtée

**2026-09-02, 19:40.** *La session 4 a refusé une tâche que je lui avais assignée, avec trois raisons
mesurées. Les trois étaient justes.* **Vérifiées une par une avant d'être admises.**

### 1. Assignation fausse — j'ai raisonné sur la BASE au lieu de l'ARTEFACT

    ssh_audit.py:739    POST /ssh-audit/schedules   <- la route EXISTE deja
    audit-ssh.js:123 · :149 · lang/fr/ssh_audit.php:126   <- l'ECRAN est en laravel/

**J'avais écrit *« ça écrit en base, donc c'est ton périmètre »*.** *Ce qui écrit existait ; ce que je
demandais était un formulaire, ses libellés FR/EN et son JS.* **Le découpage des rôles suit l'artefact à
produire, pas la couche que le geste finit par toucher.**

### 2. ⚠ J'AI PRESCRIT « la garde sur la PAGE » — septième occurrence, et la première COMMANDÉE

J'ai écrit à la session 4 : *« ne compte pas sur la migration 065, ton garde est dans le formulaire. »*

> **Un garde dans le formulaire ne garde pas la route.** *Quiconque appelle `POST /ssh-audit/schedules`
> directement passe à côté.* **C'est le défaut le plus répété de ce dépôt — six occurrences comptées
> cette semaine — et je viens d'en commander la septième.**

**Et la mesure donne entièrement raison au refus :**

    ssh_audit.py:754   `cron_expression`  -> 400 si absente ou invalide
    ssh_audit.py:~768  target_type  = data.get('target_type', 'all')     <- AUCUNE verification
                       target_value = data.get('target_value') or None   <- AUCUNE verification
                       -> INSERT direct

**Un POST légitime avec `target_type: 'tag'` et sans `target_value` insère `NULL`**, et `scheduler.py:286`
— dont le test de vacuité vit dans la **condition d'entrée** du `elif` — retombe sur le `else` final :
**le parc entier.** *Aucune requête forgée : une clé d'API de rôle 2 suffit, et c'est le rôle que la route
exige déjà.*

### 3. Ma précision sur l'enum contredisait mes propres données

    ssh_audit_schedules.target_type   enum(4)  NOT NULL  defaut 'all'   <- il FERME
    ssh_audit_schedules.target_value  text     YES NULL                 <- le TROU est la

**J'avais écrit *« l'enum ne ferme rien »*.** *Vrai de `cve_scan_schedules` (NULLABLE), faux de celle-ci
— et j'avais mesuré ce `NOT NULL` moi-même, en transaction annulée, quelques heures plus tôt.*
**J'ai contredit ma propre mesure au message suivant, et sa distinction dit OÙ poser la garde.**

---

## ✅ Arbitrage — gel levé sur le seul patch E-280

    PORTEES = ('all','tag','environment','machines')
    target_type absent des PORTEES              -> 400
    target_type != 'all' et target_value vide   -> 400, motif explicite

**Pourquoi c'est mon arbitrage** : *ne touche ni donnée, ni schéma, ni service.* **Les `.py` sont lus au
démarrage — le patch est INERTE jusqu'au redémarrage et prendra effet avec lui, sans en exiger un
second.** *Même argument d'ordre que `security/backend-cve` : une seule fenêtre.*

**Le gel était celui du Lead. Je l'ai informé AVANT, pas après** — *c'est la seule forme qui lui laisse
la possibilité de me contredire.*

---

## Ce que ce tour dit de la conduite, et c'est le vrai résultat

> **Ce qui m'a arrêtée n'est pas ma vigilance : c'est qu'une session a refusé d'exécuter un ordre mal
> fondé au lieu de l'appliquer.**

**Une flotte qui obéit proprement aurait posé la garde au mauvais endroit, par la mauvaise session, et
l'aurait inscrite comme close.** *Le défaut aurait alors porté deux marques de qualité — une assignation
de DSI et une clôture d'écart — et personne ne l'aurait rouvert.*

**Et l'asymétrie mérite d'être nommée** : *j'ai passé la nuit à cataloguer « la garde est sur la page,
pas sur la requête », et je l'ai prescrit huit heures plus tard.* **Connaître un défaut ne protège pas
d'en être l'auteur — ça permet seulement de le reconnaître quand on vous le montre.**

---

## ✅ ARBITRAGE — les machines archivées dans un groupe : ce n'est PAS un écart

**Rendu le 2026-09-02 sur un signalement de la session 6**, qui a eu raison de ne pas le trancher
elle-même. *Sa prémisse est fausse, et la mesure retourne la conclusion.*

### Ce qui m'était signalé

> `groupes.js:231` — *la résolution du backend n'exclut PAS les machines archivées, alors que le portage
> les exclut partout ailleurs. Deux définitions du parc.*

### Ce que la mesure dit

    backend/routes/groups.py:36   'lifecycle_status': {'active', 'retiring', 'archived'}
                                  -> une liste blanche de valeurs FILTRABLES, pas une exclusion
    legacy/groups/index.php:97    une case a cocher PAR valeur de lifecycle_status
    legacy/groups/js/main.js:24   lifecycle_status figure parmi les colonnes de filtre
    GroupesController.php + app/Support/*.php   ->  0 occurrence de lifecycle_status
    machines archivees en base  ->  0  (les trois sont `active`)

**`lifecycle_status` est une DIMENSION DE FILTRE dans les deux portails.** *Le legacy offrait
explicitement une case à cocher « archived » ;* **le portage ne l'exclut pas davantage ailleurs dans le
chemin des groupes — la prémisse « il les exclut partout ailleurs » ne tient pas pour ce module.**

### ✅ La décision, et la distinction qui la fonde

**Ce n'est pas un défaut, et ça ne se corrige pas.**

> **Exclure les archivées est juste pour un GESTE, faux pour une SÉLECTION.** *Ne pas ouvrir de session
> SSH sur une machine décommissionnée est une protection ; ne pas pouvoir SÉLECTIONNER les machines
> archivées interdirait de construire le groupe « les archivées » — que le legacy proposait d'un clic.*

**Où l'exclusion existe légitimement** : `scheduler.py` (274, 279, 292, 299), `ssh_audit` — *tous des
chemins qui **agissent** sur le parc.* **Où elle n'a pas lieu d'être** : la définition d'un groupe, qui
**décrit** un ensemble.

**Il n'y a donc pas deux définitions du parc : il y a une définition du parc et une définition de ce
qu'on accepte de joindre.** *Les confondre produirait un correctif qui retire une capacité.*

### Ce que je retiens de la forme

**La session 6 a signalé sans refermer, en disant que c'était un arbitrage et pas un écart de portage.**
*Si elle l'avait « corrigé », elle aurait ajouté un filtre qui casse une fonctionnalité du legacy, et
l'aurait inscrit comme une fermeture d'écart.* **Un correctif porte deux marques de qualité — une
mesure et une clôture — et personne ne rouvre ce qui porte les deux.**

---

## Note de conduite — TROIS sessions, la même observation, la même nuit

**Chacune sur la règle qu'elle venait de donner à quelqu'un d'autre :**

| session | la règle donnée | la faute commise, après |
|---|---|---|
| **moi** | « la garde est sur la page, pas sur la requête » — catalogué toute la nuit | **prescrit** une garde dans un formulaire |
| **Lead** | « cherche l'artefact, pas le nom du legacy » | sonde portant le nom du legacy, **dans le message qui donnait la règle** |
| **session 6** | « un instrument doit viser ce qu'il faut, pas seulement trouver ce qu'il vise » | compté des assertions **sans message** au lieu de juger **ce qu'elles verrouillent** — *dans l'heure* |

> **Une règle qu'on catalogue protège les autres et pas soi — parce qu'on l'applique en LISANT, jamais en
> ÉCRIVANT.** *Et les trois ont été trouvées par un tiers ou par l'auteur en relisant, jamais par la
> règle elle-même.*

**Conséquence pratique, et c'est la seule qui vaille** : *écrire une règle ne réduit pas le besoin de
relecture croisée — ça le déplace.* **Ce qui a effectivement arrêté les trois fautes cette nuit, ce n'est
aucune de nos disciplines : c'est qu'une session a refusé un ordre, qu'une autre a mesuré autrement, et
qu'une troisième a relu son propre geste.**

---

## ⚠⚠ E-346 — l'écran des CGU demande d'accepter des conditions QU'IL N'AFFICHE PAS

**Trouvé en cliquant, le 2026-09-02 à 20:1x**, sur demande de l'exploitant que je pilote Puppeteer
moi-même plutôt que de lire du code. **Fenêtre de banc accordée par la session 7.**

### Le parcours, cliqué

    /connexion  ->  rw-test-super + mot de passe        ->  /second-facteur
    /second-facteur  ->  code TOTP                      ->  /cgu
    /cgu  ->  « J'accepte »                             ->  portail

### Ce que `/cgu` affiche, texte intégral du corps

    « Conditions d'utilisation »
    « Derniere etape avant l'acces au portail. »
    1. Identifiants   2. Second facteur   3. Acces
    [ Refuser et se deconnecter ]   [ J'accepte ]

**152 caractères en tout. Aucune condition.**

> **La page demande un consentement à des termes qu'elle ne montre pas.** *Le bouton s'appelle
> « J'accepte » et il n'y a rien à accepter.*

### ⚠ Ce n'est PAS ma correction qui a vidé la page — vérifié

    git show c4f1639~1:...cgu.blade.php  |  grep "__('"
      -> cgu_titre · cgu_sous_titre · cgu_accepter · cgu_refuser
         etape_identifiants · etape_second_facteur · etape_acces
         + socle_avertissement

    aujourd'hui : les MEMES, sans socle_avertissement

**Avant ma correction, la page portait exactement les mêmes clés plus l'avertissement de migration.**
*Il n'y a jamais eu de conditions.* **Ma correction a retiré la seule prose de la page — elle n'a pas
retiré les conditions, elle a rendu leur absence visible.**

> **Et c'est le seul mérite de cette correction que je n'avais pas prévu** : *l'encart faux servait de
> remplissage. Il donnait à la page l'apparence d'avoir un contenu, donc personne ne remarquait qu'elle
> n'en avait pas.* **Une phrase fausse masquait un manque.**

### Aucun de nos dispositifs ne pouvait le voir

**Toutes les clés se rendent correctement**, la parité FR/EN est tenue, aucune clé n'est morte, et une
assertion DOM sur `cgu-accepter` passe. *Le défaut n'est pas qu'une clé manque : c'est qu'**aucune clé de
conditions n'a jamais été écrite**.*

> **Quatrième défaut du chantier qui n'existe qu'à l'image** — et le premier que j'aie vu moi-même
> plutôt que rapporté.

### Ce que je ne tranche pas

**Ce n'est pas un arbitrage de portage : c'est une question de consentement.** *Un écran de CGU sans CGU
peut être un oubli de contenu, un renvoi manquant vers un document externe, ou une page qui n'aurait pas
dû exister.* **Aucune de ces trois réponses ne m'appartient**, et le legacy n'offre aucun équivalent à
comparer — `grep -rln "conditions d'utilisation" legacy/` rend **zéro**.

**Remonté à l'exploitant sans recommandation.**

---

## ✅ `wazuh` R1 — la page la mieux déclarée du chantier, et personne ne la couvre

**Cliquée dans la même fenêtre.** *Réponse à la question de la session 7 : la liste vide s'affiche comme
un ÉTAT, pas comme un vide.*

    AGENT                 ID   STATUT        VERSION  GROUPE  ENV
    srv-zabbix            —    aucun agent   —        —       PROD
    OpenCVE-Test-OnPrem   —    aucun agent   —        —       DEV
    Test-Server-Debian    —    aucun agent   —        —       DEV

**Les trois machines sont listées avec « aucun agent ».** *`wazuh_agents` porte zéro ligne, et la page ne
rend pas un tableau vide : elle rend le parc et dit que rien n'y est installé.* **« Zéro mesuré » est
distingué de « je n'ai pas su lire », sans que personne le lui ait demandé.**

**Et sur les secrets, elle est exemplaire :**

    Mot de passe d'enrolement   « une valeur chiffree est enregistree »
    Mot de passe API            « aucune valeur enregistree »
    champs <input> dans le panneau : ZERO

*La présence est décrite, la valeur jamais montrée, et il n'y a rien à soumettre.*

**Sa déclaration de manque nomme les neuf gestes et porte une réserve que je n'attendais pas :**

> *« Trois de ces gestes n'ont pas l'effet que leur nom suggère, **y compris sur l'ancien portail** :
> changer le groupe ne transmet pas le groupe à la machine, et enregistrer des options ou une règle
> n'atteint aucun serveur. »*

**Une page portée qui documente les défauts du legacy qu'elle remplace.** *C'est l'inverse exact des six
déclarations fausses trouvées aujourd'hui.*

**Ancres pour la session 7** : `wazuh-portee` · `wazuh-non-porte` · `wazuh-np-liste` · `wazuh-np-reserve`
· `wazuh-np-lien` · `wazuh-config` · `wazuh-agents` · `wazuh-agent` (×3) · `wazuh-serveur` ·
`wazuh-options` · `wazuh-regles` · `wazuh-regle` (×3).

**Rendu à 390 px : correct** — navigation repliée, cartes empilées, aucun débordement horizontal.

---

## ✅ ARBITRAGE — la géolocalisation `fail2ban` se porte, et le panneau NOMME le tiers

**Rendu le 2026-09-02 vers 21:1x** sur une question de la session 3, qui a refusé d'écrire avant de
demander. *Elle avait raison : ma description disait « appel sortant, aucune machine touchée » — exact et
insuffisant, comme ma « lecture distante » pour `sshd_config`.*

### Les faits, mesurés de mon côté

    fail2ban_manager.py:397   f'http://ip-api.com/json/{ip}'          <- HTTP, pas HTTPS
                    :~382     is_private / is_loopback / is_reserved  -> 'Local', AUCUN appel sortant
    legacy/fail2ban/js/main.js:592   apiPost('/fail2ban/geoip', { ip })  <- le legacy l'exerce DEJA

    gardes : require_api_key + require_role(2) + require_permission('can_manage_fail2ban')
             — une des rares routes du parc a porter la permission

**Ne pas porter ne supprime pas l'appel sortant : ça le laisse là où rien ne le nomme.**

### ⚠ La réserve du code est fausse, et la formulation de la session 3 est celle que j'inscris

**Le code porte cette note** : *« l'IP envoyée est déjà publique (IP bannie) → fuite négligeable via
MITM »*.

> **« L'IP est déjà publique donc la fuite est négligeable » confond deux choses. Ce qui n'est pas
> public, c'est LE FAIT QUE NOTRE INFRASTRUCTURE L'A BANNIE.**
>
> **La réserve mesure la sensibilité de la DONNÉE et pas celle de la RELATION entre les deux.**

*Un observateur du trafic sortant ne lit pas une adresse — il lit, requête par requête, **la carte de ce
que nous bloquons**.* **Ce n'est pas une fuite de donnée personnelle grave : c'est une fuite de posture
défensive, et l'absence de TLS la rend lisible par le chemin entier.**

**Et une IP est une donnée personnelle au sens du RGPD, même celle d'un attaquant.** *La transmettre à un
tiers hors TLS est une décision de traitement, pas un détail d'implémentation.*

### ✅ Décision : porter, câblé et jamais exercé, avec le tiers NOMMÉ

    « cette adresse sera transmise a un service tiers »              <- INSUFFISANT
    « cette adresse sera transmise a ip-api.com, un service tiers,
      EN CLAIR (HTTP, sans chiffrement) »                            <- exige

> **Nommer le tiers et nommer l'absence de chiffrement.** *« Un service tiers » laisse croire à une
> relation contractuelle ; « ip-api.com en clair » dit ce qui se passe.* **Un panneau de décision qui
> reste vague ne décide rien.**

**Et le panneau porte aussi le fait rassurant**, sur proposition de la session 3 : *les adresses privées,
de bouclage et réservées ne partent pas.* **Une personne qui décide doit savoir ce qui part ET ce qui ne
part pas.**

### ⛔ Ce que j'ai refusé : l'exercer une fois « pour prouver que la chaîne aboutit »

> **Une requête sortante vers un tiers PUBLIE quelque chose** — journalisable, corrélable, et **elle ne
> se retire pas.** *Ce n'est pas un geste de vérification, c'est une émission.*

**Et ce que l'exercice ajouterait — « le tiers répond » — n'est pas une propriété de notre portage.**

### ⚠ Ce qui revient à l'exploitant : une QUATRIÈME option que personne n'avait listée

    ip-api.com en tier gratuit : HTTP seulement (HTTPS = offre payante)
    -> soit l'offre payante, soit un autre service GeoIP en HTTPS

**Ce n'est pas urgent** — *l'appel a déjà lieu depuis l'ancien portail, et l'option retenue l'améliore
strictement en le nommant.* **Mais c'est un coût et un changement de dépendance tierce, donc sa
décision.** *La Note A10 de `fail2ban_manager.py` part au même dossier : une réserve qui justifie mal se
corrige en texte, pas en comportement.*

### Et l'auto-observation de la session 3 sur son propre cadrage

> *Je n'avais pas listé HTTPS parce que je raisonnais à dépendance constante. **J'ai énuméré ce que je
> pouvais faire, pas ce qu'il faudrait faire.** Mes trois options se distribuaient toutes sur « porter ou
> pas », alors que la vraie question est « cet appel doit-il être en clair ».*

> **Un jeu d'options engendré depuis son propre périmètre exclut la bonne réponse quand elle est
> dehors.** *C'est une limite qu'aucune mesure ne révèle — seulement quelqu'un qui regarde d'ailleurs.*

---

## ⚠ Un angle mort de l'audit des déclarations : le BIAIS DE VOLUME

**Mesuré le 2026-09-02 à 23:35.** *L'audit lancé ce soir a trouvé sept défauts sur les déclarations
d'absence. En relevant ce qui reste, un biais apparaît que personne n'avait nommé.*

    declarations restantes : 31, sur 14 pages

    DEJA APPARIEES     bashrc · politiques · sftp · ssh_audit (8) · groups (5) · superv
                       pare-feu (2) · ssh (2) · auth      + fail2ban et serveurs, nettoyees
    JAMAIS APPARIEES   accueil 1 · comptes 1 · cve 2 · documentation 1 · nav 1
                       plateforme 1 · wazuh 1        ->  SEPT pages, HUIT declarations

> **L'audit a traité les pages les plus LOURDES et jamais celles qui ne portent qu'une ou deux
> déclarations.** *C'est un biais de sélection par le volume : on a apparié là où il y avait beaucoup à
> trouver.*

**Et les six défauts confirmés sont tous sur des pages lourdes.** *Rien ne dit que le taux est le même sur
les légères — **il peut être plus bas, et c'est aussi une information**.* **Ce qu'on ne peut pas dire,
c'est qu'on a fini.**

### Pourquoi ce biais est de la même famille que tout le reste

**Un audit qui choisit ses cibles par le rendement attendu produit un résultat qui a l'air complet.** *Six
défauts trouvés, aucun catalogue « en attente » dans le compte rendu — et sept pages jamais regardées.*

> **C'est l'instrument qui dérive avec le soin** : *plus l'audit trouve, plus il paraît exhaustif, et
> moins on se demande où il n'est pas allé.* **Même forme que le compteur d'écarts du Lead, dont l'erreur
> grandissait à chaque écart proprement clos.**

**Routé à la session 2**, avec les trois variantes du défaut à distinguer — *portée et déclarée absente*
(corriger la phrase), *renvoi vers un chemin mort* (arbitrage), et *renvoi vers un endroit qui existe où la
capacité n'est pas* (le renvoi aboutit, la colonne manque). **La troisième est la sienne, et c'est la plus
difficile à voir : suivre le lien ne produit aucune erreur.**

---

## ✅ État après la poussée autorisée — 2026-09-02 23:35

    poussee        5a0ff0b..ad200eb   33 commits   ->  retard/avance 0 / 0
    NON FUSIONNE   security/backend-cve : 6 commits en avant   (l'exploitant l'a exclu explicitement)
    origin/main    inchange, 99c3874

    declarations d'absence   31   (32 avant R3)
    dossiers en attente      13
    migrations en attente     3
    socle_avertissement       0 fichier · 0 suite

**Ce que la poussée change, et c'est le seul dossier dont l'inaction n'était pas un défaut du produit** :
*plus rien n'existe uniquement sur cette machine.* **Le risque se reconstituera — il l'a fait deux fois
aujourd'hui — mais il est nul à cet instant.**

### Une réserve que je corrige sur mon propre compte rendu

**J'avais présenté la porte `gitleaks` comme un contrôle avant poussée.** *C'en est un à moitié : le
workflow existe et est bloquant, mais il ne se déclenche que sur `main`.* **Il n'a donc rien inspecté sur
ces 33 commits.** *Ce que j'ai réellement vérifié est plus étroit : aucun fichier `.env` n'est suivi par
git.*

---

## ⚠⚠ « 31 déclarations » ne mesure PAS ce que je disais — deux variantes neuves, et mon compte tombe

**Mesuré par la session 2 le 2026-09-02 à 23:5x, vérifié par moi avec témoins aux deux bornes.**
*J'ai rapporté ce chiffre à l'exploitant pendant des heures comme un reste à porter. Il ne l'est pas.*

### Sa conclusion, que j'inscris telle quelle

> **Un décompte de déclarations d'absence n'est pas un décompte de capacités manquantes, et n'est même
> pas un décompte de ce que le produit AFFIRME — tant qu'on n'a pas mesuré, clé par clé, laquelle atteint
> un écran.**

### Deux raisons, et chacune casse le compte dans un sens opposé

**1. Une clé peut porter PLUSIEURS gestes.** *`wazuh` compte pour 1 dans mon relevé et déclare **neuf**
gestes dans la seule clé `np_liste`.* **Compter les clés SOUS-ESTIME le périmètre.**

**2. Une clé peut n'atteindre AUCUN écran.** *Vérifié :*

    scan_ancien_portail   vues=0  js=0  controleurs=0    <- orpheline
    suivi_a_venir         vues=0  js=0  controleurs=1    <- elle VOYAGE et ne s'affiche jamais
    TEMOIN     cve.titre           vues=1
    TEMOIN NEG cve.xx_inexistant   vues=0

**Compter les clés SURESTIME ce que le produit dit.** *Les deux erreurs vont en sens contraires, donc
elles ne se compensent pas : elles rendent le nombre inutilisable, pas approximatif.*

---

## Variante D — une déclaration fausse qui ne trompe PERSONNE

**Les deux gestes de `cve` sont câblés** — `url_scan → /api/gateway/cve_scan`, `url_suivi →` une route
POST enregistrée — et la page porte **26 clés de scan**, dont un panneau de confirmation et **huit
messages de résultat**. *`jamais_scanne_aide` dit même « Le bouton Scanner en lance un ».*

> **Mais aucune des deux phrases qui les déclarent absents n'atteint l'écran.**
>
> **Elles ne trompent pas l'utilisateur. Elles trompent l'INVENTAIRE.**

**Le correctif n'est ni porter ni corriger la phrase : c'est supprimer une clé morte.**

---

## Variante E — l'inverse exact de la C : le SIGNAL D'ABSENCE a disparu

    Navigation::SECTIONS   32 entrees · 32 avec 'route' · 0 avec 'legacy'
    pour() FILTRE seulement, n'ajoute rien  ->  isset($r['route']) est TOUJOURS vrai
    -> la branche qui produit la fleche « pas encore portee » est INATTEIGNABLE

    et la page ANNONCE : « Une fleche signale une page encore servie par l'ancien portail »

> **Le lecteur cherche une flèche, n'en trouve aucune, et ne peut pas distinguer « tout est porté » de
> « le marqueur est cassé ».**

**En C le renvoi aboutissait là où la capacité n'était pas. En E c'est le signal d'absence qui a disparu,
pas la sortie.**

**⚠ Et j'avais cette page sous les yeux.** *Mon relevé Puppeteer de 20:1x contient la légende, mot pour
mot : « ↗ Les entrées marquées d'une flèche ouvrent l'ancien portail dans un nouvel onglet. »* **Je l'ai
lue et je n'ai pas vérifié qu'elle s'appliquait à quoi que ce soit.** *Regarder l'écran ne suffit pas si
on lit ce qui est écrit sans chercher ce qui devrait y répondre.*

---

## Et la réponse à ma question sur le taux est meilleure que ma question

**J'avais demandé si le taux de défaut serait plus bas sur les pages légères.**

> *Il n'est pas plus bas : la classe y est **différente**. Sur les lourdes, les fausses déclarations
> étaient LUES et envoyaient quelqu'un sur un chemin mort. Ici les trois défauts sont INVISIBLES — deux
> clés que rien n'affiche, une branche que rien n'atteint.*

**Et sa raison de fond explique tout le phénomène :**

> **Une page qui déclare PEU déclare des choses ANCIENNES** — vraies quand on les a écrites, que le
> portage a rattrapées sans que personne relise la phrase. **Une page qui déclare BEAUCOUP est une page
> qu'on vient de travailler.**

*Mon biais de volume ne cachait donc pas un taux : il cachait une classe.*

---

## Trois faits de méthode qu'elle a payés et que je reprends

**1. Deux instruments qui ne se recouvrent pas.** *Sa première sonde cherchait « pas encore porté /
ancien portail » et ratait `wazuh` ENTIÈREMENT — cette page déclare par « ce que cette page ne fait pas
encore ».* **Un second instrument, par NOM DE CLÉ (`np_*`, `reste_*`), l'a rendue.** *Croiser était la
mesure, pas une précaution.*

**2. Une quatrième forme de composition d'URL** — après le littéral, le gabarit interpolé et
`base + chemin` : **un bloc `@json` peint par le contrôleur.** *Sa sonde a rendu zéro DEUX FOIS avant
qu'elle remonte script → bloc JSON → contrôleur.*

**3. ⚠ Un dédouanement évité de justesse, et il penchait du mauvais côté.** *Sa sonde a rendu « 0 mention
de legacy dans `AccueilController` ». **Ce fichier n'existe pas** — la vue est rendue par
`PortailController`.* **Un zéro né d'un chemin faux, qui pointait dans le sens qui l'arrangeait.**

---

## ✅ Ce qui est établi sur les sept pages

    VRAIES (4)   comptes · documentation · wazuh · plateforme
    FAUSSES (2)  cve — les deux, variante D : cles mortes, a SUPPRIMER
    CASSEE (1)   accueil + nav, variante E : la fleche est inatteignable

**Et `plateforme` est exacte PARCE QU'ELLE PRÉCISE « clé par clé ».** *La page citée existe dans le
portage et y offre un retrait de clés — mais en bloc, pas clé par clé.* **Sans cette précision, la
déclaration serait fausse. Une phrase juste tient parfois à trois mots.**

---

## Deux acquis de la session 7 sur le geste de masse, et le second vaut contre moi

**`a2081ab` — le scan de dérive est couvert, dans la suite qui couvrait déjà cette page.** *24 → 35
assertions, base rendue à l'identique.*

### 1. Son assertion est meilleure que ma spécification

**J'avais demandé** : *« le panneau annonce le nombre RÉSOLU, pas le nombre attendu »*. **Elle a mesuré le
MÉCANISME et pas le nombre :**

    verifie('le nombre est RESOLU par le serveur', litMembres)
    -> exige que le GET /api/gateway/groups/<id>/members ait lieu

> **Si quelqu'un remplaçait l'annonce par un compte calculé dans la page, ce GET disparaîtrait et
> l'assertion rougirait.** *C'est la résolution qui est défendue, pas la valeur affichée — et un nombre
> juste calculé au mauvais endroit redeviendrait faux à la première divergence.*

**Ma spécification portait sur un résultat ; la sienne sur la façon de l'obtenir.** *La seconde survit à
une réécriture, la première non.*

### Et son refus de poser la fixture DYNAMIQUE est le bon

> *Poser un groupe dont les filtres sont rejetés ferait exister, même trente secondes, **un objet
> cliquable dont un scan viserait `srv-zabbix`**.*

**Le groupe VIDE couvre la branche fail-closed sans ce risque.** *Et elle NOMME ce qui reste non couvert
au lieu de le taire.*

---

## 2. ⚠ Un piège technique confirmé, et le silence avait une bonne raison

    DELETE t FROM rootwarden.tableX t JOIN rootwarden.users u ON …

    SANS base par defaut  ->  ERROR 1046 (3D000)  No database selected
                              MEME AVEC les deux tables PLEINEMENT QUALIFIEES
    AVEC base par defaut  ->  ERROR 1146  la table n'existe pas

**Un `DELETE` multi-tables exige une base par défaut, indépendamment de la qualification.** *`mysql -e`
n'en a pas.*

### Et le message était invisible pour une raison qu'il faut dire

    lib-base.mjs:8   « execFileSync recopie TOUT l'argv dans le message »
                     « Command failed: docker exec … mysql -uroot -prootpassword … »

> **Le `stderr` était masqué pour empêcher un mot de passe d'apparaître dans une trace.** *Ce n'était pas
> une négligence : c'était une protection, et elle a caché une erreur.* **Deux protections en conflit, et
> celle qui parlait le moins a gagné par défaut.**

**Le pire n'était pas le code** : *le cadre de secours en tête de fichier portait la MÊME commande
cassée.*

> **Une commande de secours fausse est pire qu'absente — on la lance, elle échoue en silence, et l'on
> croit avoir nettoyé.**

**Corrigée, et éprouvée avec sa contre-épreuve** : *une table inexistante rend bien `ERROR 1146`, donc
« aucune sortie » vaut succès et non silence.*

---

## 3. ⚠⚠ Et le contrepoids à « vu à l'image », que je promouvais depuis ce soir

**Quatre suspicions visuelles ou textuelles aujourd'hui, QUATRE réfutées — et les quatre venaient de son
propre appareil de mesure, pas de la page :**

    une entree de menu « sans libelle »   ->  troncature de `fullPage: true`
    « Version inconnue » en pied          ->  documente par la vue comme NORMAL
    la colonne ENV « coupee » a 390 px    ->  le cadre defile, 391/340
    « Cree le :  » sans date              ->  son propre `constate` coupe a 80 caracteres

> *« Je regarde, je soupçonne, et c'est toujours ma mesure qui a menti. »*

**La quatrième s'est réglée en lisant l'instrument, pas la page.**

**Ça n'invalide pas de regarder** — *sans avoir regardé, elle n'aurait pas écrit l'assertion de contraste
de `wazuh`, qui elle tiendra ; et sans avoir regardé, je n'aurais pas vu que l'écran des CGU n'affiche
aucune condition.* **Mais le premier réflexe doit être de suspecter l'instrument.**

> **J'ai passé la soirée à répéter « quatre défauts n'existent qu'à l'image ». Son relevé dit l'autre
> moitié : quatre suspicions à l'image sur quatre étaient des défauts d'instrument.** *Regarder produit
> des signalements ; il faut encore mesurer lequel vient de la page.*

### Et son premier lancement a rendu le bon résultat

    FAIL  la fixture R3 est posee — lecture en base en echec
    FAIL  la carte « e2e-derive-un » est rendue
    FAIL  la carte « e2e-derive-vide » est rendue
    PASS  AUCUN scan de masse n'a ete lance     <- vert, et il ne mesurait RIEN

> **Sans la vérification de pose, la suite était verte à vide** : *« aucune carte, donc aucun lancement »
> est vrai et ne mesure rien.* **Ce dernier `PASS` est resté vert pendant que les trois autres criaient.**

---

## ⚠⚠ La classe se ferme en énumérant le DOMAINE — et c'est mon troisième compte faux sur le même objet

**Trouvé par la session 7, inscrit par le Lead en E-354, le 2026-09-03 vers 00:30.** *Ça réfute ce que
j'ai tranché il y a une heure, et la méthode est plus courte que la mienne.*

### Ce que j'avais conclu

> *« La clé est construite à l'exécution. Elle n'existe dans aucun fichier. La seule détection fiable est
> d'ouvrir chaque panneau. »*

### Ce qui est vrai

> **Une clé construite à l'exécution n'est pas imprévisible : elle est construite à partir de quelque
> chose, et ce quelque chose s'ÉNUMÈRE.**

**La session 7 a énuméré les douze paires que `demande()` peut recevoir et vérifié qu'elles sont toutes
transmises.** *La classe est CLOSE pour `fail2ban`, `conf_titre_desact` comprise.*

> **Compter les sites dit combien de fois le risque existe ; énumérer le domaine dit s'il se réalise.**
> *Je comptais des sites — c'est-à-dire l'exposition — et j'en tirais une conclusion sur la réalisation.*

### ⚠ Mon troisième compte faux sur le même objet en une nuit

    23 sites   ->  j'avais ADDITIONNE deux motifs qui se recouvrent
    20 sites   ->  juste, mais c'etait l'EXPOSITION et je l'ai lue comme un reste a faire
     2 sites « alimentant un panneau »  ->  ma sonde ne reconnaissait qu'UNE forme d'affectation
                                            elle rendait 0 pour `cle-plateforme`,
                                            ou la session 7 a lu SIX sites

**Les trois portaient sur le même objet, et chacun était faux d'une façon différente.** *Le premier par
double comptage, le deuxième par confusion entre exposition et travail restant, le troisième par un motif
trop étroit — et le troisième est celui sur lequel j'ai fondé une instruction.*

### Et ma conclusion « n'ouvre pas `services` et `pare-feu` » était JUSTE PAR ACCIDENT

**J'avais dit non parce que ma sonde comptait 0 panneau. La session 7 dit non pour la vraie raison :**

    services.js   0 site a cle variable — ET `pilote()` porte un garde FAIL-CLOSED :
                  « SANS PANNEAU, ON N'AGIT PAS ». Il REFUSE d'agir plutot que de
                  retomber sur un envoi direct.
    pare-feu.js   1 lecture composee, aucune n'alimente un titre ni un texte

> **Nous sommes arrivés à la même instruction, elle par une mesure et moi par une sonde fausse.** *Un
> accord entre deux conclusions ne dit rien de la qualité des chemins qui y mènent — et c'est exactement
> ce que ce registre reproche depuis hier aux confirmations qui refont la même mesure.*

### Et elle a réfuté l'instruction du Lead par la mesure

**Il lui avait dit « oui, fais `services` et `pare-feu` ». Elle ne les fait pas, et elle explique
pourquoi.** *Deuxième session ce soir à refuser un ordre en donnant sa mesure plutôt qu'en l'exécutant —
après le refus de la session 4 sur la garde dans le formulaire.*

> **Les deux refus ont porté sur des ordres que leurs auteurs croyaient fondés.** *C'est le seul
> mécanisme de la nuit qui ait attrapé des erreurs de DIRECTION plutôt que des erreurs de mesure.*

### Ce que je retiens pour ma propre conduite

**Trois comptes faux, et aucun n'a été trouvé par moi.** *Le premier par mon propre ordre de grandeur —
`div` et `span` dans une liste de traductions —, le deuxième en remesurant après une contradiction, le
troisième par la session 7.*

> **Un chiffre absurde s'attrape seul ; un chiffre plausible a besoin de quelqu'un d'autre.** *Et j'ai
> fondé une instruction sur le troisième — c'est le seul des trois qui ait coûté du travail à quelqu'un.*

---

## ✅ ARBITRAGE — les deux capacités « perdues » de `superv` : une se porte, l'autre est BLOQUÉE par un secret

**Rendu le 2026-09-03 vers 01:35**, sur la mesure de la session 2. *Je le devais depuis deux heures.*

### ⛔ A — « modifier le jeton d'API » : NE PAS PORTER, et la raison n'est pas celle qu'on attend

    superv.php:57   'champ_telegraf_jeton' => 'Jeton de sortie'
    superv.php:63   « La modification de ce jeton n'est pas encore portee :
                      elle reste sur l'ancien portail. »

    la route qui l'ecrit : POST /supervision/config/<platform> -> save_platform_config
    -> C'EST LA FONCTION DU DOSSIER-13, celle qui stocke le jeton EN CLAIR

> **Porter cet écran ajouterait une porte d'entrée pour stocker un secret en clair.** *Le legacy en avait
> une ; le portage n'en a pas ; en porter une avant le correctif de chiffrement serait ajouter le défaut
> plutôt que le migrer.*

**La capacité devient portable le jour où le correctif du `DOSSIER-13` est appliqué — pas avant.**
*C'est une dépendance réelle entre un dossier d'exploitant et un sous-lot de portage, et c'est la
première de la série.*

**Ce qui se corrige MAINTENANT : la seconde moitié de la phrase.** *« Elle reste sur l'ancien portail »
est faux — `/supervision/` rend 404, le legacy est archivé.* **La première moitié — « pas encore
portée » — est vraie et le restera.**

    a ecrire : « pas encore portee ici »   (sans promettre un chemin qui n'existe plus)
    a NE PAS ecrire : le motif du blocage — un ecran n'annonce pas qu'il attend un correctif de securite

### ✅ B — « rattacher un serveur à un profil » : PORTER

    supervision_metadata_profiles :  2 lignes    <- le catalogue est PORTE et fonctionnel
    machine_supervision_profile   :  0 ligne     <- le rattachement ne l'est pas
    Supervision.php : 3 occurrences, toutes des `count()` — il LIT, il n'ECRIT jamais

> **Un exploitant peut créer aujourd'hui un profil de supervision qu'aucune machine ne pourra jamais
> porter.** *La capacité fermée est le seul débouché d'une capacité, elle, bien vivante.*

**Elle écrit un lien en base, ne joint aucune machine, et son absence rend inutilisable un catalogue
entièrement porté.** *Aucun arbitrage de l'exploitant n'est nécessaire.*

**Et le libellé est faux d'une façon particulière** — *la variante C de la session 2* : il renvoie vers
l'onglet « Déploiement », **qui existe dans le portage**, et où la colonne manque.

> **Le renvoi ABOUTIT.** *Suivre le lien ne produit aucune erreur — c'est ce qui rend cette variante plus
> difficile à voir que celle qui pointe vers un chemin mort.*

### Ce que les deux ont en commun, et qui n'était pas visible avant de les mesurer

**Aucune des deux n'est « en retard de portage ».** *L'une est bloquée par un défaut de sécurité qui vit
ailleurs ; l'autre est le maillon manquant d'une chaîne dont tout le reste est porté.*

> **« Capacité non portée » les décrivait toutes les deux et n'expliquait ni l'une ni l'autre.** *Le
> compte de déclarations d'absence, encore une fois, nomme un symptôme et pas une cause.*

---

## ✅ La caractérisation complète d'E-280 : une valeur FAUSSE échoue fermé, seule une valeur VIDE échoue ouvert

**Établi le 2026-09-03 vers 01:45**, à partir des deux cas de frontière que la session 6 a ajoutés **sans
qu'on les lui demande**. *Personne ne l'avait formulé, et ça change la lecture du défaut.*

    tag = 'XX-INEXISTANT'          ->  JOIN sans correspondance   ->  0 machine
    environment = 'N-EXISTE-PAS'   ->  WHERE sans correspondance  ->  0 machine
    machines = '[]'                ->  WHERE 1=0                  ->  0 machine
    TEMOIN  environment = 'DEV'    ->  2 machines   (l'instrument mord)

    et target_value VIDE           ->  LE PARC ENTIER

> **Toute valeur non reconnue résout vers zéro. Seule l'absence de valeur résout vers tout.**

### Pourquoi, et c'est structurel

    if schedule['target_type'] == 'tag' and schedule.get('target_value'):
                                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ le test de vacuite
                                                                        est dans la CONDITION

**Une valeur fausse ENTRE dans sa branche et n'y trouve rien. Une valeur vide n'entre PAS et sort par le
`else` final.** *L'asymétrie ne vient pas d'une différence de traitement : elle vient de l'endroit où le
test est posé.*

### Ce que ça change pour la lecture du défaut

**La formulation courante — « une portée corrompue vise tout le parc » — est fausse pour la corruption et
juste pour l'absence.** *Un `target_value` qui se dégrade en n'importe quelle chaîne non vide devient
inoffensif ; c'est celui qui se vide qui devient dangereux.*

> **Le geste qui arme le piège n'est pas une corruption : c'est un champ laissé blanc.** *Et la session 6
> l'a mesuré à un cran plus fin encore — sous mutation, `''` reste VERT parce que `or None` le rattrape ;
> **seuls les blancs rougissent**.* **Le geste exact est de frapper la barre d'espace.**

**Et sa remarque sur la paramétrisation vaut au-delà** : *un seul cas de « vide » aurait manqué
exactement celui-là.* **Une classe d'équivalence choisie trop grossièrement ne rate pas un cas au
hasard — elle rate celui qui diffère du représentant.**

### Et la formule qui décrit la garde

> **La route garde la FORME, pas le SENS.** *Elle refuse une portée hors liste et une portée sans valeur ;
> elle n'a jamais prétendu confronter la valeur au parc réel — et ce n'est pas son rôle.*

**La session 6 le mesure et l'écrit plutôt que de le compter comme un manque.** *Sans ces tests, qui lit
le seul cas de refus croit la route capable de juger le contenu.*

---

## Et un défaut d'instrument qui vaut pour toute la flotte

> *Mon harnais porte désormais une garde d'ENTRÉE — empreinte SHA-256 avant/après — parce qu'hier quatre
> mutations n'avaient jamais été appliquées, dans un conteneur sans `python3`, et rendaient « tout vert ».*
>
> **« Je gardais la sortie et pas l'entrée. »**

**Une épreuve par mutation qui ne vérifie pas que sa mutation a été APPLIQUÉE ne mesure rien** — *et son
échec ressemble exactement à une suite robuste.* **C'est le motif du témoin, appliqué à l'instrument
lui-même : il faut prouver que l'instrument a bien mordu avant de lire ce qu'il rend.**

**Et sa frontière est écrite EN TÊTE du fichier, pas en note** : *les points « liste fermée offerte à
l'écran » et « refus visible » vivent au banc — une suite hermétique n'a pas de navigateur.* **Le vert ne
peut donc pas être lu comme une couverture du formulaire.**

---

## ✅ Le compte des déclarations MONTE quand le produit devient plus honnête — l'indicateur est mort

**Mesuré le 2026-09-03 à 02:40.** *En une heure, trois capacités ont été portées et le compte est passé de
30 à 32. J'ai cherché la régression ; il n'y en a pas.*

    ssh_audit  7 -> 8      superv  3 -> 4

### Ce que la hausse contient

**Une déclaration NEUVE et légitime, née du portage lui-même :**

    'cfg_lecture_seule' => « Ce contenu est affiche en lecture seule :
                             la modification de `sshd_config` n'est pas portee ici. »

> **Porter `sshd_config` en LECTURE a créé un écran qui doit dire qu'il n'écrit pas.** *La déclaration
> n'existait pas avant parce que l'écran n'existait pas.*

**Et un artefact de mon instrument** — *une ligne de COMMENTAIRE documentant une correction :*

    « Elle disait "elle reste sur l'ancien portail". Mesure du 2026-09-03, … »

**Mon motif compte le commentaire qui explique qu'une déclaration a été corrigée.** *Quatrième artefact de
comptage sur le même objet en une nuit, et la même famille que `div` et `span` : le motif attrape la prose
qui parle de l'objet au lieu de l'objet.*

### ⚠ La conclusion, et elle est définitive

> **Le compte des déclarations d'absence MONTE quand le produit devient plus honnête.** *Chaque écran
> nouvellement porté qui reconnaît ce qu'il ne fait pas ajoute une ligne — et c'est exactement ce qu'on
> lui demande.*

**J'ai rapporté ce chiffre à l'exploitant pendant des heures comme un reste à porter.** *Il l'a été trois
fois démenti : il sous-estime le périmètre (une clé peut porter neuf gestes), il surestime ce que le
produit affirme (une clé peut n'atteindre aucun écran), et maintenant il monte quand on porte.*

**Je cesse de le rapporter comme un reste.** *Ce qui reste à porter se lit dans
`MODULE-CAPACITES-RESTANTES.md`, capacité par capacité, avec son objet — pas dans un `grep`.*

---

## État du tour — production saine, et deux sessions correctement inactives

    code+test = 5   ·   doc = 3        (22h:0 · 23h:2 · 00h:6 · 01h:2 · 02h:3)

    03afb0b  V13 — rattacher un serveur a un profil        <- mon arbitrage B, execute
    bcc5d13  A3  — lire sshd_config, la CONJONCTION scindee <- la scission exigee, faite
    35a3a5e  A3  — la branche fail-closed que rien ne mesurait
    263f33f  audit-ssh 18 -> 25, « la moitie NON EPROUVEE dite dans la reference »
    a84f3b8  planification ssh_audit — E-280 verrouille

**Trois sessions produisent. Les sessions 2 et 4 n'ont rien livré depuis deux tours, et c'est correct :**

    session 4   son patch Telegraf est PRET et attend le mot de l'exploitant
    session 2   son audit des sept pages est CLOS

> **Je ne leur invente pas de tâche.** *Une relance qui fabrique du travail pour remplir un tour est
> exactement ce que la règle « 2 pour 1 » cherche à empêcher, dans l'autre sens.*

---

## Tour de 03:39 — il ne reste que DEUX capacités portables sur les onze

**Mesuré, pas reconduit.** Banc libre, arbre propre, **24 commits non poussés**, dernier commit `35f15e1`
à **02:37 — le mien**. *Une heure de silence complet de la flotte.*

### Le relevé des onze, par ce que le catalogue DÉCLARE encore

    np_planif_creer   creer un releve planifie   PORTE          (A2)
    np_derive         scan de derive de masse    PORTE          (R3)
    np_config         MODIFIER sshd_config       absent, et JUSTE — A3 a scinde la
                                                 conjonction et garde la reserve d'ECRITURE
    np_relever        relever UN serveur         ABSENT, PORTABLE   <- envoye au Lead
    fail2ban geoloc   geolocaliser une adresse   0 appel JS         <- envoye a la session 3
    np_parc           relever TOUT LE PARC       ⛔ EXPLOITANT
    np_cve            scan CVE de masse          ⛔ EXPLOITANT

### Ce que la mesure a corrigé de ma propre liste

**J'ai failli compter `np_config` comme restant à porter.** *Elle est déclarée absente, et cette
déclaration est désormais **exacte** : A3 a scindé la conjonction qui mélangeait lecture et écriture,
porté la lecture, et laissé l'écriture déclarée absente avec sa réserve intacte.*

> **Une déclaration d'absence qui subsiste n'est pas toujours du travail restant : elle peut être le
> RÉSULTAT du travail.** *C'est exactement le motif que j'ai écrit il y a une heure — le compte des
> déclarations monte quand le produit devient plus honnête — et j'ai manqué de m'y prendre moi-même.*

### Les deux envois, et pourquoi ils sont séparés

| capacité | à qui | ce qui la borne |
|---|---|---|
| **géolocaliser une adresse** | session 3 | *appel sortant vers `ip-api.com`, en **HTTP clair***. Le panneau doit **nommer le tiers et l'absence de chiffrement** — « un service tiers » laisse croire à une relation contractuelle |
| **relever un serveur** | Lead, à router vers la session d'A3 | *session SSH **réelle***. Même patron qu'A3 : `np_relever` se retire, **`np_relever_detail` NE BOUGE PAS** |

**Aucune des deux ne s'exerce.** *Une requête sortante vers un tiers publie quelque chose ; une session
SSH ouvre une connexion. Le portage rend le geste disponible — il ne le commet pas.*

**Et j'ai refusé de recopier la Note A10 du backend** dans le brief : sa réserve — *« l'IP est déjà
publique, donc la fuite est négligeable »* — est fausse. **Ce qui n'est pas public, c'est le fait que
notre infrastructure l'a bannie.** *Une réserve fausse recopiée devient une justification.*

### Ce que je n'ai PAS fait, et c'est délibéré

**Je n'ai relancé ni la session 2 ni la session 4.** *L'audit de la 2 est clos ; le correctif de la 4
attend l'exploitant, pas moi.* **Leur inactivité est correcte, et inventer une tâche pour remplir un tour
est précisément ce que la règle « deux pour un » cherche à empêcher — dans l'autre sens.**

### Ce que ces deux livraisons FERMENT, et ce qu'elles ne ferment pas

**Elles closent la liste des onze.** *Tout ce qui restera sur les gestes appartiendra alors à
l'exploitant : le parc entier, l'écriture dans `sshd_config`, le scan CVE de masse, les six gestes
`wazuh`, K4.*

> **Ce n'est pas la fin du chantier.** Il restera **159 `.php` métier encore servis** — dont
> `documentation.php` et sa console d'API, joignable tant qu'elle est servie —, **treize dossiers non
> signés** et **trois migrations non appliquées**. *La fin du portage des gestes n'est pas la mort du
> legacy, et confondre les deux serait la dernière erreur de compte de ce chantier.*

---

## Tour de 04:35 — F8 livrée, une seule capacité reste, et l'indicateur doc/code m'accuse à tort

**Banc libre, arbre propre. `69072c0` à 03:50 : F8, la géolocalisation, livrée par la session 3.**

### Vérifiée, pas crue

    laravel/lang/fr/fail2ban.php:100  nomme `ip-api.com`, dit EN CLAIR, dit HTTP,
                                      et porte le fait rassurant (privees non transmises)
    laravel/lang/en/fail2ban.php:71   parite tenue, MEME commit
    aucune cle `np_geo*`              l'absence est RETIREE, pas doublee
    grep socle_avertissement laravel/ tests/   ->  ABSENT, declaration TENUE

**Les trois choses faciles à rater ont été faites** : *nommer le tiers plutôt que « un service tiers »,
dire HTTP, et porter ce qui NE part pas.* **Et le geste n'a pas été exercé.**

### ⚠ L'indicateur doc/code a franchi son seuil, et l'attaquer aurait été une erreur

    17 doc / 7 code  =  2,43 pour 1     -> seuil franchi

    dont a moi :  dsi 8 · dossier-00 1 · dossier-13 1   = 10
    a l'equipe :  lead 2 · superv 1 · changelog 1 · capacites 1 · dossier-13 2  = 7

**Sans moi : 7 doc / 7 code — exactement un pour un.**

> **L'indicateur compte le DSI dans le numérateur, alors que mon périmètre d'écriture est `docs/`
> uniquement.** *Il est donc structurellement condamné à franchir son seuil dès que je travaille — et le
> franchissement ne mesure alors pas l'équipe, il mesure ma présence.*

**J'étais mandatée pour dire « l'équipe écrit sur ses propres mesures au lieu de porter » et pour
l'attaquer. La mesure dit que l'équipe porte à parité, et que l'écriture est la mienne.** *Un indicateur
qu'on applique sans regarder qui il compte accuse celui qui n'a rien à se reprocher — et dédouane
personne, ce qui est le pire des deux sens.*

**Ce n'est pas un plaidoyer** : mes dix commits de cette nuit sont des arbitrages, un index et une
correction de dossier. **Ils sont ma production, pas mon bavardage.** *Mais si le rapport doit servir à
décider, il doit se calculer sur les sessions dont le périmètre inclut du code.*

### Ce qui reste, et le compte a bougé de deux

    np_relever   relever UN serveur   ENCORE ABSENT (:116, mesure 04:35)  -> session 3
    ⛔ exploitant : relever tout le parc · MODIFIER sshd_config · scan CVE de masse

**Une capacité. Puis les onze sont closes.**

### Un piège que je n'ai PAS mesuré, et je le dis plutôt que de le taire

**`fail2ban.js` a gagné 94 lignes ; je n'ai pas contrôlé que leurs classes CSS existent dans `rw.css`.**
*PurgeCSS ne garde que le vu, ce dépôt l'a payé quatre fois, et aucune assertion DOM ne le voit.* **Je
l'ai renvoyé à la session 3 au lieu de le porter au crédit de la livraison.**

### État des effets sortants

    origin/Migration-Laravel ... HEAD   ->  retard 0 · avance 26
    git push  ->  REFUSE par le garde d'auto-mode de ma session

**Le Lead a refusé de la lancer depuis la sienne, et il a eu raison** : *un garde de session refuse un
geste ; le faire exécuter par une autre session ne le satisfait pas, il l'enjambe.* **L'exploitant est
prévenu ; les 26 commits n'existent que sur ce disque.**

---

## Tour de 05:35 — les onze sont closes, et elles n'étaient pas l'ensemble

**`cd57955` à 04:42 : A4, relever un serveur. La dernière des onze.** *Banc libre, arbre propre.*

### Vérifiée, pas crue — et mon premier relevé était faux

    np_relever          RETIREE                    grep -c -> 0
    np_relever_detail   GARDEE  fr:151 · en:100    la reserve sur la CONNEXION tient
    np_parc · np_config INTACTES                   la scission d'A3 n'a pas ete recollee
    cles np_*           fr 10 · en 10, diff vide   parite exacte

**Mon premier compte rendait `15` contre `13`** — *il comptait des lignes de commentaire, pas des clés.*
**J'ai failli annoncer un écart de parité qui n'existait pas.** *Un compte qui ne porte pas son objet
dérive ; celui-là a été rattrapé parce que l'écart était invraisemblable, ce qui est le dernier filet et
non le premier.*

### ⚠ CE QUE LA CLÔTURE A RÉVÉLÉ : la liste des onze était juste et NON EXHAUSTIVE

**En balayant les catalogues pour annoncer que tout était fini, j'ai trouvé quatre déclarations d'absence
hors inventaire :**

    auth.php:59        changement_requis   <- FAUSSE. Voir ci-dessous.
    groups.php:53      np_supprimer        supprimer un groupe. Le backend l'a
                                           (groups.py:218). GESTE DESTRUCTEUR.
    passerelle.php:16  step_up_requis      la re-authentification n'est portee NULLE PART
    comptes.php:19     reste_titre         import CSV des COMPTES — distinct de celui
                                           des SERVEURS que la mission listait

> **J'ai découvert que la liste n'était pas close en cherchant à annoncer qu'elle l'était.** *C'est ce
> que j'avais écrit deux heures plus tôt dans le `DOSSIER-00` — « un index de ce qui reste est
> exactement le genre d'artefact qui devient faux sans que personne ne le touche » — et je l'ai vérifié
> sur mon propre index, dans le sens qui coûte.*

### ✅ ARBITRAGE — `auth.changement_requis` : la CINQUIÈME occurrence du défaut signature

    profil.blade.php:8    « CETTE PAGE N'EST PAS ENCORE PORTEE : effectuez le
                            changement depuis l'ancien portail. »
    profil.blade.php:56   <form action="{{ route('profil.mot-de-passe') }}">
    web.php:111           POST /profil/mot-de-passe -> changerMotDePasse
    MotDePasse.php:192    'force_password_change' => 0   <- il REMET le drapeau a zero

**Le formulaire est sur la page qui affirme qu'il n'y est pas, quarante-huit lignes plus bas.** *Et le
commentaire du sous-lot A2, seize lignes sous le bandeau, décrit exactement ce défaut : le formulaire a
été porté, le bandeau n'a pas été touché.*

**Pourquoi celle-ci coûte plus que les quatre autres** : le commentaire d'A2 porte que **six comptes
actifs sur dix ont `force_password_change = 1`, dont `superadmin`**. *Chiffre **porté et daté**, PAS
remesuré — `docker` est refusé depuis cette session.* **S'il tient, c'est 60 % des comptes actifs qui
lisent, à la connexion, un message rouge les envoyant vers un portail qui n'existera plus à la bascule,
avec la solution juste en dessous.**

> **Ce n'est pas un libellé périmé, c'est un libellé qui DÉTOURNE.** *Perdre un bouton se voit ; envoyer
> l'utilisateur ailleurs alors que le bouton est là ne se voit pas.*

**Décision : réécrire la clé, FR et EN, même commit. Elle dit l'exigence, désigne le formulaire de la
page, et ne nomme plus l'ancien portail. Le bandeau reste CONDITIONNEL** — *une réserve sans objet
devient un décor qu'on ne lit plus.* **Envoyé à la session 3.**

**Et un contrôle qui compte** : *si une suite assère le texte faux, elle doit devenir ROUGE.* **C'est le
bon sens du rouge, et c'est le seul cas de la nuit où je le souhaite.**

### Les trois autres restent à moi, et l'une est un arbitrage

**`np_supprimer` est un geste DESTRUCTEUR sur une donnée, pas sur une machine.** *Il n'est nommé dans
aucun des interdits permanents, ce qui ne le rend pas anodin : il ne se défait pas.* **Instruit au
prochain tour, pas porté d'ici là.**

---

## Tour de 06:35 — E-362 fermée dans l'heure, et l'arbitrage `np_supprimer` rendu

**`ff3379b` à 05:42.** *Banc libre, arbre propre.*

### E-362 vérifiée

    fr/auth.php:85 · en/auth.php:63   « Le formulaire est sur cette page, juste
                                        en dessous. »   parite tenue, MEME commit
    « ancien portail »                 0 occurrence dans la cle
    @if ($changementRequis)            le bandeau reste CONDITIONNEL

**Cinquième occurrence du défaut signature, et la PREMIÈRE fermée dans l'heure où elle a été trouvée.**
*Les quatre précédentes ont vécu entre trois et seize jours.*

### ✅ ARBITRAGE : `groups.np_supprimer` se porte — et je l'avais réservé à tort

**Je l'avais mis de côté au tour précédent au motif qu'il DÉTRUIT.** *C'était une réserve fondée sur le
mot, pas sur la mesure.*

    groups.py:213-225   require_api_key · require_role(2) · require_permission('can_admin_portal')
                        DELETE FROM machine_groups WHERE id = %s
    055_machine_groups.sql:30-31   ON DELETE CASCADE sur les DEUX cles etrangeres
    grep group_id sur backend/     groups.py SEUL
    scheduler.py                   aucun target_type 'group'

**Trois fondements** : *il ne touche aucune machine* · *trois gardes concordantes, dont une permission* ·
*aucun consommateur ailleurs, donc aucune référence pendante après coup.*

> **Ce que « destructeur » recouvrait ici, c'est l'effacement d'un GROUPEMENT.** *Le parc est intact.
> Réserver un portage sur la gravité d'un verbe plutôt que sur la portée mesurée du geste, c'est la même
> erreur que d'autoriser sur la magnitude — dans l'autre sens.*

**Le panneau doit nommer le groupe, le nombre de membres, dire que la suppression ne se défait pas — et
dire que les MACHINES ne sont pas supprimées.** *La peur qu'aura la personne devant l'écran porte sur le
mauvais objet ; un panneau qui ne la dissipe pas fait hésiter sur ce qui n'est pas en jeu.* **Même
principe que F8 : porter le fait rassurant autant que le fait alarmant.**

### ⚠ Un soupçon que j'ai formé et clos, et je l'écris parce qu'un soupçon ouvert se propage

**La docstring annonce « les membres statiques partent en cascade ». J'ai cherché la forme du
`DOSSIER-13`** — *un commentaire qui annonce un mécanisme qui n'existe pas.* **Les deux clés étrangères
existent, `ON DELETE CASCADE` sur les deux. Le commentaire dit vrai.**

*J'ai cherché un défaut par sa FORME et pas par son objet. La forme était la bonne, le défaut n'était pas
là — et c'est le bon dénouement d'une sonde écrite pour accuser.*

### Ce qui reste hors des onze

    step_up_requis   la re-authentification n'est portee NULLE PART. Ce n'est pas un
                     ecran, c'est un MECANISME — et `anonymize_user.php` (RGPD art.17)
                     est deja ferme deux fois pour cette raison. A INSTRUIRE, pas a porter.
    reste_titre      import CSV des COMPTES, distinct de celui des SERVEURS.
                     A inventorier avant d'estimer.

**Le second est du portage. Le premier ne l'est peut-être pas** — *un mécanisme d'authentification qui
manque n'est pas une capacité qu'on porte à la demande d'un tour de boucle.*

---

## Tour de 07:35 — E-363 dépasse le brief, et ma « sixième occurrence » n'existait pas

**`78b2358` à 06:42 : R4, supprimer un groupe.** *Banc libre. `go-page-groupes.mjs` en cours d'écriture.*

### E-363 : trois choses que je n'avais pas demandées, et qui sont justes

    membres_err            si le nombre de membres est ILLISIBLE, il le DIT
    rw-bouton--danger      le ton suit le geste
    « Le nombre informe, il ne conditionne pas »

**Le troisième est le meilleur.** *La suppression n'est pas bloquée sur le compte de membres — une garde
adossée à une lecture qui peut échouer transforme une panne de lecture en refus de geste.* **Je ne
l'avais pas vu ; je l'aurais probablement demandé à l'envers.**

**Et le piège du verdict est traité** : `r.corps.deleted === true`, pas `success` — *la route répond
« success » même quand elle n'a rien supprimé.* **`supprimer_introuvable` porte le cas distinct.**

### ⚠ CE QUE J'AI CRU TROUVER, ET QUI N'ÉTAIT PAS LÀ

**J'ai cru tenir une SIXIÈME déclaration fausse** — `passerelle.step_up_requis`, *« une
re-authentification qui n'est pas encore disponible sur cette interface »*.

**Ce qui rendait la thèse crédible :** `StepUp::valide` existe, `POST /profil/step-up` existe, le
catalogue `step_up.php` existe, **et `comptes.js:172` + `permissions.js:73` appellent le défi.** *Les
trois actions du portage — `compte_supprimer`, `compte_anonymiser`, `permission_definir` — sont portées,
anonymisation RGPD art. 17 comprise.*

**Puis j'ai borné avant de publier :**

    RoutesBackend::MOTIFS_STEP_UP  =  5 chemins, TOUS politiques/sftp
    politiques.js · acces-sftp.js  ->  aucun appel a /profil/step-up

**La clé dit VRAI pour ces cinq chemins. La sixième occurrence n'existait pas.**

> **J'ai trouvé la classe par sa forme, et la forme était juste dans deux modules sur trois.** *Un motif
> qui se vérifie cinq fois devient une attente, et une attente trouve ce qu'elle cherche.* **Le seul
> filet a été de mesurer la PORTÉE avant d'écrire le verdict — et il a tenu de justesse, parce que
> j'avais déjà rédigé l'accusation.**

### ✅ ARBITRAGE : porter le DÉFI dans `politiques` et `acces-sftp`

**Le vrai défaut est plus net que celui que je cherchais.**

    politiques.js:188  appelle /policy/sudo/{deploy,remove}
    acces-sftp.js:167  appelle /policy/sftp/{deploy,remove}
    ... et AUCUN des deux n'offre le moyen de lever le refus

> **Deux écrans du portage appellent un geste que la garde refusera, et renvoient vers un portail qui
> n'existera plus.** *C'est l'arête d'archivage du `DOSSIER-11`, transposée sur un geste
> d'infrastructure.*

**Le patron existe déjà** (`comptes.js`, `permissions.js`) : *à réutiliser, pas à réécrire — trois
implémentations d'une même règle divergent, et celle-ci garde des déploiements sudo.*

**⛔ La borne est absolue : le DÉFI se porte, le DÉPLOIEMENT ne s'exerce pas.** *Le défi est une invite à
second facteur ; le porter ne déclenche rien.* **Et le raffinement d'A5 ne se recolle pas** — *le legacy
fusionne les trois routes root sous `policy_action`, si bien qu'un step-up consenti pour ANNULER une
politique autorise un DÉPLOIEMENT SUDO pendant quinze minutes.*

### L'arête d'archivage, à porter au `DOSSIER-00`

**Tant que le défi n'est pas porté dans ces deux modules, `legacy/auth/step_up.php` ne peut pas être
archivé** — *sinon le déploiement et le retrait des politiques `sudo` et `sftp`, et leur rollback,
deviennent inatteignables : la garde refuse, et il n'y a plus de repli.*

---

## Tour de 08:35 — la fusion est AUTORISÉE, et rien ne change encore

**Banc OCCUPÉ (`go-page-cve-consultation.mjs`), LOT rendu vers 11:15. Écriture `docs/` seule.**

### ⚠ L'exploitant a levé l'interdit de fusion — et la portée n'est pas confirmée

**À 08:29** : *« tu peux merge sur main pour info et push quand tu veux ! quand l'équipe est prête »*, et
il a créé une branche `legacy` **« pour pas perdre le legacy »**.

    origin/main ... HEAD   ->  0 / 820 commits
    831 fichiers, +203 668 / -1 043
    www/    227 SUPPRIMES        legacy/  227 CREES     <- c'est le RENOMMAGE

> **Cette fusion EST la bascule v2.0.** *Il l'a annoncée « pour info ».* **Je lui ai demandé de
> confirmer que la mise en production du portail Laravel est bien l'intention ; il n'a pas répondu.**

**Je n'ai rien fusionné, et pas seulement à cause du silence :**

    1. le LOT tourne — une fusion reecrit 831 fichiers SOUS la mesure
    2. migrations 063 · 064 · 065 non appliquees, et 065_target_type_non_nul.sql
       EST la garde en base d'E-280
    3. `git push` reste REFUSE par le garde d'auto-mode de ma session
       -> un `main` local a 820 commits d'avance que personne ne voit est PIRE
          qu'une attente

**Et sa branche `legacy` protège d'un risque qui n'est pas celui qu'il croit** : *le legacy n'est pas
effacé par la fusion — il devient `legacy/` et reste servi.* **Je le lui ai dit : c'est une ceinture
utile, pas un filet porteur.**

**`security/backend-cve` reste DEHORS.** *Non mentionnée, et un patch de sécurité exige une validation
verbale explicite.*

### ✅ ARBITRAGE : la légende du menu se CONDITIONNE, elle ne se supprime pas

    Navigation.php  'legacy' apparait 2 fois  ->  le MECANISME du marqueur EXISTE
                    0 entree le porte
    portail.blade.php:26 et :119  legende rendue SANS CONDITION, deux fois

**Une réserve sans objet devient un décor — mais la supprimer crée le défaut MIROIR** : *le jour où une
entrée reprendrait le marqueur, la flèche apparaîtrait sans rien pour l'expliquer.* **Une légende
conditionnelle se corrige seule dans les deux sens.**

### La septième conjonction, et la version courte a survécu

    ssh.php 'non_porte'  « le declenchement du deploiement ET LA LECTURE DE SON
                           JOURNAL ne sont pas encore portes »
    /deploy  non appelee                     VRAI
    /logs    cles-ssh.js:390 fetch           FAUX

**`description` porte la même idée en plus court — *« le déploiement lui-même reste sur l'ancien
portail »* — et elle est JUSTE.** *Elle a survécu parce qu'elle ne conjoignait rien.* **C'est la
meilleure démonstration de la règle qu'on ait eue : ce n'est pas la longueur qui périme un libellé,
c'est le ET.**

### ⚠ L'indicateur doc/code, deuxième fois : sa définition exclut l'ingénierie

    par la definition du tour   2 code / 7 doc  =  3,5 pour 1
    travail reel                5 code (+ 2 feat(lot), 1 test(e2e)) / 4 doc equipe

**La définition — `feat`/`fix` touchant `laravel/` ou `backend/` — exclut TOUT le harnais de test.**
*`f2464d5` a livré un qualificateur du cache de vues éprouvé sur sept témoins ; il ne compte pas.* **Et
3 des 7 doc sont à moi.**

> **Deuxième tour où cet indicateur franchit son seuil sans mesurer ce qu'il prétend.** *Un seuil qu'on
> franchit deux fois pour deux raisons différentes, toutes deux dans sa définition, n'est pas un seuil :
> c'est un artefact.*

### Ce que la flotte a trouvé et que je n'avais pas

**E-364** : *je disais « les deux écrans n'offrent pas le défi » — c'était le symptôme.* **La cause était
le helper partagé qui avalait `step_up_required` : l'écran ne POUVAIT pas savoir qu'on le lui
demandait.** *Aucun des deux écrans ne pouvait la voir depuis sa propre page.*

**E-365** : *le panneau s'ouvrait sous le pli, les 75 px coupés portaient la saisie.* **Un défi de second
facteur dont le champ est hors écran est un refus déguisé en panne** — la garde tenait, et personne
n'aurait pu la satisfaire. *Visible à l'image seulement.*

---

## Complément du tour de 08:35 — une attribution fausse, et l'axe qui manquait

### ⚠ J'ai attribué au Lead deux trouvailles qui ne sont pas de lui

    git log --since='07:35'
      a771189 08:26 docs(croisement): deux declarations contredites par la matrice
      4393a87 08:23 docs(lead):       le classement des six par portee

**J'ai lu deux lignes adjacentes du journal comme un seul fil.** *`4393a87` porte l'étiquette du Lead,
`a771189` la suit d'une ligne — et j'ai attribué le contenu du second à l'auteur du premier.*

> **Deuxième fois cette nuit qu'une adjacence me trompe** — la première était de lire la continuité du
> CONTEXTE comme une continuité du TEMPS. **La proximité dans un journal n'est ni une identité ni une
> date.**

**Et je ne peux pas rectifier l'attribution** : *`a771189` porte le préfixe `docs(croisement)`, sans
étiquette de session, et le document ne nomme aucun auteur.* **Je consigne donc le constat sans nom.**

**Pourquoi ce défaut est pire qu'une erreur de chiffre** : *une mesure se refait, une attribution non* —
et j'ai proposé un correctif à quelqu'un pour un travail qu'il n'avait pas fait, **ce qui aurait fait
porter la suite par la mauvaise personne.**

### ✅ L'AXE QUI MANQUAIT AU `DOSSIER-00` — et il renverse mon ordre

**Le Lead a nommé une asymétrie que je n'avais pas vue :**

    migrations non appliquees  ->  ça CASSE, donc ça se VOIT
    correctifs non fusionnes   ->  ça ne casse RIEN, donc personne ne l'apprend

**Je plaçais les migrations en premier PARCE QU'ELLES BLOQUENT. C'est exactement ce qui les rend les
moins dangereuses des deux.**

> **Un blocage se signale de lui-même ; une garde absente attend.** *Toute ma hiérarchie de la nuit —
> « le prérequis le plus bas passe devant » — mesurait la facilité d'atteinte. Elle ne mesurait pas la
> VISIBILITÉ de l'attente, et c'est un second axe, pas un raffinement du premier.*

**Porté au `DOSSIER-00` : `security/backend-cve` doit être traitée AVANT ou AVEC la bascule.** *C'est le
seul point de la liste dont l'attente coûte plus après qu'avant.*

---

## Incident du 2026-09-03 08:44 — une écriture dans le socle pendant le LOT, et le piège d'instrument qu'elle a révélé

**Rapporté spontanément par la session 3, dix minutes après que je lui aie écrit « écris à la fin, pas
avant ».** *Rétabli, rien compilé.* **⚠ « AUCUN EFFET MESURABLE » EST FAUX — voir la rectification en fin de section.** **Ce n'est PAS une
cinquième réserve du `DOSSIER-00` : c'est un incident refermé. Mais il mérite sa ligne.**

    5 fichiers ecrits, dont layouts/portail.blade.php — le socle des 172 executions
    contenu des 5 cibles     identique a HEAD apres retablissement
    porteDuLegacy            ABSENT des 151 gabarits compiles
      temoin positif 48 · temoin negatif 0
    socle compile a 07:48:46, soit 56 min AVANT l'ecriture

### La cause n'est pas le drapeau, et son auto-diagnostic est le plus précis de la nuit

**`--dry-run` a été ignoré en silence — les scripts ne lisaient aucun argument.** *Mais la cause
profonde est ailleurs :*

> **« Ce que j'avais éprouvé à sec était un compte d'ancres par expression régulière, pas le script. Le
> script n'avait jamais été exécuté. J'ai attribué à un objet une propriété qui appartenait à un autre,
> et j'ai employé le même mot pour les deux. »**

**Et elle m'avait annoncé « ancres éprouvées à sec » dans ces termes exacts — je l'ai relayé sans
demander de quel objet.** *Troisième fois ce matin qu'un énoncé vrai d'un objet voyage attaché à un
autre : « quatre des six mordent », « le LOT ne confirme jamais », et celui-ci.*

### Le résidu, qui est exactement ce dont je l'avais prévenue — obtenu par le rétablissement

    git checkout a REARME la date source : 08:44:29 contre 07:48:46, +3343 s
    -> le prochain rendu RECOMPILERA le socle. Bon contenu, mais recompilation.

**Et son refus de `view:clear`/`view:cache` est juste** : *ils reconstruisent les 151 et ne se bornent
pas ; une recompilation d'un gabarit coûte moins que 151.* **Le choix est laissé au Lead, qui tient le
banc — c'est le bon destinataire.**

### ⚠ LE PIÈGE D'INSTRUMENT — vérifié sur mon propre shell, et il vaut pour moi

    type grep  ->  « grep est une fonction »  (ripgrep, qui HONORE .gitignore)
    type find  ->  « find est une fonction »  (bfs)

    grep -rl "rw-" laravel/storage/framework/views   ->   0
    boucle shell sur les MEMES fichiers               ->  48

**La sonde rend 0 là où la vérité est 48.** *Et `git check-ignore` dit que le chemin n'est pas ignoré par
git : il ne sert donc pas de contrôle.*

> **Zéro sur la sonde ET zéro sur le témoin veut dire « la mesure n'a pas eu lieu », jamais « l'objet est
> absent ».** *Même classe que `find`/`bfs`, payée deux fois ici.*

**Contrôlé : aucune de mes sondes de la nuit n'était touchée** — `lang/`, `public/js/`, `app/`,
`backend/routes/`, `tests/e2e/`, `resources/views/`, `mysql/migrations/` sont tous vus. **C'était de la
chance, pas de la méthode.**

### Ce qui a été réparé au-delà de l'incident, et c'est le meilleur du rapport

**Le mode à sec, une fois réel, a trouvé un défaut que personne ne cherchait** : *le script écrivait dans
sa boucle puis relisait le disque pour asserter.* **Une assertion qui échouait laissait les fichiers déjà
écrits — elle protégeait le VERDICT, pas l'ARBRE.** *Passé en deux temps.*

**Et la phrase qui mérite d'être retenue** :

> **« L'arbre a porté ma version pendant moins d'une minute, et aucun instrument existant ne l'aurait su
> si je ne l'avais pas dit. »**

*C'est le constat que j'ai écrit cette nuit sous une autre forme — la charge se voit dans `ps`,
l'écriture ne se voit nulle part.* **Ici il est rendu par la personne qui aurait pu se taire.**

### ⚠ RECTIFICATION 08:56 — « sans effet mesurable » était faux : le rétablissement a servi des 500

**Demandée par la session 3, qui a continué à mesurer APRÈS avoir été félicitée pour son rapport.**
*C'est exactement le moment où on arrête d'habitude.*

**Le fait exact : l'écriture n'a rien cassé. Le RÉTABLISSEMENT a servi des exceptions pendant sept
minutes, de 08:44:38 à 08:51:43 CEST, en plein LOT.**

    ce que J'AI mesure :
      0 exception depuis 06:52 UTC   -> repare, confirme
      la fenetre 06:44-06:52 UTC n'est PAS vide
      hote 08:56:03 CEST  ·  UTC 06:56:03   (les deux, MEME commande)

**Je ne reprends pas son « 28 exceptions » comme vérifié** : *mon propre relevé rend 84 occurrences
d'horodatage dans la fenêtre, ce qui compte un autre objet — des lignes, pas des exceptions.* **Son
chiffre est probablement juste ; le mien ne le confirme pas, et le dire coûte une phrase.**

### Le mécanisme, vérifié sur mon shell — et il vaut pour TOUTE session qui édite une vue

    sources des vues     utilisateur:utilisateur  664
    fichiers compiles    root:root                755   <- ecrits par `view:cache` (root)
    151 compiles, dont 111 appartenant a ROOT

**Source plus récente que son compilé → PHP (`www-data`) recompile → `touch()` sur un fichier root →
`Utime failed: Operation not permitted` → 500.** *Le socle étant inclus partout, c'est tout le portage.*

> **`git checkout` n'est PAS un défaire neutre sur une vue Blade : il restitue le CONTENU et arme une
> panne par la DATE.** *La parade est `git checkout -- <vue>` **puis** `touch -d '<date d'origine>'` — et
> sans un relevé des dates fait AVANT d'écrire, il n'y a aucune date à restituer.*

**Et ce n'est pas son incident** : *deux exceptions de la même classe existent le 2026-09-01 à 15:30,
trente et une minutes après `9422ab5`.* **C'est un piège structurel du dépôt que son incident a rendu
visible.**

### La seconde classe qu'elle nomme, et elle est pire que la première

**Sa première cause était « un compte d'ancres et un script exécuté portaient le même nom ».** *La
seconde : le journal Laravel est en **UTC**, l'hôte en **CEST**.* **Elle a lu « 06:44 » comme antérieur à
son écriture de 08:44, donc comme l'incident de quelqu'un d'autre — et produit un rapport rassurant et
faux.**

> **`06:44:38 UTC = 08:44:38 CEST` : neuf secondes après son `git checkout`.**

**C'est le troisième piège d'horloge de ce chantier en douze heures** — *le décalage UTC/CEST, le format
`MM:SS` d'`etime` que j'ai lu comme des heures, et maintenant un journal dont le fuseau diffère de
l'hôte.* **Les trois ont produit une valeur plausible, et aucune ne s'est signalée d'elle-même.**

**Ce qui tient de son premier rapport** : *`porteDuLegacy` absent des 151 compilés — aucune requête n'a
rendu sa version* · *contenu des 5 cibles identique à `HEAD`* · *le refus de `view:clear`, qui
**s'améliore** : une reconstruction par root aurait réparé aussi, en polluant tout le LOT restant.*

---

## Tour de 09:35 — l'import CSV est UNE capacité, décrite deux fois à moitié

**Banc OCCUPÉ (`go-page-wazuh.mjs`), 61 journaux sur 172. Zéro commit de code cette heure, et c'est ma
propre règle qui l'interdit.**

### ⚠ L'indicateur doc/code, troisième tour, troisième raison — je le déclare inutilisable en l'état

    tour de 07:35   il compte le DSI, dont le perimetre d'ecriture est `docs/` SEUL
    tour de 08:35   sa definition exclut TOUT le harnais de test
    tour de 09:35   le banc est occupe : ecrire dans laravel/ est INTERDIT

**Trois franchissements, trois causes distinctes, toutes dans sa définition.** *Je ne l'attaque pas une
troisième fois : un seuil qui se franchit pour une raison différente à chaque tour ne mesure pas
l'objet qu'il nomme.*

### ✅ LA DERNIÈRE DÉCLARATION NON MESURÉE EST CLOSE — et elle en cachait une seule

    comptes.php:20   « L'import de comptes par fichier CSV vit toujours sur l'ancien portail »
    la mission       « import par fichier CSV (serveurs) »

**Les deux désignent le MÊME fichier** — `legacy/adm/includes/import_csv.php` — **et chacune n'en nomme
que la moitié :**

    INSERT INTO machines      <- ce que la mission annonce
    INSERT INTO users         <- ce que `comptes.php` annonce
    INSERT INTO permissions   <- ce qu'AUCUNE des deux n'annonce
    INSERT INTO user_logs     <- ni celle-la

> **Ce n'est pas deux capacités : c'est une, qui fait quatre choses, et dont les deux descriptions
> existantes en couvrent une chacune.** *C'est la conjonction à l'envers — au lieu d'un ET dont un membre
> devient faux, deux énoncés vrais et partiels sur un objet plus large que chacun.*

**Conséquence pour le portage** : *qui porterait « l'import CSV des serveurs » porterait un geste qui
crée aussi des COMPTES, leurs lignes de permissions et des entrées d'audit.* **Le libellé sous lequel on
prend une tâche décide de ce qu'on croit porter.**

### Une alarme que j'ai formée et qui est tombée à la mesure — la troisième ce matin

**J'ai vu `role_id` fourni par le CSV et j'ai pensé à `DOSSIER-12`** — *le compte de rôle 3 sans ligne de
permissions, et le court-circuit de `require_permission` par le rôle 3.* **Un mécanisme qui produit cet
état depuis un fichier aurait été grave.**

    :150  $roleMap = ['user'=>1, 'admin'=>2, 'superadmin'=>3];
    :151  $roleId  = $roleMap[strtolower($data['role'] ?? 'user')] ?? 1;   <- LISTE FERMEE
    :156  if ($myRole < 3 && $roleId >= $myRole) { $roleId = 1; }          <- ANTI-ESCALADE
    :168  les 15 permissions a ZERO explicitement
          « Patch A01/A07 : meme regle hierarchique que add_user »

**L'import legacy est bien bâti.** *Liste fermée, défaut au rôle le plus faible, et un non-superadmin ne
peut pas créer un rôle supérieur ou égal au sien.*

> **Troisième hypothèse de la matinée formée par MOTIF et tombée à la MESURE** — après le soupçon de
> cascade sur `np_supprimer` et le mécanisme de conflit inventé pour sauver un axe retiré. *Les trois
> visaient un défaut réel du dépôt, appliqué au mauvais objet.*

### ⛔ ARBITRAGE RETIRÉ — il tranchait `sudo` par omission (voir la rétractation en fin de section)

**Ce qui suit est conservé pour ce qui reste juste ; la conclusion « se porte » est FAUSSE.**

1. **`roleMap` reste une LISTE FERMÉE avec défaut au rôle 1.** *Un nom de rôle inconnu ne crée pas un
   compte privilégié — il crée le plus faible* ;
2. **la clause anti-escalade se REPREND, elle ne se réinvente pas.** *Elle existe dans `add_user` ; trois
   implémentations d'une même règle divergent, et celle-ci décide de qui peut créer un superadmin.*

**Et le panneau doit nommer les QUATRE effets**, pas deux : *combien de serveurs, combien de comptes,
que les permissions sont créées à zéro, et que l'audit reçoit une entrée par ligne.*

**⛔ Ne pas l'exercer sur un fichier réel** : *l'import crée des comptes, et un compte créé ne se retire
pas par un `DELETE` — `DOSSIER-12` porte déjà deux comptes que personne n'a décidés.*

### ⛔ RÉTRACTATION 09:50 — mon arbitrage tranchait `sudo` par omission, et mon « alarme infondée » était un DÉDOUANEMENT

**Refusé par la session 3, qui a vérifié à la source au lieu de me relayer. Revérifié par moi.**

#### Le défaut vit UNE LIGNE sous ma dernière citation

    :150-:156  roleMap ferme, defaut role 1, anti-escalade   <- ce que j'ai cite : JUSTE
    :162       $sudo = (int)($data['sudo'] ?? 0);            <- AUCUNE garde
    :166       ->execute([… $roleId, $active, $sudo]);       <- ecrit tel quel

    toggle_sudo.php:26   checkAuth([ROLE_SUPERADMIN])
                  :47    refuse meme de modifier SON PROPRE sudo

**`users.sudo` est la précondition du repli `NOPASSWD: ALL` de `ssh/`.** *Un rôle 2 porteur de
`can_admin_portal` crée donc par fichier ce que le geste dédié réserve au rôle 3.* **C'est E-130, mesuré
ici le 2026-08-26.**

> **J'ai cherché l'escalade sur `role_id`, je l'ai trouvée bien gardée, et j'ai conclu sur l'objet
> ENTIER.** *C'est la classe que je démonte depuis ce matin — un énoncé vrai d'un membre appliqué à
> l'ensemble — et cette fois elle DÉDOUANE, donc rien ne l'aurait signalée.*

#### Et mes « quatre effets » étaient trois et demi, plus un cinquième que personne n'avait nommé

    j'ai ecrit   « une entree d'audit part par LIGNE »
    mesure       :120 et :181 — UNE par IMPORT, portant un COMPTE

    et le CINQUIEME :  INSERT INTO user_logs (user_id, action)
                       ni prev_hash ni self_hash  ->  les inserts sont NUS
    les chaineurs : audit_log.php · audit_seal.php · audit_verify.php

**`user_logs` porte une chaîne de hachage depuis la migration `036`.** *Chaque import ajoute donc un
orphelin à la chaîne d'audit — la classe des 1385 orphelins déjà relevés.* **Un panneau qui promettrait
une trace d'audit promettrait une trace non chaînable.**

#### Ce qui rend ma faute plus lourde que la mesure : le travail était DÉJÀ FAIT

    MODULE-ADM.md §5.0decies   D6c CARACTERISE le 2026-08-26 (v1.37.69)
                               E-129 · E-130 · E-131 · E-132 nommes
    tests/e2e/go-adm-import-csv.mjs   7 PASS / 0 FAIL sur le legacy, hors LOT
    PLAN-DE-MIGRATION.md:1648  LES TROIS DECISIONS, avec leurs issues redigees

**Et le plan écrit, sur `sudo`** : *« Retirer une colonne d'un format de fichier documenté change un
contrat : ce n'est pas à moi. »* **Une session précédente avait déjà refusé de trancher, correctement.**

> **Concevoir un panneau maintenant aurait tranché `sudo` par OMISSION** — précisément ce que le plan
> refuse de faire à la place de l'exploitant. *Et ma propre mémoire porte « lire les docs du chantier
> AVANT de replanifier », écrite après exactement cette faute.*

#### ⚠ Et une règle de mon registre vient d'être RÉFUTÉE, ce qui est la meilleure nouvelle

**J'y ai écrit** : *« la relecture par un pair attrape les fausses alarmes, JAMAIS les dédouanements — les
trois miens ont été trouvés par moi seule, en relisant du déjà-publié. »*

**Celui-ci a été trouvé par un pair, en une heure, sur du frais.** *Ce qui a changé : la session 3 a
vérifié à la source une affirmation qui l'ARRANGEAIT — je venais de lui dire que la voie était libre.*
**Un pair qui remesure ce qui le dispense de travail est le seul instrument qui attrape un
dédouanement.**

#### Ce qui SURVIT de mon arbitrage, et la session 3 le préserve

    roleMap        LISTE FERMEE, defaut role 1 — l'absence d'entree libre EST la garde
    anti-escalade  REPRISE de `add_user`, jamais reinventee
    permissions    les 15 a ZERO explicitement

**Et l'interdit d'exercice tient, renforcé** : *inutile de risquer un compte — la suite existe et passe à
7/0 sur le legacy.*

---

## Mes points aveugles, relevés et nommés — 2026-09-03 10:30

**Établi après deux dédouanements attrapés en une heure, tous deux par la session 3, et tous deux parce
qu'elle allait AGIR sur ce que je disais.** *Relevé depuis ce registre, pas récité : ce ne sont pas dix
arbitrages, ce sont **dix-huit**.*

### Le tri, par ce qui les a éprouvés

    A · EPROUVES PAR LE GESTE (8)   :2968 · :3103 · :3598 · :4063 · :4470
                                     :4804 · :4854 · :4938
        -> quelqu'un a porte dessus, donc quelqu'un les a testes.
           Deux fois sur huit, la session 3 a trouve MIEUX que mon enonce.

    B · EN ATTENTE DE GESTE (1)     :4998  la legende du menu — correctif gele

    C · RETIRE (1)                  :5260/:5275  l'import CSV

    D · AUCUN GESTE NE LES ATTEND (4)   :1628 · :3165 · :3896 · :4024

    E · RELU, ET J'AVAIS TORT (1)   :3866  « gel leve sur E-280 » — le Lead et la
                                     session 4 m'ont contredite, correctement

### ⚠ Le groupe D, et pourquoi c'est là que se cachent mes erreurs

**Trois des quatre sont des UNIVERSELLES NÉGATIVES, et toutes DISPENSENT de travail :**

    :1628  « le middleware mord SANS redemarrage, la propriete tient par un REGLAGE »
           -> ⚠ JE L'AI ETIQUETEE « Dedouanement » DANS SON TITRE, de ma propre main
    :3165  « il n'y a PAS de troisieme portage injoignable »
           -> vraie a vide si l'instrument ne voyait rien — et je sais depuis 08:51
              que `grep -r` est AVEUGLE sur les chemins ignores
    :3896  « les machines archivees dans un groupe : ce n'est PAS un ecart »
           -> si elle est fausse, il y a du portage que personne ne fait

> **Un arbitrage qui dispense de travail n'a pas de contradicteur naturel** : *celui qui en bénéficie n'a
> aucune raison de rouvrir le fichier, et celui qui l'a rendu ne se relit pas.* **C'est la forme exacte
> des deux que la session 3 vient d'attraper.**

### Le mécanisme, formulé par celle qui l'a exercé deux fois

> **« Je n'ai pas vérifié par vertu — j'ai vérifié parce que j'allais écrire du code sur cette base. Ce
> qui attrape le dédouanement n'est pas le pair, c'est le pair QUI VA AGIR DESSUS. Si tu m'avais
> seulement informée, je t'aurais crue. »**

**Conséquence opérationnelle, et elle vaut pour tout ce registre** : *un arbitrage qui ne déclenche aucun
geste ne sera jamais relu par personne.* **Il ne suffit donc pas de rendre un arbitrage juste : il faut
savoir lesquels ne seront jamais testés, et les traiter comme provisoires.**

**Les quatre du groupe D sont désormais nommés, et `:3896` et `:3165` sont envoyés à la session 3 avec
consigne d'essayer de les CASSER — pas de les valider.** *Elle a posé sa propre réserve, qui est juste :
« je ne serai un bon contradicteur que sur ce que je dois porter ; sur le reste je lirai comme quelqu'un
qui n'agit pas, donc mal, et tu ne dois pas compter mon accord comme une relecture. »*

### Et le modèle de l'épreuve, qu'elle a produit sur son propre travail

**Ses trois « non appelées » étaient de la même classe — des négatives dans un document que personne ne
porte. Elle les a rouvertes :**

    litteral direct   /approvals/stats 0 · /services/logs 0 · /services/status 0
    temoin POSITIF    /services/list 4 · /graylog/templates/ 2 · /approvals/ 5
    temoin NEGATIF    /zzz/inexistant 0
    backend           les TROIS existent bien — 1 route chacune      <- LE RELEVE QUI COMPTE

> **Sans le dernier, « non appelée » aurait été vrai et CREUX — et il aurait rempli une case du tableau
> exactement comme un vrai résultat.** *C'est la meilleure application de « une universelle négative est
> vraie à vide » que ce chantier ait produite, et elle porte sur son propre travail.*

---

## ⛔ RECTIFICATION 10:45 — `:3896` est CASSÉ, sur mon propre critère laissé inappliqué

**Cassé par la session 3, à qui j'avais demandé d'essayer. Chaîne revérifiée par moi, site par site.**

### Mon critère était juste, et je ne l'ai pas appliqué au geste

> **Ce que j'avais écrit** : *« Exclure les archivées est juste pour un GESTE, faux pour une SÉLECTION. »*
> *« Où l'exclusion existe légitimement : `scheduler.py`, `ssh_audit` — tous des chemins qui AGISSENT sur
> le parc. »*

**Le module `groups` offre un GESTE, et je ne l'ai pas examiné.**

    groupes.js:521   ecris('/groups/' + id + '/run', { action: 'drift_scan' })
    groups.py:286    @bp.route('/groups/<int:group_id>/run', POST) @threaded_route
             :38     _BULK_ACTIONS = {'drift_scan', 'cve_scan'}

    _member_ids:85   "SELECT machine_id FROM machine_group_members WHERE group_id = %s"
                     <- SELECT NU, aucun filtre de cycle de vie
    _run_bulk        drift_scan -> scan_machine(mid)
                     cve_scan   -> « Reutilise tout le pipeline CVE
                                     (SSH + enrichissement + persistance) »

**Énumération, pas motif** : `lifecycle_status` apparaît **exactement deux fois** dans `groups.py` —
`:36` comme **valeur de filtre autorisée** (donc `archived` est un filtre LÉGAL), `:247` dans un `SELECT`
qui **rend** la colonne. **Aucune clause d'exclusion.**

**Et la convention est établie SEPT fois ailleurs, pas quatre comme je l'avais citée :**

    scheduler.py   274 · 279 · 292 · 299 · 457-458
    ssh_audit.py   254 · 301

### ⚠ Le défaut s'ARME PAR LE TEMPS, et c'est ce qui le rend invisible

**`machine_group_members` est une table d'appartenance STATIQUE.** *Une machine ajoutée à un groupe
aujourd'hui y reste quand elle passe `archived` le mois prochain.*

> **Construire le groupe pendant que tout est actif, archiver une machine ensuite, lancer le groupe — et
> une session SSH s'ouvre sur une machine décommissionnée.** *Personne n'a rien fait de mal, et rien dans
> la chaîne ne le remarque.*

### ⚠⚠ ET MA MESURE A ÉTÉ PRISE À VIDE — je l'ai citée comme élément RASSURANT

    ce que j'avais releve : « machines archivees en base -> 0 (les trois sont `active`) »

> **Avec zéro machine archivée, aucune observation ne distingue « correctement traité » de « pas traité du
> tout ».** *La mesure ne rendait pas la propriété vraie : elle la rendait INOBSERVABLE — et elle figurait
> au dossier du bon côté.*

**C'est la forme que la session 3 venait d'éprouver sur ses trois « non appelées », dans l'autre sens** :
*elle a pu montrer que les trois routes EXISTAIENT côté backend, donc que son négatif mesurait quelque
chose.* **Mon zéro n'avait pas ce témoin, et je ne l'ai pas cherché.**

### La portée réécrite

> **La SÉLECTION n'est pas un défaut et ne se corrige pas.** *Le GESTE `/groups/<id>/run` en est un : il
> agit sur le parc sans exclure les archivées, contrairement aux SEPT autres chemins agissants du dépôt.*

**La session 6 avait tort sur la prémisse et raison de trouver quelque chose.** *J'ai fermé la question au
lieu de déplacer sa portée.*

> **« Ce n'est pas un défaut, et ça ne se corrige pas » est la phrase qui a dispensé tout le monde de
> regarder le geste.** *C'est ma forme la plus coûteuse : pas une erreur de mesure, une FERMETURE DE
> QUESTION.*

### Ce qui n'est PAS établi, et la session 3 le dit plutôt que de l'arrondir

    ETABLI par enumeration   la chaine /run ne porte aucun filtre de cycle de vie
    ETABLI par enumeration   sept autres chemins agissants excluent, eux
    NON ETABLI               s'il existe une machine archivee AUJOURD'HUI
                             -> `docker` refuse l'acces, la base n'est pas relevee
    NON ETABLI               qu'une session SSH s'ouvre reellement
                             -> il faudrait LANCER le geste, et le scan CVE de masse
                                est reserve a l'exploitant

**Le défaut de CODE est établi ; son caractère ACTIF aujourd'hui ne l'est pas.**

---

## ⛔ RECTIFICATION 11:00 — `:3165` est CASSÉ : il y a bien un TROISIÈME portage injoignable

**Cassé par la session 3, à qui j'avais demandé d'essayer. Vérifié par moi.**

    web.php:578   GET  /notifications/preferences -> NotificationsController::reglages
                  middleware ['role:3', 'perm:can_admin_portal']
                  name('notifications.reglages')
    Controller:134  return view('notifications-reglages', [ … ])   <- c'est bien UNE PAGE
    web.php:580   POST meme chemin -> notifications.preferences.poser

    citations du NOM de route, par `glob`+`io.open` (insensible a .gitignore) :
      laravel/routes/web.php    <- SA PROPRE DECLARATION
      total = 1

    citations du CHEMIN hors web.php :
      notifications-reglages.js:40   fetch('/notifications/preferences'…)
      <- la page vers SON PROPRE POST

    Navigation : 0

**Une page complète, gardée, portée — et rien n'y mène.**

### Pourquoi je l'ai manquée : j'ai énuméré par MODULE, elle a énuméré par ROUTE

    mon releve   notifications   nav=0  vues=2  js=2   -> « clearee »
    la realite   `notifications`           role:1, liee depuis le SOCLE (portail:68)
                 `notifications.reglages`  role:3, liee de NULLE PART

> **Mon compte `vues=2` mesurait les liens vers la page VOISINE.** *Un module peut être atteignable
> pendant qu'une de ses pages ne l'est pas — et le préfixe partagé rend la confusion invisible : les deux
> s'appellent « notifications ».*

**Encore une propriété vraie d'un objet, attribuée à un autre.** *C'est la classe de toute la matinée, et
c'est la quatrième fois.*

**Second facteur d'invisibilité** : *la page est `role:3` **et** `can_admin_portal`.* **Seul un
superadministrateur pourrait la voir — donc personne ne s'est jamais étonné de ne pas la trouver.**

### ⚠ Et sa méthode alarme là où la mienne dédouanait — elle le dit avant qu'on le trouve

    la mienne   6 candidates, avec des FAUX NEGATIFS
    la sienne   13 candidates, dont 8 FAUX POSITIFS (cibles de `fetch`, redirections)

> **Aucun des deux n'est bon seul.** *Il a fallu une étape qui n'est dans aucune de nos deux méthodes
> d'origine : **discriminer page / point-d'appel par la présence d'une VUE**.*

### ✅ ARBITRAGE — un lien contextuel sur `notifications`, conditionné au rôle 3

**Le précédent existe et il est exact** — `cles-api`, `role:3` + `perm:can_manage_api_keys`, liée depuis
`comptes.blade.php:15-19` :

    @if ((int) session('role_id', 0) >= 3)
        <a data-rw="comptes-lien-cles-api" href="{{ route('cles-api') }}">…</a>
    @endif

    et son commentaire porte deja ma convention :
    « Reservee au role 3 : l'afficher plus bas menerait a un 403. »

**Décision : le même patron, sur la page `notifications`.** *`data-rw`, i18n FR/EN dans le même commit,
et la condition `role_id >= 3`.*

**Et la condition sur le seul rôle est EXACTE, mesuré** :

    ExigePermission.php:35-36   if ($roleId >= 3) { return $suite($requete); }

*Un rôle 3 franchit donc toujours `perm:can_admin_portal` — **aucun trou entre ce que le lien montre et
ce que la garde accepte**.* **Les deux couches s'accordent ici, ce qui est rare dans ce dépôt : le
portage court-circuite au rôle 3 comme `helpers.py` le fait côté backend.**

**Pas une entrée de menu** : *le précédent `cles-api` a choisi le lien contextuel, et le même raisonnement
vaut — une page de réglages n'est pas une destination de navigation.*

### Ce que ça dit de mes deux « questions closes »

**J'ai demandé qu'on casse deux de mes quatre points aveugles. Les DEUX sont tombés en deux heures.**

    :3896   casse — le GESTE de groupe n'excluait pas les archivees
    :3165   casse — un troisieme portage injoignable existe

> **Deux universelles négatives, toutes deux fausses, toutes deux dispensant de travail, et aucune n'avait
> jamais été relue.** *Le taux est de 2 sur 2 — ce qui ne se conclut pas sur deux essais, mais qui ne
> laisse pas non plus supposer que les deux restantes tiennent.*

**`:1628` est en cours d'épreuve, avec la réserve de son autrice : elle ne touche pas son portage, donc
elle la lira en lectrice, et elle dira « je ne peux pas conclure » plutôt que « elle tient ».**
