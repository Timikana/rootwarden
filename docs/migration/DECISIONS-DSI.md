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
