# Décisions du DSI délégué — session 8

**Ouvert le 2026-08-28.** Charte au **§7.0 de `PLAN-DE-MIGRATION.md`**. Ce document porte les
**sept arbitrages délégués**, tranchés. Les huit qui ne peuvent pas l'être vivent dans les
`DOSSIER-*.md`, une page chacun.

> **La ligne de la charte :** *ce qui se défait d'un clic est délégué ; ce qui détruit, retire un accès
> ou publie ne l'est pas.* Aucune décision de ce document n'écrit sur une machine, ne redémarre un
> service, n'applique une migration, ne pousse ni ne fusionne.

**Toutes les mesures de ce document datent du 2026-08-28, entre 06:40 et 06:55 UTC** (08:40–08:55
CEST). Chacune porte sa commande de remesure. *Une conclusion écrite sur un état mutable se périme
sans prévenir* — et deux des mesures ci-dessous ont déjà retourné une prémisse écrite la veille.

---

## Table des sept

| # | arbitrage | décision | ce qu'elle coûte |
|---|---|---|---|
| 1 | portée du tableau de bord | **bornée au périmètre** | `opsuser` voit 1 machine au lieu de 3 |
| 2 | E-221 — accorder les 4 permissions | **n'en accorder AUCUNE** — la prémisse est fausse | rien ; et une fixture est sauvée |
| 3 | E-209 · E-212 · E-219 — textes faux | **corriger, et E-219 avec son remplacement** | trois chaînes × deux langues, plus une docstring |
| 4 | E-225 — dépôt tiers laissé par la désinstallation | **le DIRE** (issue 1), ne pas le retirer | une phrase dans la réponse |
| 5 | E-208 — les 3 pages qui ne bornent pas | **borner dans le PORTAGE, ne pas toucher le legacy** | rien : zéro porteur mesuré |
| 6 | E-224 — borne d'`install_all` | **`machine_ids` obligatoire**, 400 si absent ou vide | le bouton « installer sur tous » envoie sa liste |
| 7 | E-222 — `UNIQUE (server_id)` | **écrire la migration**, ne pas l'appliquer | `DOSSIER-06` pour la signature |

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

### La décision, en une ligne

> **Aucune permission n'est accordée. Le durcissement ne retire aucun accès d'interface : les pages
> portent déjà la garde que les routes s'apprêtent à porter.** La tâche de configuration « à faire
> avant, pas après » n'a pas d'objet — *et le geste qu'elle appelait le plus naturellement,
> `can_manage_iptables` à `rw-test-admin`, aurait détruit la seule fixture de garde du parc.*

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
divergence. Une seule implémentation, et le texte de la réponse en dérive au lieu d'être recopié.

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

## Ce que ces sept décisions ne font pas

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
