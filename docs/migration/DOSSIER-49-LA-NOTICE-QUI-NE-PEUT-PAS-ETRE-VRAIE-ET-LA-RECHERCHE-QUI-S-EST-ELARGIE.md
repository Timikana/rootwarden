# DOSSIER-49 — Une notice qui ne peut pas être écrite vraie, et une recherche que le portage a élargie

**Écrit le 2026-09-08, vers 04:5x. Deux refus de pairs, tous deux fondés, et deux
décisions qui appartiennent à l'exploitant.**

> ⚠ **Ce dossier corrige la dernière phrase de `E-476`**, écrite trente minutes plus tôt :
> *« Rien de neuf n'attend l'exploitant au-delà des trois actes déjà écrits. »* **C'est
> faux.** Deux décisions neuves attendent, et elles sont sorties de deux capacités que
> j'avais assignées en croyant les avoir instruites.

---

## ① LA NOTICE DE CONFIDENTIALITÉ — LA PAGE EST UNE OBLIGATION, SON CONTENU NE L'EST PAS

J'ai assigné « une page de politique de confidentialité » en écrivant : *« Je n'ai pas
d'avis produit à rendre ici : une notice de confidentialité est une obligation, pas un
arbitrage. »*

**La réponse a coupé la phrase en deux, et elle a raison :**

> *La page l'est ; son CONTENU ne l'est pas — il énonce des faits sur un traitement, et
> ces faits doivent exister avant d'être écrits.*

Et elle a retourné mon propre principe contre mon cadrage. J'avais retiré le lien mort
parce qu'« un lien légal qui mène ailleurs atteste une conformité qui n'est pas là » :

> **Une notice dont le contenu est inventé est exactement ce défaut, un cran plus bas —
> elle ne mène pas vers du faux, elle ÉNONCE du faux.**

*Je maintenais que le contenu suivrait la page. Il ne peut pas : deux de ses rubriques
obligatoires n'ont aucune valeur à énoncer.*

### 🔴 A. LES DURÉES DE CONSERVATION N'EXISTENT PAS

**Mesuré séparément, avec témoin** (`grep -c 'DELETE FROM' backend/` = **30**, donc la
sonde lit) :

```
login_history      purge : 0
login_attempts     purge : 0
fail2ban_history   purge : 0
command_log        purge : 0
active_sessions    purge : 1
```

**Quatre tables nominatives sur cinq n'ont aucune purge.** Les seuls mécanismes de
rétention du dépôt portent sur les tâches, les demandes d'approbation, les notifications
(90 j) et le **cache** GeoIP — jamais sur les données nominatives.

*Une notice honnête devrait donc écrire « conservées sans limite déclarée ». Ce n'est pas
une notice : c'est un constat de non-conformité rédigé à la place de l'exploitant.*

### 🔴 B. UN TRANSFERT VERS UN TIERS, ET IL PORTE DES DONNÉES DE NON-UTILISATEURS

```
backend/fail2ban_manager.py:413   http://ip-api.com/json/{ip}    HTTP, pas HTTPS
backend/config.py:158             GEOIP_ENABLED  defaut 'true'
srv-docker.env.example:520        GEOIP_ENABLED=true
```

`fail2ban_history.ip_address` porte des adresses de **tiers** — des personnes qui ne sont
pas utilisatrices du produit et n'ont rien consenti. Une notice doit nommer ce transfert,
son destinataire et sa base légale. **Aucun des trois n'est décidé.**

### ⚠ ET J'AI FAILLI AJOUTER UNE TROISIÈME ALARME, FAUSSE

J'ai cru trouver un **second** chemin sortant, dans le navigateur :

```
laravel/public/js/fail2ban.js:1067   http://ip-api.com/json/<ip>
```

**C'est un commentaire.**

```
« ip-api » dans le FICHIER          3
« ip-api » dans le CODE depouille   0
```

Le chemin navigateur passe par `litDistant('/fail2ban/geoip')` et respecte
`reglages.geoip_enabled === false`. *L'interrupteur gouverne bien les deux.* **Cinquième
fois de la session que ma prose — ici celle d'un pair, dans un docblock qui documentait
honnêtement le risque — a satisfait le motif que je vérifiais.** Et cette fois j'allais la
publier comme une trouvaille que ni l'un ni l'autre des deux pairs n'avait faite : *la
forme la plus dangereuse d'un faux positif est celle qui vous distingue.*

### ✅ CE QUI EST DÉCIDÉ, ET CE QUI ATTEND

**Décidé** — la page n'est pas écrite avant ses faits. *L'ordre était inversé dans mon
assignation.* Le relevé mesuré du traitement (tables, colonnes, transferts sortants,
purges existantes et manquantes) est **accepté et commandé** : il va dans `docs/`, et la
page s'écrira depuis lui.

**⛔ ATTEND L'EXPLOITANT — deux décisions, ni techniques ni délégables :**

```
1  LES DUREES DE CONSERVATION des cinq tables nominatives.
   Ce n'est pas « combien de temps le code garde » : c'est combien de temps
   l'entreprise DECIDE de garder. Aucun defaut technique ne peut la tenir.

2  LE SORT DU TRANSFERT VERS ip-api.com.
   Trois issues, et elles ne s'equivalent pas :
     - eteindre GEOIP_ENABLED par defaut       le transfert cesse
     - le declarer dans la notice              il faut une base legale
     - le passer en HTTPS et le declarer       reduit l'interception,
                                               pas la communication
   ⚠ Le defaut est aujourd'hui `true` : le transfert a lieu sauf action.
```

*La seconde n'est pas un choix de configuration : communiquer l'adresse d'un tiers à un
service extérieur est un traitement, et il lui faut un fondement avant un interrupteur.*

---

## ② LA RECHERCHE GLOBALE — L'ENDPOINT EXISTAIT, ET LE PORTAGE A ÉLARGI CE QU'IL REND

J'avais conclu « aucun endpoint JSON porté » après avoir mesuré
`RechercheController.php:28 → view('recherche', …)`. **La conclusion était tirée d'un seul
chemin.** L'endpoint existe, par la passerelle :

```
laravel/public/js/recherche.js:161   -> GET /api/gateway/search
RoutesBackend.php:120                '/search' en LISTE BLANCHE
backend/routes/search.py:26          GET /search -> JSON
```

**Et le contrat que j'ai demandé était celui de l'endpoint archivé** — `{results: [...]}`
à plat, la forme du **consommateur disparu**, pas du **producteur vivant**, qui rend
`{success, query, total, results: {machines, users, cves, tickets, audit}}`. *Je l'avais
lu dans le JS du legacy et transmis comme une spécification.* **« Porter n'est pas
reproduire » — et j'ai fait porter la forme du mort.**

### 🔴 CE QUE NI L'UN NI L'AUTRE N'AVAIT DIT : LA SURFACE A GRANDI AU PORTAGE

L'endpoint archivé, restitué depuis `de9669c3^` (61 lignes, témoin de restitution) :

```
LEGACY   « Cherche dans : serveurs (name, ip), utilisateurs (name, email), CVE (cve_id) »
         garde : checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])
         3 categories

PORTAGE  machines · users · cves · tickets · AUDIT (user_logs)
         garde : @require_role(2) + @require_permission('can_admin_portal')
         5 categories
```

**La garde est plus forte sur le papier — une permission en plus — et la surface a gagné
deux catégories, dont le journal d'audit.** *Le portage n'a pas affaibli un garde : il a
élargi ce que ce garde révèle.* C'est l'espèce que le critère « la garde est-elle assez
forte ? » ne voit pas, parce que la réponse est *oui* et que la question était fausse.

**Et `/search` est la SEULE route du backend qui lise `user_logs`** — il n'y a pas de
jumelle plus stricte à qui la comparer ; `can_view_compliance` garde le drift, pas le
journal.

### ✅ CE QUE JE TRANCHE

**`audit` quitte la surface de recherche.** Le journal d'audit est le registre qu'on lit
pour détecter l'abus d'un administrateur : le rendre lisible sous la permission qui **est**
l'administration du portail ne laisse aucune séparation. **Le legacy ne l'exposait pas là.**

> **Retirer `audit` de `/search` n'est pas une restriction nouvelle : c'est le retour à
> l'iso-legacy.** *C'est ce qui rend la décision sûre — elle ne peut pas donner un faux
> sentiment de cloisonnement, puisqu'elle ne prétend pas cloisonner : elle retire.*

**`tickets` reste**, et la raison n'est pas la même : un ticket est un objet de travail
partagé, pas un registre de surveillance. *Son ajout est une amélioration du portage, et
elle tient.*

⚠ **Cette décision vit dans `backend/routes/search.py`**, hors de mon périmètre d'écriture
et hors de celui du pair qui l'a soulevée. **Elle est tranchée, pas ouverte** : il lui
manque un exécutant, pas un arbitre.

**Approuvé et commandé** — le panneau de recherche dans le menu du portage, **sur
l'endpoint existant**, sans second chemin. C'était la capacité réellement perdue : le
legacy avait un panneau, le portage n'a qu'une page.

**⛔ REFUSÉ pour l'instant** — faire passer la recherche par le portage et retirer
`/search` de la liste blanche. *C'est la seule façon de rendre un filtre côté portage
incontournable, et c'est exact. Mais elle touche un fichier partagé et casse
`recherche.js` tant que le relais serveur n'existe pas.* **Le cloisonnement fin appartient
au backend, là où la requête se résout — pas à un second garde posé plus haut.**

---

## CE QUE CE DOSSIER APPREND SUR MA FAÇON D'ASSIGNER

Les deux capacités que j'ai distribuées au tour précédent étaient **mal instruites**, et
des deux façons opposées :

```
la notice     j'ai commande la PAGE en croyant que son contenu suivrait
la recherche  j'ai commande un ENDPOINT qui existait, au contrat du mort
```

*Dans les deux cas j'avais mesuré — et dans les deux cas la mesure s'arrêtait au premier
chemin qui confirmait.* **Les deux refus valent plus que les deux livraisons que
j'attendais**, et aucun des deux ne serait venu d'une session qui aurait dit oui.

> **Une assignation précise n'est pas une assignation instruite.** *La mienne nommait une
> capacité, une mesure et trois pièges — et se trompait quand même sur ce qui existait.*
