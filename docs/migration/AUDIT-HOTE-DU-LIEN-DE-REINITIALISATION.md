# AUDIT — l'hôte du lien de réinitialisation est fourni par le demandeur

    Session   5 — securite, LECTURE SEULE.
    Mesure    2026-09-08. AUCUN formulaire soumis, aucun courriel emis.
    Verdict   VULNERABILITE CONFIRMEE · le compte d'UN flux CONFIRME
              · une correction d'ORDRE proposee qui supprime le risque d'ordre

---

## 1. Confirmée, et sur trois points indépendants

```
TrustHosts · trustedHosts · forceRootUrl · URL::force   ->  0 occurrence
  TEMOIN+ : bootstrap/app.php declare bien d'autres middlewares (:35 web append,
            :56 validateCsrfTokens, :60 alias) — la sonde n'est pas aveugle

apache-ssl.conf.tmpl:23  <VirtualHost *:80>    ServerName ${SERVER_NAME}
                    :53  <VirtualHost *:443>   ServerName ${SERVER_NAME}
  -> un `*:443` UNIQUE est le vhost PAR DEFAUT : tout `Host:` est servi.
     Aucun rejet, aucun `ServerAlias` restrictif.

SERVER_NAME=localhost        hotes declares : localhost · 192.168.0.245
```

**`route()` en contexte de requête bâtit sur l'hôte de la requête. Le lien de
réinitialisation part donc sur un hôte que le DEMANDEUR choisit, vers une boîte
que la VICTIME possède, jeton compris.**

*Latent tant que `mail.default` vaut `log`. **C'est une configuration, pas une
propriété** — et la phrase déjà inscrite dans ce fichier pour un autre défaut du
même flux s'applique une seconde fois : « il devient vivant le jour où un
transport RÉSEAU est configuré ».*

---

## 2. « J'en ai mesuré UN — ne me crois pas sur ce 1 » — CONFIRMÉ, autre axe

**Je n'ai pas cherché les liens : j'ai cherché les ENVOIS, puis regardé ce que
chacun compose.**

```
laravel/app : Mail:: · Notification:: · Http::post · Http::get
  -> 2 lignes, TOUTES DEUX dans Auth/ReinitialisationController (:39 commentaire, :219 l'envoi)

backend : webhooks.py · mail_utils.py
  -> le seul lien compose est https://www.cve.org/CVERecord?id=…   FIXE, externe
  -> aucun lien vers le portail, et aucun contexte de requete (ordonnanceur)
```

> **Un seul flux au monde compose un lien destiné à sortir, et c'est celui-là.**
> *Le compte tient. Et il tiendra mal : le jour où une notification portera un
> lien « voir dans le portail », elle héritera du même défaut sans qu'on y pense.*

---

## 3. ⚠ UN FAIT QUI M'A PRESQUE FAIT PUBLIER UNE FAUSSE ALARME

**J'allais signaler `LARAVEL_URL=https://192.168.0.245:8443` comme pointant vers
le LEGACY.** *C'est faux — et l'erreur venait de MA note, pas du dépôt.*

```
docker-compose.yml:18  « Le legacy les reprend, le portage passe sur 8080/8443 »
                 :81  « Le PORTAGE prend les ports du portail historique (8080/8443) »
```

**Les ports ont été échangés. `8443` est le PORTAGE.** *Ma fiche disait l'inverse,
et elle avait raison quand elle a été écrite.*

> ⛔ **Quiconque raisonne sur ces URL de mémoire commettra cette erreur — et elle
> porte directement sur l'ORDRE des correctifs proposés.** *« `APP_URL` pointe
> vers le legacy en clair » est un argument dont la vérité dépend d'un échange de
> ports que personne n'a en tête.*

**⛔ ET JE NE PEUX PAS VÉRIFIER `APP_URL` :** `laravel/.env` m'est refusé en
lecture (*permission denied*). **La valeur qui fonde l'ordre « 1 avant 0 » n'est
donc pas contrôlée par moi.**

---

## 4. Les trois questions posées

### 4.1 Quels motifs `TrustHosts` sont légitimes ?

**Le mécanisme est bon — il échoue en FERMETURE.** *Mais il exige d'énumérer
CHAQUE chemin d'accès légitime, et le dépôt n'en déclare que deux :*

```
localhost          (SERVER_NAME)
192.168.0.245      (LARAVEL_URL)
```

**Le portail est joint par IP ET par nom, depuis plusieurs réseaux. Personne ne
peut compléter cette liste ce soir sans se tromper — et une liste incomplète
COUPE un accès réel.**

### 4.2 Apache plutôt que le middleware ?

**Non, et pour la même raison, en pire.** *Un rejet Apache couvre tous les
chemins — c'est son avantage — mais il partage le problème d'énumération avec un
rayon d'action bien plus large : une adresse oubliée ne casse pas le courriel,
elle casse le PORTAIL.*

### 4.3 D'autres flux ? — §2. Un seul, confirmé.

---

## 5. ⚠ CE QUE JE PROPOSE : supprimer le risque d'ORDRE au lieu de l'ordonner

**L'ordre « 1 avant 0 » existe parce que le correctif 0 lirait `config('app.url')`
— une valeur dont on sait qu'elle est fausse.**

> **Ne pas la lire supprime la dépendance.**

    forcer la racine SUR LE CHEMIN DU COURRIEL, depuis une valeur
    VERIFIEE au moment de poser le correctif — pas depuis `config('app.url')`
    lue en aveugle.

**Ce que ça donne :**

- **échoue du bon côté** : le lien part toujours sur l'hôte de l'exploitant,
  quel que soit le `Host:` reçu ;
- **n'exige AUCUNE énumération** : un seul hôte à connaître, celui qu'on écrit ;
- **rayon d'action minimal** : le courriel seul. Aucun autre chemin ne change ;
- **et l'ordre disparaît** : il n'y a plus de « 1 avant 0 », il y a UN geste.

**`TrustHosts` reste souhaitable ENSUITE, en défense en profondeur — quand
quelqu'un pourra énumérer les hôtes sans deviner.** *Le poser d'abord, c'est
échanger une vulnérabilité latente contre une panne d'accès certaine.*

---

## 6. Bornes

    NON SOUMIS   aucun formulaire, aucun courriel emis. La demonstration de ce
                 defaut EST le defaut : elle enverrait un lien pieges a une
                 personne reelle. Je ne l'ai pas faite et je ne la ferai pas.
    NON LU       `laravel/.env` — permission refusee. `APP_URL` non verifie.
    NON MESURE   si un compte reel a emprunte ce chemin : rien ne le
                 distinguerait d'une demande de reinitialisation ordinaire.

---

## 7. « "Ne pas envoyer" crée-t-il un oracle ? » — NON, et il RÉDUIT celui qui existe

**Question posée avant d'écrire le correctif. Réponse structurelle ci-dessous ;
elle n'est PAS une mesure, et je dis à la fin ce qu'il faut mesurer.**

### 7.1 La structure des deux branches

```
adresse INCONNUE   brule()  =  1 × password_hash(BCRYPT, cout)
adresse CONNUE     emet()   =  1 × password_hash(BCRYPT, MEME cout)
                              + DB::transaction( UPDATE … ; INSERT … )
                   puis, dans terminating() : l'envoi
```

**Le terme dominant — bcrypt — est présent des DEUX côtés au MÊME coût. C'est
l'égalisation, et elle est bien faite.**

### 7.2 Pourquoi il n'y a pas d'inversion — l'hypothèse que j'ai testée d'abord

**J'ai d'abord soupçonné le contraire** : *un égalisateur calibré contre un coût
devient un DISCRIMINATEUR quand l'autre côté s'allège.* **Si la branche connue
perd le rendu du courriel, pourrait-elle passer SOUS la branche inconnue ?**

> **Non, et c'est structurel :** `brule()` = 1 bcrypt · `emet()` = 1 bcrypt **+**
> une transaction. **La branche connue est supérieure ou égale, quoi qu'on fasse
> en aval.** *L'inversion est inexprimable — pas seulement improbable.*

*Je le note parce que l'hypothèse était raisonnable et qu'elle est fausse : je
l'ai vérifiée avant de la transmettre.*

### 7.3 Et l'écart DIMINUE

**L'envoi vit dans `terminating()` — APRÈS la composition de la réponse.** *Sous
un SAPI qui termine la requête, il est invisible ; sous `mod_php`, il tombe dans
la fenêtre de connexion (DOSSIER-24).*

    aujourd'hui   Mail::raw -> rendu du gabarit + ecriture par le transport `log`
    apres         Log::warning -> une ligne, aucun gabarit

**Moins de travail post-réponse sur la seule branche qui en portait. L'écart
rétrécit.**

### 7.4 ⚠ Trois conditions, et la troisième est la vraie

1. **La réponse au demandeur ne change pas** — *`back()->with('succes', …)` dans
   les deux cas.* **C'est là que vit la propriété anti-énumération, pas dans le
   chronomètre.**
2. **Le journal ne doit pas être plus bavard sur la branche connue que le
   courriel ne l'était** — *une ligne, pas un dump du jeu de données.*
3. ⛔ **Ce raisonnement est STRUCTUREL, pas mesuré.** *Je ne prends jamais le
   banc, et je n'ai pas chronométré ces 2,4 ms.*

**Ce qu'il faut mesurer, et c'est court** : *le résidu APRÈS correctif, sur les
deux branches, avec le même instrument qui a produit le 2,4 ms — et la comparer à
lui.* **Attendu : plus petit. Si c'est plus grand, la cause est le journal, pas
la structure.**

> **L'exigence « l'écart est MESURÉ, pas supposé » est la bonne, et cette section
> n'y répond pas : elle établit qu'aucune inversion n'est POSSIBLE, ce qui borne
> le risque sans le chiffrer.**
