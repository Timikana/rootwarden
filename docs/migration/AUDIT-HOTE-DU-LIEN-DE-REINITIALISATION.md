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
