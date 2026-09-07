# SPEC DE MESURE — Q2 : « aucune requête n'est émise avant consentement »

    Session   5 — sécurité. CONCEPTION DE TÉMOIN, pas portage.
    Objet     prouver la propriété qui empêche le geste irréversible,
              SANS jamais l'émettre.
    Statut    spécification. Aucun code écrit, aucun geste exercé.

> **Q2 est la seule des quatre propriétés qui empêche de couper RootWarden d'une
> machine. Et elle a une élégance rare : elle se prouve par une ABSENCE.**
> *C'est aussi ce qui la rend facile à mesurer faussement — une absence est ce
> que rend un instrument cassé.*

---

## 1. La propriété, énoncée sans ambiguïté

**Un jeu de règles qui ne contient pas d'`ACCEPT` sur le port SSH **de cette
machine** est refusé AVANT l'envoi, et la raison est nommée.**

Trois observables, et ils ne se remplacent pas :

    O1  aucune requête ne part vers le point d'application
    O2  un refus est ANNONCE a l'ecran
    O3  le refus NOMME sa raison (le port manquant), pas « erreur »

*O1 sans O2 est un échec silencieux — l'utilisateur reclique.* **O2 sans O1 est
un mensonge : l'écran dit « refusé » et la machine a reçu les règles.**

---

## 2. ⛔ Les quatre pièges, mesurés dans ce dépôt

### 2.1 Le filtre réseau ne peut PAS porter sur `iptables`

**La page émet DÉJÀ du trafic légitime vers ce préfixe** — `pare-feu.js:710`
appelle `/iptables-validate` (sous-lot I4, porté).

```
filtre "iptables"          -> attrape la validation LEGITIME de I4  -> faux ECHEC
filtre "/iptables-"        -> idem (c'est une entree a PREFIXE, RoutesBackend:114)
filtre sur l'URL RESOLUE   -> seul correct
                              …/api/gateway/iptables-apply
                              …/api/gateway/iptables-restore
```

> ⚠ **Un faux échec est plus dangereux qu'un faux succès ici** : *on ajuste le
> filtre jusqu'à ce que la suite passe, et on finit avec un filtre qui ne
> capture plus rien.* **Le filtre se fixe AVANT, sur la liste exacte des points
> d'application, et il ne se retouche pas pour faire verdir.**

*Le legacy compose (`${window.API_URL}/iptables-apply`) — sans effet ici :
`page.on('request')` voit l'URL RÉSOLUE, pas sa forme source.*

### 2.2 La requête doit être FORGÉE — sinon on mesure le garde du navigateur

**Déclencher par l'interface mesure le garde client, qu'on sait faible** (E-249 :
un `minlength` refuse la soumission avant l'envoi, l'URL ne bouge pas, et
l'assertion est verte sans rien mesurer).

    forger depuis la page (page.evaluate), avec un corps SANS ACCEPT
    -> ce qui doit tenir est le garde qui precede l'emission, pas le `disabled`

**Un `disabled` sur le bouton ne prouve rien : une requête forgée le contourne.**

### 2.3 ⚠ LE TÉMOIN POSITIF — sans lui la mesure est vraie à vide

> **« Aucune requête ne part » et « mon instrument ne voit aucune requête » sont
> la MÊME SORTIE.**

    sonde   jeu SANS ACCEPT sur le port   -> attendu 0 requete
    TEMOIN  jeu AVEC ACCEPT sur le port   -> attendu >= 1 requete VUE

**⛔ Zéro sur la sonde ET zéro sur le témoin = la mesure n'a pas eu lieu.** *Le
verdict doit être NON CONCLUANT, jamais PASS.*

⚠ **Et le témoin pose un problème que la spec doit trancher, pas contourner** :
*un jeu valide DOIT partir — donc il atteindrait une machine.* **Le témoin se
mesure sur une cible dont la réponse est SERVIE par la suite** (régime F5 : le
chemin de rendu s'exécute en entier, aucune machine n'est jointe). **Ce qu'on
observe est que la requête EST ÉMISE, pas ce qu'elle produit.**

### 2.4 Le port ne se code pas en dur — et le piège est déjà écrit

**Les trois machines du parc écoutent sur 22.** *Une sonde qui écrit `22` mesure
son presse-papier : elle passerait au vert même si le gabarit ignorait la base.*

    lire le port en base pour la machine choisie   -> P
    construire le jeu SANS ACCEPT sur P            -> doit etre REFUSE
    construire le jeu AVEC ACCEPT sur P            -> doit PARTIR (temoin)

**Contre-épreuve qui qualifie la sonde** : *un jeu avec `ACCEPT` sur un port
**autre** que P doit être REFUSÉ.* **Sans elle, un gabarit qui accepte n'importe
quel `ACCEPT` passerait les deux premiers cas.**

---

## 3. Deux points que la mesure doit observer et qu'on oublie

### 3.1 La fenêtre temporelle — asserter trop tôt garantit le PASS

**« Aucune requête » est vrai à l'instant 0 de toute page.** *Une émission
asynchrone part après.*

**L'assertion doit être ancrée sur un signal POSITIF** : attendre que le refus
soit ANNONCÉ (O2), puis asserter O1. *À défaut, une attente bornée — mais un
signal vaut mieux qu'un délai.*

### 3.2 Le refus doit s'annoncer où l'écran ÉCOUTE

**`showNotification` du legacy vise `#notifications` : 13 points d'appel,
ZÉRO occurrence de la cible dans `legacy/iptables/index.php`** (mesuré). *Les
treize lèvent une `TypeError`, y compris ceux placés dans un `catch`.*

**Le portage a ses propres régions persistantes**, avec des ancres stables :

```
pare-feu.blade.php:84   data-rw="ipt-annonce"
                 :127   data-rw="ipt-copie-annonce"
                 :157   data-rw="ipt-valid-annonce"
```

⚠ **L'assertion O3 porte sur une ANCRE ou une clé, jamais sur le texte rendu** :
*les libellés existent en `fr` et `en`, et une assertion sur la phrase casse au
premier changement de langue du banc.*

---

## 4. ⛔ La cible — et le faux ami qui produit un faux PASS

    Test-Server-Debian (id 2)   CONTENEUR, sans systemd, reseau Docker
                                -> y appliquer des regles n'est pas « sans danger » :
                                   c'est SANS SIGNIFICATION
    srv-zabbix (id 1)           PRODUCTION — jamais, sous aucun regime

> **Un test qui passe parce que la cible ne peut rien produire est un FAUX PASS.**
> *Il ne mesure pas le refus : il mesure l'inertie de la cible.*

**Le régime retenu est F5 : la suite SERT les réponses. Ce qui se mesure est le
REFUS et l'ABSENCE DE REQUÊTE — jamais l'effet distant.** *Aucun
`iptables-apply` n'est émis vers une machine réelle, à aucun moment.*

---

## 5. Ce que cette spec ne couvre pas, et qui le dit

- **Q2 ne protège pas la requête forgée hors navigateur.** *Un `curl` direct vers
  la passerelle ne rencontre aucun garde client.* **La seule barrière est alors
  celle du backend — et elle n'existe pas : `/iptables-apply` n'inspecte pas les
  règles.** ⚠ *Q2 est un garde d'INTERFACE. Le dire ici évite qu'on le prenne
  pour une garantie.*
- **La borne réelle reste `require_permission`** (le rôle ≥ 3 le court-circuite,
  et `check_machine_access` rend `True` dès le rôle 2 — §6 de
  `AUDIT-IPTABLES-CINQ-GESTES.md`).
- **Je n'ai pas mesuré** si un compte occupe ce chemin aujourd'hui : les quatre
  voies d'accès à la base me sont fermées.

---

## 6. CONTRAINTE DE PROCÉDURE — le filtre réseau ne se retouche pas

**Ce n'est pas un conseil. C'est la seule règle de cette spec qui porte sur la
CONDUITE de la mesure, parce que le défaut qu'elle prévient se produit APRÈS que
la sonde est écrite.**

    1. la liste des points d'application se fixe AVANT d'ecrire la sonde,
       en URL RESOLUE et en toutes lettres :
           .../api/gateway/iptables-apply
           .../api/gateway/iptables-restore
    2. elle est ECRITE dans la suite comme une constante nommee
    3. ⛔ elle NE SE MODIFIE PAS pour faire passer un test.
       Un ECHEC sur ce filtre est un resultat, pas un reglage.

> **Une épingle qui meurt par réflexe.** *La sonde rend un faux ÉCHEC parce
> qu'elle attrape `/iptables-validate` (I4, légitime) ; on élargit ou on
> restreint le filtre jusqu'au vert ; et on termine avec un filtre qui ne
> capture plus rien — c'est-à-dire une suite qui ne peut plus jamais échouer.*

**Si le filtre doit changer, le changement se justifie DANS la suite, à côté de
la constante, et la contre-épreuve du §2.3 est rejouée.**

---

## 7. Le comptage de `showNotification` — décomposé, parce que trois relevés le donnaient différent

**Trois chiffres circulaient : 8, 12, 13. Deux sont justes et mesurent des objets
différents ; un est faux.**

```
legacy/iptables/js/main.js
  APPELS       12   :148 :150 :154 · :182 :185 :189 · :225 :227 :231 · :273 :276 :280
  DECLARATION   1   :290  function showNotification(message, type = 'success')
  ─────────────────
  lignes        13   <- mon chiffre : le JETON, declaration comprise
```

**Le « 12 » compte les APPELS. Mon « 13 » comptait les LIGNES PORTANT LE JETON.
Les deux sont exacts ; ils ne répondent pas à la même question.** *Le chiffre qui
fonde la conséquence est **12** — c'est le nombre de sites qui lèvent.*

**Le « 8 » vient de `AUDIT-PRERELECTURE-IPTABLES.md:135` et n'a pas de référent.**
⚠ *Il a voyagé d'un document vers une consigne sans être remesuré, dans un
message qui demandait précisément de mesurer.*

### 7.1 ⚠ Et la cible EXISTE — dans un fichier déprécié

    #notifications dans le legacy SERVI                    0
      (index.php, et ses includes REELS : ../head.php, ../menu.php, ../footer.php)
    #notifications ailleurs
      legacy/_deprecated/adm/includes/manage_roles.php:273
        <div id="notifications" class="fixed bottom-4 right-4 z-50"></div>

> **La conclusion tient — chacun des 12 appels lève — mais l'origine n'est pas
> « personne n'a jamais écrit le conteneur ».** *C'est que `showNotification` a
> été écrite pour une page qui l'avait, et qu'elle a voyagé sans lui.* **Le
> module qui le portait est déprécié ; la fonction lui a survécu.**

*Note de méthode : le relevé qui nommait `legacy/includes/head.php`,
`menu.php`, `footer.php` visait des chemins qui n'existent pas — les includes
réels sont `legacy/head.php`, `menu.php`, `footer.php`. **Le résultat était
juste et la mesure ne mesurait pas ce qu'elle annonçait.***
