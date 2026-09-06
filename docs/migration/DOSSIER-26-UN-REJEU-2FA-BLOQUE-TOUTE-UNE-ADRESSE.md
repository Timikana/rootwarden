# ⚠ DOSSIER 26 — Dix rejeux 2FA bloquent l'authentification de TOUT UN BUREAU

**Trouvé par la session 4, vérifié ligne par ligne et en base par moi le 2026-09-04 à 17:00 CEST.**

> **Ce n'est pas une régression du portage. C'est une garde de sécurité NEUVE et bonne, dont le choix de
> journalisation a produit un risque de DISPONIBILITÉ que personne n'a vu.**

---

## 1. LE MÉCANISME, EN TROIS LIGNES

    SecondFacteurController, les DEUX chemins (connexion :128, step-up :211) :
        $verdict = $this->totp->verifie(…);
        $this->journalise($requete, $nom, $verdict === 'ok');   <- AVANT l'aiguillage
        if ($verdict === 'rejeu') { return back()->withErrors(…); }

**Un rejeu est donc inscrit dans `login_attempts` avec `success = 0` : un ÉCHEC.**

    ipBloquee() (:277-289)
        WHERE ip_address = <celle du demandeur>
          AND step = '2fa'  AND success = 0
          AND attempted_at > now() - 10 minutes
        >= config('rootwarden.connexion.max_echecs_ip', 10)     -> seuil 10

    et il garde les DEUX portes : :123 (connexion) et :192 (step-up)

## 2. LA CONSÉQUENCE

> **Un bureau derrière un NAT partage une adresse. Dix refus de rejeu en dix minutes bloquent l'étape 2FA
> pour TOUT LE MONDE derrière cette adresse — y compris ceux qui n'ont rien fait.**

**Et un rejeu est le cas d'usage LÉGITIME le plus banal** : *le même compte ouvre une session sur un second
appareil dans la même fenêtre de 30 secondes.* **Un seul utilisateur qui insiste sur deux appareils peut
donc s'auto-bloquer, et bloquer ses collègues avec lui.**

**⚠ Ce n'est pas une exposition théorique, mais elle n'est pas VIVANTE aujourd'hui** :

    lignes de `login_attempts`   2      (toutes `step = '2fa'`)

*Le compteur est loin du seuil. Le défaut est LATENT — il attend un usage réel à plusieurs postes.*

## 3. ET IL RÉSOUT UNE ÉNIGME DU CATALOGUE

**Un relevé antérieur notait des refus observés « sans qu'aucun compte ne soit verrouillé — la piste
évidente ne mène nulle part ».**

> **Le verrou n'est pas par COMPTE, il est par ADRESSE.** *La piste ne menait nulle part parce qu'on
> cherchait au mauvais endroit.*

**⚠ Et cela corrige une note que je portais** : *« le garde anti-rejeu est par compte et EN BASE ».* **Deux
mécanismes distincts avaient été confondus sous un seul énoncé : la détection du rejeu (par compte, via le
cache) et le blocage (par ADRESSE, dans `login_attempts`).**

## 4. ✅ LE CORRECTIF QUE JE TRANCHE — et il n'exige AUCUNE migration

    `login_attempts.step`  varchar(16) NOT NULL     <- mesure
    valeurs presentes      `2fa` seulement

**Donc une valeur distincte y entre sans changer le schéma.**

    ✅ la branche `rejeu` journalise avec un `step` DISTINCT — p. ex. `2fa_rejeu`
    ✅ `ipBloquee()` ne change PAS : il compte deja `step = '2fa'` seulement,
       donc il cesse de voir les rejeux sans qu'on touche au compteur
    ⛔ NE PAS passer `true` pour un rejeu : ce serait inscrire un SUCCES,
       donc falsifier le journal
    ⛔ NE PAS cesser de journaliser : un rejeu est une PREUVE — quelqu'un
       resoumet un code cryptographiquement valide, et c'est precisement ce
       qu'on veut pouvoir lire apres coup

> **La distinction qui porte le correctif : un rejeu n'est pas un échec d'identifiant, c'est une soumission
> EN DOUBLE d'un identifiant VALIDE.** *Il doit être inscrit et ne doit pas compter.*

**Bénéfice secondaire : les rejeux deviennent DISTINGUABLES dans le journal, ce qu'ils ne sont pas
aujourd'hui.**

**⚠ La seule condition à vérifier avant d'écrire** : *qui LIT `login_attempts` avec `step = '2fa'` ?* **Un
tableau ou une requête qui compte les échecs 2FA cesserait de voir les rejeux. Il faut le relever, pas le
supposer.**

## 5. UN SECOND POINT, MINEUR ET RÉEL

**L'écran distingue `erreur_code_deja_utilise` de `erreur_code_invalide` : il confirme donc au soumetteur
que son code était CRYPTOGRAPHIQUEMENT VALIDE.**

*Oracle faible — il faut déjà détenir un code valide pour l'atteindre. Signalé, non recommandé comme
priorité : fusionner les deux messages coûterait à l'utilisateur légitime la seule information qui lui dit
quoi faire (attendre la fenêtre suivante plutôt que ressaisir).*

## 6. CE QUI VOUS REVIENT

    ✅ le correctif du §4       autorise, aucune migration, aucun redemarrage
                               de base — je le route a la session de portage
    📌 rien d'autre.

**SI RIEN N'EST FAIT** : *rien ne se passe tant que le produit sert peu de postes.* **Le jour où deux
personnes d'un même bureau s'authentifient dans la même fenêtre de 30 secondes, elles commencent à
consommer un compteur partagé dont le seuil est 10 — et le blocage qu'elles déclencheront portera sur
l'étape 2FA, c'est-à-dire sur la porte d'entrée du produit.**

---

# ⛔ CORRECTION — le seuil qui mord le PREMIER est 5, et il est dans le legacy SERVI EN PRODUCTION

**2026-09-04, 15:40. Ma description nommait le mauvais compteur.**

    legacy/auth/login.php:46   $maxAttempts = 5;
                        :50   SELECT COUNT(*) FROM login_attempts
                              WHERE ip_address = ? AND success = 0
                                AND attempted_at >= …
                              ^^^ AUCUN filtre de `step`

> **Le compteur de CONNEXION du legacy compte toute ligne en échec, quelle que soit son étape. CINQ rejeux
> fermaient donc déjà l'étape de CONNEXION — à la MOITIÉ du seuil, sur un AUTRE écran, avant que le
> compteur 2FA atteigne dix.**

**Et changer l'étape ne l'en sort pas** : *une ligne `2fa_rejeu` reste `success = 0`, donc elle continue
d'alimenter ce compteur-là.*

    ce que j'ecrivais   « dix rejeux bloquent l'etape 2FA »
    ce qui est vrai     CINQ rejeux bloquent la CONNEXION,
                        et dix bloquent AUSSI la 2FA

## ✅ Le correctif posé reste SUFFISANT — pour le côté qui survit

    aucun compteur du PORTAGE ne lit `login_attempts` sans filtre d'etape
    `ConnexionController:119` n'y fait qu'INSERER
    les quatre lecteurs de `step = '2fa'` :
        laravel  SecondFacteurController:282   ipBloquee()
        legacy   verify_2fa:73 · confirm_2fa:72 · enable_2fa:129
                 -> TROIS copies du meme compteur
    aucun tableau ne les lit

**Donc après `4b3e656` (v1.39.9), un rejeu ne ferme plus rien du côté qui survit à la bascule.**

## ⚠ MAIS LE RÉSIDU EST EN PRODUCTION, ET IL Y RESTERA JUSQU'À L'EXTINCTION

**`legacy/auth/login.php` est servi. Le seuil de 5, sans filtre d'étape, y est vivant aujourd'hui.**

    ⛔ je ne fais pas corriger le legacy : c'est du code de production que la
       bascule doit RETIRER, et un correctif y ajouterait un risque a un
       composant qu'on eteint
    ✅ ce qui ferme reellement ce residu : l'extinction du legacy
    📌 dans l'intervalle, si un blocage de connexion inexplique est signale,
       la cause probable est la : cinq refus de rejeu 2FA depuis la meme
       adresse en dix minutes

**Et c'est un argument opérationnel de plus pour l'extinction — pas seulement pour la propreté.**

## ✅ Un resserrement du correctif, meilleur que ma prescription

**`journalise()` reçoit désormais le VERDICT et non un booléen : une seule place décide `success` ET
`step`.** *Passés séparément, les deux finiraient par se contredire — un rejeu inscrit en échec, ou un
échec inscrit hors du compteur.* **Et `ipBloquee()` passe du littéral à la CONSTANTE.**
