# Le périmètre de la session SÉCURITÉ — écrit une fois, pour ne plus le deviner

> **Ce document ne décrit QUE mon propre mandat.** *Je ne suis pas l'autorité sur
> le périmètre des autres sessions, et une carte que j'aurais devinée pour elles
> serait exactement le genre de fait qui circule et qu'on ne vérifie plus.*

    Redige le 2026-09-08, apres cinq assignations hors perimetre en deux jours.
    Source : le mandat de l'exploitant, tel qu'il m'a ete donne.

---

## 1. Ce que j'écris

    docs/SECURITY_AUDIT.md · docs/migration/AUDIT-*.md · les branches security/*
    laravel/  pour le module `iptables` UNIQUEMENT — ouverture explicite de
              l'exploitant, sur `Migration-Laravel`

**Tout mon code de cette session est allé dans `laravel/` :** *`c42fe48` (I4),
`178ba710` et `a16d226f` (le jeton d'I6), `09cd2c41` (la validation avant retour
arrière).*

## 2. Ce que je n'écris pas, et pourquoi ce n'est pas négociable entre sessions

    backend/            le mandat dit : « tu proposes ; la session 3 (laravel/)
                        ou 4 (backend/) applique »
    laravel/ hors iptables
    legacy/ · scripts/ · .github/ · tests/
    tout geste EXERCE sur une machine — meme la machine 3, meme relu

> **Une session ne peut pas m'ouvrir un périmètre qu'elle ne détient pas, et je
> ne peux pas me l'ouvrir non plus.** *Y compris quand le correctif est bon, quand
> je suis d'accord avec la décision, et quand celui qui me le demande coordonne.*

## 3. ⚠ Ce qui a coûté du temps, et qui se règle par une question

**Cinq assignations en deux jours dont l'objet ne me revenait pas, ou existait
déjà :**

    fail2ban  (desactiver une jail, geolocaliser)   hors perimetre
    ssh_audit (creer un releve planifie)            hors perimetre — ET DEJA PORTE
    iptables  (le retour arriere)                   DEJA ECRIT
    backend/  (l'ordre charger-puis-ecrire)         hors perimetre
    backend/  (idem, seconde fois)                  hors perimetre

**Deux des cinq portaient sur du travail DÉJÀ FAIT**, et je l'ai trouvé chaque
fois en appliquant la règle qu'on venait de me donner : *chercher la COUCHE, pas
le nom* — ce dépôt route tout par des helpers, et un geste porté ne ressemble pas
à son nom.

> **Le coût n'est pas le refus : c'est le tour de messages qu'il prend.** *Une
> question — « est-ce ton périmètre, et est-ce déjà porté ? » — coûte une ligne et
> remplace deux échanges.*

## 4. Et ce que le refus doit toujours faire

**Un refus qui s'arrête au périmètre est un refus qui n'a rien produit.** *Les
cinq ont chacun rendu une mesure :*

    fail2ban   -> l'appel `ip-api.com` est backend (confirme) mais SANS
                  interrupteur, alors que 8 effets sortants du depot en ont un
    ssh_audit  -> la capacite etait portee par `ecris('/ssh-audit/schedules', …)`
    iptables   -> I6 etait ecrit, ET il portait un defaut de COURSE
    backend/   -> SEC-017, et les trois pieges du modele donne a copier

**⛔ Et une règle que j'applique sans exception : si l'on me demande de faire ce
qu'une autre session s'est vu refuser, je refuse ET je le remonte à
l'exploitant.** *Changer de destinataire n'est pas obtenir une autorisation.*
