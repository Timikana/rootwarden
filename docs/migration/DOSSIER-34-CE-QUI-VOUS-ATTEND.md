# DOSSIER 34 — ce qui vous attend, au 2026-09-05 à 23:40

**Établi par la session 8 (DSI délégué).** *Onze entrées de registre écrites entre 22:30 et
23:35 vous concernent. Les recoudre n'est pas votre travail — le voici fait.*

> **Chaque geste porte : ce qu'il coûte · ce qu'il se passe si vous ne faites rien · et la
> commande exacte.** *Rien ici n'a été exécuté.*

---

## ⑴ RECRÉER LES CONTENEURS — et ce geste en règle TROIS d'un coup

**C'est le seul geste de cette liste qui répare plusieurs choses à la fois.**

    ce qu'il repare
      a) l'affichage de la version    le portail montre `2.0.94`, la vraie valeur est `2.0.11`
      b) le montage detache            le conteneur sert un inode ORPHELIN
      c) il est le SEUL moyen de       un redemarrage ne relit PAS `env_file:`
         changer une variable d'env

**Si vous ne faites rien** : *le pied de page continue d'afficher un numéro faux — et il est
**PLUS ÉLEVÉ** que le vrai, donc il rassure.* **Quiconque ouvre une page pour vérifier qu'une
livraison est en service lit « oui, et même largement ».** *Un numéro trop bas aurait fait
chercher ; celui-là ne fera rien chercher à personne.*

    sudo docker compose up -d --force-recreate rootwarden_laravel rootwarden_php

**Contrôle après** :

    sudo docker exec rootwarden_laravel cat /var/www/html/version.txt     # doit rendre 2.0.11
    stat -c %i legacy/version.txt
    sudo docker exec rootwarden_laravel stat -c %i /var/www/html/version.txt   # doivent CONCORDER

⚠ **Un lot tourne depuis 23:22.** *Attendez sa fermeture — la QA prévient.*

---

## ⑵ LE CHOIX QUI NE SE POSE QU'UNE FOIS : `docker-compose.prod.yml`

**La production porte le même montage de FICHIER, et elle n'a PAS encore dérivé.**

    docker-compose.prod.yml:124   - ./legacy/version.txt:/var/www/html/version.txt:ro
    prod a v1.37.15 — aucun bump par le script n'y a encore eu lieu

> **C'est le seul endroit où vous pouvez encore choisir sans réparer d'abord.** *En
> développement, le mal est fait et le remède posé ; en production, la page est blanche.*

**Deux options, et la première ne sacrifie rien :**

    A. monter le REPERTOIRE plutot que le fichier
       -> le montage suit le CHEMIN, l'ecriture atomique redevient possible
    B. garder l'ecriture EN PLACE que j'ai posee en dev
       -> simple, deja eprouve, au prix de l'atomicite

**Ma recommandation : A pour la production.** *J'ai pris B en développement parce qu'elle était
immédiate, pas parce qu'elle est meilleure.*

**Si vous ne faites rien** : *la production dérivera au premier bump, et le défaut y sera plus
difficile à voir qu'ici — parce qu'il **se répare tout seul à chaque redémarrage** et revient
au bump suivant.* **Chacun le verra à un moment différent du cycle, et chacun aura raison.**

---

## ⑶ ⛔ LE SMTP : UNE DE VOS TROIS ISSUES A UN FAUX REMÈDE

**`DOSSIER-24` vous offrait trois issues. Celle qui paraissait gratuite ne l'est pas.**

    fichier /var/www/html/.env   MAIL_MAILER=log     <- la valeur SURE, et elle PERD
    env du processus             MAIL_MAILER=smtp    <- injecte par `env_file:`
    ce que Laravel SERT          smtp                <- mesure dans le conteneur qui sert

> **`.env` porte DÉJÀ `log`.** *Si vous l'ouvrez pour vérifier avant d'agir, vous y lisez la
> valeur sûre, vous en concluez que l'envoi est désarmé, et vous ne faites rien.* **Vous n'avez
> même pas besoin d'éditer pour vous tromper.**

**Les trois issues, avec leur prix réel :**

    accepter l'oracle en le sachant     gratuit, et c'est une decision, pas un oubli
    poser `php-fpm`                     le ferme PAR CONSTRUCTION — la reponse est
                                        terminee avant que la poignee TLS parte
    desarmer                            editer `srv-docker.env` PUIS recreer (⑴)

**Ce qui est en jeu** : *un POST sur `/mot-de-passe-oublie` — page **publique**, liée depuis
l'écran de connexion — envoie un courriel réel. Et sous `mod_php` sans `php-fpm`, la poignée
TLS (78 ms rien que pour ouvrir la socket) se produit **pendant** la requête et **seulement**
dans la branche « l'adresse existe ».* **L'écart de temps dit si une adresse est connue.**

⛔ **Ne demandez à personne de mesurer cet écart au réseau** : *la branche « connue » exige une
adresse réelle, donc un vrai courriel vers une vraie personne.* **Deux sessions ont refusé de
le faire, et elles ont eu raison.**

---

## ⑷ TROIS CAPACITÉS SONT MORTES SANS QUE CE SOIT DÉCIDÉ

    /policy/rollback      POST — ouvre une session SSH, ECRIT sur les machines
    /policy/deployments   GET  — lecture
    /policy/list          GET  — lecture

**Les routes existent, sont gardées, et RIEN ne les appelle.** *Leur interface —
`server_user_policy.js` et `health_check.php` — vit dans `_deprecated/`.*

> ⚠ **Et le portage porte un test qui exerce le step-up sur `rollback` : la règle est VERTE.**
> *Une capacité orpheline dont la garde passe ses tests ne produit aucun signal, nulle part —
> et un vert se lit « cette capacité est saine ».*

**Trois issues, et c'est un arbitrage produit que je ne prends pas** : *leur rendre une
interface · les retirer · les laisser en l'état en le sachant.* **La troisième est légitime ;
elle ne l'est que si elle est écrite.**

---

## ⑸ LES GESTES DÉJÀ CONNUS, INCHANGÉS

    pousser        git push origin Migration-Laravel     (~235 commits d'avance)
    fusionner      main date du 2026-09-03
    rotation       le mot de passe SMTP est en clair dans l'env du conteneur
    relire         `security/backend-cve` — 6 commits jamais relus
    K4             deploiement sur la machine 3, portee arbitree `rootwarden` SEUL
    DOSSIER-32     scan sortant et application du pare-feu — effets sur des tiers

---

## CE QUE JE RECOMMANDE, DANS CET ORDRE

    1. attendre la fermeture du lot (la QA previent)
    2. ⑴ recreer les conteneurs — repare trois choses
    3. ⑶ trancher le SMTP, en sachant que « desarmer » coute ⑴
    4. ⑵ choisir pour la production PENDANT qu'elle est encore saine
    5. ⑷ ecrire la decision sur les trois orphelines, meme si c'est « on laisse »

> **Le seul de ces cinq qui se dégrade en attendant est ⑵** — *chaque bump en production
> rapproche le moment où le choix devra être précédé d'une réparation.*
