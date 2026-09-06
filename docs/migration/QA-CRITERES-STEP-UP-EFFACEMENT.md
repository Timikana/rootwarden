# Critères d'attestation — step-up sur `POST /profil/effacement` (E-449)

**Écrits AVANT toute lecture du code de `gestion-ssh-key-c1`.** Mesuré à l'instant de la
rédaction : `PortailController` ne mentionne `StepUp` que dans `verifieStepUp` et
`revoqueStepUp` ; `ACTIONS_PORTAGE` ne contient pas `profil_effacement`. **Rien n'est posé.**

> Ces critères sont scellés pour une raison précise : *des critères écrits après lecture se
> moulent sur ce qui a été construit.* Ils portent sur des **propriétés**, jamais sur une
> forme d'implémentation — je n'ai pas à dicter comment le geste est écrit, seulement ce
> qu'il doit tenir.

---

## C1 — La garde EXISTE et MORD

Une requête authentifiée, avec la confirmation CORRECTE, et **sans marque de step-up
fraîche**, doit être **refusée**, et le compte doit rester **intact**.

**La propriété à mesurer est l'ABSENCE d'effet, pas la présence d'un message.** Un refus qui
affiche une erreur *et* anonymise quand même serait vert sur le message. J'asserte donc
l'état du compte **après** la requête, pas la réponse seule.

    AVANT   name / email / totp_secret du compte
    APRES   IDENTIQUES

## C2 — La garde ne coûte AUCUN accès

Le même geste, avec une marque de step-up **valide**, doit **aboutir**.

Un contrôle qui refuse tout le monde satisfait C1 parfaitement. **C1 sans C2 est un déni de
service qui a l'air d'une sécurité.**

Fondement mesuré (chaîne, pas supposition) : atteindre la route exige une session ; avoir une
session exige d'avoir franchi la connexion ; `ConnexionController:168` force l'enrôlement si
`totp_secret` est vide. **Quiconque atteint cette route dispose donc d'un second facteur.**

## C3 — L'ordre des gardes

Le step-up doit être exigé **avant** l'anonymisation, évidemment — mais aussi de façon à ne
pas contourner les trois protections déjà gelées. Je vérifie que restent vraies, dans cet
ordre : identifiant de SESSION · confirmation par ressaisie · dernier superadministrateur ·
journal AVANT anonymisation.

**Un correctif qui ajoute une garde en déplaçant les autres est une régression nette.**

## C4 — L'action est dans la liste FERMÉE, et elle est NOUVELLE

`profil_effacement` (ou le nom retenu) doit figurer dans `StepUp::ACTIONS_PORTAGE`, **avec
son motif écrit**, comme les trois autres.

⚠ **Et elle ne doit PAS réutiliser `compte_anonymiser`.** Une marque consentie pour
l'anonymisation ADMINISTRATIVE ouvrirait alors l'effacement de son propre compte — c'est
exactement le défaut du legacy que ce dépôt a corrigé en séparant les noms d'action
(`RoutesBackend`, à propos de `policy_action` : un step-up consenti pour ANNULER une
politique autorisait un DÉPLOIEMENT pendant quinze minutes).

## C5 — Mes deux marqueurs datés sont RETOURNÉS, pas silenciés

`test_le_step_up_du_LIBRE_SERVICE_reste_A_POSER` et
`test_le_step_up_n_est_pose_par_AUCUN_intergiciel` **doivent rougir**. C'est ce qu'ils
annonçaient dans leur propre message.

Je les retourne : ils asserteront désormais la PRÉSENCE. Et la garde neuve est inscrite dans
`TableDesGardes`, faute de quoi mon inventaire déclare un monde qui a changé.

**Un marqueur qu'on supprime au lieu de le retourner efface la trace du manque en même temps
que le manque.**

## C6 — La PORTÉE reste écrite à côté de la garde

> « La friction protège du geste ACCIDENTEL, pas d'une session COMPROMISE — le nom à retaper
> est affiché sur la page elle-même. »

Sans cette phrase, le prochain lecteur voit deux contrôles et conclut qu'il y en a deux.
**Il y en a un contre l'accident et un contre le vol de session : ils ne protègent pas de la
même chose**, et c'est vrai *après* le correctif comme avant.

---

## Ce que je n'attesterai PAS, et qu'il ne faut pas me faire dire

- **Que la forme est la bonne.** Si `c1` produit un intergiciel là où les trois précédents
  passent par un contrôleur, je le signalerai comme incohérence de forme — mais mon
  attestation porte sur les propriétés C1 à C6, pas sur le style.
- **Que le parcours à l'écran fonctionne.** Le geste est un `<form method="POST">` et la
  modale de step-up écoute un `fetch`. Le raccord entre les deux se mesure **au navigateur**,
  et ce n'est pas le banc PHPUnit. Si je ne l'ai pas mesuré, je le dirai plutôt que de
  laisser un vert le suggérer.
- **Qu'aucune autre route n'a le même manque.** Mes critères portent sur celle-ci.
