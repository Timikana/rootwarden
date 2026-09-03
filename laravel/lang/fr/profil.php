<?php

/**
 * Profil — francais. Parite stricte avec lang/en/profil.php.
 */
return [

    'compte_titre' => 'Compte',
    'compte_texte' => 'Connecté sous :nom, avec le rôle :role.',

    'second_facteur_titre'  => 'Second facteur',
    'second_facteur_valeur' => 'Actif',
    'second_facteur_texte'  => "Un code à usage unique est exigé à chaque connexion. Il n'existe aucun accès sans second facteur.",

    'non_porte_titre' => 'Pas encore ici',
    // E-203 : les sessions SONT listees desormais. La chaine decrivait un
    // manque qui vient d'etre comble — un libelle qui survit au defaut
    // qu'il decrit devient faux sans que rien ne le signale.
    'non_porte_texte' => 'Les connexions mémorisées ne sont pas encore listées ici : l\'ancien portail les affiche. Le changement de mot de passe et les sessions ouvertes, eux, se gèrent désormais sur cette page.',
    /*
     * ── SOUS-LOT A2 : LE CHANGEMENT DE MOT DE PASSE ──────────────────────
     *
     * La politique est celle du legacy, a l'identique : les deux portails
     * partagent la base, donc une regle plus laxiste d'un cote serait un
     * contournement de l'autre. Le legacy rend UNE seule cle pour les cinq
     * regles de complexite — on garde ce choix : dire QUELLE regle a echoue
     * renseigne autant l'attaquant que la personne.
     */
    'mdp_titre' => 'Changer le mot de passe',
    'mdp_politique' => 'Au moins :longueur caracteres, avec une minuscule, une majuscule, un chiffre et un caractere special. Les :historique derniers mots de passe sont refuses, ainsi que celui en cours.',
    'mdp_actuel' => 'Mot de passe actuel',
    'mdp_nouveau' => 'Nouveau mot de passe',
    'mdp_confirmation' => 'Confirmer le nouveau mot de passe',
    'mdp_enregistrer' => 'Changer le mot de passe',
    // E-203 : la reserve « il ne consulte pas encore » n'a plus d'objet.
    'mdp_effet_sessions' => "Vos autres sessions seront fermées, sur ce portail comme sur l'ancien — les deux vérifient à chaque requête — et les connexions mémorisées oubliées.",
    'mdp_ok' => 'Mot de passe modifie avec succes.',
    'mdp_erreur_actuel' => 'Mot de passe actuel incorrect.',
    'mdp_erreur_correspondance' => 'Les mots de passe ne correspondent pas.',
    'mdp_erreur_politique' => 'Le mot de passe doit contenir au moins 15 caracteres, une majuscule, une minuscule, un chiffre et un caractere special.',
    'mdp_erreur_historique' => 'Ce mot de passe a deja ete utilise. Choisissez-en un autre.',
    'mdp_erreur_fuite' => 'Ce mot de passe apparait dans une fuite de donnees publique. Choisissez-en un autre.',
    'mdp_erreur_compte' => 'Compte introuvable.',

    // ══ E-203 : LES SESSIONS OUVERTES ════════════════════════════════════
    'sessions_titre' => 'Vos sessions ouvertes',
    'sessions_aide'  => "Chaque connexion à ce portail ou à l'ancien ouvre une session. Fermer une session la déconnecte immédiatement, des deux côtés.",
    'sessions_vide'  => "Aucune session enregistrée — pas même celle-ci, ce qui n'est pas normal.",
    'sessions_err'   => "Vos sessions n'ont pas pu être lues. Ce n'est pas « aucune session » : la liste n'a pas répondu.",
    'sessions_actuelle' => 'session actuelle',
    'sessions_depuis' => 'ouverte le :date',
    'sessions_vue'    => 'vue le :date',
    // La liste est bornee, et la borne est DITE : montrer 20 lignes sur 2 584
    // sans le dire serait le compteur qui ment qu'on corrige partout ailleurs.
    'sessions_bornee' => 'Les :n plus récentes, sur :total enregistrées.',
    // Une ligne de trois semaines n'est PAS une session ouverte : le fichier
    // de session a expiré depuis longtemps. Le dire évite de présenter un
    // vestige comme un accès vivant.
    'sessions_vestiges' => "L'ancien portail enregistre une ligne par connexion et n'en retire jamais : les plus anciennes ne correspondent plus à un accès ouvert.",
    'sessions_revoquer' => 'Fermer',
    // L'identifiant complet ne sort pas du serveur — voir SessionsActives.
    'sessions_empreinte' => 'empreinte :valeur',
    'sessions_revoquee'  => 'Session fermée.',
    'sessions_introuvable' => "Cette session n'existe plus — elle a peut-être déjà été fermée.",
    'sessions_pas_la_sienne' => "Pour fermer la session courante, utilisez « Déconnexion ».",
];
