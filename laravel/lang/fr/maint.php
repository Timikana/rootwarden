<?php

/*
 * Fenetres de maintenance. Cles PLATES : le fichier est charge d'un bloc par
 * `@json(__('maint'))`. Jeu identique a `lang/en/maint.php`, verifie dans le
 * meme commit.
 */
return [
    'title' => 'Fenêtres de maintenance',
    'desc'  => "Plages horaires pendant lesquelles les actions mutantes (mises à jour, redémarrages, déploiements) sont autorisées.",

    /*
     * L'ENCART QUI DIT CE QUE LE LEGACY GLISSE EN DEMI-PHRASE. Se tromper ici
     * bloque la flotte a l'heure ou l'on en a besoin.
     */
    'guide_titre'    => "Attention : une fenêtre restreint la flotte",
    'guide_aucune'   => "Sans fenêtre activée, rien n'est restreint.",
    'guide_une'      => "Dès qu'une fenêtre est activée, les actions mutantes ne passent plus que pendant ses plages.",
    'guide_role'     => "Les superadmins passent toujours ; leur passage est journalisé.",
    'guide_ailleurs' => "Un refus s'affiche sur la page de l'action (mises à jour, supervision), pas ici.",

    'etat_libre'     => 'Aucune restriction',
    'etat_restreint' => 'Flotte restreinte',
    'etat_machines'  => ':n machine restreinte|:n machines restreintes',

    'etat_detail'    => ':n fenêtre(s) activée(s), dont :g globale(s)',
    'horloge_serveur' => "⚠ Calculé sur l'horloge du serveur (:heure, :decalage), pas sur celle de votre navigateur.",

    'btn_new'        => 'Nouvelle fenêtre',
    'tip_new'        => 'Définir une plage pendant laquelle les actions mutantes sont autorisées.',
    'f_name'         => 'Nom',
    'f_scope'        => 'Portée',
    'scope_global'   => 'Globale (toute la flotte)',
    'scope_machine'  => 'Machine précise',
    'f_machine'      => 'Machine',
    'f_days'         => 'Jours',
    'f_start'        => 'Début',
    'f_end'          => 'Fin',
    'f_enabled'      => 'Activée',
    'overnight_hint' => "Début après la fin : la fenêtre passe minuit (ex. 22:00 → 06:00).",
    'btn_save'       => 'Enregistrer',
    'btn_cancel'     => 'Annuler',

    'col_name'   => 'Nom',
    'col_scope'  => 'Portée',
    'col_days'   => 'Jours',
    'col_hours'  => 'Horaires',
    'col_status' => 'État',

    'mon' => 'Lun', 'tue' => 'Mar', 'wed' => 'Mer', 'thu' => 'Jeu',
    'fri' => 'Ven', 'sat' => 'Sam', 'sun' => 'Dim',

    'loading'    => 'Chargement…',
    'empty'      => 'Aucune fenêtre définie — donc aucune restriction.',
    'active_now' => 'Ouverte maintenant',
    'closed_now' => 'Fermée maintenant',
    'disabled'   => 'Désactivée',
    'enable'     => 'Activer',
    'disable'    => 'Désactiver',
    'delete'     => 'Supprimer',

    // La confirmation se prend EN PAGE : pas de boite native.
    'confirm_titre'     => 'Supprimer cette fenêtre ?',
    'confirm_aide'      => "La fenêtre « :name » sera supprimée. Si c'était la dernière activée, la flotte n'est plus restreinte.",
    'confirm_supprimer' => 'Supprimer',
    'confirm_annuler'   => 'Annuler',

    'saved'      => 'Fenêtre enregistrée.',
    'deleted'    => 'Fenêtre supprimée.',
    'err_load'   => 'Impossible de charger les fenêtres.',
    'err_save'   => 'L\'enregistrement a échoué.',
    'err_name'   => 'Le nom est requis.',
    'err_days'   => 'Sélectionnez au moins un jour.',
    'err_reseau' => 'Le serveur n\'a pas répondu. Réessayez dans un instant.',
];
