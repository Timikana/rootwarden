<?php

/*
 * ChatOps : correspondances « identifiant chat -> compte RootWarden ».
 *
 * Cles PLATES : le fichier est charge d'un bloc par `@json(__('chatops'))`. Le
 * legacy prefixe ses cles JS par `js.chatops.` a cause de son dictionnaire plat
 * injecte par `head.php` — pas ici. Le jeu doit rester identique a
 * `lang/en/chatops.php`, verifie dans le meme commit.
 */
return [
    'title' => 'ChatOps',
    'desc'  => 'Associe un identifiant de messagerie (Slack, Teams) à un compte RootWarden, pour que les commandes envoyées depuis le chat soient exécutées au nom de la bonne personne.',

    'setup_title'      => 'Ce qu\'il faut configurer',
    'setup_url'        => 'Adresse à déclarer comme webhook entrant dans votre messagerie :',
    'setup_slack'      => 'Slack : créez une commande slash pointant sur cette adresse, et renseignez le secret de signature côté serveur.',
    'setup_token'      => 'Teams ou générique : renseignez un jeton partagé côté serveur et envoyez-le dans l\'en-tête de chaque requête.',
    'setup_commands'   => 'Commandes reconnues',
    // Le legacy ne le dit pas, et c'est precisement ce qui casse une bascule.
    'setup_changement' => 'Cette adresse a changé avec le nouveau portail : elle ne finit plus par « webhook.php ». Reportez-la dans votre messagerie avant d\'activer ChatOps.',

    'mappings_title' => 'Correspondances',
    'f_platform'     => 'Plateforme',
    'f_chat_id'      => 'Identifiant chat',
    'f_user'         => 'Compte RootWarden',
    'f_label'        => 'Libellé',
    'btn_add'        => 'Ajouter',
    'tip_add'        => 'Associe cet identifiant de chat au compte choisi.',

    'col_platform' => 'Plateforme',
    'col_chat_id'  => 'Identifiant chat',
    'col_user'     => 'Compte',
    'col_label'    => 'Libellé',

    'loading'  => 'Chargement…',
    'empty'    => 'Aucune correspondance. Associez un identifiant chat à un compte.',
    'enabled'  => 'ChatOps actif',
    'disabled' => 'ChatOps désactivé',
    'delete'   => 'Supprimer',

    // La confirmation se prend EN PAGE : pas de boite native.
    'confirm_titre'     => 'Supprimer cette correspondance ?',
    'confirm_aide'      => 'L\'identifiant :chat (:plateforme) ne sera plus reconnu : les commandes venues de ce compte de messagerie seront refusées.',
    'confirm_supprimer' => 'Supprimer',
    'confirm_annuler'   => 'Annuler',

    'saved'      => 'Correspondance enregistrée.',
    'deleted'    => 'Correspondance supprimée.',
    'err_chatid' => 'Renseignez un identifiant chat.',
    'err_load'   => 'Impossible de charger les correspondances.',
    'err_save'   => 'L\'enregistrement a échoué.',
    // Le legacy n'a pas cet equivalent : son `fetch` non enveloppe n'affiche
    // jamais de message quand le reseau tombe.
    'err_reseau' => 'Le serveur n\'a pas répondu. Réessayez dans un instant.',
    // Rendu au client PUBLIC du webhook : volontairement muet sur la cause.
    'backend_injoignable' => 'Service momentanément indisponible.',
];
