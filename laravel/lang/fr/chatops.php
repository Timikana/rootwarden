<?php

/*
 * ChatOps : correspondances « identifiant chat -> compte RootWarden ».
 *
 * Cles PLATES : le fichier est charge d'un bloc par `@json(__('chatops'))`. Le
 * jeu doit rester identique a `lang/en/chatops.php`.
 * Regles de redaction : docs/REDACTION-INTERFACE.md.
 */
return [
    'title' => 'ChatOps',
    'desc'  => 'Les commandes envoyées depuis Slack ou Teams s\'exécutent au nom du compte RootWarden associé.',

    'setup_title'      => 'Configurer la messagerie',
    'setup_url'        => 'Adresse du webhook entrant :',
    'setup_slack'      => 'Slack : créez une commande slash vers cette adresse et renseignez CHATOPS_SLACK_SIGNING_SECRET sur le serveur.',
    'setup_token'      => 'Teams ou générique : renseignez CHATOPS_TOKEN sur le serveur et envoyez-le dans l\'en-tête X-ChatOps-Token.',
    'setup_activer'    => 'Puis activez CHATOPS_ENABLED=true.',
    'setup_commands'   => 'Commandes reconnues',

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

    'confirm_titre'     => 'Supprimer cette correspondance ?',
    'confirm_aide'      => 'L\'identifiant :chat (:plateforme) ne sera plus reconnu : les commandes venues de ce compte de messagerie seront refusées.',
    'confirm_supprimer' => 'Supprimer',
    'confirm_annuler'   => 'Annuler',

    'saved'      => 'Correspondance enregistrée.',
    'deleted'    => 'Correspondance supprimée.',
    'err_chatid' => 'Renseignez un identifiant chat.',
    'err_load'   => 'Impossible de charger les correspondances.',
    'err_save'   => 'L\'enregistrement a échoué.',
    'err_reseau' => 'Le serveur n\'a pas répondu. Réessayez dans un instant.',
    // Rendu au client PUBLIC du webhook : volontairement muet sur la cause.
    'backend_injoignable' => 'Service momentanément indisponible.',
];
