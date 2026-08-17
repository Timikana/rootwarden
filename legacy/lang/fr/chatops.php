<?php
// lang/fr/chatops.php - ChatOps bidirectionnel
return [
    'nav.chatops' => 'ChatOps',
    'nav.tip_chatops' => 'Commandes/approbations depuis Slack ou Teams (bidirectionnel)',

    'chatops.title' => 'ChatOps (Slack / Teams)',
    'chatops.desc' => 'Pilotez RootWarden depuis le chat : consultez l\'etat de la flotte et approuvez/rejetez les demandes depuis Slack ou Teams. Les notifications sortantes restent configurees via les webhooks.',
    'chatops.setup_title' => 'Configuration du webhook entrant',
    'chatops.setup_url' => 'URL a renseigner comme cible de la slash command Slack (ou du webhook sortant Teams) :',
    'chatops.setup_slack' => 'Slack : creez une slash command pointant vers cette URL et renseignez CHATOPS_SLACK_SIGNING_SECRET (signature verifiee).',
    'chatops.setup_token' => 'Teams / generique : envoyez l\'en-tete X-ChatOps-Token = CHATOPS_TOKEN (jeton partage).',
    'chatops.setup_commands' => 'Commandes disponibles',
    'chatops.mappings_title' => 'Mapping chat -> utilisateur RootWarden',
    'chatops.f_platform' => 'Plateforme',
    'chatops.f_chat_id' => 'Identifiant chat',
    'chatops.f_user' => 'Utilisateur',
    'chatops.f_label' => 'Libelle',
    'chatops.btn_add' => 'Ajouter',
    'chatops.tip_add' => 'Associer un identifiant de chat (Slack/Teams) a un utilisateur RootWarden, pour que ses commandes soient authentifiees.',
    'chatops.col_platform' => 'Plateforme',
    'chatops.col_chat_id' => 'Identifiant chat',
    'chatops.col_user' => 'Utilisateur',
    'chatops.col_label' => 'Libelle',
    'chatops.loading' => 'Chargement...',

    // JS
    'js.chatops.enabled' => 'ChatOps active',
    'js.chatops.disabled' => 'ChatOps desactive (definir CHATOPS_ENABLED + secret/jeton)',
    'js.chatops.empty' => 'Aucun mapping. Associez un identifiant chat a un utilisateur.',
    'js.chatops.delete' => 'Supprimer',
    'js.chatops.saved' => 'Mapping enregistre.',
    'js.chatops.deleted' => 'Mapping supprime.',
    'js.chatops.confirm_delete' => 'Supprimer ce mapping ?',
    'js.chatops.err_load' => 'Erreur de chargement.',
    'js.chatops.err_save' => 'Echec de l\'enregistrement.',
    'js.chatops.err_chatid' => 'L\'identifiant chat est requis.',
];
