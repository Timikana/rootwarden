<?php
// lang/fr/appr.php - Workflow d'approbation 4-eyes
return [
    'nav.approvals' => 'Approbations',
    'nav.tip_approvals' => 'Validation 4-eyes des actions destructives (2e admin)',

    'appr.title' => 'Approbations (4-eyes)',
    'appr.desc' => 'Les actions destructives (suppression d\'utilisateur, reboot...) peuvent exiger l\'aval d\'un second administrateur. Vous ne pouvez pas approuver vos propres demandes.',
    'appr.tab_pending' => 'En attente',
    'appr.tab_approved' => 'Approuvees',
    'appr.tab_rejected' => 'Rejetees',
    'appr.tab_all' => 'Toutes',
    'appr.col_action' => 'Action',
    'appr.col_target' => 'Cible',
    'appr.col_machine' => 'Machine',
    'appr.col_requester' => 'Demandeur',
    'appr.col_status' => 'Etat',
    'appr.loading' => 'Chargement...',

    // JS
    'js.appr.empty' => 'Aucune demande.',
    'js.appr.approve' => 'Approuver',
    'js.appr.reject' => 'Rejeter',
    'js.appr.by' => 'par',
    'js.appr.own_hint' => 'Vous ne pouvez pas approuver votre propre demande (regle 4-eyes).',
    'js.appr.confirm' => 'Confirmer : :action cette demande ?',
    'js.appr.reason_prompt' => 'Motif du rejet (optionnel) :',
    'js.appr.done' => 'Decision enregistree.',
    'js.appr.err_load' => 'Erreur de chargement.',
    'js.appr.err_decide' => 'Echec de la decision.',
];
