<?php

/**
 * Audit log — `adm/` module, sub-lot D1. English.
 *
 * `entries_total` carries a PLACEHOLDER, and it is substituted. The legacy shows
 * "4 179 :count entries": its key carries the same placeholder, but its `t()`
 * helper substitutes nothing — in English as in French. See PARITE E-105.
 *
 * Strict parity with lang/fr/audit.php.
 */
return [

    'title' => 'Audit log',
    'desc' => 'History of every action performed on the platform, sealed by a hash chain. Filter by user, action or date.',
    'entries_total' => ':nombre entries in total',
    'filtered' => 'filtered',

    // Columns
    'col_id' => 'ID',
    'col_date' => 'Date',
    'col_utilisateur' => 'User',
    'col_action' => 'Action',

    // Filters
    'filter_user' => 'User',
    'filter_action' => 'Action',
    'filter_from' => 'From',
    'filter_to' => 'To',
    'placeholder_name' => 'Name…',
    'placeholder_action' => 'Login, Create, Delete…',
    'filtrer' => 'Filter',
    'reinitialiser' => 'Reset',

    'empty' => 'No entry matches',
    'empty_aide' => 'Widen the period or clear the filters.',

    // Pagination
    'pagination' => 'Audit log pages',
    'page_sur' => 'Page :page of :total',
    'precedent' => 'Previous',
    'suivant' => 'Next',

    // Export
    'btn_export_csv' => 'Export CSV',
    'export_hint' => 'Exports ALL filtered results, not just the page on screen.',

    // Chain integrity
    'btn_verify' => 'Verify integrity',
    'btn_verify_tip' => 'Recomputes the hash chain and reports the first inconsistency. Read only: nothing is written.',
    'btn_seal' => 'Seal orphan rows',
    'btn_seal_tip' => 'Attaches to the chain the rows inserted without a seal. IRREVERSIBLE: a sealed row cannot be unsealed.',

    'verif_en_cours' => 'Verifying the chain…',
    'chaine_intacte' => 'Chain intact: :scellees sealed rows, :orphelines unsealed, head = :tete',
    'chaine_rompue' => 'Inconsistency at row #:ligne (:type): expected :attendu, found :trouve. Nothing was written.',

    'sceller_titre' => ':nombre rows would be attached to the chain. The operation is irreversible.',
    'sceller_consigne' => 'To confirm, type the number :nombre',
    'sceller_rien' => 'No orphan row: the chain is already complete.',
    'sceller_en_cours' => 'Operation in progress…',
    'sceller_fait' => ':scellees rows sealed out of :sur. New chain head = :tete',
    'sceller_refus' => 'Sealing cancelled. Nothing was written.',
    'err_confirmation' => 'The number typed does not match the :attendu rows concerned. Nothing was written.',
    'err_reseau' => 'The portal did not answer (status :statut). Nothing was written.',

    'annuler' => 'Cancel',
    'confirmer' => 'Seal',
];
