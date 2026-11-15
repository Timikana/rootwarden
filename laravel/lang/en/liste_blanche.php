<?php

/*
 * CVE whitelist — accepted false positives.
 *
 * Same-scope port of `legacy/security/index.php`, whose three backend routes had
 * stayed alive with no screen to reach them.
 */

return [
    'titre'       => 'CVE whitelist',
    'description' => "Accepted false positives, with reason, author and expiry. A whitelisted CVE stays listed in scan results but is no longer counted, notified or turned into a ticket, from the next scan on.",

    // ── The form ─────────────────────────────────────────────────────────
    'champ_cve'        => 'CVE identifier',
    'champ_cve_aide'   => "Form CVE-2024-1234.",
    'champ_motif'      => 'Reason',
    'champ_motif_aide' => "Why this finding is a false positive.",
    'champ_machine'      => 'Machine',
    'champ_machine_aide' => "\"All machines\" accepts the CVE across the whole estate.",
    'machine_toutes'     => 'All machines (global)',
    'champ_expiration'   => 'Expiry',
    'champ_sans_expiration' => "No expiry",
    'champ_expiration_aide' => "A date, or tick \"no expiry\".",
    'poser'    => 'Add',
    'retirer'  => 'Remove',
    'confirmer_retrait' => "Remove this entry?",

    // ── The table ────────────────────────────────────────────────────────
    'col_cve'     => 'CVE',
    'col_portee'  => 'Scope',
    'col_motif'   => 'Reason',
    'col_auteur'  => 'Added by',
    'col_echeance' => 'Expiry',
    'col_pose'    => 'Added on',
    'portee_globale' => 'Whole estate',
    'sans_echeance'  => 'None',
    'echue'          => 'Expired',
    'vide'           => 'No CVE whitelisted.',

    // ── Refusals, one per reason returned by the service ─────────────────
    'err_cve_requis'    => 'The CVE identifier is required.',
    'err_cve_malforme'  => 'Expected form: CVE-2024-1234.',
    'err_motif_requis'  => "A reason is required.",
    'err_motif_trop_long' => 'The reason exceeds 500 characters.',
    'err_machine_inconnue' => 'This machine does not exist.',
    'err_expiration_a_decider' => "Set an expiry, or tick \"no expiry\".",
    'err_expiration_contradictoire' => "Both a date and \"no expiry\": choose one.",
    'err_date_malformee' => 'Expected date format: YYYY-MM-DD.',
    'err_date_passee'    => "This expiry is already past.",
    'err_introuvable'    => 'This entry does not exist any more.',

    // ── Announcements ────────────────────────────────────────────────────
    'posee'   => 'Entry added.',
    'retiree' => 'Entry removed.',
    'err_reseau' => 'The request did not complete.',
];
