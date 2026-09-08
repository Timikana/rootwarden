<?php

/*
 * CVE whitelist — accepted false positives.
 *
 * Same-scope port of `legacy/security/index.php`, whose three backend routes had
 * stayed alive with no screen to reach them.
 */

return [
    'titre'       => 'CVE whitelist',
    'description' => 'A CVE listed here is accepted as a false positive and stops being '
                     . 'reported. Every entry carries its reason, its author and its expiry: '
                     . 'these are what stop a whitelisting from being forgotten.',

    // ── The form ─────────────────────────────────────────────────────────
    'champ_cve'        => 'CVE identifier',
    'champ_cve_aide'   => 'Form CVE-2024-1234. A typo creates an entry that whitelists nothing '
                          . 'and looks like protection.',
    'champ_motif'      => 'Reason',
    'champ_motif_aide' => 'Why this finding is a false positive. Read by whoever picks this up '
                          . 'later, not by you.',
    'champ_machine'      => 'Machine',
    'champ_machine_aide' => 'Leaving this empty whitelists the CVE across the WHOLE estate.',
    'machine_toutes'     => 'All machines (global)',
    'champ_expiration'   => 'Expiry',
    'champ_sans_expiration' => 'No expiry, deliberately',
    'champ_expiration_aide' => 'A date, or the explicit choice not to set one. The field cannot '
                               . 'be left empty without a decision: that is the only difference '
                               . 'from the old portal, and it prevents the oversight — not the act.',
    'poser'    => 'Add',
    'retirer'  => 'Remove',
    'confirmer_retrait' => 'Remove this entry? The CVE will be reported again.',

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
    'err_motif_requis'  => 'A reason is required: an entry without one cannot be re-read.',
    'err_motif_trop_long' => 'The reason exceeds 500 characters.',
    'err_machine_inconnue' => 'This machine does not exist.',
    'err_expiration_a_decider' => 'Set an expiry, or explicitly tick “no expiry”.',
    'err_expiration_contradictoire' => 'Both a date AND “no expiry”: pick one.',
    'err_date_malformee' => 'Expected date format: YYYY-MM-DD.',
    'err_date_passee'    => 'This expiry is already past: it would whitelist zero days.',
    'err_introuvable'    => 'This entry does not exist any more.',

    // ── Announcements ────────────────────────────────────────────────────
    'posee'   => 'Entry added.',
    'retiree' => 'Entry removed.',
    'err_reseau' => 'The request did not complete.',
];
