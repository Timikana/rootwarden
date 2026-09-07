<?php

/*
 * Liste blanche des CVE — faux positifs acceptes.
 *
 * Portage a ISO-PERIMETRE de `legacy/security/index.php`, dont les trois routes
 * backend etaient restees vivantes sans ecran pour les atteindre.
 */

return [
    'titre'       => 'Liste blanche des CVE',
    'description' => 'Une CVE inscrite ici est acceptee comme faux positif et cesse d\'etre '
                     . 'signalee. Chaque entree porte son motif, son auteur et son echeance : '
                     . 'ce sont eux qui empechent qu\'un blanchiment soit oublie.',

    // ── Le formulaire ────────────────────────────────────────────────────
    'champ_cve'        => 'Identifiant CVE',
    'champ_cve_aide'   => 'Forme CVE-2024-1234. Une faute de frappe cree une entree qui ne '
                          . 'blanchit rien et qui a l\'air de proteger.',
    'champ_motif'      => 'Motif',
    'champ_motif_aide' => 'Pourquoi ce signalement est un faux positif. Lu par la personne qui '
                          . 'reprendra ce dossier, pas par vous.',
    'champ_machine'      => 'Machine',
    'champ_machine_aide' => 'Laisser vide blanchit la CVE sur TOUT le parc.',
    'machine_toutes'     => 'Toutes les machines (global)',
    'champ_expiration'   => 'Echeance',
    'champ_sans_expiration' => 'Sans echeance, delibérément',
    'champ_expiration_aide' => 'Une date, ou le choix explicite de ne pas en poser. Le champ ne '
                               . 'peut pas rester vide sans decision : c\'est la seule difference '
                               . 'avec l\'ancien portail, et elle empeche l\'oubli — pas le geste.',
    'poser'    => 'Inscrire',
    'retirer'  => 'Retirer',
    'confirmer_retrait' => 'Retirer cette entree ? La CVE sera de nouveau signalee.',

    // ── Le tableau ───────────────────────────────────────────────────────
    'col_cve'     => 'CVE',
    'col_portee'  => 'Portee',
    'col_motif'   => 'Motif',
    'col_auteur'  => 'Inscrite par',
    'col_echeance' => 'Echeance',
    'col_pose'    => 'Inscrite le',
    'portee_globale' => 'Tout le parc',
    'sans_echeance'  => 'Aucune',
    'echue'          => 'Echue',
    'vide'           => 'Aucune CVE en liste blanche.',

    // ── Les refus, un par motif rendu par le service ─────────────────────
    'err_cve_requis'    => 'L\'identifiant CVE est requis.',
    'err_cve_malforme'  => 'Forme attendue : CVE-2024-1234.',
    'err_motif_requis'  => 'Le motif est requis : une entree sans motif ne se relit pas.',
    'err_motif_trop_long' => 'Le motif depasse 500 caracteres.',
    'err_machine_inconnue' => 'Cette machine n\'existe pas.',
    'err_expiration_a_decider' => 'Poser une echeance, ou cocher explicitement « sans echeance ».',
    'err_expiration_contradictoire' => 'Une date ET « sans echeance » : choisir l\'un des deux.',
    'err_date_malformee' => 'Date attendue au format AAAA-MM-JJ.',
    'err_date_passee'    => 'Cette echeance est deja passee : elle ne blanchirait aucun jour.',
    'err_introuvable'    => 'Cette entree n\'existe pas ou plus.',

    // ── Les annonces ─────────────────────────────────────────────────────
    'posee'   => 'Entree inscrite.',
    'retiree' => 'Entree retiree.',
    'err_reseau' => 'La demande n\'a pas abouti.',
];
