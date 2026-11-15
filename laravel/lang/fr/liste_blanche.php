<?php

/*
 * Liste blanche des CVE — faux positifs acceptes.
 *
 * Portage a ISO-PERIMETRE de `legacy/security/index.php`, dont les trois routes
 * backend etaient restees vivantes sans ecran pour les atteindre.
 */

return [
    'titre'       => 'Liste blanche des CVE',
    'description' => "Faux positifs acceptés, avec motif, auteur et échéance. Ces entrées ne masquent pas les CVE dans les résultats de scan ni dans les rapports.",

    // ── Le formulaire ────────────────────────────────────────────────────
    'champ_cve'        => 'Identifiant CVE',
    'champ_cve_aide'   => "Forme CVE-2024-1234.",
    'champ_motif'      => 'Motif',
    'champ_motif_aide' => "Pourquoi ce signalement est un faux positif.",
    'champ_machine'      => 'Machine',
    'champ_machine_aide' => "« Toutes les machines » accepte la CVE sur tout le parc.",
    'machine_toutes'     => 'Toutes les machines (global)',
    'champ_expiration'   => "Échéance",
    'champ_sans_expiration' => "Sans échéance",
    'champ_expiration_aide' => "Une date, ou cochez « sans échéance ».",
    'poser'    => 'Inscrire',
    'retirer'  => 'Retirer',
    'confirmer_retrait' => "Retirer cette entrée ?",

    // ── Le tableau ───────────────────────────────────────────────────────
    'col_cve'     => 'CVE',
    'col_portee'  => "Portée",
    'col_motif'   => 'Motif',
    'col_auteur'  => 'Inscrite par',
    'col_echeance' => "Échéance",
    'col_pose'    => 'Inscrite le',
    'portee_globale' => 'Tout le parc',
    'sans_echeance'  => 'Aucune',
    'echue'          => "Échue",
    'vide'           => 'Aucune CVE en liste blanche.',

    // ── Les refus, un par motif rendu par le service ─────────────────────
    'err_cve_requis'    => 'L\'identifiant CVE est requis.',
    'err_cve_malforme'  => 'Forme attendue : CVE-2024-1234.',
    'err_motif_requis'  => "Le motif est requis.",
    'err_motif_trop_long' => "Le motif dépasse 500 caractères.",
    'err_machine_inconnue' => 'Cette machine n\'existe pas.',
    'err_expiration_a_decider' => "Posez une échéance, ou cochez « sans échéance ».",
    'err_expiration_contradictoire' => "Une date et « sans échéance » : choisissez l'un des deux.",
    'err_date_malformee' => 'Date attendue au format AAAA-MM-JJ.',
    'err_date_passee'    => "Cette échéance est déjà passée.",
    'err_introuvable'    => "Cette entrée n'existe pas ou plus.",

    // ── Les annonces ─────────────────────────────────────────────────────
    'posee'   => "Entrée inscrite.",
    'retiree' => "Entrée retirée.",
    'err_reseau' => 'La demande n\'a pas abouti.',
];
