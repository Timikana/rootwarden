<?php

/*
 * Inventaire et veille des conteneurs Docker. Cles PLATES : le fichier part d'un
 * bloc par `@json(__('docker'))`. Regles de redaction : docs/REDACTION-INTERFACE.md.
 */
return [
    'title' => 'Conteneurs Docker',
    'desc'  => "Conteneurs Docker de chaque serveur et mises à jour disponibles : image plus récente sur le registre, ou stack git en retard.",

    'machine_libelle' => 'Serveur à scanner',
    'btn_scan_one'    => 'Scanner ce serveur',
    'btn_scan_all'    => 'Scanner tout',
    'tip_scan_one'    => "Liste les conteneurs du serveur choisi et compare les empreintes d'images.",
    'tip_scan_all'    => 'Scanne tous les serveurs non archivés, l\'un après l\'autre.',

    'guide_scan'      => "Un scan ouvre une session SSH et lance un git fetch dans chaque projet compose. « Scanner tout » vise tous les serveurs, production comprise.",

    'col_machine'          => 'Serveur',
    'col_container'        => 'Conteneur',
    'col_image'            => 'Image',
    'col_state'            => 'État',
    'col_image_update'     => 'MAJ image',
    'col_git'              => 'Git (stack)',
    'col_checked'          => 'Vérifié le',
    'tip_col_image_update' => "« MAJ dispo » : une image plus récente existe sur le registre.",
    'tip_col_git'          => 'Commits de retard du dépôt git de la stack. Cliquer pour voir le changelog.',

    'loading'          => 'Chargement…',
    'empty'            => 'Aucun conteneur connu. Lancez un scan.',
    'up_to_date'       => 'À jour',
    'update_available' => 'MAJ dispo',
    'update_hint'      => 'Une version plus récente de cette image existe sur le registre.',
    'unknown'          => 'Inconnu',
    'commits_behind'   => ':n commit(s) en retard',

    'sum_containers'   => 'Conteneurs',
    'sum_machines'     => 'Serveurs',
    'sum_img_updates'  => 'MAJ image disponibles',
    'sum_git_updates'  => 'Stacks git en retard',

    'scanning'             => 'Scan Docker en cours…',
    'scanning_all'         => 'Scan Docker de tous les serveurs…',
    'scan_done'            => 'Scan Docker terminé.',
    // ── LE BILAN EST CHIFFRE, ET IL NOMME LES ECHECS ─────────────────
    // `POST /docker/scan_all` rend un FLUX JSON-lines en `text/plain` : le 200
    // part AVANT que le premier scan ne tourne. Un verdict tire du statut HTTP
    // annonce donc une reussite meme si toutes les machines ont echoue.
    'scan_all_done_simple' => 'Scan terminé : :ok réussi(s) sur :total serveur(s) rapporté(s).',
    'scan_all_interrompu' => "Le flux s'est interrompu : :ok réussi(s) et :echecs échec(s) rapportés, les serveurs suivants n'ont pas été traités. Rechargez la page pour lire l'état réel.",
    'scan_all_sans_fin' => "Ce nombre compte les serveurs qui ont répondu, pas tout le parc : une interruption ne se distingue pas d'une fin normale. Rechargez la page pour lire l'état de chaque serveur.",
    'scan_all_echecs'      => ':n serveur(s) en échec : :noms',
    'scan_all_illisible'   => "Le scan a été lancé, mais son compte rendu est illisible. Rechargez la page pour lire l'état réel.",
    'scan_all_aucun'       => "Le scan n'a rendu aucun compte rendu : aucun serveur traité, ou flux interrompu avant la première réponse.",
    'no_docker'            => 'Docker n\'est pas installé sur ce serveur.',
    'err_load'             => 'Impossible de charger l\'inventaire.',
    'err_scan'             => 'Le scan Docker a échoué.',
    'err_reseau'           => 'Le serveur n\'a pas répondu. Réessayez dans un instant.',
];
