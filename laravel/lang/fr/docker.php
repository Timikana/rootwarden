<?php

/*
 * Inventaire et veille des conteneurs Docker.
 *
 * Le legacy prefixe ses cles JS par `js.docker.` parce que son `head.php`
 * injecte un dictionnaire plat. Ici le fichier est charge d'un bloc par
 * `@json(__('docker'))` : les cles sont donc PLATES, sans prefixe. Le jeu doit
 * rester identique a `lang/en/docker.php` — parite verifiee dans le meme commit.
 */
return [
    'title' => 'Conteneurs Docker',
    'desc'  => 'Détecte les conteneurs Docker de chaque serveur et signale les mises à jour disponibles : côté image (une version plus récente existe sur le registre) et côté git (la stack vient d\'un dépôt en retard, avec le changelog des commits).',

    'machine_libelle' => 'Serveur à scanner',
    'btn_scan_one'    => 'Scanner ce serveur',
    'btn_scan_all'    => 'Scanner tout',
    'tip_scan_one'    => 'Ouvre une session SSH sur le serveur choisi, liste ses conteneurs et compare les empreintes d\'images.',
    'tip_scan_all'    => 'Lance le scan sur TOUS les serveurs non archivés, l\'un après l\'autre — production comprise.',

    // Le guidage dit ce que le geste fait vraiment. Le legacy le presente comme
    // une simple lecture ; ce n'en est pas une.
    'guide_titre'     => 'Ce que font ces boutons',
    'guide_lecture'   => 'La page se charge sans rien scanner : elle affiche le dernier inventaire connu.',
    'guide_scan'      => '« Scanner ce serveur » ouvre une session SSH, lance un `git fetch` dans chaque dépôt de projet compose, et interroge le registre d\'images. Ce n\'est pas une lecture inerte.',
    'guide_scan_tout' => '« Scanner tout » fait la même chose sur TOUS les serveurs non archivés, production comprise.',

    'col_machine'          => 'Serveur',
    'col_container'        => 'Conteneur',
    'col_image'            => 'Image',
    'col_state'            => 'État',
    'col_image_update'     => 'MAJ image',
    'col_git'              => 'Git (stack)',
    'col_checked'          => 'Vérifié le',
    'tip_col_image_update' => 'Compare l\'empreinte de l\'image locale à celle du registre : « MAJ dispo » signifie qu\'une version plus récente existe.',
    'tip_col_git'          => 'Si la stack vient d\'un dépôt git : nombre de commits en retard. Cliquer pour voir le changelog.',

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
    'scan_all_done_simple' => 'Scan de tous les serveurs terminé.',
    'no_docker'            => 'Docker n\'est pas installé sur ce serveur.',
    'err_load'             => 'Impossible de charger l\'inventaire.',
    'err_scan'             => 'Le scan Docker a échoué.',
    // Le legacy n'a pas cet equivalent : son `fetch` non enveloppe n'affiche
    // JAMAIS de message quand le reseau tombe.
    'err_reseau'           => 'Le serveur n\'a pas répondu. Réessayez dans un instant.',
];
