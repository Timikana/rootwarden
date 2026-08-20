<?php

/**
 * Module `security/` — vulnerabilites.
 *
 * Sous-lot S1 : export CSV d'un scan. Les libelles du fichier exporte sont ici
 * et non dans le controleur : une chaine ecrite en dur echappe a la parite
 * FR/EN, et un rapport exporte se lit dans la langue de qui l'exporte.
 */

return [
    // Refus
    'export_parametre_requis'  => 'machine_id ou scan_id requis',
    'export_scan_introuvable'  => 'Aucun scan trouve',

    // Metadonnees en tete du fichier
    'export_titre'        => 'Rapport CVE - :machine',
    'export_date'         => 'Date du scan : :date',
    'export_paquets'      => 'Paquets scannes : :nombre',
    'export_seuil'        => 'Seuil CVSS : :seuil',
    'export_repartition'  => 'Critical : :critical | High : :high | Medium : :medium | Low : :low',

    // En-tete du tableau
    'col_cve'       => 'CVE ID',
    'col_paquet'    => 'Package',
    'col_version'   => 'Version',
    'col_cvss'      => 'CVSS',
    'col_severite'  => 'Severite',
    'col_resume'    => 'Resume',

    // Etat vide : il DIT sur quoi il porte, plutot que de rendre un tableau nu.
    'export_aucune' => 'Aucune vulnerabilite trouvee au-dessus du seuil configure',

    // Sous-lot S3 : la consultation des resultats CVE.
    'titre'                   => 'Scan de vulnerabilites CVE',
    'description'             => 'Resultats du dernier scan de chaque serveur autorise. Cette page est en lecture seule.',
    'section_resume'          => 'Resume du parc',
    'section_serveurs'        => 'Serveurs',
    'serveurs_scannes'        => 'Serveurs scannes',
    'tuile_scannes_aide'      => 'parmi ceux qui vous sont accessibles',
    'total_cve'               => 'Vulnerabilites au total',
    'tuile_total_aide'        => 'somme des derniers scans',
    'critiques'               => 'Critiques',
    'hautes'                  => 'Elevees',
    'moyennes'                => 'Moyennes',
    'tuile_critiques_aide'   => 'a corriger en premier',
    'tuile_hautes_aide'      => 'a traiter ensuite',
    'tuile_moyennes_aide'    => 'a planifier',
    'jamais_scanne'           => 'Jamais scanne',
    'jamais_scanne_aide'      => 'Aucun scan termine pour ce serveur. Le declenchement d’un scan reste sur l’ancien portail.',
    'dernier_scan'            => 'Scan',
    'paquets_scannes'         => 'paquets analyses',
    'seuil_du_scan'           => 'seuil CVSS',
    'voir_details'            => 'Cliquer pour voir le detail',
    'replier'                 => 'Replier le detail',
    'nb_cve'                  => ':nombre CVE',
    'col_suivi'               => 'Suivi',
    'filtre_severite'         => 'Severite :',
    'filtre_annee'            => 'Annee :',
    'filtre_toutes'           => 'Toutes',
    'filtre_tout'             => 'Tout',
    'recherche'               => 'Rechercher un CVE ou un paquet...',
    'affiche_sur'             => 'Affiche :montre sur :total',
    'voir_plus'               => 'Voir plus',
    'aucune_cve'              => 'Aucune vulnerabilite au-dessus du seuil configure.',
    'aucun_resultat'          => 'Aucune vulnerabilite ne correspond a cette recherche.',
    'suivi_a_venir'           => 'Le suivi d’une vulnerabilite reste sur l’ancien portail.',
    'comparer'                => 'Comparer',
    'comparer_aide'           => 'Comparer les deux derniers scans termines',
    'comparaison_titre'       => 'Comparaison des deux derniers scans',
    'comparaison_insuffisante' => 'Un seul scan termine pour ce serveur : il n’y a rien a comparer. La comparaison demande deux scans.',
    'comparaison_ajoutees'    => 'Nouvelles',
    'comparaison_corrigees'   => 'Corrigees',
    'comparaison_inchangees'  => 'Inchangees',
    'comparaison_identique'   => 'Aucune difference entre les deux scans.',
    'fermer'                  => 'Fermer',
    'erreur_chargement'       => 'Le detail des vulnerabilites n’a pas pu etre affiche.',
    'erreur_comparaison'      => 'La comparaison n’a pas pu etre obtenue.',
    'machine_invalide'        => 'Serveur inconnu ou non accessible.',
    'aucun_serveur'           => 'Aucun serveur ne vous est attribue.',
    'aucun_serveur_aide'      => 'Un administrateur doit vous attribuer au moins un serveur pour que cette page ait un contenu.',
    'export_csv'              => 'Exporter en CSV',
    'scan_ancien_portail'     => 'Declencher un scan reste sur l’ancien portail',
];
