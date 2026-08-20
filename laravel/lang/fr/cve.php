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
];
