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
    'export_detail_purge'     => "Detail purge par la retention : seuls les compteurs de ce scan sont conserves.",

    // Sous-lot S3 : la consultation des resultats CVE.
    'titre'                   => 'Scan de vulnerabilites CVE',
    'description'             => "Résultats du dernier scan de chaque serveur qui vous est attribué.",
    'section_resume'          => 'Resume du parc',
    'section_serveurs'        => 'Serveurs',
    'serveurs_scannes'        => 'Serveurs scannes',
    'tuile_scannes_aide'      => 'parmi ceux qui vous sont accessibles',
    'total_cve'               => 'Vulnerabilites au total',
    'tuile_total_aide'        => 'somme des derniers scans',
    'critiques'               => 'Critiques',
    'hautes'                  => 'Elevees',
    'moyennes'                => 'Moyennes',
    'jamais_scanne'           => 'Jamais scanne',
    'jamais_scanne_aide'      => 'Aucun scan termine pour ce serveur. Le bouton « Scanner » en lance un.',
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
    'comparer'                => 'Comparer',
    'comparer_aide'           => 'Comparer les deux derniers scans termines',
    'comparaison_titre'       => 'Comparaison des deux derniers scans',
    'comparaison_insuffisante' => "Un seul scan terminé pour ce serveur : la comparaison en demande deux.",
    'comparaison_ajoutees'    => 'Nouvelles',
    'comparaison_corrigees'   => 'Corrigees',
    'comparaison_inchangees'  => 'Inchangees',
    'comparaison_identique'   => 'Aucune difference entre les deux scans.',
    'fermer'                  => 'Fermer',
    'erreur_chargement'       => 'Le detail des vulnerabilites n’a pas pu etre affiche.',
    'chargement'              => 'Chargement du detail...',
    'filtre_invalide'         => 'Filtre de recherche invalide.',
    'erreur_comparaison'      => 'La comparaison n’a pas pu etre obtenue.',
    'machine_invalide'        => 'Serveur inconnu ou non accessible.',
    'aucun_serveur'           => 'Aucun serveur ne vous est attribue.',
    'aucun_serveur_aide'      => "Demandez à un administrateur de vous attribuer un serveur.",
    'export_csv'              => 'Exporter en CSV',
    // ── Enrichissement EPSS / KEV — sous-lot S6 ─────────────────────────────
    'tri_explication' => "Les vulnérabilités activement exploitées (KEV) sont classées en tête.",
    'blanchie' => "Liste blanche",
    'blanchie_aide' => "En liste blanche : enregistrée, mais absente des compteurs, des notifications et des tickets.",
    'kev_aide' => 'Activement exploitee — catalogue CISA des vulnerabilites exploitees connues',
    'kev_depuis' => 'au catalogue depuis le :date',
    'epss_aide' => "EPSS : probabilite d'exploitation dans les 30 jours",
    'priorite_aide' => 'priorite :libelle',
    'non_enrichi' => 'EPSS inconnu',
    'reprio' => 'Rafraichir EPSS / KEV',
    'reprio_aide' => "Interroge FIRST.org et le catalogue CISA pour recalculer la priorité",
    'reprio_confirmer_titre' => "Rafraichir l'enrichissement EPSS / KEV ?",
    'reprio_avertissement' => "Réécrit la priorité des :nombre vulnérabilités du dernier scan, sans retour en arrière. Une coupure réseau peut laisser l'enrichissement incomplet.",
    'reprio_confirmer' => 'Rafraichir',
    'reprio_annuler' => 'Annuler',
    'reprio_encours' => 'Rafraichissement EPSS / KEV en cours...',
    'reprio_ok' => 'Enrichissement rafraichi — :kev exploitees connues, :epss scores EPSS mis a jour',
    'reprio_echec' => "Le rafraichissement de l'enrichissement a echoue",
    // ── Le scan (sous-lot S7a) ──────────────────────────────────────────────
    'scan' => 'Scanner',
    'scan_aide' => "Recherche les vulnerabilites des paquets installes sur ce serveur",
    'scan_en_cours' => 'Scan en cours...',
    'scan_confirmer_titre' => 'Lancer un scan de vulnerabilites sur :nom ?',
    'scan_avertissement' => "Ouvre une session SSH sur la machine, en lecture seule. Le scan peut durer plusieurs minutes, remplace le résultat affiché et envoie un rapport par courriel si des CVE sont trouvées.",
    'scan_seuil' => 'Seuil CVSS',
    'scan_source' => 'Source des donnees',
    'scan_source_fast' => 'Rapide',
    'scan_source_hybrid' => 'Hybride — recommande',
    'scan_source_precise' => 'Precise',
    'scan_confirmer' => 'Lancer le scan',
    'scan_annuler' => 'Annuler',
    'scan_demarre' => 'Initialisation...',
    'scan_paquet' => ':paquet (:courant/:total)',
    'scan_termine' => 'Scan termine : :paquets paquets, :cve CVE',
    'scan_erreur' => 'Le scan a echoue : :message',
    'scan_refuse' => 'Le scan a ete refuse par le serveur (code :statut)',
    'scan_interrompu' => "Le flux du scan s'est interrompu sans conclusion : le resultat est incertain",
];
