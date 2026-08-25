<?php

/**
 * Journal d'audit — module `adm/`, sous-lot D1. Français.
 *
 * Libellés repris du legacy, avec les ACCENTS rétablis : il écrit « Historique
 * de toutes les actions effectuees ». Une amélioration d'affichage, sans effet
 * sur le comportement.
 *
 * `entries_total` porte un GABARIT, et il est substitué. Le legacy affiche
 * « 4 179 :count entrees au total » : sa clé porte le même gabarit, mais sa
 * fonction `t()` ne remplace rien, en français comme en anglais. Voir PARITE
 * E-105.
 *
 * Parité stricte avec lang/en/audit.php.
 */
return [

    'title' => "Journal d'audit",
    'desc' => "Historique de toutes les actions effectuées sur la plateforme, scellé par une chaîne de hachage. Filtrez par utilisateur, action ou date.",
    'entries_total' => ':nombre entrées au total',
    'filtered' => 'filtré',

    // Colonnes
    'col_id' => 'ID',
    'col_date' => 'Date',
    'col_utilisateur' => 'Utilisateur',
    'col_action' => 'Action',

    // Filtres
    'filter_user' => 'Utilisateur',
    'filter_action' => 'Action',
    'filter_from' => 'Depuis le',
    'filter_to' => "Jusqu'au",
    'placeholder_name' => 'Nom…',
    'placeholder_action' => 'Connexion, Création, Suppression…',
    'filtrer' => 'Filtrer',
    'reinitialiser' => 'Réinitialiser',

    'empty' => 'Aucune entrée ne correspond',
    'empty_aide' => 'Élargissez la période ou videz les filtres.',

    // Pagination
    'pagination' => 'Pages du journal',
    'page_sur' => 'Page :page sur :total',
    'precedent' => 'Précédent',
    'suivant' => 'Suivant',

    // Export
    'btn_export_csv' => 'Exporter CSV',
    'export_hint' => "Exporte TOUS les résultats filtrés, pas seulement la page affichée.",

    // Intégrité de la chaîne
    'btn_verify' => "Vérifier l'intégrité",
    'btn_verify_tip' => "Recalcule la chaîne de hachage et signale la première incohérence. Lecture seule : rien n'est écrit.",
    'btn_seal' => 'Sceller les orphelines',
    'btn_seal_tip' => "Rattache à la chaîne les lignes insérées sans scellement. IRRÉVERSIBLE : une ligne scellée ne se descelle pas.",

    'verif_en_cours' => "Vérification de la chaîne en cours…",
    'chaine_intacte' => "Chaîne intacte : :scellees lignes scellées, :orphelines non scellées, tête = :tete",
    'chaine_rompue' => "Incohérence à la ligne #:ligne (:type) : attendu :attendu, trouvé :trouve. Aucune écriture n'a eu lieu.",

    'sceller_titre' => ":nombre lignes seraient rattachées à la chaîne. L'opération est irréversible.",
    'sceller_consigne' => 'Pour confirmer, saisissez le nombre :nombre',
    'sceller_rien' => "Aucune ligne orpheline : la chaîne est déjà complète.",
    'sceller_en_cours' => 'Opération en cours…',
    'sceller_fait' => ':scellees lignes scellées sur :sur. Nouvelle tête de chaîne = :tete',
    'sceller_refus' => "Scellement annulé. Rien n'a été écrit.",
    'err_confirmation' => "Le nombre saisi ne correspond pas aux :attendu lignes concernées. Rien n'a été écrit.",
    'err_reseau' => "Le portail n'a pas répondu (statut :statut). Rien n'a été écrit.",

    'annuler' => 'Annuler',
    'confirmer' => 'Sceller',
];
