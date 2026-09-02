<?php

/*
 * Groupes de machines et actions de masse.
 *
 * Cles PLATES : le fichier est charge d'un bloc par `@json(__('groups'))`, et
 * Laravel espace deja par fichier — le prefixe `groups.` du legacy disparait
 * donc, et les cles `js.` fusionnent avec les autres. Le jeu de cles doit
 * rester identique a `lang/en/groups.php`.
 */
return [
    'titre' => 'Groupes et actions de masse',
    'desc'  => "Regroupez vos serveurs par règle dynamique (environnement, criticité, réseau, cycle de vie, tags) ou par liste statique, puis lancez des opérations groupées suivies dans le centre de tâches.",

    'chargement' => 'Chargement…',
    'vide_titre'  => 'Aucun groupe',
    'vide_texte'  => "Aucun groupe n'existe pour l'instant. Un groupe rassemble des serveurs, puis sert de cible à une action de masse.",
    'err_charge'  => "La liste des groupes n'a pas pu être lue.",

    'membres'       => 'Membres',
    'type_dynamique' => 'Dynamique',
    'type_statique'  => 'Statique',
    'cree_par'      => 'Créé par',
    'cree_le'       => 'Créé le',
    // ── E-274 : LE LEGACY AFFICHE UNE LIGNE BLANCHE POUR CE CAS ───────────
    // `filtersSummary({})` rend la chaine vide. Or `_resolve_dynamic`
    // (`groups.py:77`) termine par `'1=1'` quand aucun critere n'est coche :
    // le groupe contient alors LE PARC ENTIER, production comprise. Le dire.
    'sans_filtre'   => 'aucun filtre — toutes les machines du parc',
    'membres_aucun' => 'Aucun serveur ne correspond à ce groupe.',
    'membres_err'   => "Les membres de ce groupe n'ont pas pu être lus.",

    'act_membres'  => 'Voir les membres',
    'act_masquer'  => 'Masquer les membres',
    'act_derive'   => 'Scan de dérive',
    'act_cve'      => 'Scan CVE',
    'act_supprimer' => 'Supprimer',
    'act_nouveau'  => 'Nouveau groupe',

    'aide_membres' => 'Affiche les serveurs que ce groupe résout en ce moment.',

    // ══ LES PANNEAUX DES CAPACITES NON PORTEES ═══════════════════════════
    // R1 ne porte que la LECTURE. Chaque geste absent ouvre un panneau qui
    // dit ce qu'il engage, plutot qu'un bouton qui ne fait rien.
    // UN PANNEAU PARTAGE DOIT NOMMER SA CIBLE. Il vit au niveau de la PAGE
    // et sert quatre boutons de cartes differentes : sans cette ligne, il
    // decrit un geste sans dire sur quoi il porte — vu a l'image.
    'np_sur_groupe' => 'Groupe visé : :nom',
    'np_titre'      => 'Pas encore porté',
    'np_ouvrir'     => "Ouvrir dans l'ancien portail",
    'np_fermer'     => 'Fermer',

    'np_supprimer'  => 'La suppression de groupe n’est pas encore portée sur cette interface.',
    'np_supprimer_detail' => "La suppression ne touche que le groupe : les serveurs qu'il rassemble ne sont pas modifiés.",

    'np_derive'     => "Le scan de dérive de masse n'est pas encore porté sur cette interface.",
    'np_derive_detail' => "Ce geste n'ouvre AUCUNE session SSH : il relit des données déjà en base et met à jour le relevé de dérive de chaque membre. Le planificateur fait déjà le même travail toutes les heures sur l'ensemble du parc.",

    'np_cve'        => "Le scan CVE de masse n'est pas encore porté sur cette interface.",
    // ⚠ LE PANNEAU LE PLUS IMPORTANT DU MODULE. Un clic, N machines, et pour
    // CHACUNE : une session SSH reelle, un courriel, une notification, un
    // webhook. Le `confirm()` du legacy ne nomme ni le nombre, ni les
    // machines, ni la production, ni la difference avec le scan de derive.
    'np_cve_detail' => "Ce geste ouvre une session SSH réelle sur CHAQUE membre du groupe, et chaque machine dont le scan aboutit déclenche l'envoi d'un rapport par courriel. Ce n'est pas une lecture : c'est autant de connexions et d'envois que le groupe compte de serveurs.",
    'np_cve_membres' => "Ce groupe résout :n serveur(s) aujourd'hui.",
    'np_cve_prod'   => "⚠ La production en fait partie : :noms.",
    'np_cve_derive' => "Le nombre affiché est celui d'aujourd'hui. Un groupe dynamique est ré-résolu au moment du lancement : une machine ajoutée au parc entre-temps entrerait dans le geste sans avoir jamais été affichée ici.",

    // ── CE QUE LA PAGE DIT D'ELLE-MEME ────────────────────────────────────
    'portee_titre' => 'Ce que cette page peut faire aujourd’hui',
    // ⚠ R2 : cette phrase disait que la CREATION passait par l'ancien portail.
    // Elle est devenue fausse au moment ou R2 l'a portee — le meme mecanisme
    // que `pare-feu`, `superv` et l'encart des CGU, et je l'aurais livre.
    // Un libelle se relit avec le code qu'il decrit, dans le MEME commit.
    'portee_texte' => "La lecture des groupes, de leurs membres et la création sont portées. La suppression et les deux actions de masse passent encore par l'ancien portail — chaque bouton explique ce qu'il engage avant d'y renvoyer.",
    'parc_entier'  => "Un rôle administrateur peut viser l'ensemble du parc : aucune attribution de machine ne borne les actions de masse.",

    // ══ R2 — LA CREATION D'UN GROUPE ═════════════════════════════════════
    'form_titre' => 'Nouveau groupe',
    'f_nom' => 'Nom',
    'f_desc' => 'Description',
    'f_type' => 'Comment les membres sont choisis',
    'type_dyn_aide' => "Par règle : les machines correspondant aux critères entrent et sortent d'elles-mêmes.",
    'type_stat_aide' => 'Par liste : vous désignez les machines une par une.',
    'f_env' => 'Environnement',
    'f_crit' => 'Criticité',
    'f_reseau' => 'Réseau',
    'f_cycle' => 'Cycle de vie',
    'f_membres' => 'Machines du groupe',
    'btn_enregistrer' => 'Enregistrer',
    'btn_annuler' => 'Annuler',
    /*
     * ⚠ E-274 FERME PAR CONSTRUCTION.
     *
     * `_resolve_dynamic` (`groups.py:77`) termine par `'1=1'` quand aucun
     * critere n'est coche : le groupe contient alors LE PARC ENTIER. Et
     * l'etat par DEFAUT du formulaire du legacy est exactement celui-la —
     * saisir un nom et enregistrer suffit, sans qu'aucun ecran ne le dise.
     *
     * Ici l'enregistrement passe par le panneau de decision, qui ANNONCE la
     * portee resolue. On ne peut donc plus creer un groupe sans avoir lu ce
     * qu'il contiendra.
     */
    'portee_aucun_filtre' => "Aucun critère n'est coché : ce groupe contiendra TOUTES les machines du parc, production comprise.",
    'portee_filtres' => 'Critères retenus : :liste',
    'portee_statique' => ':n machine(s) désignée(s).',
    'portee_statique_vide' => "Aucune machine désignée : le groupe sera vide.",
    'portee_archivees' => "Le calcul du parc côté serveur n'exclut pas les machines archivées : un groupe sans critère peut en contenir.",
    'err_nom' => 'Un nom est nécessaire.',
    'cree' => 'Groupe créé.',
    'err_creation' => "Le groupe n'a pas pu être créé.",
];
