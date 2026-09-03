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

    /*
     * ══ R4 — LA SUPPRESSION D'UN GROUPE EST PORTEE ════════════════════════
     *
     * `np_supprimer` est RETIREE. `np_supprimer_detail` NE BOUGE PAS — et
     * c'est celle qui compte le plus : elle porte le FAIT RASSURANT.
     *
     * > La peur qu'aura la personne devant l'ecran est « est-ce que je detruis
     * > mes machines ». La reponse est NON, et le panneau doit la donner —
     * > sinon il fait hesiter sur le mauvais objet.
     *
     * Meme principe que F8 : porter le fait rassurant autant que le fait
     * alarmant. Un panneau qui n'annonce que le risque fait renoncer a un
     * geste sur.
     *
     * MESURES REFAITES plutot que relayees :
     *   DELETE /groups/<id>   require_api_key + require_role(2)
     *                         + require_permission('can_admin_portal')
     *   055_machine_groups.sql:30-31   ON DELETE CASCADE sur group_id ET
     *                                  machine_id — le commentaire du backend
     *                                  dit vrai
     *   group_id hors groups.py : 0 fichier   (temoin : 18 dedans)
     *   scheduler.py, target_type 'group' : 0 — aucune planification ne
     *                                  viserait un groupe, donc aucune
     *                                  reference pendante apres coup
     *
     * ⚠ ET LE VERDICT N'EST PAS `success`. La route rend
     * `{'success': True, 'deleted': rowcount > 0}` : elle repond « success »
     * meme quand elle n'a rien supprime. `supprimer_introuvable` existe pour
     * ce cas — le marqueur n'est pas le verdict.
     */
    'supprimer_titre'      => 'Supprimer ce groupe ?',
    'supprimer_membres'    => 'Ce groupe rassemble :n serveur(s) aujourd\'hui.',
    'supprimer_definitif'  => 'Cette suppression ne se défait pas : le groupe et ses appartenances disparaissent, et il faudra le recréer.',
    'supprimer_valider'    => 'Supprimer le groupe',
    'supprimer_fait'       => 'Le groupe « :nom » est supprimé. Les serveurs qu\'il rassemblait n\'ont pas été modifiés.',
    'supprimer_introuvable' => 'Aucun groupe n\'a été supprimé : « :nom » n\'existait plus. La liste est rechargée.',
    'supprimer_echec'      => 'Le groupe n\'a pas pu être supprimé. :message',
    'np_supprimer_detail' => "La suppression ne touche que le groupe : les serveurs qu'il rassemble ne sont pas modifiés.",

    // ══ R3 — LE SCAN DE DERIVE DE MASSE, PORTE ══════════════════════════
    //
    // `np_derive` et `np_derive_detail` sont RETIREES : la premiere declarait
    // une absence qui n'existe plus, la seconde decrivait le geste pour
    // expliquer pourquoi on renvoyait ailleurs. Son contenu reste — il est
    // exact et il rassure a bon droit — mais sous un nom qui ne dit plus
    // « pas porte ».
    //
    // `np_cve` et ses satellites NE BOUGENT PAS : le scan CVE ouvre une
    // session SSH par machine et envoie un courriel par machine a resultats.
    // Il reste hors de cette interface, et cette declaration reste vraie.
    'der_titre'  => 'Lancer un scan de dérive',
    'der_texte'  => "Ce geste n'ouvre AUCUNE session SSH : il relit des données déjà en base et met à jour le relevé de dérive de chaque membre. Le planificateur fait déjà le même travail toutes les heures sur l'ensemble du parc.",
    'der_lancer' => 'Lancer le scan de dérive',

    // LE NOMBRE ANNONCE EST LE NOMBRE RESOLU, jamais le nombre attendu. Un
    // groupe dont TOUS les filtres ont ete rejetes par `_sanitize_filters` se
    // stocke en `{}` — le meme objet qu'un groupe sans critere, donc `1=1`,
    // donc le parc entier. Seul le nombre resolu distingue « je scanne mes
    // trois serveurs de test » de « je scanne tout ».
    //
    // Ces trois libelles disent la meme chose que `np_cve_membres`,
    // `np_cve_prod` et `np_cve_derive`. Ils sont VOLONTAIREMENT distincts :
    // unifier demanderait de toucher le panneau du scan CVE, qui doit rester
    // en place. A unifier quand ce panneau sera porte — il sera reecrit.
    'resolu_nombre'   => "Ce groupe résout :n serveur(s) aujourd'hui.",
    'resolu_prod'     => "⚠ La production en fait partie : :noms.",
    'resolu_reresolu' => "Le nombre affiché est celui d'aujourd'hui. Un groupe dynamique est ré-résolu au moment du lancement : une machine ajoutée au parc entre-temps entrerait dans le geste sans avoir jamais été affichée ici.",

    // ⚠ SANS PORTEE ANNONCEE, PAS DE CONFIRMATION OFFERTE. Un panneau qui ne
    // sait pas sur combien de machines il porte ne peut pas faire consentir :
    // le bouton reste absent, et la raison est dite.
    'der_illisible' => "La portée n'a pas pu être lue : impossible de dire sur combien de serveurs ce scan porterait. Le lancement n'est donc pas proposé.",
    'der_vide'      => "Ce groupe ne résout aucun serveur aujourd'hui : un scan ne relèverait rien.",
    'der_lance'     => ':n serveur(s) mis en file. Le suivi se fait dans le centre de tâches.',
    'der_echoue'    => "Le scan de dérive n'a pas pu être lancé. :message",

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
    'portee_texte' => "La lecture des groupes, de leurs membres, la création et le scan de dérive de masse sont portés. La suppression et le scan CVE de masse passent encore par l'ancien portail — chaque bouton explique ce qu'il engage avant d'y renvoyer.",
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
