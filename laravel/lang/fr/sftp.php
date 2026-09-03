<?php

/**
 * Acces SFTP/SSH par compte distant — sous-lot D9b.
 *
 * ATTENTION AVANT DE MODIFIER UNE AIDE. Le legacy portait ici des aides JUSTES —
 * « Si ce n'est pas necessaire, decoche : c'est plus sur » — et livrait les trois
 * cases correspondantes COCHEES. L'ecran conseillait l'inverse de ce qu'il
 * livrait.
 *
 * `tests/e2e/go-adm-sftp.mjs` apparie chaque case a SON aide dans le DOM et
 * refuse qu'une aide recommandant de decocher accompagne une case cochee. Une
 * aide reformulee sans que l'etat initial suive fait donc ECHOUER le LOT — c'est
 * voulu.
 */

return [
    'titre'        => 'Acces SFTP par compte distant',
    'intro_titre'  => 'A quoi sert cette page ?',
    'intro'        => 'Vous reglez ici ce qu\'un compte distant a le droit de faire en se connectant '
                      . 'en SSH : transferer des fichiers seulement, ou ouvrir un terminal ; avec ou '
                      . 'sans mot de passe ; avec ou sans tunnels reseau. Le reglage est ecrit sur la '
                      . 'machine dans un bloc dedie a ce compte.',
    'machine'      => 'Machine',
    'compte'       => 'Compte distant',
    'aucun_compte' => 'Aucun compte gere sur cette machine',
    'vide_titre'   => 'Aucun compte a qui regler un acces',
    'vide_texte'   => 'Cette machine n\'a aucun compte au statut « gere » ou « a examiner ». '
                      . 'Lancez un inventaire depuis les comptes distants, puis classez les comptes '
                      . 'concernes.',
    'vide_action'  => 'Ouvrir les comptes distants',

    'options'      => 'Ce que le compte pourra faire en se connectant',

    // ── CE QUE CHAQUE REGLAGE PRODUIT ──────────────────────────────────────
    'f_sftp_only'  => 'Transfert de fichiers uniquement (pas de terminal)',
    'h_sftp_only'  => 'Actif, le compte peut SEULEMENT envoyer et telecharger des fichiers. Il ne peut '
                      . 'pas ouvrir un terminal pour taper des commandes. C\'est ce que « acces SFTP » '
                      . 'veut dire, et c\'est pourquoi ce reglage est actif au depart.',
    'f_chroot'     => 'Cage (dossier racine)',
    'h_chroot'     => 'Le compte ne voit QUE ce dossier et ce qu\'il contient, comme s\'il etait seul '
                      . 'sur la machine. Chemin absolu, sans « .. ». Laisse vide : pas de cage.',
    'f_working'    => 'Dossier d\'arrivee',
    'h_working'    => 'Le dossier ou le compte se trouve en arrivant. N\'a d\'effet qu\'avec le '
                      . 'transfert de fichiers uniquement : en mode terminal, le module ne l\'applique '
                      . 'pas et se contente de l\'inscrire en commentaire.',
    'f_password'   => 'Autoriser la connexion par mot de passe',
    'h_password'   => 'Actif, le compte peut se connecter avec un mot de passe. Inactif, il DOIT '
                      . 'utiliser une cle SSH — nettement plus sur, et c\'est l\'etat de depart.',
    'f_tcp'        => 'Autoriser les tunnels reseau (port forwarding)',
    'h_tcp'        => 'Actif, le compte peut faire passer d\'autres connexions reseau a travers SSH, '
                      . 'par exemple pour atteindre une base de donnees interne depuis l\'exterieur. '
                      . 'Inactif au depart : c\'est plus sur.',
    'f_agent'      => 'Autoriser le rebond de cle (agent forwarding)',
    'h_agent'      => 'Actif, le compte peut reutiliser sa cle SSH pour rebondir de cette machine vers '
                      . 'une autre. Inactif au depart.',
    'f_x11'        => 'Autoriser l\'affichage graphique distant (X11)',
    'h_x11'        => 'Actif, le compte peut ouvrir des fenetres graphiques a travers SSH. Rarement '
                      . 'utile sur un serveur. Inactif au depart.',

    // ── L'ETAT DE DEPART, ET POURQUOI IL EST CELUI-LA ──────────────────────
    'neuve_titre'  => 'Aucun acces n\'est encore regle pour ce compte',
    'neuve_texte'  => 'Les reglages ci-dessous partent de la position la plus fermee : transfert de '
                      . 'fichiers seulement, cle SSH obligatoire, aucun tunnel. Ouvrez ce dont vous '
                      . 'avez besoin, plutot que de refermer ce dont vous n\'avez pas besoin.',
    'ouvre'        => 'Elargit l\'acces',
    'restreint'    => 'Restreint l\'acces',

    // ── LES GESTES ─────────────────────────────────────────────────────────
    'deployer'      => 'Deployer…',
    'auditer'       => 'Auditer',
    'retirer'       => 'Retirer…',
    'aide_deployer' => 'Ecrit le bloc sur la machine, apres validation de la configuration complete.',
    'aide_auditer'  => 'Lit le bloc reellement present sur la machine. Ne modifie rien.',
    'aide_retirer'  => 'Supprime ce bloc de la machine ; le compte retombe sur la configuration '
                       . 'generale du serveur.',

    // ── LA CONFIRMATION, QUI MANQUAIT ──────────────────────────────────────
    'confirmer_titre'   => 'Confirmer le deploiement',
    'confirmer_intro'   => 'Ceci va ecrire un bloc de configuration SSH sur la machine. Ce bloc '
                           . 'REMPLACE, pour ce compte, ce que la configuration generale du serveur '
                           . 'aurait donne. Verifiez avant de valider :',
    'confirmer_machine' => 'Machine',
    'confirmer_compte'  => 'Compte',
    'confirmer_effet'   => 'Ce que cela ouvre',
    'confirmer_ouvre'   => 'Ces reglages ELARGISSENT l\'acces de ce compte',
    'aucun_reglage_ouvert' => 'aucun reglage n\'elargit l\'acces',
    'confirmer_valider' => 'Deployer sur la machine',
    'confirmer_annuler' => 'Annuler',
    'retirer_titre'     => 'Confirmer le retrait',
    'retirer_intro'     => 'Le bloc de ce compte sera supprime de la machine. Le compte retombera sur '
                           . 'la configuration generale du serveur, qui peut etre plus permissive.',
    'retirer_valider'   => 'Retirer de la machine',
    'reauth'            => 'Une re-authentification vous sera demandee avant l\'envoi.',

    // ── L'HISTORIQUE ───────────────────────────────────────────────────────
    'historique'       => 'Historique et restauration',
    'hist_date'        => 'Date',
    'hist_auteur'      => 'Par',
    'hist_etat'        => 'Etat',
    'hist_bloc'        => 'Bloc ecrit',
    'hist_vide'        => 'Aucun deploiement enregistre pour ce compte.',
    'etat_applied'     => 'Applique',
    'etat_rolled_back' => 'Annule',
    'etat_failed'      => 'Echoue',
    'etat_superseded'  => 'Remplace',
    'derniere'         => 'Derniere ecriture',
    'jamais'           => 'jamais deploye',
    'resultat'         => 'Resultat',
    'rollback_titre'   => 'Restaurer une version anterieure',
    'rollback_texte'   => 'L\'annulation d\'un deploiement n\'est pas encore portee. Elle reecrit un '
                          . 'bloc SSH sur la machine, et se fait pour l\'instant depuis l\'ancien portail.',
    'rollback_lien'    => 'Annuler ce deploiement dans l\'ancien portail',
];
