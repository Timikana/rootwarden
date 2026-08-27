<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * La cle de plateforme — sous-lot P1 : la page, ses gardes, ses compteurs.
 *
 * Porte `legacy/adm/platform_keys.php`. P1 ne fait AUCUNE ecriture et n'ouvre
 * aucune session SSH : il lit la base et rend la cle PUBLIQUE. Les lectures
 * distantes sont P2, la migration mot de passe -> cle est P3, la rotation P4.
 *
 * ══ L'EN-TETE DU LEGACY MENT, CINQUIEME OCCURRENCE DU MOTIF E-36 ═════════
 *
 * `platform_keys.php:4` annonce « Acces : superadmin uniquement ». Huit lignes
 * plus bas, `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` admet les
 * TROIS roles, et c'est `checkPermission('can_manage_platform_key')` qui
 * decide. La garde reelle est donc portee telle quelle : `role:1` +
 * `perm:can_manage_platform_key`.
 *
 * Consequence pour toute mesure : **il n'existe aucun chemin de refus par le
 * ROLE sur cette page**. Un role 1 comme un role 2 sont refuses par la
 * PERMISSION. Une suite qui croirait mesurer « le role 1 est refuse »
 * mesurerait la permission — une mesure plus large que la propriete.
 *
 * ══ UNE SEULE CLE, TOUT LE PARC, LES DEUX COMPTES ════════════════════════
 *
 * `ssh_key_manager.py:30` : la paire vit dans UN fichier
 * (`/app/platform_ssh/rootwarden_ed25519`). La meme cle publique sert le compte
 * nominal ET le compte de service `rootwarden`. Il n'existe donc ni « une cle
 * par machine » ni « une cle par compte » : il en existe UNE.
 */
class ClePlateforme
{
    /**
     * Le parc, avec ce que la page a besoin de dire de chaque machine.
     *
     * Aucun filtre de cycle de vie : le legacy n'en pose pas
     * (`platform_keys.php:18`), et la page decrit l'etat de la cle sur toutes
     * les machines connues. Le releve reste fidele.
     */
    public function machines(): array
    {
        return DB::select(
            'SELECT id, name, ip, port, user, online_status, environment, '
            . 'platform_key_deployed, platform_key_deployed_at, ssh_password_required, '
            . 'service_account_deployed, service_account_deployed_at, '
            // ── LES DEUX COLONNES QUE LE LEGACY NE REGARDE PAS ────────────
            //
            // Il compte `ssh_password_required`, un DRAPEAU. On lit aussi le
            // FAIT — les deux colonnes de mot de passe sont-elles vides ? Voir
            // `compteurs()` : les deux ont divergé, et c'est mesurable.
            //
            // On ne rend JAMAIS la valeur, seulement sa presence : ces colonnes
            // sont chiffrees et n'ont aucune raison de traverser un gabarit.
            . "(password <> '') AS a_mot_de_passe, "
            . "(root_password <> '') AS a_mot_de_passe_root "
            . 'FROM machines ORDER BY name'
        );
    }

    /**
     * Les compteurs de la page — et ils comptent le FAIT, pas le DRAPEAU.
     *
     * ══ LE DEFAUT MESURE LE 2026-08-27 ═══════════════════════════════════
     *
     * Le legacy compte « Password supprime » par `! ssh_password_required`
     * (`platform_keys.php:24`). Or ce drapeau n'est ecrit que par
     * `remove_ssh_password` et `reenter_ssh_password` : **la page Serveurs, seul
     * chemin qui REMPLIT `root_password` (`manage_servers.php:136,182`), ne le
     * touche pas.** Restaurer un mot de passe la-bas laisse donc cette page
     * annoncer qu'il est supprime.
     *
     * Mesure du jour, `srv-zabbix` : `ssh_password_required = 0` — donc compte
     * comme « supprime » — alors que `password` ET `root_password` sont TOUS
     * DEUX PRESENTS. Le compteur du legacy est faux d'une machine sur trois.
     *
     * On compte donc les colonnes, et l'ecran DIT quand le drapeau les
     * contredit : les deux portails afficheront des nombres differents, et un
     * exploitant qui les compare doit savoir pourquoi.
     *
     * ══ CE QUE « SANS RETOUR » VEUT DIRE, ET IL SE CALCULE ═══════════════
     *
     * Une machine dont la cle est deployee et dont RootWarden ne detient plus
     * AUCUN mot de passe n'a plus qu'une voie d'acces : cette cle. La rotation
     * (P4) detruit la cle privee sans copie — pour ces machines-la, elle est
     * sans retour. Le nombre est calcule, jamais suppose : aujourd'hui il vaut
     * zero, et il ne doit pas etre ecrit en dur pour autant.
     */
    public function compteurs(array $machines): array
    {
        $vrai = fn ($v) => (bool) ((int) $v);
        $total = count($machines);

        $cle = array_filter($machines, fn ($m) => $vrai($m->platform_key_deployed));
        $compteService = array_filter($machines, fn ($m) => $vrai($m->service_account_deployed));

        // LE FAIT : plus aucun mot de passe connu de RootWarden, ni l'un ni l'autre.
        $sansMotDePasse = array_filter($machines, fn ($m) => ! $vrai($m->a_mot_de_passe)
            && ! $vrai($m->a_mot_de_passe_root));

        // LE DRAPEAU, garde pour pouvoir dire qu'il diverge.
        $drapeauSupprime = array_filter($machines, fn ($m) => ! $vrai($m->ssh_password_required));

        // SANS RETOUR : la cle est le seul acces restant.
        $sansRetour = array_filter($machines, fn ($m) => $vrai($m->platform_key_deployed)
            && ! $vrai($m->a_mot_de_passe) && ! $vrai($m->a_mot_de_passe_root));

        $divergentes = array_filter($machines, fn ($m) => ! $vrai($m->ssh_password_required)
            && ($vrai($m->a_mot_de_passe) || $vrai($m->a_mot_de_passe_root)));

        return [
            'total'            => $total,
            'cle'              => count($cle),
            'compte_service'   => count($compteService),
            'en_attente'       => $total - count($cle),
            'sans_mot_de_passe' => count($sansMotDePasse),
            'drapeau_supprime' => count($drapeauSupprime),
            'sans_retour'      => count($sansRetour),
            'divergentes'      => count($divergentes),
            'noms_divergentes' => array_values(array_map(fn ($m) => $m->name, $divergentes)),
            'noms_sans_retour' => array_values(array_map(fn ($m) => $m->name, $sansRetour)),
            // La barre de progression : deux segments, en POURCENTAGE d'un total
            // qui peut valoir zero — un parc vide ne divise pas.
            'pct_cle'          => $total > 0 ? (int) round(count($cle) / $total * 100) : 0,
            'pct_sans_mdp'     => $total > 0 ? (int) round(count($sansMotDePasse) / $total * 100) : 0,
        ];
    }

    /**
     * L'etat d'authentification d'une machine, en TROIS valeurs.
     *
     * Le legacy rend trois pastilles (`keypair`, `keypair + pwd`, `password`)
     * calculees sur le drapeau. Ici elles se calculent sur le FAIT, pour la
     * meme raison que les compteurs.
     */
    public function etatAuth(object $m): string
    {
        $cle = (bool) ((int) $m->platform_key_deployed);
        $mdp = ((int) $m->a_mot_de_passe) || ((int) $m->a_mot_de_passe_root);

        if ($cle && ! $mdp) {
            return 'cle_seule';
        }

        return $cle ? 'cle_et_mot_de_passe' : 'mot_de_passe_seul';
    }

    /** `PROD` ou `CRITIQUE`, et une valeur inconnue compte comme sensible. */
    public function estSensible(object $m): bool
    {
        $env = strtoupper(trim((string) ($m->environment ?? '')));

        return $env === 'PROD' || $env === 'OTHER' || $env === '';
    }
}
