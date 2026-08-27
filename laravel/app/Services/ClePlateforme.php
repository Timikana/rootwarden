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
            //
            // `IS NOT NULL AND <> ''` ET NON LE SEUL `<> ''`. Une comparaison
            // avec une colonne NULL rend NULL, pas 0. Aucune machine n'a de
            // colonne nulle aujourd'hui — mesure — et PHP traite NULL comme
            // faux, donc le resultat serait juste. Mais ce booleen peut un jour
            // partir en JSON vers le navigateur, ou `null` et `0` ne sont pas la
            // meme valeur. Motif deja employe par `Supervision.php:272` pour
            // `tls_psk_value` : on s'y aligne plutot que d'en inventer un second.
            . "(password IS NOT NULL AND password <> '') AS a_mot_de_passe, "
            . "(root_password IS NOT NULL AND root_password <> '') AS a_mot_de_passe_root "
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

    /**
     * ══ P3 — LES PORTEES DES GESTES QUI ECRIVENT ═════════════════════════
     *
     * Chaque geste de masse porte sa PROPRE liste, et le nombre annonce sur le
     * bouton est celui de CETTE liste. Le legacy en avait deux, et elles ne
     * concordaient pas.
     *
     * Mesure du 2026-08-27, `platform_keys.php:61` : le bouton d'effacement de
     * masse affiche `$nbDeployed - $nbPasswordRemoved`, ou `$nbPasswordRemoved`
     * compte `! ssh_password_required` sur TOUT le parc — machines sans cle
     * incluses. La liste sur laquelle il agit (`:329`) exige en plus
     * `platform_key_deployed`. Les deux predicats different : une machine qui
     * n'a jamais commence la migration DIMINUE le nombre affiche sans sortir de
     * la liste. Le compte annonce et le compte agi peuvent donc differer.
     *
     * Ici une portee est un tableau `['ids' => int[], 'noms' => string[],
     * 'sensibles' => string[]]`. Le nombre est `count($p['ids'])`, point.
     */
    private function portee(array $machines, callable $predicat): array
    {
        $retenues = array_values(array_filter($machines, $predicat));

        return [
            'ids'       => array_map(fn ($m) => (int) $m->id, $retenues),
            'noms'      => array_map(fn ($m) => (string) $m->name, $retenues),
            // Les machines de PRODUCTION de la portee, nommees a part : le
            // panneau de decision doit pouvoir les dire, et non les noyer dans
            // un nombre. Le legacy ne distingue rien.
            'sensibles' => array_values(array_map(
                fn ($m) => (string) $m->name,
                array_filter($retenues, fn ($m) => $this->estSensible($m))
            )),
        ];
    }

    /** Les machines sans cle de plateforme — la portee de « deployer ». */
    public function porteeDeploiement(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ! ((int) $m->platform_key_deployed));
    }

    /**
     * Les machines a cle dont le compte de service manque.
     *
     * ══ CE GESTE EST UNE REPRISE, PAS UNE ETAPE SUIVANTE ═════════════════
     *
     * `deploy_platform_key` cree DEJA le compte `rootwarden` avec
     * `NOPASSWD: ALL`, dans la meme requete (`ssh.py:786-861`, « dans la
     * foulee »), et pose `service_account_deployed` lui-meme (`:855`). Une
     * machine n'apparait donc ici que si cette tentative incluse a ECHOUE —
     * `ssh.py:862` avale l'exception en `logger.warning` et rend « Keypair
     * deployee OK (service account echoue - deployer manuellement) ».
     *
     * Le legacy presente les deux boutons cote a cote, sans dire que le second
     * ne sert qu'au rattrapage du premier. L'ecran le dit.
     */
    public function porteeCompteService(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ((int) $m->platform_key_deployed)
            && ! ((int) $m->service_account_deployed));
    }

    /**
     * Les machines dont RootWarden peut effacer sa copie des mots de passe.
     *
     * ══ LA PRECONDITION DU BACKEND, QUE LE LEGACY N'APPLIQUE PAS ═════════
     *
     * `remove_ssh_password` REFUSE (400, « Service account non deploye ») si
     * `service_account_deployed` est faux (`ssh.py:1235-1237`). C'est une
     * precondition juste : sans le compte de service, effacer les mots de passe
     * retire a RootWarden tout moyen de passer root — `execute_as_root` ne
     * court-circuite le mot de passe que sur ce compte (`ssh_utils.py:537`).
     *
     * Le bouton PAR LIGNE du legacy la respecte (`:203` teste `$saDeployed`).
     * **Le bouton de MASSE ne la teste pas** (`:329` : `platform_key_deployed`
     * et `ssh_password_required` seulement). Il propose donc des machines que
     * le backend va refuser — et la boucle qui les envoie compte les reussites
     * sans jamais nommer les refus (`:333-340` : `if (d.success) ok++`, et un
     * `catch` vide). L'exploitant lit « 3/7 » sans savoir lesquelles, ni
     * pourquoi.
     *
     * La portee porte donc la precondition, et `porteeEffacementRefusees()`
     * nomme ce qui en est ecarte : une portee qui retrecit en silence se lit
     * comme une portee complete.
     */
    public function porteeEffacement(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ((int) $m->platform_key_deployed)
            && ((int) $m->service_account_deployed)
            && (((int) $m->a_mot_de_passe) || ((int) $m->a_mot_de_passe_root)));
    }

    /**
     * Ce que le legacy aurait propose et que le backend refuserait.
     *
     * La cle est deployee, un mot de passe subsiste, mais le compte de service
     * manque. Ces machines ne sont pas « deja faites » : elles sont BLOQUEES,
     * et ce qui les debloque est le geste du compte de service.
     */
    public function porteeEffacementRefusees(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ((int) $m->platform_key_deployed)
            && ! ((int) $m->service_account_deployed)
            && (((int) $m->a_mot_de_passe) || ((int) $m->a_mot_de_passe_root)));
    }

    /** `PROD` ou `CRITIQUE`, et une valeur inconnue compte comme sensible. */
    public function estSensible(object $m): bool
    {
        $env = strtoupper(trim((string) ($m->environment ?? '')));

        return $env === 'PROD' || $env === 'OTHER' || $env === '';
    }
}
