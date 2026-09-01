<?php

namespace App\Services;

/*
 * ══════════════════════════════════════════════════════════════════════════
 *  LA REGION D'ALERTES DE L'ACCUEIL — E-264
 * ══════════════════════════════════════════════════════════════════════════
 *
 * `legacy/index.php:88-133` construit HUIT alertes — et non neuf : la
 * neuvieme est promise par un commentaire (`:147` « Fail2ban alerts …
 * Seront evaluees plus bas ») qui n'a jamais eu de code. Le compte reel se
 * mesure : `grep -c '$alerts\[\] *=' legacy/index.php` -> 8.
 *
 * ── CE QUI CHANGE LA FORME DU PORTAGE ─────────────────────────────────
 *
 * CINQ des huit comptent un fait qui a DEJA un indicateur borne sur le meme
 * ecran, et le legacy les calcule par des requetes NON bornees :
 *
 *   hors ligne          <- indicateurs.hors_ligne   (borne au perimetre)
 *   sans cle plateforme <- indicateurs.machines/cle (borne au perimetre)
 *   CVE critiques       <- cve.critiques            (borne au perimetre)
 *   comptes sans 2FA    <- comptes.sans_2fa         (borne par role)
 *   comptes sans cle    <- comptes.sans_cle         (borne par role)
 *
 * Les porter comme des requetes neuves mettrait DEUX NOMBRES DIFFERENTS POUR
 * LE MEME FAIT sur un seul ecran : la tuile dirait « 1 hors ligne » (borne)
 * et l'alerte « 3 machines hors ligne » (parc entier). On DERIVE donc des
 * tableaux deja calcules : zero requete de plus, et la coherence n'est pas
 * une propriete a surveiller, elle est structurelle.
 *
 * ── POURQUOI PAS DE SECOND GEL DE ROLE PAR-DESSUS ─────────────────────
 *
 * L'arbitrage demandait de borner la REGION en trois classes (exploitation /
 * population et flotte / surface d'attaque). Ces trois classes EXISTENT
 * DEJA — dans les services, sous forme de bornes :
 * `indicateursComptes` rend `null` (et non 0) pour ce qu'un role n'a pas a
 * voir, et `sans_2fa` n'est lu qu'au role 3.
 *
 * Poser un gel de role EN PLUS masquerait une alerte dont le nombre reste
 * affiche deux tuiles au-dessus. C'est le defaut refute a E-235c :
 * une alerte derivee suit la borne de SON indicateur, jamais une seconde.
 *
 * ── TROIS FAITS SONT REELLEMENT NEUFS ─────────────────────────────────
 *
 * Rien ne les affiche encore, ils demandent une lecture — bornee :
 * releve datant de plus de 30 jours, score SSH sous 50, cle de compte de
 * plus de 90 jours.
 *
 * ── L'ABSENCE D'ALERTE EST UNE AFFIRMATION ────────────────────────────
 *
 * Le legacy avale trois de ses lectures dans des `catch (\Exception $e) {}`
 * VIDES (`:117`, `:134`) : une base qui ne repond pas y produit une region
 * vide, qui se lit « tout va bien ». Sur un tableau de bord de securite
 * c'est le mensonge le plus couteux qui soit. Ici une famille illisible est
 * NOMMEE, et son absence d'alerte n'est jamais presentee comme un calme.
 */
final class AlertesAccueil
{
    /*
     * Chaque alerte pointe une CLE DE NAVIGATION, pas une URL. Le lien et le
     * droit d'y aller se lisent alors au meme endroit que le menu et les
     * tuiles : `ssh_audit` n'etant pas porte, son entree porte `legacy`, et
     * une personne sans `can_audit_ssh` n'a simplement pas l'entree — donc
     * pas de lien, sans qu'aucune garde soit recopiee ici.
     */
    private const NAV = [
        'hors_ligne'      => null,            // aucune page ne « repare » un hors ligne
        'sans_cle_parc'   => 'platform_key',
        'cve_critiques'   => 'cve_scan',
        'sans_2fa'        => 'admin',
        'sans_cle_compte' => 'admin',
        'maj_ancienne'    => 'updates',
        'ssh_faible'      => 'ssh_audit',
        'cles_anciennes'  => 'admin',
    ];

    private const TON = [
        'hors_ligne'      => 'grave',
        'sans_cle_parc'   => 'attention',
        'cve_critiques'   => 'grave',
        'sans_2fa'        => 'attention',
        'sans_cle_compte' => 'info',
        'maj_ancienne'    => 'attention',
        'ssh_faible'      => 'grave',
        'cles_anciennes'  => 'grave',
    ];

    public function __construct(
        private Machines $machines,
        private Comptes $comptes,
    ) {
    }

    /**
     * @param  array  $indicateurs  retour de Machines::indicateurs()
     * @param  array  $cve          retour de Machines::indicateursCve()
     * @param  array  $comptesInd   retour de Comptes::indicateursComptes()
     */
    public function pour(int $roleId, int $userId, array $indicateurs, array $cve, array $comptesInd): array
    {
        $brut = [];
        $illisibles = [];

        // ══ LES CINQ DERIVEES — aucune lecture ══════════════════════════
        if ($indicateurs['lisible'] ?? false) {
            $brut['hors_ligne'] = $indicateurs['hors_ligne'] ?? null;

            /*
             * « Sans la cle de plateforme » se DEDUIT et ne se lit pas : le
             * legacy interroge `platform_key_deployed = 0 OR IS NULL` sur tout
             * le parc, alors que la tuile affiche deja `cle` sur le perimetre.
             * La soustraction reste dans la borne ; la requete en sortait.
             */
            $brut['sans_cle_parc'] = max(0, (int) ($indicateurs['machines'] ?? 0) - (int) ($indicateurs['cle'] ?? 0));
        } else {
            $illisibles[] = 'parc';
        }

        /*
         * L'ETAT INCONNU NE LEVE PAS D'ALERTE, et c'est deliberé. Le legacy
         * comptait « != ONLINE » et rangeait donc l'inconnu parmi les pannes,
         * ce qui alarmait sur un fait que la donnee ne porte pas. Les trois
         * etats restent visibles en tuile, avec leur explication ; seule la
         * panne CONSTATEE devient une alerte.
         */

        if ($cve['lisible'] ?? false) {
            $brut['cve_critiques'] = $cve['critiques'] ?? null;
        } else {
            $illisibles[] = 'cve';
        }

        if ($comptesInd['lisible'] ?? false) {
            // `null` = ce role n'a pas a le voir. Ce n'est PAS zero, et la
            // boucle plus bas fait bien la difference.
            $brut['sans_2fa'] = $comptesInd['sans_2fa'] ?? null;
            $brut['sans_cle_compte'] = $comptesInd['sans_cle'] ?? null;
        } else {
            $illisibles[] = 'comptes';
        }

        // ══ LES TROIS NEUVES — lectures bornees ═════════════════════════
        $parc = $this->machines->alertesParc($roleId, $userId);
        if ($parc['lisible']) {
            $brut['maj_ancienne'] = $parc['maj_ancienne'];
            $brut['ssh_faible'] = $parc['ssh_faible'];
        } else {
            $illisibles[] = 'parc_suivi';
        }

        $cles = $this->comptes->alertesCles($roleId);
        if ($cles['lisible']) {
            $brut['cles_anciennes'] = $cles['cles_anciennes'];
        } else {
            $illisibles[] = 'cles_comptes';
        }

        // ══ MISE EN FORME ═══════════════════════════════════════════════
        $alertes = [];
        foreach ($brut as $cle => $nombre) {
            // `null` (hors du perimetre de lecture du role) et `0` (rien a
            // signaler) tombent tous deux — mais pour deux raisons opposees,
            // et c'est `null` qui ne doit surtout pas devenir un « 0 ».
            if ($nombre === null || (int) $nombre <= 0) {
                continue;
            }

            $alertes[] = [
                'cle'    => $cle,
                'ton'    => self::TON[$cle],
                'nombre' => (int) $nombre,
                'nav'    => self::NAV[$cle],
            ];
        }

        /*
         * Les graves d'abord. Le legacy rend dans l'ordre de son code, si bien
         * que « comptes sans cle SSH » (info) precede « CVE critiques »
         * (grave) : la premiere ligne lue est la moins consequente.
         */
        $poids = ['grave' => 0, 'attention' => 1, 'info' => 2];
        usort($alertes, fn ($a, $b) => $poids[$a['ton']] <=> $poids[$b['ton']]);

        return ['alertes' => $alertes, 'illisibles' => $illisibles];
    }
}
