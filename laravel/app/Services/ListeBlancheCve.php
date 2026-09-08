<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * La liste blanche des CVE — faux positifs acceptes, module `security/`.
 *
 * ══ POURQUOI CE PORTAGE EXISTE ═══════════════════════════════════════════
 *
 * `legacy/security/index.php` a ete archive en acceptant la perte de cette
 * capacite — motif : « zero ligne en base, un garde-fou jamais employe ne
 * protege de rien ». L'exploitant a ensuite tranche pour un portage a
 * ISO-PERIMETRE : la question n'etait pas « est-ce que ca vaut la peine » mais
 * « est-ce que le legacy l'offrait ». Il l'offrait.
 *
 * Les trois routes backend restent VIVANTES et passent deja la passerelle —
 * `RoutesBackend.php:35` autorise le prefixe `/cve_`, verifie. La capacite
 * n'etait donc pas PERDUE, elle etait SANS INTERFACE. Ce service lui en rend une,
 * en remplacant l'appel backend plutot qu'en le relayant : meme raison qu'en S4
 * pour les planifications — ici `perm:can_scan_cve` garde enfin l'ecriture.
 *
 * ══ TROIS DEFAUTS DU LEGACY, MESURES, ET FERMES ICI ══════════════════════
 *
 * **1. L'AUTEUR VENAIT DU CLIENT.** `backend/routes/cve.py:673` :
 * `whitelisted_by = (data.get('whitelisted_by') or 'admin').strip()`. La colonne
 * qui existe pour dire QUI a accepte le faux positif portait ce que le client
 * envoyait — ou litteralement « admin » s'il n'envoyait rien. **Une tracabilite
 * dont la valeur vient de celui qu'elle trace ne trace personne.** Ici le nom est
 * resolu depuis la SESSION et n'est jamais lu dans la requete.
 *
 * **2. LE DOUBLON GLOBAL EST POSSIBLE.** La table porte
 * `UNIQUE KEY uniq_cve_machine (cve_id, machine_id)` et `machine_id` est
 * NULLABLE. En MySQL, **deux NULL sont distincts dans un index unique** :
 * l'`ON DUPLICATE KEY UPDATE` du legacy ne mord donc PAS sur les entrees
 * globales. Mesure sur table temporaire :
 *
 *     machine_id=42,   meme CVE deux fois  ->  1 ligne  (l'upsert mord)
 *     machine_id=NULL, meme CVE deux fois  ->  2 lignes (il ne mord pas)
 *
 * Consequence cote legacy : une meme CVE pouvait etre blanchie globalement un
 * nombre illimite de fois, chaque ligne portant un motif et un auteur differents,
 * et rien ne disait laquelle faisait foi. `pose()` verifie donc explicitement
 * l'existence avant d'inserer, au lieu de s'en remettre a l'index.
 *
 * **3. `cve_id` N'ETAIT PAS VALIDE.** Le legacy accepte n'importe quelle chaine
 * non vide. Une faute de frappe cree une entree qui ne blanchit RIEN et qui a
 * l'air de proteger — le pire des deux etats.
 *
 * ══ ⚠ UN ECART ASSUME AVEC LE LEGACY, ET IL EST DELIBERE ═════════════════
 *
 * Le legacy rend `expires_at` FACULTATIF (`cve.py:674`, « YYYY-MM-DD ou null »).
 * **Ici une decision est EXIGEE** : soit une date, soit `sans_expiration` coche.
 *
 * *Ce n'est pas un rétrécissement : la capacite « blanchir sans echeance » est
 * conservee entiere.* Ce qui disparait est l'OMISSION SILENCIEUSE — on ne peut
 * plus laisser le champ vide sans avoir dit qu'on le voulait. **Une liste blanche
 * sans expiration est une dette qui ne se rappelle a personne ; une liste blanche
 * dont l'absence d'expiration a ete CHOISIE reste une decision tracable.**
 *
 * ══ CE QUE CE SERVICE NE FAIT PAS ════════════════════════════════════════
 *
 * Il n'applique PAS la liste blanche aux resultats de scan. Le filtrage vit cote
 * backend et n'est pas touche ici : ce portage rend l'ECRAN, pas le moteur.
 */
class ListeBlancheCve
{
    /** `CVE-<annee>-<sequence>`, la seule forme que l'ecran accepte. */
    public const MOTIF_CVE = '/^CVE-\d{4}-\d{4,7}$/';

    /** Longueur de `reason` en base — `varchar(500)`. */
    public const MOTIF_MAX = 500;

    public function __construct(private readonly Comptes $comptes)
    {
    }

    /**
     * Les entrees, la plus recente d'abord, avec le nom de la machine ciblee.
     *
     * `LEFT JOIN` et non `JOIN` : une entree GLOBALE porte `machine_id = NULL` et
     * doit rester visible. Un `JOIN` la ferait disparaitre de l'ecran tout en la
     * laissant active — un blanchiment invisible est exactement ce que cette page
     * existe pour empecher.
     */
    public function liste(): array
    {
        return DB::table('cve_whitelist as w')
            ->leftJoin('machines as m', 'm.id', '=', 'w.machine_id')
            ->orderByDesc('w.created_at')
            ->get([
                'w.id', 'w.cve_id', 'w.machine_id', 'w.reason',
                'w.whitelisted_by', 'w.expires_at', 'w.created_at',
                'm.name as machine_name',
            ])
            ->map(static fn ($l) => (array) $l)
            ->all();
    }

    /**
     * Valide une saisie. Rend un tableau de refus, VIDE si tout est accepte.
     *
     * TOUTE la validation vit ici et nulle part ailleurs : le controleur ne
     * decide de rien. C'est ce qui rend impossible un chemin d'ecriture qui
     * sauterait un controle — le defaut que S4 a mesure sur le `PUT` du legacy.
     */
    public function valide(array $d): array
    {
        $refus = [];

        $cve = strtoupper(trim((string) ($d['cve_id'] ?? '')));
        if ($cve === '') {
            $refus['cve_id'] = 'cve_requis';
        } elseif (preg_match(self::MOTIF_CVE, $cve) !== 1) {
            $refus['cve_id'] = 'cve_malforme';
        }

        $motif = trim((string) ($d['reason'] ?? ''));
        if ($motif === '') {
            $refus['reason'] = 'motif_requis';
        } elseif (mb_strlen($motif) > self::MOTIF_MAX) {
            $refus['reason'] = 'motif_trop_long';
        }

        // `machine_id` absent ou vide = entree GLOBALE, et c'est legitime.
        $machine = $d['machine_id'] ?? null;
        if ($machine !== null && $machine !== '') {
            if (! ctype_digit((string) $machine) || ! $this->machineExiste((int) $machine)) {
                $refus['machine_id'] = 'machine_inconnue';
            }
        }

        /*
         * ⚠ LA DECISION D'EXPIRATION EST EXIGEE — voir l'ecart assume ci-dessus.
         * Un champ vide SANS `sans_expiration` est un oubli, pas un choix.
         */
        $sans = (bool) ($d['sans_expiration'] ?? false);
        $date = trim((string) ($d['expires_at'] ?? ''));

        if ($sans && $date !== '') {
            $refus['expires_at'] = 'expiration_contradictoire';
        } elseif (! $sans && $date === '') {
            $refus['expires_at'] = 'expiration_a_decider';
        } elseif (! $sans) {
            $j = \DateTimeImmutable::createFromFormat('!Y-m-d', $date);
            if ($j === false || $j->format('Y-m-d') !== $date) {
                $refus['expires_at'] = 'date_malformee';
            } elseif ($j <= new \DateTimeImmutable('today')) {
                // Une echeance passee blanchit zero jour : elle a l'air d'une
                // protection et n'en est pas une.
                $refus['expires_at'] = 'date_passee';
            }
        }

        return $refus;
    }

    /**
     * Pose ou met a jour une entree. Rend son identifiant.
     *
     * ⚠ L'AUTEUR EST RESOLU DEPUIS LA SESSION, JAMAIS LU DANS LA REQUETE — c'est
     * le defaut n°1 du legacy, et le seul des trois qui touche la tracabilite.
     *
     * ⚠ ET L'EXISTENCE EST VERIFIEE EXPLICITEMENT, sans compter sur l'index
     * unique : il ne mord pas quand `machine_id` est NULL (defaut n°2, mesure).
     */
    public function pose(array $d, int $idCompte): int
    {
        $cve = strtoupper(trim((string) $d['cve_id']));
        $machine = ($d['machine_id'] ?? null) === null || $d['machine_id'] === ''
            ? null
            : (int) $d['machine_id'];
        $sans = (bool) ($d['sans_expiration'] ?? false);

        $valeurs = [
            'reason' => trim((string) $d['reason']),
            'whitelisted_by' => $this->nomDe($idCompte),
            'expires_at' => $sans ? null : trim((string) $d['expires_at']),
        ];

        $existante = DB::table('cve_whitelist')
            ->where('cve_id', $cve)
            ->when($machine === null,
                static fn ($q) => $q->whereNull('machine_id'),
                static fn ($q) => $q->where('machine_id', $machine))
            ->value('id');

        if ($existante !== null) {
            DB::table('cve_whitelist')->where('id', $existante)->update($valeurs);

            return (int) $existante;
        }

        return (int) DB::table('cve_whitelist')->insertGetId(
            $valeurs + ['cve_id' => $cve, 'machine_id' => $machine]
        );
    }

    /** Retire une entree. Rend `false` si elle n'existait pas. */
    public function supprime(int $id): bool
    {
        return DB::table('cve_whitelist')->where('id', $id)->delete() > 0;
    }

    /**
     * Le nom a inscrire dans `whitelisted_by`.
     *
     * La colonne est un `varchar(100)` et non une cle etrangere : c'est le schema
     * du backend, on ne le change pas depuis ici. Un compte anonymise plus tard
     * laissera donc son ancien nom sur la ligne — c'est le comportement du
     * legacy, et le changer demanderait une migration qui n'appartient pas a ce
     * portage.
     */
    private function nomDe(int $idCompte): string
    {
        $compte = $this->comptes->trouve($idCompte);

        return mb_substr((string) ($compte['name'] ?? ''), 0, 100) ?: 'inconnu';
    }

    private function machineExiste(int $id): bool
    {
        return DB::table('machines')->where('id', $id)->exists();
    }
}
