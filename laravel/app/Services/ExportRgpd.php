<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * L'export des donnees personnelles — RGPD article 15 (acces) et 20 (portabilite).
 *
 * Porte de `legacy/profile/export.php`, 121 lignes lues en entier. La
 * specification de reference est `docs/migration/QA-SPEC-EXPORT-RGPD.md`.
 *
 * ══ DEUX PROTECTIONS DELIBEREES DU LEGACY, CONSERVEES ─────────────────────
 *
 * Elles se lisent comme des details d'implementation et sont des DECISIONS DE
 * SECURITE. Un portage qui recopie les requetes sans les commentaires les perd
 * toutes les deux en silence, et aucune suite ne le verrait : le fichier
 * resterait parfaitement valide.
 *
 *  1. `session_id` est TRONQUE a 8 caracteres. Un jeton de session en clair
 *     dans un fichier que la personne telecharge, archive et transfere par
 *     courriel est une FUITE D'IDENTIFIANT. La troncature est ce qui rend cette
 *     section exportable.
 *  2. `password_history` n'exporte que `changed_at`, JAMAIS les empreintes.
 *     Elles ne sont pas reversibles, mais elles n'ont rien a faire dans une
 *     copie de donnees personnelles et offriraient une cible hors ligne.
 *
 * ══ TROIS DIVERGENCES ASSUMEES AVEC LE LEGACY ─────────────────────────────
 *
 *  A. LES COUPES S'ANNONCENT. Le legacy borne `user_logs` a 10 000 lignes et
 *     `login_history` a 1 000, et rien dans le fichier produit ne dit qu'il a
 *     ete coupe : la personne recoit un JSON qui se presente comme complet.
 *     Mesure en base du 2026-09-04 : `login_history` atteint 1882 lignes pour
 *     un compte, donc DEUX comptes depassent la borne aujourd'hui. Leur export
 *     serait incomplet sans aucun moyen de le savoir.
 *     -> chaque section bornee porte `_total`, `_exportees` et `_tronque`.
 *     La borne elle-meme est CONSERVEE : elle protege la memoire du serveur, et
 *     l'annoncer est sans risque la ou la retirer n'en est pas.
 *
 *  B. UNE SECTION EN ECHEC NE CHANGE PAS DE TYPE. Le legacy rend
 *     `['_error' => 'fetch failed']` a la place du tableau de lignes : la
 *     section devient un OBJET la ou le consommateur attend une LISTE. C'est
 *     indiscernable d'une section vide pour qui ne lit pas, et un plantage de
 *     lecture pour qui lit. Ici la section reste une LISTE VIDE et son nom est
 *     inscrit dans `_metadata.sections_en_echec`.
 *
 *  C. `SELECT *` SUR `permissions` EST CONSERVE, ET C'EST UN CHOIX.
 *     La regle « jamais de `SELECT *` » s'INVERSE sur un export de
 *     portabilite : cette table est un pur matricule — `user_id` et dix-huit
 *     booleens `can_*` — et une liste fermee de colonnes omettrait
 *     silencieusement une permission ajoutee apres le portage. C'est exactement
 *     le mode de defaillance que la portabilite vise a empecher.
 */
class ExportRgpd
{
    /** Bornes reprises du legacy, telles quelles. */
    public const BORNE_JOURNAL = 10000;
    public const BORNE_CONNEXIONS = 1000;

    /** Les sections toujours presentes. `api_keys_created` s'y ajoute au role 3. */
    public const SECTIONS = [
        'user',
        'permissions',
        'user_machine_access',
        'user_logs',
        'login_history',
        'active_sessions',
        'notification_preferences',
        'password_history',
    ];

    /** Noms des sections dont la lecture a echoue, pour `_metadata`. */
    private array $enEchec = [];

    /**
     * Construit l'export d'UN compte.
     *
     * ⚠ `$idCompte` vient de la SESSION chez l'appelant, jamais de la requete.
     * Aucun parametre de cette methode n'est expose a l'exterieur : ne pas
     * offrir d'entree libre est plus sur que la valider.
     */
    public function pour(int $idCompte, int $roleCompte): array
    {
        $this->enEchec = [];

        $export = [
            '_metadata' => [
                'generated_at' => now()->toIso8601String(),
                'rootwarden_version' => \App\Support\Version::numero(),
                'user_id' => $idCompte,
                'format_version' => '1.0',
                'rgpd_articles' => ['art_15_access', 'art_20_portability'],
            ],
            'user' => $this->lit(
                'user',
                fn () => DB::table('users')->where('id', $idCompte)->select(
                    'id', 'name', 'email', 'company', 'role_id', 'active', 'sudo',
                    'created_at', 'password_updated_at', 'ssh_key', 'ssh_key_updated_at',
                    'password_expiry_override', 'force_password_change',
                    'failed_attempts', 'locked_until', 'last_failed_login_at',
                )->get(),
            ),
            // Voir la divergence C : `SELECT *` est DELIBERE ici.
            'permissions' => $this->lit(
                'permissions',
                fn () => DB::table('permissions')->where('user_id', $idCompte)->get(),
            ),
            // Le `LEFT JOIN` conserve la ligne quand la machine a disparu : la
            // personne a bien eu cet acces, et l'omettre reecrirait son histoire.
            'user_machine_access' => $this->lit(
                'user_machine_access',
                fn () => DB::table('user_machine_access as uma')
                    ->leftJoin('machines as m', 'm.id', '=', 'uma.machine_id')
                    ->where('uma.user_id', $idCompte)
                    ->select('uma.machine_id', 'm.name as machine_name', 'm.ip')->get(),
            ),
            'user_logs' => $this->litBorne(
                'user_logs',
                self::BORNE_JOURNAL,
                fn () => DB::table('user_logs')->where('user_id', $idCompte)->count(),
                fn () => DB::table('user_logs')->where('user_id', $idCompte)
                    ->orderByDesc('created_at')->limit(self::BORNE_JOURNAL)
                    // `LEFT(self_hash, 16)` : de quoi verifier son ancrage dans la
                    // chaine, pas de quoi la rejouer.
                    ->selectRaw('id, action, created_at, LEFT(self_hash, 16) AS hash_chain')
                    ->get(),
            ),
            'login_history' => $this->litBorne(
                'login_history',
                self::BORNE_CONNEXIONS,
                fn () => DB::table('login_history')->where('user_id', $idCompte)->count(),
                fn () => DB::table('login_history')->where('user_id', $idCompte)
                    ->orderByDesc('created_at')->limit(self::BORNE_CONNEXIONS)
                    ->select('id', 'ip_address', 'user_agent', 'status', 'created_at')->get(),
            ),
            'active_sessions' => $this->masqueJetons($this->lit(
                'active_sessions',
                fn () => DB::table('active_sessions')->where('user_id', $idCompte)
                    ->select('session_id', 'ip_address', 'user_agent',
                             'last_activity', 'created_at')->get(),
            )),
            'notification_preferences' => $this->lit(
                'notification_preferences',
                fn () => DB::table('notification_preferences')->where('user_id', $idCompte)
                    ->select('event_type', 'email', 'in_app')->get(),
            ),
            // PROTECTION 2 : les DATES seulement. Jamais `password_hash`.
            'password_history' => $this->lit(
                'password_history',
                fn () => DB::table('password_history')->where('user_id', $idCompte)
                    ->orderByDesc('changed_at')->select('changed_at')->get(),
            ),
        ];

        // Les cles API creees PAR ce compte, au role 3 seulement — comme le legacy.
        if ($roleCompte === 3) {
            $export['api_keys_created'] = $this->lit(
                'api_keys_created',
                fn () => DB::table('api_keys')->where('created_by', $idCompte)
                    ->select('name', 'key_prefix', 'scope_json',
                             'created_at', 'revoked_at', 'last_used_at')->get(),
            );
        }

        // Divergence B : l'echec s'annonce EN TETE, et la section garde son type.
        $export['_metadata']['sections_en_echec'] = $this->enEchec;

        return $export;
    }

    /** Le nom de fichier, portant l'identifiant et l'horodatage comme le legacy. */
    public function nomFichier(int $idCompte): string
    {
        return sprintf('rootwarden-export-user-%d-%s.json', $idCompte, now()->format('Ymd-His'));
    }

    /**
     * Une section. En cas d'echec elle rend une LISTE VIDE et se declare — elle
     * ne devient JAMAIS un objet portant `_error` : un consommateur qui attend
     * une liste ne doit pas recevoir autre chose selon qu'une requete a abouti.
     *
     * @return array<int, array<string, mixed>>
     */
    private function lit(string $nom, callable $requete): array
    {
        try {
            return array_map(static fn ($l) => (array) $l, $requete()->all());
        } catch (\Throwable $e) {
            Log::error('export RGPD : section illisible', ['section' => $nom, 'erreur' => $e->getMessage()]);
            $this->enEchec[] = $nom;

            return [];
        }
    }

    /**
     * Une section BORNEE, qui annonce sa coupe.
     *
     * Le compte total est lu SEPAREMENT de la page exportee : sans lui, « 1000
     * lignes » et « exactement 1000 lignes existantes » sont la meme sortie.
     * C'est le meme releve que le temoin d'une sonde — sans lui, la coupe est
     * indiscernable de la completude.
     */
    private function litBorne(string $nom, int $borne, callable $compte, callable $requete): array
    {
        $lignes = $this->lit($nom, $requete);
        if (in_array($nom, $this->enEchec, true)) {
            return $lignes;
        }
        try {
            $total = (int) $compte();
        } catch (\Throwable $e) {
            Log::error('export RGPD : compte total illisible', ['section' => $nom]);
            // On ne PRETEND pas savoir : sans le total, on ne peut pas affirmer
            // que rien n'a ete coupe. La section reste, l'annonce est absente,
            // et son absence est elle-meme declaree.
            $this->enEchec[] = $nom . '._total';

            return $lignes;
        }

        return [
            '_total' => $total,
            '_exportees' => count($lignes),
            '_tronque' => $total > count($lignes),
            '_borne' => $borne,
            'lignes' => $lignes,
        ];
    }

    /**
     * PROTECTION 1 : le jeton de session ne sort JAMAIS en clair.
     *
     * Huit caracteres suffisent a reconnaitre sa session dans la liste ; ils ne
     * suffisent pas a la rejouer. Le suffixe `...` dit que la valeur est coupee,
     * sans quoi elle passerait pour le jeton entier.
     */
    private function masqueJetons(array $sessions): array
    {
        return array_map(static function (array $s): array {
            $s['session_id'] = mb_substr((string) ($s['session_id'] ?? ''), 0, 8) . '...';

            return $s;
        }, $sessions);
    }
}
