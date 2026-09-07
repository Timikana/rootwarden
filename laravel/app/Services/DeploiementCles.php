<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Le déploiement des clés SSH — sous-lot K4, le geste que le legacy ne gardait
 * que dans un `.then()`.
 *
 * ══ CE QUE CE SERVICE DÉPLACE, ET IL NE L'AJOUTE PAS ═════════════════════
 *
 * Le legacy enchaîne `/preflight_check` puis `/deploy` **dans la même chaîne
 * `fetch`** (`legacy/ssh/js/main.js:110` puis `:194`). Le garde qui empêche une
 * révocation générale y est donc un `.then()` de navigateur.
 *
 * Mesure du 2026-09-07 sur `backend/routes/ssh.py` (`/deploy`, 93 lignes de code) :
 *
 *     « preflight »        ABSENT
 *     « users_with_keys »  ABSENT
 *     « scan_required »    ABSENT
 *
 * **Le backend ne vérifie rien.** `POST /deploy {machines:[…]}` déploie sans
 * qu'aucun preflight n'ait jamais tourné — et `MODULE-SSH.md:280` dit ce que ça
 * coûte : sans ce garde, un déploiement **révoquerait les clés de toutes les
 * machines cochées**. Ce n'est pas une absence d'effet, c'est une révocation.
 *
 * > **La capacité « on ne déploie pas sans avoir vérifié » existe dans le legacy ;
 * > c'est son EMPLACEMENT qui ne tient pas.** Un garde côté client ne garde que
 * > ceux qui passent par le client. Porter le bouton avec son `.then()` aurait
 * > offert un chemin de révocation que la page du legacy n'offre pas.
 *
 * *L'iso-périmètre porte des CAPACITÉS, pas des implémentations.*
 *
 * ══ LA GARDE EST PAR CONSTRUCTION, PAS PAR DISCIPLINE ════════════════════
 *
 * `deploie()` n'accepte pas une liste de machines : elle accepte un
 * `PreflightConcluant`, que **seul** `preflight()` sait fabriquer, et seulement
 * quand toutes les machines passent. *Il n'existe aucun chemin d'appel qui
 * déploie sans preflight — pas parce qu'on y pense, parce que c'est
 * inexprimable.*
 *
 * ══ ⛔ CE QUE CE SERVICE NE FERME PAS, ET IL FAUT LE LIRE ═════════════════
 *
 * **Quiconque détient une clé d'API joint `/deploy` directement**, sans passer
 * par le portage. Ce trou existe aujourd'hui, ce service ne le creuse pas et ne
 * le referme pas : le refermer demande une garde DANS `ssh.py`, donc une décision
 * sur le backend, hors de ce lot.
 *
 * ══ TOUT OU RIEN, ET LA MACHINE FAUTIVE EST NOMMÉE ═══════════════════════
 *
 * Si une machine sur cinq échoue au preflight, **rien n'est déployé** et son nom
 * est rendu. C'est ce que fait le legacy (`main.js:186-191` : `allOk=false` puis
 * `return`, avec `failedNames`), et c'est aussi le seul comportement défendable —
 * *un déploiement partiel silencieux laisse croire que cinq machines ont été
 * traitées.*
 */
class DeploiementCles
{
    /**
     * Lance le preflight et rend un verdict.
     *
     * @param  list<int>  $machines
     * @return array{concluant: ?PreflightConcluant, echecs: list<string>, brut: array, erreur: ?string}
     */
    public function preflight(array $machines, int $idCompte, int $role, array $permissions): array
    {
        $vide = ['concluant' => null, 'echecs' => [], 'brut' => [], 'erreur' => null];

        if ($machines === []) {
            return $vide + ['erreur' => 'aucune_machine'];
        }

        $reponse = $this->appelle('/preflight_check', ['machines' => array_values($machines)],
                                  $idCompte, $role, $permissions);

        if ($reponse === null) {
            return array_merge($vide, ['erreur' => 'backend_injoignable']);
        }
        if (($reponse['success'] ?? false) !== true) {
            return array_merge($vide, ['erreur' => 'preflight_refuse', 'brut' => $reponse]);
        }

        $resultats = $reponse['results'] ?? [];
        $echecs = [];

        foreach ($resultats as $r) {
            $nom = (string) ($r['name'] ?? ('#' . ($r['machine_id'] ?? '?')));

            /*
             * DEUX CONDITIONS, ET LA SECONDE EST CELLE QUI COMPTE.
             *
             * `ssh_ok` dit que la machine répond. `users_with_keys` dit qu'il y a
             * des comptes À DÉPLOYER — et c'est son ZÉRO qui, dans le legacy,
             * transforme le déploiement en révocation générale
             * (`MODULE-SSH.md:280`). Ne vérifier que `ssh_ok` porterait la moitié
             * du garde, c'est-à-dire pas le garde.
             */
            if (($r['ssh_ok'] ?? false) !== true) {
                $echecs[] = $nom;
                continue;
            }
            if ((int) ($r['users_with_keys'] ?? 0) <= 0) {
                $echecs[] = $nom;
            }
        }

        // Une liste de résultats VIDE n'est pas un succès : c'est une mesure qui
        // n'a pas eu lieu. Sans ce garde, zéro résultat vaudrait zéro échec.
        if ($resultats === []) {
            return array_merge($vide, ['erreur' => 'preflight_sans_resultat', 'brut' => $reponse]);
        }

        if ($echecs !== []) {
            return array_merge($vide, ['echecs' => $echecs, 'brut' => $reponse]);
        }

        return array_merge($vide, [
            'concluant' => new PreflightConcluant(array_values($machines)),
            'brut' => $reponse,
        ]);
    }

    /**
     * Relaie le déploiement. **Inappelable sans un preflight concluant.**
     *
     * @return array{success: bool, message: ?string}
     */
    public function deploie(PreflightConcluant $concluant, int $idCompte, int $role, array $permissions): array
    {
        $reponse = $this->appelle('/deploy', ['machines' => $concluant->machines],
                                  $idCompte, $role, $permissions);

        if ($reponse === null) {
            return ['success' => false, 'message' => null];
        }

        return [
            'success' => ($reponse['success'] ?? false) === true,
            'message' => isset($reponse['message']) ? (string) $reponse['message'] : null,
        ];
    }

    /**
     * Un appel au backend, avec les mêmes en-têtes que la passerelle.
     *
     * Les clés de configuration sont celles de `PasserelleController:103-112` :
     * une seconde source d'adresse finirait par diverger de la première.
     */
    private function appelle(string $chemin, array $corps, int $idCompte, int $role, array $permissions): ?array
    {
        $base = rtrim((string) config('rootwarden.backend.url'), '/');

        try {
            $reponse = Http::withHeaders([
                'X-API-KEY' => (string) config('rootwarden.backend.cle_api'),
                'X-User-ID' => (string) $idCompte,
                'X-User-Role' => (string) $role,
                'X-User-Permissions' => json_encode($permissions),
                'Content-Type' => 'application/json',
            ])
                ->timeout((int) config('rootwarden.backend.delai', 120))
                ->post($base . $chemin, $corps);

            return $reponse->json() ?? [];
        } catch (\Throwable $e) {
            Log::error('deploiement de cles : backend injoignable', [
                'chemin' => $chemin,
                'erreur' => $e->getMessage(),
            ]);

            return null;
        }
    }
}

/**
 * La preuve qu'un preflight a conclu — le seul laissez-passer de `deploie()`.
 *
 * ⚠ **NE PAS RENDRE CE CONSTRUCTEUR PUBLIC HORS DE CE FICHIER.** Il est
 * `final` et sa seule fabrique légitime est `DeploiementCles::preflight()`,
 * qui ne le construit que lorsque **toutes** les machines passent. *Une garde
 * par construction ne se périme pas ; une garde par discipline se périme au
 * premier appelant pressé.*
 */
final class PreflightConcluant
{
    /** @param list<int> $machines */
    public function __construct(public readonly array $machines)
    {
    }
}
