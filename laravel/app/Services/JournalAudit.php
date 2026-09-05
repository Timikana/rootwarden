<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Le journal d'audit — module `adm/`, sous-lot D1.
 *
 * LECTURE ET ECRITURE EN BASE. `user_logs` n'a aucun effet de bord externe et
 * aucune route du backend Python ne l'expose : le portage la lit directement,
 * comme il le fait deja pour `cve_remediation` (S5).
 *
 * ══ LE DEFAUT QUE CE SERVICE REFERME : DEUX LECTURES DE LA MEME CHAINE ══════
 *
 * Le legacy porte DEUX parcours de la chaine de hachage, et ils ne s'accordent
 * pas devant une ligne non scellee (`self_hash IS NULL`) :
 *
 *   - `adm/api/audit_verify.php:44-51` la SAUTE sans avancer la tete de chaine ;
 *   - `adm/api/audit_seal.php:79-84`  calcule son hachage et AVANCE la tete.
 *
 * Mesure du 2026-08-25 : sur la meme base, a la meme seconde, « Verifier
 * l'integrite » annonce une chaine intacte pendant que « Sceller les
 * orphelines » annonce une desynchronisation a la ligne 3 et refuse d'ecrire.
 *
 * QUI A RAISON SE LIT DANS LE CODE QUI ECRIT, pas dans les deux qui lisent.
 * `adm/includes/audit_log.php:111-115`, seul chemin d'insertion scellee :
 *
 *     SELECT self_hash FROM user_logs
 *      WHERE self_hash IS NOT NULL          <-- il SAUTE les orphelines
 *      ORDER BY id DESC LIMIT 1 FOR UPDATE
 *
 * La chaine reellement inscrite saute donc les lignes non scellees. Les donnees
 * le confirment ligne a ligne (la ligne 3 porte le `self_hash` de la ligne 1,
 * pas celui de la 2), et un `LAG()` SQL sur les seules lignes scellees rend
 * 0 rupture sur 3311 maillons. Trois mesures independantes, un seul verdict.
 *
 * Consequence du defaut, et c'est elle qui coute : `stopped_at_tamper` verrouille
 * le bloc d'`UPDATE` (`audit_seal.php:105`), si bien que le bouton « Sceller les
 * orphelines » du legacy ne peut sceller AUCUNE ligne — jamais — tout en ecrivant
 * une alarme `SECURITY … investigation requise` a chaque appel, pour une ligne
 * qui n'a pas ete alteree. Le trou grandit seul : 757 lignes annoncees au plan,
 * 868 mesurees.
 *
 * ICI, UNE SEULE LECTURE, partagee par la verification et le scellement :
 * `parcourt()`. Elles ne peuvent plus diverger, parce qu'il n'y a plus qu'un
 * parcours.
 *
 * ══ CE QUI EST REPRIS TEL QUEL, ET POURQUOI ════════════════════════════════
 *
 * - la FORMULE de hachage, au caractere pres : `hash_hmac('sha256', prev|user|
 *   action|ts, cle)`, avec le repli SHA-256 nu des lignes scellees avant le
 *   correctif A08-02. Un octet d'ecart rendrait toute la chaine illisible d'un
 *   portail a l'autre ;
 * - le REPLI DE CLE sur `SECRET_KEY` quand `AUDIT_HMAC_KEY` est absente — c'est
 *   l'etat mesure de cet environnement. Le portage ne choisit pas une autre cle
 *   que celle qui a signe les lignes existantes ;
 * - le refus d'ECRASER une ligne deja scellee, et le garde-fou SQL
 *   `WHERE self_hash IS NULL` qui l'accompagne. Ce sont les deux bonnes idees du
 *   fichier d'origine, et elles restent.
 */
class JournalAudit
{
    /** Valeur initiale de `prev_hash` quand la table est vide. Cle du legacy. */
    public const GENESE = 'GENESIS';

    /** Ce que le legacy pagine (`adm/audit_log.php:19`). */
    public const PAR_PAGE = 50;

    private ?string $cleHmac = null;

    /* ═══ Lecture paginee ═══════════════════════════════════════════════════ */

    /**
     * Les filtres, normalises. Une date qui n'est pas au format `AAAA-MM-JJ` est
     * IGNOREE, comme dans le legacy (`audit_log.php:23`) : elle ne restreint
     * rien plutot que de faire echouer la page.
     */
    public function filtres(array $brut): array
    {
        // `?user[]=x` fait arriver un TABLEAU. Un `(string)` dessus leve une
        // TypeError, donc un 500 sur une page publique du portail : tout ce qui
        // n'est pas une chaine est traite comme absent, pas converti.
        $texte = static fn (string $cle): string => is_string($brut[$cle] ?? null)
            ? trim($brut[$cle]) : '';
        $date = static fn (string $v): string => preg_match('/^\d{4}-\d{2}-\d{2}$/', $v) === 1 ? $v : '';

        return [
            'utilisateur' => $texte('user'),
            'action' => $texte('action'),
            'du' => $date($texte('from')),
            'au' => $date($texte('to')),
        ];
    }

    public function compte(array $filtres): int
    {
        return (int) $this->requete($filtres)->count();
    }

    /** Une page de lignes, la plus recente d'abord. */
    public function lignes(array $filtres, int $page, int $parPage = self::PAR_PAGE): array
    {
        $decalage = max(0, ($page - 1) * $parPage);

        return $this->requete($filtres)
            ->select('l.id', 'l.action', 'l.created_at', 'u.name as utilisateur')
            ->orderByDesc('l.created_at')
            ->offset($decalage)->limit($parPage)
            ->get()->map(static fn ($l) => (array) $l)->all();
    }

    /**
     * TOUTES les lignes filtrees, pour l'export — jamais la seule page affichee.
     * Le legacy porte ici un defaut deja corrige chez lui, et le commentaire de
     * `audit_log.php:46` le dit : « l'export ne prenait que les 50 rows de la
     * page courante ». On garde la correction.
     */
    public function toutesPourExport(array $filtres): \Generator
    {
        $requete = $this->requete($filtres)
            ->select('l.id', 'l.action', 'l.created_at', 'u.name as utilisateur')
            ->orderByDesc('l.created_at');

        foreach ($requete->cursor() as $ligne) {
            yield (array) $ligne;
        }
    }

    private function requete(array $filtres): \Illuminate\Database\Query\Builder
    {
        $q = DB::table('user_logs as l')->join('users as u', 'l.user_id', '=', 'u.id');

        if ($filtres['utilisateur'] !== '') {
            $q->where('u.name', 'like', '%' . $filtres['utilisateur'] . '%');
        }
        if ($filtres['action'] !== '') {
            $q->where('l.action', 'like', '%' . $filtres['action'] . '%');
        }
        if ($filtres['du'] !== '') {
            $q->where('l.created_at', '>=', $filtres['du'] . ' 00:00:00');
        }
        if ($filtres['au'] !== '') {
            $q->where('l.created_at', '<=', $filtres['au'] . ' 23:59:59');
        }

        return $q;
    }

    /* ═══ La chaine — UN SEUL parcours ══════════════════════════════════════ */

    /**
     * Parcourt la chaine une fois et rend tout ce dont la verification ET le
     * scellement ont besoin.
     *
     * La regle est celle du CODE QUI ECRIT : une ligne non scellee ne participe
     * pas a la chaine, donc la tete n'avance pas dessus.
     *
     * @return array{total:int, scellees:int, orphelines:int, tete:?string,
     *               erreur:?array, aSceller:array<int, array{0:int,1:string,2:string}>}
     */
    public function parcourt(): array
    {
        $tete = self::GENESE;
        $total = 0;
        $scellees = 0;
        $orphelines = 0;
        $erreur = null;
        $aSceller = [];

        $lignes = DB::table('user_logs')
            ->selectRaw('id, user_id, action, UNIX_TIMESTAMP(created_at) as ts, prev_hash, self_hash')
            ->orderBy('id')->cursor();

        foreach ($lignes as $l) {
            $total++;

            if ($l->self_hash === null) {
                $orphelines++;
                // La tete N'AVANCE PAS : c'est ce que fait `audit_log_raw`, et
                // c'est donc ce que la chaine inscrite en base signifie. Le
                // hachage propose reprend la tete courante — sceller cette ligne
                // la place exactement la ou le prochain INSERT l'aurait placee.
                $aSceller[] = [(int) $l->id, $tete,
                    $this->empreinte($tete, (int) $l->user_id, (string) $l->action, (int) $l->ts)];

                continue;
            }

            $scellees++;

            if ($erreur === null && $l->prev_hash !== $tete) {
                $erreur = [
                    'id' => (int) $l->id,
                    'type' => 'CHAINON_ROMPU',
                    'attendu' => $this->abrege($tete),
                    'trouve' => $this->abrege((string) $l->prev_hash),
                ];
            }

            if ($erreur === null && ! $this->verifieEmpreinte(
                (string) $l->self_hash, (string) $l->prev_hash,
                (int) $l->user_id, (string) $l->action, (int) $l->ts
            )) {
                $erreur = [
                    'id' => (int) $l->id,
                    'type' => 'EMPREINTE_ALTEREE',
                    'attendu' => $this->abrege($this->empreinte(
                        (string) $l->prev_hash, (int) $l->user_id,
                        (string) $l->action, (int) $l->ts
                    )),
                    'trouve' => $this->abrege((string) $l->self_hash),
                ];
            }

            $tete = (string) $l->self_hash;
        }

        return [
            'total' => $total,
            'scellees' => $scellees,
            'orphelines' => $orphelines,
            'tete' => $scellees > 0 ? $this->abrege($tete) : null,
            'erreur' => $erreur,
            'aSceller' => $aSceller,
        ];
    }

    /** Le verdict d'integrite, sans rien ecrire. */
    public function verifie(): array
    {
        $p = $this->parcourt();

        return [
            'integre' => $p['erreur'] === null,
            'total' => $p['total'],
            'scellees' => $p['scellees'],
            'orphelines' => $p['orphelines'],
            'tete' => $p['tete'],
            'erreur' => $p['erreur'],
        ];
    }

    /**
     * ⛔ NE SCELLE PLUS RIEN — arbitrage E-415 du 2026-09-05.
     *
     * ══ POURQUOI CETTE METHODE N'ECRIT PLUS ────────────────────────────────
     *
     * Mesure du 2026-09-05 14:39 : 6272 lignes, 4788 scellees, 1484 nues, et
     * **4788 `prev_hash` DISTINCTS** parmi les scellees — la chaine est INTACTE.
     *
     * Les 1484 nues portent un `prev_hash` NUL, toutes. Elles sont hors chaine
     * PAR CONSTRUCTION : la tete se calcule en les sautant, ici comme dans le
     * legacy (`SELECT self_hash … WHERE self_hash IS NOT NULL ORDER BY id DESC`).
     *
     *     id 1  prev=GENESIS    self=d36ccba57
     *     id 2  prev=(null)     self=(NULL)      <- nue
     *     id 3  prev=d36ccba57  self=5a070372c   <- reprend id=1, SAUTE id=2
     *
     * **Les y remettre exige de reecrire le `prev_hash` des 4788 autres**, donc
     * de detruire la seule propriete que la chaine apporte. Les deux sceleurs du
     * depot etaient deux impasses :
     *
     *     le LEGACY   avance sa tete, casse a la 1re scellee qui suit, et STOPPE
     *     ce PORTAGE  posait 1484 `prev_hash` IDENTIQUES, et le `whereNull` qui
     *                 l'accompagnait interdisait la reprise — CASSE **ET** BLOQUE
     *
     * ⚠ Le commentaire qui justifiait le non-avancement de la tete citait un
     * comportement REEL (`audit_log_raw`) a l'appui du MAUVAIS objet : son
     * homologue est `audit_seal.php`, qui scelle en lot, pas l'inserteur qui
     * ecrit une ligne a la fois.
     *
     * ══ LE VRAI REMEDE EST AILLEURS, ET IL EST POSE ───────────────────────
     *
     * `backend/audit_chain.py` (v1.45.0) : 11 sites d'insertion nue repris,
     * compte restant **0**. On a cesse d'en fabriquer. Les 1484 restent, et le
     * DIRE est plus honnete que de leur donner un faux chainage.
     *
     * ══ FORME ─────────────────────────────────────────────────────────────
     *
     * L'ecriture n'est pas mise derriere un drapeau : elle est RETIREE. Une
     * garde par construction ne depend pas de la justesse de l'instrument qui
     * la verifierait, ni de la vigilance de qui relira ce fichier.
     *
     * @return array l'etat de la chaine, et le motif du refus
     */
    public function scelle(bool $simulation): array
    {
        $p = $this->parcourt();

        return [
            'simulation' => $simulation,
            'total' => $p['total'],
            'orphelines' => $p['orphelines'],
            'scellees' => 0,
            'scellement_possible' => false,
            'motif' => 'audit.scellement_impossible',
            'arret_sur_incoherence' => $p['erreur'] !== null,
            'erreur' => $p['erreur'],
            'tete' => $p['tete'],
        ];
    }

    /* ═══ Empreintes — la formule du legacy, au caractere pres ══════════════ */

    /**
     * Ajoute une ligne au journal, EN CHAINANT — l'ecrivain canonique.
     *
     * ══ POURQUOI CETTE METHODE, ET POURQUOI AVEC UN VERROU ────────────────
     *
     * Le portage porte DEJA trois copies de cet insert (`ComptesController`,
     * `PermissionsController`, `ServeursController`) et une quatrieme ecriture
     * NUE assumee (`MotDePasse`, qui documente son choix). En ecrire une
     * cinquieme etait la solution la moins couteuse et la plus mauvaise : ce
     * depot a paye trois copies du garde SSRF et trois compteurs 2FA.
     *
     * ⚠ ET LES TROIS COPIES EXISTANTES OMETTENT LE VERROU. Elles lisent la tete
     * de chaine par un simple `orderByDesc('id')->value('self_hash')`, hors
     * transaction. Le legacy, lui, le fait dans une transaction avec
     * `FOR UPDATE` (`adm/includes/audit_log.php:107-116`) — et ce verrou n'est
     * pas decoratif : **deux ecritures concurrentes qui lisent la meme tete
     * produisent deux lignes portant le MEME `prev_hash`, donc une chaine
     * FOURCHUE**, que `verifie()` signalera comme rompue sans pouvoir dire
     * laquelle des deux branches est la bonne.
     *
     * Cette methode reprend donc le verrou du legacy. **Les trois copies
     * restent a migrer** — ce n'est pas fait ici, et c'est declare.
     */
    public function ajoute(int $auteur, string $action): void
    {
        $action = mb_substr($action, 0, 255);
        try {
            DB::transaction(function () use ($auteur, $action): void {
                $tete = DB::table('user_logs')->whereNotNull('self_hash')
                    ->orderByDesc('id')->lockForUpdate()->value('self_hash') ?: self::GENESE;
                $ts = time();
                DB::table('user_logs')->insert([
                    'user_id' => $auteur,
                    'action' => $action,
                    'created_at' => date('Y-m-d H:i:s', $ts),
                    'prev_hash' => $tete,
                    'self_hash' => $this->empreinte($tete, $auteur, $action, $ts),
                ]);
            });
        } catch (\Throwable $e) {
            /*
             * Best-effort, comme le legacy : un echec de journalisation ne doit
             * pas annuler le geste qu'il trace. Mais il se JOURNALISE, sans quoi
             * une trace manquante serait indiscernable d'un geste non accompli.
             */
            \Illuminate\Support\Facades\Log::error('journal d\'audit : ecriture impossible', [
                'auteur' => $auteur,
                'erreur' => $e->getMessage(),
            ]);
        }
    }

    public function empreinte(string $precedent, int $utilisateur, string $action, int $ts): string
    {
        return hash_hmac('sha256', implode('|', [$precedent, (string) $utilisateur, $action, (string) $ts]), $this->cle());
    }

    /**
     * Accepte l'empreinte HMAC (format courant) OU le SHA-256 nu des lignes
     * scellees avant le correctif A08-02. Sans ce second essai, toutes les
     * lignes anciennes seraient declarees alterees.
     */
    public function verifieEmpreinte(string $stockee, string $precedent, int $utilisateur, string $action, int $ts): bool
    {
        if (hash_equals($stockee, $this->empreinte($precedent, $utilisateur, $action, $ts))) {
            return true;
        }

        return hash_equals(
            $stockee,
            hash('sha256', implode('|', [$precedent, (string) $utilisateur, $action, (string) $ts]))
        );
    }

    /**
     * `AUDIT_HMAC_KEY` si elle existe, `SECRET_KEY` sinon — l'ordre exact du
     * legacy (`adm/includes/audit_log.php:44-58`). Mesure de cet environnement
     * au 2026-08-25 : la premiere est ABSENTE, donc les deux portails signent
     * avec `SECRET_KEY`. Separer les deux cles est une decision d'exploitation,
     * pas un detour de portage : la changer ici rendrait illisibles les 3311
     * lignes deja scellees.
     */
    private function cle(): string
    {
        if ($this->cleHmac === null) {
            $dediee = (string) config('rootwarden.audit.cle_hmac', '');
            $this->cleHmac = $dediee !== ''
                ? $dediee
                : ((string) config('rootwarden.secret_key', '') ?: 'rootwarden-audit-default');
        }

        return $this->cleHmac;
    }

    private function abrege(string $empreinte): string
    {
        return mb_substr($empreinte, 0, 16) . '…';
    }
}
