<?php

namespace App\Services;

use Cron\CronExpression;
use Illuminate\Support\Facades\DB;

/**
 * Les planifications de scans CVE — module `security/`, sous-lot S4.
 *
 * TOUTE LA VALIDATION VIT ICI, et c'est le coeur du sous-lot : cinq defauts
 * mesures sur le legacy s'y referment, dont un qui est un risque d'exploitation.
 *
 * LE CLAMP ANTI-FREQUENCE EST REJOUE A LA MODIFICATION. Cote legacy il ne l'est
 * pas : a la creation (`backend/routes/cve.py:500-517`) le code valide
 * l'expression, calcule DEUX occurrences et refuse en dessous de 600 s — son
 * commentaire nomme le risque, « `* * * * *` lancait un scan par minute -> ban
 * OpenCVE upstream + DoS interne ». Au `PUT` (`cve.py:549-566`),
 * `cron_expression` est ajoute a la requete AVANT toute validation, le bloc
 * suivant ne recalcule que `next_run` sans `is_valid` ni comparaison, et un
 * `except Exception: pass` avale l'echec : l'`UPDATE` ecrit quand meme. MESURE EN
 * FONCTIONNEMENT : un `PUT` avec `* * * * *` rend 200 et la base porte
 * l'expression. Ici la MEME fonction valide les deux chemins — il n'existe pas
 * d'endroit ou le clamp puisse manquer.
 *
 * CE QUE CE SERVICE N'ECRIT JAMAIS. `last_run` appartient au scheduler Python
 * (`backend/scheduler.py:125-128`), qui l'ecrit AVANT d'executer et saute
 * l'execution si l'`UPDATE` echoue — c'est sa garantie anti-boucle (fix
 * v1.37.14). Y toucher la casserait. Et `next_run` n'est JAMAIS laisse a NULL sur
 * une ligne active : la requete de `scheduler.py:614` prend
 * `next_run IS NULL OR next_run <= now`, donc une ligne active sans echeance
 * declencherait un scan dans la minute.
 *
 * AUCUN SCAN N'EST DECLENCHE ICI. Creer ou modifier une planification n'ecrit que
 * la table ; le seul declencheur est la boucle du scheduler. C'est ce que fait le
 * legacy, et c'est ce qu'il faut continuer a faire.
 */
class PlanificationsCve
{
    /** Intervalle minimum entre deux executions, en secondes. */
    public const INTERVALLE_MINIMUM = 600;

    /** Les seules sources de scan acceptees. Deja en liste blanche cote legacy. */
    public const SOURCES = ['fast', 'hybrid', 'precise'];

    /**
     * Les seules cibles acceptees — c'est l'ENUM de la colonne
     * (`mysql/init.sql:312`). Le legacy ne le controle PAS cote code, alors que
     * `scan_source` juste a cote l'est : une cible hors liste produisait un 500
     * avec une page HTML au lieu d'un 400.
     */
    public const CIBLES = ['all', 'tag', 'machines'];

    /** @return list<object> */
    public function liste(): array
    {
        return DB::table('cve_scan_schedules as s')
            ->leftJoin('users as u', 'u.id', '=', 's.created_by')
            ->select('s.id', 's.name', 's.cron_expression', 's.min_cvss', 's.scan_source',
                     's.target_type', 's.target_value', 's.enabled', 's.last_run', 's.next_run',
                     'u.name as auteur')
            ->orderByDesc('s.created_at')
            ->get()
            ->all();
    }

    public function parId(int $id): ?object
    {
        return DB::table('cve_scan_schedules')->where('id', $id)->first();
    }

    /**
     * Les cinq prochaines executions d'une expression, plus sa validite.
     *
     * ECART VOULU. Le legacy rend en plus une PHRASE en francais, fabriquee en
     * Python (`cve.py:460-474`) : « Tous les jours a 03:00 ». Elle n'est donc
     * traduisible par aucun mecanisme du portage. Les cinq dates reelles, mises
     * en forme dans la langue de la session, disent la meme chose et davantage.
     *
     * @return array{valide:bool,prochaines:list<string>,intervalle:?int}
     */
    public function apercu(string $expression): array
    {
        if (! CronExpression::isValidExpression($expression)) {
            return ['valide' => false, 'prochaines' => [], 'intervalle' => null];
        }

        $cron = new CronExpression($expression);
        $prochaines = [];
        $depuis = new \DateTime();
        for ($i = 0; $i < 5; $i++) {
            $depuis = $cron->getNextRunDate($depuis);
            $prochaines[] = $depuis->format('Y-m-d H:i:s');
        }

        return [
            'valide' => true,
            'prochaines' => $prochaines,
            'intervalle' => $this->intervalle($expression),
        ];
    }

    /**
     * Valide un jeu de champs. Rend la liste des refus, vide si tout va bien.
     *
     * `$creation` ne change QUE la liste des champs obligatoires — jamais la
     * severite des controles. C'est precisement la ou le legacy se relache : son
     * `PUT` ne revalide ni le cron, ni le nom, ni le seuil.
     *
     * @param  array<string,mixed>  $d
     * @return array<string,string>  champ => raison
     */
    public function valide(array $d, bool $creation): array
    {
        $refus = [];

        if ($creation || array_key_exists('name', $d)) {
            $nom = trim((string) ($d['name'] ?? ''));
            if ($nom === '') {
                $refus['name'] = 'nom_requis';
            } elseif (mb_strlen($nom) > 100) {
                // La colonne est un VARCHAR(100) : sans ce controle, MySQL en
                // mode strict rend une erreur 1406, donc un 500 et non un 400.
                $refus['name'] = 'nom_trop_long';
            }
        }

        if ($creation || array_key_exists('cron_expression', $d)) {
            $expr = trim((string) ($d['cron_expression'] ?? ''));
            if (! CronExpression::isValidExpression($expr)) {
                $refus['cron_expression'] = 'cron_invalide';
            } else {
                $intervalle = $this->intervalle($expr);
                if ($intervalle !== null && $intervalle < self::INTERVALLE_MINIMUM) {
                    $refus['cron_expression'] = 'cron_trop_frequent';
                }
            }
        }

        if ($creation || array_key_exists('min_cvss', $d)) {
            $seuil = $d['min_cvss'] ?? 0;
            if (! is_numeric($seuil) || (float) $seuil < 0 || (float) $seuil > 10) {
                // `DECIMAL(3,1)` : au-dela de 99,9 MySQL refuse et rend un 500.
                // Le vrai domaine d'un score CVSS est 0-10.
                $refus['min_cvss'] = 'seuil_hors_bornes';
            }
        }

        if ($creation || array_key_exists('scan_source', $d)) {
            if (! in_array((string) ($d['scan_source'] ?? 'hybrid'), self::SOURCES, true)) {
                $refus['scan_source'] = 'source_inconnue';
            }
        }

        if ($creation || array_key_exists('target_type', $d)) {
            $cible = (string) ($d['target_type'] ?? 'all');
            if (! in_array($cible, self::CIBLES, true)) {
                $refus['target_type'] = 'cible_inconnue';
            } elseif ($cible === 'tag' && trim((string) ($d['target_value'] ?? '')) === '') {
                $refus['target_value'] = 'tag_requis';
            } elseif ($cible === 'machines') {
                // Une liste ILLISIBLE ou VIDE est refusee ici, et ce n'est pas du
                // zele : cote scheduler (`scheduler.py:198-209`) une cible
                // `machines` dont la valeur ne se decode pas RETOMBE SUR TOUT LE
                // PARC. Accepter la ligne, c'est armer un scan complet.
                $ids = json_decode((string) ($d['target_value'] ?? ''), true);
                if (! is_array($ids) || $ids === []) {
                    $refus['target_value'] = 'machines_requises';
                } elseif ($this->machinesInconnues($ids) !== []) {
                    $refus['target_value'] = 'machines_inconnues';
                }
            }
        }

        return $refus;
    }

    /** @param  array<string,mixed>  $d */
    public function creer(array $d, int $idCompte): int
    {
        $expr = trim((string) $d['cron_expression']);

        return (int) DB::table('cve_scan_schedules')->insertGetId([
            'name'            => trim((string) $d['name']),
            'cron_expression' => $expr,
            'min_cvss'        => (float) ($d['min_cvss'] ?? 0),
            'scan_source'     => (string) ($d['scan_source'] ?? 'hybrid'),
            'target_type'     => (string) ($d['target_type'] ?? 'all'),
            'target_value'    => (string) ($d['target_value'] ?? ''),
            // JAMAIS NULL sur une ligne active : le scheduler declencherait dans
            // la minute.
            'next_run'        => $this->prochaine($expr),
            // LE LEGACY NE L'ECRIT JAMAIS, alors que la colonne existe et pointe
            // vers `users(id)`. Une planification sans auteur ne se reproche a
            // personne.
            'created_by'      => $idCompte,
        ]);
    }

    /** @param  array<string,mixed>  $d */
    public function modifier(int $id, array $d): void
    {
        $champs = [];
        foreach (['name', 'cron_expression', 'min_cvss', 'scan_source', 'target_type', 'target_value'] as $c) {
            if (array_key_exists($c, $d)) {
                $champs[$c] = is_string($d[$c]) ? trim($d[$c]) : $d[$c];
            }
        }
        if (array_key_exists('enabled', $d)) {
            // La colonne est un TINYINT(1) : on ne relaie pas la valeur brute du
            // client, on la ramene a 0 ou 1.
            $champs['enabled'] = filter_var($d['enabled'], FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
        }
        if (array_key_exists('min_cvss', $champs)) {
            $champs['min_cvss'] = (float) $champs['min_cvss'];
        }
        // L'echeance suit l'expression, et seulement elle. Recalculer `next_run`
        // en dehors de ce cas entrerait en concurrence avec `_advance_schedule`.
        if (array_key_exists('cron_expression', $champs)) {
            $champs['next_run'] = $this->prochaine((string) $champs['cron_expression']);
        }

        if ($champs !== []) {
            DB::table('cve_scan_schedules')->where('id', $id)->update($champs);
        }
    }

    public function supprimer(int $id): bool
    {
        return DB::table('cve_scan_schedules')->where('id', $id)->delete() > 0;
    }

    /** Les tags reellement portes par au moins une machine NON archivee. */
    public function tagsDisponibles(): array
    {
        return DB::table('machine_tags as mt')
            ->join('machines as m', 'm.id', '=', 'mt.machine_id')
            ->where(function ($q) {
                $q->whereNull('m.lifecycle_status')->orWhere('m.lifecycle_status', '!=', 'archived');
            })
            ->whereNotNull('mt.tag')->where('mt.tag', '!=', '')
            ->distinct()->orderBy('mt.tag')->pluck('mt.tag')->all();
    }

    /**
     * L'intervalle, en secondes, entre les deux prochaines executions.
     *
     * Deux occurrences suffisent pour un cron periodique. Rend `null` si
     * l'expression ne se calcule pas — l'appelant a deja verifie sa validite.
     */
    private function intervalle(string $expression): ?int
    {
        try {
            $cron = new CronExpression($expression);
            $premiere = $cron->getNextRunDate();
            $seconde = $cron->getNextRunDate($premiere);

            return $seconde->getTimestamp() - $premiere->getTimestamp();
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * La prochaine execution, au format de la base.
     *
     * MEME BASE HORAIRE QUE LE LEGACY : `datetime` naif, heure du processus
     * (`cve.py:504` fait `croniter(expr).get_next(datetime)` sans fuseau, et le
     * scheduler compare a `datetime.now()`). Poser un UTC ici decalerait le
     * declenchement de l'ecart de fuseau — dans le sens qui declenche tout de
     * suite si l'ecart est negatif.
     */
    private function prochaine(string $expression): string
    {
        return (new CronExpression($expression))->getNextRunDate()->format('Y-m-d H:i:s');
    }

    /** @param  list<mixed>  $ids */
    private function machinesInconnues(array $ids): array
    {
        $demandes = array_values(array_unique(array_map('intval', $ids)));
        $connues = DB::table('machines')
            ->whereIn('id', $demandes)
            ->where(function ($q) {
                $q->whereNull('lifecycle_status')->orWhere('lifecycle_status', '!=', 'archived');
            })
            ->pluck('id')->all();

        return array_values(array_diff($demandes, array_map('intval', $connues)));
    }
}
