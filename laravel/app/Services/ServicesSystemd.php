<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Le pilotage des services systemd distants — module `services/`, sous-lot S1.
 *
 * Porte `legacy/services/index.php`. S1 ne couvre que **la page** : son
 * inventaire de machines et ses gardes. Les lectures distantes sont S2, les
 * ecritures S3.
 *
 * ══ E-149 : LA GARDE EST SUR LA PAGE, PAS SUR LA REQUETE ═════════════════
 *
 * **Ce module porte le sixieme cas du motif le plus repandu du depot**, et le
 * portage ne le referme pas — il ne le peut pas seul.
 *
 * Les huit routes de `backend/routes/services.py` portent `@require_api_key`,
 * `@require_machine_access` et `@threaded_route` — **ni `@require_role`, ni
 * `@require_permission`**. Et `/services/` est absent des deux listes
 * « admin » : `$ADMIN_ONLY_PREFIXES` cote legacy, `ADMIN_SEULEMENT` cote
 * portage. `check_machine_access()` ouvrant par « role >= 2 : acces a tout », le
 * seul garde restant sur la requete est la cle d'API — que le proxy fournit.
 *
 * **Mesure du 2026-08-27 : le trou est reel dans le code et n'est exploitable
 * par aucun compte existant.** Le seul compte de role 2 du parc detient
 * `can_manage_services` ; le compte de role 1 qui ne l'a pas est arrete par
 * `@require_machine_access`, qui pour lui n'est PAS inerte.
 *
 * Le refermer pour les DEUX portails exige `@require_permission` sur les huit
 * routes backend, donc de toucher la production. C'est un correctif de securite :
 * branche dediee, jamais fusionne sans accord verbal. **Porte au §7 du plan.**
 *
 * ══ CE QUE LE PORTAGE CORRIGE, ET C'EST DE PRESENTATION ══════════════════
 *
 * Deux constats de S1, vus a l'image puis mesures :
 *
 * 1. **Les trois filtres sont presents mais INVISIBLES au chargement.** Une
 *    assertion d'existence les declarait bons ; ils ne paraissent qu'une fois un
 *    serveur charge. Le portage les montre des le depart, desactives, avec la
 *    raison — un filtre qui apparait sans prevenir se cherche.
 * 2. **Un panneau de journaux VIDE est affiche des le chargement** — un cadre
 *    noir qui ne dit rien. La convention du chantier veut qu'un etat vide DISE
 *    ce qui manque et pourquoi.
 */
class ServicesSystemd
{
    /**
     * Les machines proposables.
     *
     * `criticality` et `environment` sont retenues pour que l'ecran puisse
     * DISTINGUER la production — ce module pilote des services systemd, et
     * `srv-zabbix` en fait tourner. Meme raison qu'en `bashrc/` B1.
     */
    public function machines(): array
    {
        return DB::select(
            'SELECT id, name, ip, port, environment, criticality '
            . 'FROM machines '
            . "WHERE lifecycle_status IS NULL OR lifecycle_status != 'archived' "
            . 'ORDER BY name'
        );
    }

    /**
     * Cette machine demande-t-elle une attention particuliere ?
     *
     * Reprise a l'identique de `Bashrc::estSensible()` : `PROD` OU `CRITIQUE`,
     * et **`OTHER` ou une valeur vide comptent comme sensibles** — un
     * environnement inconnu ne se range pas du cote sur.
     *
     * Les deux colonnes sont des `enum` (`PROD|DEV|TEST|OTHER` et
     * `CRITIQUE|NON CRITIQUE`), relevees en base le 2026-08-26.
     */
    public function estSensible(object $machine): bool
    {
        $env = strtoupper(trim((string) ($machine->environment ?? '')));
        $crit = strtoupper(trim((string) ($machine->criticality ?? '')));

        return $env === 'PROD' || $env === 'OTHER' || $env === ''
            || $crit === 'CRITIQUE';
    }

    /** Le nombre de machines sensibles, pour l'annonce d'ensemble. */
    public function compteSensibles(array $machines): int
    {
        return count(array_filter($machines, fn ($m) => $this->estSensible($m)));
    }
}
