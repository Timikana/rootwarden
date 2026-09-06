<?php

declare(strict_types=1);

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * `login_history` — l'historique des connexions, et **le lecteur qui lui
 * survivrait**.
 *
 * ══ POURQUOI CETTE ECRITURE COMPTE PLUS QUE SA TAILLE ═════════════════════
 *
 * Mesure du 2026-09-05 : **5 067 lignes, derniere ecriture le jour meme**, et
 * **un seul ecrivain — `legacy/auth/login.php`**. Le portage n'en avait aucun.
 *
 * `ExportRgpd` LIT cette table (`:131`) : c'est une section d'un livrable
 * d'exercice du droit d'acces. **Eteindre le legacy sans porter cette ecriture
 * fige la donnee au jour de l'extinction — et le lecteur continue de repondre**,
 * en presentant comme complet un jeu qui a cesse de croitre.
 *
 * ⚠ ET LE DISPOSITIF CONCU CONTRE CE MENSONGE Y EST AVEUGLE. `ExportRgpd` porte
 * `_total`, `_exportees` et `_tronque` sur chaque section bornee, ecrits
 * precisement parce que le legacy livrait *« un JSON qui se presente comme
 * complet »*. **Aucun des trois n'attraperait le gel** : rien n'est tronque, la
 * donnee s'arrete. *Le compteur dirait la verite sur un ensemble mort.*
 *
 * ══ DEUX STATUTS SUR QUATRE, ET LES DEUX AUTRES N'ONT AUCUN ECRIVAIN ══════
 *
 * La colonne est un `enum('success','failed_password','failed_2fa','locked')`.
 * Mesure : le legacy n'ecrit QUE les deux premiers (`login.php:206` et `:267`),
 * et la base ne porte que ces deux-la — 4 957 et 110.
 *
 * **`failed_2fa` et `locked` n'ont d'ecrivain nulle part, dans aucun des deux
 * portails.** On ne les invente donc pas ici : *porter un statut que personne
 * n'ecrit reviendrait a fabriquer une donnee qui n'a jamais existe, et a rendre
 * un export plus riche que l'historique qu'il decrit.* Ils sont declares, pas
 * comples.
 */
final class HistoriqueConnexions
{
    /**
     * Les deux statuts REELLEMENT ecrits, releves du legacy et de la base.
     *
     * Liste fermee : `enregistre()` refuse tout autre valeur plutot que de
     * laisser MySQL trancher. *Un `enum` refuse en levant ; ici on refuse en
     * journalisant, parce qu'un historique manquant ne doit pas casser une
     * connexion valide.*
     */
    public const STATUTS = ['success', 'failed_password'];

    /** Les deux valeurs du schema que PERSONNE n'ecrit — declarees, pas portees. */
    public const STATUTS_SANS_ECRIVAIN = ['failed_2fa', 'locked'];

    /**
     * ⚠ L'ECHEC NE CASSE PAS LA CONNEXION, MAIS IL SE JOURNALISE.
     *
     * Le legacy avale l'exception sans rien dire. *Les insertions muettes sont
     * ce qui a permis a 1 484 lignes de se poser hors de la chaine d'audit sans
     * que personne ne le voie* — et une ligne d'historique qui n'arrive pas est
     * une ligne que l'export ne montrera jamais, sans qu'aucun compteur ne
     * l'annonce.
     *
     * `user_agent` est borne a 500 caracteres : c'est la largeur de la colonne,
     * et une chaine plus longue serait tronquee par MySQL — silencieusement en
     * mode permissif, par une erreur sinon. On tronque donc ici, ou on le voit.
     */
    public function enregistre(int $idCompte, string $statut, ?string $ip, ?string $agent): bool
    {
        if (! in_array($statut, self::STATUTS, true)) {
            Log::warning('[historique connexions] statut refuse : ' . $statut);

            return false;
        }

        try {
            DB::table('login_history')->insert([
                'user_id'    => $idCompte,
                'ip_address' => mb_substr($ip ?? '0.0.0.0', 0, 45),
                'user_agent' => $agent === null ? null : mb_substr($agent, 0, 500),
                'status'     => $statut,
                'created_at' => now(),
            ]);

            return true;
        } catch (\Throwable $e) {
            Log::warning('[historique connexions] insertion impossible pour le compte '
                . $idCompte . ' (' . $statut . ') : ' . $e->getMessage());

            return false;
        }
    }
}
