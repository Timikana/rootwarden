<?php

namespace App\Http\Controllers;

use App\Services\Machines;
use App\Services\PlanificationsCve;
use App\Services\Serveurs;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Audit de configuration SSH — sous-lot A1.
 *
 * ══ CE QUE A1 PORTE ═══════════════════════════════════════════════════════
 *
 * La LECTURE, et elle seule : les relevés déjà faits (`GET /ssh-audit/results`),
 * la politique appliquée (`GET /ssh-audit/policies`), l'état de la flotte
 * (`GET /ssh-audit/fleet`) et les relevés planifiés (`GET /ssh-audit/schedules`).
 *
 * ══ ET CE QU'IL N'APPELLE JAMAIS, DELIBEREMENT ════════════════════════════
 *
 * **`POST /ssh-audit/policies` n'est compose nulle part.** SEC-013 :
 *
 *     GET  /ssh-audit/policies  ->  require_permission('can_audit_ssh') + require_machine_access
 *     POST /ssh-audit/policies  ->  require_role(2)  SEUL
 *
 * Un role 2 sans la permission ne peut donc pas LIRE une politique et peut en
 * ECRIRE une, sur n'importe quelle machine. L'ecriture est moins gardee que la
 * lecture, sur la MEME URL — et la passerelle ne peut pas les separer :
 * `RoutesBackend::correspond` compare des CHEMINS, jamais des methodes. C'est
 * structurel, pas un oubli. La fermeture se fait donc **par l'absence
 * d'appel**, ici comme sur `iptables` en I1.
 *
 * ══ LA GARDE EST CELLE DU LEGACY, PAS UNE PLUS LARGE ══════════════════════
 *
 * `role:1` + `perm:can_audit_ssh`, comme `legacy/ssh-audit/index.php:12-13`.
 * **Surtout pas `role:2`** : cinq routes du module sont reellement concues
 * pour le role 1, et le passer a 2 reproduirait cote portage le croisement
 * qu'on reproche au backend.
 */
class AuditSshController extends Controller
{
    /*
     * ══ A2 — LES QUATRE PERIODICITES, ET POURQUOI ELLES SONT FERMEES ═══════
     *
     * Le legacy offre un champ cron LIBRE. Ici la liste est fermee, et ce
     * n'est pas de la prudence de principe : une planification declenche des
     * sessions SSH REELLES, a repetition, sans personne devant l'ecran.
     *
     * La borne serveur existe et elle tient (`ssh_audit.py:752-765` : cron
     * requis, intervalle minimum de DIX MINUTES, `target_type` en liste
     * fermee, `target_value` exigee des que la portee n'est pas `all`). Ce
     * n'est donc PAS le formulaire qui garde — c'est le serveur. Le formulaire
     * porte l'ergonomie : eviter l'erreur plutot que la refuser apres coup.
     *
     * ⚠ CAPACITE REDUITE ET DECLAREE : une expression cron arbitraire n'est
     * pas saisissable ici. `planif_freq_bornee` le dit a l'ecran et renvoie a
     * l'ancien portail. *Une capacite qui disparait doit etre DECLAREE, jamais
     * perdue.*
     *
     * Les quatre valeurs sont toutes au-dessus du plancher de dix minutes —
     * la plus frequente est horaire.
     */
    public const FREQUENCES = [
        'planif_freq_horaire'    => '0 * * * *',
        'planif_freq_six_heures' => '0 */6 * * *',
        'planif_freq_quotidien'  => '0 2 * * *',
        'planif_freq_hebdo'      => '0 3 * * 1',
    ];

    /** Les portees que le backend accepte — sa liste, pas une copie choisie. */
    /**
     * Les portees PROPOSABLES pour une planification. `all` n'y est plus.
     *
     * ══ SIX ETAGES, ET LE BACKEND REFUSE DEJA ═════════════════════════════
     *
     *   ssh_audit.py:816   PORTEES = ('tag','environment','machines')
     *              :826    `target_type == 'all'` -> 400, par DECISION
     *   -> garde ECRITE mais INERTE : les `.py` sont lus au DEMARRAGE.
     *      **Apres le redemarrage que l'exploitant attend, l'ecran proposerait
     *      ce que le serveur rejette.**
     *
     * Ce que le portage portait, et qui est ferme ici :
     *
     *   1. `all` PREMIER de cette liste -> l'option SELECTIONNEE par defaut
     *   2. `planif_portee_all`, le libelle de cette option -> devient mort
     *   3. `audit-ssh.js:458`  `planifPortee ? … : 'all'`  <- repli
     *   4. `audit-ssh.js:517`  idem, sur le chemin de SOUMISSION
     *
     * ⚠ 5. LA VUE N'A RIEN A CORRIGER, et c'est ce qui la sauve : elle construit
     * ses `<option>` DEPUIS cette constante (`audit-ssh.blade.php:194`). *Sur
     * `scan-cve` la liste etait ecrite a la main dans le gabarit, et retirer la
     * constante y aurait laisse une option que le serveur refuse (E-387).*
     * **Une liste rendue depuis sa source ne peut pas la contredire.**
     *
     * ⛔ 6. ET UN ETAGE HORS DE PORTEE, DECLARE : la colonne elle-meme est
     * `enum('all','tag','environment','machines') NOT NULL DEFAULT 'all'`. Un
     * `INSERT` omettant `target_type` obtiendrait donc `all` PAR LA BASE. Le
     * portage l'envoie toujours, et le backend refuse desormais cette valeur —
     * le mode de defaillance est un 400, pas un relevé du parc en silence. *Mais
     * le defaut du schema reste, et une migration n'est pas de mon ressort.*
     *
     * **`tag` rend le meme service en exigeant un geste explicite** : le
     * durcissement ferme les ACCIDENTS, rien ne ferme l'INTENTION — et un `all`
     * delibere, c'est une session SSH vers chaque machine, production comprise,
     * sur un calendrier et sans personne devant l'ecran.
     */
    public const PORTEES = ['environment', 'tag', 'machines'];

    public function __construct(
        private readonly Machines $machines,
        private readonly PlanificationsCve $planifications,
    ) {
    }

    public function __invoke(Request $requete): View
    {
        $role = (int) $requete->session()->get('role_id', 0);
        $idCompte = (int) $requete->session()->get('utilisateur_id', 0);

        /*
         * Le legacy refait la borne a la main (`index.php:22-33`) — sa propre
         * correction d'IDOR, le selecteur ayant liste tout le parc, noms et IP
         * compris, quel que soit le role. Ici c'est `Machines::perimetre` qui
         * la porte, et elle est ecrite UNE fois pour tout le service.
         */
        $perimetre = $this->machines->perimetre($role, $idCompte);

        return view('audit-ssh', [
            'serveurs' => $perimetre['serveurs'],
            'lisible'  => $perimetre['lisible'],
            // La borne MORD au role 1 seulement. Le dire evite d'afficher une
            // reserve a qui ne subit aucune restriction.
            'borne'    => $role < 2,
            // La flotte et les planifications sont reservees a
            // l'administration cote backend (`@require_role(2)`). Les afficher
            // au role 1 produirait deux 403 a l'ecran plutot qu'une absence
            // expliquee.
            'administration' => $role >= 2,
            /*
             * A2 : les trois listes fermees du formulaire. Elles ne sont
             * rendues QU'A l'administration — le role 1 n'a pas de formulaire,
             * et lui envoyer la liste des tags du parc serait une fuite de
             * perimetre pour un ecran qu'il ne voit pas.
             *
             * `tagsDisponibles()` est repris de `PlanificationsCve` plutot que
             * reecrit : les tags REELLEMENT portes par une machine non
             * archivee, une seule definition pour les deux modules.
             */
            'frequences' => $role >= 2 ? self::FREQUENCES : [],
            /*
             * Les trois listes de valeurs de portee, PRETES A L'EMPLOI.
             *
             * Construites ici et non dans la vue : `@json` ne franchit pas une
             * fonction flechee contenant un tableau, et le premier jet a
             * compile un `json_encode` TRONQUE — gabarit entier en erreur de
             * syntaxe, pour une expression pourtant sur une seule ligne. La
             * regle du projet disait « garder `@json` sur une ligne » ; elle
             * est NECESSAIRE ET PAS SUFFISANTE.
             *
             * Et c'est la bonne place de toute facon : une vue rend, elle ne
             * faconne pas la donnee.
             *
             * Les machines sont celles du PERIMETRE deja borne, pas une
             * seconde requete : deux lectures du parc divergent toujours a la
             * fin, et c'est celle qui borne le moins qu'on oublie.
             */
            'planifListes' => $role >= 2 ? [
                'environment' => Serveurs::ENVIRONNEMENTS,
                'tag' => $this->planifications->tagsDisponibles(),
                'machines' => array_map(
                    static fn ($m) => ['id' => (int) $m->id, 'nom' => (string) $m->name],
                    $perimetre['serveurs'],
                ),
            ] : ['environment' => [], 'tag' => [], 'machines' => []],
            'libelles' => __('ssh_audit'),
            'lienLegacy' => rtrim((string) config('app.url_legacy'), '/') . '/ssh-audit/',
        ]);
    }
}
