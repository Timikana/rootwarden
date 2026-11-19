<?php

declare(strict_types=1);

namespace App\Services;

use App\Http\Controllers\Auth\ReinitialisationController;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

/**
 * Le lien d'acces envoye par un administrateur : un courriel qui porte un lien
 * a usage unique pour choisir son mot de passe.
 *
 * C'est le « magic link d'activation » du legacy (`manage_users.php:129`,
 * `mail_helper.php:sendActivationEmail`), perdu a l'extinction : le portage
 * remettait un mot de passe genere a l'ecran, a transmettre de la main a la main.
 *
 * ══ LE MEME JETON QUE « MOT DE PASSE OUBLIE » ═════════════════════════════
 *
 * `ReinitialisationMotDePasse::emet()`, le meme formulaire, le meme
 * `MotDePasse::reinitialise()` — donc la meme politique, la meme purge des
 * sessions. Seule la duree change : 24 heures, celle du legacy, parce qu'un
 * courriel d'administrateur se lit le lendemain matin, pas dans l'heure.
 *
 * ⚠ EMETTRE CE LIEN TUE LES LIENS EN COURS DU COMPTE, y compris celui qu'il
 * aurait demande lui-meme : `emet()` les consomme d'abord. C'est voulu, un seul
 * lien vivant par compte.
 *
 * ══ CE LIEN N'OUVRE AUCUNE SESSION ═══════════════════════════════════════
 *
 * Il fait choisir un mot de passe, puis le compte se connecte par l'ecran de
 * connexion, second facteur compris. Un lien qui connecterait directement ferait
 * de la boite de courriel un facteur unique.
 *
 * ══ PAS D'EGALISATION DE TEMPS ICI ═══════════════════════════════════════
 *
 * Contrairement a « mot de passe oublie », le demandeur est un administrateur
 * authentifie qui voit deja la liste des comptes : il n'y a rien a enumerer.
 * L'envoi est donc SYNCHRONE, et son echec se dit a l'ecran.
 */
final class LienAcces
{
    /** 24 heures, comme l'activation du legacy (`strtotime('+24 hours')`). */
    public const DUREE_SECONDES = 86400;

    /** Un envoi par compte et par minute : un double clic n'envoie pas deux courriels. */
    public const INTERVALLE_SECONDES = 60;

    public function __construct(
        private readonly ReinitialisationMotDePasse $jetons,
    ) {
    }

    /**
     * Le transport ne sort pas de la machine : personne ne recevra le courriel,
     * et l'ecran doit le dire.
     *
     * ⚠ L'ECRAN NE DIT PAS « ECRIT DANS LE JOURNAL ». Le transport `log` ecrit
     * au niveau `debug` : des que `LOG_LEVEL` vaut `info` (mesure sur la pile
     * isolee, 2026-11-19), le courriel n'est ecrit nulle part.
     */
    public function transportLocal(): bool
    {
        return in_array((string) config('mail.default'),
            ReinitialisationController::TRANSPORTS_LOCAUX, true);
    }

    /**
     * Emet un jeton et envoie le lien. Rend `null` en cas de succes, sinon la
     * cle i18n du refus.
     *
     * @param  callable(int, string): string  $url  construit le lien depuis
     *         (uid, jeton) — la route vit cote HTTP, pas dans le service
     */
    public function envoie(int $idCompte, int $roleAuteur, string $ip, callable $url): ?string
    {
        $cible = DB::table('users')->where('id', $idCompte)
            ->first(['id', 'name', 'email', 'role_id', 'active']);
        if ($cible === null) {
            return 'comptes.err_inconnu';
        }
        // La garde hierarchique de `motDePasse()` : un role 2 ne fait pas
        // choisir le mot de passe d'un role 3.
        if ($roleAuteur < 3 && (int) $cible->role_id >= 3) {
            return 'comptes.err_hierarchie';
        }
        // Un compte suspendu ne se connecte pas : lui envoyer un lien lui
        // ferait choisir un mot de passe inutilisable.
        if ((int) $cible->active !== 1) {
            return 'comptes.lien_inactif';
        }
        $courriel = (string) ($cible->email ?? '');
        if (filter_var($courriel, FILTER_VALIDATE_EMAIL) === false) {
            return 'comptes.lien_sans_courriel';
        }
        // `add` n'ecrit que si la cle est absente : c'est le verrou.
        if (! Cache::add('lien-acces:' . $idCompte, 1, self::INTERVALLE_SECONDES)) {
            return 'comptes.lien_trop_tot';
        }

        $clair = $this->jetons->emet($idCompte, $ip, self::DUREE_SECONDES);

        try {
            Mail::raw(
                __('comptes.lien_courriel_corps', [
                    'nom' => $cible->name,
                    'lien' => $url($idCompte, $clair),
                    'heures' => intdiv(self::DUREE_SECONDES, 3600),
                ]),
                function ($m) use ($courriel) {
                    $m->to($courriel)->subject(__('comptes.lien_courriel_sujet'));
                }
            );
        } catch (\Throwable $e) {
            // Un lien que personne n'a recu ne doit pas rester valable 24 heures.
            $this->jetons->consomme($idCompte);
            Log::error('[lien-acces] envoi impossible : ' . $e->getMessage());

            return 'comptes.lien_echec';
        }

        return null;
    }
}
