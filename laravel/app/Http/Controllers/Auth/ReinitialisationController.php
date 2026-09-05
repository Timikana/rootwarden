<?php

declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\MotDePasse;
use App\Services\ReinitialisationMotDePasse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\View\View;

/**
 * La reinitialisation de mot de passe par courriel.
 *
 * ══ CE QUI FERME L'ENUMERATION, ET CE QUI NE LA FERMAIT PAS ═══════════════
 *
 * Le legacy avait deja egalise le MESSAGE — il est hors du `if ($user)`, et son
 * commentaire dit que le defaut etait de l'avoir mis dedans. **Le TEMPS, lui,
 * ne l'etait pas**, et le correctif qui pretendait le fermer a egalise le terme
 * le moins couteux :
 *
 *     adresse INCONNUE          adresse CONNUE
 *     1 x password_hash         1 x UPDATE
 *                               1 x password_hash
 *                               1 x INSERT
 *                               1 x envoi SMTP **SYNCHRONE**
 *
 * *Un envoi SMTP dure des ordres de grandeur de plus qu'un bcrypt.* La branche
 * « l'adresse existe » etait donc nettement PLUS LENTE : l'oracle subsistait,
 * simplement inverse. **Le commentaire decrivait une mesure reelle portant sur
 * le mauvais terme.**
 *
 * ══ ET UNE FILE D'ATTENTE N'Y AURAIT RIEN CHANGE ══════════════════════════
 *
 * `QUEUE_CONNECTION=sync` (mesure) : `Mail::queue` s'EXECUTE EN LIGNE. Une
 * prescription de mise en file aurait ete inoperante ici, et elle aurait donne
 * l'apparence d'un correctif.
 *
 * **Le mecanisme employe est `terminating()`** : la fermeture s'execute APRES
 * que la reponse a ete transmise. L'envoi sort donc du temps mesurable par le
 * demandeur, sans dependre d'un ouvrier de file qui n'existe pas.
 *
 * ⚠ CE QUI SUBSISTE, ET QUI EST DIT PLUTOT QUE TU : un `UPDATE` et un `INSERT`
 * ne se produisent que dans la branche connue. Ils se comptent en fractions de
 * milliseconde la ou le bcrypt — egalise, lui — se compte en centaines. *Le
 * residu n'est pas nul ; il est borne, et il est enonce.*
 */
class ReinitialisationController extends Controller
{
    public function __construct(
        private readonly ReinitialisationMotDePasse $jetons,
        private readonly MotDePasse $motDePasse,
    ) {
    }

    /** L'ecran de demande. Aucune session requise — c'est tout son objet. */
    public function demander(): View
    {
        return view('auth.mot-de-passe-oublie');
    }

    public function envoyer(Request $requete): RedirectResponse
    {
        /*
         * ⚠ LA LIMITE D'ABORD, ET AVANT DE SAVOIR SI L'ADRESSE EXISTE.
         * C'est ce qui fait qu'elle compte les DEMANDES et non les jetons emis.
         */
        if (! $this->jetons->autorise((string) $requete->ip())) {
            return back()->with('erreur', __('reinit.trop_de_demandes'));
        }

        $courriel = (string) $requete->input('email', '');
        $compte = $courriel !== '' ? $this->jetons->compteParCourriel($courriel) : null;

        if ($compte === null) {
            // LE COUT EGALISE. Rien n'est ecrit, rien n'est envoye.
            $this->jetons->brule();
        } else {
            $clair = $this->jetons->emet((int) $compte->id, (string) $requete->ip());
            $lien = route('reinit.formulaire', ['uid' => (int) $compte->id, 'jeton' => $clair]);

            /*
             * L'ENVOI PART APRES LA REPONSE. Voir le docblock de classe : c'est
             * le terme qui refermait l'ecart de temps, et `sync` interdisait de
             * le mettre en file.
             *
             * Une exception d'envoi ne doit RIEN changer a ce qu'a vu le
             * demandeur : le jeton est deja emis, la reponse deja partie. On la
             * journalise et on s'arrete la.
             */
            app()->terminating(function () use ($compte, $lien): void {
                try {
                    Mail::raw(
                        __('reinit.courriel_corps', [
                            'nom' => $compte->name,
                            'lien' => $lien,
                            'heures' => 1,
                        ]),
                        function ($m) use ($compte) {
                            $m->to($compte->email)->subject(__('reinit.courriel_sujet'));
                        }
                    );
                } catch (\Throwable $e) {
                    Log::error('[reinitialisation] envoi impossible : ' . $e->getMessage());
                }
            });
        }

        /*
         * ⚠ « PREPARE » ET NON « ENVOYE ».
         *
         * `MAIL_MAILER` vaut `log` (mesure) : rien ne part vers une boite. Un
         * ecran qui affirmerait un envoi ferait attendre un courriel qui
         * n'arrivera pas, et ce serait FAUX aujourd'hui et vrai demain — donc
         * une phrase a rectifier au lieu d'une phrase juste.
         *
         * « Un lien a ete prepare » reste vrai dans les deux regimes.
         */
        return back()->with('succes', __('reinit.demande_recue'));
    }

    /**
     * L'ecran de saisie du nouveau mot de passe.
     *
     * Le jeton est valide ICI pour ne pas afficher un formulaire qui echouera —
     * **et il le sera A NOUVEAU avant l'ecriture**. Entre les deux, il peut
     * expirer ou etre consomme par une seconde soumission.
     */
    public function formulaire(Request $requete): View
    {
        $uid = (int) $requete->query('uid', 0);
        $jeton = (string) $requete->query('jeton', '');

        return view('auth.mot-de-passe-reinitialiser', [
            'uid' => $uid,
            'jeton' => $jeton,
            'valide' => $uid > 0 && $this->jetons->valide($uid, $jeton) !== null,
        ]);
    }

    public function appliquer(Request $requete): RedirectResponse
    {
        $uid = (int) $requete->input('uid', 0);
        $jeton = (string) $requete->input('jeton', '');

        // LA REVALIDATION, contre la double soumission.
        if ($uid <= 0 || $this->jetons->valide($uid, $jeton) === null) {
            return redirect()->route('reinit.demander')->with('erreur', __('reinit.jeton_invalide'));
        }

        $cle = $this->motDePasse->reinitialise(
            $uid,
            (string) $requete->input('mot_de_passe', ''),
            (string) $requete->input('confirmation', ''),
        );

        if ($cle !== MotDePasse::OK) {
            // On reste sur le formulaire AVEC le jeton : il n'a pas ete consomme,
            // et refuser un mot de passe trop faible ne doit pas obliger a
            // redemander un lien.
            return redirect()
                ->route('reinit.formulaire', ['uid' => $uid, 'jeton' => $jeton])
                ->with('erreur', __($cle, ['minimum' => \App\Services\Comptes::LONGUEUR_MINIMALE]));
        }

        // Le jeton consomme, ET TOUS LES AUTRES du compte.
        $this->jetons->consomme($uid);

        /*
         * AUCUNE SESSION N'EST OUVERTE. Le compte se reconnecte, second facteur
         * compris : reinitialiser un mot de passe ne contourne pas la 2FA.
         */
        return redirect()->route('connexion')->with('succes', __('reinit.mot_de_passe_pose'));
    }
}
