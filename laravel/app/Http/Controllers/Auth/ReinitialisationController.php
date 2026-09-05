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
 * **Le mecanisme employe est `terminating()`**, et ⚠ **IL NE GARANTIT PAS ICI CE
 * QU'IL GARANTIT AILLEURS** — corrige apres relecture, la formulation qui vivait
 * ici etait trop forte.
 *
 * `Response::send()` (symfony/http-foundation) choisit dans cet ordre :
 *
 *     fastcgi_finish_request()      -> termine la requete   (php-fpm)
 *     litespeed_finish_request()    -> idem                 (litespeed)
 *     closeOutputBuffers(); flush() -> VIDE LES TAMPONS SEULEMENT
 *
 * **Ce conteneur tourne sous `mod_php`** — mesure : Apache charge
 * `/usr/lib/apache2/modules/libphp.so`, aucun binaire `php-fpm`, aucune socket
 * `/run/php/*.sock`. Seule la troisieme branche s'execute : *le corps est ecrit
 * et vide, mais la CONNEXION reste ouverte jusqu'a la fin du script — donc
 * apres les rappels `terminating()`.*
 *
 * > **`terminating()` deplace le travail apres l'ECRITURE de la reponse, pas
 * > apres sa FIN. Sous php-fpm ce sont la meme chose ; sous mod_php, non.**
 *
 * ══ CE QUE CELA CHANGE, ET CE QUE CELA NE CHANGE PAS ══════════════════════
 *
 * Un demandeur qui chronometre **le dernier octet du corps** ne voit pas
 * l'envoi. Un demandeur qui chronometre **la fermeture de connexion** le voit.
 * *La propriete n'est donc pas acquise par construction : elle depend d'un
 * comportement de tampon que personne n'a mesure.*
 *
 * ⚠ ET AUJOURD'HUI LE DEFAUT EST LATENT, PAS VIVANT. `mail.default` vaut `log` :
 * l'envoi est une ecriture de fichier, du meme ordre que l'`INSERT` qu'il
 * accompagne. **Il devient vivant le jour ou un transport RESEAU est configure**
 * — et ce jour-la, personne ne pensera a relire ce fichier.
 *
 * **C'est pourquoi la condition est VERIFIEE A L'EXECUTION et journalisee**
 * plutot que laissee a ce commentaire : voir `envoyer()`. *Un commentaire ne
 * produit aucun evenement le jour ou sa premisse cesse d'etre vraie.*
 *
 * ⚠ ET CE QUI SUBSISTE EN TOUT ETAT DE CAUSE : un `UPDATE` et un `INSERT` ne se
 * produisent que dans la branche connue. Ils se comptent en fractions de
 * milliseconde la ou le bcrypt — egalise, lui — se compte en centaines : **2,4 ms
 * d'ecart mesure, 1 % du cout de base.** *Le residu n'est pas nul ; il est
 * borne, et il est enonce.*
 */
class ReinitialisationController extends Controller
{
    /**
     * Les transports dont l'envoi ne sort pas de la machine. Avec eux, le cout
     * de l'envoi est du meme ordre que celui de l'`INSERT` qui le precede, et
     * l'ecart de temps reste dans le residu mesure.
     *
     * ⚠ LISTE FERMEE, ET C'EST VOULU : un transport inconnu est traite comme
     * DISTANT. *Se tromper du cote qui journalise coute un message ; se tromper
     * de l'autre rouvre un oracle en silence.*
     */
    public const TRANSPORTS_LOCAUX = ['log', 'array', 'null', 'failover-log'];

    public function __construct(
        private readonly ReinitialisationMotDePasse $jetons,
        private readonly MotDePasse $motDePasse,
    ) {
    }

    /**
     * La valeur de `MAIL_MAILER` telle qu'elle est ECRITE dans `.env`, ou `null`.
     *
     * ⚠ ON NE PASSE PAS PAR `env()` : elle rend la valeur EFFECTIVE, celle qui a
     * gagne. Le but est precisement de comparer le FICHIER a ce qui opere, donc
     * il faut lire le fichier — et rien d'autre.
     *
     * Toute erreur de lecture rend `null` : l'avertissement principal ne doit
     * jamais dependre de ce complement.
     */
    private function mailerDuFichierEnv(): ?string
    {
        try {
            $chemin = base_path('.env');
            if (! is_readable($chemin)) {
                return null;
            }
            foreach (file($chemin, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $ligne) {
                if (preg_match('/^\s*MAIL_MAILER\s*=\s*"?([A-Za-z0-9_-]*)"?\s*$/', $ligne, $m) === 1) {
                    return $m[1];
                }
            }
        } catch (\Throwable $e) {
            return null;
        }

        return null;
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
            /*
             * ⚠ LA PREMISSE DE `terminating()` EST VERIFIEE, PAS SUPPOSEE.
             *
             * Elle ne tient que si le transport est LOCAL — sinon l'envoi est un
             * aller-retour reseau execute avant la fermeture de connexion, et
             * l'oracle de temps rouvre. Le jour ou l'exploitant posera le SMTP,
             * ce fichier ne sera pas relu : **le controle doit donc produire un
             * evenement, pas dormir dans un commentaire.**
             */
            $transport = (string) config('mail.default');
            if (! in_array($transport, self::TRANSPORTS_LOCAUX, true)) {
                /*
                 * ⚠ L'AVERTISSEMENT DIT AUSSI QUE `.env` MENT, PARCE QUE C'EST LA
                 * PREMIERE CHOSE QU'ON IRA LIRE.
                 *
                 * Mesure du 2026-09-06 :
                 *
                 *     environnement du processus   MAIL_MAILER=smtp   <- gagne
                 *     .env (fichier)               MAIL_MAILER=log    <- perdu
                 *     config('mail.default')       smtp
                 *
                 * `Dotenv::safeLoad()` ne REMPLACE pas une variable deja presente
                 * dans l'environnement. **Qui ouvre `.env` pour verifier y lit la
                 * valeur sure et conclut qu'il n'y a rien a faire** — et le seul
                 * levier reel est `srv-docker.env` PUIS la recreation du
                 * conteneur.
                 *
                 * *C'est la meme forme que tout ce que cette journee a corrige :
                 * une declaration qui decrit un etat qui n'est plus l'etat
                 * operant. Sauf qu'ici elle ne vit pas dans un commentaire mais
                 * dans un fichier de configuration, donc elle a l'air de faire
                 * autorite.* **Le dire DANS l'avertissement est ce qui evite le
                 * mauvais diagnostic au moment ou on le pose.**
                 */
                $dansFichier = $this->mailerDuFichierEnv();
                $desaccord = ($dansFichier !== null && $dansFichier !== $transport)
                    ? ' ⚠ `.env` porte MAIL_MAILER=' . $dansFichier . ', et il PERD contre '
                      . 'l environnement du processus : le modifier ne changerait rien. '
                      . 'Le levier est `srv-docker.env` PUIS la recreation du conteneur.'
                    : '';

                Log::warning(
                    '[reinitialisation] transport « ' . $transport . ' » non local sous '
                    . 'mod_php : l envoi se produit AVANT la fermeture de connexion, '
                    . 'et l ecart de temps entre adresse connue et inconnue redevient '
                    . 'mesurable. Il faut php-fpm (fastcgi_finish_request) ou un '
                    . 'ouvrier de file.' . $desaccord
                );
            }

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
