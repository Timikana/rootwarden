<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Un compte marque « doit changer son mot de passe » ne va nulle part d'autre.
 *
 * ══ CE QUE LE LEGACY FAIT, ET QUE LE PORTAGE NE FAISAIT PAS ══════════════
 *
 * `legacy/auth/verify.php:169-183` relit la BASE a chaque requete et REDIRIGE
 * si `force_password_change = 1`. Le portage, lui, ne lisait ce drapeau nulle
 * part : `SessionAuthentifiee` ne teste que la presence d'`utilisateur_id`, et
 * l'exigence n'y etait **qu'un bandeau, pas un verrou**.
 *
 * C'est une correction de PARITE, pas une politique nouvelle : le legacy exerce
 * ce controle aujourd'hui, donc le porteur du drapeau y est deja arrete. Le
 * portage etait le chemin PLUS PERMISSIF des deux. *Le cout n'est donc pas une
 * friction nouvelle, c'est le retrait d'un contournement.*
 *
 * ══ POURQUOI CE DRAPEAU EST LE SEUL FREIN POUR CERTAINS COMPTES ══════════
 *
 * Mesure du 2026-09-01 : **huit comptes actifs le portent**, et **trois sont
 * au-dessus du role 1** — `id 1` et `id 78` en role 3, `id 77` en role 2.
 *
 * Pour un role 3, il n'y a pas « des chemins a garder » : le role 3
 * court-circuite chaque `perm:` et chaque `role:`. **Ce drapeau est le seul
 * frein entre son detenteur et l'administration complete du portage.**
 *
 * ══ LA LECTURE EST EN BASE, JAMAIS EN SESSION ════════════════════════════
 *
 * Comme le legacy, et pour la meme raison que `Droits::permissions` : une
 * valeur de session est posee a la connexion et ne bouge plus. Un
 * administrateur qui leve le drapeau doit le voir prendre effet a la requete
 * suivante, pas a la reconnexion suivante — et l'inverse compte davantage :
 * POSER le drapeau doit arreter une session DEJA ouverte.
 *
 * `ouvreLaSession()` pose `role_id` AVANT toute redirection : une session
 * privilegiee existe donc deja au moment ou ce garde s'applique.
 *
 * ══ ⚠ L'EXEMPTION, ET POURQUOI ELLE TIENT EN DEUX ENTREES ════════════════
 *
 * *Un garde-fou qui se declenche a tort ne protege plus : il empeche.* Rediriger
 * TOUT enfermerait le compte hors de l'ecran qui le libere.
 *
 * Le legacy exempte cinq pages, dont sa propre cible — sinon boucle infinie. Le
 * portage n'en a besoin que de DEUX, et c'est un effet de la STRUCTURE et non
 * d'une liste plus courte :
 *
 *   `profil`               l'ecran qui PORTE le formulaire (GET)
 *   `profil.mot-de-passe`  le geste qui le soumet (POST)
 *
 * **La deconnexion n'a pas besoin d'exemption** : elle vit HORS du groupe
 * `session.authentifiee` (middleware `[web]` seul, mesure). Elle tombe donc
 * hors de portee de ce garde **par construction**.
 *
 * ⚠ ET C'EST CE QUI EVITE UN PIEGE : `GET /deconnexion` **n'a aucun nom de
 * route** (`web.php:71`). Une exemption par NOM qui aurait inclus
 * `'deconnexion'` aurait couvert le POST et **manque le GET** — un compte
 * marque, cliquant un lien de deconnexion, aurait ete renvoye vers son profil
 * au lieu de sortir. *Une liste d'exemptions qui depend d'un nom depend de ce
 * que quelqu'un a pense a nommer.*
 *
 * Le selecteur de langue ne demande rien non plus : il conserve la page courante
 * et n'ajoute que `?lang=`, donc il reste sur l'ecran exempte.
 *
 * ══ CE QUI N'EST PAS PORTE ICI, ET NE DOIT PAS PASSER POUR FERME ═════════
 *
 * **Le legacy verifie DEUX choses, pas une.** Apres le drapeau, il calcule
 * l'EXPIRATION du mot de passe (`password_updated_at`,
 * `password_expiry_override`) et redirige vers `profile.php?password_expired=1`.
 *
 * **Ce second garde n'est pas porte**, parce qu'il depend de la politique de mot
 * de passe, que le portage declare non portee. Mesure du jour : aucun compte n'a
 * de `password_updated_at` nul ni d'`override`, donc la politique par defaut
 * s'appliquerait — mais elle n'existe pas encore ici.
 *
 * *Porter le drapeau seul ferme la moitie de l'ecart. Le dire evite que
 * « parite restauree » soit inscrit pour les deux.*
 */
class ChangementMotDePasseExige
{
    /**
     * Les routes que ce garde ne doit JAMAIS intercepter.
     *
     * LISTE FERMEE, par NOM de route et non par chemin : un chemin change au
     * premier renommage d'URL, un nom est reference partout ailleurs et bouge
     * donc avec ses appelants.
     *
     * Elle ne contient QUE l'ecran qui libere et le geste qui le soumet. Toute
     * entree supplementaire serait un trou : c'est le seul endroit du portage ou
     * allonger une liste d'exemptions AFFAIBLIT la garde.
     */
    private const EXEMPTES = ['profil', 'profil.mot-de-passe'];

    public function handle(Request $requete, Closure $suite): Response
    {
        $nom = $requete->route()?->getName();
        if ($nom !== null && in_array($nom, self::EXEMPTES, true)) {
            return $suite($requete);
        }

        $id = (int) $requete->session()->get('utilisateur_id', 0);
        if ($id <= 0) {
            // Sans session, `SessionAuthentifiee` a deja tranche. On ne double
            // pas sa decision : deux gardes qui repondent a la meme question
            // finissent par ne plus s'accorder.
            return $suite($requete);
        }

        try {
            $exige = DB::table('users')
                ->where('id', $id)
                ->where('active', 1)
                ->value('force_password_change');
        } catch (\Throwable $e) {
            /*
             * ⚠ FAIL-OPEN, ET C'EST DELIBERE — a l'inverse de la regle habituelle.
             *
             * Une base injoignable empecherait TOUS les comptes d'utiliser le
             * portage, y compris ceux qui ne portent pas le drapeau. Or ce garde
             * ne protege pas une donnee : il impose une hygiene. Le refus par
             * defaut transformerait une panne de lecture en indisponibilite
             * totale, pour un gain nul — le porteur du drapeau ne peut de toute
             * facon rien lire non plus si la base est morte.
             *
             * La panne est JOURNALISEE : un fail-open muet serait une garde qui
             * disparait sans trace.
             */
            Log::error('[ChangementMotDePasseExige] drapeau illisible pour ' . $id . ' : ' . $e->getMessage());

            return $suite($requete);
        }

        if ((int) $exige === 1) {
            // Le legacy redirige vers `profile.php?force_change=1`. Le parametre
            // est conserve : c'est lui qui fait afficher a la page la raison de
            // l'arrivee, plutot qu'un formulaire sans explication.
            return redirect()->route('profil', ['force_change' => 1]);
        }

        return $suite($requete);
    }
}
