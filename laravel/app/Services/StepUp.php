<?php

namespace App\Services;

use App\Support\RoutesBackend;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;

/**
 * La re-authentification ponctuelle — le « step-up ».
 *
 * Une session valide ne doit pas suffire a declencher un geste qui donne root.
 * Le legacy l'exige sur quatre chemins (`legacy/auth/step_up.php`) ; ce service
 * porte la meme exigence, sans reprendre ses quatre defauts.
 *
 * ══ CE QUI CHANGE PAR RAPPORT AU LEGACY ═════════════════════════════════════
 *
 * **1. L'anti-rejeu est par COMPTE, et il est PARTAGE avec la connexion.** Le
 * legacy pose sa garde dans `$_SESSION['_step_up_last_totp']` : une session
 * NEUVE ne la voit pas, et le rejeu passe — mesure le 2026-08-24, le meme code a
 * ete accepte deux fois. Ici la garde est celle de `Totp::verifie`, un compteur
 * de fenetre MONOTONE par compte. Un code ne sert donc qu'UNE FOIS, pour quoi
 * que ce soit : un code observe a la connexion ne peut pas etre retourne en
 * step-up. C'est precisement l'escalade que le step-up existe pour empecher, et
 * le legacy la laisse ouverte.
 *
 * Consequence assumee : deux step-up dans la MEME fenetre de 30 s sont
 * impossibles, il faut attendre le code suivant. Le legacy refuse deja ce cas
 * (sa cle est unique pour toutes les actions) — mais pour la mauvaise raison, et
 * de façon contournable. Voir `PARITE.md`.
 *
 * **2. Le quota est par COMPTE, et remis a zero sur succes.** Le legacy empile
 * la tentative AVANT toute verification et ne vide jamais le tableau : cinq
 * step-up REUSSIS en une minute rendent 429. Mesure : apres un succes, la
 * cinquieme tentative suivante est deja refusee.
 *
 * **3. Un nom d'action PAR ROUTE.** `api_proxy.php:63` fusionne trois routes
 * root sous `policy_action`, si bien qu'un step-up consenti pour ANNULER une
 * politique autorise un DEPLOIEMENT sudo pendant quinze minutes. Ici le nom est
 * derive du chemin : `/policy/sudo/deploy` -> `policy_sudo_deploy`.
 *
 * **4. La duree de validite est LUE.** `config('rootwarden.step_up_ttl')`
 * existait deja et n'etait lu par personne.
 *
 * ══ OU VIT LA MARQUE ════════════════════════════════════════════════════════
 *
 * Dans le cache applicatif (pilote fichier), comme la garde anti-rejeu de
 * `Totp`. Le schema appartient au backend Python et ne recoit pas de migration
 * depuis ici. Contrepartie assumee, la meme que pour `Totp` : la marque ne
 * survit pas a une purge du cache — ce qui **referme** une autorisation au lieu
 * de l'ouvrir, donc le defaut est du bon cote.
 */
class StepUp
{
    public const OK = 'ok';

    /**
     * Les gestes DU PORTAGE qui exigent une re-authentification.
     *
     * `RoutesBackend::MOTIFS_STEP_UP` ne couvre que les chemins transmis au
     * backend Python — c'est son objet, et l'y elargir brouillerait son sens.
     * Le portage a desormais ses propres gestes destructeurs, qui ne passent par
     * aucune passerelle : le sous-lot D4 est le premier a en porter.
     *
     * La liste reste FERMEE, pour la meme raison qu'elle l'est cote backend :
     * le legacy accepte n'importe quel nom d'action, le nettoie au caractere
     * puis pose `_step_up_<ce que le client a envoye>` — on peut donc y poser
     * une marque qui n'ouvre rien aujourd'hui, et quelque chose demain.
     */
    public const ACTIONS_PORTAGE = [
        // Supprime un compte, et avec lui tout ce que les cles etrangeres
        // emportent en cascade — son journal d'audit compris (PARITE E-116).
        'compte_supprimer',
        // Efface les donnees personnelles d'un compte en PRESERVANT son journal.
        'compte_anonymiser',
        // Accorde ou retire un droit fonctionnel. Le legacy garde deja ce geste
        // par un step-up ; ce que le portage ajoute, c'est un chemin pour y
        // repondre (PARITE E-119).
        'permission_definir',
    ];

    /**
     * L'action que ce chemin exige, ou `null` s'il n'exige rien.
     *
     * Le nom est DERIVE du chemin, et non pris dans une table : une route
     * ajoutee aux motifs obtient donc automatiquement son propre nom, sans
     * qu'on puisse oublier de l'y declarer — c'est l'oubli qui a produit le
     * quatrieme defaut du legacy.
     */
    public function actionPour(string $chemin): ?string
    {
        return RoutesBackend::actionStepUp($chemin);
    }

    /**
     * L'action est-elle l'une de celles qu'on garde ? Soit un chemin REELLEMENT
     * garde cote backend, soit un geste destructeur du portage. Dans les deux
     * cas la liste est fermee : une marque ne se pose jamais sur un nom libre.
     */
    private function actionConnue(string $action): bool
    {
        return RoutesBackend::cheminStepUp($action) !== null
            || in_array($action, self::ACTIONS_PORTAGE, true);
    }

    /** Une marque fraiche existe-t-elle pour ce compte et cette action ? */
    public function valide(int $idCompte, string $action): bool
    {
        if (! $this->actionConnue($action)) {
            return false;
        }

        return Cache::get($this->cleMarque($idCompte, $action)) !== null;
    }

    /**
     * Verifie un code et, s'il est bon, pose la marque.
     *
     * @return string  self::OK, ou la cle i18n du refus
     */
    public function verifie(int $idCompte, string $action, string $code): string
    {
        /*
         * L'ACTION EST VALIDEE CONTRE UNE LISTE FERMEE, ET D'ABORD.
         *
         * Le legacy accepte n'importe quel nom d'action : il le nettoie au
         * caractere puis pose `_step_up_<ce que le client a envoye>`. Ici le nom
         * doit correspondre a un chemin REELLEMENT garde, faute de quoi on
         * poserait une marque qui n'ouvre rien — ou qui ouvrira quelque chose
         * plus tard, quand un motif changera.
         */
        if (! $this->actionConnue($action)) {
            return 'step_up.action_inconnue';
        }

        $code = trim($code);
        /*
         * LA FORME AVANT LE QUOTA. Une requete mal formee ne peut pas deviner un
         * code : la faire consommer un jeton n'ajoute rien et permettrait a un
         * tiers de bruler le quota d'un compte sans jamais tenter un code.
         */
        if (! preg_match('/^\d{6}$/', $code)) {
            return 'step_up.code_invalide';
        }

        $cleQuota = 'step_up:quota:' . $idCompte;
        $maximum  = (int) config('rootwarden.step_up_tentatives', 5);
        if (RateLimiter::tooManyAttempts($cleQuota, $maximum)) {
            return 'step_up.trop_de_tentatives';
        }
        RateLimiter::hit($cleQuota, 60);

        $secret = DB::table('users')->where('id', $idCompte)->value('totp_secret');
        if (empty($secret)) {
            return 'step_up.sans_second_facteur';
        }

        $verdict = $this->totp->verifie($idCompte, $secret, $code);
        if ($verdict === 'rejeu') {
            return 'step_up.code_deja_utilise';
        }
        if ($verdict !== 'ok') {
            return 'step_up.code_invalide';
        }

        /*
         * LE QUOTA EST REMIS A ZERO. Sans cela, cinq gestes sensibles legitimes
         * dans la meme minute finissent en 429 — c'est le troisieme defaut du
         * legacy, et il frappe l'exploitant, pas l'attaquant.
         */
        RateLimiter::clear($cleQuota);
        $duree = (int) config('rootwarden.step_up_ttl', 900);
        Cache::put($this->cleMarque($idCompte, $action), time(), $duree);

        /*
         * L'INDEX DES ACTIONS MARQUEES. Le pilote fichier du cache ne sait pas
         * effacer par motif : sans cet index, `revoque()` n'aurait aucun moyen
         * de retrouver ce qu'il doit effacer.
         */
        $index = Cache::get($this->cleIndex($idCompte), []);
        if (! in_array($action, $index, true)) {
            $index[] = $action;
        }
        Cache::put($this->cleIndex($idCompte), $index, $duree);

        return self::OK;
    }

    /**
     * Rend ses privileges : efface toutes les marques du compte.
     *
     * Strictement DE-escaladant, donc sans garde de role — on n'a jamais besoin
     * d'une permission pour renoncer a une autorisation. Le legacy n'offre rien
     * de tel : sa marque vit quinze minutes et rien ne permet de l'abreger, pas
     * meme la fermeture du panneau.
     *
     * @return int  nombre de marques effacees
     */
    public function revoque(int $idCompte): int
    {
        $efacees = 0;
        foreach (Cache::get($this->cleIndex($idCompte), []) as $action) {
            if (Cache::forget($this->cleMarque($idCompte, (string) $action))) {
                $efacees++;
            }
        }
        Cache::forget($this->cleIndex($idCompte));

        return $efacees;
    }

    public function __construct(private readonly Totp $totp)
    {
    }

    /** La marque est nommee par le COMPTE et par l'ACTION, jamais par la session. */
    private function cleMarque(int $idCompte, string $action): string
    {
        return 'step_up:marque:' . $idCompte . ':' . $action;
    }

    private function cleIndex(int $idCompte): string
    {
        return 'step_up:actions:' . $idCompte;
    }
}
