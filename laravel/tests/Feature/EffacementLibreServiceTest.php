<?php

namespace Tests\Feature;

use App\Http\Controllers\PortailController;
use App\Services\StepUp;
use Tests\TestCase;

/**
 * `POST /profil/effacement` — le seul geste IRREVERSIBLE ouvert a tout compte
 * connecte sans garde de role. Ce fichier gele ses protections REELLES, et dit
 * lesquelles manquent.
 *
 * ══ POURQUOI IL N'EXISTAIT AUCUN TEST ICI ════════════════════════════════
 *
 * La route est neuve (`feaaaa2`, DOSSIER-30). Elle est entree dans le portage
 * avec trois protections serieuses et **zero verrou** : rien ne rougissait si
 * l'une d'elles disparaissait. C'est le geste le plus couteux du portail a se
 * tromper, et c'etait le moins tenu.
 *
 * ══ CE QUE PROTEGE LA CONFIRMATION, ET CE QU'ELLE NE PROTEGE PAS ═════════
 *
 * La confirmation exige la RESSAISIE du nom du compte — pas une case a cocher.
 * **Mais ce nom est AFFICHE sur la page de profil elle-meme.** La friction
 * protege donc du geste ACCIDENTEL, pas d'une session COMPROMISE.
 *
 * > Le prochain lecteur verra deux controles et conclura qu'il y en a deux. Il
 * > y en a un contre l'accident et **aucun** contre le vol de session : ils ne
 * > protegent pas de la meme chose, et le dire est la moitie du travail.
 *
 * ══ CE QUI EST DECIDE ET PAS ENCORE FAIT — E-449 ═════════════════════════
 *
 * Le DSI a arbitre pour exiger le step-up ici. Le pendant ADMINISTRATIF le fait
 * deja : `ComptesController:333` garde `compte_anonymiser`. **L'asymetrie est
 * l'inverse de l'intuition** — un administrateur qui anonymise le compte d'un
 * AUTRE se re-authentifie ; le sujet qui anonymise le SIEN, non.
 *
 * ⚠ ET CE N'EST PAS « UN INTERGICIEL A POSER ». Mesure du 2026-09-06 :
 *
 *     intergiciels declares dans `bootstrap/app.php`   7, AUCUN de step-up
 *     consommateurs du step-up                         3, TOUS cote controleur
 *     `StepUp::ACTIONS_PORTAGE`                        liste FERMEE de 3
 *     `/profil/effacement` cote client                 <form method="POST">
 *     `step-up.js`                                     modale sur `fetch` + JSON
 *
 * Le motif de la liste fermee est ecrit sur place : le legacy accepte n'importe
 * quel nom d'action et pose `_step_up_<ce que le client envoie>`, si bien qu'on
 * peut y deposer une marque qui n'ouvre rien aujourd'hui et quelque chose
 * demain. **Une quatrieme entree est donc une decision, pas une ligne.**
 *
 * Et le geste est soumis par un FORMULAIRE (`profil.blade.php:254`) tandis que
 * les trois consommateurs rendent `step_up_required: true` en JSON a une modale
 * qui ecoute un `fetch`. Poser le step-up demande donc **une vue, un module JS,
 * un service et un controleur** — pas un intergiciel.
 */
class EffacementLibreServiceTest extends TestCase
{
    /** La source du controleur, DEPOUILLEE de ses commentaires. */
    private function code(): string
    {
        $chemin = base_path('app/Http/Controllers/PortailController.php');
        $this->assertFileExists($chemin);

        $sortie = '';
        foreach (token_get_all((string) file_get_contents($chemin)) as $jeton) {
            if (is_array($jeton) && in_array($jeton[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }
            $sortie .= is_array($jeton) ? $jeton[1] : $jeton;
        }

        // TEMOIN : le depouillement n'a pas emporte le code. Ce fichier PORTE sa
        // demonstration en commentaire ; y chercher un motif sans depouiller
        // trouverait la prose et non les appels.
        $this->assertStringContainsString('demanderEffacement', $sortie,
            'le retrait des commentaires a emporte le code : mesure invalide');

        return $sortie;
    }

    /** Le corps de `demanderEffacement`, depuis le code depouille. */
    private function corps(): string
    {
        $code = $this->code();
        $debut = strpos($code, 'function demanderEffacement');
        $this->assertNotFalse($debut, '`demanderEffacement` a disparu du controleur');

        // Jusqu'a la declaration suivante : scoper a la FONCTION et non a une
        // fenetre de lignes — 28 sites « proteges » se sont deja reveles 27.
        $suivante = strpos($code, 'function ', $debut + 10);
        $fin = $suivante === false ? strlen($code) : $suivante;

        $corps = substr($code, $debut, $fin - $debut);

        // CONTRE-EPREUVE : le decoupage rend bien un corps, pas une chaine vide.
        // Une universelle negative est vraie a vide, et toutes les assertions
        // d'ABSENCE de ce fichier passeraient alors sans rien mesurer.
        $this->assertGreaterThan(400, strlen($corps),
            'le decoupage de la fonction a rendu un corps trop court : les '
            . 'assertions d\'absence ci-dessous ne mesureraient rien');

        return $corps;
    }

    // ══════════════════════════════════════════════════════════════════════
    // LES TROIS PROTECTIONS REELLES — aucune n'avait de verrou
    // ══════════════════════════════════════════════════════════════════════

    public function test_l_identifiant_vient_de_la_SESSION_et_jamais_de_la_REQUETE(): void
    {
        $corps = $this->corps();

        $this->assertStringContainsString("session()->get('utilisateur_id'", $corps,
            "l'identifiant du compte ne vient plus de la session");

        // La propriete qui compte est l'ABSENCE de l'autre chemin : un `id` lu
        // dans la requete ferait de ce geste une anonymisation D'AUTRUI.
        foreach (["input('id'", 'input("id"', "route('id'", '$idCompte = (int) $requete->input'] as $interdit) {
            $this->assertStringNotContainsString($interdit, $corps,
                "le compte cible peut etre designe par la REQUETE ($interdit) : "
                . "le geste n'est plus du libre-service, c'est une anonymisation "
                . "d'autrui sans garde de role");
        }
    }

    public function test_la_confirmation_est_une_RESSAISIE_du_nom_et_pas_une_case(): void
    {
        $corps = $this->corps();

        $this->assertStringContainsString("input('confirmation')", $corps,
            'la confirmation a disparu');
        $this->assertStringContainsString("\$compte['name']", $corps,
            'la confirmation ne se compare plus au NOM du compte : une case a '
            . "cocher ou un booleen mettrait ce geste a un clic d'un geste ordinaire");

        // La comparaison doit etre STRICTE et NEGATIVE (on sort si ca ne
        // correspond pas). Un `==` accepterait des valeurs coercees.
        $this->assertStringContainsString('!==', $corps,
            'la comparaison de confirmation n\'est plus stricte');
    }

    public function test_le_DERNIER_superadministrateur_ne_peut_pas_se_retirer(): void
    {
        $corps = $this->corps();

        $this->assertStringContainsString('superadminsActifs()', $corps,
            'la protection du dernier superadministrateur a disparu : le portail '
            . 'peut devenir inadministrable par un geste de libre-service');
        $this->assertStringContainsString('<= 1', $corps,
            'le seuil du dernier superadministrateur a change de forme — a relire');
    }

    public function test_le_JOURNAL_precede_l_anonymisation(): void
    {
        $corps = $this->corps();

        $posteJournal = strpos($corps, '$this->journal->ajoute');
        $posteAnonyme = strpos($corps, '$this->comptes->anonymise');

        $this->assertNotFalse($posteJournal, 'la demande n\'est plus journalisee');
        $this->assertNotFalse($posteAnonyme, "l'anonymisation a disparu");

        $this->assertLessThan($posteAnonyme, $posteJournal,
            "l'ordre est inverse : apres l'anonymisation la session est morte et "
            . 'le compte inactif. Une ecriture qui echouerait laisserait un '
            . 'effacement SANS TRACE — le pire des deux mondes.');
    }

    public function test_le_geste_est_une_ANONYMISATION_et_pas_une_SUPPRESSION(): void
    {
        $corps = $this->corps();

        $this->assertStringContainsString('anonymise(', $corps);
        $this->assertStringNotContainsString('supprime(', $corps,
            '`user_logs` est une chaine de hachage : retirer une ligne romprait '
            . 'la verification de TOUTES les suivantes');
    }

    public function test_la_session_est_INVALIDEE_apres_le_geste(): void
    {
        $corps = $this->corps();

        $this->assertStringContainsString('flush()', $corps);
        $this->assertStringContainsString('invalidate()', $corps,
            'la session survit a l\'anonymisation de son propre compte');
    }

    // ══════════════════════════════════════════════════════════════════════
    // LE CONSTAT — la portee du controle, et ce qui manque
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_pendant_ADMINISTRATIF_exige_deja_le_step_up(): void
    {
        /*
         * Ce test ne juge pas `/profil/effacement` : il etablit l'ASYMETRIE, qui
         * est le fait a transmettre. Il rougit si le step-up administratif saute
         * — auquel cas ce n'est plus une asymetrie mais une absence generale.
         */
        $code = (string) file_get_contents(base_path('app/Http/Controllers/ComptesController.php'));

        $this->assertStringContainsString("exigeStepUp(\$auteur, 'compte_anonymiser')", $code,
            "l'anonymisation ADMINISTRATIVE n'exige plus de re-authentification");

        $this->assertContains('compte_anonymiser', StepUp::ACTIONS_PORTAGE,
            "`compte_anonymiser` a quitte la liste fermee des actions du portage");
    }

    public function test_le_step_up_du_LIBRE_SERVICE_reste_A_POSER(): void
    {
        /*
         * ⚠ CE TEST EST UN CONSTAT DATE, PAS UN FEU VERT.
         *
         * Il gele l'etat du 2026-09-06 : le libre-service n'exige AUCUNE
         * re-authentification. Le DSI a arbitre pour l'exiger (E-449) ; le geste
         * n'est pas fait, et il n'est pas d'une ligne.
         *
         * **Quand il sera pose, ce test rougira — et c'est voulu.** Il faudra
         * alors le RETOURNER (asserter la presence), inscrire la garde dans
         * `TableDesGardes`, et retirer `profil/effacement` de la liste gelee des
         * routes authentifiees-sans-controle-supplementaire. Un marqueur qui date
         * un manque doit rougir le jour ou le manque est comble, sinon personne
         * ne sait qu'il est perime.
         */
        $corps = $this->corps();

        $this->assertStringNotContainsString('stepUp', $corps,
            "LE STEP-UP EST POSE SUR `/profil/effacement` — c'est ce qu'E-449 "
            . 'demandait. Retourner ce marqueur : asserter desormais sa PRESENCE, '
            . 'inscrire la garde dans `TableDesGardes`, et relire la portee ecrite '
            . 'a cote (la ressaisie couvre l\'accident, le step-up couvre le vol '
            . 'de session — deux controles, deux objets).');

        $this->assertNotContains('profil_effacement', StepUp::ACTIONS_PORTAGE,
            'une action `profil_effacement` existe : voir ci-dessus, le marqueur '
            . 'est a retourner.');
    }

    public function test_le_step_up_n_est_pose_par_AUCUN_intergiciel(): void
    {
        /*
         * La prémisse « c'est un intergiciel a POSER » est fausse, et ce test la
         * gele pour qu'elle ne se reforme pas. Les TROIS consommateurs du step-up
         * l'appellent depuis un CONTROLEUR ; aucun intergiciel ne le porte.
         *
         * Consequence pratique : poser le step-up ici demande une vue (le geste
         * est un `<form>`, pas un `fetch`), un module JS (la modale ecoute un
         * `fetch` et lit `step_up_required`), une entree dans une liste FERMEE, et
         * un controleur. C'est une decision, pas une ligne.
         */
        $app = (string) file_get_contents(base_path('bootstrap/app.php'));

        $this->assertStringNotContainsString('StepUp::class', $app,
            'un intergiciel de step-up est desormais declare : la forme du portage '
            . 'a change, relire ce fichier en entier');

        $this->assertStringContainsString('<form method="POST"', (string) file_get_contents(
            base_path('resources/views/profil.blade.php')),
            'la page de profil ne soumet plus par formulaire : si elle est passee '
            . 'au `fetch`, le chemin du step-up est desormais ouvert et ce constat '
            . 'est perime');
    }
}
