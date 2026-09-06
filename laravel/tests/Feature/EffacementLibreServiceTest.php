<?php

namespace Tests\Feature;

use App\Http\Controllers\PortailController;
use App\Services\Comptes;
use App\Services\JournalAudit;
use App\Services\StepUp;
use Illuminate\Support\Facades\Cache;
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
 * ══ CE QUI ETAIT DECIDE ET QUI EST FAIT — E-449, `f94c947` ══════════════
 *
 * Le DSI a arbitre pour exiger le step-up ici. Le pendant ADMINISTRATIF le fait
 * deja : `ComptesController:333` garde `compte_anonymiser`. **L'asymetrie est
 * l'inverse de l'intuition** — un administrateur qui anonymise le compte d'un
 * AUTRE se re-authentifie ; le sujet qui anonymise le SIEN, non.
 *
 * ⚠ CE N'ETAIT PAS « UN INTERGICIEL A POSER », et le correctif l'a confirme :
 * la garde vit dans le CONTROLEUR, comme ses trois soeurs. Mesure du 2026-09-06,
 * conservee parce qu'elle explique la FORME retenue :
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
 *
 * ══ CE QUE LE CORRECTIF A FAIT DE MIEUX QUE LA CONSIGNE ══════════════════
 *
 * Le second facteur est dans le MEME formulaire, pas dans une modale : cela
 * DISSOUT le probleme forme-contre-`fetch` au lieu de le contourner, et evite
 * un quatrieme mecanisme. Le motif est ecrit dans la vue — *un second ecran
 * ajouterait un etat a perdre entre deux soumissions*, pour un geste qui doit
 * en avoir le moins possible.
 *
 * Et la portee des deux controles est passee du CODE a l'ECRAN (`eff_code_aide`).
 * Je demandais que la phrase survive dans le fichier ; elle atteint desormais
 * l'utilisateur, chez qui la confusion etait tout aussi probable.
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

    // ══════════════════════════════════════════════════════════════════════
    // C1 / C2 — LA GARDE MORD, ET ELLE NE COUTE AUCUN ACCES
    //
    // Criteres SCELLES avant lecture du correctif : `4ff0853`, empreinte
    // `ab53508d05650012`. Le correctif atteste est `f94c947`.
    // ══════════════════════════════════════════════════════════════════════

    private const NOM_DU_COMPTE = 'compte-epreuve';

    /**
     * Le harnais, et **pourquoi il double le depot plutot que la base**.
     *
     * La propriete a mesurer est « le compte a-t-il ete anonymise », pas « quel
     * message a ete rendu ». Un refus qui affiche une erreur ET anonymise quand
     * meme serait VERT sur la reponse. On observe donc l'APPEL a `anonymise()`,
     * qui est l'effet lui-meme.
     *
     * `StepUp` reste le VRAI service : c'est lui qu'on mesure.
     *
     * @return object le registre des appels, `->anonymises` etant la liste des
     *                identifiants reellement anonymises
     */
    private function harnais(): object
    {
        $registre = new \stdClass();
        $registre->anonymises = [];

        $comptes = $this->createStub(Comptes::class);
        $comptes->method('trouve')->willReturn([
            'id' => self::COMPTE, 'name' => self::NOM_DU_COMPTE, 'role_id' => 1, 'active' => 1,
        ]);
        // Deux superadministrateurs : la garde du DERNIER ne doit pas se
        // declencher, sinon elle refuserait avant meme le step-up et C1
        // passerait pour la mauvaise raison.
        $comptes->method('superadminsActifs')->willReturn(2);
        $comptes->method('anonymise')->willReturnCallback(
            static function (int $id) use ($registre): void { $registre->anonymises[] = $id; }
        );

        $this->instance(Comptes::class, $comptes);
        $this->instance(JournalAudit::class, $this->createStub(JournalAudit::class));

        return $registre;
    }

    public function test_C1_SANS_marque_fraiche_le_compte_reste_INTACT(): void
    {
        /*
         * La confirmation est CORRECTE : on ne mesure donc pas la garde du nom,
         * qui existait deja. Ce qui manque est la seule chose neuve.
         */
        $registre = $this->harnais();

        $reponse = $this->connecte(1)->post('/profil/effacement', [
            'confirmation' => self::NOM_DU_COMPTE,
        ]);

        $this->assertSame([], $registre->anonymises,
            'LE COMPTE A ETE ANONYMISE SANS RE-AUTHENTIFICATION : la garde du '
            . 'step-up ne mord pas. Une session volee suffit a exercer le geste '
            . 'irreversible.');

        // Et le geste n'a pas ABOUTI non plus : la redirection de succes mene a
        // la connexion (session detruite), celle d'echec au profil.
        $this->assertStringContainsString('/profil', (string) $reponse->headers->get('Location'),
            'la reponse a la forme d\'une reussite alors que rien n\'a ete efface');
    }

    public function test_C2_AVEC_une_marque_valide_le_geste_ABOUTIT(): void
    {
        /*
         * ⚠ CE TEST EST LE TEMOIN DE C1, ET C'EST SA RAISON D'ETRE PREMIERE.
         *
         * « `anonymise()` n'a pas ete appele » et « ce harnais ne sait pas voir
         * un appel » sont la MEME sortie. C2 montre que le meme harnais observe
         * l'anonymisation quand elle a lieu : le zero de C1 cesse d'etre vacant.
         *
         * Et il porte sa propre propriete : **une garde qui refuse tout le monde
         * satisfait C1 parfaitement.** C1 sans C2 est un deni de service qui a
         * l'air d'une securite — c'est ce qui serait arrive si la vue avait pose
         * `code_2fa` et le controleur lu un autre nom.
         */
        $registre = $this->harnais();

        Cache::put('step_up:marque:' . self::COMPTE . ':profil_effacement', true, 900);

        $reponse = $this->connecte(1)->post('/profil/effacement', [
            'confirmation' => self::NOM_DU_COMPTE,
        ]);

        $this->assertSame([self::COMPTE], $registre->anonymises,
            'une marque de step-up VALIDE ne suffit pas a exercer le geste : la '
            . 'garde refuse un compte qui vient de se re-authentifier. Verifier '
            . 'le couplage du champ (`name="code_2fa"` cote vue contre '
            . '`input(...)` cote controleur) et le nom de l\'action.');

        $this->assertStringContainsString('/connexion', (string) $reponse->headers->get('Location'),
            'le geste a abouti mais la session n\'est pas rendue a la connexion');
    }

    public function test_C4_l_action_est_NEUVE_et_ne_reutilise_aucune_autre(): void
    {
        /*
         * ⚠ LE POINT LE PLUS COUTEUX A RATER. Reutiliser `compte_anonymiser`
         * aurait fait qu'une marque consentie pour l'anonymisation
         * ADMINISTRATIVE ouvre l'effacement de son propre compte — le defaut
         * `policy_action` du legacy, ou un step-up consenti pour ANNULER une
         * politique autorisait un DEPLOIEMENT pendant quinze minutes.
         */
        $this->assertContains('profil_effacement', StepUp::ACTIONS_PORTAGE,
            "l'action du libre-service a quitte la liste FERMEE");

        $corps = $this->corps();
        $this->assertStringContainsString("'profil_effacement'", $corps,
            "le controleur n'exige plus l'action qui lui est propre");
        $this->assertStringNotContainsString("'compte_anonymiser'", $corps,
            'le libre-service REUTILISE le nom d\'action de l\'anonymisation '
            . 'administrative : une marque obtenue pour l\'une ouvre l\'autre');
    }

    // ══════════════════════════════════════════════════════════════════════
    // C5 — LES DEUX MARQUEURS DATES, RETOURNES LE 2026-09-06 (E-449, f94c947)
    //
    // Ils asseraient l'ABSENCE et portaient dans leur message ce qu'il faudrait
    // faire le jour ou ils rougiraient. Ce jour est venu : ils asserent
    // desormais la PRESENCE. **Retournes, pas supprimes** — un marqueur qu'on
    // efface emporte la trace du manque avec le manque.
    // ══════════════════════════════════════════════════════════════════════

    public function test_C5_le_step_up_du_libre_service_est_POSE(): void
    {
        $corps = $this->corps();

        $this->assertStringContainsString('stepUp', $corps,
            'LE STEP-UP A DISPARU de `/profil/effacement`. Il y a ete pose le '
            . '2026-09-06 (E-449) : son retrait est une regression, pas un choix '
            . 'a redocumenter.');

        // L'ORDRE : la garde doit preceder l'ecriture, pas seulement exister.
        $posteGarde   = strpos($corps, 'stepUp');
        $posteAnonyme = strpos($corps, '$this->comptes->anonymise');
        $this->assertLessThan($posteAnonyme, $posteGarde,
            "la re-authentification est exigee APRES l'anonymisation : elle ne "
            . 'garde plus rien');
    }

    public function test_C5_la_garde_est_cote_CONTROLEUR_comme_ses_trois_soeurs(): void
    {
        /*
         * Le second marqueur, retourne dans le meme sens : il assertait qu'aucun
         * intergiciel ne portait le step-up, et cela reste VRAI apres le
         * correctif — c'etait le point de la consigne corrigee.
         *
         * ⚠ ET C'EST POURQUOI CETTE GARDE N'EST PAS INSCRITE DANS
         * `TableDesGardes`. Ce releve gele les gardes de ROUTE ; celle-ci vit
         * dans le controleur, comme les trois autres consommateurs de `StepUp`.
         * L'y inscrire dirait qu'un intergiciel la porte — c'est-a-dire une
         * chose fausse, dans le fichier meme qui existe pour dire le vrai. La
         * route reste « authentifiee, sans role », et c'est la RAISON ecrite a
         * cote qui porte desormais le step-up.
         */
        $app = (string) file_get_contents(base_path('bootstrap/app.php'));

        $this->assertStringNotContainsString('StepUp::class', $app,
            'un intergiciel de step-up est desormais declare : la forme du '
            . 'portage a change, et `TableDesGardes` doit alors le refleter — ce '
            . "qu'elle ne fait pas aujourd'hui, deliberement.");
    }

    public function test_C6_la_PORTEE_des_deux_controles_est_ecrite_A_L_ECRAN(): void
    {
        /*
         * Deux controles ne font pas deux protections quand ils protegent de
         * choses differentes. Le nom retape protege du geste ACCIDENTEL — il est
         * affiche juste au-dessus — et le code protege d'une session VOLEE.
         *
         * Le correctif va plus loin que ce qui etait demande : la distinction
         * n'est pas seulement en commentaire, elle est DITE A L'UTILISATEUR par
         * `eff_code_aide`. Ce test tient les deux, et la parite FR/EN avec.
         */
        $vue = (string) file_get_contents(base_path('resources/views/profil.blade.php'));

        $this->assertStringContainsString('eff_code_aide', $vue,
            'la portee des deux controles n\'est plus dite a l\'ecran : le '
            . 'lecteur verra deux controles et conclura qu\'il y en a deux');

        foreach (['fr', 'en'] as $langue) {
            $cles = require base_path("lang/$langue/profil.php");
            foreach (['eff_code_aide', 'eff_code_label'] as $cle) {
                $this->assertArrayHasKey($cle, $cles, "`$cle` manque en « $langue »");
                $this->assertNotSame('', trim((string) $cles[$cle]),
                    "`$cle` est vide en « $langue » : la phrase n'atteint aucun ecran");
            }
        }
    }
}
