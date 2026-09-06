<?php

namespace Tests\Feature;

use App\Services\StepUp;
use App\Support\RoutesBackend;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

/**
 * `StepUp` — la PORTEE d'une marque de re-authentification.
 *
 * ══ POURQUOI CE FICHIER ══════════════════════════════════════════════════
 *
 * `StepUp` porte une propriete que son propre commentaire REVENDIQUE et que
 * rien ne mesurait :
 *
 * > « le legacy fusionne les trois routes root sous `policy_action`, si bien
 * > qu'un step-up consenti pour ANNULER une politique autorise un DEPLOIEMENT
 * > sudo pendant quinze minutes. »
 *
 * C'est le defaut que la separation des noms d'action existe pour empecher.
 * **Une propriete affirmee en commentaire et jamais exercee n'est pas tenue :
 * elle est esperee.** Trois gestes destructeurs en dependent
 * (`compte_supprimer`, `compte_anonymiser`, `permission_definir`), et un
 * quatrieme est POSE depuis le 2026-09-06 (E-449, `profil_effacement`).
 *
 * ══ CE QUE CE FICHIER NE MESURE PAS ══════════════════════════════════════
 *
 * Ni la VERIFICATION du code TOTP (`verifie()`), ni le quota de tentatives, ni
 * la duree de validite. Il mesure ce qu'une marque DEJA POSEE ouvre — et
 * seulement cela. Les marques sont posees directement en cache, par la cle
 * derivee du format connu, avec un temoin de couplage : si `cleMarque` change
 * de format, l'echec se produit sur le temoin et NON plus loin sous une cause
 * obscure.
 */
class StepUpPorteeDesMarquesTest extends TestCase
{
    private const ID_A = 4242;
    private const ID_B = 4243;

    private function stepUp(): StepUp
    {
        return app(StepUp::class);
    }

    private function poseMarque(int $idCompte, string $action): void
    {
        Cache::put('step_up:marque:' . $idCompte . ':' . $action, true, 900);
    }

    public function test_TEMOIN_la_cle_posee_est_bien_celle_que_valide_LIT(): void
    {
        /*
         * Le temoin de couplage, et il doit venir en PREMIER. Toutes les
         * assertions de ce fichier posent une marque par une cle DERIVEE d'un
         * format prive. Si ce format change, les contre-epreuves ci-dessous
         * passeraient toutes — pour la mauvaise raison : aucune marque ne
         * serait jamais posee, donc `valide()` rendrait `false` partout.
         *
         * **Une universelle negative est vraie a vide.** Ce test est ce qui
         * empeche ce fichier entier d'etre un dedouanement.
         */
        $s = $this->stepUp();

        $this->assertFalse($s->valide(self::ID_A, 'compte_anonymiser'),
            'une marque preexiste : le cache du banc n\'est pas propre, et les '
            . 'mesures de ce fichier ne partent pas de zero');

        $this->poseMarque(self::ID_A, 'compte_anonymiser');

        $this->assertTrue($s->valide(self::ID_A, 'compte_anonymiser'),
            'la cle posee ne correspond plus a celle que `valide()` lit : le '
            . 'format de `cleMarque` a change. Les contre-epreuves de ce fichier '
            . 'passeraient A VIDE — les refaire avant de conclure quoi que ce soit.');
    }

    public function test_une_marque_n_ouvre_QUE_son_action(): void
    {
        /*
         * LE DEFAUT `policy_action` DU LEGACY, transpose. Un step-up consenti
         * pour anonymiser ne doit pas ouvrir la suppression — les deux gestes
         * n'emportent pas la meme chose : l'anonymisation PRESERVE le journal,
         * la suppression l'emporte en cascade (PARITE E-116).
         */
        $s = $this->stepUp();
        $this->poseMarque(self::ID_A, 'compte_anonymiser');

        foreach (['compte_supprimer', 'permission_definir'] as $autre) {
            $this->assertFalse($s->valide(self::ID_A, $autre),
                "une marque consentie pour « compte_anonymiser » ouvre « $autre » : "
                . "c'est le defaut `policy_action` du legacy, que la separation des "
                . "noms d'action existe pour empecher");
        }
    }

    public function test_une_marque_n_ouvre_QUE_son_compte(): void
    {
        $s = $this->stepUp();
        $this->poseMarque(self::ID_A, 'compte_supprimer');

        $this->assertFalse($s->valide(self::ID_B, 'compte_supprimer'),
            'la marque d\'un compte vaut pour un autre : une re-authentification '
            . 'consentie par quelqu\'un ouvrirait le geste a un tiers');
    }

    public function test_une_action_HORS_de_la_liste_fermee_reste_refusee(): void
    {
        /*
         * ⚠ LA PROPRIETE QUI COMPTE LE PLUS ICI, et elle est contre-intuitive :
         * la marque EXISTE en cache et l'action est quand meme refusee.
         *
         * Le motif est ecrit dans `StepUp` : le legacy accepte n'importe quel nom
         * d'action, le nettoie au caractere puis pose `_step_up_<ce que le client
         * a envoye>`. On peut donc y deposer une marque qui n'ouvre RIEN
         * aujourd'hui — et quelque chose demain, le jour ou ce nom devient une
         * action reelle. **La fermeture de la liste est ce qui rend ce depot
         * inerte.**
         */
        $s = $this->stepUp();

        /*
         * ⚠ CES EXEMPLES SONT CHOISIS POUR NE PAS POUVOIR DEVENIR REELS.
         *
         * Ma premiere redaction citait `profil_effacement` comme action inconnue.
         * Elle est devenue reelle QUINZE MINUTES plus tard, et ce test a rougi —
         * la demonstration litterale du risque qu'il decrit, arrivee a son auteur.
         *
         * Un exemple PLAUSIBLE est un exemple PERISSABLE : il mesure la fermeture
         * de la liste aujourd'hui, et mesure autre chose demain. Ceux-ci ne
         * peuvent pas etre ajoutes a `ACTIONS_PORTAGE` — pas parce qu'on s'en
         * abstiendra, mais parce qu'aucun ne s'ecrit comme un nom d'action.
         */
        $impossibles = [
            '',                          // vide
            ' ',                         // blanc seul
            'compte anonymiser',         // espace : jamais un identifiant
            'compte_anonymiser ',        // meme nom, espace final — la comparaison
                                         // est STRICTE, un `==` laxiste passerait
            "compte_anonymiser\0",       // octet nul
            'COMPTE_ANONYMISER',         // casse differente
            str_repeat('a', 300),        // hors de toute convention de nommage
        ];

        foreach ($impossibles as $inconnue) {
            $this->poseMarque(self::ID_A, $inconnue);

            $this->assertFalse($s->valide(self::ID_A, $inconnue),
                '« ' . addcslashes($inconnue, "\0..\37") . '» est acceptee alors '
                . "qu'elle n'est pas dans "
                . '`ACTIONS_PORTAGE` : une marque deposee d\'avance ouvrirait ce '
                . "geste le jour ou le nom deviendrait reel");
        }
    }

    public function test_la_liste_des_actions_du_portage_est_FERMEE_et_datee(): void
    {
        /*
         * Le gel de la liste elle-meme. Une entree NEUVE doit faire rougir, pour
         * qu'elle soit motivee plutot que glissee — chaque action ouvre un geste
         * destructeur.
         *
         * ⚠ `profil_effacement` A ETE AJOUTE le 2026-09-06 : ce test a rougi ce
         * jour-la, exactement comme annonce, et l'entree a ete inscrite AVEC son
         * motif plutot que glissee. C'est ce que ce gel existe pour obtenir.
         */
        $this->assertSame([
            'compte_supprimer',
            'compte_anonymiser',
            'permission_definir',
            // AJOUTEE le 2026-09-06 (E-449, `f94c947`) : l'effacement en
            // LIBRE-SERVICE. Nom PROPRE, et c'est le point : reutiliser
            // `compte_anonymiser` aurait fait qu'une marque consentie pour
            // l'anonymisation ADMINISTRATIVE ouvre l'effacement de son propre
            // compte.
            'profil_effacement',
        ], StepUp::ACTIONS_PORTAGE,
            "la liste des actions du portage a change. Une entree neuve ouvre un "
            . "geste destructeur : la motiver ici, et verifier qu'elle ne REUTILISE "
            . "pas le nom d'une autre — une marque partagee entre deux gestes est "
            . 'exactement le defaut `policy_action` du legacy.');
    }

    public function test_les_deux_listes_d_actions_ne_se_MELANGENT_pas(): void
    {
        /*
         * `RoutesBackend::MOTIFS_STEP_UP` ne couvre que les chemins TRANSMIS au
         * backend Python ; `StepUp::ACTIONS_PORTAGE` ne couvre que les gestes du
         * portage. Le commentaire de `StepUp` dit que les elargir l'une dans
         * l'autre « brouillerait leur sens » — ce test le tient.
         *
         * Le nom d'une action de passerelle est DERIVE du chemin
         * (`/policy/sudo/deploy` -> `policy_sudo_deploy`) ; aucun ne doit
         * apparaitre dans la liste du portage, sans quoi une marque obtenue d'un
         * cote servirait de l'autre.
         */
        foreach (StepUp::ACTIONS_PORTAGE as $action) {
            $this->assertNull(RoutesBackend::cheminStepUp($action),
                "« $action » est a la fois un geste du portage ET une action derivee "
                . "d'un chemin de passerelle : une marque obtenue d'un cote servirait "
                . "de l'autre");
        }

        // TEMOIN : `cheminStepUp` sait rendre autre chose que `null`, sinon la
        // boucle ci-dessus passerait quelle que soit la liste.
        $this->assertNotNull(RoutesBackend::cheminStepUp('policy_sudo_deploy'),
            '`cheminStepUp` ne resout plus aucune action de passerelle : les '
            . 'assertions ci-dessus passent A VIDE');
    }
}
