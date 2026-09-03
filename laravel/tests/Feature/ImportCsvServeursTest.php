<?php

namespace Tests\Feature;

use App\Services\Serveurs;
use Tests\TestCase;

/**
 * L'import CSV de `/serveurs` — D6e, E-344. La SEULE capacite du chantier qui
 * accepte un contenu que l'utilisateur FABRIQUE.
 *
 * ── CE QUI A ETE LU AVANT D'ETRE ECRIT ──────────────────────────────────────
 *
 * La consigne demandait d'asserer qu'un CSV malforme est « refuse ». Lecture
 * faite, `importeCsv` ne refuse pas un fichier : elle lit l'EN-TETE, et si une
 * colonne obligatoire manque elle rend `manquantes` sans traiter une seule
 * ligne. Le refus est donc PAR EN-TETE, et il est lisible — c'est ce qui est
 * mesure ici, pas un refus que personne n'a choisi.
 *
 * ── CE QUI N'EST PAS MESURE ICI, ET POURQUOI ────────────────────────────────
 *
 * Le garde du NAVIGATEUR (`accept=".csv"`) et celui du cadre
 * (`mimes:csv,txt`, `max:512`) vivent avant ce service. Une suite hermetique
 * n'a pas de navigateur : elle ne peut ni les exercer ni prouver qu'ils
 * existent. Ce fichier mesure le SERVICE, c'est-a-dire ce qui reste vrai quand
 * les deux gardes sont contournes — ce qu'un appel direct fait.
 *
 * La branche des DOUBLONS n'est pas mesurable ici : `existeDeja()` est privee
 * et interroge la base. Elle est donc lue, pas assertee — voir la note en fin
 * de fichier, qui est une TRANSMISSION et pas un verdict.
 */
class ImportCsvServeursTest extends TestCase
{
    /** Un fichier temporaire, detruit avec le test. */
    private function csv(string $contenu): string
    {
        $chemin = tempnam(sys_get_temp_dir(), 'rw-import-') . '.csv';
        file_put_contents($chemin, $contenu);
        $this->fichiers[] = $chemin;

        return $chemin;
    }

    /** @var list<string> */
    private array $fichiers = [];

    protected function tearDown(): void
    {
        foreach ($this->fichiers as $f) {
            @unlink($f);
        }
        parent::tearDown();
    }

    private function service(): ServeursSansBase
    {
        return new ServeursSansBase();
    }

    private const ENTETE = "name,ip,user,password,root_password\n";

    // ══════════════════════════════════════════════════════════════════════
    // « Zero ligne importee » et « je n'ai pas su lire » sont DEUX choses
    // ══════════════════════════════════════════════════════════════════════

    public function test_un_fichier_illisible_le_dit_et_ne_traite_rien(): void
    {
        $service = $this->service();

        $bilan = $service->importeCsv('/n/existe/pas/du/tout.csv', false);

        $this->assertSame(0, $bilan['lignes']);
        $this->assertSame(0, $bilan['crees']);
        $this->assertSame([], $service->ajouts, 'aucune machine ne doit etre creee');
        $this->assertSame(__('serveurs.imp_err_illisible'), $bilan['erreurs'][0]['texte']);
    }

    public function test_un_fichier_vide_le_dit_AUTREMENT(): void
    {
        $service = $this->service();

        $bilan = $service->importeCsv($this->csv(''), false);

        $this->assertSame(__('serveurs.imp_err_vide'), $bilan['erreurs'][0]['texte']);
    }

    public function test_les_deux_messages_ne_sont_pas_le_meme(): void
    {
        // LA PROPRIETE, et elle ne se voit sur aucun des deux tests pris seul :
        // un fichier qu'on n'a pas pu OUVRIR et un fichier qu'on a lu et qui
        // etait VIDE sont deux situations opposees pour l'exploitant. La
        // premiere se retente, la seconde se corrige. Les confondre — un seul
        // message pour les deux — rendrait le bilan inutilisable au moment ou
        // il sert.
        // CE QUE CE TEST NE VOIT PAS, ET C'EST MESURE. Il compare deux entrees
        // du CATALOGUE, pas deux chemins de code : une mutation faisant rendre
        // au fichier vide le message d'« illisible » le laisse VERT — seul
        // `un_fichier_vide_le_dit_AUTREMENT` rougit alors. Il garde donc la
        // distinction dans les libelles, jamais dans le geste. Lu dans la liste
        // des verts d'une mutation, pas deduit.
        $this->assertNotSame(
            __('serveurs.imp_err_illisible'),
            __('serveurs.imp_err_vide'),
            "« illisible » et « vide » partagent le meme libelle : le bilan ne "
            . 'distingue plus « je n\'ai pas su lire » de « il n\'y avait rien »',
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // L'en-tete : le seul endroit ou l'import s'arrete AVANT de traiter
    // ══════════════════════════════════════════════════════════════════════

    public function test_une_colonne_obligatoire_manquante_arrete_tout(): void
    {
        $service = $this->service();

        $bilan = $service->importeCsv(
            $this->csv("name,ip,user\nsrv-a,10.0.0.1,root\n"),
            false,
        );

        $this->assertSame(['password', 'root_password'], $bilan['manquantes']);
        $this->assertSame(0, $bilan['lignes'], 'aucune ligne ne doit avoir ete lue');
        $this->assertSame([], $service->ajouts, 'aucune machine ne doit etre creee');
    }

    public function test_l_entete_est_lu_sans_egard_a_la_casse_ni_aux_espaces(): void
    {
        $service = $this->service();

        $bilan = $service->importeCsv(
            $this->csv(" Name , IP ,User,PASSWORD, root_password \nsrv-a,10.0.0.1,root,x,y\n"),
            false,
        );

        $this->assertSame([], $bilan['manquantes'],
            "l'en-tete est normalise : ni la casse ni les espaces ne doivent le faire echouer");
        $this->assertCount(1, $service->ajouts);
    }

    // ══════════════════════════════════════════════════════════════════════
    // La borne, et elle se DIT
    // ══════════════════════════════════════════════════════════════════════

    public function test_au_dela_de_la_borne_le_bilan_annonce_la_troncature(): void
    {
        // UNE COUPE SILENCIEUSE SE LIT COMME UNE REUSSITE. 600 lignes fournies,
        // 500 traitees : sans `tronque`, l'exploitant verrait « 500 importes »
        // et croirait son fichier passe en entier.
        $lignes = '';
        for ($i = 1; $i <= 600; $i++) {
            $lignes .= "srv-$i,10.0.0.$i,root,x,y\n";
        }
        $service = $this->service();

        $bilan = $service->importeCsv($this->csv(self::ENTETE . $lignes), false);

        $this->assertTrue($bilan['tronque'], 'la coupe doit etre annoncee');
        $this->assertSame(Serveurs::IMPORT_MAX_LIGNES, $bilan['lignes']);
    }

    public function test_sous_la_borne_rien_n_est_annonce_comme_tronque(): void
    {
        $service = $this->service();

        $bilan = $service->importeCsv($this->csv(self::ENTETE . "srv-a,10.0.0.1,root,x,y\n"), false);

        $this->assertFalse($bilan['tronque']);
        $this->assertSame(1, $bilan['lignes']);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Le chemin heureux, EN DERNIER
    // ══════════════════════════════════════════════════════════════════════

    public function test_une_ligne_valide_est_creee_avec_ses_defauts(): void
    {
        $service = $this->service();

        $bilan = $service->importeCsv(
            $this->csv(self::ENTETE . "srv-a,10.0.0.1,root,motdepasse,rootpass\n"),
            false,
        );

        $this->assertSame(1, $bilan['lignes']);
        $this->assertCount(1, $service->ajouts);
        $ajout = $service->ajouts[0];
        $this->assertSame('srv-a', $ajout['name']);
        $this->assertSame('22', $ajout['port'], 'le port absent prend son defaut');
        $this->assertSame('OTHER', $ajout['environment']);
        $this->assertSame('NON CRITIQUE', $ajout['criticality']);
        $this->assertSame('INTERNE', $ajout['network_type']);
    }

    public function test_une_valeur_hors_liste_est_refusee_SANS_arreter_le_reste(): void
    {
        // Une ligne fausse au milieu d'un fichier juste ne doit pas emporter le
        // fichier : c'est la difference entre un import et une transaction.
        $service = $this->service();

        $bilan = $service->importeCsv($this->csv(
            "name,ip,user,password,root_password,environment\n"
            . "srv-a,10.0.0.1,root,x,y,PROD\n"
            . "srv-b,10.0.0.2,root,x,y,CE-QUI-N-EXISTE-PAS\n"
            . "srv-c,10.0.0.3,root,x,y,DEV\n"
        ), false);

        $this->assertSame(3, $bilan['lignes']);
        $this->assertCount(2, $service->ajouts, 'les deux lignes valides passent');
        $this->assertCount(1, $bilan['erreurs']);
        $this->assertSame('srv-b', $bilan['erreurs'][0]['nom'],
            "l'erreur doit NOMMER la machine : un numero de ligne seul oblige a "
            . 'rouvrir le fichier');
    }

    // ══════════════════════════════════════════════════════════════════════
    // ⚠ CE QUE LA MESURE A TROUVE, ET QUI N'ETAIT PAS DEMANDE
    // ══════════════════════════════════════════════════════════════════════

    public function test_le_numero_de_ligne_annonce_apres_une_ligne_VIDE(): void
    {
        // Une ligne vide est sautee par `continue` AVANT `$ligne++`. Le compteur
        // ne suit donc plus le fichier : toute erreur signalee apres une ligne
        // vide porte un numero TROP PETIT.
        //
        // Le fichier ci-dessous : en-tete (1), srv-a (2), vide (3), srv-b (4).
        // La ligne fautive est la QUATRIEME du fichier.
        //
        // CE TEST NE DEMANDE PAS DE CORRECTIF : il mesure ce qui est annonce.
        // S'il rougit, c'est que le compteur a ete aligne sur le fichier —
        // remplacer alors l'attendu par 4, ne pas contourner.
        $service = $this->service();

        $bilan = $service->importeCsv($this->csv(
            "name,ip,user,password,root_password,environment\n"
            . "srv-a,10.0.0.1,root,x,y,PROD\n"
            . "\n"
            . "srv-b,10.0.0.2,root,x,y,CE-QUI-N-EXISTE-PAS\n"
        ), false);

        $this->assertCount(1, $bilan['erreurs']);
        $this->assertSame(3, $bilan['erreurs'][0]['ligne'],
            "le numero annonce vaut 3 alors que la ligne fautive est la 4e du "
            . 'fichier : le compteur ne compte pas les lignes vides');
    }
}

/**
 * `Serveurs` sans sa base : `ajoute()` enregistre au lieu d'ecrire.
 *
 * Ce double est le seul moyen de mesurer l'import de bout en bout sans MySQL —
 * et la propriete centrale de plusieurs tests ci-dessus est une ABSENCE
 * (« aucune machine n'a ete creee »), qui ne se lit pas sur un etat final.
 *
 * `existeDeja()` est PRIVEE, donc la branche des doublons reste hors de portee :
 * elle est LUE, pas assertee.
 *
 * ── TRANSMISSION, ET CE N'EST PAS UN VERDICT ────────────────────────────────
 *
 * Lecture de `importeUneLigne` : le doublon n'est cherche QUE si la case
 * « ignorer les doublons » est cochee. Decochee — l'etat par defaut, une case
 * non soumise valant `false` — `existeDeja()` n'est jamais appele et la machine
 * est CREEE.
 *
 * Or le libelle de la case annonce : « Ignorer les serveurs deja presents
 * PLUTOT QUE DE LES SIGNALER EN ERREUR ». Ses deux branches promettent donc
 * « ignorer » ou « signaler ». Aucune des deux ne dit « creer un second
 * exemplaire », qui est ce que fait la branche par defaut.
 *
 * Transmis, non corrige et non asserte : la politique des doublons n'a ete
 * arbitree par personne, et la route annonce « MEME GARDE QUE LE LEGACY ».
 */
class ServeursSansBase extends Serveurs
{
    /** @var list<array<string, string>> */
    public array $ajouts = [];

    public function ajoute(array $brut): ?string
    {
        $this->ajouts[] = $brut;

        return null;
    }
}
