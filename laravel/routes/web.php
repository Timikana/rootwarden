<?php

use App\Http\Controllers\ApprobationsController;
use App\Http\Controllers\ChatopsController;
use App\Http\Controllers\ClesApiController;
use App\Http\Controllers\ClePlateformeController;
use App\Http\Controllers\ClesSshController;
use App\Http\Controllers\ComparaisonCveController;
use App\Http\Controllers\ComptesController;
use App\Http\Controllers\ComptesDistantsController;
use App\Http\Controllers\AutorisationsPasserelleController;
use App\Http\Controllers\Fail2banController;
use App\Http\Controllers\ServicesController;
use App\Http\Controllers\BashrcController;
use App\Http\Controllers\AccesSftpController;
use App\Http\Controllers\PolitiquesController;
use App\Http\Controllers\DeriveConfigController;
use App\Http\Controllers\DockerController;
use App\Http\Controllers\AuditSshController;
use App\Http\Controllers\DocumentationController;
use App\Http\Controllers\WazuhController;
use App\Http\Controllers\GroupesController;
use App\Http\Controllers\GraylogController;
use App\Http\Controllers\ExportConformiteController;
use App\Http\Controllers\ExportConformitePdfController;
use App\Http\Controllers\ExportCveController;
use App\Http\Controllers\JournalAuditController;
use App\Http\Controllers\JournalCommandesController;
use App\Http\Controllers\MaintenanceController;
use App\Http\Controllers\MisesAJourController;
use App\Http\Controllers\NotificationsController;
use App\Http\Controllers\PasserelleController;
use App\Http\Controllers\PareFeuController;
use App\Http\Controllers\PermissionsController;
use App\Http\Controllers\PlanificationsCveController;
use App\Http\Controllers\PortailController;
use App\Http\Controllers\RapportConformiteController;
use App\Http\Controllers\RechercheController;
use App\Http\Controllers\SauvegardesController;
use App\Http\Controllers\ScanCveController;
use App\Http\Controllers\ServeursController;
use App\Http\Controllers\SuiviCveController;
use App\Http\Controllers\SupervisionController;
use App\Http\Controllers\TachesController;
use App\Http\Controllers\TicketsController;
use App\Http\Controllers\Auth\ConnexionController;
use App\Http\Controllers\Auth\SecondFacteurController;
use Illuminate\Support\Facades\Route;

/*
 * Socle d'authentification. Aucune page metier n'est encore portee.
 *
 * La regle : tout ce qui n'est pas explicitement public passe par
 * `session.authentifiee`. Entre le mot de passe et le second facteur, la
 * session ne porte qu'un compte temporaire — elle ne franchit pas ce garde.
 */

Route::redirect('/', '/accueil')->name('racine');

// ── Public ───────────────────────────────────────────────────────────────────
Route::get('/connexion', [ConnexionController::class, 'formulaire'])->name('connexion');
Route::post('/connexion', [ConnexionController::class, 'soumettre'])->name('connexion.soumettre');

// Etape intermediaire : le compte temporaire suffit, la session n'est PAS
// encore authentifiee. Ces routes ne sont donc pas derriere le garde.
Route::get('/second-facteur', [SecondFacteurController::class, 'formulaire'])->name('second-facteur');
Route::post('/second-facteur', [SecondFacteurController::class, 'soumettre'])->name('second-facteur.soumettre');
Route::get('/second-facteur/enrolement', [SecondFacteurController::class, 'enrolement'])->name('second-facteur.enrolement');
/* L'activation ECRIT le secret. Aucune garde de role : le compte n'est pas
   encore authentifie, il l'est PAR ce geste. La garde est la session temporaire
   plus la preuve du code. */
Route::post('/second-facteur/enrolement', [SecondFacteurController::class, 'activer'])->name('second-facteur.activer');

Route::post('/deconnexion', [ConnexionController::class, 'deconnexion'])->name('deconnexion');
Route::get('/deconnexion', [ConnexionController::class, 'deconnexion']);

// ── Authentifie ──────────────────────────────────────────────────────────────
/*
 * ══ LE GARDE DU CHANGEMENT DE MOT DE PASSE S'APPLIQUE AU GROUPE ══════════
 *
 * `legacy/auth/verify.php:169-183` relit la base a CHAQUE requete et redirige si
 * `force_password_change = 1`. Le portage ne lisait ce drapeau nulle part :
 * l'exigence n'y etait qu'un bandeau. Correction de PARITE — le legacy exerce
 * deja ce controle, le portage etait le chemin plus permissif des deux.
 *
 * POSE SUR CE GROUPE ET PAS SUR `web`, et c'est ce qui evite le piege : la
 * deconnexion (`web.php:70-71`) vit HORS du groupe, donc elle reste atteignable
 * **par construction**. Une pose sur `web` aurait exige de l'exempter — et
 * `GET /deconnexion` **n'a aucun nom de route**, donc une exemption par nom
 * l'aurait manquee et aurait enferme le compte.
 *
 * Mesure du 2026-09-01 : huit comptes actifs portent le drapeau, dont TROIS
 * au-dessus du role 1 — `id 1` et `id 78` en role 3, `id 77` en role 2. Pour un
 * role 3, ce drapeau est le SEUL frein : le role 3 court-circuite chaque `perm:`
 * et chaque `role:`.
 */
Route::middleware(['session.authentifiee', 'session.revoquee', 'mot.de.passe.a.changer'])->group(function () {
    Route::get('/cgu', [PortailController::class, 'cgu'])->name('cgu');
    Route::post('/cgu', [PortailController::class, 'accepterCgu'])->name('cgu.accepter');
    Route::get('/accueil', [PortailController::class, 'accueil'])->name('accueil');
    Route::get('/profil', [PortailController::class, 'profil'])->name('profil');
    // E-203 : fermer une session ouverte. Vise une EMPREINTE, jamais un
    // identifiant de session — celui-ci ne sort pas du serveur.
    Route::post('/profil/sessions/fermer', [PortailController::class, 'revoquerSession'])
        ->name('profil.sessions.fermer');
    /*
     * Le changement de mot de passe — sous-lot A2. Pas de garde de role ni de
     * permission : chacun change SON mot de passe, et l'identifiant du compte
     * vient de la SESSION, jamais de la requete.
     */
    Route::post('/profil/mot-de-passe', [PortailController::class, 'changerMotDePasse'])
        ->name('profil.mot-de-passe');

    /*
     * La re-authentification ponctuelle. AUCUNE garde de role : l'exigence porte
     * sur l'action visee, pas sur qui la demande, et l'identifiant du compte
     * vient de la session. Valider un step-up n'accorde par soi-meme aucun
     * acces — la passerelle applique ses propres controles ensuite.
     */
    Route::post('/profil/step-up', [PortailController::class, 'verifieStepUp'])
        ->name('profil.step-up');

    /* Rendre ses privileges. Strictement de-escaladant, donc sans garde. */
    Route::post('/profil/step-up/revoquer', [PortailController::class, 'revoqueStepUp'])
        ->name('profil.step-up.revoquer');

    /*
     * Pages metier reservees a l'administration.
     *
     * La garde est ici et NULLE PART ailleurs : ecrite aussi dans le
     * controleur, elle finirait par diverger.
     */

    // Approbation a quatre yeux des actions destructrices.
    Route::get('/approbations', ApprobationsController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('approbations');

    /*
     * Groupes de machines et actions de masse — sous-lot R1, LECTURE SEULE.
     *
     * Meme garde que le legacy aux trois couches, et c'est le premier module
     * non porte du chantier dont l'audit de gardes ne rend rien :
     * `legacy/groups/index.php:15-16` pose `checkAuth([2,3])` +
     * `checkPermission('can_admin_portal')`, `api_proxy.php` place `/groups`
     * dans la reserve d'administration, et les SIX routes backend portent
     * `@require_role(2)` + `@require_permission('can_admin_portal')`.
     *
     * Rien a ajouter a `RoutesBackend` : `/groups` y est deja, dans la liste
     * blanche ET dans la reserve d'administration.
     *
     * Aucune route d'ecriture ici : creation, suppression et actions de masse
     * ne sont pas portees en R1, et leurs boutons ouvrent un panneau qui dit
     * ce qu'ils engagent plutot que de ne rien faire.
     */
    Route::get('/groupes', GroupesController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('groupes');

    /*
     * Audit de configuration SSH — sous-lot A1, LECTURE SEULE.
     *
     * ⚠ `role:1`, PAS `role:2`. C'est la garde du legacy
     * (`legacy/ssh-audit/index.php:12-13` : `checkAuth([1,2,3])` +
     * `checkPermission('can_audit_ssh')`), et cinq routes du module sont
     * reellement concues pour le role 1 — contrairement a `platform_key`.
     * Passer a `role:2` reproduirait cote portage le croisement de gardes
     * qu'on reproche au backend.
     *
     * La liste de serveurs est bornee au perimetre du compte par
     * `Machines::perimetre()` : le legacy porte la meme borne, et c'est sa
     * propre correction d'IDOR.
     *
     * AUCUNE route d'ecriture. En particulier, rien ici ne compose un appel
     * vers `POST /ssh-audit/policies` — SEC-013 : l'ecriture de politique est
     * moins gardee que sa lecture sur la meme URL, et la passerelle compare
     * des chemins, jamais des methodes. Fermeture par l'ABSENCE.
     */
    Route::get('/audit-ssh', AuditSshController::class)
        ->middleware(['role:1', 'perm:can_audit_ssh'])
        ->name('audit-ssh');

    /*
     * Documentation du portail.
     *
     * ⚠ AUCUNE garde de role ni de permission — et c'est FIDELE, pas laxiste.
     * `legacy/documentation.php:11` pose `checkAuth([1,2,3])` et **aucun**
     * `checkPermission` (sa seule occurrence, `:295`, est dans un exemple de
     * code). Le seul cloisonnement est `$isAdmin = $role >= 2`, qui enclot
     * cinq sections — donc un SEUIL DANS LA PAGE, pas une garde de route.
     *
     * Poser `role:2` ici fermerait la page entiere a un role 1, la ou le
     * legacy lui ouvre 43 de ses 48 sections. La garde vit dans la route pour
     * tout le reste du portage ; ici l'objet garde n'est pas la page.
     */
    Route::get('/documentation', DocumentationController::class)->name('documentation');

    /*
     * Wazuh — sous-lot R1, LECTURE SEULE.
     *
     * Garde du legacy (`legacy/wazuh/index.php:25-26`) : `checkAuth([2,3])` +
     * `checkPermission('can_manage_wazuh')`. Les cinq routes backend de
     * lecture exigent la meme paire.
     *
     * AUCUNE route d'ecriture. Les neuf gestes du module sont declares absents
     * A L'ECRAN et nommes un par un — dont trois qui, meme sur l'ancien
     * portail, n'ont pas l'effet que leur nom suggere.
     *
     * ⚠ E-333 — une redirection `/wazuh/` ECRASAIT cette route. Elle se
     * normalise en `/wazuh`, soit la MEME URI : la derniere enregistree
     * remplace la premiere, NOM COMPRIS. `Route::has('wazuh')` devenait
     * faux, la redirection pointait un nom inexistant, et la page rendait
     * 500. Retiree — contrairement a `/groups/` ou `/documentation.php`, le
     * chemin du legacy est DEJA celui du portage.
     *
     * ⚠ Le discriminant entre ce qui est porte et ce qui ne l'est pas est la
     * METHODE, pas le chemin : `/wazuh/config`, `/wazuh/options` et
     * `/wazuh/rules/<name>` portent chacun un GET qui lit ET un non-GET qui
     * ecrit. Le helper `lis()` du script ne sait faire qu'un GET.
     */
    Route::get('/wazuh', WazuhController::class)
        ->middleware(['role:2', 'perm:can_manage_wazuh'])
        ->name('wazuh');

    /*
     * Derive de configuration. Seule page portee a ce jour dont la garde
     * n'est PAS `can_admin_portal` : `can_view_compliance` est portee par un
     * compte role 2, ce qui rend la permission observable independamment du
     * role.
     */
    /*
     * Deploiement des cles SSH — module `ssh/`, sous-lot K1 : la page nue.
     *
     * GARDE REPRISE TELLE QUELLE DU LEGACY : `ssh/index.php:34-35` fait
     * `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` puis
     * `checkPermission('can_deploy_keys')` — donc role >= 1 PORTANT la permission.
     *
     * ECART DECLARE, non tranche ici (voir PARITE) : l'en-tete du fichier legacy
     * annonce depuis toujours « Acces refuse pour les utilisateurs standards
     * (role_id = 1) », ce que son `checkAuth` n'applique pas. Meme nature que
     * E-36, avec une consequence plus lourde : `POST /deploy` n'a ni role ni
     * permission, donc un role 1 habilite pourrait declencher le deploiement, et
     * `GET /logs` etant `@require_role(2)` il ne pourrait pas en lire le
     * resultat. Restreindre serait un CHANGEMENT DE DROITS : decision de
     * l'exploitant, a prendre avec D-1.
     *
     * K1 n'appelle AUCUNE route du backend.
     */
    Route::get('/cles-ssh', ClesSshController::class)
        ->middleware(['role:1', 'perm:can_deploy_keys'])
        ->name('cles-ssh');

    /*
     * Supervision — module `supervision/`, sous-lot V1 : la page et ses quatre
     * onglets.
     *
     * GARDE REPRISE TELLE QUELLE DU LEGACY (`supervision/index.php:17-18`) :
     * `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis
     * `checkPermission('can_manage_supervision')`, soit role >= 2 PORTANT la
     * permission.
     *
     * AUCUN ECART A DECLARER, et c'est assez rare ici pour etre dit : l'en-tete du
     * fichier legacy annonce « admin (2) + superadmin (3) + can_manage_supervision »
     * et son code applique exactement cela. Rien a arbitrer, contrairement a `ssh/`
     * (en-tete plus strict que le code) et a `security/` (D-1).
     *
     * V1 N'APPELLE AUCUNE ROUTE DU BACKEND. Le legacy en appelle DEUX des le
     * chargement et les rejoue a chaque bascule d'onglet.
     *
     * DEFAUTS DU BACKEND CONSTATES ET NON CORRIGES ICI (voir PARITE) : les quatre
     * routes de profils n'ont aucun `@require_role`, et `/supervision/` est absent
     * de `$ADMIN_ONLY_PREFIXES` cote proxy legacy. Les fermer demanderait de
     * modifier le backend : decision de l'exploitant.
     */
    Route::get('/supervision', [SupervisionController::class, '__invoke'])
        ->middleware(['role:2', 'perm:can_manage_supervision'])
        ->name('supervision');

    /*
     * Enregistrement de la configuration globale — sous-lot V4.
     *
     * MEME GARDE QUE LA PAGE, et posee ICI : `role:2` +
     * `perm:can_manage_supervision`. Le legacy passe par
     * `POST /supervision/config`, dont l'`UPDATE` derive d'un
     * `SELECT ... ORDER BY id DESC LIMIT 1` SANS filtre de plateforme
     * (`supervision.py:508`) : enregistrer Zabbix y ecrase une ligne Centreon plus
     * recente — mesure faite, voir PARITE E-76. Le portage ecrit en base avec
     * `WHERE platform = ?` (decision S3/S4) et n'herite donc pas du defaut.
     *
     * Le PSK est chiffre par `App\Support\SecretExploitation`, dont
     * l'interoperabilite avec `encryption.py` a ete MESUREE par aller-retour, pas
     * supposee.
     */
    Route::post('/supervision/configuration', [SupervisionController::class, 'enregistrer'])
        ->middleware(['role:2', 'perm:can_manage_supervision'])
        ->name('supervision.configuration');

    /*
     * Profils de supervision : creation, modification, suppression — sous-lot V5.
     *
     * MEME GARDE QUE LA PAGE : `role:2` + `perm:can_manage_supervision`. C'est la
     * difference avec le legacy, et elle est nette : ses quatre routes de profils
     * (`supervision.py` 1734, 1760, 1801, 1817) portent `@require_permission` mais
     * **aucun `@require_role`** — la cinquieme, `machines/<mid>/profile`, porte bien
     * `@require_role(2)` avec un commentaire « Patch A01 ». Le correctif a ete
     * applique a UNE route et pas a ses quatre voisines. Et `/supervision/` est
     * absent des 25 prefixes de `$ADMIN_ONLY_PREFIXES` du proxy legacy.
     * Ici, l'ecriture se fait en base derriere cette garde : la permission garde
     * enfin la REQUETE et plus seulement la PAGE. Poser `@require_role(2)` sur les
     * quatre routes backend reste une decision d'exploitant — declaree en PARITE,
     * pas prise ici.
     *
     * LA SUPPRESSION EST DESTRUCTRICE : `ON DELETE CASCADE` (verifie au schema)
     * emporte les assignations, donc les serveurs concernes retombent sur la
     * configuration globale.
     */
    Route::post('/supervision/profils', [SupervisionController::class, 'enregistrerProfil'])
        ->middleware(['role:2', 'perm:can_manage_supervision'])
        ->name('supervision.profils.enregistrer');

    Route::post('/supervision/profils/supprimer', [SupervisionController::class, 'supprimerProfil'])
        ->middleware(['role:2', 'perm:can_manage_supervision'])
        ->name('supervision.profils.supprimer');

    /*
     * Les reglages par machine — sous-lot V10a. La garde est la MEME que celle
     * des autres gestes du module : elle vit DANS LA ROUTE et nulle part ailleurs.
     * A noter que la route backend equivalente
     * (`POST /supervision/overrides/<id>`) est la seule route du module touchant
     * une machine sans `@require_machine_access` (PARITE E-85) : le portage
     * n'emprunte pas ce chemin, il ecrit en base avec une liste fermee.
     */
    Route::post('/supervision/reglages', [SupervisionController::class, 'enregistrerOverrides'])
        ->middleware(['role:2', 'perm:can_manage_supervision'])
        ->name('supervision.reglages.enregistrer');

    Route::get('/derive-config', DeriveConfigController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('derive-config');

    /*
     * Sauvegardes de la base. La RESTAURATION est destructive et le backend la
     * reserve au role 3 : la garde de la page n'est donc pas celle de l'action.
     */
    /*
     * Inventaire Docker. Garde `role:2` SEULE, sans permission — reprise telle
     * quelle du legacy (`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`). C'est la
     * seule entree de menu gardee par le ROLE et non par une permission ; le
     * releve est signale dans INVENTAIRE.md et n'est pas corrige au detour d'un
     * portage.
     */
    /*
     * ChatOps. `role:2` + `perm:can_admin_portal`, comme le legacy
     * (`checkAuth` puis `checkPermission`). Le WEBHOOK, lui, est PUBLIC et vit
     * hors de ce groupe — voir plus bas.
     */
    Route::get('/chatops', [ChatopsController::class, 'page'])
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('chatops');

    /*
     * Fenetres de maintenance. `role:2` + `perm:can_admin_portal`, comme le
     * legacy (`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` puis
     * `checkPermission('can_admin_portal')`).
     *
     * La page ne MUTE rien par elle-meme, mais ce qu'elle ecrit decide si le
     * RESTE de la flotte peut muter : une fenetre activee referme toutes les
     * actions mutantes hors de ses plages, pour les roles < 3. La garde est donc
     * celle d'une page d'administration, pas celle d'une page de consultation.
     */
    Route::get('/maintenance', MaintenanceController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('maintenance');

    /*
     * Transfert des journaux (Graylog). `role:2` + `perm:can_manage_graylog`,
     * releve du legacy (`graylog/index.php:17-18`).
     *
     * La permission n'est PAS `can_admin_portal` : ce module a la sienne, et la
     * confondre elargirait l'acces a tous les administrateurs du portail. Les
     * routes du backend exigent la meme (`@require_permission('can_manage_graylog')`),
     * donc la garde de la page et celle de la requete disent la meme chose — ce
     * qui n'est pas le cas partout dans ce depot.
     */
    Route::get('/graylog', GraylogController::class)
        ->middleware(['role:2', 'perm:can_manage_graylog'])
        ->name('graylog');

    Route::get('/docker', DockerController::class)
        ->middleware(['role:2'])
        ->name('docker');

    Route::get('/sauvegardes', SauvegardesController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('sauvegardes');

    /*
     * Centre de taches. `role:2` SEUL, sans permission : c'est ce que fait le
     * legacy, qui n'appelle que `checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])`.
     * L'entree de MENU, elle, vit dans le bloc garde par `can_admin_portal` —
     * un role 2 sans la permission ne la voit pas et atteint pourtant la page.
     * Ecart reproduit tel quel et consigne, plutot que corrige sans arbitrage.
     */
    Route::get('/taches', TachesController::class)
        ->middleware(['role:2'])
        ->name('taches');

    // Ticketing ITSM : liste et creation manuelle.
    Route::get('/tickets', TicketsController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('tickets');

    // Recherche globale : serveurs, utilisateurs, CVE, tickets, journal d'audit.
    Route::get('/recherche', RechercheController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('recherche');

    /*
     * Mises a jour Linux — sous-lot U1 du module `update/`, lecture seule.
     * Garde reprise du legacy : role 1 ADMIS s'il porte can_update_linux, et
     * cloisonne alors par `user_machine_access`.
     */
    Route::get('/mises-a-jour', MisesAJourController::class)
        ->middleware(['role:1', 'perm:can_update_linux'])
        ->name('mises-a-jour');

    /*
     * Rapport de conformite — module `security/`, sous-lot S2a.
     *
     * GARDE VOLONTAIREMENT PLUS STRICTE QUE LE LEGACY (decision D-1). Le legacy
     * admet `ROLE_USER` et ne cloisonne aucune donnee, alors que l'en-tete de son
     * fichier annonce « Acces : admin (2) et superadmin (3) ». Un role 1 porteur
     * de `can_view_compliance` obtenait donc tout le parc avec IP, port et
     * utilisateur SSH, tous les comptes, et la posture par serveur avec les
     * ecarts en clair. La route porte la garde que le fichier annoncait.
     * Consigne dans PARITE.md : c'est une divergence, pas un oubli.
     */
    Route::get('/rapport-conformite', RapportConformiteController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('rapport-conformite');

    /*
     * Export CSV du meme rapport — sous-lot S2c. MEME garde que la page, et
     * memes chiffres : tout vient de `Conformite::rapport()`, jamais recalcule.
     */
    Route::get('/rapport-conformite/csv', ExportConformiteController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('rapport-conformite.csv');

    /*
     * Export PDF du meme rapport — sous-lot S2b. Meme garde, memes chiffres.
     * Le rendu vit dans une vue dediee : le gabarit du portail porte une barre
     * laterale et des jetons de theme dont dompdf ne sait rien.
     */
    Route::get('/rapport-conformite/pdf', ExportConformitePdfController::class)
        ->middleware(['role:2', 'perm:can_view_compliance'])
        ->name('rapport-conformite.pdf');

    /*
     * Export CSV d'un scan CVE — module `security/`, sous-lot S1.
     *
     * Garde reprise du legacy : `checkAuth([1,2,3])` + `can_scan_cve`. Le role 1
     * est bien ADMIS ; c'est le cloisonnement par `user_machine_access`, dans le
     * controleur, qui borne ce qu'il peut lire — et son refus rend 404, pas 403.
     *
     * PAS D'ENTREE DE MENU : le legacy la declenche depuis un bouton de la page
     * des vulnerabilites, qui appartient au sous-lot S3. Jusque-la la route
     * existe et se teste, mais n'est atteignable qu'en tapant son adresse. Dit
     * ici pour que personne ne cherche l'entree manquante dans Navigation.
     */
    /*
     * Consultation des scans CVE — module `security/`, sous-lot S3.
     *
     * GARDE REPRISE TELLE QUELLE de la page legacy (`security/index.php:37-38`) :
     * `checkAuth([USER,ADMIN,SUPERADMIN])` + `checkPermission('can_scan_cve')`,
     * soit role >= 1 AVEC la permission. C'est la meme que l'export de S1.
     *
     * ECART ASSUME (E-48) : cote legacy cette permission ne garde que la PAGE.
     * Le proxy met `/cve_` en liste blanche pour tout role >= 1 sans jamais
     * regarder de permission, et sur les 19 routes CVE du backend
     * `require_permission` apparait zero fois. Ici la lecture ne passe pas par
     * une route backend : elle est faite en base par le controleur, DERRIERE
     * cette garde. La permission garde donc enfin la requete.
     */
    Route::get('/scan-cve', ScanCveController::class)
        ->middleware(['role:1', 'perm:can_scan_cve'])
        ->name('scan-cve');

    Route::get('/scan-cve/comparaison', ComparaisonCveController::class)
        ->middleware(['role:1', 'perm:can_scan_cve'])
        ->name('scan-cve.comparaison');

    /*
     * Planification des scans CVE — sous-lot S4.
     *
     * `role:2` ET NON `role:1` : le bloc de planification du legacy vit sous
     * `if ($role >= 2)` (`legacy/security/index.php:231`), et ses cinq routes
     * backend portent `require_role(2)`. La consultation reste ouverte au role 1,
     * l'ecriture non — la garde est reprise telle quelle, cran par cran.
     *
     * ECART ASSUME (E-52) : ces routes REMPLACENT `cve_schedules` et
     * `cron_preview` du backend, elles ne les appellent pas. Meme raison qu'en S3
     * — la permission ne garde aucune requete backend, et le garde d'acces ne lit
     * pas le meme parametre que sa route. Ici `perm:can_scan_cve` garde enfin
     * l'ecriture.
     */
    Route::get('/scan-cve/planifications', [PlanificationsCveController::class, 'index'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->name('scan-cve.planifs');
    Route::post('/scan-cve/planifications', [PlanificationsCveController::class, 'store'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->name('scan-cve.planifs.creer');
    Route::put('/scan-cve/planifications/{id}', [PlanificationsCveController::class, 'update'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->whereNumber('id')->name('scan-cve.planifs.modifier');
    Route::delete('/scan-cve/planifications/{id}', [PlanificationsCveController::class, 'destroy'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->whereNumber('id')->name('scan-cve.planifs.supprimer');
    Route::get('/scan-cve/apercu-cron', [PlanificationsCveController::class, 'apercu'])
        ->middleware(['role:2', 'perm:can_scan_cve'])->name('scan-cve.apercu-cron');

    /*
     * Suivi de remediation — sous-lot S5.
     *
     * `role:1` + `perm:can_scan_cve`, la garde de la page : le suivi se consulte
     * et se pose depuis le tableau des vulnerabilites, pas depuis un ecran
     * d'administration.
     *
     * LA CREATION DE TICKET N'EST PAS ICI, et c'est deliberé (E-58) :
     * `POST /tickets` appelle un fournisseur ITSM EXTERNE quand il est configure.
     * Elle passe donc par la PASSERELLE, ou `/tickets` est deja dans
     * `ADMIN_SEULEMENT` — role 2 exige par la passerelle, `can_admin_portal` par
     * le backend.
     */
    Route::get('/scan-cve/suivi', [SuiviCveController::class, 'index'])
        ->middleware(['role:1', 'perm:can_scan_cve'])->name('scan-cve.suivi');
    Route::post('/scan-cve/suivi', [SuiviCveController::class, 'store'])
        ->middleware(['role:1', 'perm:can_scan_cve'])->name('scan-cve.suivi.poser');

    Route::get('/export-cve', ExportCveController::class)
        ->middleware(['role:1', 'perm:can_scan_cve'])
        ->name('export-cve');

    // Journal des commandes — tracabilite de type bastion, lecture seule.
    Route::get('/journal-commandes', JournalCommandesController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('journal-commandes');

    /*
     * Journal d'audit — module `adm/`, sous-lot D1.
     *
     * La page et l'export suivent la garde du legacy : role 2 + `can_admin_portal`.
     * Les DEUX GESTES D'INTEGRITE exigent en plus le ROLE 3, comme les points
     * d'API du legacy — mais ici la reserve vit sur la ROUTE. Le legacy ne cache
     * que les boutons de sa page ; aucun de ses seize points d'API `adm/` ne
     * porte de `checkPermission`, et le role y porte seul la charge.
     */
    /*
     * Notifications — module `adm/`, sous-lot D2.
     *
     * La boite de reception est ouverte a TOUT compte authentifie (role 1), comme
     * le legacy : `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`. Les
     * REGLAGES sont reserves au role 3, comme `manage_notifications.php` le fait
     * pour ses cases — mais ici la reserve vit sur la ROUTE, pas seulement sur
     * l'affichage du controle.
     *
     * CHAQUE GESTE QUI ECRIT EST UN POST. Le legacy lit son action dans `$_GET`
     * d'abord et ne verifie le jeton que sur `POST` : `GET ?action=read_all`
     * ecrit sans jeton (E-109). Ici le seul GET est le compteur, et il ne fait
     * que lire.
     */
    Route::get('/notifications', NotificationsController::class)
        ->middleware('role:1')->name('notifications');
    Route::get('/notifications/compte', [NotificationsController::class, 'compte'])
        ->middleware('role:1')->name('notifications.compte');
    Route::post('/notifications/tout-lire', [NotificationsController::class, 'toutLire'])
        ->middleware('role:1')->name('notifications.tout-lire');
    Route::post('/notifications/{id}/lire', [NotificationsController::class, 'lire'])
        ->whereNumber('id')->middleware('role:1')->name('notifications.lire');
    Route::delete('/notifications/{id}', [NotificationsController::class, 'supprimer'])
        ->whereNumber('id')->middleware('role:1')->name('notifications.supprimer');
    Route::get('/notifications/preferences', [NotificationsController::class, 'reglages'])
        ->middleware(['role:3', 'perm:can_admin_portal'])->name('notifications.reglages');
    Route::post('/notifications/preferences', [NotificationsController::class, 'definirPreference'])
        ->middleware(['role:3', 'perm:can_admin_portal'])->name('notifications.preferences.poser');

    /*
     * Comptes du portail — module `adm/`, sous-lot D3.
     *
     * Garde relevee du legacy : role 2 + `can_admin_portal` (`admin_page.php:40-41`).
     * La GARDE HIERARCHIQUE — un role 2 ne touche pas un role 3 — vit dans le
     * controleur, parce qu'elle depend de la CIBLE et pas seulement de l'auteur.
     */
    Route::get('/comptes', ComptesController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])->name('comptes');

    /*
     * ══ LES GARDES DE `comptes` NE SONT PAS TOUTES AU MEME NIVEAU ══════════
     *
     * Elles viennent de fichiers DIFFERENTS du legacy, et il faut les relire un
     * par un — l'intuition ne les devine pas. Releve par une relecture croisee
     * le 2026-08-26, apres qu'un premier jet eut mis `cle-ssh` et
     * `deverrouiller` au role 2 :
     *
     *   `manage_roles.php:31`      role 2 et 3   -> mot de passe, second facteur
     *                              + garde HIERARCHIQUE `:80` (un role < 3 ne
     *                                touche pas un role >= 3)
     *   `api/unlock_user.php:23`   role 3 SEUL   -> deverrouillage
     *   `api/update_user.php:31`   role 3 SEUL   -> pose de la cle SSH
     *   `api/delete_user.php`      role 2 et 3   -> suppression
     *
     * DEUX ETAIENT AFFAIBLIES PAR LE PORTAGE, et c'est le pire resultat
     * possible : un role 2 pouvait poser la cle SSH sur le compte d'un role 3 —
     * donc, une fois la cle deployee, obtenir un acces machine sous une
     * identite qui n'est pas la sienne. Le legacy l'interdisait par le ROLE, et
     * n'avait donc pas besoin d'une garde hierarchique ici.
     *
     * UNE EST RENFORCEE, ET C'EST DELIBERE : la suppression passe de « role 2
     * et 3 » a `role:3`. Motif ecrit en PARITE E-116 — supprimer un compte
     * EFFACE son journal d'audit et rompt la chaine que D1 vient de rendre
     * verifiable. Une divergence voulue se declare, sinon la relecture suivante
     * la lit comme une erreur.
     */
    Route::post('/comptes', [ComptesController::class, 'creer'])
        ->middleware(['role:2', 'perm:can_admin_portal'])->name('comptes.creer');
    Route::post('/comptes/{id}/mot-de-passe', [ComptesController::class, 'motDePasse'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('comptes.mot-de-passe');
    Route::post('/comptes/{id}/cle-ssh', [ComptesController::class, 'cleSsh'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('comptes.cle-ssh');
    Route::post('/comptes/{id}/deverrouiller', [ComptesController::class, 'deverrouiller'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('comptes.deverrouiller');
    /*
     * Suppression et anonymisation — sous-lot D4. Role 3 sur la ROUTE : le
     * legacy exige le meme role, mais dans le corps du fichier.
     *
     * L'etat est un GET separe : la page a besoin de savoir, AVANT d'ouvrir son
     * panneau, si le compte porte un journal — auquel cas la suppression
     * l'emporterait (E-116) et c'est l'anonymisation qu'il faut proposer.
     */
    Route::get('/comptes/{id}/etat-suppression', [ComptesController::class, 'etatSuppression'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('comptes.etat-suppression');
    Route::delete('/comptes/{id}', [ComptesController::class, 'supprimer'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('comptes.supprimer');
    Route::post('/comptes/{id}/anonymiser', [ComptesController::class, 'anonymiser'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('comptes.anonymiser');

    Route::post('/comptes/{id}/second-facteur', [ComptesController::class, 'reinitialiserTotp'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('comptes.second-facteur');

    /*
     * Permissions et acces machines — module `adm/`, sous-lot D5.
     *
     * Garde de page : role 3 + `can_admin_portal`, relevee du legacy
     * (`update_permissions.php:47` exige le superadmin). La garde HIERARCHIQUE —
     * on ne modifie ni ses propres droits ni ceux d'un rang egal ou superieur —
     * vit dans le controleur, parce qu'elle depend de la CIBLE.
     *
     * Le geste porte en plus un STEP-UP, comme le legacy. La difference est
     * qu'ici il existe un chemin pour y repondre : le panneau ecrit pour D4.
     */
    Route::get('/permissions', PermissionsController::class)
        ->middleware(['role:3', 'perm:can_admin_portal'])->name('permissions');

    /*
     * Le parc de machines — module `adm/`, sous-lot D6a.
     *
     * MEME GARDE QUE `/comptes`, et c'est celle de la PAGE HOTE du legacy :
     * `admin_page.php` exige `checkPermission('can_admin_portal')`. Son include
     * `manage_servers_table.php` ne l'exige PAS, et reste servi par Apache —
     * PARITE E-120. Ici il n'y a pas de fragment separe : la page rend son
     * tableau elle-meme, il n'y a donc rien a garder deux fois.
     *
     * TROIS GESTES, TROIS ROUTES. Le legacy les distingue par le `name` du
     * bouton clique dans un POST unique vers la page ; un `name` oublie sur un
     * `<button>` y transforme une modification en creation.
     */
    Route::get('/serveurs', ServeursController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs');
    Route::post('/serveurs/ajouter', [ServeursController::class, 'ajouter'])
        ->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.ajouter');
    Route::post('/serveurs/{id}/modifier', [ServeursController::class, 'modifier'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.modifier');
    Route::post('/serveurs/{id}/supprimer', [ServeursController::class, 'supprimer'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.supprimer');

    /*
     * Etiquettes et notes — sous-lot D6b.
     *
     * MEME GARDE QUE LA PAGE, et c'est tout l'objet : `server_actions.php`
     * n'exige que `checkAuth([2,3])`, si bien qu'un compte de role 2 refuse sur
     * `admin_page.php` y ecrit quand meme (PARITE E-126, mesure au navigateur :
     * une etiquette reellement posee en base).
     *
     * Ce sont des POST de FORMULAIRE, pas des `fetch` : les quatre gestes du
     * legacy meurent sur un jeton CSRF que son enrobage n'injecte pas pour cette
     * famille d'URL (E-125). Un formulaire n'a pas de plomberie a oublier.
     */
    Route::post('/serveurs/{id}/etiquettes', [ServeursController::class, 'poserEtiquette'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.etiquette.poser');
    Route::post('/serveurs/{id}/etiquettes/retirer', [ServeursController::class, 'retirerEtiquette'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.etiquette.retirer');
    Route::post('/serveurs/{id}/notes', [ServeursController::class, 'poserNote'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.note.poser');
    Route::post('/serveurs/{id}/notes/{note}/supprimer', [ServeursController::class, 'supprimerNote'])
        ->whereNumber('id')->whereNumber('note')
        ->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.note.supprimer');

    /*
     * Cycle de vie — sous-lot D6d.
     *
     * ECRIT EN BASE, sans passer par `POST /server_lifecycle`. Cette route du
     * backend ne fait qu'un `UPDATE` sur `machines` — aucun effet distant — et
     * rend un `updated` qui recouvre deux situations opposees (E-133). On ne
     * traverse pas la passerelle pour heriter d'un defaut qu'on ne peut pas
     * corriger a distance ; meme decision que V4 pour `supervision_config`.
     *
     * Le TEST DE CONNEXION, lui, passe bien par la passerelle : sa sonde TCP
     * appartient au backend, et `/server_status` est deja en liste blanche.
     */
    Route::post('/serveurs/{id}/cycle', [ServeursController::class, 'cycle'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('serveurs.cycle');

    /*
     * Les cles d'API — sous-lot D7.
     *
     * `role:3` + `perm:can_manage_api_keys`, releve fidele d'`api_keys.php:19-20`.
     * La permission ne DECIDE de rien — sur une page deja reservee au role 3,
     * `ExigePermission` passe par son repli superadministrateur, comme
     * `checkPermissionFromDB` le fait cote legacy (E-134). Elle est portee
     * quand meme : si la page s'ouvrait un jour au role 2, la garde serait deja
     * a sa place, et l'ecart se verrait au diff plutot qu'a l'incident.
     *
     * LA CREATION REND UNE VUE, PAS UNE REDIRECTION : la cle en clair n'existe
     * qu'une fois et ne doit pas transiter par la session, dont le pilote est
     * `file`.
     */
    Route::get('/cles-api', ClesApiController::class)
        ->middleware(['role:3', 'perm:can_manage_api_keys'])->name('cles-api');
    Route::post('/cles-api', [ClesApiController::class, 'creer'])
        ->middleware(['role:3', 'perm:can_manage_api_keys'])->name('cles-api.creer');
    Route::post('/cles-api/{id}/revoquer', [ClesApiController::class, 'revoquer'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_manage_api_keys'])->name('cles-api.revoquer');

    /*
     * Les comptes distants — sous-lot D8.
     *
     * `role:2`, LA OU LE LEGACY ADMET LE ROLE 1. `server_users.php:11` fait
     * `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])`, mais SIX de ses
     * SEPT routes exigent `@require_role(2)` et la page ne distingue aucun role
     * dans son rendu : un role 1 porteur de la permission verrait tous les
     * boutons et recevrait 401 sur six d'entre eux. La garde est donc alignee
     * sur ce que la page peut reellement faire.
     *
     * Divergence declaree, et mesuree : aucun compte de role 1 ne porte
     * `can_manage_remote_users` — un seul compte du parc l'a, `superadmin`.
     * Rien n'est retire a personne aujourd'hui.
     *
     * LE CLASSEMENT S'ECRIT EN BASE : la route du backend ne fait qu'un
     * `UPDATE` sans effet distant. Les gestes qui JOIGNENT la machine passent,
     * eux, par la passerelle, et chacun derriere son panneau de decision.
     */
    /*
     * Droits sudo par compte distant — D9a. `role:3` SEUL, comme le legacy
     * (`checkAuth([ROLE_SUPERADMIN])`, mesure : role 2 -> 403) et comme les onze
     * routes de `backend/routes/policies.py`, toutes en `@require_role(3)`.
     *
     * Aucune route d'ecriture ici : deployer, auditer et retirer partent par la
     * passerelle, qui les inscrit deja en re-authentification ponctuelle.
     */
    /*
     * Acces SFTP/SSH par compte distant — D9b. `role:3` SEUL, comme D9a : meme
     * garde de page (`checkAuth([ROLE_SUPERADMIN])`, role 2 mesure a 403) et
     * memes `@require_role(3)` cote backend.
     */
    /*
     * Deploiement du `.bashrc` standardise — B1. `role:2` + la permission,
     * repris tel quel du legacy (`checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN])` +
     * `checkPermission('can_manage_bashrc')`).
     *
     * MESURE sur le legacy, les trois chemins : role 1 -> 403, role 2 SANS la
     * permission -> 403, role 3 SANS la permission -> 200. Le contournement par
     * le role 3 vient du middleware `perm`, et il est identique cote backend
     * (`require_permission`, `helpers.py:280`).
     */
    /*
     * Services systemd distants — S1. `role:1` + la permission, repris tel quel
     * du legacy : **la page admet le role 1**, contrairement a `bashrc/`.
     *
     * MESURE par S1 : role 1 SANS la permission -> 403, role 2 AVEC -> 200,
     * role 3 SANS -> 200. Les deux admis le sont pour des raisons DIFFERENTES.
     *
     * E-149 : les huit routes backend n'ont ni role ni permission. Le portage ne
     * le referme pas — voir `App\Services\ServicesSystemd` et §7 du plan.
     */
    /*
     * Fail2ban — F1. `role:1` + la permission, repris tel quel du legacy — dont
     * l'en-tete annonce pourtant « admin (2), superadmin (3) » alors que sa
     * garde admet ROLE_USER (motif E-36).
     *
     * Le role 1 est un choix assume du projet (`CHANGELOG.md:3078-3085`). Ce qui
     * ne l'est pas, c'est E-152 : sur 23 routes des deux modules de filtrage,
     * DEUX portent une permission. Le portage ne le referme pas — §7 du plan.
     */
    /*
     * Cle de plateforme — P1. `role:1` + `perm:can_manage_platform_key`, reprise
     * telle quelle du legacy : `platform_keys.php:11` admet les TROIS roles et
     * c'est `checkPermission` qui decide. Son en-tete annonce pourtant « acces :
     * superadmin uniquement » — cinquieme occurrence du motif E-36, et la plus
     * mal placee, puisqu'elle decrit la page qui manipule la cle de la flotte.
     *
     * CONSEQUENCE POUR TOUTE MESURE : il n'existe AUCUN chemin de refus par le
     * ROLE sur cette page. Role 1 comme role 2 sont refuses par la PERMISSION.
     * Une suite qui croirait mesurer « le role 1 est refuse » mesurerait la
     * permission — une mesure plus large que la propriete.
     *
     * Et le chemin NOMINAL n'est pas exercable sur ce banc : un seul compte
     * porte `can_manage_platform_key` (`superadmin`, inutilisable), et
     * `rw-test-super` atteint la page par le contournement du role 3, donc SANS
     * la permission. Dit plutot que corrige en deplacant un droit.
     */
    Route::get('/cle-plateforme', ClePlateformeController::class)
        ->middleware(['role:1', 'perm:can_manage_platform_key'])->name('cle-plateforme');

    /*
     * Pare-feu iptables — I1, DECLARATION POSEE POUR LA SESSION 5.
     *
     * `role:1` + la permission, repris tel quel du legacy — dont l'en-tete
     * annonce « superadmin uniquement » DEUX fois alors que sa garde admet
     * ROLE_USER (motif E-36, quatrieme occurrence).
     *
     * I1 est une LECTURE : le controleur n'ouvre aucune session SSH et la page
     * n'offre aucun geste qui ecrit. Les sous-lots d'ecriture I2 a I5 s'y
     * brancheront.
     *
     * ⚠ L'ENTREE DE MENU NE BASCULE PAS, ET C'EST DELIBERE. `Navigation.php`
     * garde `'legacy' => '/iptables/'` jusqu'a I5 : la page portee ne rend que
     * la consultation, et basculer maintenant RETIRERAIT l'acces aux quatre
     * capacites d'ecriture. *Une entree qui bascule trop tot ne degrade pas
     * l'interface, elle retire une capacite.* La page porte un encart nommant
     * ce qui reste sur l'ancien portail, avec le lien marque.
     */
    Route::get('/pare-feu', PareFeuController::class)
        ->middleware(['role:1', 'perm:can_manage_iptables'])->name('pare-feu');

    /*
     * I2 — LA COPIE EN BASE. Declarations posees pour la session 5.
     *
     * MEME GARDE QUE LA PAGE, mot pour mot. Ce n'est pas une commodite : ces
     * deux routes ne passent PAS par la passerelle, elles sont servies par le
     * portage lui-meme. `RoutesBackend` ne les voit donc jamais, et la seule
     * garde qui existe est celle qui est ecrite ici. Une garde presente sur la
     * page et absente d'une route que la page appelle est le motif que ce
     * chantier a paye trois fois — la garde vit DANS LA ROUTE, et nulle part
     * ailleurs.
     *
     * `POST` pour les DEUX, y compris la lecture. `charger` prend un
     * `machine_id` dans le CORPS et le controleur le resout en machine avant de
     * decider : le verbe suit ce que fait le controleur, pas la semantique
     * theorique du geste. Un `GET` porterait l'identifiant dans l'URL, donc
     * dans les journaux d'acces et l'historique du navigateur.
     *
     * La falsification de requete est deja geree : `PreventRequestForgery` est
     * dans le groupe `web`. On n'ajoute rien par-dessus — le faire a ete tente
     * ailleurs et double le controle sans le renforcer.
     */
    Route::post('/pare-feu/copie', [PareFeuController::class, 'charger'])
        ->middleware(['role:1', 'perm:can_manage_iptables'])->name('pare-feu.copie');

    Route::post('/pare-feu/copie/enregistrer', [PareFeuController::class, 'enregistrer'])
        ->middleware(['role:1', 'perm:can_manage_iptables'])->name('pare-feu.copie.enregistrer');

    /*
     * I3 — L'HISTORIQUE. Declaration qui ATTENDAIT depuis quatre jours (E-244).
     *
     * `PareFeuController::historique()` existait et `pare-feu.js:548` l'appelait
     * deja : sans cette ligne, l'appel rendait 404 et la methode etait du code
     * mort. Le sous-lot s'etait declare porte, et la suite restait verte parce
     * qu'elle ne descend pas jusqu'a l'historique.
     *
     * *« La garde est sur la page, pas sur la requete », retourne : ici c'est la
     * CAPACITE qui etait sur la page et pas sur la requete.*
     *
     * MEME GARDE QUE LA PAGE ET QUE SES DEUX VOISINES, et ce n'est pas une
     * commodite. J'ai verifie la methode avant de poser plutot que de recopier
     * le texte qu'on me transmettait :
     *
     *   - `machineDeLaRequete()` lit `machine_id` dans le CORPS, puis resout par
     *     `machineAccessible($idCompte, $role, $id)`. **Le controle porte sur
     *     l'objet RESOLU**, et rend 403 si la machine n'est pas accessible — pas
     *     sur le parametre recu ;
     *   - la methode ne joint AUCUNE machine et n'appelle pas la passerelle :
     *     elle lit `iptables_rules_history` en base. `POST` malgre la lecture,
     *     pour la meme raison que `/pare-feu/copie` : l'identifiant voyage dans
     *     le corps, pas dans l'URL ni dans les journaux d'acces.
     *
     * `role:1` + la permission : identique a la page, donc aucun compte legitime
     * ne gagne ni ne perd un acces par cette ligne.
     */
    Route::post('/pare-feu/historique', [PareFeuController::class, 'historique'])
        ->middleware(['role:1', 'perm:can_manage_iptables'])->name('pare-feu.historique');

    Route::get('/fail2ban', Fail2banController::class)
        ->middleware(['role:1', 'perm:can_manage_fail2ban'])->name('fail2ban');

    /*
     * Ce que la passerelle autorise — remplace `legacy/api/docs.php`.
     *
     * `role:3` SEUL, et c'est la garde du CODE legacy, pas celle de son
     * commentaire : `api/docs.php:4` annonce « admins et superadmins » alors que
     * sa ligne 9 fait `checkAuth([ROLE_SUPERADMIN])` — E-231, un commentaire qui
     * promet un acces plus large que le code. On porte le code.
     *
     * Pas de permission : le legacy n'en exige aucune sur cette page, et en
     * inventer une resserrerait sans mandat.
     *
     * La page ne sert AUCUNE description figee. Elle derive `RoutesBackend` a
     * chaque affichage — la description OpenAPI du legacy etait un fichier
     * statique date du 2026-08-20 dont 7 chemins n'existaient pas.
     */
    Route::get('/autorisations-passerelle', AutorisationsPasserelleController::class)
        ->middleware(['role:3'])->name('autorisations-passerelle');

    /*
     * F6 : la PORTEE des deux gestes de parc, lue en base.
     *
     * `ban_all_servers` et `install_all` ne prennent aucun `machine_id` : leurs
     * cibles sont choisies par un `LEFT JOIN`/`INNER JOIN` du backend, et
     * toutes jointes. Cette route rend ce que ces deux requetes retiennent, en
     * les rejouant sur la MEME base — elle ne recalcule pas la regle, elle la
     * remonte de la ou elle s'applique.
     *
     * Elle existe parce qu'un releve ECRIT le cache qui decide de cette portee :
     * sans relecture, l'ecran garderait celle du chargement. Trois `SELECT`,
     * aucune machine jointe.
     *
     * Gardes IDENTIQUES a celles de la page : une capacite ne se garde pas moins
     * parce qu'elle ne fait que renseigner.
     */
    Route::get('/fail2ban/portee', [Fail2banController::class, 'portee'])
        ->middleware(['role:1', 'perm:can_manage_fail2ban'])->name('fail2ban.portee');

    Route::get('/services', ServicesController::class)
        ->middleware(['role:1', 'perm:can_manage_services'])->name('services');

    Route::get('/bashrc', BashrcController::class)
        ->middleware(['role:2', 'perm:can_manage_bashrc'])->name('bashrc');

    Route::get('/acces-sftp', AccesSftpController::class)
        ->middleware(['role:3'])->name('acces-sftp');

    Route::get('/politiques', PolitiquesController::class)
        ->middleware(['role:3'])->name('politiques');

    Route::get('/comptes-distants', ComptesDistantsController::class)
        ->middleware(['role:2', 'perm:can_manage_remote_users'])->name('comptes-distants');
    Route::post('/comptes-distants/{machine}/classer', [ComptesDistantsController::class, 'classer'])
        ->whereNumber('machine')
        ->middleware(['role:2', 'perm:can_manage_remote_users'])->name('comptes-distants.classer');
    Route::post('/comptes-distants/{machine}/classer-en-attente', [ComptesDistantsController::class, 'classerLesEnAttente'])
        ->whereNumber('machine')
        ->middleware(['role:2', 'perm:can_manage_remote_users'])->name('comptes-distants.classer-en-attente');
    Route::get('/comptes-distants/{machine}/cles/{username}', [ComptesDistantsController::class, 'cles'])
        ->whereNumber('machine')->where('username', '[A-Za-z0-9._-]{1,64}')
        ->middleware(['role:2', 'perm:can_manage_remote_users'])->name('comptes-distants.cles');

    Route::post('/permissions/{id}', [PermissionsController::class, 'definir'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('permissions.definir');
    Route::post('/permissions/{id}/acces', [PermissionsController::class, 'acces'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('permissions.acces');

    /*
     * Permissions TEMPORAIRES — sous-lot D5b.
     *
     * `manage_permissions.php:184-267` porte un formulaire d'octroi, une liste
     * et une revocation ; D5 a porte le fichier en laissant cette moitie dehors
     * (E-134). L'octroi passe par la PASSERELLE parce qu'il notifie le compte
     * concerne ; la revocation s'ecrit ici, n'ayant aucun effet de bord.
     */
    Route::post('/permissions/temporaires/{id}/revoquer', [PermissionsController::class, 'revoquerTemporaire'])
        ->whereNumber('id')
        ->middleware(['role:3', 'perm:can_admin_portal'])->name('permissions.temp.revoquer');

    Route::get('/journal-audit', JournalAuditController::class)
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('journal-audit');
    Route::get('/journal-audit/export', [JournalAuditController::class, 'csv'])
        ->middleware(['role:2', 'perm:can_admin_portal'])
        ->name('journal-audit.csv');
    Route::get('/journal-audit/verifier', [JournalAuditController::class, 'verifier'])
        ->middleware(['role:3', 'perm:can_admin_portal'])
        ->name('journal-audit.verifier');
    Route::post('/journal-audit/sceller', [JournalAuditController::class, 'sceller'])
        ->middleware(['role:3', 'perm:can_admin_portal'])
        ->name('journal-audit.sceller');

    /*
     * Passerelle vers le backend Python. Elle reste dans le groupe `web` : la
     * session ET le jeton CSRF s'appliquent, ce qui est le point de la
     * manoeuvre — c'est l'endpoint le plus puissant du portail, il transmet
     * toutes les routes du backend.
     *
     * `where` autorise le slash dans le parametre, sinon `/fail2ban/status`
     * ne serait pas capture.
     */
    Route::any('/api/gateway/{chemin?}', PasserelleController::class)
        ->where('chemin', '.*')
        ->name('passerelle');
});

/*
 * Compatibilite avec les chemins du legacy, pour que le MEME test de
 * caracterisation puisse viser les deux cibles sans etre reecrit. Un test qui
 * doit changer d'adresse selon la cible ne compare plus rien.
 */
Route::get('/auth/login.php', fn () => redirect()->route('connexion'));
Route::get('/auth/verify_2fa.php', fn () => redirect()->route('second-facteur'));
Route::get('/index.php', fn () => redirect()->route('accueil'));
Route::get('/profile.php', fn () => redirect()->route('profil'));
Route::get('/terms.php', fn () => redirect()->route('cgu'));
Route::get('/adm/admin_page.php', fn () => redirect()->route('accueil'));
Route::get('/commandlog/', fn () => redirect()->route('journal-commandes'));
Route::get('/approvals/', fn () => redirect()->route('approbations'));
Route::get('/groups/', fn () => redirect()->route('groupes'));
Route::get('/ssh-audit/', fn () => redirect()->route('audit-ssh'));
Route::get('/documentation.php', fn () => redirect()->route('documentation'));
Route::get('/drift/', fn () => redirect()->route('derive-config'));
Route::get('/backups/', fn () => redirect()->route('sauvegardes'));
Route::get('/tasks/', fn () => redirect()->route('taches'));
Route::get('/search/', fn () => redirect()->route('recherche'));

/*
 * ══ LE WEBHOOK CHATOPS : LE SEUL CHEMIN PUBLIC QUI ECRIT ════════════════════
 *
 * Hors du groupe authentifie, et exclu du controle de falsification
 * (`bootstrap/app.php`) : Slack ne peut presenter ni session ni jeton. Ce n'est
 * pas une porte ouverte pour autant — l'authentification reelle est faite par
 * le backend, sur la SIGNATURE Slack ou un jeton partage, et il refuse d'emblee
 * si ChatOps est desactive.
 *
 * L'adresse DIFFERE de celle du legacy (`/chatops/webhook.php`) : activer
 * ChatOps apres la bascule demande de la reporter dans Slack. La page le dit.
 */
Route::post('/chatops/webhook', [ChatopsController::class, 'webhook'])
    ->name('chatops.webhook');
