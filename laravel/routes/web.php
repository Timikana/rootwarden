<?php

use App\Http\Controllers\ApprobationsController;
use App\Http\Controllers\ChatopsController;
use App\Http\Controllers\ClesSshController;
use App\Http\Controllers\ComparaisonCveController;
use App\Http\Controllers\ComptesController;
use App\Http\Controllers\DeriveConfigController;
use App\Http\Controllers\DockerController;
use App\Http\Controllers\ExportConformiteController;
use App\Http\Controllers\ExportConformitePdfController;
use App\Http\Controllers\ExportCveController;
use App\Http\Controllers\JournalAuditController;
use App\Http\Controllers\JournalCommandesController;
use App\Http\Controllers\MaintenanceController;
use App\Http\Controllers\MisesAJourController;
use App\Http\Controllers\NotificationsController;
use App\Http\Controllers\PasserelleController;
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
Route::middleware('session.authentifiee')->group(function () {
    Route::get('/cgu', [PortailController::class, 'cgu'])->name('cgu');
    Route::post('/cgu', [PortailController::class, 'accepterCgu'])->name('cgu.accepter');
    Route::get('/accueil', [PortailController::class, 'accueil'])->name('accueil');
    Route::get('/profil', [PortailController::class, 'profil'])->name('profil');
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
    Route::post('/comptes', [ComptesController::class, 'creer'])
        ->middleware(['role:2', 'perm:can_admin_portal'])->name('comptes.creer');
    Route::post('/comptes/{id}/mot-de-passe', [ComptesController::class, 'motDePasse'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('comptes.mot-de-passe');
    Route::post('/comptes/{id}/cle-ssh', [ComptesController::class, 'cleSsh'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('comptes.cle-ssh');
    Route::post('/comptes/{id}/deverrouiller', [ComptesController::class, 'deverrouiller'])
        ->whereNumber('id')->middleware(['role:2', 'perm:can_admin_portal'])->name('comptes.deverrouiller');
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

    Route::post('/permissions/{id}', [PermissionsController::class, 'definir'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('permissions.definir');
    Route::post('/permissions/{id}/acces', [PermissionsController::class, 'acces'])
        ->whereNumber('id')->middleware(['role:3', 'perm:can_admin_portal'])->name('permissions.acces');

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
