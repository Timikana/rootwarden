<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * La cle de plateforme — sous-lot P1 : la page, ses gardes, ses compteurs.
 *
 * Porte `legacy/adm/platform_keys.php`. P1 ne fait AUCUNE ecriture et n'ouvre
 * aucune session SSH : il lit la base et rend la cle PUBLIQUE. Les lectures
 * distantes sont P2, la migration mot de passe -> cle est P3, la rotation P4.
 *
 * ══ L'EN-TETE DU LEGACY MENT, CINQUIEME OCCURRENCE DU MOTIF E-36 ═════════
 *
 * `platform_keys.php:4` annonce « Acces : superadmin uniquement ». Huit lignes
 * plus bas, `checkAuth([ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN])` admet les
 * TROIS roles, et c'est `checkPermission('can_manage_platform_key')` qui
 * decide. La garde reelle est donc portee telle quelle : `role:1` +
 * `perm:can_manage_platform_key`.
 *
 * Consequence pour toute mesure : **il n'existe aucun chemin de refus par le
 * ROLE sur cette page**. Un role 1 comme un role 2 sont refuses par la
 * PERMISSION. Une suite qui croirait mesurer « le role 1 est refuse »
 * mesurerait la permission — une mesure plus large que la propriete.
 *
 * ══ UNE SEULE CLE, TOUT LE PARC, LES DEUX COMPTES ════════════════════════
 *
 * `ssh_key_manager.py:30` : la paire vit dans UN fichier
 * (`/app/platform_ssh/rootwarden_ed25519`). La meme cle publique sert le compte
 * nominal ET le compte de service `rootwarden`. Il n'existe donc ni « une cle
 * par machine » ni « une cle par compte » : il en existe UNE.
 */
class ClePlateforme
{
    /**
     * Le parc, avec ce que la page a besoin de dire de chaque machine.
     *
     * Aucun filtre de cycle de vie : le legacy n'en pose pas
     * (`platform_keys.php:18`), et la page decrit l'etat de la cle sur toutes
     * les machines connues. Le releve reste fidele.
     */
    public function machines(): array
    {
        return DB::select(
            'SELECT id, name, ip, port, user, online_status, environment, '
            . 'platform_key_deployed, platform_key_deployed_at, ssh_password_required, '
            . 'service_account_deployed, service_account_deployed_at, '
            // ── LES DEUX COLONNES QUE LE LEGACY NE REGARDE PAS ────────────
            //
            // Il compte `ssh_password_required`, un DRAPEAU. On lit aussi le
            // FAIT — les deux colonnes de mot de passe sont-elles vides ? Voir
            // `compteurs()` : les deux ont divergé, et c'est mesurable.
            //
            // On ne rend JAMAIS la valeur, seulement sa presence : ces colonnes
            // sont chiffrees et n'ont aucune raison de traverser un gabarit.
            //
            // `IS NOT NULL AND <> ''` ET NON LE SEUL `<> ''`. Une comparaison
            // avec une colonne NULL rend NULL, pas 0. Aucune machine n'a de
            // colonne nulle aujourd'hui — mesure — et PHP traite NULL comme
            // faux, donc le resultat serait juste. Mais ce booleen peut un jour
            // partir en JSON vers le navigateur, ou `null` et `0` ne sont pas la
            // meme valeur. Motif deja employe par `Supervision.php:272` pour
            // `tls_psk_value` : on s'y aligne plutot que d'en inventer un second.
            . "(password IS NOT NULL AND password <> '') AS a_mot_de_passe, "
            . "(root_password IS NOT NULL AND root_password <> '') AS a_mot_de_passe_root "
            . 'FROM machines ORDER BY name'
        );
    }

    /**
     * Les compteurs de la page — et ils comptent le FAIT, pas le DRAPEAU.
     *
     * ══ LE DEFAUT MESURE LE 2026-08-27 ═══════════════════════════════════
     *
     * Le legacy compte « Password supprime » par `! ssh_password_required`
     * (`platform_keys.php:24`). Or ce drapeau n'est ecrit que par
     * `remove_ssh_password` et `reenter_ssh_password` : **la page Serveurs, seul
     * chemin qui REMPLIT `root_password` (`manage_servers.php:136,182`), ne le
     * touche pas.** Restaurer un mot de passe la-bas laisse donc cette page
     * annoncer qu'il est supprime.
     *
     * Mesure du jour, `srv-zabbix` : `ssh_password_required = 0` — donc compte
     * comme « supprime » — alors que `password` ET `root_password` sont TOUS
     * DEUX PRESENTS. Le compteur du legacy est faux d'une machine sur trois.
     *
     * On compte donc les colonnes, et l'ecran DIT quand le drapeau les
     * contredit : les deux portails afficheront des nombres differents, et un
     * exploitant qui les compare doit savoir pourquoi.
     *
     * ══ CE QUE « SANS RETOUR » VEUT DIRE, ET IL SE CALCULE ═══════════════
     *
     * Une machine dont la cle est deployee et dont RootWarden ne detient plus
     * AUCUN mot de passe n'a plus qu'une voie d'acces : cette cle. La rotation
     * (P4) detruit la cle privee sans copie — pour ces machines-la, elle est
     * sans retour. Le nombre est calcule, jamais suppose : aujourd'hui il vaut
     * zero, et il ne doit pas etre ecrit en dur pour autant.
     */
    public function compteurs(array $machines): array
    {
        $vrai = fn ($v) => (bool) ((int) $v);
        $total = count($machines);

        $cle = array_filter($machines, fn ($m) => $vrai($m->platform_key_deployed));
        $compteService = array_filter($machines, fn ($m) => $vrai($m->service_account_deployed));

        // LE FAIT : plus aucun mot de passe connu de RootWarden, ni l'un ni l'autre.
        $sansMotDePasse = array_filter($machines, fn ($m) => ! $vrai($m->a_mot_de_passe)
            && ! $vrai($m->a_mot_de_passe_root));

        // LE DRAPEAU, garde pour pouvoir dire qu'il diverge.
        $drapeauSupprime = array_filter($machines, fn ($m) => ! $vrai($m->ssh_password_required));

        // SANS RETOUR : la cle est le seul acces restant.
        $sansRetour = array_filter($machines, fn ($m) => $vrai($m->platform_key_deployed)
            && ! $vrai($m->a_mot_de_passe) && ! $vrai($m->a_mot_de_passe_root));

        $divergentes = array_filter($machines, fn ($m) => ! $vrai($m->ssh_password_required)
            && ($vrai($m->a_mot_de_passe) || $vrai($m->a_mot_de_passe_root)));

        return [
            'total'            => $total,
            'cle'              => count($cle),
            'compte_service'   => count($compteService),
            'en_attente'       => $total - count($cle),
            'sans_mot_de_passe' => count($sansMotDePasse),
            'drapeau_supprime' => count($drapeauSupprime),
            'sans_retour'      => count($sansRetour),
            'divergentes'      => count($divergentes),
            'noms_divergentes' => array_values(array_map(fn ($m) => $m->name, $divergentes)),
            'noms_sans_retour' => array_values(array_map(fn ($m) => $m->name, $sansRetour)),
            // La barre de progression : deux segments, en POURCENTAGE d'un total
            // qui peut valoir zero — un parc vide ne divise pas.
            'pct_cle'          => $total > 0 ? (int) round(count($cle) / $total * 100) : 0,
            'pct_sans_mdp'     => $total > 0 ? (int) round(count($sansMotDePasse) / $total * 100) : 0,
        ];
    }

    /**
     * L'etat d'authentification d'une machine, en TROIS valeurs.
     *
     * Le legacy rend trois pastilles (`keypair`, `keypair + pwd`, `password`)
     * calculees sur le drapeau. Ici elles se calculent sur le FAIT, pour la
     * meme raison que les compteurs.
     */
    public function etatAuth(object $m): string
    {
        $cle = (bool) ((int) $m->platform_key_deployed);
        $mdp = ((int) $m->a_mot_de_passe) || ((int) $m->a_mot_de_passe_root);

        if ($cle && ! $mdp) {
            return 'cle_seule';
        }

        return $cle ? 'cle_et_mot_de_passe' : 'mot_de_passe_seul';
    }

    /**
     * ══ P3 — LES PORTEES DES GESTES QUI ECRIVENT ═════════════════════════
     *
     * Chaque geste de masse porte sa PROPRE liste, et le nombre annonce sur le
     * bouton est celui de CETTE liste. Le legacy en avait deux, et elles ne
     * concordaient pas.
     *
     * Mesure du 2026-08-27, `platform_keys.php:61` : le bouton d'effacement de
     * masse affiche `$nbDeployed - $nbPasswordRemoved`, ou `$nbPasswordRemoved`
     * compte `! ssh_password_required` sur TOUT le parc — machines sans cle
     * incluses. La liste sur laquelle il agit (`:329`) exige en plus
     * `platform_key_deployed`. Les deux predicats different : une machine qui
     * n'a jamais commence la migration DIMINUE le nombre affiche sans sortir de
     * la liste. Le compte annonce et le compte agi peuvent donc differer.
     *
     * Ici une portee est un tableau `['ids' => int[], 'noms' => string[],
     * 'sensibles' => string[]]`. Le nombre est `count($p['ids'])`, point.
     */
    private function portee(array $machines, callable $predicat): array
    {
        $retenues = array_values(array_filter($machines, $predicat));

        return [
            'ids'       => array_map(fn ($m) => (int) $m->id, $retenues),
            'noms'      => array_map(fn ($m) => (string) $m->name, $retenues),
            // Les machines de PRODUCTION de la portee, nommees a part : le
            // panneau de decision doit pouvoir les dire, et non les noyer dans
            // un nombre. Le legacy ne distingue rien.
            //
            // ══ CE N'EST PAS UNE GARDE, ET IL FAUT LE DIRE ════════════════
            //
            // Aucun geste de parc ne viserait `srv-zabbix` aujourd'hui — la
            // machine a sa cle, son compte de service, et son drapeau la sort
            // de la portee d'effacement. Mais cela tient a L'ETAT DU PARC, pas
            // a une regle : il suffit qu'une colonne change pour que la
            // production entre dans une portee. **Une propriete qui tient par
            // l'etat du parc n'est pas une propriete.**
            //
            // Ce qui est porte ici est donc un AVERTISSEMENT nomme, pas un
            // refus. Refuser retirerait a un administrateur une capacite qu'il
            // a aujourd'hui : c'est l'arbitrage de l'exploitant, et il lui est
            // remonte plutot que tranche ici.
            'sensibles' => array_values(array_map(
                fn ($m) => (string) $m->name,
                array_filter($retenues, fn ($m) => $this->estSensible($m))
            )),
        ];
    }

    /** Les machines sans cle de plateforme — la portee de « deployer ». */
    public function porteeDeploiement(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ! ((int) $m->platform_key_deployed));
    }

    /**
     * Les machines a cle dont le compte de service manque.
     *
     * ══ CE GESTE EST UNE REPRISE, PAS UNE ETAPE SUIVANTE ═════════════════
     *
     * `deploy_platform_key` cree DEJA le compte `rootwarden` avec
     * `NOPASSWD: ALL`, dans la meme requete (`ssh.py:786-861`, « dans la
     * foulee »), et pose `service_account_deployed` lui-meme (`:855`). Une
     * machine n'apparait donc ici que si cette tentative incluse a ECHOUE —
     * `ssh.py:862` avale l'exception en `logger.warning` et rend « Keypair
     * deployee OK (service account echoue - deployer manuellement) ».
     *
     * Le legacy presente les deux boutons cote a cote, sans dire que le second
     * ne sert qu'au rattrapage du premier. L'ecran le dit.
     */
    public function porteeCompteService(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ((int) $m->platform_key_deployed)
            && ! ((int) $m->service_account_deployed));
    }

    /**
     * Les machines dont RootWarden peut effacer sa copie des mots de passe.
     *
     * ══ LA PRECONDITION DU BACKEND, QUE LE LEGACY N'APPLIQUE PAS ═════════
     *
     * `remove_ssh_password` REFUSE (400, « Service account non deploye ») si
     * `service_account_deployed` est faux (`ssh.py:1235-1237`). L'INTENTION est
     * juste : sans le compte de service, effacer les mots de passe retire a
     * RootWarden tout moyen de passer root — `execute_as_root` ne court-circuite
     * le mot de passe que sur ce compte (`ssh_utils.py:537`).
     *
     * MAIS SON ENTREE PEUT ETRE PERIMEE, et c'est un DRAPEAU de plus qui ne dit
     * pas le fait. Sur une revocation partielle (`exit 2` : compte supprime,
     * fichier sudoers subsistant), `service_account_deployed` reste
     * DELIBEREMENT a 1 pour garder le rejeu ouvert — aucune ecriture en base
     * dans cette branche. La precondition dit donc « le compte existe » alors
     * qu'il n'existe plus, et cette portee inclurait la machine.
     *
     * On la garde telle quelle, et pour DEUX raisons dont la seconde est la
     * plus forte :
     *
     * 1. c'est la MEME condition que celle du backend. Proposer une portee plus
     *    etroite que ce que la route accepte ferait diverger deux regles au lieu
     *    d'une — un drapeau de moins vaut mieux qu'une regle en double ;
     *
     * 2. UNE PORTEE PLUS ETROITE MASQUERAIT LE CORRECTIF AMONT. Le jour ou le
     *    backend posera `service_account_deployed` a 0 sur la revocation
     *    partielle, il refusera de lui-meme et **cette portee se resserrera
     *    seule** : une regle, une source, et la correction devient visible a
     *    l'ecran sans qu'on touche a rien ici. Une condition plus stricte ecrite
     *    en dur rendrait ce correctif INVISIBLE — l'ecran offrirait deja moins,
     *    donc rien ne changerait, et personne ne saurait si la correction a pris.
     *
     * LE CRITERE, pour la fois suivante : resserrer pour coller a un refus que
     * le backend applique DEJA est juste — on annonce plus tot. Resserrer EN
     * DESSOUS de ce que le backend accepte cree une seconde regle. La question
     * n'est pas « est-ce plus prudent », c'est « mon resserrement DECOULE-t-il
     * d'une regle existante, ou en CREE-t-il une ? ».
     *
     * Ce qui manque est un etat nomme cote backend, demande et non contourne
     * ici — le distinguer par le TEXTE du message serait une coincidence de
     * redaction, pas une mesure.
     *
     * Le bouton PAR LIGNE du legacy la respecte (`:203` teste `$saDeployed`).
     * **Le bouton de MASSE ne la teste pas** (`:329` : `platform_key_deployed`
     * et `ssh_password_required` seulement). Il propose donc des machines que
     * le backend va refuser — et la boucle qui les envoie compte les reussites
     * sans jamais nommer les refus (`:333-340` : `if (d.success) ok++`, et un
     * `catch` vide). L'exploitant lit « 3/7 » sans savoir lesquelles, ni
     * pourquoi.
     *
     * La portee porte donc la precondition, et `porteeEffacementRefusees()`
     * nomme ce qui en est ecarte : une portee qui retrecit en silence se lit
     * comme une portee complete.
     */
    public function porteeEffacement(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ((int) $m->platform_key_deployed)
            && ((int) $m->service_account_deployed)
            && (((int) $m->a_mot_de_passe) || ((int) $m->a_mot_de_passe_root)));
    }

    /**
     * Les machines qui portent le compte de service — la portee de sa REPRISE.
     *
     * ══ POURQUOI CE GESTE EXISTE ICI ALORS QUE LE LEGACY NE L'OFFRE PAS ══
     *
     * `revoke_service_account` existe dans le backend depuis le correctif
     * A04-INSEC-N5 et **n'a aucun appelant** : ni le legacy ni le portage ne
     * l'atteignaient. Or P3 rend l'OCTROI de `NOPASSWD: ALL` disponible en un
     * clic. Livrer l'octroi sans la reprise, c'est livrer une porte sans
     * poignee interieure. Ce n'est donc pas une idee ajoutee au portage : c'est
     * la contrepartie de ce que P3 expedie.
     *
     * ══ DEUX BORNES MESUREES, ET LA SECONDE EST UN DEFAUT DU BACKEND ═════
     *
     * 1. LA ROUTE EST RESERVEE AU ROLE 3 (`ssh.py:896`, `@require_role(3)`),
     *    alors que cette page se garde par `perm:can_manage_platform_key` a
     *    partir du role 1. Un compte role 1 ou 2 porteur de la permission peut
     *    donc ACCORDER `NOPASSWD: ALL` et **ne peut pas le reprendre**. Le
     *    bouton n'est rendu qu'au role 3 — sans quoi il promettrait un geste
     *    qui finirait en 403. L'asymetrie elle-meme est DITE a l'ecran : elle
     *    n'est pas de mon fait et je ne la corrige pas en silence.
     *
     * 2. E-218, ET LA RESERVE EST LEVEE POUR LA REVOCATION, PAS POUR LA
     *    REPRISE. Le backend est corrige (`599d1a3`) : les deux routes passent
     *    desormais `service_account=` ET selectionnent la colonne qui le porte
     *    — sans quoi le correctif aurait ete prouvablement inerte, le drapeau
     *    valant toujours `False`. Le retrait du sudoers passe en dernier, et le
     *    verdict controle les DEUX effets (compte absent ET fichier absent).
     *
     *    CE QUI RESTE VRAI, ET CE QUI NE L'EST PLUS.
     *
     *    Pour la REVOCATION : la reserve est levee. La route se connecte par le
     *    compte de service quand il est deploye, donc `execute_as_root`
     *    court-circuite avec `sudo sh -c` et n'a plus besoin d'un mot de passe.
     *    Il subsiste un cas RESIDUEL : `connect_ssh` retombe sur le compte
     *    nominal si la connexion au compte de service echoue
     *    (`ssh_utils.py:250-264`) — cas connu du depot, un `sshd_config` durci
     *    par `AllowUsers`. Le repli rencontre alors `root_password = ''`.
     *
     *    Pour la REPRISE du compte de service : la reserve TIENT, et le
     *    correctif ne pouvait pas la lever. Apres une revocation,
     *    `service_account_deployed` vaut 0 : la route ne peut donc PAS se
     *    connecter par un compte qui n'existe plus, retombe sur le compte
     *    nominal, et sur une machine migree `root_password` est vide. L'aller-
     *    retour « supprimer puis redeployer » n'est pas symetrique — et c'est le
     *    bouton de revocation qui rend cet etat atteignable, puisque `ssh.py:986`
     *    est la SEULE ecriture qui remette ce drapeau a 0.
     *
     *    LA CAUSE PROFONDE RESTE CELLE-CI, et elle ne depend d'aucun parametre :
     *    `remove_ssh_password` REFUSE de vider les mots de passe tant que
     *    `service_account_deployed` est faux (`ssh.py:1235`). **Le seul etat ou
     *    `root_password` est vide est donc exactement l'etat ou le compte de
     *    service existe** — ou a existe. Ce n'est pas une conjonction
     *    malheureuse, c'est une implication.
     *
     *    DANS LES DEUX CAS, ECHEC FERME ET VISIBLE : la commande part en un
     *    seul `execute_as_root` avec `set -e`, aucun etat partiel dangereux,
     *    aucune ecriture en base, et l'ecran l'annonce.
     *
     * 3. LE GESTE RETIRE UNE PORTE SUR TROIS, ET SON NOM NE DOIT PAS LE TAIRE.
     *    `deploy_platform_key` ecrit la MEME cle publique dans
     *    `~/.ssh/authorized_keys` du compte nominal (`:745`) ET dans
     *    `/root/.ssh/authorized_keys` (`:755`) ; le compte de service en recoit
     *    une troisieme copie (`:808`, `:1081`). La revocation ne supprime que
     *    le compte `rootwarden` et son sudoers : **la cle reste autorisee sur
     *    root et sur le compte nominal.**
     *
     *    Sa docstring nomme pourtant « compromission suspectee de la cle » — ce
     *    que le geste ne traite pas. Le libelle porte donc ce que le geste FAIT
     *    (« supprimer le compte d'administration ») et non la capacite qu'il
     *    n'a pas, et le panneau dit ce qui reste en place. Le seul remede a une
     *    cle compromise est la rotation, qui n'est pas portee.
     */
    public function porteeRevocation(array $machines): array
    {
        return $this->portee($machines, fn ($m) => (int) $m->service_account_deployed);
    }

    /**
     * Ce que le legacy aurait propose et que le backend refuserait.
     *
     * La cle est deployee, un mot de passe subsiste, mais le compte de service
     * manque. Ces machines ne sont pas « deja faites » : elles sont BLOQUEES,
     * et ce qui les debloque est le geste du compte de service.
     */
    public function porteeEffacementRefusees(array $machines): array
    {
        return $this->portee($machines, fn ($m) => ((int) $m->platform_key_deployed)
            && ! ((int) $m->service_account_deployed)
            && (((int) $m->a_mot_de_passe) || ((int) $m->a_mot_de_passe_root)));
    }

    /** `PROD` ou `CRITIQUE`, et une valeur inconnue compte comme sensible. */
    public function estSensible(object $m): bool
    {
        $env = strtoupper(trim((string) ($m->environment ?? '')));

        return $env === 'PROD' || $env === 'OTHER' || $env === '';
    }
}
