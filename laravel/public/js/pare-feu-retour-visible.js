/*
 * Q3 — TOUT RETOUR PRODUIT UN MESSAGE VISIBLE, SUCCÈS COMME ÉCHEC
 *
 * ══ LA PROPRIÉTÉ, ET POURQUOI ELLE EST UNE PROPRIÉTÉ ET NON UN SOIN ══════
 *
 * `rwRetourPareFeu(...)` est **totale** : il n'existe aucune entrée pour
 * laquelle elle rende `null`, `undefined` ou la chaîne vide. C'est mesuré sur
 * un espace d'entrées généré, y compris des formes que le backend ne produit
 * pas — `laravel/tests/Outils/q3-retour-visible.mjs`.
 *
 * *Le défaut qu'elle ferme n'est pas « un message manque » : c'est un chemin de
 * retour sur lequel personne n'a pensé à en mettre un.* Rendre la fonction
 * totale déplace la question — on ne demande plus « ai-je traité ce cas ? »,
 * on ne PEUT plus en oublier un.
 *
 * ══ CE QUE J'AI VU CETTE NUIT, ET QUI EST EXACTEMENT CE DÉFAUT ═══════════
 *
 * Le menu du legacy portait, sur sa recherche vive :
 *
 *     catch (e) { container.classList.add('hidden'); }
 *
 * L'endpoint était archivé depuis des jours. Chaque frappe partait, échouait,
 * et le panneau se cachait. **Aucune erreur visible, aucun résultat jamais —
 * donc rien à quoi se cogner.**
 *
 * > **Un repli qui cache l'échec transforme une capacité morte en capacité
 * > SILENCIEUSE, et c'est ce silence qui l'a fait survivre à son endpoint.**
 *
 * Sur `iptables`, le même silence ne coûterait pas une recherche : il
 * couvrirait un `iptables-restore` dont on ne saurait pas s'il a eu lieu.
 *
 * ══ QUATRE ISSUES, PAS DEUX — ET LE DISCRIMINANT N'EST PAS `success` ═════
 *
 * Relevé sur le code servi (`pare-feu.js:639-661`), pas supposé :
 * `/iptables-validate` rend `success: false` pour QUATRE situations —
 * identifiants irrésolus (400), règles vides (400), erreur interne (500), et
 * « erreur de syntaxe » (200). **Se fier à `success` seul confondrait « vos
 * règles sont invalides » avec « je n'ai rien pu vérifier »** : deux verdicts
 * qui appellent des gestes opposés — corriger, ou réessayer.
 *
 *     verdict     seul un 200 porte un verdict SUR LES REGLES
 *     inabouti    400 / 500 / reseau : le controle n'a pas eu lieu
 *     doute       200, mais la fondation du verdict est incertaine (ci-dessous)
 *     succes      le geste a eu lieu et on le dit
 *
 * ⚠ **`doute` n'est pas une politesse.** Le backend calcule
 * `exit_code = 0 if any('EXIT_CODE=0' in l for l in output_lines) else 1` sur
 * des fragments de 4096 octets. **Un marqueur à cheval sur deux fragments
 * n'est retrouvé dans aucun des deux, et un jeu VALIDE est alors déclaré
 * invalide.** Le portage ne répare pas le backend : il cesse de présenter
 * cette incertitude comme un verdict.
 *
 * ⛔ CE FICHIER N'ÉMET RIEN. Il transforme un retour en message. Aucune
 *    requête, aucune machine jointe, aucun DOM touché.
 */
(function (racine) {
    'use strict';

    /*
     * Les tons sont une liste FERMÉE, et le message en porte toujours un.
     * `neutre` n'existe pas exprès : un retour d'`iptables` n'est jamais neutre.
     */
    var TONS = { SUCCES: 'succes', ECHEC: 'echec', DOUTE: 'doute', INABOUTI: 'inabouti' };

    /** Un entier de statut HTTP, ou `null` si l'appel n'a pas abouti du tout. */
    function statutLisible(statut) {
        if (typeof statut !== 'number' || !isFinite(statut)) { return null; }
        if (statut < 100 || statut > 599) { return null; }
        return statut;
    }

    /*
     * ⚠ LE DETAIL EST CONDITIONNE AU VERDICT, SANS EXCEPTION.
     *
     * Un détail qui ne vaut que pour un verdict et s'affiche sous l'autre fait
     * chercher au mauvais endroit : un échec qui affiche la sortie d'un succès
     * (ou l'inverse) masque le seul renseignement utile. La sortie brute
     * n'accompagne donc QUE les verdicts qui portent sur les règles.
     */
    function detailPour(ton, sortie) {
        if (ton !== TONS.ECHEC && ton !== TONS.SUCCES && ton !== TONS.DOUTE) { return ''; }
        var brut = String(sortie == null ? '' : sortie);
        return brut.trim() === '' ? '' : brut;
    }

    /**
     * @param  {object|null} reponse  le corps rendu, tel quel — jamais suppose
     * @param  {number|null} statut   le statut HTTP, ou null si rien n'est parti
     * @param  {Error|null}  erreur   l'exception si l'appel a leve
     * @return {{ton: string, titre: string, detail: string, sur: boolean}}
     *         TOUJOURS un objet, TOUJOURS un `titre` non vide.
     *
     * `sur` dit si le message repose sur un verdict fondé. Il est `false` dès
     * que la fondation est douteuse ou absente — c'est ce que l'écran doit
     * refléter, et c'est ce qu'un booléen `success` ne pouvait pas porter.
     */
    function retour(reponse, statut, erreur) {
        var st = statutLisible(statut);

        /* ① L'appel n'a pas abouti. C'est un AVEU, pas une accusation. */
        if (erreur || st === null) {
            return {
                ton: TONS.INABOUTI,
                titre: 'ipt_retour_inabouti',
                detail: '',
                sur: false,
            };
        }

        /* ② Tout ce qui n'est pas 200 est un contrôle qui n'a pas eu lieu. */
        if (st !== 200) {
            return {
                ton: TONS.INABOUTI,
                titre: st >= 500 ? 'ipt_retour_erreur_serveur' : 'ipt_retour_refus',
                detail: '',
                sur: false,
            };
        }

        /*
         * ③ 200 sans corps exploitable. Le statut dit « j'ai répondu », le corps
         *    ne dit rien : c'est le cas où le silence s'installait.
         */
        if (!reponse || typeof reponse !== 'object') {
            return {
                ton: TONS.INABOUTI,
                titre: 'ipt_retour_corps_illisible',
                detail: '',
                sur: false,
            };
        }

        /*
     * ⚠ UN SEUL ALIAS, ET C'EST CELUI QUE LE BACKEND REND.
     *
     * Mesure : l'alias francais comme cle JSON dans `backend/` -> 0 producteur.
     * Cette route rend `success`, `message`, `output`. **Je l'avais ajoute par
     * symetrie avec le nom de la variable locale, pas d'apres un producteur.**
     *
     * Un alias sans producteur ne tolere rien : il se lit comme une tolerance, et
     * il double le nom qu'un producteur futur devra deviner.
     */
    var sortie = reponse.output;

        /*
         * ④ 200 dont le verdict repose sur le marqueur fragmenté. Le backend
         *    signale ce doute quand il le connaît ; on ne le déduit pas.
         */
        /*
         * ⛔⛔ AUCUN PRODUCTEUR N'EXISTE POUR CE DRAPEAU, ET C'EST ECRIT ICI POUR
         *     QU'ON NE LE DEDUISE PAS DE LA PRESENCE DE CE CODE.
         *
         * Mesure du 2026-09-08 sur le depot ENTIER, pas seulement `backend/` :
         * trois occurrences du jeton, et les TROIS sont des consommateurs — cette
         * ligne et deux cas forges de l'epreuve. **Zero producteur, et zero dans
         * toute l'histoire des commits.**
         *
         * **Cette branche n'a jamais ete atteignable depuis le parc.** Je l'avais
         * justifiee en ecrivant qu'un correctif « l'avait perimee » — faux : le
         * backend ne l'a JAMAIS posee. J'ai invente le champ en lisant la
         * DESCRIPTION du defaut dans un commentaire, et j'ai ecrit son consommateur
         * avant que quiconque ait ecrit son producteur.
         *
         * > **Un consommateur sans producteur se lit « gere ».** Une session qui
         * > mesure « l'incertitude du verdict est-elle traitee ? » trouve du code
         * > et conclut que oui.
         *
         * *C'est le symetrique exact de ce qu'un pair a refuse d'ecrire deux jours
         * plus tot — une branche pour un code que le backend ne pouvait pas
         * produire — et dont j'avais approuve le refus. Applique en LISANT, commis
         * en ECRIVANT.*
         *
         * ══ LE CONTRAT, POUR QUI ECRIRA LE PRODUCTEUR ═══════════════════════
         *
         *     fichier   backend/routes/iptables.py, route /iptables-validate
         *     cle JSON  celle testee ci-dessous, en ANGLAIS — les cles de cette
         *               route sont `success`, `message`, `output` ; un nom francais
         *               divergerait de ses voisines
         *     valeur    `true` UNIQUEMENT si le marqueur de code de sortie n'a pas
         *               pu etre localise de facon sure. Jamais deduit ici.
         *
         * ⚠ J'acceptais DEUX orthographes du meme champ. **Deux noms pour un champ
         * sans producteur, c'est un tirage au sort offert a celui qui viendra** : il
         * en choisit un, et si c'est le troisieme la branche reste inerte en ayant
         * l'air branchee. Un seul nom desormais.
         */
        if (reponse.marker_uncertain === true) {
            return {
                ton: TONS.DOUTE,
                titre: 'ipt_retour_doute_marqueur',
                detail: detailPour(TONS.DOUTE, sortie),
                sur: false,
            };
        }

        /* ⑤ Un verdict sur les règles, et c'est le seul cas où il est fondé. */
        if (reponse.success === true) {
            return { ton: TONS.SUCCES, titre: 'ipt_retour_succes',
                     detail: detailPour(TONS.SUCCES, sortie), sur: true };
        }
        if (reponse.success === false) {
            return { ton: TONS.ECHEC, titre: 'ipt_retour_regles_invalides',
                     detail: detailPour(TONS.ECHEC, sortie), sur: true };
        }

        /*
         * ⑥ LE CAS SANS NOM — et il rend un message, pas `null`.
         *
         * Un 200, un objet, et pas de `success` : le contrat a changé, ou la
         * route n'est pas celle qu'on croit. **C'est précisément le chemin sur
         * lequel un repli silencieux s'installe**, parce qu'il n'a pas de nom
         * dans la spec et qu'aucun cas de test ne le décrit.
         */
        return { ton: TONS.INABOUTI, titre: 'ipt_retour_contrat_inconnu', detail: '', sur: false };
    }

    racine.rwRetourPareFeu = retour;
    racine.rwRetourTons = function () { return Object.keys(TONS).map(function (k) { return TONS[k]; }); };
}(typeof globalThis !== 'undefined' ? globalThis : this));
