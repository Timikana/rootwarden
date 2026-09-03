/**
 * acces-sftp.js - Acces SFTP/SSH par compte distant, sous-lot D9b.
 *
 * MEME CORRECTION QU'EN D9a, ET POUR LA MEME RAISON : le legacy ouvrait
 * `removePolicy()` par `if (!confirm(...)) return;` et laissait `deployPolicy()`
 * partir au premier clic. Mesure de la suite sur le legacy : 1 requete au seul
 * clic sur « Deployer », aucun controle de confirmation.
 *
 * Ce qui part alors, releve au reseau :
 *   {"sftp_only":false,"chroot_dir":null,"allow_password_auth":true,
 *    "allow_tcp_forwarding":true,"allow_agent_forwarding":true}
 * c'est-a-dire un bloc `Match User` sans restriction SFTP, avec tunnels — sur une
 * page intitulee « Acces SFTP ».
 *
 * LE PANNEAU NOMME CE QUI S'ELARGIT. Un bloc `Match User` REMPLACE, pour ce
 * compte, ce que la configuration generale de la machine aurait donne : deployer
 * un bloc permissif sur une machine durcie OUVRE l'acces. Le panneau enumere donc
 * les reglages actifs classes « ouvre », plutot que d'annoncer un deploiement en
 * bloc.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var libelles = {};
    try {
        var bloc = document.getElementById('sftp-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { libelles = {}; }

    var form = document.querySelector('[data-rw="sftp-form"]');
    if (! form) { return; }

    var panneau = document.querySelector('[data-rw="sftp-panneau"]');
    var panneauTitre = document.querySelector('[data-rw="sftp-panneau-titre"]');
    var panneauTexte = document.querySelector('[data-rw="sftp-panneau-texte"]');
    var panneauDetail = document.querySelector('[data-rw="sftp-panneau-detail"]');
    var boutonConfirmer = document.querySelector('[data-rw="sftp-confirmer"]');
    var boutonAnnuler = document.querySelector('[data-rw="sftp-annuler"]');
    var zoneResultat = document.querySelector('[data-rw="sftp-resultat"]');
    var zoneSortie = document.querySelector('[data-rw="sftp-sortie"]');

    /* ═══ LE CORPS ENVOYE ═════════════════════════════════════════════════ */

    /**
     * Les cles sont celles que `sftp_deploy()` LIT, comparees une a une au
     * `collectBody()` du legacy : `machine_id`, `server_user_id`, `sftp_only`,
     * `chroot_dir`, `working_dir`, `allow_password_auth`, `allow_tcp_forwarding`,
     * `allow_agent_forwarding`, `x11_forwarding`.
     *
     * Les quatre booleens partent TOUJOURS, et ce n'est pas une precaution de
     * style : `sftp_deploy` prend `data.get('allow_tcp_forwarding', True)` — un
     * booleen omis retombe du cote PERMISSIF. Meme mecanique qu'E-144 en D9a.
     *
     * `|| null` sur les deux chemins : le legacy envoie `null` pour un champ
     * vide, et `_validate_path` n'est appele que si la valeur est vraie. Une
     * chaine vide transmise telle quelle passerait dans le rendu comme un chemin.
     */
    function corps() {
        var envoi = {
            machine_id: parseInt(form.dataset.machine, 10),
            server_user_id: parseInt(form.dataset.compte, 10),
            chroot_dir: form.querySelector('[data-rw="sftp-chroot"]').value.trim() || null,
            working_dir: form.querySelector('[data-rw="sftp-working"]').value.trim() || null,
        };
        form.querySelectorAll('input[type="checkbox"]').forEach(function (c) {
            envoi[c.name] = c.checked;
        });

        return envoi;
    }

    /** Les reglages actifs qui ELARGISSENT l'acces, par leur libelle affiche. */
    function ceQuiOuvre() {
        var noms = [];
        form.querySelectorAll('input[type="checkbox"]').forEach(function (c) {
            if (c.checked && c.dataset.effet === 'ouvre') {
                // Le libelle est vise par son `data-rw`, pas par sa position.
                // `span > span` ramassait le badge avec le titre : le panneau
                // annoncait « Autoriser… Elargit l'acces », ou le badge se lisait
                // comme une partie du nom du reglage.
                var etiquette = c.closest('label');
                var titre = etiquette ? etiquette.querySelector('[data-rw^="sftp-titre-"]') : null;
                noms.push(titre ? (titre.textContent || '').trim() : c.name);
            }
        });

        return noms;
    }

    /**
     * Appelle la passerelle. FAIL-CLOSED : sans `success === true` on annonce un
     * echec. Un `undefined` affiche comme « fait » serait un mensonge, et c'est
     * ici un mensonge sur l'acces SSH d'un compte.
     */
    function appelle(chemin, envoi) {
        return fetch(PASSERELLE + chemin, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(envoi),
        }).then(function (r) {
            return r.json().catch(function () { return null; });
        }).then(function (d) {
            /*
             * ⚠ LE CORPS REMONTE DESORMAIS, et c'est la piece qui manquait.
             *
             * Ce helper ne rendait que `{ok, texte}` : le statut ET
             * `step_up_required` etaient AVALES. Un `403` exigeant une
             * re-authentification arrivait donc comme un echec ordinaire, avec
             * pour seule trace son message — celui qui disait d'aller sur
             * l'ancien portail. L'ecran ne POUVAIT pas offrir le defi : il ne
             * savait pas qu'on le lui demandait.
             *
             * `corps` est AJOUTE, pas substitue : les appelants existants
             * lisent `ok` et `texte`, et ne changent pas.
             */
            return { corps: d, ok: !!(d && d.success === true), texte: (d && (d.content || d.output || d.message || d.error)) || '' };
        }).catch(function () {
            return { ok: false, texte: '' };
        });
    }

    /*
     * ══ LE DEFI DE RE-AUTHENTIFICATION — A5, ce module en est le consommateur
     *
     * `deploy` et `remove` figurent dans `RoutesBackend::MOTIFS_STEP_UP`. La
     * passerelle les refuse par un `403` qui porte `step_up_required` ET
     * `action` — l'action etant DERIVEE DU CHEMIN cote serveur.
     *
     * ⚠ ON NE COMPOSE PAS CE NOM ICI. Le legacy fusionne les trois routes root
     * sous `policy_action`, si bien qu'un step-up consenti pour ANNULER une
     * politique autorise un DEPLOIEMENT SUDO pendant quinze minutes. Le
     * portage nomme l'action par la route ; un client qui la devinerait
     * recollerait le defaut.
     *
     * Le module est PARTAGE avec l'autre ecran de politiques : trois
     * implementations d'une meme regle divergent, et celle-ci garde des
     * ecritures `sudo` et `sftp` sur des machines reelles.
     */
    var libellesStepUp = {};
    try {
        var blocSU = document.getElementById('sftp-stepup-libelles');
        if (blocSU) { libellesStepUp = JSON.parse(blocSU.textContent || '{}'); }
    } catch (e) { libellesStepUp = {}; }

    var stepUp = window.rwStepUp ? window.rwStepUp.installe({
        panneau: document.querySelector('[data-rw="sftp-panneau-stepup"]'),
        champ: document.querySelector('[data-rw="sftp-stepup-code"]'),
        valider: document.querySelector('[data-rw="sftp-stepup-valider"]'),
        annuler: document.querySelector('[data-rw="sftp-stepup-annuler"]'),
        textes: libellesStepUp,
        dis: function (texte) { affiche({ ok: false, texte: texte }); },
    }) : null;

    function affiche(verdict) {
        zoneResultat.hidden = false;
        zoneSortie.textContent = verdict.texte || '';
        zoneResultat.classList.toggle('rw-resultat--externe', ! verdict.ok);
    }

    /* ═══ LES DEUX GESTES QUI ECRIVENT : PANNEAU D'ABORD ══════════════════ */

    var enCours = null;

    function ferme() {
        panneau.hidden = true;
        enCours = null;
    }

    function ouvre(geste) {
        enCours = geste;
        var estDeploiement = (geste === 'deploy');

        panneauTitre.textContent = estDeploiement ? libelles.confirmer_titre : libelles.retirer_titre;
        panneauTexte.textContent = estDeploiement ? libelles.confirmer_intro : libelles.retirer_intro;

        var detail = libelles.confirmer_machine + ' : ' + (form.dataset.nomMachine || '?')
            + ' · ' + libelles.confirmer_compte + ' : ' + (form.dataset.nomCompte || '?');
        if (estDeploiement) {
            // CE QUI S'ELARGIT SE NOMME. Un compteur a zero s'enonce plutot que
            // de s'afficher comme un « 0 » : « aucun reglage n'elargit l'acces »
            // est une information, « 0 » n'en est pas une.
            var ouverts = ceQuiOuvre();
            detail += ' · ' + libelles.confirmer_effet + ' : '
                + (ouverts.length ? libelles.confirmer_ouvre + ' — ' + ouverts.join(', ')
                                  : libelles.aucun_reglage_ouvert);
        }
        detail += ' · ' + libelles.reauth;
        panneauDetail.textContent = detail;

        boutonConfirmer.textContent = estDeploiement ? libelles.confirmer_valider : libelles.retirer_valider;
        panneau.hidden = false;
        boutonConfirmer.focus();
    }

    form.querySelector('[data-rw="sftp-deployer"]')
        .addEventListener('click', function () { ouvre('deploy'); });
    form.querySelector('[data-rw="sftp-retirer"]')
        .addEventListener('click', function () { ouvre('remove'); });
    boutonAnnuler.addEventListener('click', ferme);

    /*
     * LE GESTE EST EXTRAIT POUR ETRE REJOUABLE. Apres un second facteur
     * valide, il repart de lui-meme : sans cela l'operateur devrait
     * recommencer, et une re-authentification qui ne sert a rien se transforme
     * en gene qu'on cherche a contourner.
     *
     * ⚠ LE CORPS CONSENTI EST CAPTURE, pas relu. Si le formulaire bouge
     * pendant la saisie du code, le rejeu doit envoyer CE QUI A ETE CONFIRME —
     * pas ce que la page porte au retour du defi.
     */
    function envoieGeste(geste, envoi) {
        boutonConfirmer.disabled = true;

        return appelle('/policy/sftp/' + geste, envoi).then(function (verdict) {
            boutonConfirmer.disabled = false;
            ferme();
            // Le defi d'abord : s'il prend en charge le refus, on n'affiche
            // pas un echec par-dessus le panneau qu'il vient d'ouvrir.
            if (stepUp && stepUp.intercepte(verdict, function () {
                envoieGeste(geste, envoi);
            })) { return verdict; }
            affiche(verdict);

            return verdict;
        });
    }

    boutonConfirmer.addEventListener('click', function () {
        var geste = enCours;
        if (! geste) { return; }
        envoieGeste(geste, (geste === 'remove')
            ? { machine_id: parseInt(form.dataset.machine, 10),
                server_user_id: parseInt(form.dataset.compte, 10) }
            : corps());
    });

    /* ═══ L'AUDIT : UNE LECTURE, DONC AUCUN PANNEAU ═══════════════════════ */

    form.querySelector('[data-rw="sftp-auditer"]').addEventListener('click', function () {
        var bouton = this;
        bouton.disabled = true;
        appelle('/policy/sftp/audit', {
            machine_id: parseInt(form.dataset.machine, 10),
            server_user_id: parseInt(form.dataset.compte, 10),
        }).then(function (verdict) {
            bouton.disabled = false;
            affiche(verdict);
        });
    });
}());
