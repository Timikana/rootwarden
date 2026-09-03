/**
 * politiques.js - Droits sudo par compte distant, sous-lot D9a.
 *
 * DEUX DIFFERENCES AVEC `legacy/adm/js/server_user_policy.js`, et ce sont les
 * deux defauts que le portage corrige.
 *
 * 1. **DEPLOYER SE CONFIRME.** Le legacy ouvrait `removePolicy()` et `rollback()`
 *    par `if (!confirm(...)) return;` et laissait `deployPolicy()` partir au
 *    premier clic. Mesure de la suite : deployer = 0 boite, retirer = 1. Un seul
 *    clic ecrivait donc `/etc/sudoers.d/rootwarden-<user>` sur la machine — le
 *    geste qui DONNE etait libre, celui qui REPREND etait garde.
 *
 * 2. **LA PORTEE S'AFFICHE AVANT LE CHOIX, ET ELLE DIT VRAI.** L'aide vient du
 *    catalogue, le classement de `App\Services\Politiques::PORTEE`. Rien n'est
 *    recopie ici : ni un gabarit de regle sudoers, ni une affirmation sur ce
 *    qu'un prereglage accorde.
 */
(function () {
    'use strict';

    var PASSERELLE = '/api/gateway';

    var libelles = {};
    try {
        var bloc = document.getElementById('politiques-libelles');
        if (bloc) { libelles = JSON.parse(bloc.textContent || '{}'); }
    } catch (e) { libelles = {}; }

    var form = document.querySelector('[data-rw="politique-form"]');
    if (! form) { return; }

    var choixPrereglage = form.querySelector('[data-rw="politique-prereglage"]');
    var zonePortee = form.querySelector('[data-rw="politique-portee"]');
    var zoneAide = form.querySelector('[data-rw="politique-aide"]');
    var blocRegles = form.querySelector('[data-rw="politique-bloc-regles"]');
    var blocServices = form.querySelector('[data-rw="politique-bloc-services"]');

    var panneau = document.querySelector('[data-rw="politique-panneau"]');
    var panneauTitre = document.querySelector('[data-rw="politique-panneau-titre"]');
    var panneauTexte = document.querySelector('[data-rw="politique-panneau-texte"]');
    var panneauDetail = document.querySelector('[data-rw="politique-panneau-detail"]');
    var boutonConfirmer = document.querySelector('[data-rw="politique-confirmer"]');
    var boutonAnnuler = document.querySelector('[data-rw="politique-annuler"]');
    var zoneResultat = document.querySelector('[data-rw="politique-resultat"]');
    var zoneSortie = document.querySelector('[data-rw="politique-sortie"]');

    /* ═══ LA PORTEE DU PREREGLAGE ═════════════════════════════════════════ */

    function porteeDe(prereglage) {
        return (libelles.portee && libelles.portee[prereglage]) || 'inconnu';
    }

    function montreLaPortee() {
        var p = choixPrereglage.value;
        var classe = porteeDe(p);

        zoneAide.textContent = (libelles.aide && libelles.aide[p]) || '';

        // Le marqueur ne parait QUE pour ce qui n'est pas borne : un bandeau
        // affiche sur les six prereglages ne distinguerait plus rien.
        if (classe === 'borne') {
            zonePortee.hidden = true;
        } else {
            zonePortee.hidden = false;
            zonePortee.textContent = libelles['portee_' + classe] + ' — '
                + libelles['portee_' + classe + '_detail'];
        }

        blocRegles.hidden = (p !== 'custom');
        blocServices.hidden = (p !== 'systemctl_specific');
    }

    choixPrereglage.addEventListener('change', montreLaPortee);
    montreLaPortee();

    /* ═══ LE CORPS ENVOYE ═════════════════════════════════════════════════ */

    /**
     * Les cles sont celles que `backend/routes/policies.py` LIT. Comparees une a
     * une au `collectBody()` du legacy : meme jeu, meme orthographe —
     * `machine_id`, `server_user_id`, `preset`, `nopasswd`, `runas`,
     * `custom_rules`, `services`.
     *
     * `preset` PART TOUJOURS, et ce n'est pas une precaution de style :
     * `sudo_deploy` fait `data.get('preset', 'apt_only')`. Une requete qui
     * l'omet obtient donc le prereglage EQUIVALENT ROOT. Le repli dangereux
     * n'est pas seulement a l'ecran, il est aussi dans le backend.
     */
    function corps() {
        var services = form.querySelector('[data-rw="politique-services"]');
        var regles = form.querySelector('[data-rw="politique-regles"]');
        var envoi = {
            machine_id: parseInt(form.dataset.machine, 10),
            server_user_id: parseInt(form.dataset.compte, 10),
            preset: choixPrereglage.value,
            nopasswd: form.querySelector('[data-rw="politique-nopasswd"]').checked,
            runas: form.querySelector('[data-rw="politique-runas"]').value,
        };
        if (choixPrereglage.value === 'custom' && regles) {
            envoi.custom_rules = regles.value;
        }
        if (choixPrereglage.value === 'systemctl_specific' && services) {
            // Decoupage sur virgules ET espaces, comme le legacy. Avec un
            // decoupage sur la seule virgule, « nginx redis » partait en UN
            // jeton, que la liste blanche du backend (`^[A-Za-z0-9@._-]+$`)
            // rejette — l'ecart se serait vu en erreur, pas en parite.
            envoi.services = services.value.split(/[,\s]+/)
                .filter(function (s) { return s.length > 0; });
        }

        return envoi;
    }

    /**
     * Appelle la passerelle. FAIL-CLOSED : sans `success === true` on annonce un
     * echec. Un `undefined` affiche comme « fait » serait un mensonge, et c'est
     * ici un mensonge sur les droits root d'un compte.
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
            return { corps: d, ok: !!(d && d.success === true), texte: (d && (d.output || d.message || d.error)) || '' };
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
        var blocSU = document.getElementById('politiques-stepup-libelles');
        if (blocSU) { libellesStepUp = JSON.parse(blocSU.textContent || '{}'); }
    } catch (e) { libellesStepUp = {}; }

    var stepUp = window.rwStepUp ? window.rwStepUp.installe({
        panneau: document.querySelector('[data-rw="politiques-panneau-stepup"]'),
        champ: document.querySelector('[data-rw="politiques-stepup-code"]'),
        valider: document.querySelector('[data-rw="politiques-stepup-valider"]'),
        annuler: document.querySelector('[data-rw="politiques-stepup-annuler"]'),
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
        var p = choixPrereglage.value;

        panneauTitre.textContent = estDeploiement ? libelles.confirmer_titre : libelles.retirer_titre;
        panneauTexte.textContent = estDeploiement ? libelles.confirmer_intro : libelles.retirer_intro;

        // LE PANNEAU NOMME CE SUR QUOI IL PORTE. Une confirmation qui ne dit ni
        // la machine ni le compte ne fait que ralentir le clic.
        var detail = libelles.confirmer_machine + ' : ' + (form.dataset.nomMachine || '?')
            + ' · ' + libelles.confirmer_compte + ' : ' + (form.dataset.nomCompte || '?');
        if (estDeploiement) {
            detail += ' · ' + libelles.confirmer_portee + ' : '
                + libelles['portee_' + porteeDe(p)];
            if (porteeDe(p) === 'root') { detail += ' — ' + libelles.confirmer_root; }
        }
        detail += ' · ' + libelles.reauth;
        panneauDetail.textContent = detail;

        boutonConfirmer.textContent = estDeploiement ? libelles.confirmer_valider : libelles.retirer_valider;
        panneau.hidden = false;
        boutonConfirmer.focus();
    }

    form.querySelector('[data-rw="politique-deployer"]')
        .addEventListener('click', function () { ouvre('deploy'); });
    form.querySelector('[data-rw="politique-retirer"]')
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

        return appelle('/policy/sudo/' + geste, envoi).then(function (verdict) {
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

    form.querySelector('[data-rw="politique-auditer"]').addEventListener('click', function () {
        var bouton = this;
        bouton.disabled = true;
        appelle('/policy/sudo/audit', {
            machine_id: parseInt(form.dataset.machine, 10),
            server_user_id: parseInt(form.dataset.compte, 10),
        }).then(function (verdict) {
            bouton.disabled = false;
            affiche(verdict);
        });
    });
}());
