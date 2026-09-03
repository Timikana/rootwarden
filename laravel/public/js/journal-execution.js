/**
 * journal-execution.js - Module `update/`, sous-lot U2 : le journal d'execution.
 *
 * Presentation pure : aucune route backend. Le journal est alimente par les
 * autres sous-lots, qui l'atteignent par `window.rwJournal`.
 *
 * POURQUOI UNE API DECLAREE PLUTOT QUE DES FONCTIONS GLOBALES.
 *
 * Le legacy definit `appendLog` DEUX FOIS : dans `domManipulation.js`, qui
 * ecrit dans la zone globale `#logs`, puis dans `apiCalls.js`, qui ecrit dans
 * `#logs-container`. Les deux sont des declarations globales et `apiCalls.js`
 * charge en second : sa definition gagne, l'autre est du code mort. Resultat
 * mesure — la zone `#logs`, un cadre noir de 12 rem que la page rend, n'est
 * alimentee par PERSONNE, et `clearLog()` vide une zone toujours vide. Les
 * messages globaux, eux, se deposent parmi les panneaux de serveur.
 *
 * C'est le meme defaut que `escHtml()` defini deux fois dans le legacy, et que
 * `.rw-etiquette` dans notre propre feuille de style. Un point d'entree unique
 * et NOMME ne peut pas etre ecrase par megarde.
 *
 * Rendu par `textContent` : les lignes portent des sorties de commandes SSH.
 */
(function () {
    'use strict';

    const conteneur = document.getElementById('logs-container');
    const globale = document.getElementById('logs');
    const libelles = JSON.parse(document.getElementById('journal-libelles')?.textContent || '{}');

    if (!conteneur) return;

    /** Distance au bas en deca de laquelle on considere qu'on « suit ». */
    const PRES_DU_BAS = 40;

    /**
     * Panneau d'un serveur, cree a la premiere ligne et REUTILISE ensuite.
     *
     * L'en-tete reste fixe ; seule la zone des lignes defile. La case « suivre »
     * se decoche quand on remonte a la main et se recoche quand on redescend,
     * pour qu'une nouvelle ligne ne vienne pas arracher la lecture en cours.
     */
    function panneau(serveur) {
        let existant = null;
        for (const el of conteneur.querySelectorAll('[data-server-name]')) {
            if (el.getAttribute('data-server-name') === serveur) existant = el;
        }
        if (existant) return existant.querySelector('.log-window');

        const bloc = document.createElement('div');
        bloc.className = 'server-log-window';
        bloc.setAttribute('data-server-name', serveur);

        const entete = document.createElement('div');
        entete.className = 'log-header';

        const nom = document.createElement('span');
        nom.className = 'server-name';
        nom.textContent = serveur;
        entete.appendChild(nom);

        const etiquette = document.createElement('label');
        etiquette.className = 'log-follow-toggle';
        etiquette.title = libelles.suivre_aide || '';
        const case_ = document.createElement('input');
        case_.type = 'checkbox';
        case_.checked = true;
        etiquette.appendChild(case_);
        etiquette.appendChild(document.createTextNode(' ' + (libelles.suivre || 'Suivre')));
        entete.appendChild(etiquette);

        bloc.appendChild(entete);

        const fenetre = document.createElement('div');
        fenetre.className = 'log-window';
        bloc.appendChild(fenetre);

        // Un defilement PROGRAMMATIQUE ne doit pas decocher la case : sans ce
        // drapeau, chaque ligne suivie ferait clignoter le reglage.
        fenetre.addEventListener('scroll', () => {
            if (fenetre._defilementProgramme) return;
            const presDuBas = (fenetre.scrollHeight - fenetre.scrollTop - fenetre.clientHeight) < PRES_DU_BAS;
            case_.checked = presDuBas;
        }, { passive: true });

        conteneur.appendChild(bloc);
        return fenetre;
    }

    function suitLeBas(zone) {
        const bloc = zone.closest('.server-log-window');
        const case_ = bloc ? bloc.querySelector('.log-follow-toggle input') : null;
        const suit = case_ ? case_.checked : true;
        const presDuBas = (zone.scrollHeight - zone.scrollTop - zone.clientHeight) < PRES_DU_BAS;
        return suit && presDuBas;
    }

    function defileEnBas(zone) {
        zone._defilementProgramme = true;
        zone.scrollTop = zone.scrollHeight;
        requestAnimationFrame(() => requestAnimationFrame(() => {
            zone._defilementProgramme = false;
        }));
    }

    /**
     * Ajoute une ligne au journal.
     *
     * @param {string} message
     * @param {string} [type]     'info' | 'progress' | 'error' | 'ok'
     * @param {string|null} [serveur] nom du serveur, ou rien pour le journal general
     */
    function ajoute(message, type, serveur) {
        const genre = type || 'info';

        // SANS SERVEUR : la zone GENERALE, pas le conteneur des panneaux. C'est
        // la difference qui compte avec le legacy, ou le message atterrissait
        // parmi les panneaux pendant que la zone generale restait vide.
        if (!serveur) {
            if (!globale) return;
            const ligne = document.createElement('p');
            ligne.className = 'log-line ' + genre;
            ligne.textContent = message;
            globale.appendChild(ligne);
            globale.scrollTop = globale.scrollHeight;
            globale.classList.remove('rw-journal--vide');
            return;
        }

        const zone = panneau(serveur);
        const suivre = suitLeBas(zone);

        // Une ligne de PROGRESSION remplace la precedente au lieu de s'empiler :
        // un compteur qui defile sur mille lignes n'informe personne.
        if (genre === 'progress') {
            const derniere = zone.lastElementChild;
            if (derniere && derniere.classList.contains('progress')) {
                derniere.textContent = message;
                if (suivre) defileEnBas(zone);
                return;
            }
        }

        const ligne = document.createElement('p');
        ligne.className = 'log-line ' + genre;
        ligne.textContent = message;
        zone.appendChild(ligne);

        if (suivre) defileEnBas(zone);
    }

    /** Efface les panneaux ET la zone generale — le journal entier. */
    function vide() {
        conteneur.replaceChildren();
        if (globale) {
            globale.replaceChildren();
            globale.classList.add('rw-journal--vide');
        }
    }

    if (globale && !globale.textContent.trim()) globale.classList.add('rw-journal--vide');

    const boutonVider = document.getElementById('clear-logs-btn');
    if (boutonVider) boutonVider.addEventListener('click', vide);

    // Point d'entree UNIQUE et nomme, pour les sous-lots U3 a U6.
    window.rwJournal = { ajoute, vide };
})();
