{{--
    LE BASCULE DE THEME — soleil et lune, comme le legacy (`menu.php:200`).

    ⚠ CETTE CAPACITE N'AVAIT JAMAIS ETE PORTEE, et elle ne figurait dans AUCUNE
    des 16 capacites de l'inventaire : cet inventaire a ete construit a partir
    des ENTREES DE MENU, et un bascule n'en est pas une. L'unite d'un inventaire
    decide de ce qu'il peut voir. Trouvee par l'exploitant en se servant du
    produit, le 2026-09-05.

    LES DEUX ICONES SONT DANS LE DOM ; c'est le theme APPLIQUE qui decide
    laquelle se voit, par CSS. Le script n'a donc rien a synchroniser, et un
    etat impossible — les deux visibles, ou aucune — ne peut pas se produire
    par oubli de mise a jour.

    On affiche ce qu'on PROPOSE, pas ce qu'on subit : en clair, la lune.
--}}
<button class="rw-theme" type="button" data-rw="theme-bascule"
        title="{{ __('nav.theme_basculer') }}"
        aria-label="{{ __('nav.theme_basculer') }}">
    <span class="rw-theme__soleil" aria-hidden="true">&#9728;&#65039;</span>
    <span class="rw-theme__lune" aria-hidden="true">&#127769;</span>
</button>
<script>
    (function () {
        var b = document.querySelector('[data-rw="theme-bascule"]');
        if (!b) { return; }
        b.addEventListener('click', function () {
            var r = document.documentElement;
            /*
             * ⚠ ON NE LIT PAS L'ATTRIBUT POUR SAVOIR OU L'ON EST.
             *
             * Quand rien n'est choisi il est ABSENT, et le theme affiche vient
             * alors du systeme. Un `getAttribute() === 'dark' ? …` traiterait
             * ce cas comme « clair » et le premier clic ne ferait RIEN pour un
             * utilisateur en systeme sombre — la moitie des gens, un bouton mort.
             *
             * On demande donc au navigateur ce qui est REELLEMENT applique.
             */
            var sombre = getComputedStyle(r).getPropertyValue('--rw-fond').trim() === '#0f1722';
            var voulu = sombre ? 'light' : 'dark';
            r.setAttribute('data-theme', voulu);
            try { localStorage.setItem('rw-theme', voulu); } catch (e) { /* non persiste */ }
        });
    })();
</script>
