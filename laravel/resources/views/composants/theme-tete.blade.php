{{--
    LE THEME, APPLIQUE AVANT LE PREMIER RENDU.

    ⚠ CE SCRIPT DOIT RESTER DANS LE `<head>`, EN LIGNE, ET SANS `defer`.

    Pose apres le rendu, il produirait un SCINTILLEMENT : la page s'affiche
    dans le theme du systeme, puis saute dans celui qu'on a choisi. Le defaut
    est bref et il est laid, et aucune assertion DOM ne le voit — seule une
    capture le montre.

    Il n'ecrit rien : il LIT le choix et le pose sur la racine. Si rien n'est
    choisi, il ne pose AUCUN attribut, et `prefers-color-scheme` decide — c'est
    le troisieme etat, celui qu'on oublie en n'en prevoyant que deux.

    `try/catch` parce qu'un navigateur en navigation privee, ou regle pour
    refuser le stockage, fait LEVER l'acces a `localStorage` — pas rendre nul.
    Sans la garde, le gabarit entier cesserait de s'afficher pour un theme.
--}}
<script>
    (function () {
        try {
            var c = localStorage.getItem('rw-theme');
            if (c === 'dark' || c === 'light') {
                document.documentElement.setAttribute('data-theme', c);
            }
        } catch (e) { /* stockage refuse : le systeme decide, et c'est correct */ }
    })();
</script>
