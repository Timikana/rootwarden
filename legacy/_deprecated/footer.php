<?php
/**
 * footer.php - Pied de page compact
 *
 * Affiche : copyright, logos techno en ligne, liens legaux.
 * Le script dark mode est geere dans menu.php.
 */
if (!function_exists('t')) { require_once __DIR__ . '/includes/lang.php'; }
$_footerCompany = htmlspecialchars(getenv('APP_COMPANY') ?: (getenv('APP_NAME') ?: 'RootWarden'));
?>
<footer class="border-t border-gray-200 dark:border-gray-800 mt-auto">
    <div class="px-6 py-3 flex flex-col sm:flex-row items-center justify-between text-xs text-gray-400 dark:text-gray-500 gap-2">
        <span>&copy; <?= date('Y') ?> <?= $_footerCompany ?></span>
        <div class="flex items-center gap-4">
            <div class="flex gap-3 opacity-30">
                <img src="/img/logos/new-php-logo.svg" alt="PHP" class="h-4">
                <img src="/img/logos/python-logo.png" alt="Python" class="h-4">
                <img src="/img/logos/docker-logo-blue.svg" alt="Docker" class="h-4">
            </div>
            <a href="https://buymeacoffee.com/timikana" target="_blank" rel="noopener" class="hover:text-yellow-500 transition-colors" title="Buy me a coffee">&#9749;</a>
            <a href="<?= rtrim(getenv('LARAVEL_URL') ?: 'http://localhost:8080', '/') ?>/cgu" class="hover:text-gray-600 dark:hover:text-gray-300 transition-colors"><?= t('footer.terms') ?></a>
            <?php /*
             * LE LIEN « CONFIDENTIALITE » EST RETIRE, PAS REBASE.
             *
             * `privacy.php` est archive (c29c3b3f), et le portage n'a AUCUNE destination :
             * `cgu.blade.php` est la seule page de ce genre et porte 0 occurrence de
             * « confidentialite », « RGPD » ou « donnees personnelles » — mesure 2026-09-08.
             *
             * Les deux substitutions plausibles sont FAUSSES :
             *   /cgu                          les conditions ne sont pas la politique
             *   /profil/donnees-personnelles  c'est `ExportRgpdController`, l'export
             *                                 art. 20 : un GESTE de l'utilisateur, pas
             *                                 une NOTICE
             *
             * Une destination fausse est pire qu'une destination absente : un lien legal
             * qui mene ailleurs atteste une conformite qui n'est pas la.
             *
             * POUR L'EXPLOITANT : le portage doit une page de politique de confidentialite
             * avant la bascule. Ce n'est pas une regression — `t('footer.privacy')` menait
             * deja au vide — mais c'est une obligation qui n'a pas de titulaire aujourd'hui.
             */ ?>
        </div>
    </div>
</footer>
</div><!-- /lg:ml-56 content wrapper from menu.php -->
