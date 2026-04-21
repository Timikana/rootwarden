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
            <a href="/terms.php" class="hover:text-gray-600 dark:hover:text-gray-300 transition-colors"><?= t('footer.terms') ?></a>
            <a href="/privacy.php" class="hover:text-gray-600 dark:hover:text-gray-300 transition-colors"><?= t('footer.privacy') ?></a>
        </div>
    </div>
</footer>
</div><!-- /lg:ml-56 content wrapper from menu.php -->
