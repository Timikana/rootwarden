<?php
/**
 * howto_tip.php — Composant tip contextuel pliable pour les pages RootWarden.
 *
 * Usage :
 *   <?php $tipId = 'ssh-deploy'; $tipSteps = [
 *       t('tip.ssh_step1'),
 *       t('tip.ssh_step2'),
 *       t('tip.ssh_step3'),
 *   ]; require __DIR__ . '/includes/howto_tip.php'; ?>
 *
 * Variables attendues :
 *   $tipId    (string) : identifiant unique (pour localStorage dismiss)
 *   $tipSteps (array)  : liste des etapes a afficher
 *   $tipTitle (string, optionnel) : titre du tip (defaut: "Comment ca marche ?")
 */

$tipTitle = $tipTitle ?? t('tip.default_title');
?>
<details id="tip-<?= htmlspecialchars($tipId) ?>" class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl mb-4 group">
    <summary class="flex items-center gap-2 px-4 py-2.5 cursor-pointer select-none text-sm font-medium text-blue-700 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-xl transition-colors">
        <svg class="w-4 h-4 flex-shrink-0 transition-transform group-open:rotate-90" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
        <span>&#128161; <?= htmlspecialchars($tipTitle) ?></span>
    </summary>
    <div class="px-4 pb-3 pt-1">
        <ol class="list-decimal list-inside space-y-1.5 text-sm text-gray-600 dark:text-gray-400">
            <?php foreach ($tipSteps as $i => $step): ?>
            <li class="leading-relaxed"><?= $step ?></li>
            <?php endforeach; ?>
        </ol>
    </div>
</details>
<?php unset($tipId, $tipSteps, $tipTitle); ?>
