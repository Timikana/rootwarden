<?php
/**
 * Extrait, PAR LE LEXEUR DE PHP LUI-MEME, les correspondances
 *     'cle' => url('/api/gateway/<chemin>')
 * des controleurs du portage.
 *
 * `token_get_all()` plutot qu'une expression reguliere : c'est PHP qui lit du
 * PHP. Le meme principe que faire lire `Navigation::SECTIONS` par un `require`,
 * apres qu'un motif eut rendu 32 entrees pour 33.
 */
$sortie = ['resolues' => [], 'interpolees' => []];

foreach (glob($argv[1] . '/*.php') as $fichier) {
    $jetons = token_get_all(file_get_contents($fichier));
    $n = count($jetons);
    for ($i = 0; $i < $n; $i++) {
        // motif : T_CONSTANT_ENCAPSED_STRING  T_DOUBLE_ARROW  url ( <chaine> )
        if (!is_array($jetons[$i]) || $jetons[$i][0] !== T_CONSTANT_ENCAPSED_STRING) continue;
        $cle = trim($jetons[$i][1], "'\"");
        $j = $i + 1;
        while ($j < $n && is_array($jetons[$j]) && in_array($jetons[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $j++;
        if ($j >= $n || !is_array($jetons[$j]) || $jetons[$j][0] !== T_DOUBLE_ARROW) continue;
        $j++;
        while ($j < $n && is_array($jetons[$j]) && in_array($jetons[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) $j++;
        if ($j >= $n || !is_array($jetons[$j]) || $jetons[$j][0] !== T_STRING) continue;
        $fonction = $jetons[$j][1];
        if (!in_array($fonction, ['url', 'route'], true)) continue;
        $j++;
        while ($j < $n && is_array($jetons[$j]) && $jetons[$j][0] === T_WHITESPACE) $j++;
        if ($j >= $n || $jetons[$j] !== '(') continue;
        $j++;
        while ($j < $n && is_array($jetons[$j]) && $jetons[$j][0] === T_WHITESPACE) $j++;
        if ($j >= $n) continue;

        $entree = ['fichier' => basename($fichier), 'cle' => $cle, 'fonction' => $fonction];

        if (is_array($jetons[$j]) && $jetons[$j][0] === T_CONSTANT_ENCAPSED_STRING) {
            $entree['cible'] = trim($jetons[$j][1], "'\"");
            $sortie['resolues'][] = $entree;
        } elseif ($jetons[$j] === '"' || (is_array($jetons[$j]) && $jetons[$j][0] === T_ENCAPSED_AND_WHITESPACE)) {
            // Chaine INTERPOLEE : `url("/api/gateway/supervision/{$plateforme}/version")`.
            // Elle n'est PAS statiquement resoluble, et c'est un SILENCE MESURE,
            // pas un silence par incapacite de l'outil : on le dit.
            $morceaux = '';
            $k = $j;
            while ($k < $n && $jetons[$k] !== '"') {
                if (is_array($jetons[$k]) && $jetons[$k][0] === T_ENCAPSED_AND_WHITESPACE) $morceaux .= $jetons[$k][1];
                elseif (is_array($jetons[$k]) && $jetons[$k][0] === T_VARIABLE) $morceaux .= '{' . $jetons[$k][1] . '}';
                $k++;
            }
            $entree['cible'] = $morceaux;
            $sortie['interpolees'][] = $entree;
        }
    }
}
echo json_encode($sortie, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
