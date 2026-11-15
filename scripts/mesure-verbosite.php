<?php
// Mots FR affiches dans les elements d'aide, par vue. Les cles se resolvent en
// chargeant les catalogues PHP eux-memes (pas de lecture par motif).
// Une vue a 0 ne veut pas dire « sans texte » : ses libelles passent peut-etre
// par le controleur.
//
// Usage, depuis la racine du depot :
//   docker run --rm --network none -v "$PWD/laravel":/app:ro -v "$PWD/scripts":/s:ro php:8.3-cli php /s/mesure-verbosite.php
$lang = [];
foreach (glob('/app/lang/fr/*.php') as $f) { $lang[basename($f, '.php')] = include $f; }
function val($lang, $cle) {
    $p = explode('.', $cle); $v = $lang[array_shift($p)] ?? null;
    foreach ($p as $k) { if (!is_array($v) || !array_key_exists($k, $v)) return null; $v = $v[$k]; }
    return is_string($v) ? $v : null;
}
function mots($s) { return count(preg_split('/\s+/u', trim(strip_tags($s)), -1, PREG_SPLIT_NO_EMPTY)); }
$aideRe = '/<(p|div|span|small|li|aside)\b[^>]*class="[^"]*\b(rw-aide|rw-prose|rw-encart|rw-vide__texte|rw-avertissement)\b[^"]*"[^>]*>(.*?)<\/\1>/s';
$rows = []; $absentes = 0;
foreach (glob('/app/resources/views/*.blade.php') as $v) {
    $src = preg_replace('/\{\{--.*?--\}\}/s', '', file_get_contents($v));
    $aide = 0; $nAide = 0; $tout = 0;
    preg_match_all("/__\\('([a-z_]+\\.[A-Za-z0-9_.]+)'/", $src, $m);
    foreach (array_unique($m[1]) as $c) { $x = val($lang, $c); if ($x !== null) $tout += mots($x); }
    preg_match_all($aideRe, $src, $els, PREG_SET_ORDER);
    foreach ($els as $e) {
        preg_match_all("/__\\('([a-z_]+\\.[A-Za-z0-9_.]+)'/", $e[3], $k);
        foreach ($k[1] as $c) { $x = val($lang, $c); if ($x === null) { $absentes++; continue; } $aide += mots($x); $nAide++; }
    }
    $rows[] = [basename($v, '.blade.php'), $nAide, $aide, $tout];
}
usort($rows, fn($a, $b) => $b[2] <=> $a[2]);
printf("%-28s %6s %8s %8s %6s\n", 'vue', 'aides', 'mots_aide', 'mots_tot', '%aide');
$sa = 0; $st = 0;
foreach ($rows as $r) { $sa += $r[2]; $st += $r[3]; printf("%-28s %6d %8d %8d %5d%%\n", $r[0], $r[1], $r[2], $r[3], $r[3] ? 100*$r[2]/$r[3] : 0); }
printf("TOTAL aide=%d tout=%d ; cles d'aide non resolues=%d\n", $sa, $st, $absentes);
