/*
 * ═══ LE REPLI DE BASE DOIT S'ANNONCER ═════════════════════════════════════
 *
 * 94 suites ecrivaient `process.env.E2E_BASE || '<une adresse en dur>'`. Dans un
 * lot, le repli ne sert jamais : `rejouer-lot.sh` exporte `E2E_BASE`. Lancee a
 * la main pour deboguer, la suite prenait le repli EN SILENCE.
 *
 * ══ CE QUE LE SILENCE COUTE, MESURE LE 2026-09-08 ═════════════════════════
 *
 * Les deux portails ont ECHANGE leurs ports le 2026-09-06 a 19:39. Etat mesure
 * aujourd'hui, par `curl -sk <base>/up` :
 *
 *     https://localhost:8443   /up = 200   -> PORTAGE
 *     https://localhost:8446   /up = 404   -> LEGACY
 *     http://localhost:8444    301 vers https://localhost:8444, ou rien n'ecoute
 *
 * Les 55 suites dont le repli valait `https://localhost:8443` visaient donc le
 * PORTAGE. Et comme la cible se DEDUIT de l'URL quand `E2E_CIBLE` est absente,
 * elles se declaraient « legacy » dans leur propre journal.
 *
 * **Mauvaise plateforme ET mauvaise etiquette, dans une sortie coherente.** Une
 * valeur fausse mais plausible ne se signale pas d'elle-meme : c'est le lecteur
 * qui doit etre averti, puisque le programme, lui, n'a rien remarque.
 *
 * ══ POURQUOI ANNONCER, ET NE PAS LEVER ════════════════════════════════════
 *
 * Les 10 suites qui ne LISAIENT PAS l'environnement ont ete traitees plus
 * severement : elles levent, faute d'avoir un repli qu'un runner puisse
 * surcharger. Celles-ci en ont un, et la decision prise alors — annoncer
 * plutot que lever — est conservee ici volontairement.
 *
 * > Ce module ne retire pas le repli : il retire son SILENCE. La difference
 * > tient a qui decide — un repli annonce laisse le choix au lecteur, un repli
 * > muet le prend a sa place.
 *
 * Et il n'affirme RIEN sur ce qui repond : il imprime la commande qui le dit.
 * Une adresse ne porte pas sa plateforme, seul son ETAT la porte.
 */
export function baseDeclaree(repli) {
    const declaree = process.env.E2E_BASE;
    if (declaree) return declaree;

    console.error('');
    console.error('⚠ E2E_BASE n\'est pas declaree — REPLI sur ' + repli);
    console.error('  Les deux portails ont ECHANGE leurs ports le 2026-09-06 : ce repli');
    console.error('  ne designe plus forcement la plateforme que cette suite decrit.');
    if (process.env.E2E_CIBLE === undefined || process.env.E2E_CIBLE === '') {
        console.error('  Et E2E_CIBLE n\'est pas posee : la cible sera DEDUITE de cette');
        console.error('  adresse, donc de ce repli — pas de votre intention.');
    }
    console.error('  Verifiez l\'ETAT, jamais le numero de port :');
    console.error('    curl -sk ' + repli + '/up     200 = portage · 404 = legacy');
    console.error('  puis :  E2E_BASE=… E2E_CIBLE=… node tests/e2e/<suite>.mjs');
    console.error('');

    return repli;
}
