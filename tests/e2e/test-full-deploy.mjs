import puppeteer from 'puppeteer';
import { login, BASE_URL, sleep } from './helpers.mjs';

/*
 * ═══ DESARMEE LE 2026-09-08 — ELLE DEPLOYAIT SUR LA PRODUCTION ════════════
 *
 * HORS-LOT: deploie un agent de supervision sur une machine reelle, et peut
 * ecrire la configuration GLOBALE de supervision. DEUX gardes, deux objets
 * distincts, et ni l'un ni l'autre ne rend ce fichier anodin :
 *
 *   RW_DEPLOY_CIBLE     identifiant de machine ; la production (1) refusee.
 *                       Ne gouverne QUE deploySingle/detectVersion et le
 *                       choix de la case a cocher.
 *   RW_CONFIG_GLOBALE   doit valoir "oui" pour que saveGlobalConfig() parte.
 *                       Sans identifiant : l'ecriture vaut pour TOUT le parc,
 *                       et cette suite y met TLS en clair.
 *
 * ⚠ LA PREMIERE VERSION DE CE BLOC DISAIT « la production est refusee par
 * construction », et vingt-cinq lignes plus bas « le garde ne tient que les
 * deux appels ». Les deux dans le meme docblock, le second vrai, et c'est le
 * premier qu'on lit en ouvrant le fichier. **Un commentaire qui promet plus
 * que le code ne fait pas hesiter : il fait passer.**
 *
 * CE QU'ELLE FAISAIT, en clair :
 *
 *   deploySingle(1)    ->  machine id 1 = srv-zabbix, PRODUCTION
 *   detectVersion(1)   ->  meme machine
 *   saveGlobalConfig() ->  ecrit la configuration GLOBALE de supervision,
 *                          tls_connect et tls_accept a 'unencrypted'
 *   page.on('dialog', d => d.accept())  ->  accepte toute confirmation
 *
 * L'identifiant etait un LITTERAL, jamais un choix. Aucun garde, aucune
 * declaration de cible, et la boite de confirmation — le dernier filet du cote
 * navigateur — etait acceptee d'avance.
 *
 * ⚠ ET ELLE ETAIT INVISIBLE AUX DEUX FILETS.
 *
 *   - absente de SUITES_LARAVEL et SUITES_LEGACY : aucun lot ne la joue, donc
 *     elle ne rougit jamais ;
 *   - absente de l'inventaire hors-lot : sa population etait un prefixe de NOM,
 *     et ce fichier ne commence pas par « go- ».
 *
 * Elle n'etait donc ni jouee ni surveillee. Les deux etats se ressemblent de
 * l'exterieur — dans les deux cas, rien ne se passe — et c'est leur CONJONCTION
 * qui est dangereuse. **Une population definie par un prefixe de nom exclut en
 * silence : personne ne relit une expression reguliere pour savoir ce qu'elle
 * ne dit pas.**
 *
 * ⚠ CE COMMENTAIRE NE PROTEGE RIEN. Le garde ci-dessous, si.
 *
 * CE QUI RESTE A DECIDER PAR QUI CONNAIT LA SUITE — je ne le devine pas :
 *
 *   · input[name="deploy_machines[]"] prend le PREMIER element, alors que le
 *     commentaire au-dessus affirme « Cocher debian-test ». Le commentaire
 *     atteste une identite que le code n'etablit pas : c'est l'ORDRE du tableau
 *     qui decide. La case doit etre choisie SUR l'identifiant, pas sur le rang —
 *     et le garde ci-dessous ne la couvre pas, il ne tient que les deux appels.
 *   · les captures vont dans ./screenshots, relatif au repertoire courant, et
 *     non dans tests/e2e/screenshots/<module>/.
 *   · await new Promise(() => {}) en fin de fichier ne rend jamais la main :
 *     lancee dans un lot, elle tiendrait le banc indefiniment.
 */
const CIBLE_DEPLOI = (() => {
    const PRODUCTION = new Map([[1, 'srv-zabbix']]);
    const brut = process.env.RW_DEPLOY_CIBLE;

    if (brut === undefined || brut === '') {
        throw new Error(
            'RW_DEPLOY_CIBLE absente. Cette suite DEPLOIE un agent sur une machine\n'
            + '  reelle : elle ne choisit plus de cible par defaut, parce que son\n'
            + '  defaut etait la PRODUCTION. Declarer explicitement, p.ex.\n'
            + '  RW_DEPLOY_CIBLE=2 (Test-Server-Debian). Rien n\'a ete joue.');
    }

    /*
     * ⚠ LE REFUS PORTE SUR L'ENTIER, PAS SUR LA CHAINE. '01', ' 1', '1.0' et
     * '+1' designent tous la machine 1 et franchiraient une comparaison
     * textuelle. On convertit d'abord, on refuse ensuite. Et ce qui n'est pas un
     * entier est refuse aussi, plutot que de valoir NaN et de filer vers un
     * appel dont on ne sait plus la cible.
     */
    const id = Number(brut);
    if (! Number.isInteger(id) || id <= 0) {
        throw new Error('RW_DEPLOY_CIBLE="' + brut + '" n\'est pas un identifiant de machine.');
    }
    if (PRODUCTION.has(id)) {
        throw new Error(
            'RW_DEPLOY_CIBLE=' + id + ' est ' + PRODUCTION.get(id) + ' — PRODUCTION. Refuse.\n'
            + '  Un deploiement est SORTANT et IRREVERSIBLE : il installe un agent,\n'
            + '  ecrit un fichier de service et le demarre. Aucune capture ne le defait.');
    }
    return id;
})();
console.log('[0] cible de deploiement : machine ' + CIBLE_DEPLOI + ' — production refusee par le garde');

const SCREENSHOTS = './screenshots';

const browser = await puppeteer.launch({
    headless: false,
    args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost', '--start-maximized'],
    defaultViewport: { width: 1400, height: 900 }
});

const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 900 });

// Login
console.log('[1] Login...');
await login(page);
console.log('    URL:', page.url());

// Onglet Config Globale
console.log('[2] Config globale...');
await page.goto(`${BASE_URL}/supervision/`, { waitUntil: 'networkidle2' });
await sleep(500);

// Remplir le formulaire
await page.select('#cfg-agent-type', 'zabbix-agent2');
await page.select('#cfg-agent-version', '7.0');
await page.evaluate(() => { document.getElementById('cfg-zabbix-server').value = '192.168.0.2'; });
await page.evaluate(() => { document.getElementById('cfg-listen-port').value = '10050'; });
await page.evaluate(() => { document.getElementById('cfg-hostname-pattern').value = '{machine.name}'; });
await page.select('#cfg-tls-connect', 'unencrypted');
await page.select('#cfg-tls-accept', 'unencrypted');
await page.evaluate(() => { document.getElementById('cfg-host-metadata').value = 'LinuxInterne'; });

// Sauvegarder
/*
 * ⚠ UN SECOND GARDE, PARCE QUE L'OBJET N'EST PAS LE MEME — 2026-09-08.
 *
 * `RW_DEPLOY_CIBLE` filtre un IDENTIFIANT DE MACHINE. `saveGlobalConfig()` n'a
 * pas d'identifiant : il ecrit la configuration GLOBALE de supervision, celle
 * qui s'applique a srv-zabbix comme au reste du parc.
 *
 * Donc `RW_DEPLOY_CIBLE=2` — la valeur sure que le garde du haut RECOMMANDE
 * dans son propre message d'erreur — franchissait ce point et ecrivait quand
 * meme `tls_connect` et `tls_accept` a 'unencrypted'.
 *
 * ⚠ ET LE PREMIER GARDE DOMINE POURTANT CETTE LIGNE. Il est au chargement du
 * module, tout ce qui suit passe apres lui. La domination n'etait pas en cause :
 * **un garde peut dominer tous les chemins et n'en gouverner aucun, si ce qu'il
 * filtre n'est pas ce qui rend l'action dangereuse.** Ici il filtrait la CIBLE
 * d'une action qui n'en a pas.
 *
 * > Une garde se juge sur son OBJET autant que sur sa position. « Elle est en
 * > amont » repond a la mauvaise question quand l'ecriture d'en bas ne parle pas
 * > de la meme chose.
 *
 * Et c'est le plus dangereux des deux chemins, dans deux sens : il ne demandait
 * AUCUNE variable, et il DEGRADE le chiffrement au lieu d'installer quelque
 * chose. Un agent deploye par erreur se desinstalle ; un `tls_accept` a
 * 'unencrypted' laisse une fenetre ouverte tout le temps que personne ne le
 * remarque, et rien a l'ecran ne dit qu'il a change.
 */
const ECRIT_CONFIG_GLOBALE = process.env.RW_CONFIG_GLOBALE === 'oui';
if (! ECRIT_CONFIG_GLOBALE) {
    console.log('[3] configuration globale : NON ECRITE (RW_CONFIG_GLOBALE != "oui")');
    console.log('    Les champs sont remplis a l\'ecran, rien n\'est enregistre.');
    console.log('    ⚠ Cette suite ecrivait tls_connect ET tls_accept a \'unencrypted\'');
    console.log('      dans la configuration GLOBALE, sans demander aucune variable.');
} else {
    console.log('[3] Sauvegarde config GLOBALE — demandee explicitement...');
    console.log('    ⚠ tls_connect et tls_accept vont a \'unencrypted\' pour TOUT le parc.');
    await page.evaluate(() => { saveGlobalConfig(); });
    await sleep(2000);
}
await page.screenshot({ path: `${SCREENSHOTS}/full-01-config-saved.png`, fullPage: true });
console.log('    Screenshot: full-01-config-saved.png');

// Onglet Deploy
console.log('[4] Onglet Deploiement...');
await page.click('.tab-btn[data-tab="deploy"]');
await sleep(500);

/*
 * ⚠ LA CASE EST CHOISIE SUR L'IDENTIFIANT, PLUS SUR LE RANG — 2026-09-08.
 *
 * C'etait `page.$('input[name="deploy_machines[]"]')` : le PREMIER element du
 * DOM, quelle que soit la machine, sous un commentaire qui affirmait « Cocher
 * debian-test ». Le commentaire attestait une identite que le code n'etablissait
 * pas — c'est l'ordre du tableau qui decidait, et cet ordre change avec les
 * donnees.
 *
 * Le clic seul ne deploie pas, donc ce n'etait pas une arme. Mais c'etait une
 * SECONDE selection de machine que `RW_DEPLOY_CIBLE` ne gouvernait pas, dans un
 * fichier dont on croira desormais que la cible est declaree — et c'est
 * precisement quand un fichier a l'air garde qu'on cesse de lire ses lignes.
 *
 * ⚠ FERMETURE : si aucune case ne porte cet identifiant, on ARRETE. Le repli
 * naturel — cocher la premiere — est celui qu'on vient de retirer, et un repli
 * qui retombe sur le defaut corrige ne corrige rien.
 */
const caseCible = await page.$(`input[name="deploy_machines[]"][value="${CIBLE_DEPLOI}"]`);
if (! caseCible) {
    const offertes = await page.$eval('input[name="deploy_machines[]"]',
        (l) => l.map((e) => e.value));
    throw new Error(
        `Aucune case pour la machine ${CIBLE_DEPLOI}. Offertes : [${offertes.join(', ')}]\n`
        + '  On n\'en coche AUCUNE : cocher la premiere etait le defaut corrige ici.');
}
await caseCible.click();
await sleep(300);
await page.screenshot({ path: `${SCREENSHOTS}/full-02-server-selected.png`, fullPage: true });
console.log('    Screenshot: full-02-server-selected.png');

// Deployer
console.log('[5] Deploiement en cours...');
// Click deploy et accept confirm
page.on('dialog', async dialog => { await dialog.accept(); });
await page.evaluate((id) => { deploySingle(id); }, CIBLE_DEPLOI);

// Attendre que les logs apparaissent (max 120s)
console.log('    Attente des logs de deploiement (max 120s)...');
for (let i = 0; i < 60; i++) {
    await sleep(2000);
    const logText = await page.evaluate(() => {
        const container = document.getElementById('deploy-logs-container');
        return container ? container.textContent : '';
    });
    if (logText.includes('SUCCESS_MACHINE') || logText.includes('reussi') || logText.includes('Deploiement reussi')) {
        console.log('    Deploiement reussi !');
        break;
    }
    if (logText.includes('ERROR_MACHINE') || logText.includes('Exception')) {
        console.log('    ERREUR deploiement detectee');
        break;
    }
    if (i % 5 === 0) {
        const lines = logText.split('\n').filter(l => l.trim()).length;
        console.log(`    ... ${lines} lignes de logs (${(i+1)*2}s)`);
    }
}

await page.screenshot({ path: `${SCREENSHOTS}/full-03-deploy-result.png`, fullPage: true });
console.log('    Screenshot: full-03-deploy-result.png');

// Detection version
console.log('[6] Detection version...');
await page.evaluate((id) => { detectVersion(id); }, CIBLE_DEPLOI);
await sleep(3000);
await page.screenshot({ path: `${SCREENSHOTS}/full-04-version-detected.png`, fullPage: true });
console.log('    Screenshot: full-04-version-detected.png');

console.log('\n=== Test complet termine - navigateur ouvert pour debug ===');
console.log('Ctrl+C pour fermer.');
await new Promise(() => {});
