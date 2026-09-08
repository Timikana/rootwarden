/*
 * ═══ UN AUDIT SSH QUI ABOUTIT — MESURE SUR LE SERVICE, PAS SUR L'ARBRE ════
 *
 * HORS-LOT: geste SORTANT sur une machine reelle. Ne se joue jamais dans un lot,
 * et exige une autorisation explicite a chaque execution.
 *
 * ══ CE QU'ELLE PROUVE, ET POURQUOI C'EST NEUF ═════════════════════════════
 *
 * Le chantier a beaucoup mesure que des gestes sont ATTEIGNABLES. Celui-ci
 * mesure qu'un geste ABOUTIT : `POST /ssh-audit/scan` ouvre une session SSH,
 * lit `sshd_config`, le confronte aux regles d'audit, et rend un resultat.
 *
 * ⚠ REGIME : LE SERVICE, ET C'EST LA PREMIERE FOIS QU'ON PEUT L'ECRIRE.
 *
 * Le processus `rootwarden_python` tourne avec `use_reloader = False` depuis le
 * 2026-09-07T12:53:00Z, et 19 commits de `backend/` lui sont posterieurs — donc
 * la plupart des mesures de ce depot portent sur l'ARBRE et pas sur le service.
 * Mais pour CE fichier :
 *
 *     git log --since=<StartedAt> -- backend/ssh_audit.py   ->  0 commit
 *     mtime backend/ssh_audit.py   2026-08-20T09:46:51Z     (avant le demarrage)
 *
 * **arbre == service pour ce fichier.** Le regime n'est pas une propriete du
 * depot, c'est une propriete du FICHIER et de sa DATE.
 *
 * ══ LA QUESTION QUI DECIDE, ET CE QUE LA LECTURE A DEJA TRANCHE ═══════════
 *
 * On craignait le mode d'echec d'`iptables` : un succes complet rendu sans
 * avoir rien fait. Pour `iptables`, la valeur de retour etait JETEE — trois
 * appels a `execute_as_root`, zero affectation — et le succes journalise
 * inconditionnellement.
 *
 * Ici la lecture montre le contraire, en deux couches :
 *
 *     ssh_audit.py:105          cat /etc/ssh/sshd_config 2>/dev/null
 *     ssh_audit.py:107          if rc != 0: return ''
 *     routes/ssh_audit.py:136   if not config_text: -> success:False, 500
 *
 * > Le mode « succes vide » ne se cherche pas au banc quand il se lit dans le
 * > code : ce qui le ferme est une valeur AFFECTEE puis TESTEE. Le banc reste
 * > necessaire pour ce que le code ne dit pas — pas pour ce qu'il dit.
 *
 * Cette suite ne re-demontre donc pas l'absence du mode vide. Elle mesure ce
 * que la lecture ne donne pas : **le contenu reel du resultat sur une machine
 * reelle** — combien de regles evaluees, sur quelles directives.
 *
 * ══ CE QUE LE GESTE FAIT VRAIMENT, verifie avant de le jouer ═══════════════
 *
 *   sur la machine 3   `cat /etc/ssh/sshd_config` + un releve de version.
 *                      RIEN n'est modifie a distance.
 *   en base            `_save_audit_result`, `_log_audit_action`, et
 *                      `notify_subscribed` -> INSERT INTO notifications.
 *                      Sur un grade D/E/F, une SECONDE notification.
 *
 * ⚠ `backend/notify.py` n'importe que `logging` et `get_db_connection` : ZERO
 * occurrence SMTP. Donc des lignes en base, pas de courriel. Le SMTP de ce banc
 * est arme avec des identifiants reels — cette verification etait un prealable,
 * pas une precaution de style.
 *
 * ⛔ TROIS VOISINS QU'ON NE TOUCHE JAMAIS, dans ce meme fichier backend :
 *     /ssh-audit/scan-all  (l.238, tout le parc)   /ssh-audit/fix  (l.411)
 *     /ssh-audit/config    (l.362)
 *
 * ══ LE TRANSPORT, ET POURQUOI PAS LA PASSERELLE ═══════════════════════════
 *
 * `Route::any('/api/gateway/{chemin?}')` est dans le groupe `web` : session
 * complete ET jeton CSRF. Y passer demanderait une connexion, donc un code
 * TOTP — et le garde anti-rejeu est par COMPTE et PERSISTANT, il traverse les
 * sessions de travail. Bruler une fenetre TOTP sur un compte partage pour
 * joindre une route de lecture perturberait les mesures d'autrui.
 *
 * On suit donc la convention deja etablie par `09-docker-idor.test.mjs` :
 * `docker exec` dans le conteneur, `X-API-KEY` + `X-User-ID`.
 *
 * ⚠ ET CE N'EST PAS UNE FORGERIE DE ROLE. `get_current_user` (helpers.py:178)
 * ne lit QUE `X-User-ID`, puis recharge `role_id` et `active` DEPUIS LA TABLE
 * `users`. Son propre docblock dit que l'ancienne version faisait confiance a
 * `X-User-Role`, « ce qui permettait a tout client en possession d'X-API-KEY de
 * forger role=3 ». On declare un compte reel et le backend tranche.
 *
 *   usage :  RW_SCAN_CIBLE=3 node tests/e2e/go-audit-ssh-scan-machine3.mjs
 *   sortie :  0 = l'audit a abouti et son resultat est reel
 *             1 = il a abouti mais le resultat est vide, ou une propriete est fausse
 *             2 = l'instrument n'a pas pu mesurer -> NE RIEN CONCLURE
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

/*
 * ⚠ « REGLES EVALUEES » N'EST PAS « FINDINGS », et mon premier libelle mentait.
 *
 * `audit_sshd_config` fait `for rule in AUDIT_RULES:` — les SEIZE regles sont
 * evaluees — et n'ajoute un finding que pour un ECART. La premiere execution a
 * rendu 2 findings, et ma sortie annonçait « 2 regles evaluees ».
 *
 * Le nombre etait juste, le NOM promettait autre chose : un lecteur en aurait
 * conclu que l'audit n'examine que deux directives sur seize. C'est la reponse
 * exacte a la question posee — « combien de regles evaluees ? » — et elle etait
 * fausse par son etiquette, pas par son calcul.
 *
 * > Un chiffre juste sous un nom qui promet autre chose n'a rien a quoi se
 * > cogner : aucune remesure ne le contredit, puisqu'il se remesure identique.
 *
 * Le total est donc LU depuis la source plutot que suppose.
 */
const REGLES = (() => {
    try {
        const src = readFileSync(new URL('../../backend/ssh_audit.py', import.meta.url), 'utf8');
        const d = src.indexOf('AUDIT_RULES = [');
        if (d < 0) return null;
        const f = src.indexOf('\n]', d);

        return f < 0 ? null : (src.slice(d, f).match(/'key'\s*:/g) || []).length || null;
    } catch { return null; }
})();
const PY = 'rootwarden_python';
const DB = 'rootwarden_db';
const COMPTE = 16;          /* rw-test-super, role 3 en base */
const ROUTE = '/ssh-audit/scan';

/*
 * ⚠ LA CIBLE EST DECLAREE, ET LA PRODUCTION EST INEXPRIMABLE.
 *
 * L'autorisation donnee porte sur la machine 3 et sur elle seule. Un defaut par
 * defaut vaudrait autorisation permanente : sans variable, on ne joue rien.
 *
 * Le refus porte sur l'ENTIER : '03', ' 3', '3.0' designent tous la 3 et
 * franchiraient une comparaison textuelle, tandis que '1' doit etre refuse quoi
 * qu'il arrive.
 */
const CIBLE = (() => {
    const AUTORISEES = new Map([[3, 'OpenCVE-Test-OnPrem 192.168.0.2']]);
    const INTERDITES = new Map([[1, 'srv-zabbix 192.168.0.244 — PRODUCTION'],
                                [14, 'rw-test-user — lecture seule']]);
    const brut = process.env.RW_SCAN_CIBLE;
    if (brut === undefined || brut === '') {
        throw new Error(
            'RW_SCAN_CIBLE absente. Cette suite OUVRE UNE SESSION SSH sur une machine\n'
            + '  reelle et ecrit des lignes d\'audit en base. Elle n\'a pas de cible par\n'
            + '  defaut : l\'autorisation recue porte sur la machine 3 et sur elle seule.\n'
            + '    RW_SCAN_CIBLE=3 node tests/e2e/go-audit-ssh-scan-machine3.mjs');
    }
    const id = Number(brut);
    if (! Number.isInteger(id) || id <= 0) {
        throw new Error(`RW_SCAN_CIBLE="${brut}" n'est pas un identifiant de machine.`);
    }
    if (INTERDITES.has(id)) {
        throw new Error(`RW_SCAN_CIBLE=${id} : ${INTERDITES.get(id)}. Refuse.`);
    }
    if (! AUTORISEES.has(id)) {
        throw new Error(
            `RW_SCAN_CIBLE=${id} n'est pas une cible autorisee.\n`
            + `  Autorisees : ${[...AUTORISEES.keys()].join(', ')}. Une autorisation vaut\n`
            + '  pour la machine qu\'elle nomme, pas pour la famille « machines de test ».');
    }

    return id;
})();

let echecs = 0;
const dit = (ok, quoi, detail) => {
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${quoi}${detail ? `  — ${detail}` : ''}`);
    if (! ok) echecs++;
};

const dockerSudo = (args, entree) => execFileSync('sudo', ['-n', 'docker', ...args],
    { encoding: 'utf8', input: entree, maxBuffer: 8 * 1024 * 1024 }).trim();

/* Le regime, imprime AVANT toute mesure. */
console.log('REGIME MESURE : LE SERVICE (processus rootwarden_python), pas l\'arbre.');
console.log('  backend/ssh_audit.py : 0 commit depuis le demarrage du conteneur,');
console.log('  donc pour ce fichier precisement, arbre == service.');
console.log(`CIBLE : machine ${CIBLE} — production inexprimable par construction.`);

let cle;
try {
    cle = dockerSudo(['exec', PY, 'printenv', 'API_KEY']);
} catch (e) {
    console.log(`\n⛔ cle API illisible : ${String(e.message).split('\n')[0]}`);
    console.log('   Le conteneur tourne-t-il, et `sudo -n docker` est-il permis ?');
    console.log('   NE RIEN CONCLURE.');
    process.exit(2);
}
if (cle.length < 10) {
    console.log(`\n⛔ cle API de ${cle.length} caractere(s) — invraisemblable. NE RIEN CONCLURE.`);
    process.exit(2);
}
console.log(`  cle API relevee : ${cle.length} caracteres (valeur non imprimee)`);

const appelle = (methode, chemin, corps) => {
    const args = ['exec', PY, 'curl', '-sk', '-w', '\n%{http_code}', '--max-time', '90',
        '-X', methode, `https://localhost:5000${chemin}`,
        '-H', `X-API-KEY: ${cle}`, '-H', `X-User-ID: ${COMPTE}`];
    if (corps !== undefined) args.push('-H', 'Content-Type: application/json', '-d', JSON.stringify(corps));
    const brut = dockerSudo(args);
    const coupe = brut.lastIndexOf('\n');
    const statut = Number(brut.slice(coupe + 1));
    let json = null;
    try { json = JSON.parse(brut.slice(0, coupe)); } catch { /* corps non-JSON */ }

    return { statut, json, brut: brut.slice(0, coupe) };
};

const compteLignes = (requete) => {
    try {
        const pw = dockerSudo(['exec', DB, 'sh', '-c',
            'printenv MYSQL_ROOT_PASSWORD']);
        const out = execFileSync('sudo', ['-n', 'docker', 'exec', DB, 'mysql', '-N',
            '-uroot', `-p${pw}`, 'rootwarden', '-e', requete],
            { encoding: 'utf8' });

        return Number(out.split('\n').filter((l) => ! /Using a password/.test(l))[0]);
    } catch { return null; }
};

/*
 * ══ ① PREFLIGHT EN LECTURE — le transport et l'habilitation, sans rien ecrire
 *
 * Si le POST echoue, il faut pouvoir distinguer « la route refuse » de « le
 * transport ne marche pas ». Ce GET porte EXACTEMENT les memes gardes que le
 * POST (`can_audit_ssh` + `require_machine_access`) et n'ecrit rien.
 */
console.log('\n=== ① preflight : GET /ssh-audit/results (memes gardes, aucune ecriture)\n');
const pre = appelle('GET', `/ssh-audit/results?machine_id=${CIBLE}`);
dit(pre.statut !== 401 && pre.statut !== 403,
    'le transport et l\'habilitation passent',
    pre.statut === 401 || pre.statut === 403
        ? `statut ${pre.statut} — la cle ou le compte ${COMPTE} n'est pas habilite`
        : `statut ${pre.statut}`);
if (pre.statut === 401 || pre.statut === 403) {
    console.log('\n⛔ Sans habilitation, le POST ne mesurerait que le refus. NE RIEN CONCLURE.');
    process.exit(2);
}

const avantAudits = compteLignes(`SELECT COUNT(*) FROM ssh_audit_results WHERE machine_id=${CIBLE};`);
const avantNotifs = compteLignes('SELECT COUNT(*) FROM notifications;');
console.log(`  lignes d'audit avant : ${avantAudits ?? '(non mesure)'}`);
console.log(`  notifications avant  : ${avantNotifs ?? '(non mesure)'}`);

console.log(`\n=== ② le geste : POST ${ROUTE} sur la machine ${CIBLE}\n`);
const r = appelle('POST', ROUTE, { machine_id: CIBLE });
console.log(`  statut HTTP : ${r.statut}`);

if (r.json === null) {
    dit(false, 'la reponse est du JSON', `corps non-JSON : ${r.brut.slice(0, 160)}`);
    console.log('\nUn corps illisible ne permet pas de juger le contenu du resultat.');
    process.exit(1);
}

dit(r.statut === 200, 'le geste ABOUTIT (200)',
    r.statut === 200 ? undefined : `statut ${r.statut} · ${JSON.stringify(r.json).slice(0, 140)}`);
dit(r.json.success === true, 'success vaut true',
    r.json.success === true ? undefined : `success=${JSON.stringify(r.json.success)} · ${r.json.message ?? ''}`);

/*
 * ══ ③ LE RESULTAT EST-IL REEL, OU UN SUCCES VIDE ?
 *
 * C'est la question du chantier. Un succes vide serait `success: true` avec
 * `findings: []` et un score par defaut — la forme exacte du defaut iptables.
 */
console.log('\n=== ③ le resultat est-il REEL ?\n');
const f = Array.isArray(r.json.findings) ? r.json.findings : null;
dit(f !== null, 'findings est un tableau', f !== null ? `${f.length} entree(s)` : `type ${typeof r.json.findings}`);
dit(f !== null && f.length > 0, 'findings est NON VIDE',
    f !== null && f.length > 0
        ? `${f.length} ECART(S) sur ${REGLES ?? '?'} regles evaluees`
        : 'tableau vide — SUCCES VIDE');
dit(REGLES !== null, 'le total des regles est lu depuis backend/ssh_audit.py',
    REGLES !== null ? `${REGLES} regles` : 'AUDIT_RULES illisible — total inconnu');
dit(REGLES === null || (f !== null && f.length <= REGLES),
    'les ecarts ne depassent pas le nombre de regles',
    REGLES !== null && f !== null && f.length > REGLES ? `${f.length} > ${REGLES}` : undefined);
dit(typeof r.json.score === 'number', 'score est un nombre', `score=${r.json.score}`);
dit(typeof r.json.grade === 'string' && r.json.grade.length > 0, 'grade est renseigne', `grade=${r.json.grade}`);
dit(r.json.machine_id === CIBLE, `machine_id renvoye est bien ${CIBLE}`,
    r.json.machine_id === CIBLE ? undefined : `recu ${JSON.stringify(r.json.machine_id)}`);

if (f && f.length) {
    const directives = [...new Set(f.map((x) => x.key ?? x.directive ?? x.name ?? '(sans nom)'))];
    dit(directives.length > 1 && ! directives.includes('(sans nom)'),
        'chaque finding nomme une directive',
        `${directives.length} directives : ${directives.slice(0, 8).join(', ')}`
        + (directives.length > 8 ? ` … +${directives.length - 8}` : ''));
    const c = r.json.counts ?? {};
    console.log(`  counts : ${JSON.stringify(c)}`);
    console.log(`  version SSH relevee : ${r.json.ssh_version ?? '(absente)'}`);
    dit(typeof r.json.ssh_version === 'string' && r.json.ssh_version.length > 0,
        'la version SSH a ete relevee sur la machine distante',
        typeof r.json.ssh_version === 'string' && r.json.ssh_version.length > 0
            ? undefined : 'vide — la session SSH a-t-elle vraiment abouti ?');
}

console.log('\n=== ④ les ecritures attendues ont-elles eu lieu ?\n');
console.log(`  persisted : ${JSON.stringify(r.json.persisted)}`);
if (r.json.persistence_error) console.log(`  persistence_error : ${r.json.persistence_error}`);
const apresAudits = compteLignes(`SELECT COUNT(*) FROM ssh_audit_results WHERE machine_id=${CIBLE};`);
const apresNotifs = compteLignes('SELECT COUNT(*) FROM notifications;');
console.log(`  lignes d'audit : ${avantAudits ?? '?'} -> ${apresAudits ?? '?'}`);
console.log(`  notifications  : ${avantNotifs ?? '?'} -> ${apresNotifs ?? '?'}`);
console.log('  Ces ecritures sont l\'effet NORMAL d\'un audit, pas un effet de bord :');
console.log('  un audit qui ne laisse pas de trace ne sert a rien. Rien n\'a ete');
console.log('  modifie sur la machine distante — seuls un `cat` et un releve de version.');

console.log('');
if (echecs) {
    console.log(`${echecs} propriete(s) fausse(s). Un « success: true » ne suffit pas :`);
    console.log('la question etait de savoir si le resultat PORTE un audit, ou si le geste');
    console.log('rend un succes en n\'ayant rien fait.');
    process.exit(1);
}
console.log(`L'audit ABOUTIT sur la machine ${CIBLE} : ${REGLES ?? '?'} regles evaluees,`
    + ` ${f.length} ecart(s),`);
console.log(`grade ${r.json.grade}, score ${r.json.score}, version ${r.json.ssh_version}.`);
console.log('Mesure sur le SERVICE, et le resultat n\'est pas vide.');
process.exit(0);
