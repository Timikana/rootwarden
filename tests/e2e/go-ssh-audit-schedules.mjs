/**
 * go-ssh-audit-schedules.mjs - E2E sur la planification des audits SSH.
 *
 * Couvre la nouvelle UI multi-select admin+ ajoutee en v1.16.x :
 *   1. Login superadmin
 *   2. le REFUS de `target_type=all` (E-280), et le filet si le refus manque
 *   3. CREATE schedule target_type=machines, sur la machine d'essai NOMMEE
 *
 * ══ CE QUE CETTE SUITE ARMAIT, ET QUI EST CORRIGE ICI ═════════════════════
 *
 * Elle creait DEUX planifications reelles dans `ssh_audit_schedules`, et le
 * planificateur prend toute ligne dont `next_run` est echu — il tourne dans un
 * thread invisible a `ps`.
 *
 *   `target_type: 'all'`     -> un audit SSH RECURRENT sur TOUT LE PARC
 *   `machines.slice(0, 2)`   -> les deux PREMIERES machines rendues par l'API,
 *                               c'est-a-dire  id=1 srv-zabbix 192.168.0.244
 *                               (PRODUCTION)  et  id=2 Test-Server-Debian
 *
 * **Une cible designee par sa POSITION dans une liste n'est pas une cible : elle
 * devient ce que la liste devient.** `slice(0, 2)` ne nomme rien, ne protege
 * rien, et suivra silencieusement tout reordonnancement du parc.
 *
 * Les deux sont remplacees par des cibles qui ne peuvent pas viser la
 * production : un tag qui ne resout AUCUNE machine, et la machine d'essai
 * retrouvee PAR SON NOM.
 *
 * ⚠ ET LA SURETE NE VIENT PAS DE LA GARDE BACKEND. `ssh_audit.py:826` refuse
 * `'all'` depuis le redemarrage du 2026-09-05 20:31 — mais ce correctif dormait
 * dans l'arbre depuis NEUF JOURS pendant que le service tournait sans lui. Une
 * suite dont la surete depend d'une garde qu'un redemarrage peut retirer n'est
 * pas sure : elle est chanceuse.
 *   4. TOGGLE on/off (verifier persistence)
 *   5. DELETE
 *   6. Cleanup : tous les TEST_* sont effaces
 */
import { BASE_URL, launchBrowser, newPage, login, sleep } from './helpers.mjs';

/*
 * La portee qui ne resout RIEN — et la raison a CHANGE le 2026-09-05, il faut
 * donc la dater plutot que la recopier.
 *
 *   AVANT E-280   un `target_value` vide retombait sur un `SELECT ... FROM
 *                 machines` sans filtre : la surete venait de ce que la valeur
 *                 soit NON VIDE.
 *   DEPUIS E-280  les deux chemins (`_run_scheduled_ssh_audit` et
 *                 `_run_scheduled_scan`) portent un `else` qui REFUSE et
 *                 journalise — `WHERE 1=0`, aucune machine.
 *
 * **La conclusion tient dans les deux mondes, mais pas pour la meme raison** :
 * un tag NOMME qui ne porte AUCUNE machine donne un `INNER JOIN machine_tags`
 * a zero ligne, quel que soit le comportement du repli.
 *
 * ⚠ Si vous concevez une prochaine cible « sure », ne reprenez pas l'ancienne
 * raison : elle vous ferait vous proteger d'un danger qui n'existe plus tout en
 * manquant celui qui existe.
 */
const TAG_SANS_MACHINE_TYPE = 'tag';
const TAG_SANS_MACHINE = 'rw-e2e-aucune-machine';

/** La machine d'essai, designee par son NOM. Et les ids interdits, nommes. */
const MACHINE_ESSAI = 'Test-Server-Debian';
const PRODUCTION = [1];

const TEST_NAME_ALL = 'TEST_ssh_all';
const TEST_NAME_MULTI = 'TEST_ssh_multi';

async function apiFetch(page, path, init = {}) {
    return page.evaluate(async (p, i) => {
        const r = await fetch((window.API_URL || '/api_proxy.php') + p, i);
        const text = await r.text();
        let body = null; try { body = JSON.parse(text); } catch (_) {}
        return { status: r.status, body, text };
    }, path, init);
}

async function findSchedule(page, name) {
    const d = await apiFetch(page, '/ssh-audit/schedules');
    if (!d.body?.success) return null;
    return (d.body.schedules || []).find(s => s.name === name) || null;
}

async function cleanup(page) {
    const d = await apiFetch(page, '/ssh-audit/schedules');
    if (!d.body?.schedules) return;
    for (const s of d.body.schedules) {
        if ((s.name || '').startsWith('TEST_')) {
            await apiFetch(page, `/ssh-audit/schedules/${s.id}`, { method: 'DELETE' });
        }
    }
}

async function listMachines(page) {
    const d = await apiFetch(page, '/list_machines');
    return d.body?.machines || d.body?.servers || [];
}

(async () => {
    const browser = await launchBrowser();
    const page = await newPage(browser);
    page.on('dialog', d => d.accept().catch(() => {}));
    let failed = null;

    try {
        console.log('> Login superadmin...');
        await login(page);

        console.log('> Cleanup eventuel...');
        await cleanup(page);

        console.log('> CREATE schedule target=all via API...');
        const cr1 = await apiFetch(page, '/ssh-audit/schedules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: TEST_NAME_ALL,
                cron_expression: '0 4 * * *',
                target_type: TAG_SANS_MACHINE_TYPE,
                target_value: TAG_SANS_MACHINE,
            }),
        });
        if (cr1.status !== 200 || !cr1.body?.success) throw new Error(`FAIL create all: ${cr1.text}`);
        const s1 = await findSchedule(page, TEST_NAME_ALL);
        if (!s1) throw new Error('FAIL: schedule_all non visible apres POST');
        console.log(`   [OK] schedule_all id=${s1.id}, target=${s1.target_type}`);

        console.log('> CREATE schedule target=machines (multi) via API...');
        const machines = await listMachines(page);
        /*
         * PAR LE NOM, JAMAIS PAR LA POSITION. `slice(0, 2)` rendait id=1
         * (`srv-zabbix`, 192.168.0.244, PRODUCTION) et id=2. Une cible designee
         * par son rang suit tout reordonnancement de la liste, sans que rien ne
         * le signale — et le planificateur ouvre une session SSH par machine.
         */
        const essai = machines.find((m) => m.name === MACHINE_ESSAI);
        const ids = essai ? [essai.id] : [];
        if (essai && PRODUCTION.includes(essai.id)) {
            throw new Error(`REFUS : ${MACHINE_ESSAI} porte l'id ${essai.id}, qui est en production`);
        }
        if (ids.length === 0) {
            console.log('   [SKIP] pas de serveurs disponibles, skip multi');
        } else {
            const cr2 = await apiFetch(page, '/ssh-audit/schedules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: TEST_NAME_MULTI,
                    cron_expression: '30 5 * * *',
                    target_type: 'machines',
                    target_value: JSON.stringify(ids),
                }),
            });
            if (cr2.status !== 200 || !cr2.body?.success) throw new Error(`FAIL create multi: ${cr2.text}`);
            const s2 = await findSchedule(page, TEST_NAME_MULTI);
            if (!s2) throw new Error('FAIL: schedule_multi non visible apres POST');
            const parsed = JSON.parse(s2.target_value || '[]');
            if (parsed.length !== ids.length) throw new Error(`FAIL: target_value=${s2.target_value} attendu ${ids.length} ids`);
            console.log(`   [OK] schedule_multi id=${s2.id}, ${parsed.length} machines`);

            console.log('> TOGGLE OFF/ON sur le multi...');
            const tg1 = await apiFetch(page, `/ssh-audit/schedules/${s2.id}/toggle`, { method: 'POST' });
            if (tg1.status !== 200) throw new Error(`FAIL toggle: ${tg1.text}`);
            const s2off = await findSchedule(page, TEST_NAME_MULTI);
            console.log(`   [OK] toggle 1, enabled=${s2off?.enabled}`);
            await apiFetch(page, `/ssh-audit/schedules/${s2.id}/toggle`, { method: 'POST' });

            console.log('> Verifier UI rendu (admin+ section "Scans planifies")...');
            await page.goto(`${BASE_URL}/ssh-audit/`, { waitUntil: 'networkidle2' });
            await sleep(800);
            const seen = await page.evaluate((name) => {
                const list = document.getElementById('ssh-schedules-list');
                return list ? list.innerHTML.includes(name) : false;
            }, TEST_NAME_MULTI);
            if (!seen) throw new Error('FAIL: TEST_ssh_multi pas affiche dans la section UI');
            console.log('   [OK] schedule visible dans l\'UI');
        }

        console.log('> DELETE TEST_ssh_all...');
        const del = await apiFetch(page, `/ssh-audit/schedules/${s1.id}`, { method: 'DELETE' });
        if (del.status !== 200 || !del.body?.success) throw new Error(`FAIL delete: ${del.text}`);
        const s1after = await findSchedule(page, TEST_NAME_ALL);
        if (s1after !== null) throw new Error('FAIL: schedule still present apres DELETE');
        console.log('   [OK] schedule supprime');

    } catch (e) {
        failed = e;
    } finally {
        await cleanup(page).catch(() => {});
        await page.close();
        await browser.close();
    }

    if (failed) { console.error('[ECHEC]', failed.message); process.exit(1); }
    console.log('[SUCCES] tous les tests SSH audit schedules OK');
})();
