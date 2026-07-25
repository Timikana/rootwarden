/**
 * 07-maintenance.test.mjs - E2E : fenetres de maintenance (v1.29).
 *
 * Valide la logique d'enforcement is_allowed() ET le CRUD des fenetres :
 *  - superadmin (role 3) contourne toujours (bypass)
 *  - aucune fenetre active => autorise (no-window, defaut permissif)
 *  - fenetre active ne couvrant pas maintenant => bloque (outside-window, role<3)
 *  - fenetre active couvrant maintenant => autorise (in-window)
 *  - CRUD (create/list/update/delete) + validation des heures
 *
 * L'enforcement depend du ROLE : le superadmin bypasse, donc on teste l'etat
 * "bloque" avec un utilisateur role=2 temporaire. Le proxy PHP injecte l'identite
 * de session (superadmin) et ne permet pas de la surcharger -> on interroge le
 * backend directement (X-User-ID) via `docker exec`, ce que fait aussi le proxy.
 * 100% lecture/CRUD DB : aucune action mutante sur un serveur (pas de SSH).
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';

const PY = 'rootwarden_python';
const DB = 'rootwarden_db';
const TEST_MACHINE = 2;            // Test-Server-Debian (DEV), jamais la PROD (id=1)
const RO_USER = 'e2e_maint_ro';    // user role=2 temporaire

// weekday facon Python (lundi=0 .. dimanche=6)
const todayPy = (new Date().getDay() + 6) % 7;
const notToday = (todayPy + 1) % 7;

let API_KEY = '';
let DB_PW = '';
let roUserId = 0;

// execFileSync : arguments passes en tableau, aucun parsing shell (robuste sous Windows).
function docker(args) {
    return execFileSync('docker', args, { encoding: 'utf8' }).replace(/\0/g, '').trim();
}
function mysql(sql) {
    return docker(['exec', DB, 'mysql', '-uroot', `-p${DB_PW}`, 'rootwarden', '-N', '-e', sql]);
}
// Appel backend direct (comme le proxy PHP) : X-API-KEY + X-User-ID.
function backend(method, path, userId, body) {
    const args = ['exec', PY, 'curl', '-sk', '--max-time', '20', '-X', method,
        `https://localhost:5000${path}`,
        '-H', `X-API-KEY: ${API_KEY}`, '-H', `X-User-ID: ${userId}`,
        '-H', 'Content-Type: application/json'];
    if (body) args.push('-d', JSON.stringify(body));
    let out = '';
    try { out = docker(args); } catch (e) { out = String(e.stdout || '').replace(/\0/g, '').trim(); }
    try { return { json: JSON.parse(out), raw: out }; }
    catch { return { json: null, raw: out }; }
}
function check(userId) {
    return backend('GET', `/maintenance/check?machine_id=${TEST_MACHINE}`, userId).json;
}
function createWindow(days, start, end, enabled = true, scope = 'global') {
    return backend('POST', '/maintenance/windows', 1,
        { name: `__e2e_maint__${start}_${end}`, scope, days, start_time: start, end_time: end, enabled }).json;
}
function deleteAllTestWindows() {
    const ids = mysql("SELECT id FROM maintenance_windows WHERE name LIKE '\\_\\_e2e_maint\\_\\_%'")
        .split('\n').map(s => s.trim()).filter(Boolean);
    for (const id of ids) backend('DELETE', `/maintenance/windows/${id}`, 1);
}

describe('07 - Fenetres de maintenance (enforcement + CRUD)', () => {
    before(() => {
        API_KEY = docker(['exec', PY, 'printenv', 'API_KEY']);
        DB_PW = docker(['exec', DB, 'printenv', 'MYSQL_ROOT_PASSWORD']);
        assert.ok(API_KEY.length > 10, 'API_KEY introuvable dans le conteneur python');
        assert.ok(DB_PW.length > 0, 'MYSQL_ROOT_PASSWORD introuvable');
        // user role=2 temporaire (mot de passe bidon non utilise : on tape le backend en direct)
        mysql(`INSERT INTO users (name, role_id, active, password, force_password_change) `
            + `VALUES ('${RO_USER}', 2, 1, 'x', 0) `
            + `ON DUPLICATE KEY UPDATE role_id=2, active=1`);
        roUserId = parseInt(mysql(`SELECT id FROM users WHERE name='${RO_USER}'`), 10);
        assert.ok(roUserId > 0, 'user role-2 non cree');
        mysql(`INSERT IGNORE INTO user_machine_access (user_id, machine_id) VALUES (${roUserId}, ${TEST_MACHINE})`);
        deleteAllTestWindows();
    });

    after(() => {
        deleteAllTestWindows();
        if (roUserId) {
            mysql(`DELETE FROM user_machine_access WHERE user_id=${roUserId}`);
            mysql(`DELETE FROM users WHERE id=${roUserId}`);
        }
    });

    it('sans fenetre : autorise (no-window)', () => {
        const r = check(roUserId);
        assert.strictEqual(r?.allowed, true, JSON.stringify(r));
        assert.strictEqual(r?.reason, 'no-window', JSON.stringify(r));
    });

    it('superadmin : bypass meme avec une fenetre bloquante', () => {
        createWindow([notToday], '01:00', '02:00', true); // ne couvre pas aujourd'hui
        const r = check(1); // superadmin
        assert.strictEqual(r?.allowed, true, JSON.stringify(r));
        assert.strictEqual(r?.reason, 'superadmin-bypass', JSON.stringify(r));
    });

    it('role<3 hors fenetre : bloque (outside-window)', () => {
        // la fenetre creee ci-dessus (jour != aujourd'hui) est toujours active
        const r = check(roUserId);
        assert.strictEqual(r?.allowed, false, JSON.stringify(r));
        assert.strictEqual(r?.reason, 'outside-window', JSON.stringify(r));
    });

    it('role<3 dans la fenetre : autorise (in-window)', () => {
        deleteAllTestWindows();
        createWindow([0, 1, 2, 3, 4, 5, 6], '00:00', '23:59', true); // couvre maintenant
        const r = check(roUserId);
        assert.strictEqual(r?.allowed, true, JSON.stringify(r));
        assert.strictEqual(r?.reason, 'in-window', JSON.stringify(r));
    });

    it('CRUD : create / list / update(enabled=0) / delete', () => {
        deleteAllTestWindows();
        const created = createWindow([todayPy], '03:00', '04:00', true);
        assert.strictEqual(created?.success, true, JSON.stringify(created));
        const wid = created.id;

        const list = backend('GET', '/maintenance/windows', 1).json;
        assert.ok((list?.windows || []).some(w => w.id === wid), 'fenetre absente de la liste');

        // desactiver -> la fenetre ne s'applique plus -> role-2 repasse en no-window
        const upd = backend('PUT', `/maintenance/windows/${wid}`, 1, { enabled: false }).json;
        assert.strictEqual(upd?.success, true, JSON.stringify(upd));
        assert.strictEqual(check(roUserId)?.reason, 'no-window', 'fenetre desactivee encore appliquee');

        const del = backend('DELETE', `/maintenance/windows/${wid}`, 1).json;
        assert.strictEqual(del?.deleted, true, JSON.stringify(del));
    });

    it('validation : heure invalide rejetee (400)', () => {
        const r = backend('POST', '/maintenance/windows', 1,
            { name: '__e2e_maint__bad', scope: 'global', days: [todayPy], start_time: '25:99', end_time: '26:00', enabled: true });
        assert.strictEqual(r.json?.success, false, JSON.stringify(r.json));
    });
});
