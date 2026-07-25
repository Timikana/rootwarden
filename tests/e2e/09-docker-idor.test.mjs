/**
 * 09-docker-idor.test.mjs - E2E : IDOR sur /docker/results (correctif v1.37.1).
 *
 * Sans machine_id, un role<2 ne doit voir QUE l'inventaire Docker de ses machines
 * accessibles (filtre user_machine_access) ; un admin (role>=2) voit toute la flotte.
 * Avec machine_id, l'acces a une machine non autorisee doit etre refuse (403).
 *
 * Seed docker_inventory pour machine 1 (PROD) + machine 2 (DEV) et un user role=1
 * restreint a la machine 2. 100% DB, aucune action mutante (pas de scan SSH).
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';

const PY = 'rootwarden_python';
const DB = 'rootwarden_db';
const RO_USER = 'e2e_docker_ro';   // user role=1, acces machine 2 uniquement
const M_PROD = 1;                  // srv-zabbix (jamais scanne ici, seulement seed DB)
const M_TEST = 2;                  // Test-Server-Debian
const MARK = '__e2e_didor__';

let API_KEY = '', DB_PW = '', roUserId = 0;

function docker(args) {
    return execFileSync('docker', args, { encoding: 'utf8' }).replace(/\0/g, '').trim();
}
function mysql(sql) {
    return docker(['exec', DB, 'mysql', '-uroot', `-p${DB_PW}`, 'rootwarden', '-N', '-e', sql]);
}
function backend(method, path, userId) {
    const args = ['exec', PY, 'curl', '-sk', '-w', '\\n%{http_code}', '--max-time', '20', '-X', method,
        `https://localhost:5000${path}`, '-H', `X-API-KEY: ${API_KEY}`, '-H', `X-User-ID: ${userId}`];
    let out = '';
    try { out = docker(args); } catch (e) { out = String(e.stdout || '').replace(/\0/g, '').trim(); }
    const nl = out.lastIndexOf('\n');
    const status = parseInt(out.slice(nl + 1), 10);
    let json = null;
    try { json = JSON.parse(out.slice(0, nl)); } catch { /* */ }
    return { status, json, raw: out };
}
function seedContainer(machineId, name) {
    mysql(`INSERT INTO docker_inventory (machine_id, container_name, image, image_tag, state, status, checked_at) `
        + `VALUES (${machineId}, '${name}', 'nginx', 'latest', 'running', 'Up', NOW())`);
}
function cleanup() {
    mysql(`DELETE FROM docker_inventory WHERE container_name LIKE '${MARK}%'`);
}

describe('09 - IDOR /docker/results (v1.37.1)', () => {
    before(() => {
        API_KEY = docker(['exec', PY, 'printenv', 'API_KEY']);
        DB_PW = docker(['exec', DB, 'printenv', 'MYSQL_ROOT_PASSWORD']);
        assert.ok(API_KEY.length > 10 && DB_PW.length > 0, 'secrets conteneur introuvables');
        // user role=1 restreint a la machine 2
        mysql(`INSERT INTO users (name, role_id, active, password, force_password_change) `
            + `VALUES ('${RO_USER}', 1, 1, 'x', 0) ON DUPLICATE KEY UPDATE role_id=1, active=1`);
        roUserId = parseInt(mysql(`SELECT id FROM users WHERE name='${RO_USER}'`), 10);
        mysql(`DELETE FROM user_machine_access WHERE user_id=${roUserId}`);
        mysql(`INSERT INTO user_machine_access (user_id, machine_id) VALUES (${roUserId}, ${M_TEST})`);
        cleanup();
        seedContainer(M_PROD, `${MARK}prod`);
        seedContainer(M_TEST, `${MARK}test`);
    });
    after(() => {
        cleanup();
        if (roUserId) {
            mysql(`DELETE FROM user_machine_access WHERE user_id=${roUserId}`);
            mysql(`DELETE FROM users WHERE id=${roUserId}`);
        }
    });

    const mine = (rows) => rows.filter(r => (r.container_name || '').startsWith(MARK));

    it('admin (superadmin) sans machine_id : voit les 2 machines', () => {
        const r = backend('GET', '/docker/results', 1);
        assert.strictEqual(r.status, 200, r.raw);
        const seen = mine(r.json?.containers || []).map(c => c.machine_id).sort();
        assert.deepStrictEqual([...new Set(seen)], [M_PROD, M_TEST], 'admin devrait voir prod+test');
    });

    it('role<2 sans machine_id : ne voit QUE sa machine (IDOR bloque)', () => {
        const r = backend('GET', '/docker/results', roUserId);
        assert.strictEqual(r.status, 200, r.raw);
        const machines = [...new Set(mine(r.json?.containers || []).map(c => c.machine_id))];
        assert.deepStrictEqual(machines, [M_TEST],
            `role<2 ne devrait voir que la machine ${M_TEST}, vu: ${JSON.stringify(machines)}`);
    });

    it('role<2 avec machine_id d\'une machine non autorisee : 403', () => {
        const r = backend('GET', `/docker/results?machine_id=${M_PROD}`, roUserId);
        assert.strictEqual(r.status, 403, `attendu 403, recu ${r.status} : ${r.raw}`);
    });

    it('role<2 avec sa propre machine : 200', () => {
        const r = backend('GET', `/docker/results?machine_id=${M_TEST}`, roUserId);
        assert.strictEqual(r.status, 200, `attendu 200, recu ${r.status} : ${r.raw}`);
        const machines = [...new Set(mine(r.json?.containers || []).map(c => c.machine_id))];
        assert.deepStrictEqual(machines, [M_TEST]);
    });
});
