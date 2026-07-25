/**
 * 08-approvals.test.mjs - E2E : workflow d'approbation 4-eyes (v1.30).
 *
 * Valide la regle centrale : un admin ne peut pas approuver SA PROPRE demande
 * (approved_by != requested_by), y compris le superadmin (pas de bypass dans la
 * route de decision). Plus : approbation par un tiers, rejet, demande deja
 * traitee (409), et le flag is_own dans la liste.
 *
 * Les demandes sont creees en base (approvals.gate() les cree normalement quand
 * APPROVAL_ENABLED=1 ; pas d'endpoint public de creation). Les decisions passent
 * par le backend direct (X-User-ID, comme le proxy PHP). 100% DB, aucune action
 * mutante sur un serveur.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';

const PY = 'rootwarden_python';
const DB = 'rootwarden_db';
const SUPERADMIN = 1;   // requested_by pour le cas "propre demande"
const OTHER = 2;        // opsuser : requested_by pour le cas "demande d'un tiers"

let API_KEY = '';
let DB_PW = '';

function docker(args) {
    return execFileSync('docker', args, { encoding: 'utf8' }).replace(/\0/g, '').trim();
}
function mysql(sql) {
    return docker(['exec', DB, 'mysql', '-uroot', `-p${DB_PW}`, 'rootwarden', '-N', '-e', sql]);
}
function backend(method, path, userId, body) {
    const args = ['exec', PY, 'curl', '-sk', '-w', '\\n%{http_code}', '--max-time', '20', '-X', method,
        `https://localhost:5000${path}`,
        '-H', `X-API-KEY: ${API_KEY}`, '-H', `X-User-ID: ${userId}`,
        '-H', 'Content-Type: application/json'];
    if (body) args.push('-d', JSON.stringify(body));
    let out = '';
    try { out = docker(args); } catch (e) { out = String(e.stdout || '').replace(/\0/g, '').trim(); }
    const nl = out.lastIndexOf('\n');
    const status = parseInt(out.slice(nl + 1), 10);
    let json = null;
    try { json = JSON.parse(out.slice(0, nl)); } catch { /* */ }
    return { status, json, raw: out };
}
function seedRequest(requestedBy, status = 'pending') {
    mysql(`INSERT INTO approval_requests (action_type, machine_id, target, payload, status, requested_by, created_at, expires_at) `
        + `VALUES ('reboot_server', 2, '__e2e_appr__', '{}', '${status}', ${requestedBy}, NOW(), DATE_ADD(NOW(), INTERVAL 1 DAY))`);
    return parseInt(mysql("SELECT MAX(id) FROM approval_requests WHERE target='__e2e_appr__'"), 10);
}
function cleanup() {
    mysql("DELETE FROM approval_requests WHERE target='__e2e_appr__'");
}

describe('08 - Approbation 4-eyes (v1.30)', () => {
    before(() => {
        API_KEY = docker(['exec', PY, 'printenv', 'API_KEY']);
        DB_PW = docker(['exec', DB, 'printenv', 'MYSQL_ROOT_PASSWORD']);
        assert.ok(API_KEY.length > 10 && DB_PW.length > 0, 'secrets conteneur introuvables');
        cleanup();
    });
    after(cleanup);

    it('4-eyes : approuver SA PROPRE demande est refuse (403), meme superadmin', () => {
        const id = seedRequest(SUPERADMIN);
        const r = backend('POST', `/approvals/${id}/approve`, SUPERADMIN, { reason: 'self' });
        assert.strictEqual(r.status, 403, `attendu 403, recu ${r.status} : ${r.raw}`);
        assert.strictEqual(r.json?.success, false);
        // reste pending en base
        assert.strictEqual(mysql(`SELECT status FROM approval_requests WHERE id=${id}`), 'pending');
    });

    it('approuver la demande d\'un TIERS reussit (approved_by != requested_by)', () => {
        const id = seedRequest(OTHER);
        const r = backend('POST', `/approvals/${id}/approve`, SUPERADMIN, { reason: 'ok' });
        assert.strictEqual(r.status, 200, `attendu 200, recu ${r.status} : ${r.raw}`);
        assert.strictEqual(r.json?.status, 'approved', JSON.stringify(r.json));
        const row = mysql(`SELECT status, approved_by FROM approval_requests WHERE id=${id}`).split('\t');
        assert.strictEqual(row[0], 'approved');
        assert.strictEqual(row[1], String(SUPERADMIN));
    });

    it('rejeter la demande d\'un tiers reussit', () => {
        const id = seedRequest(OTHER);
        const r = backend('POST', `/approvals/${id}/reject`, SUPERADMIN, { reason: 'non' });
        assert.strictEqual(r.status, 200, `attendu 200, recu ${r.status} : ${r.raw}`);
        assert.strictEqual(mysql(`SELECT status FROM approval_requests WHERE id=${id}`), 'rejected');
    });

    it('demande deja traitee : approbation refusee (409)', () => {
        const id = seedRequest(OTHER, 'approved');
        const r = backend('POST', `/approvals/${id}/approve`, SUPERADMIN, { reason: 'retry' });
        assert.strictEqual(r.status, 409, `attendu 409, recu ${r.status} : ${r.raw}`);
    });

    it('liste /approvals?status=pending : is_own reflete requested_by', () => {
        const own = seedRequest(SUPERADMIN);
        const other = seedRequest(OTHER);
        const r = backend('GET', '/approvals?status=pending', SUPERADMIN);
        assert.strictEqual(r.status, 200);
        const rows = r.json?.approvals || [];
        const ownRow = rows.find(x => x.id === own);
        const otherRow = rows.find(x => x.id === other);
        assert.ok(ownRow && otherRow, 'demandes pending absentes de la liste');
        assert.strictEqual(ownRow.is_own, true, 'is_own devrait etre true pour sa propre demande');
        assert.strictEqual(otherRow.is_own, false, 'is_own devrait etre false pour la demande d\'un tiers');
    });
});
