/**
 * code-totp.mjs - Imprime le code a six chiffres d'un compte de test.
 *
 * Aucun chemin d'authentification ne passe sans second facteur : pour se
 * connecter a la main, il faut ce code. Les secrets des comptes `rw-test-*` sont
 * des vecteurs deterministes, deja ecrits dans `go-socle-auth.mjs` — ce script
 * les LIT LA-BAS plutot que de les redemander ou de les recopier ailleurs. Le
 * secret ne circule donc pas, et il n'existe qu'a un seul endroit.
 *
 * Usage, depuis la VM :
 *   cd tests/e2e
 *   node code-totp.mjs                 # rw-test-admin par defaut
 *   node code-totp.mjs rw-test-super
 *   node code-totp.mjs rw-test-user
 *
 * Depuis un autre poste :
 *   ssh <vm> 'cd ~/Documents/Gestion_SSH_KEY/tests/e2e && node code-totp.mjs'
 *
 * Le mot de passe des trois comptes est celui de `E2E_TEST_PASS`, defaut
 * `RootWarden@2026-Test!`. Le code, lui, change toutes les 30 secondes : si la
 * fenetre restante affichee est courte, relancer plutot que de le saisir a la
 * hate — un code rejoue est refuse par le garde anti-rejeu du portage.
 */
import { readFileSync } from 'fs';
import { createHmac } from 'crypto';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const compte = process.argv[2] || 'rw-test-admin';
const ici = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(ici, 'go-socle-auth.mjs'), 'utf-8');

const trouve = source.match(new RegExp(`'${compte}'[^}]*secret:\\s*'([A-Z2-7]+)'`));
if (! trouve) {
    console.error(`Secret introuvable pour « ${compte} ». Comptes connus : `
        // Les comptes y sont declares `{ nom: 'rw-test-x', … }` et non
        // `'rw-test-x': {…}` : un motif trop etroit rendait une liste VIDE, donc
        // un message d'aide qui n'aide personne. Dedoublonne, l'ordre du fichier
        // n'ayant aucune raison d'etre unique.
        + [...new Set([...source.matchAll(/'(rw-test-[a-z]+)'/g)].map(m => m[1]))].join(', '));
    process.exit(1);
}

function base32(s) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const c of s.toUpperCase().replace(/=+$/, '')) {
        const v = alphabet.indexOf(c);
        if (v !== -1) bits += v.toString(2).padStart(5, '0');
    }
    const octets = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) octets.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(octets);
}

const compteur = Buffer.alloc(8);
compteur.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
const h = createHmac('sha1', base32(trouve[1])).update(compteur).digest();
const decalage = h[h.length - 1] & 0x0f;
const code = ((h.readUInt32BE(decalage) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
const reste = 30 - (Math.floor(Date.now() / 1000) % 30);

console.log(`${compte}  ->  ${code}   (encore ${reste} s${reste < 8 ? ' — mieux vaut relancer' : ''})`);
