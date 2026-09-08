/*
 * HORS-LOT: ouvre un navigateur VISIBLE sur /supervision/ pour observer a la
 * main. 21 lignes, aucune assertion, aucun verdict — elle n'a rien a rendre a
 * un lot, et `headless: false` la rend inutilisable sans ecran.
 *
 * Elle n'ecrit pas : la seule navigation est un GET vers /supervision/. C'est
 * bien un outil, mais elle reste dans la population surveillee — un fichier qui
 * ouvre une session doit etre VU par l'inventaire, meme quand il est inoffensif.
 * La classer hors population l'aurait rendue invisible pour la seule raison
 * qu'elle est benigne aujourd'hui.
 */
import puppeteer from 'puppeteer';
import { login, BASE_URL } from './helpers.mjs';

const browser = await puppeteer.launch({
    headless: false,
    args: ['--no-sandbox', '--ignore-certificate-errors', '--allow-insecure-localhost', '--start-maximized'],
    defaultViewport: { width: 1400, height: 900 }
});

const page = await browser.newPage();
await page.setViewport({ width: 1400, height: 900 });

console.log('Login...');
await login(page);
console.log('URL:', page.url());

console.log('Navigation vers /supervision/...');
await page.goto(`${BASE_URL}/supervision/`, { waitUntil: 'networkidle2' });
console.log('Page ouverte - navigateur visible. Ctrl+C pour fermer.');

await new Promise(() => {});
