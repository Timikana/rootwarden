# E-224 — la borne, proposée avant l'écriture

Session 4, **2026-08-28**. Le Lead a demandé la borne **avant** le correctif : *un défaut qui protège
par accident cesse de protéger au moment exact où on le corrige.* Voici ce que j'ai mesuré, et ce que
je propose. **Rien n'est écrit.**

---

## 1. La faute, et la bonne écriture à quelques lignes

```sql
-- wazuh.py:467, install_all
LEFT JOIN wazuh_agents a ON a.machine_id = m.id
WHERE … AND a.id IS NULL          -- ⚠ wazuh_agents n'a AUCUNE colonne `id`
```

`034_wazuh.sql:42` — `machine_id INT NOT NULL PRIMARY KEY`. Le prédicat correct est
`a.machine_id IS NULL`. **L'`execute()` fautif n'est dans aucun `try`** (le seul bloc `try` de la
fonction est ailleurs) : la route rend **500**.

`wazuh.py:298` porte le **même** `LEFT JOIN` sans la faute. Elle n'a jamais explosé parce qu'elle ne
teste rien sur la table jointe.

---

## 2. ⚠ CE QUE LA CORRECTION DÉCLENCHERAIT — mesuré, pas supposé

`wazuh_agents` porte **0 ligne**. Avec `a.machine_id IS NULL`, la requête rend **tout le parc**, dans
cet ordre :

| ordre | machine | criticité |
|---|---|---|
| **1** | **`srv-zabbix`** | **CRITIQUE** ← la production |
| 2 | `OpenCVE-Test-OnPrem` | NON CRITIQUE |
| 3 | `Test-Server-Debian` | NON CRITIQUE |

L'`ORDER BY … CASE WHEN criticality = 'CRITIQUE' THEN 0` **place la production en tête**.

### Et ce n'est pas un bouton qu'il faudrait cliquer

```php
legacy/adm/health_check.php:154
['Wazuh Install All (dry)', 'POST', '/wazuh/install_all', [], '… - dry, vide la liste'],
```

`health_check.php:200` boucle sur ces entrées et appelle `testRoute()`, qui fait un **vrai `curl`
POST**. **Ouvrir la page de diagnostic déclenche donc l'appel**, avec un corps vide.

> **Le mot « dry » de ce commentaire décrit un accident, pas une conception.** La liste revient vide
> parce que la requête échoue. **Le jour où E-224 est corrigé, ouvrir une page d'administration
> installe un paquet sur la production.** Personne n'aura cliqué sur « installer ».

C'est la forme la plus dangereuse du motif que ce chantier compte : *une conclusion écrite fait
renoncer à mesurer*. Quelqu'un a écrit « dry », et plus personne n'a regardé.

---

## 3. La borne — et pourquoi le seul précédent du produit ne convient PAS

**Une seule route de parc se borne**, sur dix-sept : `/supervision/scan-all`, par `machine_ids`
explicite **plus** `check_machine_access` machine par machine dans le corps.

**Copier ce précédent produirait ici une borne qui ne borne pas.** `check_machine_access` rend `True`
**sans condition dès le rôle 2**, et `install_all` porte `@require_role(2)` : le filtre serait
**inerte pour exactement son public**. C'est le défaut « un garde sans objet ne garde rien », et le
recopier serait la cinquième occurrence.

### Ce que je propose : `machine_ids` OBLIGATOIRE

```
absent ou vide  ->  400, aucune machine touchée
```

Trois raisons, dans cet ordre :

1. **L'appel du `health_check` a un corps vide.** Avec un paramètre obligatoire, il devient un `400`
   — **il échoue fermé**, sans qu'il faille se souvenir de modifier la page ;
2. **La page Wazuh a déjà la liste.** `wazuh.js:82` affiche le compte `noAgent` : elle connaît les
   machines sans agent, elle peut les envoyer. Le bouton « Installer sur tous » garde son sens, et
   son sens devient **explicite** ;
3. *Ne pas offrir d'entrée libre plutôt que la valider* — **un périmètre absent n'est pas un
   périmètre**. C'est ce que la maison applique déjà quand elle refuse une cible implicite.

### Ce que je ne propose PAS, et pourquoi

**Un filtre sur `criticality`.** Ce serait inventer une politique : `criticality` est une étiquette
d'inventaire, pas une autorisation, et rien ne garantit qu'elle soit tenue à jour. *Une règle de
sécurité se dérive de sa source ; elle ne s'invente pas depuis une colonne descriptive.*

---

## 4. ⚠ L'ORDRE DE LIVRAISON EST LA MOITIÉ DU CORRECTIF

**Le correctif SQL seul est plus dangereux que le défaut.** Deux ordres acceptables :

1. `machine_ids` obligatoire **et** le SQL **dans le même commit** — l'appel du `health_check` tombe
   en `400` dès la première requête ;
2. ou bien retirer l'entrée du `health_check` **d'abord**, puis corriger.

**Jamais le SQL seul.** Entre les deux livraisons, ouvrir une page d'administration installerait un
paquet sur `srv-zabbix`.

`legacy/adm/health_check.php` **n'est pas mon périmètre** : la ligne 154 est à retirer ou à borner
par quelqu'un d'autre. Je la signale, je ne la touche pas.

---

## 5. Une correction de ma propre sonde, la septième

Mon relevé automatique des routes de parc a classé `install_all` comme portant un **« filtre
criticité »**. **Faux** : `criticality` n'y apparaît que dans l'`ORDER BY`, qui est l'**inverse**
d'une borne — il met la production en premier.

**Et l'erreur allait encore dans le sens rassurant.** C'est la deuxième fois en deux jours ; le Lead
vient de signaler la même chose sur lui-même. *Rien ne prévient quand l'erreur rassure* — seule la
lecture du corps l'a montrée.

---

# E-225 — un geste réversible qui ne rend pas ce qu'il a pris

**Documenté, pas corrigé** : c'est un arbitrage d'exploitant.

## Ce que l'installation pose

```bash
# wazuh.py:366-368  ET  wazuh.py:525-527 — la meme sequence, ecrite DEUX FOIS
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg … --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
```

## Ce que la désinstallation rend

```bash
# wazuh.py:694-695
apt-get purge -y wazuh-agent 2>/dev/null || true && rm -rf /var/ossec
```

**Le paquet et ses données. Pas la clé de signature, pas le dépôt.**

> Ce qui subsiste n'est pas un fichier de configuration : c'est une **relation de confiance**. La
> machine continue d'accepter comme légitime tout paquet signé par cette clé, et de consulter ce
> dépôt à chaque `apt-get update` — y compris pendant les mises à jour de sécurité, qui sont un geste
> de parc de ce même produit.

**Même forme qu'E-220**, appliquée à une relation de confiance au lieu d'un droit `sudo` : *un geste
réversible qui ne rend pas tout ce qu'il a pris n'est pas réversible — il est partiel, et le reste
est invisible.*

## Pourquoi je ne le corrige pas

**Un exploitant peut légitimement vouloir garder le dépôt** pour réinstaller sans refaire l'amorçage.
C'est un choix défendable. **Ce qui ne l'est pas, c'est que le geste ne le dise pas** : le bouton
s'appelle « désinstaller », et rien dans la réponse ne mentionne ce qui reste.

Trois issues, par ordre de coût, et **aucune n'est mon arbitrage** :

1. **le dire** — la réponse de `uninstall` nomme ce qui subsiste ; aucun changement de comportement ;
2. **l'offrir** — un drapeau `retirer_depot`, par défaut à ce que l'exploitant choisit ;
3. **le retirer** — et alors une réinstallation refait l'amorçage complet.

## Deux dédouanements, dits aussi nettement

- **`wazuh.py` est le module le plus uniformément gardé du chantier** : les **15** routes portent
  `@require_api_key` + `@require_role(2)` + `@require_permission('can_manage_wazuh')`. **Le premier
  module où la page n'est pas plus permissive que ses requêtes.**
- La clé est importée dans un **keyring dédié** (`/usr/share/keyrings/wazuh.gpg`) et le dépôt est
  `signed-by=` ce keyring. **Ce n'est pas un `apt-key add`** : la confiance est **limitée à ce
  dépôt**, elle n'est pas globale. C'est la bonne pratique, et elle réduit nettement la portée de ce
  qui subsiste.

## Et une redite à signaler au passage

La séquence d'amorçage est écrite **deux fois** (`:366` et `:525`). Ni l'une ni l'autre n'est fausse
aujourd'hui — c'est exactement l'état des cinq `_resolve_ssh_creds` la veille de leur divergence.
*Elles sont d'accord jusqu'à ce que l'une bouge.*
