# Registre des suites HORS LOT

**Mesure du 2026-09-02 00:25 CEST.** Un registre a le droit de se perimer tant qu'il
porte sa date et la commande qui le refait ; un garde, non — ce fichier n'est
donc PAS un garde, et rien dans `rejouer-lot.sh` ne s'y refere pour decider.

## Commande de remesure

```bash
# les suites REELLEMENT jouees se lisent dans les tableaux du runner, jamais
# par `grep <nom> rejouer-lot.sh` : le runner MENTIONNE beaucoup de suites dans
# ses commentaires. Ce grep-la rendait 24 au lieu de 40.
python3 - <<'EOF'
import re, os
src = open('scripts/rejouer-lot.sh', encoding='utf-8').read()
def tab(nom):
    m = re.search(rf'^{nom}=\(', src, re.M); i, p, d = m.end()-1, 0, m.end()-1
    while i < len(src):
        if src[i] == '(': p += 1
        elif src[i] == ')':
            p -= 1
            if p == 0: break
        i += 1
    c = '\n'.join(l.split('#')[0] for l in src[d+1:i].split('\n'))
    return [x for x in c.split() if x]
jouees = set(tab('SUITES_LARAVEL')) | set(tab('SUITES_LEGACY'))
fichiers = sorted(f[:-4] for f in os.listdir('tests/e2e') if f.endswith('.mjs')
                  and not re.match(r'^(lib-|helpers|code-totp|archive|_screenshot)', f))
print(len([f for f in fichiers if f not in jouees]), 'hors LOT sur', len(fichiers))
EOF
```

## Chiffres

```
SUITES_LARAVEL   80          SUITES_LEGACY   78     ->  158 executions
suites distinctes jouees   83
fichiers de suite         123   (hors lib-*, helpers, code-totp, archive, _screenshot)
HORS LOT                   40   soit 33 %
```

**Le LOT annonce 158 executions ; ce n'est pas une couverture du corpus.**
Un tiers des fichiers de suite n'est jamais joue, et jusqu'a ce registre rien
ne distinguait « exclue a bon droit » d'« oubliee ».

## Inventaire

| suite | derniere ecriture | cible | motif d'exclusion |
|---|---|---|---|
| `go-ssh-audit-scanall` | 2026-09 | legacy | DANGER : joint la PRODUCTION |
| `go-captures-enrolement` | 2026-08 | portage | captures — a REGARDER, pas a asserter |
| `go-captures-fail2ban` | 2026-08 | portage | captures — a REGARDER, pas a asserter |
| `go-captures-graylog` | 2026-08 | portage | captures — a REGARDER, pas a asserter |
| `go-captures-maintenance` | 2026-08 | portage | captures — a REGARDER, pas a asserter |
| `go-captures-socle` | 2026-08 | portage | captures — a REGARDER, pas a asserter |
| `go-adm-import-csv` | 2026-08 | portage | motif ECRIT dans `rejouer-lot.sh:1028-1050` |
| `01-login.test` | 2026-04 | legacy | anterieure au chantier de migration |
| `02-admin-users.test` | 2026-04 | legacy | anterieure au chantier de migration |
| `go-admin-full` | 2026-04 | legacy | se connecte en `superadmin` — voir §2 |
| `go-cve-schedules` | 2026-04 | legacy | se connecte en `superadmin` — voir §2 |
| `go-quick` | 2026-04 | legacy | se connecte en `superadmin` — voir §2 |
| `go-security` | 2026-04 | legacy | anterieure au chantier de migration |
| `go-ssh-audit-schedules` | 2026-04 | legacy | se connecte en `superadmin` — voir §2 |
| `go-ssh-keys-inventory` | 2026-04 | legacy | se connecte en `superadmin` — voir §2 |
| `go-supervision-profiles` | 2026-04 | legacy | se connecte en `superadmin` — voir §2 |
| `go-wazuh` | 2026-04 | legacy | anterieure au chantier de migration |
| `go-wazuh-toggle` | 2026-04 | legacy | anterieure au chantier de migration |
| `open-supervision` | 2026-04 | legacy | anterieure au chantier de migration |
| `smoke-v1.17` | 2026-04 | legacy | se connecte en `superadmin` — voir §2 |
| `smoke-wazuh-off` | 2026-04 | legacy | anterieure au chantier de migration |
| `test-full-deploy` | 2026-04 | legacy | anterieure au chantier de migration |
| `go-access-sudo-visual` | 2026-06 | legacy | se connecte en `superadmin` — voir §2 |
| `go-func-v1.23` | 2026-06 | legacy | se connecte en `superadmin` — voir §2 |
| `go-policies-visual` | 2026-06 | legacy | se connecte en `superadmin` — voir §2 |
| `03-permissions.test` | 2026-07 | legacy | anterieure au chantier de migration |
| `04-ssh-preflight.test` | 2026-07 | legacy | anterieure au chantier de migration |
| `05-cve-scan.test` | 2026-07 | legacy | anterieure au chantier de migration |
| `07-maintenance.test` | 2026-07 | legacy | anterieure au chantier de migration |
| `08-approvals.test` | 2026-07 | legacy | anterieure au chantier de migration |
| `09-docker-idor.test` | 2026-07 | legacy | anterieure au chantier de migration |
| `go-bashrc` | 2026-07 | legacy | se connecte en `superadmin` — voir §2 |
| `go-graylog` | 2026-07 | legacy | anterieure au chantier de migration |
| `go-policies` | 2026-07 | legacy | se connecte en `superadmin` — voir §2 |
| `06-supervision.test` | 2026-08 | legacy | se connecte en `superadmin` — voir §2 |
| `go` | 2026-08 | legacy | se connecte en `superadmin` — voir §2 |
| `go-access-toggle-refresh` | 2026-08 | legacy | se connecte en `superadmin` — voir §2 |
| `go-sec-v1.23` | 2026-08 | legacy | se connecte en `superadmin` — voir §2 |
| `go-security-fixes` | 2026-08 | legacy | se connecte en `superadmin` — voir §2 |
| `go-supervision-profile-assign` | 2026-08 | legacy | se connecte en `superadmin` — voir §2 |


## §2 — DIX-NEUF DE CES SUITES SONT AUJOURD'HUI INUTILISABLES

`superadmin` (id 1) porte **`force_password_change = 1`**, depuis la base de
depart. Le middleware `ChangementMotDePasseExige` redirige donc **toute page du
portage** vers `/profil?force_change=1` pour ce compte.

    19 suites hors LOT emploient `superadmin`  ->  elles seraient redirigees
     0 suite  DU LOT   ne l'emploie            ->  le LOT est immunise

**C'est pour ça que personne ne l'a vu** : la seule population touchee est celle
qu'on ne joue pas. Et le symptome serait le pire possible — « 0 ancre rendue »,
qui ressemble exactement a une page cassee, alors que c'est une REDIRECTION.

⚠ **Ma premiere sonde en trouvait TROIS.** Elle cherchait `type('input[name=
"username"]', 'superadmin')` et les constantes `USER = 'superadmin'` ; elle
ratait `const user = process.env.E2E_USER || 'superadmin'` et les
`console.log('Login superadmin')`. **Facteur six, et du cote qui RASSURE** — la
contre-epreuve au motif large etait necessaire, et elle ne l'aurait pas ete si
je n'avais pas su que ma sonde etait etroite.

**Rien n'est corrige ici** : remettre ce drapeau a 0 masquerait la seule chose
qui rappelle que le portail exige un changement de mot de passe jamais fait.
*Un correctif qui efface le symptome d'un fait non traite n'est pas un
correctif, c'est un silence.* C'est a l'exploitant de trancher.

## §3 — L'ORIGINE DES COMPTES `e2e_test_*` RESIDUELS

`02-admin-users.test.mjs` (hors LOT) nomme son compte **`e2e_test_${Date.now()}`**
— un nom NEUF a chaque execution, qu'aucun nettoyage d'entree ne peut rattraper.

C'est la cause des **cinq comptes `e2e_test_*` actifs, de role 1**, trouves le
2026-09-01 en mesurant l'onglet `accueil` : ils comptent dans les « 12 comptes
actifs » et dans les « 12 sans cle SSH » que le tableau de bord affiche.
**L'indicateur `12/12` est donc sature en partie par du dechet de banc.** Le
chiffre reste juste ; sa signification change.

`rejouer-lot.sh` documente deja cette famille (`:1041`) en la distinguant de
`go-adm-import-csv`, dont le nettoyage par NOM EXACT est sain. **La difference
est structurelle, pas une question de soin** : on ne nettoie pas un nom qu'on ne
peut pas prevoir.
