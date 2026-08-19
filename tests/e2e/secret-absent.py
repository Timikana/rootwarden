"""
secret-absent.py - Le mot de passe root d'une machine apparait-il dans un texte ?

Sert au test de caracterisation du sous-lot U6 : les deux actions qui diffusent
leur sortie ont porte le mot de passe root en clair jusqu'au correctif du
2026-08-19. Le test doit pouvoir l'affirmer sur le journal REELLEMENT affiche.

Le secret ne quitte JAMAIS le conteneur du backend : le texte a verifier arrive
encode en base64 dans la variable d'environnement TEXTE_B64, et le script ne
repond que par ABSENT ou PRESENT.

Usage (depuis l'hote) :
    docker exec -i -e TEXTE_B64="<base64>" rootwarden_python python - <machine_id>
  avec le contenu de ce fichier sur l'entree standard.

Sortie : "ABSENT|ABSENT" ou "PRESENT|..." — le premier champ pour le mot de
passe entier, le second pour tout fragment de six caracteres.
"""
import base64
import os
import sys

sys.path.insert(0, '/app')

from routes.helpers import get_db_connection, server_decrypt_password  # noqa: E402

TAILLE_FRAGMENT = 6


def secret(machine_id):
    with get_db_connection() as conn:
        curseur = conn.cursor(dictionary=True)
        curseur.execute("SELECT root_password FROM machines WHERE id = %s", (machine_id,))
        ligne = curseur.fetchone()
    if not ligne or not ligne['root_password']:
        return ''
    return server_decrypt_password(ligne['root_password']) or ''


def main():
    machine_id = int(sys.argv[1])
    texte = base64.b64decode(os.environ.get('TEXTE_B64', '')).decode('utf-8', 'replace')

    mot = secret(machine_id)
    if not mot:
        print('SANS-SECRET|SANS-SECRET')
        return 0

    entier = 'PRESENT' if mot in texte else 'ABSENT'

    fragment = 'ABSENT'
    if len(mot) >= TAILLE_FRAGMENT:
        for depart in range(len(mot) - TAILLE_FRAGMENT + 1):
            if mot[depart:depart + TAILLE_FRAGMENT] in texte:
                fragment = 'PRESENT'
                break

    print('%s|%s' % (entier, fragment))
    return 0


if __name__ == '__main__':
    sys.exit(main())
