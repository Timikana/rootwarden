"""
cron-machine.py - Lit ou efface un fichier de /etc/cron.d/ sur une machine du parc.

Sert au test de caracterisation du sous-lot U4 : une planification qui n'est pas
RELUE sur la machine n'est pas prouvee. Le script s'execute DANS le conteneur du
backend, qui est le seul a savoir dechiffrer les mots de passe et a joindre le
parc en SSH.

Il n'IMPRIME jamais de secret : seulement le contenu du fichier cron demande.

Usage (depuis l'hote) :
    docker exec -i rootwarden_python python - lit    <machine_id> <chemin>
    docker exec -i rootwarden_python python - efface <machine_id> <chemin>
    docker exec -i rootwarden_python python - oublie-maj-secu <machine_id>
  avec le contenu de ce fichier sur l'entree standard.

La derniere action remet `machines.maj_secu_date` a NULL : la planification de
securite l'ecrit en base, et le test doit rendre la fixture telle qu'il l'a
trouvee.
"""
import sys

sys.path.insert(0, '/app')

from routes.helpers import get_db_connection, server_decrypt_password  # noqa: E402
from ssh_utils import ssh_session, execute_as_root  # noqa: E402

ABSENT = 'ABSENT'


def machine(machine_id):
    with get_db_connection() as conn:
        curseur = conn.cursor(dictionary=True)
        curseur.execute(
            "SELECT ip, port, user, password, root_password, service_account_deployed "
            "FROM machines WHERE id = %s",
            (machine_id,),
        )
        return curseur.fetchone()


def sortie_texte(resultat):
    """`execute_as_root` rend soit une chaine, soit (stdout, stderr, code)."""
    if isinstance(resultat, (tuple, list)):
        return resultat[0]
    return resultat or ''


def oublie_maj_secu(machine_id):
    with get_db_connection() as conn:
        curseur = conn.cursor()
        curseur.execute("UPDATE machines SET maj_secu_date = NULL WHERE id = %s", (machine_id,))
        conn.commit()
    print('OUBLIE')


def main():
    action = sys.argv[1]
    machine_id = int(sys.argv[2])

    if action == 'oublie-maj-secu':
        oublie_maj_secu(machine_id)
        return 0

    chemin = sys.argv[3]

    ligne = machine(machine_id)
    if not ligne:
        print('MACHINE INTROUVABLE')
        return 1

    mdp_ssh = server_decrypt_password(ligne['password'])
    mdp_root = server_decrypt_password(ligne['root_password'])

    if action == 'lit':
        commande = "cat %s 2>/dev/null || echo %s" % (chemin, ABSENT)
    elif action == 'efface':
        commande = "rm -f %s && echo EFFACE" % chemin
    else:
        print('ACTION INCONNUE')
        return 1

    with ssh_session(ligne['ip'], ligne['port'], ligne['user'], mdp_ssh,
                     service_account=ligne.get('service_account_deployed', False)) as client:
        print(sortie_texte(execute_as_root(client, commande, mdp_root)).strip())
    return 0


if __name__ == '__main__':
    sys.exit(main())
