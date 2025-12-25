
#!/usr/bin/env python3
import os
import sys

# ================= UTIL =================
def clear():
    os.system("clear")

def pause():
    input("\n[Appuie sur Entrée pour continuer]")

# ================= UI =================
def banner():
    print(r"""
██╗   ██╗ ██████╗      ██╗ ██████╗ ██╗  ██╗
╚██╗ ██╔╝██╔═══██╗     ██║██╔═══██╗╚██╗██╔╝
 ╚████╔╝ ██║   ██║     ██║██║   ██║ ╚███╔╝ 
  ╚██╔╝  ██║   ██║██   ██║██║   ██║ ██╔██╗ 
   ██║   ╚██████╔╝╚█████╔╝╚██████╔╝██╔╝ ██╗
   ╚═╝    ╚═════╝  ╚════╝  ╚═════╝ ╚═╝  ╚═╝

Bonjour,je préviens que c'est la première version de mon outil et qu'il aura des améliorations. 
YOJOX v1 – Outil de cybersécurité
Createur : Jonas Sleiman
Platform : Linux
Mode : Éducatif / Legal uniquement
""")

# ==================================================
# ================== COURS =========================
# ==================================================

def course_osint():
    clear()
    print("📘 COURS – OSINT \n")
    print("""
OSINT = Open Source Intelligence.

C’est la collecte d’informations accessibles publiquement :
- moteurs de recherche
- réseaux sociaux publics
- DNS / Whois
- forums, articles

Pourquoi c’est important ?
Avant de sécuriser un système, il faut savoir
ce que TOUT LE MONDE peut déjà voir.

OSINT sert à :
✔ audit
✔ enquête
✔ prévention
❌ pas espionner
""")
    pause()

def course_nmap():
    clear()
    print("📘 COURS – NMAP\n")
    print("""
Nmap est un scanner réseau.

Imagine un bâtiment :
- chaque port = une porte
- Nmap vérifie quelles portes sont ouvertes

Utilisé par :
- admins système
- équipes sécurité
- étudiants cyber

Nmap OBSERVE.
Il ne pirate pas.
""")
    pause()

def course_metasploit():
    clear()
    print("📘 COURS – METASPLOIT\n")
    print("""
Metasploit est un framework de sécurité.

C’est une boîte à outils pour :
- comprendre les failles
- tester des machines de LAB
- apprendre comment fonctionnent les attaques

Utilisation :
✔ VM
✔ lab
✔ autorisation

Sinon = illégal.
""")
    pause()

def course_passwords():
    clear()
    print("📘 COURS – MOTS DE PASSE\n")
    print("""
Un mot de passe faible met tout en danger.

Exemples :
- 123456
- admin
- password

John The Ripper sert à :
✔ AUDITER la solidité
✔ FORMER
❌ voler des comptes
""")
    pause()

def course_protocols():
    clear()
    print("📘 COURS – PROTOCOLES RÉSEAU\n")
    print("""
Un protocole est une règle de communication.

HTTP  : web non chiffré
HTTPS : web sécurisé
SSH   : accès distant sécurisé
DNS   : nom -> IP

Sans protocoles :
Internet ne fonctionne pas.
""")
    pause()
def course_tor():
    clear()
    print("liens du darknet\n")

# ==================================================
# ================== OUTILS ========================
# ==================================================

import subprocess

def tool_nmap():
    target = input("Target (ex: 127.0.0.1) : ")
    result = subprocess.run(
        ["nmap", "-sV", target],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    input("\nEntrée pour continuer...")

def tool_dorking():
    clear()
    print("🛠️ GOOGLE DORKING – AVANCÉ (OSINT)\n")

    print("""
🔍 FICHIERS SENSIBLES
filetype:pdf site:example.com
filetype:xls site:example.com
filetype:sql site:example.com

🔍 PANNEAUX / INDEX
intitle:"index of"
intitle:"backup"
intitle:"admin"

🔍 TECHNOLOGIES (informatif)
inurl:php?id=
inurl:login
inurl:config

🔍 EMAILS / DOCS PUBLICS
"@example.com" filetype:pdf

🔍 ERREURS APPLICATIVES
"warning" "mysql"
"fatal error" "line"

⚠️ Recherche uniquement sur des contenus publics
""")

    pause()

def tool_metasploit():
    clear()
    print("🛠️ Lancement de Metasploit...\n")
    subprocess.run(["msfconsole"])

import subprocess

def tool_john():
    clear()
    print("🛠️ JOHN THE RIPPER\n")
    print("John nécessite un fichier de hashes.\n")
    print("Exemples :")
    print("  john hashes.txt")
    print("  john --show hashes.txt")
    print("  john --list=formats\n")

    path = input("Chemin du fichier de hashes (ou Entrée pour annuler) : ")

    if path.strip() == "":
        return

    subprocess.run(["john", path])

def tool_protocols():
    clear()
    print("🛠️ PROTOCOLES – COMMANDES\n")
    print("""
ping 8.8.8.8
nslookup google.com
curl http://example.com
ssh user@ip
""")
    pause()

import subprocess

def tool_sherlock():
    clear()
    print("🕵️ SHERLOCK – OSINT USERNAME\n")

    username = input("Username à rechercher : ").strip()
    if not username:
        print("❌ Username invalide")
        pause()
        return

    subprocess.run(
        ["python3", "sherlock/sherlock.py", username]
    )

    pause()

# ==================================================
# ================== MENUS =========================
# ==================================================

def menu_courses():
    clear()
    banner()
    print("""
COURS
1 - OSINT
2 - Nmap
3 - Metasploit
4 - Mots de passe
5 - Protocoles réseau
0 - Retour
""")
    c = input("> ")
    if c == "1": course_osint()
    elif c == "2": course_nmap()
    elif c == "3": course_metasploit()
    elif c == "4": course_passwords()
    elif c == "5": course_protocols()

def menu_tools():
    clear()
    banner()
    print("""
OUTILS / COMMANDES
1 - Nmap
2 - Dorking
3 - Metasploit
4 - John The Ripper
5 - Protocoles
0 - Retour
""")
    c = input("> ")
    if c == "1": tool_nmap()
    elif c == "2": tool_dorking()
    elif c == "3": tool_metasploit()
    elif c == "4": tool_john()
    elif c == "5": tool_protocols()

def main():
    while True:
        clear()
        banner()
        print("""
1 -  Cours 
2 -  Outils 
99 -  Quitter
""")
        c = input("> ")
        if c == "1":
            menu_courses()
        elif c == "2":
            menu_tools()
        elif c == "99":
            sys.exit()

if __name__ == "__main__":
   main()
