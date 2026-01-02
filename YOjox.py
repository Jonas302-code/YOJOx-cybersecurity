#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil

# ================= UTIL =================

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    input("\n[Press Enter to continue]")

def tool_exists(tool):
    return shutil.which(tool) is not None

def get_input(prompt, required=True):
    while True:
        val = input(prompt).strip()
        if val or not required:
            return val

# ================= BANNERS =================

def banner_main():
    print(r"""
██╗   ██╗ ██████╗      ██╗ ██████╗ ██╗  ██╗
╚██╗ ██╔╝██╔═══██╗     ██║██╔═══██╗╚██╗██╔╝
 ╚████╔╝ ██║   ██║     ██║██║   ██║ ╚███╔╝ 
  ╚██╔╝  ██║   ██║██   ██║██║   ██║ ██╔██╗ 
   ██║   ╚██████╔╝╚█████╔╝╚██████╔╝██╔╝ ██╗
   ╚═╝    ╚═════╝  ╚════╝  ╚═════╝ ╚═╝  ╚═╝

Creator - Jonas Sleiman
OS only KALI LINUX
YOJOX – Cybersecurity Learning Tool
Educational / Legal use only
""")

def banner_nmap():
    print(r"""
 _   _ __  __    _    ____  
| \ | |  \/  |  / \  |  _ \ 
|  \| | |\/| | / _ \ | |_) |
| |\  | |  | |/ ___ \|  __/ 
|_| \_|_|  |_/_/   \_\_|    

NMAP – Network Mapper
""")

def banner_john():
    print(r"""
     _       _           _   _            ____  _                      
    | | ___ | |__  _ __ | |_| |__   ___  |  _ \(_)_ __  _ __   ___ _ __ 
 _  | |/ _ \| '_ \| '_ \| __| '_ \ / _ \ | |_) | | '_ \| '_ \ / _ \ '__|
| |_| | (_) | | | | | | | |_| | | |  __/ |  _ <| | |_) | |_) |  __/ |   
 \___/ \___/|_| |_|_| |_|\__|_| |_|\___| |_| \_\_| .__/| .__/ \___|_|   
                                                  |_|   |_|            

JOHN THE RIPPER
Password Auditing Tool
""")

def banner_msf():
    print(r"""
 __  __ _____ _____ ____  _____ _____ _     ___ _____
|  \/  | ____|_   _/ ___||  ___| ____| |   |_ _|_   _|
| |\/| |  _|   | | \___ \| |_  |  _| | |    | |  | |
| |  | | |___  | |  ___) |  _| | |___| |___ | |  | |
|_|  |_|_____| |_| |____/|_|   |_____|_____|___| |_| 

METASPLOIT FRAMEWORK
Authorized labs only
""")

def banner_maigret():
    print(r"""
 __  __    _    ___ ____  ____  _____ _____ 
|  \/  |  / \  |_ _/ ___||  _ \| ____|_   _|
| |\/| | / _ \  | | |  _ | |_) |  _|   | |  
| |  | |/ ___ \ | | |_| ||  _ <| |___  | |  
|_|  |_/_/   \_\___\____||_| \_\_____| |_|    

MAIGRET – OSINT USERNAME SEARCH
""")

def banner_aircrack():
    print(r"""
    _    ___ ____   ____ ____      _    ____ _  __
   / \  |_ _|  _ \ / ___|  _ \    / \  / ___| |/ /
  / _ \  | || |_) | |   | |_) |  / _ \| |   | ' / 
 / ___ \ | ||  _ <| |___|  _ <  / ___ \ |___| . \ 
/_/   \_\___|_| \_\\____|_| \_\/_/   \_\____|_|\_\

AIRCRACK‑NG
Wireless Security Suite
""")
def banner_gobuster():
    print(r"""
  ____       _               _            
 / ___| ___ | |__  _   _ ___| |_ ___ _ __ 
| |  _ / _ \| '_ \| | | / __| __/ _ \ '__|
| |_| | (_) | |_) | |_| \__ \ ||  __/ |   
 \____|\___/|_.__/ \__,_|___/\__\___|_|   

GOBUSTER – Directory & DNS Brute Forcing
Authorized targets only
""")

def banner_hashcat():
    print(r"""
 _   _           _     _____      _   
| | | | __ _ ___| |__ | ____|_  _| |_ 
| |_| |/ _` / __| '_ \|  _| \ \/ / __|
|  _  | (_| \__ \ | | | |___ >  <| |_ 
|_| |_|\__,_|___/_| |_|_____/_/\_\\__|

HASHCAT – Advanced Password Recovery
Educational / Audit use only
""")
def banner_nikto():
    print(r"""
 _   _ _ _    _        
| \ | (_) | _| |_ ___ 
|  \| | | |/ / __/ _ \
| |\  | |   <| || (_) |
|_| \_|_|_|\_\\__\___/

NIKTO – WEB VULNERABILITY SCAN
──────────────────────────────
""")

def banner_whatweb():
    print(r"""
__        ___     _   _     _     
\ \      / / |__ | |_| |__ | |__  
 \ \ /\ / /| '_ \| __| '_ \| '_ \ 
  \ V  V / | | | | |_| |_) | |_) |
   \_/\_/  |_| |_|\__|_.__/|_.__/ 

WHATWEB – WEB TECHNOLOGY AUDIT
──────────────────────────────
""")

def banner_lynis():
    print(r"""
██╗     ██╗   ██╗███╗   ██╗██╗███████╗
██║     ██║   ██║████╗  ██║██║██╔════╝
██║     ██║   ██║██╔██╗ ██║██║███████╗
██║     ██║   ██║██║╚██╗██║██║╚════██║
███████╗╚██████╔╝██║ ╚████║██║███████║
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚══════╝

LYNIS – SECURITY AUDIT
──────────────────────────────
""")

def banner_harvester():
    print(r"""
 _   _            _   _                           
| | | | __ _ _ __| |_(_) ___  _ __   ___ _ __     
| |_| |/ _` | '__| __| |/ _ \| '_ \ / _ \ '__|    
|  _  | (_| | |  | |_| | (_) | | | |  __/ |       
|_| |_|\__,_|_|   \__|_|\___/|_| |_|\___|_|       

THEHARVESTER – OSINT ENUMERATION
──────────────────────────────
""")

def banner_ss():
    print(r"""
 ____   ____  
/ ___| / ___| 
\___ \ \___ \ 
 ___) | ___) |
|____/ |____/ 

SS – NETWORK CONNECTIONS
──────────────────────────────
""")

def banner_logwatch():
    print(r"""
 _                _       _       _     
| |    ___   __ _(_)_ __ | | ___ | |__  
| |   / _ \ / _` | | '_ \| |/ _ \| '_ \ 
| |__| (_) | (_| | | | | | | (_) | |_) |
|_____\___/ \__, |_|_| |_|_|\___/|_.__/ 
             |___/                      

LOGWATCH – LOG SUMMARY
──────────────────────────────
""")
def banner_tor():
    print(r"""
█████████████████████████████
████████╗ ██████╗ ██████╗       
╚══██╔══╝██╔═══██╗██╔══██╗      
   ██║   ██║   ██║██████╔          
   ██║   ██║   ██║██╔══██╗         
   ██║   ╚██████╔╝██║  ██║         
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝         


        TOR — THE ONION ROUTER
        Privacy • Anonymity • Freedom
""")

def banner_ai():
    print(r"""
🤖 LOCAL AI ASSISTANT – OLLAMA
Model : phi
Language : English only
Educational use
""")

# ================= COURSES =================

def course_osint():
    clear()
    print("OSINT = Open Source Intelligence")
    pause()

def course_nmap():
    clear()
    print("Nmap scans networks and services.")
    pause()

def course_metasploit():
    clear()
    print("Metasploit is for authorized labs only.")
    pause()

def course_passwords():
    clear()
    print("Password auditing & awareness.")
    pause()

def course_protocols():
    clear()
    print("HTTP, HTTPS, SSH, DNS")
    pause()

# ================= TOOLS =================

def tool_nmap():
    if not tool_exists("nmap"):
        print("❌ Nmap not installed")
        pause()
        return

    while True:
        clear()
        banner_nmap()
        print("""
1 - Fast scan
2 - TCP SYN scan
3 - TCP connect scan
4 - UDP scan
5 - Version detection
6 - OS detection
7 - Aggressive scan
8 - All ports scan
0 - Back
""")

        c = input("> ")
        if c == "0":
            break

        target = input("Target IP / domain: ").strip()
        if not target:
            continue

        scans = {
            "1": ["nmap", "-T4", "-F", target],
            "2": ["nmap", "-sS", target],
            "3": ["nmap", "-sT", target],
            "4": ["nmap", "-sU", target],
            "5": ["nmap", "-sV", target],
            "6": ["nmap", "-O", target],
            "7": ["nmap", "-A", target],
            "8": ["nmap", "-p-", target],
        }

        subprocess.run(scans.get(c, []))
        pause()

def tool_john():
    if not tool_exists("john"):
        print("❌ John not installed")
        pause()
        return

    while True:
        clear()
        banner_john()
        print("""
1 - Simple crack
2 - Wordlist
3 - Wordlist + rules
4 - Show cracked passwords
0 - Back
""")

        c = input("> ")
        if c == "0":
            break

        path = input("Hash file path: ").strip()
        if not path:
            continue

        if c == "1":
            subprocess.run(["john", path])
        elif c == "2":
            wl = input("Wordlist path: ")
            subprocess.run(["john", f"--wordlist={wl}", path])
        elif c == "3":
            wl = input("Wordlist path: ")
            subprocess.run(["john", f"--wordlist={wl}", "--rules", path])
        elif c == "4":
            subprocess.run(["john", "--show", path])

        pause()

def tool_metasploit():
    if not tool_exists("msfconsole"):
        print("❌ Metasploit not installed")
        pause()
        return
    clear()
    banner_msf()
    subprocess.run(["msfconsole"])

def tool_maigret():
    if not tool_exists("maigret"):
        print("❌ Maigret not installed")
        print("Install: pip3 install maigret")
        pause()
        return

    clear()
    banner_maigret()
    username = input("Username to search: ").strip()
    if username:
        subprocess.run(["maigret", username])
    pause()

def tool_aircrack():
    if not tool_exists("aircrack-ng"):
        print("❌ Aircrack-ng not installed")
        print("Install: sudo apt install aircrack-ng")
        pause()
        return

    while True:
        clear()
        banner_aircrack()
        print("""
1 - Monitor mode (airmon-ng)
2 - Capture packets (airodump-ng)
3 - Crack WPA/WPA2 (aircrack-ng)
0 - Back
""")

        c = input("> ").strip()

        if c == "0":
            break

        elif c == "1":
            iface = input("Interface (ex: wlan0): ").strip()
            if iface:
                subprocess.run(["airmon-ng", "start", iface])

        elif c == "2":
            iface = input("Monitor interface (ex: wlan0mon): ").strip()
            if iface:
                subprocess.run(["airodump-ng", iface])

        elif c == "3":
            cap = input("Capture file (.cap): ").strip()
            wl = input("Wordlist path: ").strip()
            if cap and wl:
                subprocess.run(["aircrack-ng", "-w", wl, cap])

        pause()
def tool_gobuster():
    if not tool_exists("gobuster"):
        print("❌ Gobuster not installed")
        print("Install: sudo apt install gobuster")
        pause()
        return

    while True:
        clear()
        banner_gobuster()
        print("""
1 - Directory scan
2 - DNS subdomain scan
0 - Back
""")

        c = input("> ").strip()
        if c == "0":
            break

        target = input("Target URL / domain: ").strip()
        wordlist = input("Wordlist path: ").strip()

        if not target or not wordlist:
            continue

        if c == "1":
            subprocess.run([
                "gobuster", "dir",
                "-u", target,
                "-w", wordlist
            ])

        elif c == "2":
            subprocess.run([
                "gobuster", "dns",
                "-d", target,
                "-w", wordlist
            ])

        pause()
def tool_hashcat():
    if not tool_exists("hashcat"):
        print("❌ Hashcat not installed")
        print("Install: sudo apt install hashcat")
        pause()
        return

    while True:
        clear()
        banner_hashcat()
        print("""
1 - Dictionary attack
2 - Show cracked hashes
0 - Back
""")

        c = input("> ").strip()
        if c == "0":
            break

        hash_file = input("Hash file path: ").strip()
        if not hash_file:
            continue

        if c == "1":
            mode = input("Hash mode (ex: 0 = MD5, 1000 = NTLM): ").strip()
            wordlist = input("Wordlist path: ").strip()
            subprocess.run([
                "hashcat",
                "-m", mode,
                hash_file,
                wordlist
            ])

        elif c == "2":
            subprocess.run([
                "hashcat",
                "-m", "0",
                hash_file,
                "--show"
            ])

        pause()
def tool_sqlmap():
    if not tool_exists("sqlmap"):
        print("❌ SQLMap not installed")
        print("Install: sudo apt install sqlmap")
        pause()
        return

    while True:
        clear()
        print("""
 ____   ___  _     __  __    _    ____  
/ ___| / _ \| |   |  \/  |  / \  |  _ \ 
\___ \| | | | |   | |\/| | / _ \ | |_) |
 ___) | |_| | |___| |  | |/ ___ \|  __/ 
|____/ \__\_\_____|_|  |_/_/   \_\_|    

SQLMAP – SQL Injection Tool
⚠️ LABS AUTHORIZED ONLY
""")

        print("""
1 - Basic test (URL)
2 - Dump database (LAB)
3 - Enumerate databases
0 - Back
""")

        c = input("> ").strip()
        if c == "0":
            break

        url = input("Target URL (with parameter): ").strip()
        if not url:
            continue

        if c == "1":
            subprocess.run([
                "sqlmap",
                "-u", url,
                "--batch"
            ])

        elif c == "2":
            subprocess.run([
                "sqlmap",
                "-u", url,
                "--dump",
                "--batch"
            ])

        elif c == "3":
            subprocess.run([
                "sqlmap",
                "-u", url,
                "--dbs",
                "--batch"
            ])
    pause()

def tool_nikto():
    if not tool_exists("nikto"):
        print("❌ Nikto not installed")
        print("Install: sudo apt install nikto")
        pause()
        return

    clear()
    banner_nikto()
    target = input("Target URL (LAB ONLY): ").strip()
    if target:
        subprocess.run(["nikto", "-h", target])
    pause()

def tool_whatweb():
    if not tool_exists("whatweb"):
        print("❌ WhatWeb not installed")
        print("Install: sudo apt install whatweb")
        pause()
        return

    clear()
    banner_whatweb()
    target = input("Target URL: ").strip()
    if target:
        subprocess.run(["whatweb", target])
    pause()

def tool_lynis():
    if not tool_exists("lynis"):
        print("❌ Lynis not installed")
        print("Install: sudo apt install lynis")
        pause()
        return

    clear()
    banner_lynis()
    subprocess.run(["lynis", "audit", "system"])
    pause()

def tool_harvester():
    if not tool_exists("theHarvester"):
        print("❌ theHarvester not installed")
        print("Install: sudo apt install theharvester")
        pause()
        return

    clear()
    banner_harvester()
    domain = input("Domain to search: ").strip()
    if domain:
        subprocess.run([
            "theHarvester",
            "-d", domain,
            "-b", "bing"
        ])
    pause()

def tool_ss():
    clear()
    banner_ss()
    subprocess.run(["ss", "-tulpen"])
    pause()

def tool_logwatch():
    if not tool_exists("logwatch"):
        print("❌ Logwatch not installed")
        print("Install: sudo apt install logwatch")
        pause()
        return

    clear()
    banner_logwatch()
    subprocess.run(["logwatch", "--detail", "Low"])
    pause()



# ================= AI =================

def ai_ollama():
    if not tool_exists("ollama"):
        print("❌ Ollama not installed")
        pause()
        return

    clear()
    banner_ai()

    system_prompt = (
        "You are a cybersecurity teaching assistant. "
        "Explain concepts clearly and legally. "
        "Answer only in English."
    )

    while True:
        q = input("AI > ").strip()
        if q.lower() in ["exit", "quit", "q"]:
            break

        prompt = system_prompt + "\n\nUser: " + q + "\nAssistant:"
        subprocess.run(["ollama", "run", "phi", prompt])
        print("-" * 40)

# ================= MENUS =================

def menu_courses():
    while True:
        clear()
        banner_main()
        print("""
COURSES
1 - OSINT
2 - Nmap
3 - Metasploit
4 - Passwords
5 - Protocols
0 - Back
""")
        c = input("> ")
        if c == "0": break
        elif c == "1": course_osint()
        elif c == "2": course_nmap()
        elif c == "3": course_metasploit()
        elif c == "4": course_passwords()
        elif c == "5": course_protocols()

def menu_tools():
    while True:
        clear()
        banner_main()
        print("""
TOOLS
1 - Nmap
2 - John The Ripper
3 - Metasploit
4 - Maigret (OSINT)
5 - Aircrack-ng (WiFi)
6 - Gobuster
7 - Hashcat
8 - Sqlmap
9 - Nikto
10 - WhatWeb
11 - lynis
12 - theHarvester
13 - ss
14 - Logwatch
0 - Back
""")
        c = input("> ")
        if c == "0": break
        elif c == "1": tool_nmap()
        elif c == "2": tool_john()
        elif c == "3": tool_metasploit()
        elif c == "4": tool_maigret()
        elif c == "5": tool_aircrack()
        elif c == "6": tool_gobuster()
        elif c == "7": tool_hashcat()
        elif c == "8": tool_sqlmap()
        elif c == "9": tool_nikto()
        elif c == "10": tool_whatweb()
        elif c == "11": tool_lynis()
        elif c == "12": tool_harvester()
        elif c == "13": tool_ss()
        elif c == "14": tool_logwatch()
# ================= MAIN =================

def main():
    while True:
        clear()
        banner_main()
        print("""
1 - Courses
2 - Tools
3 - AI Assistant
99 - Quit
""")
        c = input("> ")
        if c == "1":
            menu_courses()
        elif c == "2":
            menu_tools()
        elif c == "3":
            ai_ollama()
        elif c == "99":
            sys.exit(0)

if __name__ == "__main__":
    main()
