#Ce script semble fonctionner, mais vous pouvez le manipuler a votre guise. C'est OpenSource, prenez ce que vous voulez.
#je deteste ce script, il est trop mal réalisé, je l'ai juste fait pour le fun et par ennuis.


import os

try:
    import subprocess
    import sys
    import time
    import requests
    import urllib.request
    import zipfile
    import binascii
except:
    installation=input("Acceptez vous l'installation des librairies nécessaire au bon fonctionnement de l'application ? (o/n):")
    oui = ["o","y","oui","yes"]
    if installation in oui:  
        librairies = ["subprocess","sys","time","requests","urllib.request","zipfile","binascii"]#certaines librairies sont déjà installé, mais on est jamais trop sûr de rien.
        for lib in librairies:
            print(f"Installation de {lib}...")
            os.system(f"pip install {lib}")
            print(f"{lib} installé avec succès. Veuillez relancer le script.")
    else:
        print("ok, bye.")
try:
    title="Kali-Pocket"
    if os.name == "nt":
        os.system(f"title {title}")
    else:
        print("Kali-Pocket est fait pour windows.")
    os.system("cls")
except:
    pass

home_chemin = os.getcwd()


menu1="""\033[31m╔══════════════════════════════╗
\033[31m║            \033[0mOsint             \033[31m║
\033[31m╠════════════════════╦═════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour       \033[31m║ \033[0m[5] : ? \033[31m║
\033[31m║ \033[0m[1] : Sherlock     \033[31m║ \033[0m[6] : ? \033[31m║
\033[31m║ \033[0m[2] : holehe       \033[31m║ \033[0m[7] : ? \033[31m║
\033[31m║ \033[0m[3] : Email lookup \033[31m║ \033[0m[8] : ? \033[31m║
\033[31m║ \033[0m[4] : Ip lookup    \033[31m║ \033[0m[9] : ? \033[31m║
\033[31m╚════════════════════╩═════════╝\n\033[0m"""
menu2="""\033[31m╔════════════════════════════════╗
\033[31m║          \033[0mPentesting            \033[31m║
\033[31m╠═════════════════╦══════════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour    \033[31m║ \033[0m[5] : ?      \033[31m║
\033[31m║ \033[0m[1] : SQLmap    \033[31m║ \033[0m[6] : ?      \033[31m║
\033[31m║ \033[0m[2] : XSStrike  \033[31m║ \033[0m[7] : ?      \033[31m║
\033[31m║ \033[0m[3] : NoSQLmap  \033[31m║ \033[0m[8] : ?      \033[31m║
\033[31m║ \033[0m[4] : ?         \033[31m║ \033[0m[9] : ?      \033[31m║
\033[31m╚═════════════════╩══════════════╝\n\033[0m"""
menu3="""\033[31m╔═════════════════════════════╗
\033[31m║      \033[0mAnalyse de réseau      \033[31m║
\033[31m╠═══════════════════╦═════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour      \033[31m║ \033[0m[5] : ? \033[31m║
\033[31m║ \033[0m[1] : Pyshark     \033[31m║ \033[0m[6] : ? \033[31m║
\033[31m║ \033[0m[2] : ?           \033[31m║ \033[0m[7] : ? \033[31m║
\033[31m║ \033[0m[3] : ?           \033[31m║ \033[0m[8] : ? \033[31m║
\033[31m║ \033[0m[4] : ?           \033[31m║ \033[0m[9] : ? \033[31m║
\033[31m╚═══════════════════╩═════════╝\n\033[0m"""
"""\033[31m╔═════════════════════════════════════╗
\033[31m║     \033[0mAnalyse de vulnérabilités       \033[31m║
\033[31m╠═══════════════════════════╦═════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour              \033[31m║\033[0m [5] : ? \033[31m║
\033[31m║\033[0m [1] : ?                   \033[31m║\033[0m [6] : ? \033[31m║
\033[31m║\033[0m [2] : ?                   \033[31m║\033[0m [7] : ? \033[31m║
\033[31m║\033[0m [3] : ?                   \033[31m║\033[0m [8] : ? \033[31m║
\033[31m║ \033[0m[4] : ?                   \033[31m║ \033[0m[9] : ? \033[31m║
\033[31m╚═══════════════════════════╩═════════╝\n\033[0m"""
menu5="""\033[31m╔═════════════════════════════════╗
\033[31m║           \033[0mExploitation          \033[31m║
\033[31m╠═══════════════════════╦═════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour          \033[31m║ \033[0m[5] : ? \033[31m║
\033[31m║ \033[0m[1] : Hashcat         \033[31m║ \033[0m[6] : ? \033[31m║
\033[31m║ \033[0m[2] : John the Ripper \033[31m║ \033[0m[7] : ? \033[31m║
\033[31m║ \033[0m[3] : Hydra           \033[31m║ \033[0m[8] : ? \033[31m║
\033[31m║ \033[0m[4] : ?               \033[31m║ \033[0m[9] : ? \033[31m║
\033[31m╚═══════════════════════╩═════════╝\n\033[0m
"""
"""\033[31m╔═════════════════════════════════╗
\033[31m║        \033[0mIngénierie sociale       \033[31m║
\033[31m╠═══════════════════════╦═════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour          \033[31m║ \033[0m[5] : ? \033[31m║
\033[31m║ \033[0m[1] : ?               \033[31m║ \033[0m[6] : ? \033[31m║
\033[31m║ \033[0m[2] : ?               \033[31m║ \033[0m[7] : ? \033[31m║
\033[31m║ \033[0m[3] : ?               \033[31m║ \033[0m[8] : ? \033[31m║
\033[31m║ \033[0m[4] : ?               \033[31m║ \033[0m[9] : ? \033[31m║
\033[31m╚═══════════════════════╩═════════╝\n\033[0m"""
menu4="""\033[31m╔═══════════════════════════════════╗
\033[31m║         \033[0mRéseaux sans fil          \033[31m║
\033[31m╠═════════════════════════╦═════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour            \033[31m║ \033[0m[5] : ? \033[31m║
\033[31m║ \033[0m[1] : Wifiphisher      \033[31m ║ \033[0m[6] : ? \033[31m║
\033[31m║ \033[0m[2] : ?                 \033[31m║ \033[0m[7] : ? \033[31m║
\033[31m║ \033[0m[3] : ?                 \033[31m║ \033[0m[8] : ? \033[31m║
\033[31m║ \033[0m[4] : ?                 \033[31m║ \033[0m[9] : ? \033[31m║
\033[31m╚═════════════════════════╩═════════╝\n\033[0m"""
menu6="""\033[31m╔════════════════════════════╗
\033[31m║         \033[0mReversing          \033[31m║
\033[31m╠══════════════════╦═════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour    \033[31m ║ \033[0m[5] : ? \033[31m║
\033[31m║ \033[0m[1] : Capstone  \033[31m ║ \033[0m[6] : ? \033[31m║
\033[31m║ \033[0m[2] : Radare2    \033[31m║ \033[0m[7] : ? \033[31m║
\033[31m║ \033[0m[3] : ?          \033[31m║ \033[0m[8] : ? \033[31m║
\033[31m║ \033[0m[4] : ?          \033[31m║ \033[0m[9] : ? \033[31m║
\033[31m╚══════════════════╩═════════╝\n\033[0m"""
menu7="""\033[31m╔═══════════════════════════════════════════════════╗
\033[31m║                     \033[0mDiscord                       \033[31m║
\033[31m╠═══════════════════╦═══════════════════════════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] Retour        \033[31m║ \033[0m[5] Tokens Joiner             \033[31m║
\033[31m║ \033[0m[1] Token Nuke    \033[31m║ \033[0m[6] Tokens Raid Serveur       \033[31m║
\033[31m║ \033[0m[2] Token Cleaner \033[31m║ \033[0m[7] Token Bot Mass DM Serveur \033[31m║
\033[31m║ \033[0m[3] Token Mass DM \033[31m║ \033[0m[8] Token Bot Raid Serveur    \033[31m║
\033[31m║ \033[0m[4] Token Info    \033[31m║ \033[0m[9] Webhook Nuke              \033[31m║
\033[31m╚═══════════════════╩═══════════════════════════════╝\n\033[0m"""
menu8="""\033[31m╔════════════════════════════════════════════════════════════╗
\033[31m║                      \033[0mOutils divers                         \033[31m║
\033[31m╠══════════════════════════════╦═════════════════════════════╣
\033[31m║ \033[0m[\033[31m0\033[0m] : Retour                 \033[31m║ \033[0m[5] : ?                     \033[31m║
\033[31m║ \033[0m[1] : ?                      \033[31m║ \033[0m[6] : ?                     \033[31m║
\033[31m║ \033[0m[2] : ?                      \033[31m║ \033[0m[7] : ?                     \033[31m║
\033[31m║ \033[0m[3] : ?                      \033[31m║ \033[0m[8] : ?                     \033[31m║
\033[31m║ \033[0m[4] : ?                      \033[31m║ \033[0m[9] : ?                     \033[31m║
\033[31m╚══════════════════════════════╩═════════════════════════════╝\n\033[0m"""
def colored(chaines,couleur):
    couleurs={
        "vert":"\033[32m",
        "rouge":"\033[31m",
        "blanc":"\033[0m"}
    try:
        return f"{couleurs[couleur]}{chaines}{couleurs["blanc"]}"
    except:
        print(f"probleme avec couleur {couleur}")

def menu1d():
    while True:
        choix=str(input(f"choix :"))
        if choix == "0":
            return 1
        elif choix == "1":
            sherlock()
            return 0
        elif choix == "2":
            holehe()
            return 0
        elif choix =="3":
            print("soucis technique")
        elif choix =="4":
            lookup_ip()
            return 0
        else:
            print("?")

def menu2d():
    while True:
        choix=str(input(f"choix :"))
        if choix == "0":
            return 1
        elif choix == "1":
            sqlmap()
            return 0
        elif choix == "2":
            xsstrike()
            return 0
        elif choix == "3":
            nosqlmap()
            return 0
        else:
            print("?")

def menu3d():
    while True:
        choix=str(input(f"choix :"))
        if choix == "0":
            return 1
        elif choix == "1":
            pyshark()
            return 0
        else:
            print("?")

def menu4d():
    while True:
        choix=str(input(f"choix :"))
        if choix == "0":
            return 1
        elif choix == "1":
            wifiphisher()
            return 0
        else:
            print("?")

def menu5d():
    while True:
        choix=str(input(f"choix :"))
        if choix == "0":
            return 1
        elif choix == "1":
            hashcat()
            return 0
        elif choix == "2":
            john()
            return 0
        elif choix == "3":
            hydra()
            return 0
        else:
            print("?")

def menu6d():
    while True:
        choix=str(input(f"choix :"))
        if choix == "0":
            return 1
        elif choix == "1":
            capstone()
            return 0
        elif choix == "2":
            radare2()
            return 0
        else:
            print("?")

def menu():
    menu="""\033[31m╔══════════════════════════╦═══════════════════════════════╗
\033[31m║ \033[0m[\033[31m0\033[0m] : exit               \033[31m║ \033[0m[5] : Exploitation            \033[31m║
\033[31m║ \033[0m[1] : Osint              \033[31m║ \033[0m[6] : Reversing               \033[31m║
\033[31m║ \033[0m[2] : Pentesting         \033[31m║ \033[0m[7] : Discord                 \033[31m║
\033[31m║ \033[0m[3] : Analyse de réseau  \033[31m║ \033[0m[8] : Outils divers           \033[31m║
\033[31m║ \033[0m[4] : Réseaux sans fil   \033[31m║ \033[0m[9] : Désinstaller des tools  \033[31m║
\033[31m╚══════════════════════════╩═══════════════════════════════╝\n\033[0m"""
    print(menu)
    while(True):
        os.chdir(home_chemin)
        choix=str(input(f"choix :"))
        if choix == "0":
            return 0
        elif choix == "1":
            print(menu1)
            if menu1d() == 0:
                return 0
            print(menu)
        elif choix == "2":
            print(menu2)
            if menu2d() == 0:
                return 0
            print(menu)
            
        elif choix == "3":
            print(menu3)
            if menu3d() == 0:
                return 0
            print(menu)
        elif choix == "4":
            print(menu4)
            if menu4d() == 0:
                return 0
            print(menu)
        elif choix == "5":
            print(menu5)
            if menu5d() == 0:
                return 0
            print(menu)
        elif choix == "6":
            print(menu6)
            if menu6d() == 0:
                return 0
            print(menu)
        elif choix == "7":
            print(menu7)
            #menu7d()
            print("Arrive dans la \033[31mv1.2\033[0m")
        elif choix == "8":
            print(menu8)
            #menu8d()
            print("Arrive dans la \033[31mv1.2\033[0m")
        elif choix == "9":
            print("Arrive dans la \033[31mv1.2\033[0m")
            
        else:
            print("?")

def radare2():
    exe_path = input("Entrez le chemin du fichier exécutable à analyser : ").strip()
    if not os.path.isfile(exe_path):
        print("Le fichier spécifié n'existe pas.")
        return
    radare2_path = "./tools/menu6d/radare2"
    if not os.path.exists(radare2_path ):
        choix = input("radare2 n'est pas installé. Souhaitez-vous l'installer ? (o/n) ")
        if choix.lower() == "o":
            os.makedirs(radare2_path , exist_ok=True)
            print("Installation de Radare2...")
            radare2_url = "https://github.com/radareorg/radare2/releases/download/5.6.0/radare2-w64-5.6.0.exe"
            radare2_installer = "radare2_installer.exe"

            try:
                subprocess.run(["curl", "-L", radare2_url, "-o", radare2_installer], check=True)
                print("Téléchargement de Radare2 terminé.")
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors du téléchargement de Radare2 : {e}")
                return 
            try:
                subprocess.run([radare2_installer, "/S"], check=True)  
                print("Installation de Radare2 terminée.")
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors de l'installation de Radare2 : {e}")
                return 

            os.remove(radare2_installer)

            print("Installation de R2Pipe...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "r2pipe"], check=True)
                print("Installation de R2Pipe terminée.")
            except subprocess.CalledProcessError as e:
                print(f"Erreur lors de l'installation de R2Pipe : {e}")
                return 
        else:
            print("D'accord.")
            return
    try:
        import r2pipe
        r2 = r2pipe.open(exe_path)
    except Exception as e:
        print(f"Erreur lors de l'ouverture de Radare2 : {e}")
        return

    try:
        info = r2.cmd("i")
        print("Informations sur le fichier :")
        print(info)
        functions = r2.cmd("afl")
        print("\nFonctions trouvées :")
        print(functions)
        disasm = r2.cmd("pdf @ main")
        print("\nDésassemblage de la fonction main :")
        print(disasm)
    except Exception as e:
        print(f"Erreur lors de l'exécution des commandes Radare2 : {e}")

    finally:
        r2.quit()


def capstone():
    capstone_path = "./tools/menu6d/capstone"
    if not os.path.exists(capstone_path):
        choix = input("Capstone n'est pas installé. Souhaitez-vous l'installer ? (o/n) ")
        if choix.lower() == "o":
            os.makedirs(capstone_path, exist_ok=True)
            os.system(f"pip install capstone")
            print("Installation de Capstone terminée.")
        else:
            print("D'accord.")
            return
    try:
        import capstone
    except ImportError:
        print("Problème avec l'importation de capstone, veuillez vérifier l'installation.")
        return

    code_hex = input("Entrez le code hexadécimal à désassembler (ex : 6a 01 5b 31 c0 40 39 d8) : ").strip()
    code = binascii.unhexlify(code_hex.replace(" ", ""))
    arch = input("Entrez l'architecture (x86, x86_64, arm, arm64, mips) : ").strip().lower()
    if arch == "x86":
        arch, mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
    elif arch == "x86_64":
        arch, mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
    elif arch == "arm":
        arch, mode = capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
    elif arch == "arm64":
        arch, mode = capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    elif arch == "mips":
        arch, mode = capstone.CS_ARCH_MIPS, capstone.CS_MODE_32
    else:
        print("Architecture non supportée.")
        return 

    md = capstone.Cs(arch, mode)
    try:
        for insn in md.disasm(code, 0x1000):
            print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
    except capstone.CsError as e:
        print(f"Erreur de désassemblage : {e}")

def hydra():
    hydra_path = "./tools/menu5d/hydra"
    target = input("Entrez la cible (par ex., 192.168.1.1) : ")
    protocol = input("Entrez le protocole (par ex., ssh, ftp, http) : ")
    username_list = input("Entrez le chemin vers la liste des utilisateurs : ")
    password_list = input("Entrez le chemin vers la liste des mots de passe : ")

    if not os.path.exists(hydra_path):
        choix = input("Hydra n'est pas installé. Souhaitez-vous l'installer ? (o/n) ")
        if choix.lower() == "o":
            os.makedirs(hydra_path, exist_ok=True)
            url = "https://github.com/vanhauser-thc/thc-hydra/archive/refs/heads/master.zip"
            local_zip = os.path.join(hydra_path, "hydra.zip")
            
            print("Téléchargement de Hydra...")
            urllib.request.urlretrieve(url, local_zip)
            with zipfile.ZipFile(local_zip, 'r') as zip_ref:
                zip_ref.extractall(hydra_path)
            print("Installation de Hydra terminée.")
        else:
            print("D'accord.")
            return
        
    hydra_executable = os.path.join("./tools/menu5d/hydra/thc-hydra-master", "hydra.exe")
    
    if not os.path.exists(hydra_executable):
        print("Hydra n'est pas trouvé. Veuillez vérifier l'installation.")
        return
    run_cmd = f"{hydra_executable} -L {username_list} -P {password_list} {target} {protocol}"
    subprocess.run(run_cmd, shell=True)

def john():
    zip_file = input("Entrez le chemin du fichier ZIP à cracker : ")
    john_path = "./tools/menu5d/john"

    if not os.path.exists(john_path):
        choix = str(input("John the Ripper n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(john_path, exist_ok=True)
            url = "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip" 
            local_zip = os.path.join(john_path, "john.zip")
            print("Téléchargement de John the Ripper...")
            urllib.request.urlretrieve(url, local_zip)

            with zipfile.ZipFile(local_zip, 'r') as zip_ref:
                zip_ref.extractall(john_path)
            print("Installation de John the Ripper terminée.")
        else:
            print("D'accord.")
            return
        
    zip2john_executable = os.path.join(john_path, "run", "zip2john.exe")
    john_executable = os.path.join(john_path, "run", "john.exe")
    hash_file = "hash.txt"

    print(f"Extraction des hashes du fichier {zip_file}...")
    run_cmd = f"{zip2john_executable} {zip_file} > {hash_file}"
    subprocess.run(run_cmd, shell=True)

    print("Lancement de John the Ripper pour craquer le mot de passe...")
    run_cmd = f"{john_executable} {hash_file}"
    subprocess.run(run_cmd, shell=True)

    print("Mot de passe trouvé :")
    run_cmd = f"{john_executable} --show {hash_file}"
    subprocess.run(run_cmd, shell=True)
    os.chdir(home_chemin)

def hashcat():
    hashfile = input("Entrez le chemin du fichier contenant les hashes : ")
    wordlist = input("Entrez le chemin de la wordlist : ")
    hashcat_path = "./tools/menu5d/hashcat"
    if not os.path.exists(hashcat_path):
        choix = str(input("Hashcat n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(hashcat_path, exist_ok=True)
            url = "https://hashcat.net/files/hashcat-6.2.6.7z" 
            local_zip = os.path.join(hashcat_path, "hashcat.zip")
            print("Téléchargement de Hashcat...")
            urllib.request.urlretrieve(url, local_zip)
            with zipfile.ZipFile(local_zip, 'r') as zip_ref:
                zip_ref.extractall(hashcat_path)

            print("Installation de Hashcat terminée.")
        else:
            print("D'accord.")
            return
        
    hashcat_executable = os.path.join("./tools/menu1d/hashcat/hashcat-6.2.6", "hashcat.exe")
    if not os.path.exists(hashcat_executable):
        print("Hashcat n'est pas trouvé. Veuillez vérifier l'installation.")
        return
    
    run_cmd = f"{hashcat_executable} -a 0 -m 0 {hashfile} {wordlist}"
    subprocess.run(run_cmd, shell=True)
    os.chdir(home_chemin)

def wifiphisher():
    wifiphisher_path = "./tools/menu4d/wifiphisher"
    if not os.path.exists(wifiphisher_path):
        choix = str(input("Wifiphisher n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(wifiphisher_path, exist_ok=True)
            os.chdir(wifiphisher_path)
            clone_cmd = "git clone https://github.com/wifiphisher/wifiphisher.git"
            subprocess.run(clone_cmd, shell=True, check=True)
            os.chdir("wifiphisher")
            install_cmd = "python3 setup.py install"
            subprocess.run(install_cmd, shell=True, check=True)

            print("Installation de Wifiphisher terminée.")
        else:
            print("D'accord.")
            return

    print("Lancement de Wifiphisher...")
    run_cmd = "python3 wifiphisher.py"
    subprocess.run(run_cmd, shell=True)
    os.chdir(home_chemin)

def pyshark():
    try:
        import pyshark
        print("PyShark est déjà installé.")
    except ImportError:
        choix = str(input("PyShark n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            install_cmd = f"{sys.executable} -m pip install pyshark"
            subprocess.run(install_cmd, shell=True, check=True)
            print("Installation de PyShark terminée.")
            import pyshark
        else:
            print("D'accord.")
            return
    interface = str(input("Entrez le nom de l'interface réseau (par ex., eth0, wlan0) : "))
    output_file = str(input("Entrez le nom du fichier de sortie (par ex., capture.pcap) : "))
    timeout = int(input("Combien de temp de capture ? (par ex., 50, 30) secondes : "))
    print(f"Lancement de la capture de paquets sur l'interface '{interface}'...")
    capture = pyshark.LiveCapture(interface=interface,output_file=output_file)
    capture.sniff(timeout) 
    choix=str(input("Print les resultats ? (o/n)"))
    if choix=="o":
        for packet in capture.sniff_continuously(packet_count=None):
            print(packet)
    print(f"Capture terminée. Paquets sauvegardés dans '{output_file}'.")

def build_docker_image():
    print("Construction de l'image Docker pour NoSQLMap...")
    subprocess.run("docker build -t nosqlmap .", shell=True, check=True)

def nosqlmap():
    target = str(input("Entrez l'URL de la cible : "))
    nosqlmap_path = "./tools/menu2d/nosqlmap"
    dockerfile_path = os.path.join(nosqlmap_path, "Dockerfile")

    if not os.path.exists(dockerfile_path):
        choix = str(input("Dockerfile pour NoSQLMap n'existe pas. Souhaitez-vous le créer et installer les dépendances ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(nosqlmap_path, exist_ok=True)
            dockerfile_content = """\
#image Python officielle
FROM python:3.10-slim

#NoSQLMap et ses dépendances
RUN pip install --no-cache-dir NoSQLMap pymongo

#répertoire de travail dans le conteneur
WORKDIR /app

#commande par défaut de NoSQLMap
ENTRYPOINT ["nosqlmap"]
"""
            with open(dockerfile_path, 'w') as file:
                file.write(dockerfile_content)
            print(f"Dockerfile créé avec succès dans {dockerfile_path}")
            build_docker_image()
        else:
            print("D'accord. Opération annulée.")
            return
    else:
        build_docker_image()

    print(f"Lancement de NoSQLMap pour la cible '{target}'...")
    run_cmd = f"docker run --rm -v {os.getcwd()}:/app -w /app nosqlmap -u {target}"
    subprocess.run(run_cmd, shell=True)

def xsstrike():
    target = str(input("Entrez l'URL de la cible : "))
    xsstrike_path = "./tools/menu2d/xsstrike"

    if not os.path.exists(xsstrike_path):
        choix = str(input("XSStrike n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(xsstrike_path, exist_ok=True)
            clone_cmd = f"git clone https://github.com/s0md3v/XSStrike.git {xsstrike_path}"
            subprocess.run(clone_cmd, shell=True, check=True)
            requirements_cmd = f"{sys.executable} -m pip install -r {xsstrike_path}/requirements.txt"
            subprocess.run(requirements_cmd, shell=True, check=True)
            
            print("Installation de XSStrike terminée.")
        else:
            print("D'accord.")
            return

    print(f"Lancement de XSStrike pour la cible '{target}'...")
    try:
        os.chdir(xsstrike_path)
    except FileNotFoundError:
        print("Répertoire introuvable.")
        return
    except NotADirectoryError:
        print("Le chemin spécifié n'est pas un répertoire.")
        return

    run_cmd = f"{sys.executable} xsstrike.py -u {target} --crawl -l 2"
    subprocess.run(run_cmd, shell=True)
    os.chdir(home_chemin)

def sqlmap():
    target = str(input("Entrez l'URL de la cible : "))
    sqlmap_path = "./tools/menu2d/sqlmap"

    if not os.path.exists(sqlmap_path):
        choix = str(input("SQLmap n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(sqlmap_path, exist_ok=True)
            clone_cmd = f"git clone https://github.com/sqlmapproject/sqlmap.git {sqlmap_path}"
            subprocess.run(clone_cmd, shell=True, check=True)
            print("Installation de SQLmap terminée.")
        else:
            print("D'accord.")
            return
        
    print(f"Lancement de SQLmap pour la cible '{target}'...")
    try:
        os.chdir(sqlmap_path)
    except FileNotFoundError:
        print("Répertoire introuvable.")
        return
    except NotADirectoryError:
        print("Le chemin spécifié n'est pas un répertoire.")
        return
    run_cmd = f"python sqlmap.py -u {target} --batch"
    subprocess.run(run_cmd, shell=True)
    os.chdir(home_chemin)

def lookup_ip():
    ip=str(input("IPv4 :"))
    try:
        url = f'https://ipinfo.io/{ip}/json'
        response = requests.get(url)
        data = response.json()
        ip = data.get('ip', 'Non disponible')
        city = data.get('city', 'Non disponible')
        region = data.get('region', 'Non disponible')
        country = data.get('country', 'Non disponible')
        loc = data.get('loc', 'Non disponible')
        org = data.get('org', 'Non disponible')
        print(f"Adresse IP: {ip}")
        print(f"Ville: {city}")
        print(f"Région: {region}")
        print(f"Pays: {country}")
        print(f"Localisation: {loc}")
        print(f"Organisation: {org}")
    except requests.RequestException as e:
        print(f"Erreur lors de la récupération des informations pour {ip}: {e}")

def sherlock():
    username=str(input("Pseudo :"))
    sherlock_path = "./tools/menu1d/sherlock"
    if not os.path.exists(sherlock_path):
        choix = str(input("Sherlock n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(sherlock_path, exist_ok=True)
            clone_cmd = f"git clone https://github.com/sherlock-project/sherlock.git {sherlock_path}"
            setup =f"pip install --user sherlock-project"
            subprocess.run(clone_cmd, shell=True, check=True)
            subprocess.run(setup, shell=True, check=True)
            print("Installation de Sherlock terminée.")
        else:
            print("D'accord.")
            return

    print(f"Lancement de Sherlock pour rechercher l'utilisateur '{username}'...")
    
    try:
        os.chdir(sherlock_path)
    except FileNotFoundError:
        print("Répertoire introuvable.")
        return
    except NotADirectoryError:
        print("Le chemin spécifié n'est pas un répertoire.")
        return

    run_cmd = f"{sys.executable} sherlock_project/sherlock.py {username} --timeout 3"
    subprocess.run(run_cmd, shell=True)
    os.chdir(home_chemin)



def holehe():
    target=str(input("Email :"))
    holehe_path = "./tools/menu1d/holehe"
    
    if not os.path.exists(holehe_path):
        choix = str(input("Holehe n'est pas installé. Souhaitez-vous l'installer ? (o/n) "))
        if choix.lower() == "o":
            os.makedirs(holehe_path, exist_ok=True)
            os.chdir(holehe_path)
            clone_cmd = f"pip3 install holehe"

            subprocess.run(clone_cmd, shell=True, check=True)

            print("Installation de holehe terminée.")
        else:
            print("D'accord.")
            return
    print(f"Lancement de holehe pour la cible '{target}'...")

    run_cmd = f"holehe {target}"
    subprocess.run(run_cmd, shell=True)
    os.chdir(home_chemin)

def cmd(command):
    if command.startswith("cd "):
        directory = command[3:]
        try:
            os.chdir(directory)
        except FileNotFoundError:
            print("Répertoire introuvable.")
        except NotADirectoryError:
            print("Le chemin spécifié n'est pas un répertoire.")
    elif command == "ls":
        files = os.listdir()
        for file in files:
            print(file)
    elif command == "clear":
        os.system("cls")
    elif command == "update":
        os.system("python.exe -m pip install --upgrade pip")
    elif command.startswith("mkdir "):
        directory = command[6:]
        try:
            os.mkdir(directory)
        except FileExistsError:
            print("Le répertoire existe déjà.")
        except:
            print("Erreur lors de la création du répertoire.")
    elif command.startswith("cp "):
        arguments = command[3:].split(" ")
        source = arguments[0]
        destination = arguments[1]
        try:
            os.system(f"copy {source} {destination}")
        except:
            print("Erreur lors de la copie du fichier.")
    elif command.startswith("mv "):
        arguments = command[3:].split(" ")
        source = arguments[0]
        destination = arguments[1]
        try:
            os.rename(source, destination)
        except:
            print("Erreur lors du déplacement du fichier.")
    elif command == "tools":
        print("""\033[34m▄ •▄  ▄▄▄· ▄▄▌  ▪   ▄▄▄·       ▄▄· ▄ •▄ ▄▄▄ .▄▄▄▄▄
█▌▄▌▪▐█ ▀█ ██•  ██ ▐█ ▄█▪     ▐█ ▌▪█▌▄▌▪▀▄.▀·•██  
▐▀▀▄·▄█▀▀█ ██▪  ▐█· ██▀· ▄█▀▄ ██ ▄▄▐▀▀▄·▐▀▀▪▄ ▐█.▪
▐█.█▌▐█ ▪▐▌▐█▌▐▌▐█▌▐█▪·•▐█▌.▐▌▐███▌▐█.█▌▐█▄▄▌ ▐█▌·
·▀  ▀ ▀  ▀ .▀▀▀ ▀▀▀.▀    ▀█▄▀▪·▀▀▀ ·▀  ▀ ▀▀▀  ▀▀▀ 
              v1.1""")
        menu()
    elif command =="help" or command == "h":
        print("Commandes disponibles:\n")
        print(f"tools {colored(":","rouge")} Lance kali-pocket.")
        print(f"exit {colored(":","rouge")} Quitte le terminal.")
        print(f"update {colored(":","rouge")} Met à jour pip, (soon).")
        print(f"cd [répertoire] {colored(":","rouge")} Change le répertoire courant.")
        print(f"ls {colored(":","rouge")} Affiche le contenu du répertoire courant.")
        print(f"clear {colored(":","rouge")} Efface l'écran.")
        print(f"mkdir [répertoire] {colored(":","rouge")} Crée un nouveau répertoire.")
        print(f"cp [source] [destination] {colored(":","rouge")} Copie un fichier.")
        print(f"mv [source] [destination] {colored(":","rouge")} Déplace un fichier.")
        print(f"help {colored(":","rouge")} Affiche cette liste d'aide.")
    else:
        print("Commande introuvable.")
def terminal():
    try:
        while True:
            chemin = os.getcwd()
            utilisateur=os.getlogin()
            nom="kali-pocket"
            home_path = os.path.expanduser("~")
            if chemin.startswith(home_path):
                chemin = chemin.replace(home_path, "~").replace("\\", "/")
            prompt = f"{colored("┌──(", "vert")}{colored(utilisateur+"@"+nom, "rouge")}{colored(")-[", "vert")}{colored(chemin, "blanc")}{colored("]", "vert") }"
            print(prompt)
            commande = input(colored("└─", "vert")+colored("$", "rouge")+"\033[0m" )
            if commande.strip() == "exit":
                print("Bye !")
                break
            cmd(commande.strip())
    except KeyboardInterrupt:
        print("\nShell fermé.")

if __name__ == "__main__":
    terminal()