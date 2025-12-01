import subprocess
import ipaddress
import socket
import re
import xml.etree.ElementTree as ET
import os

# Desteklenen servis ve default username/password listesi
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

def get_input_type(target):
    """Verilen girdinin IP, CIDR veya Hostname olup olmadığını belirler."""
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
    """Nmap XML çıktısını ayrıştırarak açık TCP portlarının listesini döndürür."""
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
    """Belirtilen hedefe karşı bir Nmap taraması çalıştırır ve çıktıyı XML olarak alır."""
    print(f"\n[*] {target} → Nmap -Pn -A taraması başlatılıyor...")
    try:
        cmd = ["nmap", "-Pn", "-A", "-oX", "-", target]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        ports = parse_nmap_xml(result.stdout)
        if ports:
            print(f"[+] {target} için bulunan açık portlar: {ports}")
        else:
            print(f"[-] {target} için desteklenen açık port bulunamadı.")
        return ports, result.stdout
    except FileNotFoundError:
        print("[!] HATA: 'nmap' komutu bulunamadı. Lütfen Nmap'in kurulu olduğundan emin olun.")
        return [], ""
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"[!] {target} için Nmap taraması başarısız oldu veya zaman aşımına uğradı. Hata: {e}")
        return [], ""

def load_custom_credentials(username_file, password_file):
    """Kullanıcı tarafından sağlanan dosyalardan kombinasyonları yükler."""
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
    """PostgreSQL için 'psql' istemcisini kullanarak kimlik doğrulaması dener."""
    print(f"[*] {ip}:{port} → POSTGRES (psql ile) için parola denemesi başlatılıyor...")
    found_credential = False
    my_env = os.environ.copy()
    for username, password in creds:
        my_env["PGPASSWORD"] = password
        try:
            cmd = ["psql", "-h", ip, "-U", username, "-d", "postgres", "-p", str(port), "-c", "\\q"]
            result = subprocess.run(cmd, env=my_env, capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                print(f"[✅] GİRİŞ BAŞARILI → POSTGRES | {ip}:{port} | Kullanıcı: {username} | Parola: '{password}'")
                found_credential = True
        except FileNotFoundError:
            print("[!] HATA: 'psql' komutu bulunamadı. 'postgresql-client' paketini kurun.")
            return
        except subprocess.TimeoutExpired:
            print(f"[-] {ip}:{port} için psql denemesi ({username}) zaman aşımına uğradı.")
    if not found_credential:
        print(f"[-] {ip}:{port} → POSTGRES için listedeki kimlik bilgileriyle giriş yapılamadı.")

def run_hydra(ip, port, service, creds):
    """Belirtilen servis için Hydra ile parola denemesi yapar."""
    print(f"[*] {ip}:{port} → {service.upper()} (Hydra ile) için parola denemesi başlatılıyor...")
    found_credential = False
    for username, password in creds:
        password_arg = password if password else "^$"
        try:
            cmd = ["hydra", "-t", "4", "-l", username, "-p", password_arg, "-s", str(port), "-f", f"{service}://{ip}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if "1 valid password found" in result.stdout:
                print(f"[✅] GİRİŞ BAŞARILI → {service.upper()} | {ip}:{port} | Kullanıcı: {username} | Parola: '{password}'")
                found_credential = True
        except FileNotFoundError:
            print("[!] HATA: 'hydra' komutu bulunamadı. Hydra'nın kurulu olduğundan emin olun.")
            return
        except Exception as e:
            print(f"[!] Hydra çalıştırılırken bir hata oluştu: {e}")
    if not found_credential:
        print(f"[-] {ip}:{port} → {service.upper()} için listedeki kimlik bilgileriyle giriş yapılamadı.")

def main():
    target_input = input("Hedef IP / Hostname / CIDR girin: ").strip()
    
    # YENİ MANTIK: Kullanılacak kimlik bilgisi kaynağını başlangıçta belirle
    custom_creds = []
    use_defaults = False
    
    custom_lists_choice = input("[?] Kendi kullanıcı/parola listelerinizi kullanmak ister misiniz? (e/h): ").lower().strip()
    
    if custom_lists_choice == 'e':
        username_file = input("  [->] Kullanıcı adı dosyasının yolunu girin: ").strip()
        password_file = input("  [->] Parola dosyasının yolunu girin: ").strip()
        custom_creds = load_custom_credentials(username_file, password_file)
        if not custom_creds:
            print("[!] Özel kimlik bilgisi listeleri yüklenemedi veya boş. Program sonlandırılıyor.")
            return
        print(f"[+] Özel listeler kullanılacak. {len(custom_creds)} adet kimlik bilgisi kombinasyonu yüklendi.")
    elif custom_lists_choice == 'h':
        use_defaults = True
        print("[+] Varsayılan kimlik bilgileri kullanılacak.")
    else:
        print("[!] Geçersiz seçim. Lütfen 'e' veya 'h' girin.")
        return

    input_type = get_input_type(target_input)
    if input_type == "unknown":
        print("[!] Geçersiz hedef girdiniz.")
        return

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
            return

    for ip in targets:
        open_ports, _ = run_nmap_scan(ip)
        if not open_ports:
            print(f"[-] {ip} için devam ediliyor, açık port bulunamadı veya desteklenmiyor.")
            print("-" * 60)
            continue
        
        for port in open_ports:
            if port in default_credentials:
                service, base_creds = default_credentials[port]
                creds_for_this_run = []
                
                # YENİ MANTIK: Ya varsayılanları ya da özelleri kullan
                if use_defaults:
                    creds_for_this_run = base_creds
                else: # Özel liste modu
                    creds_for_this_run = custom_creds
                
                print(f"\n[*] Port {port} ({service.upper()}) için toplam {len(creds_for_this_run)} kimlik bilgisi denenecek.")
                
                if not creds_for_this_run:
                    print(f"[-] Port {port} için denenecek kimlik bilgisi bulunmuyor, atlanıyor.")
                    continue
                
                # Yönlendirme mantığı
                if port == 5432:
                    run_psql_check(ip, port, creds_for_this_run)
                else:
                    run_hydra(ip, port, service, creds_for_this_run)
            else:
                print(f"[-] Port {port} → desteklenen bir servis değil, atlanıyor.")
        print("-" * 60)

if __name__ == "__main__":
    main()
