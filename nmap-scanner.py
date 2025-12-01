import re
import subprocess
import ipaddress
import socket

def get_input_type(target):
    try:
        # IP adresi mi?
        ip = ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    try:
        # CIDR bloğu mu?
        network = ipaddress.ip_network(target, strict=False)
        return "cidr"
    except ValueError:
        pass

    try:
        # Geçerli bir host ismi mi (alan adı)?
        socket.gethostbyname(target)
        return "host"
    except socket.error:
        return "unknown"

def run_nmap_scan(target):
    input_type = get_input_type(target)

    if input_type == "unknown":
        print("Geçersiz hedef girdisi.")
        return

    print(f"[+] Girdi tipi: {input_type.upper()} -> {target}")
    
    # nmap komutu
    command = ["nmap", "-Pn", "-T4", target]

    try:
        result = subprocess.run(command, capture_output=True, text=True)
        print("---------- Nmap Çıktısı ----------")
        print(result.stdout)
    except Exception as e:
        print(f"Hata oluştu: {e}")

if __name__ == "__main__":
    target = input("Hedef IP/Host/CIDR girin: ").strip()
    run_nmap_scan(target)
