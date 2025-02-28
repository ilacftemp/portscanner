from scapy.all import sr1, IP, TCP, UDP, ICMP
import socket
import re
import ipaddress

WELL_KNOWN_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
}

def scanner():
    while (tipo_scan := input("Você deseja escanear uma rede ou um host? (r/h): ")).strip().lower() not in ("r", "h"):
        print("Opção inválida.")

    ip = consegue_ip()

    if tipo_scan == "r":
        prefixo = consegue_prefixo()
        ip = f"{ip}/{prefixo}"

    while True:
        resposta = input("\nDeseja fazer um scan de um range específico de portas? (s/n): ").strip().lower()
        if resposta == "s":
            primeira_porta, ultima_porta = range_portas()
            break
        elif resposta == "n":
            print("Apenas as WELL-KNOWN PORTS serão escaneadas.")
            primeira_porta, ultima_porta = -1, -1
            break
        else:
            print("Opção inválida.")

    while (protocolo := input("\nDeseja escanear apenas um tipo de protocolo? (tcp/udp/ambos): ").strip().lower()) not in ["tcp", "udp", "ambos"]:
        print("Protocolo inválido.")

    if "/" in ip:
        try:
            rede = ipaddress.ip_network(ip, strict=False)
            for host in rede.hosts():
                print(f"\nEscaneando o host {host}...")
                escanear_portas(str(host), primeira_porta, ultima_porta, protocolo)
        except ValueError:
            print("Rede inválida.")
    else:
        escanear_portas(ip, primeira_porta, ultima_porta, protocolo)

    
def escanear_portas(ip, primeira_porta, ultima_porta, protocolo):
    portas = range(primeira_porta, ultima_porta + 1) if primeira_porta != -1 else WELL_KNOWN_PORTS.keys()
    
    if protocolo in ["tcp", "ambos"]:
        for porta in portas:
            escanear_portas_tcp(ip, porta)
    
    if protocolo in ["udp", "ambos"]:
        for porta in portas:
            escanear_portas_udp(ip, porta)


def consegue_ip():
    while True:
        ip = input("\nUsando o formato xxx.xxx.xxx.xxx, escreva o IP do alvo (sendo rede ou host): ").strip()
        try:
            ipaddress.ip_address(ip)  # Valida IP
            return ip
        except ValueError:
            print("IP inválido. Tente novamente.")


def consegue_prefixo():
    while True:
        try:
            prefixo = int(input("\nDigite o comprimento do prefixo da rede (o valor após a barra (/) no IP): "))
            if 0 <= prefixo <= 32:
                return prefixo
        except ValueError:
            pass
        print("Prefixo inválido. Tente novamente.")


def range_portas():
    while True:
        print("\nLembrete: as portas devem estar entre 0 e 65535.")
        try:
            portas = list(map(int, input("Digite a primeira e última portas que deseja escanear separadas por vírgula: ").split(",")))
            if len(portas) == 2 and 0 <= portas[0] <= 65535 and 0 <= portas[1] <= 65535 and portas[0] <= portas[1]:
                return portas[0], portas[1]
        except ValueError:
            pass
        print("Entrada inválida. Tente novamente.")


def escanear_portas_tcp(ip, porta):
    print(f"\nEscaneando porta TCP {porta} em {ip}...")
    pacote = IP(dst=ip)/TCP(dport=porta, flags="S")
    resposta = sr1(pacote, timeout=1, verbose=False)

    servico = WELL_KNOWN_PORTS.get(porta, "Desconhecido")
    status = "filtrada"

    if resposta and resposta.haslayer(TCP):
        if resposta[TCP].flags == 0x12:  # SYN-ACK
            status = "aberta"
            banner_grabbing(ip, porta)
        elif resposta[TCP].flags == 0x14:  # RST
            status = "fechada"

    print(f"Porta {porta}: {status} ({servico})")


def escanear_portas_udp(ip, porta):
    print(f"\nEscaneando porta UDP {porta} em {ip}...")
    pacote = IP(dst=ip) / UDP(dport=porta)
    resposta = sr1(pacote, timeout=2, verbose=False)

    servico = WELL_KNOWN_PORTS.get(porta, "Desconhecido")
    status = "possivelmente aberta ou filtrada"

    if resposta and resposta.haslayer(ICMP) and resposta[ICMP].type == 3:
        if resposta[ICMP].code == 3:
            status = "fechada"

    print(f"Porta {porta}: {status} ({servico})")


def banner_grabbing(ip, porta):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, porta))
        sock.sendall(b"\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if banner:
            so = identificar_so(banner)
            print(f"Porta {porta} - SO: {so}")

    except (socket.timeout, ConnectionRefusedError):
        pass


def identificar_so(banner):
    so_patterns = {
        r"OpenSSH": "Linux/BSD (OpenSSH detectado)",
        r"Microsoft-IIS": "Windows Server (IIS detectado)",
        r"Apache": "Linux (Apache detectado)",
    }

    for pattern, so in so_patterns.items():
        if re.search(pattern, banner, re.IGNORECASE):
            return so
    
    return "Sistema operacional não identificado"


scanner()
