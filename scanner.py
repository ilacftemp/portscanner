from scapy.all import sr1, IP, TCP, UDP, Raw, ICMP
import socket
import re

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
        ip_com_pref = f"{ip}/{prefixo}"

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
            print("Opção inválida. Digite 's' para sim ou 'n' para não.")

    while (protocolo := input("\nDeseja escanear apenas um tipo de protocolo? (tcp/udp/ambos): ").strip().lower()) not in ["tcp", "udp", "ambos"]:
        print("Protocolo inválido. Escolha entre 'tcp', 'udp' ou 'ambos'.")

    if tipo_scan == "h":
        if protocolo in ["tcp", "ambos"]:
            escanear_portas_tcp(ip, primeira_porta, ultima_porta)
        if protocolo in ["udp", "ambos"]:
            escanear_portas_udp(ip, primeira_porta, ultima_porta)
    else:
        for sub in range(1, 2**(32-int(prefixo))):
            ip = ip.split(".")[:3]
            ip.append(str(sub))
            ip = ".".join(ip)
            print(f"\nEscaneando a sub-rede {ip}...")
            if protocolo in ["tcp", "ambos"]:
                escanear_portas_tcp(str(ip), primeira_porta, ultima_porta)
            if protocolo in ["udp", "ambos"]:
                escanear_portas_udp(str(ip), primeira_porta, ultima_porta)


def consegue_ip():
    while True:
        ip = input("\nUsando o formato xxx.xxx.xxx.xxx, escreva o IP do alvo (sendo rede ou host): ")
        ip_test = ip.split(".")
        if len(ip_test) == 4 and all(i.isdigit() and 0 <= int(i) <= 255 for i in ip_test):
            return ip
        print("IP inválido. Tente novamente.")


def consegue_prefixo():
    while True:
        prefixo = int(input("\nDigite o comprimento do prefixo da rede (o valor após a barra (/) no IP): "))
        if 0 <= prefixo <= 32:
            return prefixo
        print("Prefixo inválido. Tente novamente.")


def range_portas():
    while True:
        print("\nLembrete: as portas devem estar entre 0 e 65535.")
        portas = list(map(int, input("Digite a primeira e última portas que deseja escanear separadas por vírgula: ").split(",")))

        if len(portas) != 2:
            print("Número de portas inválido. Insira duas portas separadas por vírgula.\n")
            continue
        elif not (0 <= portas[0] <= 65535 and 0 <= portas[1] <= 65535):
            print("Porta inválida - as portas devem estar entre 0 e 65535.\n")
            continue
        elif portas[0] > portas[1]:
            print("A primeira porta deve ser menor do que a última.\n")
            continue

        return portas[0], portas[1]


def escanear_portas_tcp(ip, primeira_porta, ultima_porta):
    print(f"\nEscaneando portas TCP em {ip}...")

    if primeira_porta == -1:
        for porta in WELL_KNOWN_PORTS:
            pacote = IP(dst=ip)/TCP(dport=porta, flags="S")
            resposta = sr1(pacote, timeout=1, verbose=False)

            if resposta and resposta.haslayer(TCP):
                if resposta[TCP].flags == 0x12: # 0x12 = SYN-ACK
                    status = "aberta"
                    banner_grabbing(ip, porta)
                elif resposta[TCP].flags == 0x14:  # 0x14 = RST
                    status = "fechada"
                else:
                    status = "filtrada"
            else:
                status = "filtrada"

            servico = WELL_KNOWN_PORTS[porta]

            print(f"Porta {porta}: {status} ({servico})")
    else:
        for porta in range(primeira_porta, ultima_porta + 1):
            pacote = IP(dst=ip)/TCP(dport=porta, flags="S")
            resposta = sr1(pacote, timeout=1, verbose=False)

            if resposta and resposta.haslayer(TCP):
                if resposta[TCP].flags == 0x12: # 0x12 = SYN-ACK
                    status = "aberta"
                    banner_grabbing(ip, porta)
                elif resposta[TCP].flags == 0x14: # 0x14 = RST
                    status = "fechada"
                else:
                    status = "filtrada"
            else:
                status = "filtrada"

            servico = WELL_KNOWN_PORTS.get(porta, "Desconhecido")

            print(f"Porta {porta}: {status} ({servico})")


def escanear_portas_udp(ip, primeira_porta, ultima_porta):
    print(f"\nEscaneando portas UDP em {ip}...")

    if primeira_porta == -1:
        for porta in WELL_KNOWN_PORTS:
            pacote = IP(dst=ip) / UDP(dport=porta)
            resposta = sr1(pacote, timeout=1, verbose=False)

            if resposta is None:
                status = "possivelmente aberta ou filtrada"
            elif resposta.haslayer(ICMP) and resposta[ICMP].type == 3 and resposta[ICMP].code == 3:
                status = "fechada"
            else:
                status = "resposta inesperada"

            servico = WELL_KNOWN_PORTS.get(porta, "Desconhecido")

            print(f"Porta {porta}: {status} ({servico})")

    else:
        for porta in range(primeira_porta, ultima_porta + 1):
            pacote = IP(dst=ip) / UDP(dport=porta)
            resposta = sr1(pacote, timeout=1, verbose=False)

            if resposta is None:
                status = "possivelmente aberta ou filtrada"
            elif resposta.haslayer(ICMP) and resposta[ICMP].type == 3 and resposta[ICMP].code == 3:
                status = "fechada"
            else:
                status = "resposta inesperada"

            servico = WELL_KNOWN_PORTS.get(porta, "Desconhecido")

            print(f"Porta {porta}: {status} ({servico})")
            

def banner_grabbing(ip, porta):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, porta))
        
        if porta == 21:  # FTP
            sock.sendall(b'USER anonymous\r\n')
        elif porta in [25, 465, 587]:  # SMTP
            sock.sendall(b'EHLO banner_check\r\n')
        elif porta in [80, 443]:  # HTTP/HTTPS
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            sock.sendall(request.encode())
        
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if any(x in banner for x in ["400 Bad Request", "403 Forbidden", "404 Not Found"]):
            return "Nenhum SO encontrado"

        so = identificar_so(banner)

        print(f"Porta {porta} - SO: {so}")
        return so

    except Exception:
        return "Nenhum SO encontrado"

def identificar_so(banner):
    so_patterns = {
        r"OpenSSH": "Linux/BSD (OpenSSH detectado)",
        r"Microsoft-IIS": "Windows Server (IIS detectado)",
        r"Apache": "Linux (Apache detectado)",
        r"nginx": "Linux/BSD (nginx detectado)",
        r"Debian": "Linux (Debian)",
        r"Ubuntu": "Linux (Ubuntu)",
        r"CentOS": "Linux (CentOS)",
        r"Red Hat": "Linux (Red Hat)",
        r"VMware": "Possivelmente VMware ESXi",
        r"ESXi": "Possivelmente VMware ESXi",
        r"RouterOS": "Possivelmente um roteador MikroTik",
        r"Cisco": "Possivelmente um equipamento Cisco",
        r"Juniper": "Possivelmente um equipamento Juniper",
        r"RDP": "Windows (RDP detectado)",
    }

    for pattern, so in so_patterns.items():
        if re.search(pattern, banner, re.IGNORECASE):
            return so
    
    return "Sistema operacional não identificado"


scanner()