# Scanner de Portas com Scapy

Este é um **scanner de portas** baseado em **Scapy** que permite identificar serviços abertos em um **host ou rede**, utilizando técnicas de **TCP SYN Scan** e **UDP Scan**. O programa também utiliza **banners** para tentar identificar o sistema operacional ou o serviço rodando em determinada porta.

## Funcionalidades
 **Escaneia um único host ou uma rede inteira**  
 **Suporte a TCP e UDP**  
 **Identificação de serviços por portas bem conhecidas**  
 **Uso de banner para identificação de SO**  
 **Validação de entrada para evitar erros**  

---

## Instalação

### 1. Requisitos

Para executar o scanner corretamente, você precisa instalar as seguintes dependências:

#### **Windows**
1. **Instale o Npcap** (obrigatório para captura de pacotes com Scapy):  
   🔗 [Baixar Npcap](https://nmap.org/npcap/)
   
2. **Instale a biblioteca Scapy**:
   ```bash
   pip install scapy
   ```

#### **Linux/macOS**
1. **Instale o libpcap**:
   ```bash
   sudo apt install libpcap-dev  # Debian/Ubuntu
   sudo dnf install libpcap-devel  # Fedora
   brew install libpcap  # macOS
   ```
5. **Instale a biblioteca Scapy**:
   ```bash
   pip install scapy
   ```

---

## Como Usar

Execute o script no terminal:

```bash
python scanner.py
```

O programa pedirá algumas informações para personalizar o escaneamento:

1. **Rede ou Host:** Escolha `"r"` para escanear uma rede inteira ou `"h"` para escanear um único IP.  
2. **IP de destino:** Digite o endereço IP do alvo.  
3. **Prefixo de Rede (CIDR):** Se escolher **rede**, informe o prefixo (ex: `/24` para escanear `xxx.xxx.xxx.0 - xxx.xxx.xxx.255`).  
4. **Escolha das portas:**  
   - `"s"` → Especificar um **intervalo de portas**  
   - `"n"` → Escanear apenas **portas bem conhecidas**  
5. **Protocolo:** Escolha entre **TCP**, **UDP** ou **ambos**.  

---

## Exemplos de Uso

### Escanear um único host
Se desejar escanear um **host específico**, escolha `"h"` e forneça um IP:

```
Você deseja escanear uma rede ou um host? (r/h): h
Usando o formato xxx.xxx.xxx.xxx, escreva o IP do alvo (sendo rede ou host): 192.168.1.10
Deseja fazer um scan de um range específico de portas? (s/n): s
Digite a primeira e última portas que deseja escanear separadas por vírgula: 20,1000
Deseja escanear apenas um tipo de protocolo? (tcp/udp/ambos): tcp
```
 **O scanner testará as portas de 20 a 1000 no protocolo TCP.**

---

### Escanear uma rede inteira
Se deseja escanear **toda uma sub-rede**, escolha `"r"`:

```
Você deseja escanear uma rede ou um host? (r/h): r
Usando o formato xxx.xxx.xxx.xxx, escreva o IP do alvo (sendo rede ou host): 192.168.1.0
Digite o comprimento do prefixo da rede (o valor após a barra (/)): 24
Deseja fazer um scan de um range específico de portas? (s/n): n
Deseja escanear apenas um tipo de protocolo? (tcp/udp/ambos): ambos
```
 **O scanner testará todas as máquinas dentro do range `192.168.1.1 - 192.168.1.255`, escaneando apenas portas conhecidas (HTTP, FTP, SSH, etc.).**

---

## Serviços Detectados

Caso a porta escaneada seja uma das **WELL-KNOWN PORTS**, o script mostrará qual serviço está rodando:

| Porta | Serviço |
|-------|---------|
| 20    | FTP Data |
| 21    | FTP Control |
| 22    | SSH |
| 25    | SMTP |
| 53    | DNS |
| 80    | HTTP |
| 110   | POP3 |
| 143   | IMAP |
| 443   | HTTPS |
| 995   | POP3S |
| 3306  | MySQL |
| 3389  | RDP |

---

## Possíveis Problemas e Soluções

### **Scapy não consegue enviar pacotes no Windows**
 **Solução:** Certifique-se de que o **Npcap** está instalado corretamente e execute o script como **administrador**.

### **"Permission Denied" ao rodar no Linux/macOS**
 **Solução:** O Scapy precisa de permissões de superusuário para enviar pacotes:
```bash
sudo python scanner.py
```
