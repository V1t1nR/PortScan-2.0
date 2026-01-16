Port Scanner (Scapy)
Um scanner de portas leve e poderoso escrito em Python 3 utilizando a biblioteca Scapy. Desenvolvido para administradores de sistemas e entusiastas de segurança, este script simula funcionalidades avançadas do Nmap, incluindo detecção de Host, resolução de MAC Address e a técnica de Decoy Scan para evasão de IDS.

🚀 Funcionalidades e Tipos de Scan:

Multithreading Real: Escaneamento paralelo (até 200 threads) para alta velocidade.

Tipos de Scan:

TCP SYN: Scan furtivo (padrão).

TCP FIN: Técnica de bypass para firewalls stateless.

UDP Scan: Verificação de serviços UDP.

Fragmentação dos pacotes: Divide pacotes em pedaços de 8 bytes para tentar passar por firewalls simples.

Host Discovery: Verifica se o alvo está online (ICMP) antes de escanear.

MAC Detection: Identifica o endereço MAC e o fabricante (Vendor) se o alvo estiver na rede local (LAN).

Auto-Elevação: O script detecta automaticamente a necessidade de privilégios e solicita a senha sudo apenas uma vez, sem necessidade de digitar sudo python3.

Log Verboso: Saída detalhada estilo Nmap que mostra em tempo real qual IP (Real ou Decoy) está enviando o pacote.

📋 Pré-requisitosEste script foi projetado para ambientes Linux/Unix.

Python 3 instalado.

Biblioteca Scapy.

sudo apt update

sudo apt install python3-scapy

⚙️ Instalação (Como comando do sistema)

Para executar o script apenas digitando scan no terminal de qualquer diretório:

Dê permissão de execução ao arquivo:

chmod +x portscan.py

Mova para a pasta de binários do usuário:

sudo mv portscan.py /usr/local/bin/scan

Agora você pode rodar o scanner de qualquer lugar.

💻 Uso e ExemplosSintaxe básica:

scan [ALVO] -p [PORTAS] [OPÇÕES]

1. Scan Básico (SYN)Escaneia as portas 20 até 80 usando o método padrão (SYN Stealth) scan 192.168.1.15 -p 20-80
2. Modo Verboso (Estilo Nmap)Mostra cada etapa, ping, resolução DNS e detecção de MAC scan google.com -p 80,443 -v
3. FIN Scan (Stealth/Bypass)Envia pacotes com a flag FIN. Firewalls simples podem deixar passar, enquanto portas fechadas respondem com RST scan 192.168.1.15 -p 22 -t F -v
4. Scan UDPVerifica serviços UDP (como DNS ou DHCP) scan 192.168.1.1 -p 53,67 -U
5. Uso de Threads para aumentar a "velocidade do scan": scan 192.168.1.1 -p 80 -T5

