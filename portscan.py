#!/usr/bin/env python3
import sys
import socket
import argparse
import time
import ipaddress 
import re 
import os
import random
from datetime import datetime
from scapy.all import *

# Retira mensagens de erros da biblioteca Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# Mensagem de Log quando o modo verbose está ativo
def log(mensagem, nivel="INFO", verbose=False):
    if verbose:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefixo = "[*]"
        if nivel == "SUCCESS":
            prefixo = "[+]"
        elif nivel == "DEBUG":
            prefixo = "[DEBUG]"
        elif nivel == "ERROR":
            prefixo = "[!]"
            
        print(f"{prefixo} {timestamp} | {mensagem}")

# Função para gerar IPs aleatórios para utilização no Decoy Scan
def gerar_ip_aleatorio():
    primeiro_octeto = random.randint(1, 223)
    while primeiro_octeto in [127, 10, 172, 192]: 
         primeiro_octeto = random.randint(1, 223)
    return f"{primeiro_octeto}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

# Função para execução do Decoy Scan
def processar_decoys(decoy_arg):
    lista_decoys = []
    if not decoy_arg:
        return []

    if decoy_arg.upper().startswith("RND:"):
        try:
            quantidade = int(decoy_arg.split(":")[1])
            for _ in range(quantidade):
                lista_decoys.append(gerar_ip_aleatorio())
        except (IndexError, ValueError):
            sys.exit("Erro: Formato RND inválido. Use RND:numero (ex: RND:5).")
    else:
        ips = decoy_arg.split(",")
        for ip in ips:
            ip = ip.strip()
            try:
                ipaddress.ip_address(ip)
                lista_decoys.append(ip)
            except ValueError:
                sys.exit(f"Erro: O IP de Decoy '{ip}' é inválido.")
    return lista_decoys

# Função para resolver DNS da máquina alvo
def validar_e_resolver_alvo(alvo, verbose=False):
    log(f"Iniciando resolução DNS para: {alvo}", "INFO", verbose)
    try:
        ip_obj = ipaddress.ip_address(alvo)
        log(f"IP Alvo: {ip_obj}", "INFO", verbose)
        return str(ip_obj)
    except ValueError:
        pass

    regex_dominio = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    if alvo != "localhost" and not re.match(regex_dominio, alvo):
        sys.exit(f"O domínio '{alvo}' inválido.")

    try:
        ip = socket.gethostbyname(alvo)
        log(f"Resolução DNS concluída: {alvo} -> {ip}", "SUCCESS", verbose)
        return ip
    except socket.gaierror:
        sys.exit(f"Não foi possível encontrar o IP para '{alvo}', domínio inalcançável.")

# Função para verificar o estado da máquina alvo
def verificar_ligado(target_ip, verbose=False):
    log(f"Iniciando Host Discovery em {target_ip}", "INFO", verbose)
    is_up = False
    motivo = "Sem resposta"

    log(f"Enviando ICMP Echo Request para {target_ip}", "DEBUG", verbose)
    resp_icmp = sr1(IP(dst=target_ip)/ICMP(), timeout=1, verbose=0)
    if resp_icmp:
        is_up = True
        motivo = f"Resposta ICMP (Type {resp_icmp.getlayer(ICMP).type})"

    if is_up:
        log(f"Host {target_ip} está ONLINE.", "SUCCESS", verbose)
        if verbose:
            try:
                mac_addr = getmacbyip(target_ip)
                if mac_addr:
                    vendor = "Desconhecido"
                    try:
                        vendor = conf.manufdb._get_manuf(mac_addr)
                    except: pass
                    log(f"MAC Address: {mac_addr} ({vendor})", "SUCCESS", verbose)
            except: pass
    else:
        log(f"Host {target_ip} está OFFLINE.", "ERROR", verbose)
    return is_up

# Função para evitar erro de digitação nas portas
def validar_portas(ports_str):
    if not re.match(r"^[\d\-,]+$", ports_str):
        sys.exit(f"A porta '{ports_str}' contém caracteres inválidos.")
    try:
        if ports_str == "-": return range(1, 65536)
        elif "-" in ports_str:
            partes = ports_str.split("-")
            start, end = int(partes[0]), int(partes[1])
            if start > end or start < 1 or end > 65535: sys.exit(f"Range inválido.")
            return range(start, end + 1)
        else:
            lista = [int(p) for p in ports_str.split(",")]
            for p in lista:
                if p < 1 or p > 65535: sys.exit(f"Porta {p} inválida.")
            return lista
    except ValueError:
        sys.exit("Erro ao processar portas.")

def obter_servico(porta, proto="tcp"):
    try: return socket.getservbyport(porta, proto)
    except: return "Desconhecido"

# Funções de análise, aqui será feito a analise do pacote de resposta e indicar o estado da porta
def analisar_syn(resp):
    if resp is None: return "FILTRADA"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12: return "ABERTA"
        elif resp.getlayer(TCP).flags == 0x14: return "FECHADA"
    return "FILTRADA"

def analisar_ack(resp):
    if resp is None: return "FILTRADA"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x04: return "NÃO FILTRADA"
    return "DESCONHECIDO"

def analisar_fin(resp):
    if resp is None: return "ABERTA|FILTRADA"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags & 0x04: return "FECHADA"
    elif resp.haslayer(ICMP):
        if resp.getlayer(ICMP).type == 3: return "FILTRADA"
    return "DESCONHECIDO"

def analisar_udp(resp):
    if resp is None: return "ABERTA|FILTRADA"
    elif resp.haslayer(ICMP):
        tipo = resp.getlayer(ICMP).type
        codigo = resp.getlayer(ICMP).code
        if tipo == 3 and codigo == 3: return "FECHADA"
        elif tipo == 3 and codigo in [1, 2, 9, 10, 13]: return "FILTRADA"
    elif resp.haslayer(UDP): return "ABERTA"
    return "DESCONHECIDO"

def analisar_xmas(resp):
    if resp is None: return "ABERTA|FILTRADA"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags & 0x04: return "FECHADA"
    elif resp.haslayer(ICMP):
        if resp.getlayer(ICMP).type == 3: return "FILTRADA"
    return "DESCONHECIDO"

# Função principal onde o PortScan é executado
def executar_scan(target_ip, portas, tipo_scan, decoys, verbose):
    start_time = time.time()
    proto_servico = "udp" if tipo_scan == "UDP" else "tcp"
    
    try:
        meu_ip_real = get_if_addr(conf.iface)
    except:
        meu_ip_real = "IP Desconhecido"

    log(f"Iniciando {tipo_scan} Scan em {target_ip}", "INFO", verbose)
    
    if decoys:
        log(f"DECOY ATIVO. Utilizando os IPs:", "INFO", verbose)
        for d in decoys:
             log(f" -> {d}", "INFO", verbose)

    log(f"Escaneando {len(portas)} portas", "INFO", verbose)

    resultados = []

    for porta in portas:
        src_port = RandShort()
        
        try:
            servico = obter_servico(porta, proto_servico)
            
            if decoys:
                for decoy_ip in decoys:
                    log(f"IP Falso: {decoy_ip} enviando pacote para {target_ip}:{porta}", "DEBUG", verbose)
                    
                    if tipo_scan == "SYN":
                        send(IP(src=decoy_ip, dst=target_ip)/TCP(sport=src_port, dport=porta, flags="S"), verbose=0)
                    elif tipo_scan == "FIN":
                        send(IP(src=decoy_ip, dst=target_ip)/TCP(sport=src_port, dport=porta, flags="F"), verbose=0)
                    elif tipo_scan == "UDP":
                        send(IP(src=decoy_ip, dst=target_ip)/UDP(sport=src_port, dport=porta), verbose=0)

            log(f"IP Real: {meu_ip_real} enviando pacote para {target_ip}:{porta}", "DEBUG", verbose)
            
            estado = "ERRO"
            resp = None

            if tipo_scan == "SYN":
                pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="S")
                resp = sr1(pkt, timeout=1, verbose=0)
                estado = analisar_syn(resp)
                if estado == "ABERTA":
                    send(IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="R"), verbose=0)
            
            elif tipo_scan == "FIN":
                pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="F")
                resp = sr1(pkt, timeout=1, verbose=0)
                estado = analisar_fin(resp)

            elif tipo_scan == "ACK":
                pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="A")
                resp = sr1(pkt, timeout=1, verbose=0)
                estado = analisar_ack(resp)

            elif tipo_scan == "UDP":
                pkt = IP(dst=target_ip)/UDP(sport=src_port, dport=porta)
                resp = sr1(pkt, timeout=2, verbose=0) 
                estado = analisar_udp(resp)

            elif tipo_scan == "XMAS":
                pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="FPU")
                resp = sr1(pkt, timeout=1, verbose=0)
                estado = analisar_xmas(resp)

            if estado in ["ABERTA", "NÃO FILTRADA"] or (estado == "ABERTA|FILTRADA" and tipo_scan == "UDP"):
                 log(f"Descoberta porta {estado}: {porta}/{proto_servico} ({servico})", "SUCCESS", verbose)

            resultados.append((porta, proto_servico, servico, estado))

        except KeyboardInterrupt:
            print("\nScan interrompido pelo usuário.")
            sys.exit(0)
        except Exception as e:
            log(f"Erro na porta {porta}: {e}", "ERROR", verbose)

    elapsed = time.time() - start_time
    print(f"\nScan finalizado em {elapsed:.2f} segundos")
    print("-" * 85)
    print(f"{'PORTA':<10} {'PROTOCOLO':<10} {'SERVIÇO':<20} {'ESTADO'}")
    print("-" * 85)
    
    for r in resultados:
        print(f"{r[0]:<10} {r[1].upper():<10} {r[2]:<20} {r[3]}")
    print("-" * 85)

# Main
def main():
    parser = argparse.ArgumentParser(description="PortScan Estilo Nmap com Decoy")
    parser.add_argument("target", help="IP ou Hostname Alvo")
    
    parser.add_argument("-p", "--ports", help="Range de portas (Padrão: 1-1024)", required=False)
    
    parser.add_argument("-U", "--udp", action="store_true", help="Realizar UDP Scan")
    parser.add_argument("-t", "--type", choices=["S", "A", "X", "F"], default="S", 
                        help="Tipo TCP: S (SYN), A (ACK), X (XMAS), F (FIN). Padrão: S")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo Verboso")
    parser.add_argument("-D", "--decoy", help="IPs falsos. Ex: '10.0.0.1,10.0.0.2' OU 'RND:5'")

    args = parser.parse_args()

    if os.geteuid() != 0:
        try:
            os.execvp("sudo", ["sudo", "python3"] + sys.argv)
        except Exception as e:
            sys.exit(f"Encerrando Scan: {e}")
            
    mapa_scans = {"S": "SYN", "A": "ACK", "X": "XMAS", "F": "FIN"}
    tipo_escolhido = "UDP" if args.udp else mapa_scans[args.type]

    if args.verbose:
        print(f"Iniciando PortScan em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    lista_decoys = processar_decoys(args.decoy)
    target_ip = validar_e_resolver_alvo(args.target, args.verbose)

    if not verificar_ligado(target_ip, args.verbose):
        print(f"O Host {target_ip} está offline.")
        sys.exit()

    if args.ports:
        portas = validar_portas(args.ports)
    else:
        if args.verbose:
            print("[*] Nenhuma porta definida. Escaneando as 1024 portas padrão...")
        portas = range(1, 1025)

    executar_scan(target_ip, portas, tipo_escolhido, lista_decoys, args.verbose)

# Indicativo para o python saber onde deve começar
if __name__ == "__main__":
    main()
