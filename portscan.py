#!/usr/bin/env python3
import sys
import socket
import argparse
import time
import ipaddress 
import re 
import os
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

print_lock = threading.Lock()

TIMING_CONFIG = {
    0: {"threads": 1,   "timeout": 2.0, "sleep": 5.0, "desc": "Furtivo"},
    1: {"threads": 1,   "timeout": 1.5, "sleep": 2.0, "desc": "Discreto"},
    2: {"threads": 1,   "timeout": 1.0, "sleep": 0.4, "desc": "Suave"},
    3: {"threads": 50,  "timeout": 1.0, "sleep": 0.2, "desc": "Normal"},
    4: {"threads": 100, "timeout": 0.5, "sleep": 0.1, "desc": "Agressivo"},
    5: {"threads": 200, "timeout": 0.2, "sleep": 0.0, "desc": "Extremo"}
}

def log(mensagem, nivel="INFO", verbose=False):
    if verbose:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefixo = "[*]"
        if nivel == "SUCCESS": prefixo = "[+]"
        elif nivel == "DEBUG": prefixo = "[DEBUG]"
        elif nivel == "ERROR": prefixo = "[!]"
        
        with print_lock:
            print(f"{prefixo} {timestamp} | {mensagem}")

def validar_e_resolver_alvo(alvo, verbose=False):
    log(f"Iniciando resolução DNS para: {alvo}", "INFO", verbose)
    try:
        ip_obj = ipaddress.ip_address(alvo)
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

def verificar_ligado(target_ip, timeout_val, verbose=False):
    log(f"Iniciando Host Discovery em {target_ip}", "INFO", verbose)
    up = False
    motivo = "Sem resposta"
    
    ip_privado = ipaddress.ip_address(target_ip).is_private
    
    try:
        pacote_arp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
        if verbose: log("Enviando ARP Request (Layer 2)...", "DEBUG", verbose)
        resp_arp = srp1(pacote_arp, timeout=timeout_val, verbose=0, iface=conf.iface)
        
        if resp_arp:
            up = True
            motivo = f"Resposta ARP (MAC: {resp_arp.hwsrc})"
    except Exception as e:
        if verbose: log(f"Falha no ARP: {e}", "DEBUG", verbose)

    if ip_privado and not up:
        log(f"Host {target_ip} (LAN) não respondeu ARP. Considerando OFFLINE.", "ERROR", verbose)
        return False

    if not up and not ip_privado:
        if verbose: log("Tentando ICMP Echo Request...", "DEBUG", verbose)
        resp = sr1(IP(dst=target_ip)/ICMP(), timeout=timeout_val, verbose=0)
        if resp:
            up = True
            motivo = f"Resposta ICMP (Type {resp.getlayer(ICMP).type})"

    if not up and not ip_privado:
        if verbose: log("Tentando TCP SYN para porta 443...", "DEBUG", verbose)
        sport_rnd = random.randint(1025, 65535)
        resp = sr1(IP(dst=target_ip)/TCP(sport=sport_rnd, dport=443, flags="S"), timeout=timeout_val, verbose=0)
        
        if resp and resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x12:
                is_up = True
                motivo = "Porta 443 ABERTA (SYN-ACK)"
                send(IP(dst=target_ip)/TCP(sport=sport_rnd, dport=443, flags="R"), verbose=0)
            elif flags == 0x14:
                is_up = True 
                motivo = "Porta 443 FECHADA (RST)"

    if not up and not ip_privado:
        if verbose: log("Tentando TCP ACK para porta 80...", "DEBUG", verbose)
        sport_rnd = random.randint(1025, 65535)
        resp = sr1(IP(dst=target_ip)/TCP(sport=sport_rnd, dport=80, flags="A"), timeout=timeout_val, verbose=0)
        
        if resp and resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags & 0x04:
                is_up = True
                motivo = "Porta 80 respondeu RST (ACK Ping)"

    if up:
        log(f"Host {target_ip} está ONLINE. Motivo: {motivo}", "SUCCESS", verbose)
    else:
        log(f"Host {target_ip} parece estar OFFLINE.", "ERROR", verbose)
    
    return up

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

def analisar_syn(resp):
    if resp is None: return "FILTRADA"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12: return "ABERTA"
        elif resp.getlayer(TCP).flags == 0x14: return "FECHADA"
    return "FILTRADA"

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

def worker_scan(target_ip, porta, tipo_scan, usar_frag, verbose, meu_ip_real, timeout_val, sleep_val):
    if sleep_val > 0:
        time.sleep(sleep_val)

    proto_servico = "udp" if tipo_scan == "UDP" else "tcp"
    src_port = RandShort()
    
    try:
        servico = obter_servico(porta, proto_servico)
        log(f"Testando {target_ip}:{porta}", "DEBUG", verbose)
        
        estado = "ERRO"
        resp = None

        pkt = None
        if tipo_scan == "SYN":
            pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="S")
        elif tipo_scan == "FIN":
            pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="F")
        elif tipo_scan == "XMAS":
            pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="FPU")
        elif tipo_scan == "UDP":
            pkt = IP(dst=target_ip)/UDP(sport=src_port, dport=porta)

        if usar_frag and pkt:
            fragmentos = fragment(pkt, fragsize=8)
            
            if verbose: log(f"Enviando {len(fragmentos)} fragmentos para porta {porta}...", "DEBUG", verbose)
            
            for frag in fragmentos:
                send(frag, verbose=0)
            resp = sr1(pkt, timeout=timeout_val, verbose=0)

        else:
            resp = sr1(pkt, timeout=timeout_val, verbose=0)

        if tipo_scan == "SYN":
            estado = analisar_syn(resp)
            if estado == "ABERTA":
                send(IP(dst=target_ip)/TCP(sport=src_port, dport=porta, flags="R"), verbose=0)
        elif tipo_scan == "FIN":
            estado = analisar_fin(resp)
        elif tipo_scan == "XMAS":
            estado = analisar_xmas(resp)
        elif tipo_scan == "UDP":
            estado = analisar_udp(resp)

        if estado in ["ABERTA", "NÃO FILTRADA"] or (estado == "ABERTA|FILTRADA" and tipo_scan == "UDP"):
             log(f"Descoberta porta {estado}: {porta}/{proto_servico} ({servico})", "SUCCESS", verbose)

        return (porta, proto_servico, servico, estado)

    except Exception as e:
        log(f"Erro na porta {porta}: {e}", "ERROR", verbose)
        return None

def executar_scan(target_ip, portas, tipo_scan, usar_frag, verbose, timing_level):
    start_time = time.time()
    
    config = TIMING_CONFIG[timing_level]
    num_threads = config["threads"]
    timeout_val = config["timeout"]
    sleep_val = config["sleep"]
    
    try:
        meu_ip_real = get_if_addr(conf.iface)
    except:
        meu_ip_real = "IP Desconhecido"

    log(f"Iniciando {tipo_scan} Scan em {target_ip}", "INFO", verbose)
    log(f"Modo T{timing_level} ({config['desc']}): {num_threads} Threads | Timeout {timeout_val}s", "INFO", verbose)
    
    if usar_frag:
        log("MODO DE FRAGMENTAÇÃO ATIVO: Pacotes serão divididos em 8 bytes (MTU).", "INFO", verbose)

    log(f"Escaneando {len(portas)} portas...", "INFO", verbose)

    resultados = []
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for porta in portas:
            futures.append(executor.submit(worker_scan, target_ip, porta, tipo_scan, usar_frag, verbose, meu_ip_real, timeout_val, sleep_val))
        
        for future in futures:
            res = future.result()
            if res:
                resultados.append(res)

    resultados.sort(key=lambda x: x[0])

    elapsed = time.time() - start_time
    print(f"\nScan finalizado em {elapsed:.2f} segundos")
    print("-" * 85)
    print(f"{'PORTA':<10} {'PROTOCOLO':<10} {'SERVIÇO':<20} {'ESTADO'}")
    print("-" * 85)
    
    for r in resultados:
        print(f"{r[0]:<10} {r[1].upper():<10} {r[2]:<20} {r[3]}")
    print("-" * 85)

def main():
    parser = argparse.ArgumentParser(description="PortScan Estilo Nmap (Fragmentação e Threads)")
    parser.add_argument("target", help="IP ou Hostname Alvo")
    parser.add_argument("-p", "--ports", help="Range de portas (Padrão: 1-1000)", required=False)
    parser.add_argument("-U", "--udp", action="store_true", help="Realizar UDP Scan")
    parser.add_argument("-t", "--type", choices=["S", "X", "F"], default="S", 
                        help="Tipo TCP: S (SYN), X (XMAS), F (FIN). Padrão: S")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo Verboso")
    
    parser.add_argument("-f", "--fragment", action="store_true", help="Ativar Fragmentação de Pacotes (Bypass Firewall)")
    
    parser.add_argument("-T", dest="timing", type=int, choices=range(6), default=3,
                        help="Nível de velocidade (0-5). Padrão: 3")

    args = parser.parse_args()

    if os.geteuid() != 0:
        try:
            os.execvp("sudo", ["sudo", "python3"] + sys.argv)
        except Exception as e:
            sys.exit(f"Encerrando Scan: {e}")
            
    mapa_scans = {"S": "SYN", "X": "XMAS", "F": "FIN"}
    tipo_escolhido = "UDP" if args.udp else mapa_scans[args.type]

    if args.verbose:
        print(f"Iniciando PortScan em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    target_ip = validar_e_resolver_alvo(args.target, args.verbose)

    timeout_discovery = TIMING_CONFIG[args.timing]["timeout"]
    if not verificar_ligado(target_ip, timeout_discovery, args.verbose):
        print(f"O Host {target_ip} está OFFLINE.")
        sys.exit()

    if args.ports:
        portas = validar_portas(args.ports)
    else:
        if args.verbose:
            portas = range(1, 1001)

    executar_scan(target_ip, portas, tipo_escolhido, args.fragment, args.verbose, args.timing)

if __name__ == "__main__":
    main()
