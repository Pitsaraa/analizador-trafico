"""Crea demo.pcap con tráfico normal, un escaneo de puertos y un barrido de ping simulados.

Los paquetes se construyen en memoria y se guardan en disco: no se envía nada a la red.
"""

import random

from scapy.all import wrpcap
from scapy.layers.inet import ICMP, IP, TCP, UDP

random.seed(42)
T0 = 1_780_000_000.0


def paquete(capa, t):
    capa.time = t
    return capa


def generar():
    pkts = []
    clientes = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    # Tráfico normal: navegación web, DNS y algún ping durante 60 s
    for i in range(300):
        t = T0 + random.uniform(0, 60)
        cliente = random.choice(clientes)
        tipo = random.random()
        if tipo < 0.6:
            servidor = random.choice(["142.250.184.4", "151.101.1.69"])
            flags = random.choice(["S", "A", "PA", "FA"])
            pkts.append(paquete(IP(src=cliente, dst=servidor) / TCP(sport=random.randint(49152, 65535), dport=443, flags=flags), t))
        elif tipo < 0.9:
            pkts.append(paquete(IP(src=cliente, dst="192.168.1.1") / UDP(sport=random.randint(49152, 65535), dport=53), t))
        else:
            pkts.append(paquete(IP(src=cliente, dst="8.8.8.8") / ICMP(), t))

    # Escaneo SYN: 192.168.1.66 sondea los puertos 1-100 de 192.168.1.20 en 5 s
    for i, puerto in enumerate(range(1, 101)):
        pkts.append(paquete(IP(src="192.168.1.66", dst="192.168.1.20") / TCP(sport=40000, dport=puerto, flags="S"), T0 + 20 + i * 0.05))

    # Barrido de ping: 192.168.1.77 hace ping a 192.168.1.100-149 en 2,5 s
    for i in range(50):
        pkts.append(paquete(IP(src="192.168.1.77", dst=f"192.168.1.{100 + i}") / ICMP(type=8), T0 + 40 + i * 0.05))

    pkts.sort(key=lambda p: p.time)
    wrpcap("demo.pcap", pkts)
    print(f"demo.pcap creado con {len(pkts)} paquetes")


if __name__ == "__main__":
    generar()
