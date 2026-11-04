"""Análisis de tráfico de red: estadísticas y detección de escaneos de puertos y barridos de ping."""

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

from scapy.layers.inet import ICMP, IP, TCP, UDP

SYN = 0x02
ACK = 0x10


@dataclass
class ScanAlert:
    src: str
    dst: str
    first_seen: float
    detected_at: float
    ports: set = field(default_factory=set)


@dataclass
class SweepAlert:
    src: str
    first_seen: float
    detected_at: float
    targets: set = field(default_factory=set)


@dataclass
class Report:
    total_packets: int = 0
    duration: float = 0.0
    protocols: Counter = field(default_factory=Counter)
    top_sources: Counter = field(default_factory=Counter)
    top_dst_ports: Counter = field(default_factory=Counter)
    alerts: list = field(default_factory=list)
    sweeps: list = field(default_factory=list)


def _protocol(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "Otro"


def analyze(packets, threshold=15, window=10.0):
    """Analiza una lista de paquetes de Scapy.

    Se considera escaneo cuando una IP envía SYN (sin ACK) a `threshold` o más
    puertos distintos del mismo destino en menos de `window` segundos, y barrido
    de ping cuando envía ICMP Echo Request a `threshold` o más IPs distintas.
    """
    report = Report()
    ip_packets = sorted((p for p in packets if p.haslayer(IP)), key=lambda p: float(p.time))
    report.total_packets = len(ip_packets)
    if not ip_packets:
        return report

    report.duration = float(ip_packets[-1].time) - float(ip_packets[0].time)
    recent = defaultdict(deque)  # (src, dst) -> deque[(tiempo, puerto)]
    alerts = {}
    recent_pings = defaultdict(deque)  # src -> deque[(tiempo, ip_destino)]
    sweeps = {}

    for pkt in ip_packets:
        t = float(pkt.time)
        src, dst = pkt[IP].src, pkt[IP].dst
        report.protocols[_protocol(pkt)] += 1
        report.top_sources[src] += 1

        # Barrido de ping: ICMP Echo Request (tipo 8) hacia muchas IPs distintas
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            if src in sweeps:
                sweeps[src].targets.add(dst)
            else:
                window_pings = recent_pings[src]
                window_pings.append((t, dst))
                while window_pings and t - window_pings[0][0] > window:
                    window_pings.popleft()
                targets = {ip for _, ip in window_pings}
                if len(targets) >= threshold:
                    sweeps[src] = SweepAlert(src, window_pings[0][0], t, targets)
                    del recent_pings[src]

        if not pkt.haslayer(TCP):
            continue
        tcp = pkt[TCP]
        report.top_dst_ports[tcp.dport] += 1
        if not (tcp.flags & SYN) or (tcp.flags & ACK):
            continue

        key = (src, dst)
        if key in alerts:
            alerts[key].ports.add(tcp.dport)
            continue

        window_pkts = recent[key]
        window_pkts.append((t, tcp.dport))
        while window_pkts and t - window_pkts[0][0] > window:
            window_pkts.popleft()

        ports = {port for _, port in window_pkts}
        if len(ports) >= threshold:
            alerts[key] = ScanAlert(src, dst, window_pkts[0][0], t, ports)
            del recent[key]

    report.alerts = sorted(alerts.values(), key=lambda a: a.first_seen)
    report.sweeps = sorted(sweeps.values(), key=lambda s: s.first_seen)
    return report
