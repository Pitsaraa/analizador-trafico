from scapy.layers.inet import ICMP, IP, TCP, UDP

from analizador import analyze
from analizador.informe import to_markdown


def pkt(capa, t):
    capa.time = t
    return capa


def syn(src, dst, port, t, flags="S"):
    return pkt(IP(src=src, dst=dst) / TCP(dport=port, flags=flags), t)


def test_detecta_escaneo_rapido():
    packets = [syn("10.0.0.66", "10.0.0.1", port, i * 0.1) for i, port in enumerate(range(1, 31))]
    report = analyze(packets, threshold=15, window=10)
    assert len(report.alerts) == 1
    alerta = report.alerts[0]
    assert (alerta.src, alerta.dst) == ("10.0.0.66", "10.0.0.1")
    assert len(alerta.ports) == 30


def test_escaneo_lento_fuera_de_ventana_no_alerta():
    packets = [syn("10.0.0.66", "10.0.0.1", port, i * 2.0) for i, port in enumerate(range(1, 31))]
    assert analyze(packets, threshold=15, window=10).alerts == []


def test_trafico_normal_no_alerta():
    packets = [syn("10.0.0.5", "10.0.0.1", 443, i * 0.1) for i in range(100)]
    packets += [syn("10.0.0.5", "10.0.0.1", port, 20 + i, flags="SA") for i, port in enumerate(range(1, 50))]
    assert analyze(packets).alerts == []


def test_estadisticas_y_informe():
    packets = [
        pkt(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80), 0),
        pkt(IP(src="10.0.0.5", dst="10.0.0.1") / UDP(dport=53), 1),
        pkt(IP(src="10.0.0.6", dst="10.0.0.1") / ICMP(), 3),
    ]
    report = analyze(packets)
    assert report.total_packets == 3
    assert report.duration == 3
    assert report.protocols == {"TCP": 1, "UDP": 1, "ICMP": 1}
    assert report.top_sources.most_common(1) == [("10.0.0.5", 2)]
    assert "Sin alertas." in to_markdown(report, "test")


def test_sin_paquetes():
    report = analyze([])
    assert report.total_packets == 0
    assert "Sin alertas." in to_markdown(report, "vacío")
