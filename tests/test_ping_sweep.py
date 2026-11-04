from scapy.layers.inet import ICMP, IP

from analizador import analyze


def ping(src, dst, t, tipo=8):
    p = IP(src=src, dst=dst) / ICMP(type=tipo)
    p.time = t
    return p


def test_detecta_barrido_de_ping():
    packets = [ping("10.0.0.66", f"10.0.0.{i}", i * 0.1) for i in range(1, 31)]
    report = analyze(packets)
    assert len(report.sweeps) == 1
    alerta = report.sweeps[0]
    assert alerta.src == "10.0.0.66"
    assert len(alerta.targets) == 30


def test_pings_al_mismo_equipo_no_son_barrido():
    packets = [ping("10.0.0.5", "8.8.8.8", i * 0.1) for i in range(100)]
    assert analyze(packets).sweeps == []


def test_respuestas_de_ping_no_cuentan():
    # Echo Reply (tipo 0): son respuestas, no sondeos
    packets = [ping(f"10.0.0.{i}", "10.0.0.66", i * 0.1, tipo=0) for i in range(1, 31)]
    packets += [ping("10.0.0.66", f"10.0.0.{i}", i * 0.1, tipo=0) for i in range(1, 31)]
    assert analyze(packets).sweeps == []


def test_barrido_lento_fuera_de_ventana_no_alerta():
    packets = [ping("10.0.0.66", f"10.0.0.{i}", i * 2.0) for i in range(1, 31)]
    assert analyze(packets, threshold=15, window=10).sweeps == []
