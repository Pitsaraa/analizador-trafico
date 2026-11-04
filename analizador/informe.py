"""Genera el informe del análisis en Markdown."""

from datetime import datetime, timezone


def _fecha(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _rango_puertos(ports):
    ports = sorted(ports)
    if len(ports) <= 10:
        return ", ".join(map(str, ports))
    return f"{ports[0]}–{ports[-1]} ({len(ports)} puertos)"


def to_markdown(report, origen):
    lineas = [
        "# Informe de tráfico",
        "",
        f"- **Origen:** `{origen}`",
        f"- **Paquetes IP:** {report.total_packets}",
        f"- **Duración:** {report.duration:.1f} s",
        "",
        "## Protocolos",
        "",
        "| Protocolo | Paquetes | % |",
        "|---|---|---|",
    ]
    for proto, n in report.protocols.most_common():
        lineas.append(f"| {proto} | {n} | {100 * n / report.total_packets:.1f} |")

    lineas += ["", "## IPs con más tráfico enviado", "", "| IP | Paquetes |", "|---|---|"]
    lineas += [f"| {ip} | {n} |" for ip, n in report.top_sources.most_common(5)]

    lineas += ["", "## Puertos TCP de destino más usados", "", "| Puerto | Paquetes |", "|---|---|"]
    lineas += [f"| {port} | {n} |" for port, n in report.top_dst_ports.most_common(5)]

    lineas += ["", "## Alertas de escaneo de puertos", ""]
    if not report.alerts:
        lineas.append("Sin alertas.")
    else:
        lineas += ["| Origen | Destino | Inicio | Puertos sondeados |", "|---|---|---|---|"]
        for a in report.alerts:
            lineas.append(f"| {a.src} | {a.dst} | {_fecha(a.first_seen)} | {_rango_puertos(a.ports)} |")

    lineas += ["", "## Alertas de barrido de ping", ""]
    if not report.sweeps:
        lineas.append("Sin alertas.")
    else:
        lineas += ["| Origen | Inicio | Equipos sondeados |", "|---|---|---|"]
        for s in report.sweeps:
            lineas.append(f"| {s.src} | {_fecha(s.first_seen)} | {len(s.targets)} |")

    return "\n".join(lineas) + "\n"
